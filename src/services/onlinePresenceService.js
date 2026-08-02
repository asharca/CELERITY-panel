const { EventEmitter } = require('events');
const HyNode = require('../models/hyNodeModel');
const HyUser = require('../models/hyUserModel');
const statsClient = require('./hysteriaStatsClient');
const logger = require('../utils/logger');

const DEFAULT_INTERVAL_MS = 2000;
const DEFAULT_STALE_TTL_MS = 10000;

function boundedInt(value, fallback, min, max) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(Math.max(parsed, min), max);
}

function emptySnapshot(intervalMs) {
    return {
        version: 0,
        generatedAt: null,
        intervalMs,
        partial: true,
        totals: {
            distinctUsers: 0,
            nodePresences: 0,
            clientInstances: 0,
        },
        nodes: [],
        presences: [],
    };
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

class OnlinePresenceService extends EventEmitter {
    constructor({
        nodeModel = HyNode,
        userModel = HyUser,
        statsClient: injectedStatsClient = statsClient,
        logger: injectedLogger = logger,
        intervalMs = boundedInt(process.env.ONLINE_PRESENCE_INTERVAL_MS, DEFAULT_INTERVAL_MS, 1000, 30000),
        staleTtlMs = boundedInt(process.env.ONLINE_PRESENCE_STALE_TTL_MS, DEFAULT_STALE_TTL_MS, 2000, 120000),
        now = () => Date.now(),
    } = {}) {
        super();
        this.nodeModel = nodeModel;
        this.userModel = userModel;
        this.statsClient = injectedStatsClient;
        this.logger = injectedLogger;
        this.intervalMs = intervalMs;
        this.staleTtlMs = staleTtlMs;
        this.now = now;
        this.running = false;
        this.timer = null;
        this.refreshPromise = null;
        this.version = 0;
        this.nodeCache = new Map();
        this.nodeErrorLogAt = new Map();
        this.snapshot = emptySnapshot(intervalMs);
        this.setMaxListeners(100);
    }

    start() {
        if (this.running) return;
        this.running = true;
        this.schedule(0);
    }

    stop() {
        this.running = false;
        if (this.timer) clearTimeout(this.timer);
        this.timer = null;
    }

    schedule(delayMs) {
        if (!this.running) return;
        this.timer = setTimeout(async () => {
            try {
                await this.refresh();
            } catch (error) {
                this.logger.warn(`[Presence] Collection failed: ${error.message}`);
            } finally {
                this.schedule(this.intervalMs);
            }
        }, delayMs);
        this.timer.unref?.();
    }

    refresh() {
        if (this.refreshPromise) return this.refreshPromise;
        this.refreshPromise = this.collect().finally(() => {
            this.refreshPromise = null;
        });
        return this.refreshPromise;
    }

    async readySnapshot() {
        if (this.snapshot.version === 0) await this.refresh();
        return this.getSnapshot();
    }

    getSnapshot() {
        return clone(this.snapshot);
    }

    async collect() {
        const nowMs = this.now();
        const generatedAt = new Date(nowMs).toISOString();
        const nodes = await this.nodeModel.find({ active: true, type: 'hysteria' })
            .select('_id name flag ip statsHost statsPort statsSecret')
            .sort({ name: 1 })
            .lean();

        const collected = await Promise.all(nodes.map(async node => {
            const nodeId = String(node._id);
            try {
                const online = await this.statsClient.fetchOnline(node, {
                    timeoutMs: Math.min(1500, this.intervalMs),
                });
                const current = {
                    nodeId,
                    nodeName: node.name,
                    flag: node.flag || '',
                    observedAt: generatedAt,
                    observedAtMs: nowMs,
                    online,
                };
                this.nodeCache.set(nodeId, current);
                this.nodeErrorLogAt.delete(nodeId);
                return { ...current, state: 'online', stale: false };
            } catch (error) {
                const previousLogAt = this.nodeErrorLogAt.get(nodeId) || 0;
                if (nowMs - previousLogAt >= 60000) {
                    this.logger.warn(`[Presence] ${node.name}: ${error.message}`);
                    this.nodeErrorLogAt.set(nodeId, nowMs);
                }
                const previous = this.nodeCache.get(nodeId);
                if (previous && nowMs - previous.observedAtMs <= this.staleTtlMs) {
                    return { ...previous, state: 'stale', stale: true };
                }
                return {
                    nodeId,
                    nodeName: node.name,
                    flag: node.flag || '',
                    observedAt: previous?.observedAt || null,
                    observedAtMs: previous?.observedAtMs || null,
                    online: {},
                    state: 'unavailable',
                    stale: true,
                };
            }
        }));

        const userIds = [...new Set(collected.flatMap(node => Object.keys(node.online)))];
        const users = userIds.length > 0
            ? await this.userModel.find({ userId: { $in: userIds } })
                .select('_id userId username enabled')
                .lean()
            : [];
        const userById = new Map(users.map(user => [user.userId, user]));

        const publicNodes = collected.map(node => {
            const nodeUsers = Object.entries(node.online)
                .map(([userId, clientInstances]) => {
                    const user = userById.get(userId);
                    const username = String(user?.username || '').trim();
                    return {
                        userId,
                        username,
                        displayName: username || userId,
                        enabled: user ? user.enabled !== false : null,
                        known: Boolean(user),
                        clientInstances,
                    };
                })
                .sort((a, b) => a.displayName.localeCompare(b.displayName));

            return {
                nodeId: node.nodeId,
                nodeName: node.nodeName,
                flag: node.flag,
                observedAt: node.observedAt,
                state: node.state,
                stale: node.stale,
                onlineUsers: nodeUsers.length,
                clientInstances: nodeUsers.reduce((sum, user) => sum + user.clientInstances, 0),
                users: nodeUsers,
            };
        });

        const presences = publicNodes.flatMap(node => node.users.map(user => ({
            ...user,
            nodeId: node.nodeId,
            nodeName: node.nodeName,
            nodeFlag: node.flag,
            observedAt: node.observedAt,
            stale: node.stale,
        }))).sort((a, b) => (
            a.displayName.localeCompare(b.displayName)
            || a.nodeName.localeCompare(b.nodeName)
        ));

        this.version += 1;
        this.snapshot = {
            version: this.version,
            generatedAt,
            intervalMs: this.intervalMs,
            partial: publicNodes.some(node => node.state !== 'online'),
            totals: {
                distinctUsers: new Set(presences.map(item => item.userId)).size,
                nodePresences: presences.length,
                clientInstances: presences.reduce((sum, item) => sum + item.clientInstances, 0),
            },
            nodes: publicNodes,
            presences,
        };

        const published = this.getSnapshot();
        this.emit('snapshot', published);
        return published;
    }
}

const service = new OnlinePresenceService();

module.exports = service;
module.exports.OnlinePresenceService = OnlinePresenceService;
