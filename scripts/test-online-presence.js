const assert = require('assert');
const fs = require('fs');
const path = require('path');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';

const root = path.join(__dirname, '..');

function queryResult(value) {
    return {
        select() { return this; },
        sort() { return this; },
        lean: async () => JSON.parse(JSON.stringify(value)),
    };
}

(async () => {
    const { normalizeOnlinePayload } = require('../src/services/hysteriaStatsClient');
    const { OnlinePresenceService } = require('../src/services/onlinePresenceService');

    assert.deepStrictEqual(
        normalizeOnlinePayload({ alice: 2, bob: 0 }),
        { alice: 2 },
        'official numeric response shape preserves positive client instance counts'
    );
    assert.throws(() => normalizeOnlinePayload([]), /Invalid Hysteria online response/);
    assert.throws(() => normalizeOnlinePayload({ alice: {} }), /Invalid Hysteria online entry/);

    let nowMs = Date.parse('2026-08-02T12:00:00.000Z');
    let responses = {
        alpha: { alice: 2, orphan: 1 },
        beta: { alice: 1, bob: 2 },
    };
    let activeRequests = 0;
    let maxActiveRequests = 0;
    let fetchCalls = 0;

    const nodes = [
        {
            _id: 'alpha',
            name: 'Alpha',
            flag: 'A',
            ip: '198.51.100.10',
            statsHost: '10.0.10.42',
            statsPort: 9999,
            statsSecret: 'alpha-secret',
        },
        {
            _id: 'beta',
            name: 'Beta',
            flag: 'B',
            ip: '203.0.113.20',
            statsHost: '10.0.10.42',
            statsPort: 9998,
            statsSecret: 'beta-secret',
        },
    ];

    const users = [
        { _id: 'u1', userId: 'alice', username: 'Alice', enabled: true },
        { _id: 'u2', userId: 'bob', username: '', enabled: false },
    ];

    const service = new OnlinePresenceService({
        nodeModel: {
            find(filter) {
                assert.deepStrictEqual(filter, { active: true, type: 'hysteria' });
                return queryResult(nodes);
            },
        },
        userModel: {
            find(filter) {
                assert(filter.userId.$in.includes('alice'));
                return queryResult(users.filter(user => filter.userId.$in.includes(user.userId)));
            },
        },
        statsClient: {
            async fetchOnline(node) {
                fetchCalls += 1;
                activeRequests += 1;
                maxActiveRequests = Math.max(maxActiveRequests, activeRequests);
                await new Promise(resolve => setImmediate(resolve));
                activeRequests -= 1;
                const value = responses[String(node._id)];
                if (value instanceof Error) throw value;
                return value;
            },
        },
        logger: { debug() {}, warn() {}, error() {} },
        intervalMs: 2000,
        staleTtlMs: 10000,
        now: () => nowMs,
    });

    const firstRefresh = service.refresh();
    const overlappingRefresh = service.refresh();
    await Promise.all([firstRefresh, overlappingRefresh]);
    assert.strictEqual(fetchCalls, 2, 'overlapping refresh calls share one collection pass');
    assert.strictEqual(maxActiveRequests, 2, 'nodes are collected concurrently');

    let snapshot = service.getSnapshot();
    assert.deepStrictEqual(snapshot.totals, {
        distinctUsers: 3,
        nodePresences: 4,
        clientInstances: 6,
    });
    assert.strictEqual(snapshot.intervalMs, 2000);
    assert.strictEqual(snapshot.partial, false);
    assert.strictEqual(snapshot.presences.length, 4);

    const aliceRows = snapshot.presences.filter(item => item.userId === 'alice');
    assert.deepStrictEqual(aliceRows.map(item => item.nodeName), ['Alpha', 'Beta']);
    assert.deepStrictEqual(aliceRows.map(item => item.clientInstances), [2, 1]);
    assert(aliceRows.every(item => item.displayName === 'Alice' && item.known && item.enabled));

    const bob = snapshot.presences.find(item => item.userId === 'bob');
    assert.strictEqual(bob.displayName, 'bob', 'empty username falls back to userId');
    assert.strictEqual(bob.enabled, false, 'disabled users with lingering sessions remain visible');

    const orphan = snapshot.presences.find(item => item.userId === 'orphan');
    assert.strictEqual(orphan.known, false, 'unknown authenticated ids remain visible');
    assert.strictEqual(orphan.displayName, 'orphan');

    const serialized = JSON.stringify(snapshot);
    for (const secret of ['alpha-secret', 'beta-secret', '10.0.10.42', '198.51.100.10', '203.0.113.20', '9999', '9998']) {
        assert(!serialized.includes(secret), `public snapshot must not contain ${secret}`);
    }

    nowMs += 2000;
    responses = {
        alpha: new Error('connect ETIMEDOUT 10.0.10.42:9999'),
        beta: {},
    };
    await service.refresh();
    snapshot = service.getSnapshot();
    assert.strictEqual(snapshot.partial, true);
    const staleAlpha = snapshot.nodes.find(node => node.nodeId === 'alpha');
    assert.strictEqual(staleAlpha.state, 'stale');
    assert.strictEqual(staleAlpha.stale, true);
    assert.strictEqual(staleAlpha.users.length, 2, 'short outage retains last confirmed presence');
    const freshBeta = snapshot.nodes.find(node => node.nodeId === 'beta');
    assert.strictEqual(freshBeta.state, 'online');
    assert.strictEqual(freshBeta.users.length, 0, 'successful empty response confirms zero online users');
    assert(!JSON.stringify(snapshot).includes('ETIMEDOUT'), 'internal error details stay server-side');

    nowMs += 12000;
    await service.refresh();
    snapshot = service.getSnapshot();
    const expiredAlpha = snapshot.nodes.find(node => node.nodeId === 'alpha');
    assert.strictEqual(expiredAlpha.state, 'unavailable');
    assert.deepStrictEqual(expiredAlpha.users, [], 'expired stale data is removed');

    service.stop();

    const dashboard = fs.readFileSync(path.join(root, 'views/dashboard.ejs'), 'utf8');
    const liveScript = fs.readFileSync(path.join(root, 'public/js/live-online.js'), 'utf8');
    const panelSystem = fs.readFileSync(path.join(root, 'src/routes/panel/system.js'), 'utf8');
    const indexSource = fs.readFileSync(path.join(root, 'index.js'), 'utf8');

    assert(dashboard.includes('id="liveOnlineRows"'), 'dashboard renders online presence rows');
    assert(dashboard.includes('id="liveOnlineStatus"'), 'dashboard renders live connection state');
    assert(dashboard.includes('/js/live-online.js'), 'dashboard loads live presence client');
    assert(liveScript.includes('/ws/presence'), 'browser consumes the shared WebSocket snapshot');
    assert(liveScript.includes('/panel/presence'), 'browser has authenticated REST fallback');
    assert(!/\.innerHTML\s*=/.test(liveScript), 'live user data is rendered without innerHTML');
    assert(panelSystem.includes("router.get('/presence'"), 'panel exposes authenticated snapshot fallback');
    assert(indexSource.includes("pathname === '/ws/presence'"), 'server exposes authenticated presence WebSocket');

    for (const locale of ['en', 'zh-CN', 'ru']) {
        const messages = JSON.parse(fs.readFileSync(path.join(root, 'src/locales', `${locale}.json`), 'utf8'));
        for (const key of [
            'liveOnlineUsers',
            'liveConnected',
            'liveReconnecting',
            'liveUser',
            'liveNode',
            'liveClients',
            'liveEmpty',
            'liveUnknownUser',
            'liveDisabled',
            'liveStale',
        ]) {
            assert(messages.dashboard[key], `${locale} locale contains dashboard.${key}`);
        }
    }

    console.log('online presence tests passed');
})().catch(error => {
    console.error(error);
    process.exit(1);
});
