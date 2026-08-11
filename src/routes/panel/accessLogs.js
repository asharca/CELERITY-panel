/**
 * Admin-only access-logs UI + JSON API.
 *
 * Routes (all behind the panel auth chain applied in panel/index.js):
 *   GET  /panel/access-logs             -> dashboard page
 *   GET  /panel/access-logs/api/analytics -> combined overview: totals, series,
 *                                          top dests/ports/blocked, per-user
 *                                          IP/fan-out (ClickHouse). degraded when
 *                                          ClickHouse is not configured/reachable.
 *   GET  /panel/access-logs/api/search  -> paged raw-event search (ClickHouse)
 *   GET  /panel/access-logs/api/status  -> per-node shipping + pipeline status
 *   POST /panel/access-logs/api/purge   -> delete the entire stored dataset
 *
 * Search/summary never interpolate user input into SQL — filters are bound as
 * ClickHouse query parameters inside searchService. When the feature is off, the
 * page shows a banner and the APIs return empty/disabled payloads.
 */

const express = require('express');
const router = express.Router();

const { render } = require('./helpers');
const logger = require('../../utils/logger');

// Parse a bounded date from a query string; returns null when absent/invalid.
function parseDate(v) {
    if (!v) return null;
    const d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
}

// Build the filter object from query params, shared by search + summary.
function filtersFromQuery(q) {
    const f = {};
    const from = parseDate(q.from);
    const to = parseDate(q.to);
    if (from) f.from = from;
    if (to) f.to = to;
    if (q.nodeId) f.nodeId = String(q.nodeId).slice(0, 64);
    if (q.email) f.email = String(q.email).slice(0, 256);
    if (q.sourceIp) f.sourceIp = String(q.sourceIp).slice(0, 64);
    if (q.destination) f.destination = String(q.destination).slice(0, 256);
    if (q.action && ['accepted', 'rejected', 'blocked'].includes(q.action)) f.action = q.action;
    if (q.network && ['tcp', 'udp'].includes(q.network)) f.network = q.network;
    if (q.q) f.q = String(q.q).slice(0, 256);
    return f;
}

async function isEnabled() {
    const Settings = require('../../models/settingsModel');
    const s = await Settings.get();
    return !!s?.accessLogs?.enabled;
}

// ─── Page ────────────────────────────────────────────────────────────────────

router.get('/access-logs', async (req, res) => {
    try {
        const Settings = require('../../models/settingsModel');
        const HyNode = require('../../models/hyNodeModel');
        const settings = await Settings.get();
        const nodes = await HyNode.find({
            type: { $in: ['xray', 'hysteria'] },
            cascadeRole: { $in: ['standalone', 'portal'] },
        }).select('name type xray.accessLogs.status xray.accessLogs.lastBatchAt').lean();

        render(res, 'access-logs', {
            title: res.locals.t?.('accessLogs.pageTitle') || 'Access logs',
            page: 'accessLogs',
            enabled: !!settings?.accessLogs?.enabled,
            state: settings?.accessLogs?.state || 'disabled',
            nodes,
        });
    } catch (error) {
        logger.error('[Panel] GET /access-logs error:', error.message);
        res.status(500).send(`${res.locals.t?.('common.error') || 'Error'}: ${error.message}`);
    }
});

// ─── JSON API ────────────────────────────────────────────────────────────────

router.get('/access-logs/api/analytics', async (req, res) => {
    try {
        if (!(await isEnabled())) return res.json({ enabled: false });
        const filters = filtersFromQuery(req.query);
        const searchService = require('../../services/accessLogs/searchService');
        const result = await searchService.overview(filters, { topN: 10, userLimit: 25 });

        if (result.degraded && !result.partial) {
            // ClickHouse is not configured/reachable: the whole feature is backed
            // by it, so there is nothing to show. The UI renders a "configure
            // ClickHouse" banner instead of zeros.
            return res.json({
                enabled: true,
                degraded: true,
                partial: false,
                partialErrors: {},
                chRequired: true,
                totals: {},
                series: [],
                topDestinations: [],
                topPorts: [],
                topBlocked: [],
                users: [],
                usersByIp: [],
                usersByFanout: [],
            });
        }
        if (result.error) {
            // Configured but the query failed (ClickHouse down, auth error...):
            // surface the degraded banner instead of a page full of zeros.
            return res.json({
                enabled: true,
                degraded: true,
                partial: false,
                partialErrors: {},
                chRequired: true,
                error: result.error,
                totals: {},
                series: [],
                topDestinations: [],
                topPorts: [],
                topBlocked: [],
                users: [],
                usersByIp: [],
                usersByFanout: [],
            });
        }
        return res.json({
            enabled: true,
            degraded: !!result.degraded,
            partial: !!result.partial,
            partialErrors: result.partialErrors || {},
            ...result,
        });
    } catch (error) {
        logger.error('[Panel] access-logs analytics error:', error.message);
        res.status(500).json({ error: 'analytics failed' });
    }
});

router.get('/access-logs/api/search', async (req, res) => {
    try {
        const parsedLimit = parseInt(req.query.limit, 10);
        const parsedOffset = parseInt(req.query.offset, 10);
        const limit = Number.isFinite(parsedLimit) ? Math.max(1, Math.min(1000, parsedLimit)) : 200;
        const offset = Number.isFinite(parsedOffset) ? Math.max(0, parsedOffset) : 0;
        if (!(await isEnabled())) {
            return res.json({ enabled: false, rows: [], hasMore: false, offset, limit });
        }
        const filters = filtersFromQuery(req.query);
        const opts = {
            // Fetch one sentinel row so the response can distinguish an exact
            // page from a truncated one without issuing a costly count query.
            limit: limit + 1,
            offset,
            sort: req.query.sort,
            dir: req.query.dir,
        };
        const searchService = require('../../services/accessLogs/searchService');
        const result = await searchService.search(filters, opts);
        const fetchedRows = Array.isArray(result.rows) ? result.rows : [];
        return res.json({
            enabled: true,
            ...result,
            rows: fetchedRows.slice(0, limit),
            hasMore: fetchedRows.length > limit,
            offset,
            limit,
        });
    } catch (error) {
        logger.error('[Panel] access-logs search error:', error.message);
        res.status(500).json({ error: 'search failed' });
    }
});

router.get('/access-logs/api/user-ips', async (req, res) => {
    try {
        if (!(await isEnabled())) return res.json({ enabled: false, rows: [] });
        const email = String(req.query.email || '').slice(0, 256);
        if (!email) return res.json({ enabled: true, rows: [] });
        const filters = filtersFromQuery(req.query);
        const searchService = require('../../services/accessLogs/searchService');
        const result = await searchService.userIps(email, filters, { limit: 200 });
        return res.json({ enabled: true, ...result });
    } catch (error) {
        logger.error('[Panel] access-logs user-ips error:', error.message);
        res.status(500).json({ error: 'user-ips failed' });
    }
});

router.get('/access-logs/api/status', async (req, res) => {
    try {
        const Settings = require('../../models/settingsModel');
        const HyNode = require('../../models/hyNodeModel');
        const spoolService = require('../../services/accessLogs/spoolService');
        const clickhouse = require('../../services/accessLogs/clickhouseService');

        const settings = await Settings.get();
        const nodes = await HyNode.find({
            type: { $in: ['xray', 'hysteria'] },
            cascadeRole: { $in: ['standalone', 'portal'] },
        }).select('name type agentVersion xray.accessLogs').lean();

        const spool = await spoolService.spoolSize();
        const chAvailable = await clickhouse.isAvailable();

        res.json({
            enabled: !!settings?.accessLogs?.enabled,
            state: settings?.accessLogs?.state || 'disabled',
            stats: settings?.accessLogs?.stats || {},
            spool,
            clickhouse: chAvailable,
            nodes: nodes.map(n => ({
                id: String(n._id),
                name: n.name,
                type: n.type,
                agentVersion: n.agentVersion || '',
                status: n.xray?.accessLogs?.status || 'disabled',
                lastBatchAt: n.xray?.accessLogs?.lastBatchAt || null,
                lastError: n.xray?.accessLogs?.lastError || '',
            })),
        });
    } catch (error) {
        logger.error('[Panel] access-logs status error:', error.message);
        res.status(500).json({ error: 'status failed' });
    }
});

router.post('/access-logs/api/purge', async (req, res) => {
    try {
        // Purge shares the storage lock used by ingest + drain. This guarantees
        // a batch already read by the processor cannot be inserted after the
        // truncate and resurrect data the administrator just deleted.
        const processService = require('../../services/accessLogs/processService');
        await processService.purgeStoredData();

        logger.info('[AccessLogs] stored dataset purged by admin');
        res.json({ ok: true });
    } catch (error) {
        logger.error('[Panel] access-logs purge error:', error.message);
        res.status(500).json({ error: 'purge failed' });
    }
});

module.exports = router;
