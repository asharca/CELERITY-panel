/**
 * Access-logs ingest endpoint (agent -> panel).
 *
 * Mounted BEFORE the global express.json() so it can read the raw gzipped body
 * itself. Flow:
 *   1. Auth: Bearer token -> resolve owning node (constant-time hash compare).
 *   2. Read raw body with a hard size cap (streaming, no full buffering beyond
 *      the cap) to bound memory per request.
 *   3. Verify X-Batch-Id == sha256(body) so a corrupted upload is rejected.
 *   4. Idempotency: drop batches already processed.
 *   5. Backpressure: 429 when the panel spool is over its cap.
 *   6. Durably spool the raw bytes (atomic write), then ACK.
 *
 * Forwarding to ClickHouse happens in a separate processing stage draining the
 * spool, so the request path stays fast and the endpoint is safe under load.
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const logger = require('../utils/logger');
const credentialService = require('../services/accessLogs/credentialService');
const spoolService = require('../services/accessLogs/spoolService');
const cacheService = require('../services/cacheService');

// Hard caps. A single batch body must stay small; the agent batches ~500 events
// which gzip to well under this. Reject anything larger to bound memory.
const MAX_BODY_BYTES = 8 * 1024 * 1024; // 8 MB gzipped
// Refuse new batches once the on-disk spool exceeds this, so a stalled
// processor cannot fill the panel disk. Agents will retry with backoff.
const SPOOL_BACKPRESSURE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB

// spoolSize() stats every spooled file (O(n)); cache it briefly so a large
// backlog does not multiply per-request filesystem work.
let _spoolSizeCache = { bytes: 0, at: 0 };
const SPOOL_SIZE_TTL_MS = 5000;
async function cachedSpoolBytes() {
    const now = Date.now();
    if (now - _spoolSizeCache.at > SPOOL_SIZE_TTL_MS) {
        const { bytes } = await spoolService.spoolSize();
        _spoolSizeCache = { bytes, at: now };
    }
    return _spoolSizeCache.bytes;
}

// Global-enabled flag cached briefly: with many nodes shipping every few
// seconds, hitting Mongo for the settings doc on every batch is wasted work.
// 10 s of staleness after an admin disables the feature is harmless — the
// processor still handles (or the next request rejects) those batches.
let _enabledCache = { value: false, at: 0 };
const ENABLED_TTL_MS = 10 * 1000;
async function accessLogsEnabled() {
    const now = Date.now();
    if (now - _enabledCache.at > ENABLED_TTL_MS) {
        const Settings = require('../models/settingsModel');
        const s = await Settings.get();
        _enabledCache = { value: !!s?.accessLogs?.enabled, at: now };
    }
    return _enabledCache.value;
}

// Read the raw request body into a single Buffer, aborting past the cap.
function readRawBody(req, limit) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let aborted = false;
        req.on('data', (chunk) => {
            if (aborted) return;
            size += chunk.length;
            if (size > limit) {
                aborted = true;
                const err = new Error('payload too large');
                err.statusCode = 413;
                reject(err);
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => { if (!aborted) resolve(Buffer.concat(chunks)); });
        req.on('error', (e) => { if (!aborted) reject(e); });
    });
}

// Extract the Bearer token from the Authorization header.
function getBearer(req) {
    const h = req.headers['authorization'] || '';
    const m = /^Bearer\s+(.+)$/i.exec(h);
    return m ? m[1].trim() : '';
}

router.post('/ingest', async (req, res) => {
    try {
        // Feature gate: ignore ingest entirely when access logs are disabled
        // globally, so a stale agent cannot keep pushing after an admin turns
        // the feature off. Cached briefly to avoid a Mongo hit per batch.
        if (!(await accessLogsEnabled())) {
            return res.status(403).json({ error: 'access logs disabled' });
        }

        const token = getBearer(req);
        if (!token) {
            return res.status(401).json({ error: 'missing bearer token' });
        }

        const node = await credentialService.resolveNodeByToken(token);
        if (!node) {
            return res.status(401).json({ error: 'invalid token' });
        }
        const nodeId = String(node._id);

        // Backpressure: reject early (before reading the body) when spool is full.
        const spoolBytes = await cachedSpoolBytes();
        if (spoolBytes > SPOOL_BACKPRESSURE_BYTES) {
            res.set('Retry-After', '30');
            return res.status(429).json({ error: 'spool full, retry later' });
        }

        const body = await readRawBody(req, MAX_BODY_BYTES);
        if (!body || body.length === 0) {
            return res.status(400).json({ error: 'empty body' });
        }

        // Verify integrity against the agent-supplied batch id.
        const computedId = crypto.createHash('sha256').update(body).digest('hex');
        const claimedId = String(req.headers['x-batch-id'] || '').trim().toLowerCase();
        if (claimedId && claimedId !== computedId) {
            return res.status(400).json({ error: 'batch id mismatch' });
        }
        const batchId = computedId;

        // Idempotency: already-processed identical batch -> ACK without re-spooling.
        if (await cacheService.isBatchProcessed(nodeId, batchId)) {
            await bumpStats({ duplicateBatches: 1 });
            return res.status(200).json({ ok: true, duplicate: true });
        }

        const processService = require('../services/accessLogs/processService');
        // Keep the authenticated physical node's runtime -> logical-node map
        // hot for the drain that follows. A restart still falls back to Mongo.
        processService.registerRuntimeNodeMappings(
            nodeId,
            node.xray?.accessLogs?.journalSources
        );
        await processService.withStorageLock(async () => {
            await spoolService.persistBatch(nodeId, batchId, body);
            await bumpStats({ ingestedBatches: 1, lastIngestAt: new Date() });
            await touchNode(nodeId, body.length);
        });

        // Nudge the processor (best-effort; it also runs on an interval).
        try { processService.kick(); } catch (_) { /* not loaded yet */ }

        return res.status(202).json({ ok: true, batchId });
    } catch (err) {
        const code = err.statusCode || 500;
        if (code >= 500) {
            logger.error(`[AccessLogs] ingest error: ${err.message}`);
        }
        await bumpStats({ rejectedBatches: 1 }).catch(() => {});
        return res.status(code).json({ error: err.message || 'ingest failed' });
    }
});

// Increment aggregate ingest counters on the settings doc (cheap $inc).
async function bumpStats(delta) {
    const Settings = require('../models/settingsModel');
    const inc = {};
    const set = {};
    if (delta.ingestedBatches) inc['accessLogs.stats.ingestedBatches'] = delta.ingestedBatches;
    if (delta.rejectedBatches) inc['accessLogs.stats.rejectedBatches'] = delta.rejectedBatches;
    if (delta.duplicateBatches) inc['accessLogs.stats.duplicateBatches'] = delta.duplicateBatches;
    if (delta.lastIngestAt) set['accessLogs.stats.lastIngestAt'] = delta.lastIngestAt;
    const update = {};
    if (Object.keys(inc).length) update.$inc = inc;
    if (Object.keys(set).length) update.$set = set;
    if (Object.keys(update).length === 0) return;
    try {
        await Settings.updateOne({ _id: 'settings' }, update, { upsert: true });
    } catch (e) {
        logger.warn(`[AccessLogs] bumpStats failed: ${e.message}`);
    }
}

// Record per-node last-batch time and rolling spool bytes for the status UI.
async function touchNode(nodeId, byteLen) {
    const HyNode = require('../models/hyNodeModel');
    try {
        await HyNode.updateOne({ _id: nodeId }, {
            $set: {
                'xray.accessLogs.lastBatchAt': new Date(),
                'xray.accessLogs.status': 'active',
            },
        });
    } catch (e) {
        logger.warn(`[AccessLogs] touchNode failed: ${e.message}`);
    }
}

module.exports = router;
