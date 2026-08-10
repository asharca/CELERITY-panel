/**
 * Spool processor: drains durably-spooled ingest batches into ClickHouse.
 *
 * For each sealed spool file it:
 *   1. gunzips + splits NDJSON into { node_id, raw } records,
 *   2. optionally masks client IPs in the raw line (privacy setting),
 *   3. inserts the raw rows into ClickHouse access_ingest (a materialized view
 *      parses them into access_events), using the batch id as a dedup token so
 *      a retried batch is dropped natively,
 *   4. marks the batch processed in Redis (short-TTL idempotency for agent
 *      retries) and removes the spool file.
 *
 * The panel does NO per-event parsing: ClickHouse does it. That keeps CPU on the
 * panel proportional to bytes moved, not events, which matters on weak hardware.
 *
 * Runs on a timer and can be nudged via kick() right after an ingest so latency
 * stays low without a tight busy loop. A single-flight guard prevents concurrent
 * drains from racing on the same files. When ClickHouse is unavailable the run
 * stops and everything stays spooled for a later retry (at-least-once).
 */

const zlib = require('zlib');
const net = require('net');
const { promisify } = require('util');
const fsp = require('fs/promises');
const path = require('path');

const logger = require('../../utils/logger');
const spoolService = require('./spoolService');
const clickhouse = require('./clickhouseService');
const cacheService = require('../cacheService');

const gunzip = promisify(zlib.gunzip);

// Decompression bomb guard: a batch body is capped at 8 MB compressed on
// ingest; refuse to inflate past this many bytes so a crafted batch cannot
// exhaust panel memory. Legit batches (~500 log lines) are far smaller.
const MAX_INFLATED_BYTES = 64 * 1024 * 1024; // 64 MB

const PROCESS_INTERVAL_MS = 10 * 1000;
const MAX_FILES_PER_RUN = 50;

let running = false;
let timer = null;
let kickPending = false;

// Serialize storage-changing operations across ingest, drain and admin purge.
// In particular, purge must wait for an insert that has already read a spool
// file; otherwise that insert could land after ClickHouse was truncated and
// silently resurrect records the administrator just deleted.
let storageOperationTail = Promise.resolve();
function withStorageLock(operation) {
    if (typeof operation !== 'function') {
        return Promise.reject(new TypeError('storage operation must be a function'));
    }
    const run = storageOperationTail.then(operation, operation);
    // Keep the queue usable after a failed operation without creating an
    // unhandled rejection from a discarded finally-derived promise.
    storageOperationTail = run.then(() => undefined, () => undefined);
    return run;
}

// Cached maskClientIp flag (checked per drain run, cheap TTL cache).
let _maskCache = { value: false, at: 0 };
const MASK_TTL_MS = 30 * 1000;
async function shouldMaskClientIp() {
    const now = Date.now();
    if (now - _maskCache.at > MASK_TTL_MS) {
        try {
            const Settings = require('../../models/settingsModel');
            const s = await Settings.get();
            _maskCache = { value: !!s?.accessLogs?.maskClientIp, at: now };
        } catch (_) {
            // On DB error keep the previous value but do not cache the failure.
            _maskCache.at = now - MASK_TTL_MS + 5000;
        }
    }
    return _maskCache.value;
}

function resetMaskCache() {
    _maskCache = { value: false, at: 0 };
}

/**
 * Privacy mask for client IPs (settings.accessLogs.maskClientIp).
 * IPv4 keeps the /24 (last octet zeroed); IPv6 keeps the first three hextets.
 * Exact source-IP search becomes impossible by design.
 */
function maskIp(ip) {
    if (!ip) return '';
    if (net.isIP(ip) === 4) {
        const octets = ip.split('.');
        return `${octets[0]}.${octets[1]}.${octets[2]}.0`;
    }
    if (net.isIP(ip) === 6) {
        const halves = ip.toLowerCase().split('::');
        const left = halves[0] ? halves[0].split(':') : [];
        const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

        // Convert a possible IPv4-mapped tail into its two IPv6 hextets.
        const tail = right.length ? right : left;
        const last = tail[tail.length - 1] || '';
        if (last.includes('.')) {
            const octets = last.split('.').map(Number);
            tail.splice(tail.length - 1, 1,
                ((octets[0] << 8) | octets[1]).toString(16),
                ((octets[2] << 8) | octets[3]).toString(16));
        }

        const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
        const expanded = halves.length === 2
            ? [...left, ...Array(Math.max(0, missing)).fill('0'), ...right]
            : left;
        if (expanded.length === 8) {
            return expanded.slice(0, 3)
                .map(part => Number.parseInt(part || '0', 16).toString(16))
                .join(':') + '::';
        }
    }
    return ip;
}

// The source endpoint is the first token after the timestamp on the normalized
// access line (optionally prefixed by "from "). Capture the WHOLE token: IPv6
// endpoints contain colons and are normally bracketed, so stopping at the first
// colon would only mask a fragment and leak the rest of the address.
const SRC_ENDPOINT_RE = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(?:from\s+)?)(\S+)/;

function maskSourceEndpoint(endpoint) {
    if (!endpoint) return endpoint;

    // Xray may prefix the endpoint with its transport (tcp:/udp:). Keep that
    // prefix because the ClickHouse parser already knows how to remove it.
    const protoMatch = /^(tcp:|udp:)(.*)$/i.exec(endpoint);
    const proto = protoMatch ? protoMatch[1] : '';
    const value = protoMatch ? protoMatch[2] : endpoint;

    // net.Addr.String() represents IPv6 endpoints as [addr]:port. HY2 uses
    // exactly this form for its `addr` field.
    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
    if (bracketed) {
        const masked = net.isIP(bracketed[1]) === 6 ? maskIp(bracketed[1]) : '::';
        return `${proto}[${masked}]${bracketed[2] ? `:${bracketed[2]}` : ''}`;
    }

    // IPv4 with an optional port. A bare IPv6 address is also handled by
    // maskIp below; unbracketed IPv6+port is intentionally left untouched
    // because it is ambiguous and is not emitted by Xray/Hysteria net.Addr.
    const ipv4 = /^((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?$/.exec(value);
    if (ipv4) {
        return `${proto}${maskIp(ipv4[1])}${ipv4[2] ? `:${ipv4[2]}` : ''}`;
    }
    if (value.includes(':') && !/]:\d+$/.test(value)) {
        const masked = maskIp(value);
        return `${proto}${masked === value ? '::' : masked}`;
    }
    return endpoint;
}

function maskRawLine(raw) {
    if (!raw) return raw;
    return raw.replace(SRC_ENDPOINT_RE, (m, prefix, endpoint) => prefix + maskSourceEndpoint(endpoint));
}

// Parse a single spool file into ClickHouse raw rows tagged with the node id.
// Throws on corrupt gzip OR on decompression past MAX_INFLATED_BYTES (both are
// treated as an undecodable batch and dropped by the caller).
async function parseSpoolFile(filePath, mask) {
    const { nodeId } = spoolService.parseSpoolName(filePath);
    const gz = await fsp.readFile(filePath);
    const ndjson = (await gunzip(gz, { maxOutputLength: MAX_INFLATED_BYTES })).toString('utf8');

    const rows = [];
    for (const line of ndjson.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let rec;
        try {
            rec = JSON.parse(trimmed);
        } catch (_) {
            continue; // skip malformed NDJSON record
        }
        let raw = String(rec.raw == null ? '' : rec.raw);
        if (mask) raw = maskRawLine(raw);
        // The agent also sends a file offset per record; it is only used for
        // agent-side resume and is deliberately not stored.
        rows.push({ node_id: nodeId, raw });
    }
    return { nodeId, rows };
}

// Process a single spool file end-to-end. Returns the number of rows inserted.
async function processFile(filePath, mask) {
    const { batchId, nodeId } = spoolService.parseSpoolName(filePath);

    // Crash-recovery fast path: a crash between marking processed and spool-file
    // removal leaves an already-processed batch behind. The ClickHouse dedup
    // token would make re-insertion harmless, but skipping avoids wasted work.
    if (batchId && await cacheService.isBatchProcessed(nodeId, batchId)) {
        await spoolService.removeSpoolFile(filePath);
        return 0;
    }

    let parsed;
    try {
        parsed = await parseSpoolFile(filePath, mask);
    } catch (e) {
        // Undecodable batch (corrupt gzip, etc): drop it so it cannot block the
        // queue. There is no structured content to salvage.
        logger.warn(`[AccessLogs] undecodable batch ${path.basename(filePath)}: ${e.message}`);
        await spoolService.removeSpoolFile(filePath);
        return 0;
    }

    if (parsed.rows.length > 0) {
        // A failure here (incl. ClickHouse unavailable) throws: we deliberately
        // let it propagate so the batch stays in the spool and is retried later,
        // rather than acking data we never persisted.
        await clickhouse.insertRaw(parsed.rows, batchId);
    }

    await cacheService.markBatchProcessed(parsed.nodeId || nodeId, batchId);
    await spoolService.removeSpoolFile(filePath);
    return parsed.rows.length;
}

// Track a "storage unavailable" state so the drain loop can back off instead of
// hammering ClickHouse when it is unreachable.
let storageUnavailable = false;

async function drainOnceUnlocked() {
    let processedFiles = 0;
    let totalEvents = 0;
    try {
        // Skip entirely when ClickHouse is not configured: keep batches spooled
        // (backpressure guards the disk) until an admin sets up the connection.
        if (!(await clickhouse.isConfigured())) {
            return { processed: 0, unconfigured: true };
        }

        const mask = await shouldMaskClientIp();
        const files = await spoolService.listSpool();
        const slice = files.slice(0, MAX_FILES_PER_RUN);
        for (const f of slice) {
            try {
                totalEvents += await processFile(f, mask);
                processedFiles++;
                storageUnavailable = false;
            } catch (e) {
                // Any insert error (connection refused, timeout, auth): stop this
                // run, keep everything spooled, log once. The timer retries later.
                if (!storageUnavailable) {
                    logger.warn(`[AccessLogs] ClickHouse unavailable, batches remain spooled: ${e.message}`);
                    storageUnavailable = true;
                }
                break;
            }
        }
    } catch (e) {
        logger.error(`[AccessLogs] drain failed: ${e.message}`);
    }
    if (processedFiles > 0) {
        logger.info(`[AccessLogs] drained ${processedFiles} batch(es), ${totalEvents} event(s)`);
    }
    // If a kick arrived mid-drain, or there are more files than one run handled,
    // schedule an immediate follow-up.
    if (kickPending) {
        kickPending = false;
        setImmediate(() => { drainOnce().catch(() => {}); });
    }
    return { processed: processedFiles, events: totalEvents };
}

async function drainOnce() {
    if (running) { kickPending = true; return { processed: 0, skipped: true }; }
    running = true;
    try {
        return await withStorageLock(drainOnceUnlocked);
    } finally {
        running = false;
    }
}

// Delete both durable pending batches and the ClickHouse dataset as one
// operation relative to ingest/drain. Truncate runs first: if storage is down,
// pending spool data remains intact and the API reports failure instead of
// claiming success after deleting the only recoverable copy.
async function purgeStoredData() {
    return withStorageLock(async () => {
        const paths = require('./paths');
        const Settings = require('../../models/settingsModel');
        const tombstone = `${paths.INCOMING_DIR}.purge-${process.pid}-${Date.now()}`;
        let movedAside = false;
        let truncated = false;

        // Move pending files out of the processor's scan path atomically before
        // truncating. If deletion later fails, they cannot be reinserted into an
        // already-cleared ClickHouse table.
        await fsp.mkdir(paths.DATA_ROOT, { recursive: true });
        try {
            await fsp.rename(paths.INCOMING_DIR, tombstone);
            movedAside = true;
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
        await fsp.mkdir(paths.INCOMING_TMP_DIR, { recursive: true });

        try {
            await clickhouse.truncate();
            truncated = true;
            if (movedAside) {
                await fsp.rm(tombstone, { recursive: true, force: true });
            }
            await Settings.update({
                'accessLogs.stats.ingestedBatches': 0,
                'accessLogs.stats.rejectedBatches': 0,
                'accessLogs.stats.duplicateBatches': 0,
                'accessLogs.stats.lastIngestAt': null,
            });
            return { ok: true };
        } catch (error) {
            // A failed truncate means no purge occurred, so restore the durable
            // spool exactly where the processor expects it. Once truncate has
            // succeeded we intentionally never restore: doing so would revive
            // deleted records on the next drain.
            if (!truncated && movedAside) {
                try {
                    await fsp.rm(paths.INCOMING_DIR, { recursive: true, force: true });
                    await fsp.rename(tombstone, paths.INCOMING_DIR);
                } catch (restoreError) {
                    logger.error(`[AccessLogs] purge spool restore failed: ${restoreError.message}`);
                    error.message = `${error.message}; spool restore failed: ${restoreError.message}`;
                }
            }
            throw error;
        }
    });
}

// Nudge the processor to run soon (debounced by the single-flight guard).
function kick() {
    setImmediate(() => { drainOnce().catch(() => {}); });
}

function start() {
    if (timer) return;
    timer = setInterval(() => { drainOnce().catch(() => {}); }, PROCESS_INTERVAL_MS);
    if (timer.unref) timer.unref();
    logger.info('[AccessLogs] spool processor started');
    drainOnce().catch(() => {});
}

function stop() {
    if (timer) { clearInterval(timer); timer = null; }
}

module.exports = {
    start,
    stop,
    kick,
    drainOnce,
    withStorageLock,
    purgeStoredData,
    // exported for tests
    maskIp,
    maskRawLine,
    parseSpoolFile,
    processFile,
    resetMaskCache,
};
