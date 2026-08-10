/**
 * Access-log purge concurrency/error contract (no MongoDB/ClickHouse required).
 */

process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';
process.env.PANEL_DOMAIN ||= 'panel.example.invalid';
process.env.ACME_EMAIL ||= 'admin@example.invalid';

const assert = require('assert');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

(async () => {
    const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'celerity-access-purge-'));
    process.env.ACCESS_LOGS_DIR = tempRoot;

    const spoolService = require('../src/services/accessLogs/spoolService');
    const processService = require('../src/services/accessLogs/processService');
    const clickhouse = require('../src/services/accessLogs/clickhouseService');
    const cacheService = require('../src/services/cacheService');
    const Settings = require('../src/models/settingsModel');

    const original = {
        isConfigured: clickhouse.isConfigured,
        insertRaw: clickhouse.insertRaw,
        truncate: clickhouse.truncate,
        isBatchProcessed: cacheService.isBatchProcessed,
        markBatchProcessed: cacheService.markBatchProcessed,
        settingsGet: Settings.get,
        settingsUpdate: Settings.update,
        fspRm: fsp.rm,
    };

    try {
        clickhouse.isConfigured = async () => true;
        cacheService.isBatchProcessed = async () => false;
        cacheService.markBatchProcessed = async () => {};
        Settings.get = async () => ({ accessLogs: { maskClientIp: false } });
        Settings.update = async () => {};

        const body = zlib.gzipSync(Buffer.from(
            `${JSON.stringify({ raw: '2026/08/10 10:00:00 198.51.100.2:1234 accepted tcp:example.com:443 [hysteria2 -> direct] email: account-1' })}\n`
        ));
        await spoolService.persistBatch('node-1', 'a'.repeat(64), body);

        let releaseInsert;
        const insertGate = new Promise(resolve => { releaseInsert = resolve; });
        let signalInsertStarted;
        const insertStarted = new Promise(resolve => { signalInsertStarted = resolve; });
        const stored = [];
        let truncateCalls = 0;

        clickhouse.insertRaw = async rows => {
            signalInsertStarted();
            await insertGate;
            stored.push(...rows);
        };
        clickhouse.truncate = async () => {
            truncateCalls++;
            stored.length = 0;
        };

        const drain = processService.drainOnce();
        await insertStarted;
        const purge = processService.purgeStoredData();
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(truncateCalls, 0, 'purge waits for an in-flight spool insert');

        releaseInsert();
        await Promise.all([drain, purge]);
        assert.strictEqual(truncateCalls, 1);
        assert.deepStrictEqual(stored, [], 'truncate runs after the old insert, so data cannot reappear');
        assert.deepStrictEqual(await spoolService.listSpool(), []);

        // Even if deleting the moved-aside directory fails after truncate, the
        // old batch must stay outside incoming/ and can never be reinserted.
        await spoolService.persistBatch('node-1', 'c'.repeat(64), body);
        stored.push({ old: true });
        fsp.rm = async (target, options) => {
            if (String(target).includes('.purge-')) {
                const error = new Error('simulated tombstone delete failure');
                error.code = 'EACCES';
                throw error;
            }
            return original.fspRm(target, options);
        };
        await assert.rejects(processService.purgeStoredData(), /simulated tombstone delete failure/);
        assert.deepStrictEqual(stored, [], 'ClickHouse was truncated before tombstone cleanup failed');
        await processService.drainOnce();
        assert.deepStrictEqual(stored, [], 'a failed tombstone delete cannot put old data back in the drain path');
        assert.deepStrictEqual(await spoolService.listSpool(), []);
        fsp.rm = original.fspRm;

        // A ClickHouse error must be visible to the HTTP caller and must leave
        // the recoverable local spool untouched.
        await spoolService.persistBatch('node-1', 'b'.repeat(64), body);
        clickhouse.truncate = async () => { throw new Error('clickhouse unavailable'); };

        const router = require('../src/routes/panel/accessLogs');
        const layer = router.stack.find(item => item.route?.path === '/access-logs/api/purge'
            && item.route.methods.post);
        assert(layer, 'purge route is registered');
        const handler = layer.route.stack[layer.route.stack.length - 1].handle;
        let statusCode = 200;
        let payload = null;
        const response = {
            status(code) { statusCode = code; return this; },
            json(value) { payload = value; return this; },
        };
        await handler({}, response);

        assert.strictEqual(statusCode, 500, 'truncate failure must not return success');
        assert.deepStrictEqual(payload, { error: 'purge failed' });
        assert.strictEqual((await spoolService.listSpool()).length, 1, 'failed purge preserves pending batches');
    } finally {
        clickhouse.isConfigured = original.isConfigured;
        clickhouse.insertRaw = original.insertRaw;
        clickhouse.truncate = original.truncate;
        cacheService.isBatchProcessed = original.isBatchProcessed;
        cacheService.markBatchProcessed = original.markBatchProcessed;
        Settings.get = original.settingsGet;
        Settings.update = original.settingsUpdate;
        fsp.rm = original.fspRm;
        await fsp.rm(tempRoot, { recursive: true, force: true });
    }

    console.log('test-access-logs-purge: OK');
})().catch(error => {
    console.error('test-access-logs-purge FAILED:', error);
    process.exit(1);
});
