/**
 * Access-logs credential + model shape tests.
 *
 * Covers token hashing/generation (pure functions) and verifies the settings /
 * node schemas expose the access-logs fields with safe defaults. No DB needed:
 * models are instantiated in-memory.
 */

process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret';
process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.com';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'admin@example.com';

const assert = require('assert');
const cred = require('../src/services/accessLogs/credentialService');

// --- token generation / hashing -------------------------------------------
{
    const t1 = cred.generateToken();
    const t2 = cred.generateToken();
    assert.strictEqual(t1.length, 64, '32 bytes hex = 64 chars');
    assert.notStrictEqual(t1, t2, 'tokens are random');

    const h1 = cred.hashToken(t1);
    const h1again = cred.hashToken(t1);
    assert.strictEqual(h1, h1again, 'hash is deterministic');
    assert.strictEqual(h1.length, 64, 'sha256 hex = 64 chars');
    assert.notStrictEqual(h1, cred.hashToken(t2), 'different token -> different hash');

    assert.strictEqual(cred.isEligibleIngestNode({ type: 'hysteria', cascadeRole: 'standalone' }), true);
    assert.strictEqual(cred.isEligibleIngestNode({ type: 'xray', cascadeRole: 'portal' }), true);
    assert.strictEqual(cred.isEligibleIngestNode({ type: 'hysteria', cascadeRole: 'bridge' }), false);
    assert.strictEqual(cred.isEligibleIngestNode({ type: 'virtual', cascadeRole: 'standalone' }), false);
    assert.strictEqual(cred.isEligibleIngestNode({ type: 'hysteria', cascadeRole: 'standalone', active: false }), false);
}

// --- settings model defaults ----------------------------------------------
{
    const Settings = require('../src/models/settingsModel');
    const s = new Settings({ _id: 'settings' });
    assert.strictEqual(s.accessLogs.enabled, false, 'access logs off by default');
    assert.strictEqual(s.accessLogs.state, 'disabled');
    assert.strictEqual(s.accessLogs.retentionDays, 30);
    assert.strictEqual(s.accessLogs.nodeScope, 'all');
    assert.strictEqual(s.accessLogs.maskClientIp, false);
    // ClickHouse connection defaults (empty host = not configured).
    assert.strictEqual(s.accessLogs.clickhouse.host, '');
    assert.strictEqual(s.accessLogs.clickhouse.port, 8123);
    assert.strictEqual(s.accessLogs.clickhouse.database, 'default');
    assert.strictEqual(s.accessLogs.clickhouse.secure, false);
}

// --- node model defaults + credential is select:false ---------------------
{
    const HyNode = require('../src/models/hyNodeModel');
    const n = new HyNode({ type: 'xray', name: 'n', ip: '1.2.3.4' });
    assert.strictEqual(n.xray.accessLogs.enabled, false);
    assert.strictEqual(n.xray.accessLogs.status, 'disabled');

    // ingestTokenEncrypted is select:false -> excluded from a default toJSON/lean
    // projection. We at least confirm the path exists and is empty by default.
    assert.strictEqual(n.xray.accessLogs.ingestTokenHash, '');

    const path = HyNode.schema.path('xray');
    assert.ok(path, 'xray subdocument path exists');

    n.xray.accessLogs.journalSources = [{
        unit: 'hysteria-server@mobile',
        tag: 'mobile',
        nodeId: '507f1f77bcf86cd799439011',
    }];
    assert.strictEqual(n.validateSync(), undefined,
        'a journal source can persist its logical panel-node attribution');
    assert.strictEqual(String(n.xray.accessLogs.journalSources[0].nodeId), '507f1f77bcf86cd799439011');
}

(async () => {
    const HyNode = require('../src/models/hyNodeModel');
    const cryptoService = require('../src/services/cryptoService');
    const original = {
        findById: HyNode.findById,
        findOneAndUpdate: HyNode.findOneAndUpdate,
    };
    let encrypted = '';
    let storedHash = '';
    let initialReads = 0;
    let releaseInitialReads;
    const bothRead = new Promise(resolve => { releaseInitialReads = resolve; });
    const document = () => ({
        xray: { accessLogs: { ingestTokenEncrypted: encrypted, ingestTokenHash: storedHash } },
    });

    try {
        HyNode.findById = () => ({
            select: async () => {
                initialReads++;
                if (initialReads === 2) releaseInitialReads();
                if (initialReads <= 2) await bothRead;
                return document();
            },
        });
        HyNode.findOneAndUpdate = (filter, update) => ({
            select: async () => {
                const expected = filter['xray.accessLogs.ingestTokenEncrypted'];
                const permitsEmpty = Array.isArray(filter.$or);
                const matches = expected !== undefined ? encrypted === expected : permitsEmpty && encrypted === '';
                if (!matches) return null;
                encrypted = update.$set['xray.accessLogs.ingestTokenEncrypted'];
                storedHash = update.$set['xray.accessLogs.ingestTokenHash'];
                return document();
            },
        });

        const [first, second] = await Promise.all([
            cred.ensureIngestToken({ _id: 'concurrent-node' }),
            cred.ensureIngestToken({ _id: 'concurrent-node' }),
        ]);
        assert.strictEqual(first.token, second.token, 'concurrent callers return the same CAS winner');
        assert.strictEqual(storedHash, cred.hashToken(first.token));
        assert.strictEqual(cryptoService.decrypt(encrypted), first.token);
        assert.strictEqual([first.created, second.created].filter(Boolean).length, 1);
    } finally {
        HyNode.findById = original.findById;
        HyNode.findOneAndUpdate = original.findOneAndUpdate;
    }

    console.log('test-access-logs-credentials: OK');
})().catch(error => {
    console.error('test-access-logs-credentials FAILED:', error);
    process.exit(1);
});
