/**
 * End-to-end-ish test for the panel-side ingest spool + processor (no HTTP, no
 * ClickHouse). Verifies:
 *   - persistBatch writes an atomic sealed file and lists it,
 *   - the processor parses NDJSON into { node_id, raw } rows,
 *   - client-IP masking rewrites the raw line in place,
 *   - with ClickHouse not configured, the batch stays spooled (never acked
 *     without a persisted write) — the at-least-once invariant.
 *
 * Batch dedup lives in Redis (cacheService), so it is not exercised here.
 *
 * Uses a throwaway ACCESS_LOGS_DIR so it never touches real data.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const zlib = require('zlib');
const assert = require('assert');

// Point the pipeline at a temp dir BEFORE requiring modules that read it.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'al-ingest-'));
process.env.ACCESS_LOGS_DIR = TMP;

// No MongoDB in this test: disable mongoose op buffering so a settings read
// (used to check the maskClientIp flag) fails fast instead of hanging.
try { require('mongoose').set('bufferTimeoutMS', 1); } catch (_) { /* mongoose optional */ }

(async () => {
    const spoolService = require('../src/services/accessLogs/spoolService');
    const processService = require('../src/services/accessLogs/processService');
    const crypto = require('crypto');

    const nodeId = 'node123';

    function xrayLine(d, ip) {
        const y = d.getUTCFullYear();
        const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
        const da = String(d.getUTCDate()).padStart(2, '0');
        const h = String(d.getUTCHours()).padStart(2, '0');
        const mi = String(d.getUTCMinutes()).padStart(2, '0');
        const s = String(d.getUTCSeconds()).padStart(2, '0');
        return `${y}/${mo}/${da} ${h}:${mi}:${s} ${ip}:5555 accepted tcp:example.com:443 [vless-in -> direct] email: user@x`;
    }
    const line = xrayLine(new Date(), '1.2.3.4');

    const ndjson =
        JSON.stringify({ offset: 10, raw: line, read_at: new Date().toISOString() }) + '\n';
    const gz = zlib.gzipSync(Buffer.from(ndjson, 'utf8'));
    const batchId = crypto.createHash('sha256').update(gz).digest('hex');

    // Persist + verify it is listed.
    const { path: spoolPath } = await spoolService.persistBatch(nodeId, batchId, gz);
    assert.ok(fs.existsSync(spoolPath), 'spool file exists');
    let list = await spoolService.listSpool();
    assert.strictEqual(list.length, 1, 'one spooled batch');

    // parseSpoolFile yields raw rows tagged with the node id.
    const parsed = await processService.parseSpoolFile(spoolPath, false);
    assert.strictEqual(parsed.rows.length, 1, 'one parsed row');
    assert.strictEqual(parsed.rows[0].node_id, nodeId, 'row tagged with node id');
    assert.ok(parsed.rows[0].raw.includes('1.2.3.4'), 'raw line preserved');

    // One physical cc-agent can follow several HY2 systemd units. A runtime
    // tag maps those events to the matching logical panel node before insert;
    // unknown/legacy tags safely remain on the authenticated physical node.
    const physicalNodeId = '507f1f77bcf86cd799439010';
    const mobileNodeId = '507f1f77bcf86cd799439011';
    const runtimeMap = processService.buildRuntimeNodeMap([
        { tag: 'mobile', nodeId: mobileNodeId },
        { tag: 'bad-node-id', nodeId: 'not-an-object-id' },
    ]);
    const mobileHy2Line = '2026/08/11 12:00:00 203.0.113.5:5000 accepted udp:dns.example:53 [hysteria2/mobile/session-7 -> direct] email: user@x';
    assert.strictEqual(
        processService.resolveRuntimeNodeId(physicalNodeId, mobileHy2Line, runtimeMap),
        mobileNodeId,
        'a tagged HY2 record is attributed to its mapped panel node'
    );
    assert.strictEqual(
        processService.resolveRuntimeNodeId(physicalNodeId, mobileHy2Line.replace('/mobile', '/unknown'), runtimeMap),
        physicalNodeId,
        'unknown runtime tags cannot claim an arbitrary panel node'
    );
    assert.strictEqual(
        processService.resolveRuntimeNodeId(physicalNodeId, line, runtimeMap),
        physicalNodeId,
        'Xray and legacy records retain their authenticated physical node'
    );

    // IP masking primitives: IPv4 keeps /24, IPv6 keeps three hextets.
    assert.strictEqual(processService.maskIp('192.168.1.33'), '192.168.1.0', 'IPv4 masked to /24');
    assert.strictEqual(processService.maskIp('2001:db8:abcd:12:34::1'), '2001:db8:abcd::', 'IPv6 masked');
    assert.strictEqual(processService.maskIp(''), '', 'empty stays empty');

    // Masking rewrites the source IP in the raw line (/24).
    const masked = processService.maskRawLine(line);
    assert.ok(masked.includes('1.2.3.0'), 'masked to /24');
    assert.ok(!masked.includes('1.2.3.4:'), 'original source ip scrubbed');

    // HY2's net.Addr uses bracketed IPv6 endpoints. The complete address must
    // be masked rather than only the text before the first colon.
    const hy2V6 = line.replace('1.2.3.4:5555', '[2001:db8:abcd:12:34::1]:5555');
    const maskedV6 = processService.maskRawLine(hy2V6);
    assert.ok(maskedV6.includes('[2001:db8:abcd::]:5555'), 'bracketed IPv6 endpoint masked');
    assert.ok(!maskedV6.includes('abcd:12:34'), 'exact IPv6 suffix scrubbed');

    const prefixedV6 = line.replace('1.2.3.4:5555', 'tcp:[2001:db8:abcd:12::9]:5555');
    const maskedPrefixedV6 = processService.maskRawLine(prefixedV6);
    assert.ok(maskedPrefixedV6.includes('tcp:[2001:db8:abcd::]:5555'), 'transport prefix preserved');

    const compressedV6 = line.replace('1.2.3.4:5555', '[2001::dead:beef]:5555');
    const maskedCompressedV6 = processService.maskRawLine(compressedV6);
    assert.ok(maskedCompressedV6.includes('[2001:0:0::]:5555'), 'compressed IPv6 masked to /48');
    assert.ok(!maskedCompressedV6.includes('dead:beef'), 'compressed IPv6 host bits scrubbed');

    const shortCompressedV6 = line.replace('1.2.3.4:5555', '[2001:db8::10]:5555');
    assert.ok(
        processService.maskRawLine(shortCompressedV6).includes('[2001:db8:0::]:5555'),
        'compressed IPv6 produces a valid masked address'
    );

    // Drain with ClickHouse NOT configured: batch must stay spooled (never ack
    // without a persisted write) — the at-least-once invariant.
    await processService.drainOnce();
    list = await spoolService.listSpool();
    assert.strictEqual(list.length, 1, 'batch stays spooled when ClickHouse not configured');

    await fsp.rm(TMP, { recursive: true, force: true });
    console.log('test-access-logs-ingest: OK');
})().catch(async (e) => {
    console.error('test-access-logs-ingest FAILED:', e);
    try { await fsp.rm(TMP, { recursive: true, force: true }); } catch (_) {}
    process.exit(1);
});
