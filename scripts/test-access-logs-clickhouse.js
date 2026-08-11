/**
 * Tests for the ClickHouse access-logs layer.
 *
 * Two parts:
 *   1. Offline (always runs): the schema DDL is well-formed and honors the
 *      retention value, and the CH_LINE_RE regex parses representative Xray
 *      access lines into the same fields the materialized view derives. The
 *      regex is RE2-flavored but also valid JS, so we exercise it directly.
 *   2. Online (only when CLICKHOUSE_TEST_URL is set): a real end-to-end check —
 *      ensure schema, insert raw rows, and read them back parsed. Skipped
 *      otherwise so CI without a ClickHouse stays green.
 */

const assert = require('assert');

// Point at a temp dir so requiring settings-backed modules is harmless.
const os = require('os');
const path = require('path');
const fs = require('fs');
process.env.PANEL_DOMAIN ||= 'panel.example.invalid';
process.env.ACME_EMAIL ||= 'admin@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';
process.env.ACCESS_LOGS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'al-ch-'));

const clickhouse = require('../src/services/accessLogs/clickhouseService');

function routeHandler(router, routePath, method = 'get') {
    const layer = router.stack.find(item => item.route?.path === routePath && item.route.methods?.[method]);
    assert.ok(layer, `${method.toUpperCase()} ${routePath} exists`);
    return layer.route.stack[layer.route.stack.length - 1].handle;
}

function responseRecorder() {
    return {
        statusCode: 200,
        body: undefined,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(value) {
            this.body = value;
            return this;
        },
        send(value) {
            this.body = value;
            return this;
        },
    };
}

// Reproduce the materialized-view parse in JS from the shared regex, so we can
// assert the field extraction without a live server.
function parseLikeMv(raw) {
    const re = new RegExp(clickhouse.CH_LINE_RE);
    const m = re.exec(raw);
    if (!m) return { parse_ok: 0 };
    const src = (m[2] || '').replace(/^from /, '');
    const dst = m[5] || '';
    const route = m[6] || '';
    const splitRight = (s) => {
        const mm = /^(.*):(\d+)$/.exec(s);
        return mm ? { host: mm[1], port: Number(mm[2]) } : { host: s, port: 0 };
    };
    const sp = splitRight(src);
    const dp = splitRight(dst);
    const dstIsIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(dp.host) || dp.host.includes(':');
    const parts = route.split('->');
    return {
        parse_ok: 1,
        event_time: (m[1] || '').replace(/\//g, '-'),
        source_ip: sp.host,
        source_port: sp.port,
        dest_host: dstIsIp ? '' : dp.host,
        dest_ip: dstIsIp ? dp.host : '',
        dest_port: dp.port,
        network: m[4] || '',
        action: m[3] || '',
        inbound_tag: (parts[0] || '').trim(),
        outbound_tag: (parts[1] || '').trim(),
        email: m[7] || '',
    };
}

async function offlineTests() {
    // Schema DDL: three statements, retention inlined, tables named as expected.
    const ddl = clickhouse.schemaStatements(45);
    assert.strictEqual(ddl.length, 3, 'three schema statements');
    assert.ok(ddl[0].includes('access_ingest') && ddl[0].includes('ENGINE = Null'), 'ingest is Null engine');
    assert.ok(ddl[1].includes('access_events') && ddl[1].includes('MergeTree'), 'events is MergeTree');
    assert.ok(ddl[1].includes('INTERVAL 45 DAY'), 'retention honored');
    assert.ok(ddl[1].includes("DateTime('UTC')"), 'event_time pinned to UTC');
    assert.ok(ddl[2].includes('MATERIALIZED VIEW') && ddl[2].includes('access_events_mv_v5'), 'current mv defined');

    // The regex is inlined into a ClickHouse string literal, where a lone
    // backslash is an escape character: every backslash must arrive doubled or
    // the character classes ("\d", "\S") silently degrade to plain letters.
    const mvDdl = ddl[2];
    assert.ok(mvDdl.includes('\\\\d{4}/\\\\d{2}/\\\\d{2}'), 'regex backslashes doubled for SQL literal');
    assert.ok(!/[^\\]\\d\{4\}/.test(mvDdl), 'no single-backslash \\d leaked into the DDL');
    // Timestamp normalization must replace EVERY slash, not just the first.
    assert.ok(mvDdl.includes('replaceAll(ts_str'), 'date slashes replaced with replaceAll');
    // Unparsed lines must not land in 1970 (instantly TTL-dropped).
    assert.ok(mvDdl.includes("now('UTC')"), 'zero timestamps fall back to now()');
    // Connection-level error lines are parsed via the fallback regex and tagged.
    assert.ok(mvDdl.includes('handshake-error'), 'handshake-error fallback tag present');
    assert.ok(mvDdl.includes('ne > 0'), 'error-line group participates in parse_ok');

    // The fallback regex matches an error line but NOT as an access record.
    const errLine = '2026/07/10 17:41:28.205208 from 95.24.24.226:9048 rejected proxy/vless/encoding: invalid request user id: 55837f55-c7ee-4533-b2a6-0ace8a266802';
    assert.strictEqual(parseLikeMv(errLine).parse_ok, 0, 'error line is not a normal access record');
    const errRe = new RegExp(clickhouse.CH_ERR_RE);
    const em = errRe.exec(errLine);
    assert.ok(em, 'error line matches fallback regex');
    assert.strictEqual(em[2], '95.24.24.226:9048', 'fallback captures source');
    assert.strictEqual(em[3], 'rejected', 'fallback captures action');
    // A real access line must still be handled by the primary parser, not misrouted.
    assert.ok(errRe.exec('2023/11/22 17:01:32 1.2.3.4:1122 accepted tcp:example.com:443 [in -> direct]'),
        'fallback also matches normal lines (primary takes precedence in the MV)');

    // Retention clamps to sane bounds (0/NaN falls back to the 30-day default).
    assert.ok(clickhouse.schemaStatements(-5)[1].includes('INTERVAL 1 DAY'), 'retention floor');
    assert.ok(clickhouse.schemaStatements(99999)[1].includes('INTERVAL 3650 DAY'), 'retention ceiling');
    assert.ok(clickhouse.schemaStatements(0)[1].includes('INTERVAL 30 DAY'), 'retention default on 0');

    // Regex parse: a typical accepted TCP line with host destination + email.
    const a = parseLikeMv('2023/11/22 17:01:32 1.2.3.4:1122 accepted tcp:example.com:443 [vless-in -> direct] email: 42');
    assert.strictEqual(a.parse_ok, 1, 'line A parsed');
    assert.strictEqual(a.event_time, '2023-11-22 17:01:32', 'ts normalized');
    assert.strictEqual(a.source_ip, '1.2.3.4');
    assert.strictEqual(a.source_port, 1122);
    assert.strictEqual(a.dest_host, 'example.com');
    assert.strictEqual(a.dest_ip, '');
    assert.strictEqual(a.dest_port, 443);
    assert.strictEqual(a.network, 'tcp');
    assert.strictEqual(a.action, 'accepted');
    assert.strictEqual(a.inbound_tag, 'vless-in');
    assert.strictEqual(a.outbound_tag, 'direct');
    assert.strictEqual(a.email, '42');

    // UDP line to an IP destination, "from " prefix, fractional seconds.
    const b = parseLikeMv('2024/05/01 08:12:00.123456 from 9.9.9.9:5555 accepted udp:8.8.8.8:53 [in -> out] email: user@x');
    assert.strictEqual(b.parse_ok, 1, 'line B parsed');
    assert.strictEqual(b.source_ip, '9.9.9.9');
    assert.strictEqual(b.dest_ip, '8.8.8.8', 'ip destination goes to dest_ip');
    assert.strictEqual(b.dest_host, '', 'no host for ip destination');
    assert.strictEqual(b.dest_port, 53);
    assert.strictEqual(b.network, 'udp');
    assert.strictEqual(b.email, 'user@x');

    // cc-agent normalizes HY2 journal events to this same contract. Exercise
    // the exported production regex (rather than a copied Go equivalent) so a
    // future ClickHouse parser change cannot silently turn HY2 rows parse_ok=0.
    const hy2 = parseLikeMv('2026/08/10 12:34:56.123 [2001:db8::10]:4567 accepted udp:dns.example:53 [hysteria2/session-37 -> direct] email: user-42');
    assert.strictEqual(hy2.parse_ok, 1, 'normalized HY2 line parsed');
    assert.strictEqual(hy2.source_ip, '[2001:db8::10]');
    assert.strictEqual(hy2.source_port, 4567);
    assert.strictEqual(hy2.dest_host, 'dns.example');
    assert.strictEqual(hy2.dest_port, 53);
    assert.strictEqual(hy2.inbound_tag, 'hysteria2/session-37');
    assert.strictEqual(hy2.outbound_tag, 'direct');
    assert.strictEqual(hy2.email, 'user-42');

    // Existing subscription account IDs may contain internal ASCII spaces.
    // The email/userId field is the final field, so capture it greedily while
    // still rejecting leading/trailing whitespace in the normalized contract.
    const hy2SpacedAccount = parseLikeMv('2026/08/10 12:35:00 203.0.113.7:4567 accepted tcp:example.com:443 [hysteria2 -> direct] email: Team Alice');
    assert.strictEqual(hy2SpacedAccount.parse_ok, 1, 'HY2 account with internal space parsed');
    assert.strictEqual(hy2SpacedAccount.email, 'Team Alice');

    // Blocked line without email/route still parses.
    const c = parseLikeMv('2024/05/01 08:12:00 5.5.5.5:1000 blocked tcp:ads.example.net:80');
    assert.strictEqual(c.parse_ok, 1, 'line C parsed');
    assert.strictEqual(c.action, 'blocked');
    assert.strictEqual(c.email, '', 'no email');

    // Garbage line does not match.
    const d = parseLikeMv('this is not an xray line');
    assert.strictEqual(d.parse_ok, 0, 'garbage rejected');

    // Timestamps must leave ClickHouse as Unix epoch seconds, never as strings
    // built with formatDateTime. formatDateTime('%M'/'%i') is version-fragile:
    // %M flipped from "minutes" to "month name" in newer ClickHouse, which
    // produced garbage like "21:July:54" that Date() then misparsed. Guard the
    // read-side SQL so no one reintroduces it.
    const searchSrc = fs.readFileSync(
        path.join(__dirname, '..', 'src', 'services', 'accessLogs', 'searchService.js'), 'utf8');
    assert.ok(searchSrc.includes('toUnixTimestamp('), 'searchService emits epoch via toUnixTimestamp');
    assert.ok(!/formatDateTime\s*\(/.test(searchSrc), 'searchService must not use formatDateTime for output');

    // Analytics must never count parse failures (for example, ordinary Xray
    // warnings from an older journal-capable agent). Raw search intentionally
    // keeps them available as diagnostics.
    const searchService = require('../src/services/accessLogs/searchService');
    const originalIsConfigured = clickhouse.isConfigured;
    const originalQuery = clickhouse.query;
    const analyticsSql = [];
    try {
        clickhouse.isConfigured = async () => true;
        clickhouse.query = async sql => {
            analyticsSql.push(sql);
            return { ok: true, rows: [] };
        };
        await searchService.overview({ email: 'user-42' });
        await searchService.userIps('user-42');
        await searchService.ipViolators(60, 5);
        await searchService.ipsForUser('user-42', 60, 20);
        assert.strictEqual(analyticsSql.length, 10, 'all analytics queries captured');
        for (const sql of analyticsSql) {
            assert.ok(/parse_ok\s*=\s*1/.test(sql), `analytics query must filter parse failures: ${sql}`);
        }

        const overviewSql = analyticsSql.slice(0, 7);
        const totalsSql = overviewSql.find(sql => /count\(\) AS total/.test(sql));
        assert.ok(totalsSql, 'overview totals query captured');
        assert.ok(/uniqExactIf\(email,\s*email != ''\) AS users/.test(totalsSql),
            'empty email must not count as a user');
        assert.ok(/uniqExactIf\(source_ip,\s*source_ip != ''\) AS ips/.test(totalsSql),
            'empty source IP must not count as an IP');
        assert.ok(/uniqExactIf\([^\n]+,\s*[^\n]+ != ''\) AS dests/.test(totalsSql),
            'empty destination must not count as a destination');

        const usersByIpSql = overviewSql.find(sql => /ORDER BY ips DESC, events DESC, email ASC/.test(sql));
        const usersByFanoutSql = overviewSql.find(sql => /ORDER BY dests DESC, events DESC, email ASC/.test(sql));
        assert.ok(usersByIpSql, 'IP leaderboard is globally ordered in ClickHouse');
        assert.ok(usersByFanoutSql, 'fan-out leaderboard is independently and globally ordered in ClickHouse');
        for (const sql of [usersByIpSql, usersByFanoutSql]) {
            assert.ok(/uniqExactIf\(source_ip,\s*source_ip != ''\) AS ips/.test(sql),
                'user aggregates exclude empty source IPs');
            assert.ok(/AS dests/.test(sql) && /!= ''/.test(sql),
                'user aggregates exclude empty destinations');
        }

        analyticsSql.length = 0;
        await searchService.search({ q: 'warning' });
        assert.strictEqual(analyticsSql.length, 1, 'raw search query captured');
        assert.ok(!/parse_ok\s*=\s*1/.test(analyticsSql[0]), 'raw diagnostics retain parse failures');
        assert.ok(/ORDER BY event_time DESC, node_id ASC, email ASC, source_ip ASC, raw ASC/.test(analyticsSql[0]),
            'default raw search has deterministic tie-breakers');

        analyticsSql.length = 0;
        await searchService.search({}, { sort: 'email', dir: 'asc' });
        assert.ok(/ORDER BY email ASC, event_time DESC, node_id ASC, source_ip ASC, raw ASC/.test(analyticsSql[0]),
            'custom search sort retains deterministic tie-breakers without duplicating the primary column');

        // The two user lenses must carry independent result sets while `users`
        // remains the backwards-compatible alias for the IP-ranked list.
        const resultRows = [
            [{ total: 9, users: 2, ips: 3, dests: 4 }],
            [{ bucket: 1, hits: 9 }],
            [{ dest: 'example.com', hits: 4 }],
            [{ port: 443, hits: 4 }],
            [{ dest: 'blocked.example', hits: 2 }],
            [{ email: 'ip-leader', ips: 9, dests: 2 }],
            [{ email: 'fanout-leader', ips: 1, dests: 99 }],
        ];
        let queryIndex = 0;
        clickhouse.query = async () => ({ ok: true, rows: resultRows[queryIndex++] });
        const complete = await searchService.overview();
        assert.strictEqual(complete.degraded, false, 'complete overview is not degraded');
        assert.strictEqual(complete.partial, false, 'complete overview is not partial');
        assert.deepStrictEqual(complete.partialErrors, {}, 'complete overview has no partial errors');
        assert.deepStrictEqual(complete.usersByIp, resultRows[5], 'IP leaderboard returned separately');
        assert.deepStrictEqual(complete.usersByFanout, resultRows[6], 'fan-out leaderboard returned separately');
        assert.deepStrictEqual(complete.users, resultRows[5], 'legacy users aliases the IP leaderboard');

        // Every non-total query can fail independently without erasing the
        // successful widgets. Its name and error must be explicit in the schema.
        const optionalNames = [
            'series', 'topDestinations', 'topPorts', 'topBlocked', 'usersByIp', 'usersByFanout',
        ];
        for (let failedIndex = 1; failedIndex < resultRows.length; failedIndex++) {
            queryIndex = 0;
            clickhouse.query = async () => {
                const index = queryIndex++;
                return index === failedIndex
                    ? { ok: false, error: `failed-${optionalNames[failedIndex - 1]}` }
                    : { ok: true, rows: resultRows[index] };
            };
            const partial = await searchService.overview();
            const failedName = optionalNames[failedIndex - 1];
            assert.strictEqual(partial.degraded, true, `${failedName} failure marks overview degraded`);
            assert.strictEqual(partial.partial, true, `${failedName} failure marks overview partial`);
            assert.deepStrictEqual(partial.partialErrors, { [failedName]: `failed-${failedName}` },
                `${failedName} error is attributed explicitly`);
            assert.deepStrictEqual(partial.totals, resultRows[0][0], 'partial overview preserves totals');
        }
    } finally {
        clickhouse.isConfigured = originalIsConfigured;
        clickhouse.query = originalQuery;
    }

    // Route contract: public `limit` is the number returned, while the service
    // receives limit+1 so the route can calculate hasMore without COUNT(*).
    const Settings = require('../src/models/settingsModel');
    const accessLogsRouter = require('../src/routes/panel/accessLogs');
    const searchRoute = routeHandler(accessLogsRouter, '/access-logs/api/search');
    const analyticsRoute = routeHandler(accessLogsRouter, '/access-logs/api/analytics');
    const originalSettingsGet = Settings.get;
    const originalSearch = searchService.search;
    const originalOverview = searchService.overview;
    try {
        Settings.get = async () => ({ accessLogs: { enabled: true } });

        let capturedSearch;
        searchService.search = async (filters, opts) => {
            capturedSearch = { filters, opts };
            return { rows: [{ id: 1 }, { id: 2 }, { id: 3 }] };
        };
        let res = responseRecorder();
        await searchRoute({ query: { email: 'user-42', limit: '2', offset: '3' } }, res);
        assert.deepStrictEqual(capturedSearch.filters, { email: 'user-42' }, 'route forwards filters');
        assert.strictEqual(capturedSearch.opts.limit, 3, 'route overfetches one row');
        assert.strictEqual(capturedSearch.opts.offset, 3, 'route forwards normalized offset');
        assert.deepStrictEqual(res.body.rows, [{ id: 1 }, { id: 2 }], 'sentinel row is not returned');
        assert.strictEqual(res.body.hasMore, true, 'sentinel row sets hasMore');
        assert.strictEqual(res.body.limit, 2, 'response exposes public limit');
        assert.strictEqual(res.body.offset, 3, 'response exposes current offset');

        searchService.search = async (filters, opts) => {
            capturedSearch = { filters, opts };
            return { rows: [{ id: 1 }, { id: 2 }] };
        };
        res = responseRecorder();
        await searchRoute({ query: { limit: '2', offset: '-10' } }, res);
        assert.strictEqual(capturedSearch.opts.offset, 0, 'negative offset clamps to zero');
        assert.strictEqual(res.body.hasMore, false, 'an exact-size page has no sentinel');

        searchService.search = async (filters, opts) => {
            capturedSearch = { filters, opts };
            return { rows: [] };
        };
        res = responseRecorder();
        await searchRoute({ query: { limit: '99999' } }, res);
        assert.strictEqual(capturedSearch.opts.limit, 1001, 'public limit clamps to 1000 before overfetch');
        assert.strictEqual(res.body.limit, 1000, 'response reports the clamped public limit');

        // Full degradation payloads include both new arrays and the legacy one.
        searchService.overview = async () => ({ degraded: true });
        res = responseRecorder();
        await analyticsRoute({ query: {} }, res);
        assert.deepStrictEqual(res.body.users, [], 'degraded payload has legacy users array');
        assert.deepStrictEqual(res.body.usersByIp, [], 'degraded payload has IP leaderboard array');
        assert.deepStrictEqual(res.body.usersByFanout, [], 'degraded payload has fan-out leaderboard array');
        assert.strictEqual(res.body.partial, false, 'full degradation is not partial');

        // A partial result must pass successful widgets through instead of being
        // collapsed into the full ClickHouse-required response.
        searchService.overview = async () => ({
            degraded: true,
            partial: true,
            partialErrors: { series: 'timeout' },
            totals: { total: 7 },
            series: [],
            topDestinations: [{ dest: 'example.com', hits: 7 }],
            topPorts: [],
            topBlocked: [],
            users: [{ email: 'ip-leader' }],
            usersByIp: [{ email: 'ip-leader' }],
            usersByFanout: [{ email: 'fanout-leader' }],
        });
        res = responseRecorder();
        await analyticsRoute({ query: {} }, res);
        assert.strictEqual(res.body.partial, true, 'route preserves partial marker');
        assert.strictEqual(res.body.degraded, true, 'route preserves degraded marker');
        assert.deepStrictEqual(res.body.partialErrors, { series: 'timeout' }, 'route preserves partial errors');
        assert.deepStrictEqual(res.body.totals, { total: 7 }, 'route preserves successful totals');
        assert.deepStrictEqual(res.body.usersByFanout, [{ email: 'fanout-leader' }],
            'route preserves independent fan-out results');
    } finally {
        Settings.get = originalSettingsGet;
        searchService.search = originalSearch;
        searchService.overview = originalOverview;
    }

    console.log('  offline: schema + regex + epoch SQL guard OK');
}

async function onlineTests() {
    const url = process.env.CLICKHOUSE_TEST_URL;
    if (!url) {
        console.log('  online: skipped (set CLICKHOUSE_TEST_URL to run)');
        return;
    }
    // Configure the service via an in-memory settings stub.
    const u = new URL(url);
    const Settings = require('../src/models/settingsModel');
    Settings.get = async () => ({
        accessLogs: {
            retentionDays: 7,
            clickhouse: {
                host: u.hostname,
                port: Number(u.port) || 8123,
                database: u.pathname.replace(/^\//, '') || 'default',
                username: decodeURIComponent(u.username) || 'default',
                passwordEncrypted: '',
                secure: u.protocol === 'https:',
            },
        },
    });
    // Password comes plain from the URL for the test.
    const orig = clickhouse.readConfig;
    clickhouse.reset();

    const ping = await clickhouse.ping();
    assert.ok(ping.ok, `ping ok: ${ping.error || ''}`);

    await clickhouse.ensureSchema(7);

    const batchId = 'test-batch-' + Date.now();
    await clickhouse.insertRaw([
        { node_id: 'n1', raw: '2023/11/22 17:01:32 1.2.3.4:1122 accepted tcp:example.com:443 [vless-in -> direct] email: 42' },
        { node_id: 'n1', raw: '2023/11/22 17:01:33 from 9.9.9.9:5000 rejected proxy/vless/encoding: invalid request user id: abc' },
    ], batchId);

    // Give the MV a moment (insert is synchronous, but read is eventually there).
    const res = await clickhouse.query("SELECT email, network, dest_host FROM access_events WHERE email = '42' LIMIT 1");
    assert.ok(res.ok, `read ok: ${res.error || ''}`);
    assert.ok(res.rows.length >= 1, 'row present after MV parse');
    assert.strictEqual(res.rows[0].network, 'tcp');
    assert.strictEqual(res.rows[0].dest_host, 'example.com');

    // The connection-error line parsed via fallback: rejected, source set, tagged.
    const errRes = await clickhouse.query(
        "SELECT source_ip, action, outbound_tag, parse_ok FROM access_events WHERE source_ip = '9.9.9.9' LIMIT 1");
    assert.ok(errRes.ok && errRes.rows.length >= 1, 'error line stored');
    assert.strictEqual(errRes.rows[0].action, 'rejected', 'error line action');
    assert.strictEqual(errRes.rows[0].outbound_tag, 'handshake-error', 'error line tagged');
    assert.strictEqual(Number(errRes.rows[0].parse_ok), 1, 'error line counts as parsed');

    await clickhouse.truncate();
    void orig;
    console.log('  online: end-to-end OK');
}

(async () => {
    await offlineTests();
    await onlineTests();
    console.log('test-access-logs-clickhouse: OK');
    process.exit(0);
})().catch((e) => {
    console.error('test-access-logs-clickhouse FAILED:', e);
    process.exit(1);
});
