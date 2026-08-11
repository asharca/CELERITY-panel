/**
 * Search & analytics over the ClickHouse access-log store (read side).
 *
 * Builds parameterized ClickHouse SQL (using {name:Type} placeholders bound via
 * query_params) against the access_events table. All user input is bound as
 * parameters, never interpolated. ClickHouse does the heavy lifting on its own
 * server, so the panel stays light and queries can run concurrently.
 *
 * When ClickHouse is not configured/reachable the service returns
 * { degraded: true } so callers can render a "configure ClickHouse" banner
 * instead of throwing.
 */

const clickhouse = require('./clickhouseService');
const logger = require('../../utils/logger');

const MAX_ROW_LIMIT = 5000;
const DEFAULT_ROW_LIMIT = 200;

// Whitelisted sortable columns to avoid any injection via ORDER BY.
const SORTABLE = new Set(['event_time', 'email', 'source_ip', 'dest_host', 'dest_ip', 'action', 'network']);

// Translate high-level filters into a parameterized WHERE + a params object for
// ClickHouse query_params. Returns { where, params } where `where` already
// includes the leading "WHERE" (or is empty).
function buildWhere(filters = {}) {
    const clauses = [];
    const params = {};

    // Time bounds are passed as unix seconds and materialized as UTC DateTimes,
    // so comparisons never depend on the ClickHouse server timezone.
    if (filters.from instanceof Date) {
        clauses.push("event_time >= toDateTime({from:UInt32}, 'UTC')");
        params.from = toUnixSeconds(filters.from);
    }
    if (filters.to instanceof Date) {
        clauses.push("event_time <= toDateTime({to:UInt32}, 'UTC')");
        params.to = toUnixSeconds(filters.to);
    }
    if (filters.nodeId) { clauses.push('node_id = {nodeId:String}'); params.nodeId = String(filters.nodeId); }
    if (filters.email) { clauses.push('email = {email:String}'); params.email = String(filters.email); }
    if (filters.sourceIp) { clauses.push('source_ip = {sourceIp:String}'); params.sourceIp = String(filters.sourceIp); }
    if (filters.action) { clauses.push('action = {action:String}'); params.action = String(filters.action); }
    if (filters.network) { clauses.push('network = {network:String}'); params.network = String(filters.network); }

    // Destination matched against host OR ip with a case-insensitive substring.
    if (filters.destination) {
        clauses.push('(positionCaseInsensitive(dest_host, {dest:String}) > 0 OR positionCaseInsensitive(dest_ip, {dest:String}) > 0)');
        params.dest = String(filters.destination);
    }

    // Free-text search across the raw line.
    if (filters.q) {
        clauses.push('positionCaseInsensitive(raw, {q:String}) > 0');
        params.q = String(filters.q);
    }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return { where, params };
}

function toUnixSeconds(d) {
    return Math.max(0, Math.floor(d.getTime() / 1000));
}

// Analytics count only structured access events. Raw search deliberately keeps
// parse_ok=0 rows available for diagnostics and legacy-data inspection.
function parsedEventsWhere(where) {
    return where ? `${where} AND parse_ok = 1` : 'WHERE parse_ok = 1';
}

/**
 * Paged search returning individual events, newest first by default.
 * @returns {Promise<{degraded?:boolean, rows?:Array, error?:string}>}
 */
async function search(filters = {}, opts = {}) {
    if (!(await clickhouse.isConfigured())) {
        return { degraded: true, rows: [] };
    }

    const { where, params } = buildWhere(filters);
    const sortCol = SORTABLE.has(opts.sort) ? opts.sort : 'event_time';
    const sortDir = opts.dir === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.max(1, Math.min(MAX_ROW_LIMIT, Number(opts.limit) || DEFAULT_ROW_LIMIT));
    const offset = Math.max(0, Number(opts.offset) || 0);
    // DateTime is stored at second precision, so event_time alone is not a
    // stable order for offset pagination. Add deterministic value tie-breakers;
    // byte-for-byte duplicate rows remain interchangeable to API consumers.
    const tieBreakers = [
        ['event_time', 'DESC'],
        ['node_id', 'ASC'],
        ['email', 'ASC'],
        ['source_ip', 'ASC'],
        ['raw', 'ASC'],
    ].filter(([column]) => column !== sortCol);
    const orderBy = [
        `${sortCol} ${sortDir}`,
        ...tieBreakers.map(([column, direction]) => `${column} ${direction}`),
    ].join(', ');

    // Times are returned as Unix epoch seconds (absolute instants), not
    // formatted strings. This is version-independent (no reliance on
    // formatDateTime specifiers like %M, whose meaning changed across
    // ClickHouse versions) and timezone-safe — the client renders them in the
    // viewer's local zone. Aliases stay the same so the API shape is unchanged.
    const sql = `
        SELECT
            toUnixTimestamp(event_time) AS ts,
            node_id, email, source_ip, source_port,
            dest_host, dest_ip, dest_port, network,
            inbound_tag, outbound_tag, action, raw, parse_ok
        FROM access_events
        ${where}
        ORDER BY ${orderBy}
        LIMIT ${limit} OFFSET ${offset}
    `;

    const res = await clickhouse.query(sql, params, { timeoutMs: opts.timeoutMs || 30000 });
    if (!res.ok) {
        if (res.error === 'not_configured') return { degraded: true, rows: [] };
        logger.warn(`[AccessLogs] search failed: ${res.error}`);
        return { error: res.error, rows: [] };
    }
    return { rows: res.rows };
}

/**
 * Distinct source IPs a single user connected from, within the filter window —
 * powers the expandable "all IPs for this user" detail row. Ordered by activity.
 * @returns {Promise<{degraded?:boolean, rows?:Array, error?:string}>}
 */
async function userIps(email, filters = {}, opts = {}) {
    if (!(await clickhouse.isConfigured())) {
        return { degraded: true, rows: [] };
    }
    const built = buildWhere({ ...filters, email: String(email || '') });
    const where = parsedEventsWhere(built.where);
    const params = built.params;
    const limit = Math.max(1, Math.min(500, Number(opts.limit) || 200));

    const sql = `
        SELECT
            source_ip AS ip,
            count() AS events,
            uniqExact(if(dest_host != '', dest_host, dest_ip)) AS dests,
            toUnixTimestamp(max(event_time)) AS last_seen,
            toUnixTimestamp(min(event_time)) AS first_seen
        FROM access_events
        ${where} AND source_ip != ''
        GROUP BY source_ip
        ORDER BY events DESC
        LIMIT ${limit}
    `;

    const res = await clickhouse.query(sql, params, { timeoutMs: opts.timeoutMs || 30000 });
    if (!res.ok) {
        if (res.error === 'not_configured') return { degraded: true, rows: [] };
        logger.warn(`[AccessLogs] userIps failed: ${res.error}`);
        return { error: res.error, rows: [] };
    }
    return { rows: res.rows };
}

/**
 * Combined dashboard overview: totals + action/protocol split, an hourly time
 * series (with per-action breakdown), top destinations/ports/blocked, and a
 * per-user aggregate for the "users by IP count" (sharing lens) and "users by
 * fan-out" (abuse lens) tables. All filters are bound as parameters.
 *
 * ClickHouse runs each query independently on its own server, so these fire
 * concurrently. Same result shape as before so the route/UI stay unchanged.
 */
async function overview(filters = {}, opts = {}) {
    if (!(await clickhouse.isConfigured())) {
        return { degraded: true };
    }

    const built = buildWhere(filters);
    const where = parsedEventsWhere(built.where);
    const params = built.params;
    const andWhere = 'AND';
    const topN = Math.max(1, Math.min(50, Number(opts.topN) || 10));
    const userN = Math.max(1, Math.min(200, Number(opts.userLimit) || 25));

    // "dest" = human destination: host when present, else IP.
    const DEST = "if(dest_host != '', dest_host, dest_ip)";
    // "/24" subnet for IPv4 (strip last octet); IPv6 left intact.
    const SUBNET = "replaceRegexpOne(source_ip, '\\\\.[0-9]+$', '')";

    const totalsSql = `
        SELECT
            count() AS total,
            uniqExactIf(email, email != '') AS users,
            uniqExactIf(source_ip, source_ip != '') AS ips,
            uniqExactIf(${DEST}, ${DEST} != '') AS dests,
            countIf(action = 'accepted') AS accepted,
            countIf(action = 'rejected') AS rejected,
            countIf(action = 'blocked')  AS blocked,
            countIf(network = 'tcp') AS tcp,
            countIf(network = 'udp') AS udp
        FROM access_events ${where}`;

    const seriesSql = `
        SELECT
            toUnixTimestamp(toStartOfHour(event_time)) AS bucket,
            count() AS hits,
            countIf(action = 'accepted') AS accepted,
            countIf(action = 'rejected') AS rejected,
            countIf(action = 'blocked')  AS blocked
        FROM access_events ${where}
        GROUP BY bucket ORDER BY bucket`;

    const topDestSql = `
        SELECT ${DEST} AS dest, count() AS hits
        FROM access_events ${where} ${andWhere} ${DEST} != ''
        GROUP BY dest ORDER BY hits DESC LIMIT ${topN}`;

    const topPortsSql = `
        SELECT dest_port AS port, count() AS hits
        FROM access_events ${where} ${andWhere} dest_port != 0
        GROUP BY dest_port ORDER BY hits DESC LIMIT ${topN}`;

    const topBlockedSql = `
        SELECT ${DEST} AS dest, count() AS hits
        FROM access_events ${where} ${andWhere} action IN ('blocked','rejected') AND ${DEST} != ''
        GROUP BY dest ORDER BY hits DESC LIMIT ${topN}`;

    const usersBaseSql = `
        SELECT
            email,
            uniqExactIf(source_ip, source_ip != '') AS ips,
            uniqExactIf(${SUBNET}, source_ip != '') AS subnets,
            uniqExactIf(${DEST}, ${DEST} != '') AS dests,
            count() AS events,
            countIf(network = 'udp') / nullIf(count(), 0) AS udp_share,
            toUnixTimestamp(max(event_time)) AS last_seen
        FROM access_events ${where} ${andWhere} email != ''
        GROUP BY email`;

    // These are separate global rankings. Re-sorting an IP-limited candidate
    // set in the client can omit a low-IP user with exceptionally high fan-out.
    const usersByIpSql = `${usersBaseSql}
        ORDER BY ips DESC, events DESC, email ASC LIMIT ${userN}`;
    const usersByFanoutSql = `${usersBaseSql}
        ORDER BY dests DESC, events DESC, email ASC LIMIT ${userN}`;

    const timeoutMs = opts.timeoutMs || 30000;
    // Fire concurrently; ClickHouse handles the parallelism server-side.
    const [totals, series, topDest, topPorts, topBlocked, usersByIp, usersByFanout] = await Promise.all([
        clickhouse.query(totalsSql, params, { timeoutMs }),
        clickhouse.query(seriesSql, params, { timeoutMs }),
        clickhouse.query(topDestSql, params, { timeoutMs }),
        clickhouse.query(topPortsSql, params, { timeoutMs }),
        clickhouse.query(topBlockedSql, params, { timeoutMs }),
        clickhouse.query(usersByIpSql, params, { timeoutMs }),
        clickhouse.query(usersByFanoutSql, params, { timeoutMs }),
    ]);

    // If the very first query could not even connect, report degraded so the UI
    // shows the "configure ClickHouse" state rather than empty zeros.
    if (!totals.ok && totals.error === 'not_configured') return { degraded: true };
    if (!totals.ok) {
        logger.warn(`[AccessLogs] overview failed: ${totals.error}`);
        return { error: totals.error };
    }

    const optionalResults = {
        series,
        topDestinations: topDest,
        topPorts,
        topBlocked,
        usersByIp,
        usersByFanout,
    };
    const partialErrors = Object.fromEntries(
        Object.entries(optionalResults)
            .filter(([, result]) => !result.ok)
            .map(([name, result]) => [name, result.error || 'query_failed'])
    );
    const partial = Object.keys(partialErrors).length > 0;
    if (partial) {
        logger.warn(`[AccessLogs] overview partial failure: ${Object.entries(partialErrors)
            .map(([name, error]) => `${name}=${error}`)
            .join(', ')}`);
    }

    const usersByIpRows = (usersByIp.ok && usersByIp.rows) || [];
    const usersByFanoutRows = (usersByFanout.ok && usersByFanout.rows) || [];
    return {
        degraded: partial,
        partial,
        partialErrors,
        totals: (totals.rows && totals.rows[0]) || { total: 0, users: 0, ips: 0, dests: 0 },
        series: (series.ok && series.rows) || [],
        topDestinations: (topDest.ok && topDest.rows) || [],
        topPorts: (topPorts.ok && topPorts.rows) || [],
        topBlocked: (topBlocked.ok && topBlocked.rows) || [],
        // `users` remains an alias for the historical IP-ranked response shape.
        users: usersByIpRows,
        usersByIp: usersByIpRows,
        usersByFanout: usersByFanoutRows,
    };
}

/**
 * IP-sharing detection: users whose unique source-IP count over a sliding
 * window reaches `threshold`. Uses approximate uniq() (HyperLogLog) since exact
 * precision is not needed for a threshold alert, and HAVING pushes the filter
 * server-side so only violators travel back to the panel. Cheap enough to run
 * hourly against an external ClickHouse.
 *
 * @param {number} windowMinutes - sliding window length in minutes
 * @param {number} threshold     - minimum unique IPs to flag a user
 * @returns {Promise<{degraded?:boolean, rows?:Array, error?:string}>}
 *          rows: [{ email, ips }]
 */
async function ipViolators(windowMinutes, threshold, opts = {}) {
    if (!(await clickhouse.isConfigured())) {
        return { degraded: true, rows: [] };
    }
    const win = Math.max(1, Math.floor(Number(windowMinutes) || 60));
    const thr = Math.max(1, Math.floor(Number(threshold) || 5));
    const params = { win, thr };

    const sql = `
        SELECT email, uniq(source_ip) AS ips
        FROM access_events
        WHERE parse_ok = 1
          AND event_time >= now() - INTERVAL {win:UInt32} MINUTE AND email != ''
        GROUP BY email
        HAVING ips >= {thr:UInt32}
        ORDER BY ips DESC
    `;

    const res = await clickhouse.query(sql, params, { timeoutMs: opts.timeoutMs || 30000 });
    if (!res.ok) {
        if (res.error === 'not_configured') return { degraded: true, rows: [] };
        logger.warn(`[AccessLogs] ipViolators failed: ${res.error}`);
        return { error: res.error, rows: [] };
    }
    return { rows: res.rows };
}

/**
 * Distinct source IPs a single user used within a sliding window, capped by
 * `limit`. Used to attach an IP list to the sharing-alert webhook payload only
 * when the admin opts in.
 * @returns {Promise<{degraded?:boolean, rows?:Array, error?:string}>}
 *          rows: [{ ip }]
 */
async function ipsForUser(email, windowMinutes, limit, opts = {}) {
    if (!(await clickhouse.isConfigured())) {
        return { degraded: true, rows: [] };
    }
    const win = Math.max(1, Math.floor(Number(windowMinutes) || 60));
    const cap = Math.max(1, Math.min(500, Math.floor(Number(limit) || 20)));
    const params = { win, email: String(email || '') };

    const sql = `
        SELECT DISTINCT source_ip AS ip
        FROM access_events
        WHERE parse_ok = 1
          AND event_time >= now() - INTERVAL {win:UInt32} MINUTE
          AND email = {email:String} AND source_ip != ''
        LIMIT ${cap}
    `;

    const res = await clickhouse.query(sql, params, { timeoutMs: opts.timeoutMs || 30000 });
    if (!res.ok) {
        if (res.error === 'not_configured') return { degraded: true, rows: [] };
        logger.warn(`[AccessLogs] ipsForUser failed: ${res.error}`);
        return { error: res.error, rows: [] };
    }
    return { rows: res.rows };
}

module.exports = {
    buildWhere,
    search,
    userIps,
    overview,
    ipViolators,
    ipsForUser,
};
