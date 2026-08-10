const UserTrafficHourly = require('../models/userTrafficHourlyModel');

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const RANGE_CONFIG = Object.freeze({
    '24h': Object.freeze({ granularity: 'hour', bucketMs: HOUR_MS, bucketCount: 24 }),
    '7d': Object.freeze({ granularity: 'day', bucketMs: DAY_MS, bucketCount: 7 }),
    '30d': Object.freeze({ granularity: 'day', bucketMs: DAY_MS, bucketCount: 30 }),
});

/**
 * Accept only finite, positive byte deltas. Counters are integer byte counts;
 * flooring also prevents fractional or numeric-string values reaching Mongo.
 */
function normalizeByteCount(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        return 0;
    }
    return Math.floor(value);
}

function toValidDate(value) {
    const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
    return Number.isFinite(date.getTime()) ? date : null;
}

function floorToUtcHour(value) {
    const date = toValidDate(value);
    if (!date) return null;
    date.setUTCMinutes(0, 0, 0);
    return date;
}

function floorToUtcDay(value) {
    const date = toValidDate(value);
    if (!date) return null;
    date.setUTCHours(0, 0, 0, 0);
    return date;
}

function getRangeConfig(range) {
    const config = RANGE_CONFIG[range];
    if (!config) {
        const error = new RangeError(`Unsupported traffic history range: ${range}`);
        error.code = 'INVALID_TRAFFIC_HISTORY_RANGE';
        throw error;
    }
    return config;
}

/**
 * Return an aligned, half-open UTC window [from, to). The final bucket is the
 * current (possibly partial) hour/day, which keeps the series dense and stable.
 */
function getRangeWindow(range, now = new Date()) {
    const config = getRangeConfig(range);
    const currentBucket = config.granularity === 'hour'
        ? floorToUtcHour(now)
        : floorToUtcDay(now);

    if (!currentBucket) {
        throw new TypeError('Invalid traffic history reference time');
    }

    const to = new Date(currentBucket.getTime() + config.bucketMs);
    const from = new Date(to.getTime() - (config.bucketCount * config.bucketMs));
    return { ...config, from, to };
}

/**
 * Persist non-zero user deltas for one node in a UTC-hour bucket.
 *
 * @param {Object} sample
 * @param {string|Object} sample.nodeId
 * @param {string} sample.nodeName
 * @param {string} sample.nodeType
 * @param {Date|string|number} [sample.timestamp]
 * @param {Array<{userId:string,tx:number,rx:number}>} sample.deltas
 * @returns {Promise<Object|null>} Mongoose bulkWrite result, or null if empty
 */
async function recordUserTrafficDeltas({
    nodeId,
    nodeName = '',
    nodeType = '',
    timestamp = new Date(),
    deltas = [],
} = {}) {
    const normalizedNodeId = nodeId === undefined || nodeId === null
        ? ''
        : String(nodeId).trim();
    const ts = floorToUtcHour(timestamp);

    if (!normalizedNodeId || !ts || !Array.isArray(deltas)) {
        return null;
    }

    // Coalesce duplicate user rows before creating upserts. Besides reducing
    // writes, this avoids two upserts racing for the same unique key in a batch.
    const byUser = new Map();
    for (const delta of deltas) {
        if (!delta || typeof delta.userId !== 'string' || delta.userId.length === 0) {
            continue;
        }

        const tx = normalizeByteCount(delta.tx);
        const rx = normalizeByteCount(delta.rx);
        if (tx === 0 && rx === 0) continue;

        const existing = byUser.get(delta.userId) || { tx: 0, rx: 0 };
        existing.tx += tx;
        existing.rx += rx;
        byUser.set(delta.userId, existing);
    }

    if (byUser.size === 0) return null;

    const safeNodeName = typeof nodeName === 'string' ? nodeName : '';
    const safeNodeType = typeof nodeType === 'string' ? nodeType : '';
    const operations = Array.from(byUser, ([userId, traffic]) => ({
        updateOne: {
            filter: { userId, nodeId: normalizedNodeId, ts },
            update: {
                $inc: { tx: traffic.tx, rx: traffic.rx },
                $set: { nodeName: safeNodeName, nodeType: safeNodeType },
            },
            upsert: true,
        },
    }));

    return UserTrafficHourly.bulkWrite(operations, { ordered: false });
}

function emptyTotals() {
    return { tx: 0, rx: 0, total: 0 };
}

/**
 * Query a subscription account's traffic history and return a dense series.
 * Hourly source rows are folded into UTC days for the 7d and 30d ranges.
 */
async function getUserTrafficHistory(userId, range = '24h', options = {}) {
    const { granularity, bucketMs, bucketCount, from, to } = getRangeWindow(
        range,
        options.now || new Date()
    );

    const rows = await UserTrafficHourly.find({
        userId,
        ts: { $gte: from, $lt: to },
    })
        .sort({ ts: 1 })
        .lean();

    const seriesByTimestamp = new Map();
    const nodesById = new Map();
    const totals = emptyTotals();

    for (const row of rows) {
        const tx = normalizeByteCount(row.tx);
        const rx = normalizeByteCount(row.rx);
        if (tx === 0 && rx === 0) continue;

        const bucket = granularity === 'hour'
            ? floorToUtcHour(row.ts)
            : floorToUtcDay(row.ts);
        if (!bucket || bucket < from || bucket >= to) continue;

        const bucketKey = bucket.getTime();
        const point = seriesByTimestamp.get(bucketKey) || emptyTotals();
        point.tx += tx;
        point.rx += rx;
        point.total += tx + rx;
        seriesByTimestamp.set(bucketKey, point);

        const nodeId = row.nodeId === undefined || row.nodeId === null
            ? ''
            : String(row.nodeId);
        if (nodeId) {
            const node = nodesById.get(nodeId) || {
                nodeId,
                nodeName: '',
                nodeType: '',
                tx: 0,
                rx: 0,
                total: 0,
            };
            // Rows are sorted oldest-first; the newest non-empty metadata wins.
            if (row.nodeName) node.nodeName = row.nodeName;
            if (row.nodeType) node.nodeType = row.nodeType;
            node.tx += tx;
            node.rx += rx;
            node.total += tx + rx;
            nodesById.set(nodeId, node);
        }

        totals.tx += tx;
        totals.rx += rx;
        totals.total += tx + rx;
    }

    const series = [];
    for (let i = 0; i < bucketCount; i += 1) {
        const ts = new Date(from.getTime() + (i * bucketMs));
        const point = seriesByTimestamp.get(ts.getTime()) || emptyTotals();
        series.push({ ts, tx: point.tx, rx: point.rx, total: point.total });
    }

    const nodes = Array.from(nodesById.values()).sort((a, b) => (
        (b.total - a.total)
        || a.nodeName.localeCompare(b.nodeName)
        || a.nodeId.localeCompare(b.nodeId)
    ));

    return {
        userId,
        range,
        granularity,
        from,
        to,
        totals,
        series,
        nodes,
    };
}

// Concise public name used by the users API; retain the descriptive function
// name as an alias for callers that prefer it.
const getUserHistory = getUserTrafficHistory;

async function deleteUserTrafficHistory(userId) {
    if (typeof userId !== 'string' || userId.length === 0) {
        return { acknowledged: true, deletedCount: 0 };
    }
    return UserTrafficHourly.deleteMany({ userId });
}

module.exports = {
    RANGE_CONFIG,
    normalizeByteCount,
    floorToUtcHour,
    floorToUtcDay,
    getRangeConfig,
    getRangeWindow,
    recordUserTrafficDeltas,
    getUserHistory,
    getUserTrafficHistory,
    deleteUserTrafficHistory,
};
