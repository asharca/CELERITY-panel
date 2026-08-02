const axios = require('axios');

function getStatsHost(node) {
    return String(node?.statsHost || '').trim() || String(node?.ip || '').trim();
}

function normalizeOnlinePayload(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('Invalid Hysteria online response');
    }

    const online = {};
    for (const [rawUserId, rawCount] of Object.entries(data)) {
        const userId = String(rawUserId || '').trim();
        const count = Number(rawCount);
        if (!userId || !Number.isFinite(count) || count < 0) {
            throw new Error('Invalid Hysteria online entry');
        }
        const normalizedCount = Math.floor(count);
        if (normalizedCount > 0) online[userId] = normalizedCount;
    }
    return online;
}

async function fetchOnline(node, { timeoutMs = 1500 } = {}) {
    const host = getStatsHost(node);
    if (!host || !node?.statsPort || !node?.statsSecret) {
        throw new Error('Hysteria Stats API is not configured');
    }

    const response = await axios.get(`http://${host}:${node.statsPort}/online`, {
        headers: { Authorization: node.statsSecret },
        timeout: timeoutMs,
    });
    return normalizeOnlinePayload(response.data);
}

module.exports = {
    fetchOnline,
    getStatsHost,
    normalizeOnlinePayload,
};
