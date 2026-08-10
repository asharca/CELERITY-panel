/**
 * Per-node ingest credential management for the access-logs pipeline.
 *
 * Each node gets its own random Bearer token. The plaintext token is delivered
 * to the node once (inside the agent config) and stored encrypted for later
 * re-provisioning. Verification on the ingest path uses a SHA-256 hash with a
 * constant-time compare, so the plaintext is never needed to authenticate a
 * request and the node identity is resolved by the token, not the payload.
 */

const crypto = require('crypto');
const cryptoService = require('../cryptoService');

// Hash a token for storage/verification. A plain SHA-256 is sufficient here:
// the token is a 256-bit random value, so it is not brute-forceable, and this
// keeps verification cheap (constant-time compare below).
function hashToken(token) {
    return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function isEligibleIngestNode(node) {
    return !!node
        && ['xray', 'hysteria'].includes(node.type)
        && ['standalone', 'portal'].includes(node.cascadeRole)
        && node.active !== false;
}

/**
 * Ensure a node has an ingest credential. Returns the plaintext token so the
 * caller can write it into the agent config. Idempotent: reuses the existing
 * token unless `rotate` is true.
 *
 * @param {Object} node   Node document (may or may not have the encrypted field selected).
 * @param {Object} opts   { rotate?: boolean }
 * @returns {Promise<{ token: string, created: boolean }>}
 */
async function ensureIngestToken(node, opts = {}) {
    const HyNode = require('../../models/hyNodeModel');
    const rotate = !!opts.rotate;

    // Load the encrypted field explicitly (select:false in the schema).
    const fresh = await HyNode.findById(node._id).select('+xray.accessLogs.ingestTokenEncrypted');
    const existingEnc = fresh?.xray?.accessLogs?.ingestTokenEncrypted || '';

    if (existingEnc && !rotate) {
        try {
            const token = cryptoService.decrypt(existingEnc);
            if (token) return { token, created: false };
        } catch (_) {
            // Fall through to regenerate on decryption failure.
        }
    }

    const token = generateToken();
    const encrypted = cryptoService.encrypt(token);
    const encryptedPath = 'xray.accessLogs.ingestTokenEncrypted';
    const compare = existingEnc
        ? { [encryptedPath]: existingEnc }
        : {
            $or: [
                { [encryptedPath]: { $exists: false } },
                { [encryptedPath]: '' },
            ],
        };

    // Compare-and-set prevents two simultaneous first-time config pushes from
    // generating different credentials and leaving one agent with a token that
    // no longer matches MongoDB. The loser re-reads and returns the winner.
    const installed = await HyNode.findOneAndUpdate(
        { _id: node._id, ...compare },
        {
            $set: {
                [encryptedPath]: encrypted,
                'xray.accessLogs.ingestTokenHash': hashToken(token),
            },
        },
        { new: true }
    ).select(`+${encryptedPath}`);
    if (installed) return { token, created: true };

    const winner = await HyNode.findById(node._id).select(`+${encryptedPath}`);
    const winnerEncrypted = winner?.xray?.accessLogs?.ingestTokenEncrypted || '';
    if (!winnerEncrypted) {
        throw new Error(`Could not persist ingest credential for node ${node._id}`);
    }
    const winnerToken = cryptoService.decrypt(winnerEncrypted);
    if (!winnerToken) {
        throw new Error(`Could not decrypt ingest credential for node ${node._id}`);
    }
    return { token: winnerToken, created: false };
}

/**
 * Revoke a node's ingest credential (used on disable / teardown).
 */
async function revokeIngestToken(nodeId) {
    const HyNode = require('../../models/hyNodeModel');
    await HyNode.updateOne(
        { _id: nodeId },
        {
            $set: {
                'xray.accessLogs.ingestTokenEncrypted': '',
                'xray.accessLogs.ingestTokenHash': '',
            },
        }
    );
}

/**
 * Resolve the node that owns a presented Bearer token. Uses a hash lookup and a
 * constant-time comparison to avoid timing side channels. Only nodes with an
 * active (enabled) access-log module are accepted.
 *
 * @param {string} token  Plaintext Bearer token from the request.
 * @returns {Promise<Object|null>} the node document, or null if unknown/inactive.
 */
async function resolveNodeByToken(token) {
    if (!token || typeof token !== 'string') return null;
    const HyNode = require('../../models/hyNodeModel');
    const presentedHash = hashToken(token);

    // Look up by hash first (indexed-ish; small collection). Then confirm with a
    // constant-time compare so a hash-only match cannot be forced by collisions.
    const node = await HyNode.findOne({ 'xray.accessLogs.ingestTokenHash': presentedHash });
    if (!node) return null;
    const stored = node.xray?.accessLogs?.ingestTokenHash || '';
    if (!stored) return null;

    const a = Buffer.from(presentedHash, 'hex');
    const b = Buffer.from(stored, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (!node.xray?.accessLogs?.enabled) return null;
    // A role/type conversion is committed before the asynchronous remote
    // teardown finishes. Reject ingestion immediately once the node no longer
    // terminates client traffic, so a stale agent cannot keep writing data in
    // that reconciliation window.
    if (!isEligibleIngestNode(node)) return null;

    return node;
}

module.exports = {
    hashToken,
    generateToken,
    isEligibleIngestNode,
    ensureIngestToken,
    revokeIngestToken,
    resolveNodeByToken,
};
