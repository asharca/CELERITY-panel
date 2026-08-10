const mongoose = require('mongoose');

// `ts` is rounded down by up to one hour, so use 46 days to guarantee every
// sample remains available for at least 45 full days after it was collected.
const RETENTION_SECONDS = 46 * 24 * 60 * 60;

/**
 * Per-user traffic deltas collected from a single node during one UTC hour.
 *
 * `nodeName` and `nodeType` are deliberately denormalized so historical node
 * breakdowns remain useful after a node is renamed or removed.
 */
const userTrafficHourlySchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
    },
    nodeId: {
        type: String,
        required: true,
    },
    nodeName: {
        type: String,
        default: '',
    },
    nodeType: {
        type: String,
        default: '',
    },
    ts: {
        type: Date,
        required: true,
    },
    tx: {
        type: Number,
        default: 0,
        min: 0,
    },
    rx: {
        type: Number,
        default: 0,
        min: 0,
    },
}, {
    timestamps: false,
    versionKey: false,
});

// One counter per subscription account, node and UTC hour. This also makes
// repeated samples in the same hour atomic through `$inc` upserts.
userTrafficHourlySchema.index(
    { userId: 1, nodeId: 1, ts: 1 },
    { unique: true }
);

// Range queries do not constrain nodeId, so they need a separate covering
// prefix instead of relying on the unique index above.
userTrafficHourlySchema.index({ userId: 1, ts: 1 });

// MongoDB's TTL monitor removes eligible documents asynchronously. Records
// therefore live for at least 45 days and may remain slightly longer.
userTrafficHourlySchema.index(
    { ts: 1 },
    { expireAfterSeconds: RETENTION_SECONDS }
);

module.exports = mongoose.model('UserTrafficHourly', userTrafficHourlySchema);
module.exports.RETENTION_SECONDS = RETENTION_SECONDS;
