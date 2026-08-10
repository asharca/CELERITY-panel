/**
 * Hysteria + Xray node model with cascade topology support
 */

const mongoose = require('mongoose');
const { normalizePortRange, parsePortRange } = require('../utils/portRange');

function optionalPortRangeField() {
    return {
        type: String,
        default: '',
        trim: true,
        set: value => {
            const normalized = value === undefined || value === null
                ? ''
                : normalizePortRange(typeof value === 'string' ? value : String(value));
            const parsed = normalized ? parsePortRange(normalized) : null;
            return parsed ? parsed.normalized : normalized;
        },
        validate: {
            validator: value => !value || !!parsePortRange(value),
            message: 'portRange must use start-end with ports between 1 and 65535',
        },
    };
}

const portConfigSchema = new mongoose.Schema({
    name: { type: String, default: '' },
    port: { type: Number, required: true },
    portRange: optionalPortRangeField(),
    enabled: { type: Boolean, default: true },
}, { _id: false });

const outboundSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, enum: ['direct', 'socks5', 'http'], required: true },
    addr: { type: String, default: '' },
    username: { type: String, default: '' },
    password: { type: String, default: '' },
    insecure: { type: Boolean, default: false },
    direct: {
        mode: { type: String, default: '' },
        bindIPv4: { type: String, default: '' },
        bindIPv6: { type: String, default: '' },
        bindDevice: { type: String, default: '' },
        fastOpen: { type: Boolean, default: false },
    },
}, { _id: false });

const acmeOptionsSchema = new mongoose.Schema({
    email: { type: String, default: '' },
    ca: { type: String, default: 'letsencrypt' },
    listenHost: { type: String, default: '0.0.0.0' },
    type: { type: String, enum: ['', 'http', 'tls', 'dns'], default: '' },
    httpAltPort: { type: Number, default: 0 },
    tlsAltPort: { type: Number, default: 0 },
    dnsName: { type: String, default: '' },
    dnsConfig: { type: Object, default: {} },
}, { _id: false });

const masqueradeSchema = new mongoose.Schema({
    type: { type: String, enum: ['proxy', 'string'], default: 'proxy' },
    proxy: {
        url: { type: String, default: 'https://www.google.com' },
        rewriteHost: { type: Boolean, default: true },
        insecure: { type: Boolean, default: false },
    },
    string: {
        content: { type: String, default: 'Service Unavailable' },
        headers: { type: Object, default: { 'content-type': 'text/plain' } },
        statusCode: { type: Number, default: 503 },
    },
    listenHTTP: { type: String, default: '' },
    listenHTTPS: { type: String, default: '' },
    forceHTTPS: { type: Boolean, default: false },
}, { _id: false });

const bandwidthSchema = new mongoose.Schema({
    up: { type: String, default: '' },
    down: { type: String, default: '' },
}, { _id: false });

const resolverSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    type: { type: String, enum: ['udp', 'tcp', 'tls', 'https'], default: 'udp' },
    udpAddr: { type: String, default: '8.8.4.4:53' },
    udpTimeout: { type: String, default: '4s' },
    tcpAddr: { type: String, default: '8.8.8.8:53' },
    tcpTimeout: { type: String, default: '4s' },
    tlsAddr: { type: String, default: '1.1.1.1:853' },
    tlsTimeout: { type: String, default: '10s' },
    tlsSni: { type: String, default: 'cloudflare-dns.com' },
    tlsInsecure: { type: Boolean, default: false },
    httpsAddr: { type: String, default: '1.1.1.1:443' },
    httpsTimeout: { type: String, default: '10s' },
    httpsSni: { type: String, default: 'cloudflare-dns.com' },
    httpsInsecure: { type: Boolean, default: false },
}, { _id: false });

const aclSettingsSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: true },
    type: { type: String, enum: ['inline', 'file'], default: 'inline' },
    file: { type: String, default: '' },
    geoip: { type: String, default: '' },
    geosite: { type: String, default: '' },
    geoUpdateInterval: { type: String, default: '' },
}, { _id: false });

const sniffSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    enable: { type: Boolean, default: true },
    timeout: { type: String, default: '2s' },
    rewriteDomain: { type: Boolean, default: false },
    tcpPorts: { type: String, default: '80,443,8000-9000' },
    udpPorts: { type: String, default: '443,80,53' },
}, { _id: false });

const quicSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    initStreamReceiveWindow: { type: Number, default: 8388608 },
    maxStreamReceiveWindow: { type: Number, default: 8388608 },
    initConnReceiveWindow: { type: Number, default: 20971520 },
    maxConnReceiveWindow: { type: Number, default: 20971520 },
    maxIdleTimeout: { type: String, default: '60s' },
    maxIncomingStreams: { type: Number, default: 256 },
    disablePathMTUDiscovery: { type: Boolean, default: false },
}, { _id: false });

// Per-inbound stream/security settings shared by the main inbound and extras.
// Extras add `id`, `label`, `port` and reuse their own `inboundTag` instead of
// the node-level fields.
const xrayExtraInboundSchema = new mongoose.Schema({
    // Stable client-generated id (uuid) used to track edits across form submits
    id: { type: String, required: true },
    label: { type: String, default: '' },
    // When true, the subscription server name is just the label (issue #74)
    // instead of "<node name> (<label>)".
    uniqueName: { type: Boolean, default: false },
    port: { type: Number, required: true },
    inboundTag: { type: String, required: true },

    transport: { type: String, enum: ['tcp', 'ws', 'grpc', 'xhttp'], default: 'tcp' },
    security: { type: String, enum: ['reality', 'tls', 'none'], default: 'reality' },
    flow: { type: String, default: 'xtls-rprx-vision' },

    fingerprint: { type: String, default: 'chrome' },
    // Optional set of fingerprints; when non-empty, one is chosen at random when
    // the subscription cache is (re)built, rotating per cache TTL rather than on
    // every request (overrides the single `fingerprint`).
    fingerprintPool: { type: [String], default: [] },
    alpn: { type: [String], default: [] },

    realityDest: { type: String, default: 'www.google.com:443' },
    realitySni: { type: [String], default: ['www.google.com'] },
    realityPrivateKey: { type: String, default: '' },
    realityPublicKey: { type: String, default: '' },
    realityShortIds: { type: [String], default: [''] },
    realitySpiderX: { type: String, default: '' },

    wsPath: { type: String, default: '/' },
    wsHost: { type: String, default: '' },

    grpcServiceName: { type: String, default: 'grpc' },

    xhttpPath: { type: String, default: '/' },
    xhttpHost: { type: String, default: '' },
    xhttpMode: { type: String, enum: ['auto', 'packet-up', 'stream-up', 'stream-one'], default: 'auto' },

    // VLESS fallbacks[].dest — emitted only on tcp+tls; empty = no fallback.
    fallbackDest: { type: String, default: '', trim: true, maxlength: 253 },
}, { _id: false });

const xrayConfigSchema = new mongoose.Schema({
    // Transport: tcp, ws, grpc, xhttp (splithttp)
    transport: { type: String, enum: ['tcp', 'ws', 'grpc', 'xhttp'], default: 'tcp' },
    // Security: reality (no cert needed), tls (cert files), none
    security: { type: String, enum: ['reality', 'tls', 'none'], default: 'reality' },
    // XTLS flow — only for tcp+reality/tls
    flow: { type: String, default: 'xtls-rprx-vision' },

    // TLS Fingerprint (uTLS) — chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized
    fingerprint: { type: String, default: 'chrome' },
    // Optional set of fingerprints; when non-empty, one is chosen at random when
    // the subscription cache is (re)built, rotating per cache TTL rather than on
    // every request (overrides the single `fingerprint`).
    fingerprintPool: { type: [String], default: [] },
    // ALPN — comma-separated or array: h3, h2, http/1.1
    alpn: { type: [String], default: [] },

    // Reality-specific
    realityDest: { type: String, default: 'www.google.com:443' },
    realitySni: { type: [String], default: ['www.google.com'] },
    realityPrivateKey: { type: String, default: '' },
    realityPublicKey: { type: String, default: '' },
    realityShortIds: { type: [String], default: [''] },
    realitySpiderX: { type: String, default: '' },

    // WebSocket-specific
    wsPath: { type: String, default: '/' },
    wsHost: { type: String, default: '' },

    // gRPC-specific
    grpcServiceName: { type: String, default: 'grpc' },

    // xhttp (splithttp) specific
    xhttpPath: { type: String, default: '/' },
    xhttpHost: { type: String, default: '' },
    xhttpMode: { type: String, enum: ['auto', 'packet-up', 'stream-up', 'stream-one'], default: 'auto' },

    // VLESS fallbacks[].dest — emitted only on tcp+tls; empty = no fallback.
    fallbackDest: { type: String, default: '', trim: true, maxlength: 253 },

    // TLS provisioning strategy (security==='tls'):
    //   panel       — inline panel's LE cert (PANEL_DOMAIN); no node files.
    //   acme        — acme.sh on node issues LE cert for node.domain; auto-renews.
    //   manual      — operator pastes node.domain + PEM; inlined into config.json.
    //   self-signed — openssl on node; client needs allowInsecure (testing only).
    tlsSource: { type: String, enum: ['panel', 'acme', 'manual', 'self-signed'], default: 'panel' },
    // Empty acmeEmail = use panel-wide ACME_EMAIL env var.
    acmeEmail: { type: String, default: '' },
    // Public PEM (full chain) for tlsSource==='manual'. Stored as-is; safe to return.
    manualCert: { type: String, default: '' },
    // Private key PEM for tlsSource==='manual'. select:false → never returned by
    // .find()/.findOne() unless explicitly selected. API responses must use a
    // ***SET*** placeholder when surfacing the field to the form (see routes).
    manualKey: { type: String, default: '', select: false },

    // gRPC API port for user management (local, not exposed)
    apiPort: { type: Number, default: 61000 },

    // Inbound tag used in config and API calls
    inboundTag: { type: String, default: 'vless-in' },

    // CC Agent settings
    agentPort: { type: Number, default: 62080 },
    agentToken: { type: String, default: '' },
    agentTls: { type: Boolean, default: true },

    // Additional VLESS inbounds running alongside the main one with their own
    // ports and transports (Reality TCP + WS+TLS + gRPC, etc). Optional, the
    // main inbound is still defined by the flat fields above.
    extraInbounds: { type: [xrayExtraInboundSchema], default: [] },

    // Per-node access-log shipping state. Kept under `xray` for schema/backward
    // compatibility, but also used by Hysteria journal shipping. Independent
    // of core health: a shipping failure never marks the node offline.
    accessLogs: {
        // Effective state for THIS node (may lag the global setting while
        // reconciliation is in progress or the agent is too old).
        enabled: { type: Boolean, default: false },
        // Set before node deletion so every concurrent reconcile treats the
        // desired state as disabled until remote cleanup and DB deletion finish.
        deletePending: { type: Boolean, default: false },
        // Conservative tombstone: true means a remote source may still be
        // collecting and must be disabled before deleting/converting the node.
        cleanupRequired: { type: Boolean, default: false },
        status: {
            type: String,
            enum: ['disabled', 'pending', 'active', 'degraded', 'error', 'agent-outdated', 'agent-missing'],
            default: 'disabled',
        },
        // Per-node ingest credential. Encrypted at rest for re-provisioning;
        // a separate hash (below) is used for constant-time verification.
        // select:false so it never leaks via ordinary .find()/.findOne().
        ingestTokenEncrypted: { type: String, default: '', select: false },
        ingestTokenHash: { type: String, default: '' },
        // Fingerprint of the last successfully applied access-log config
        // (enabled + ingest URL + token). Reconciliation skips the expensive
        // config push + Xray restart when the fingerprint is unchanged.
        appliedFingerprint: { type: String, default: '' },
        // Runtime that was actually provisioned. Unlike the node's current
        // type, this survives a later type/role conversion long enough for the
        // old service to be torn down safely.
        appliedSource: {
            type: String,
            enum: ['', 'xray-file', 'xray-journal', 'hysteria-journal'],
            default: '',
        },
        // SSH target on which the source was provisioned. Kept separately so
        // changing a node to virtual (which clears node.ip) still leaves enough
        // information to remove the old HY2 debug drop-in remotely.
        appliedIp: { type: String, default: '', trim: true },
        // Encrypted SSH credentials belonging to appliedIp. A node update may
        // replace node.ssh at the same time as its IP; keeping the old runtime
        // credentials here lets a later reconcile/delete (including after a
        // panel restart) disable the exact host that was provisioned.
        appliedSsh: {
            port: { type: Number, default: 22 },
            username: { type: String, default: 'root' },
            privateKey: { type: String, default: '' },
            password: { type: String, default: '' },
        },
        // Write-ahead marker persisted before enabling a new remote runtime.
        // If the process/DB commit fails, deletion and later reconciles still
        // know the exact host that may need teardown.
        pendingSource: {
            type: String,
            enum: ['', 'xray-file', 'xray-journal', 'hysteria-journal'],
            default: '',
        },
        pendingIp: { type: String, default: '', trim: true },
        pendingSsh: {
            port: { type: Number, default: 22 },
            username: { type: String, default: 'root' },
            privateKey: { type: String, default: '' },
            password: { type: String, default: '' },
        },
        // Effective systemd unit used by HY2 journal shipping. Empty means the
        // current official default and is detected on first reconciliation.
        journalUnit: {
            type: String,
            enum: ['', 'hysteria-server', 'hysteria'],
            default: '',
        },
        lastError: { type: String, default: '' },
        lastBatchAt: { type: Date, default: null },
        spoolBytes: { type: Number, default: 0 },
        droppedEvents: { type: Number, default: 0 },
        lastReconcileAt: { type: Date, default: null },
    },
}, { _id: false });

// Virtual node: a balancer entry that aggregates other nodes into a single
// subscription record. Carries no transport/server fields itself — only the
// selection rule and observatory config consumed by Xray's load balancer.
const virtualConfigSchema = new mongoose.Schema({
    // 'manual' — explicit list of HyNode ids; 'group' — all active nodes from one ServerGroup.
    selectMode: { type: String, enum: ['manual', 'group'], default: 'manual' },
    sources: [{ type: mongoose.Schema.Types.ObjectId, ref: 'HyNode' }],
    sourceGroup: { type: mongoose.Schema.Types.ObjectId, ref: 'ServerGroup', default: null },
    // Xray balancer strategy. leastLoad/leastPing require an observatory.
    strategy: {
        type: String,
        enum: ['random', 'roundRobin', 'leastPing', 'leastLoad'],
        default: 'leastLoad',
    },
    // When all probes fail, route through the first source instead of dropping traffic.
    fallbackToFirst: { type: Boolean, default: true },
    observatory: {
        destination: { type: String, default: 'http://www.gstatic.com/generate_204' },
        connectivity: { type: String, default: '' },
        interval: { type: String, default: '1m' },
        timeout: { type: String, default: '5s' },
        sampling: { type: Number, default: 3 },
    },
}, { _id: false });

const hyNodeSchema = new mongoose.Schema({
    // 'hysteria' (default), 'xray' or 'virtual' (balancer aggregator).
    type: { type: String, enum: ['hysteria', 'xray', 'virtual'], default: 'hysteria' },

    name: { type: String, required: true },
    flag: { type: String, default: '' },
    // Free-form operator note displayed in the node list and dashboard.
    // Trimmed and capped to avoid abuse / excessive payload size.
    comment: { type: String, default: '', trim: true, maxlength: 500 },
    // Required for hysteria/xray; null for virtual (no transport).
    ip: { type: String, default: null },
    domain: { type: String, default: '' },
    sni: { type: String, default: '' },
    port: { type: Number, default: 443 },
    // Port hopping is opt-in. A non-empty range publishes the hopping entry
    // and configures the corresponding server-side forwarding rules.
    portRange: optionalPortRangeField(),
    hopInterval: { type: String, default: '' },
    portConfigs: { type: [portConfigSchema], default: [] },
    obfs: {
        type: { type: String, enum: ['', 'salamander', 'gecko'], default: '' },
        password: { type: String, default: '' },
    },
    acme: { type: acmeOptionsSchema, default: () => ({}) },
    masquerade: { type: masqueradeSchema, default: () => ({}) },
    bandwidth: { type: bandwidthSchema, default: () => ({}) },
    ignoreClientBandwidth: { type: Boolean, default: false },
    speedTest: { type: Boolean, default: false },
    disableUDP: { type: Boolean, default: false },
    udpIdleTimeout: { type: String, default: '' },
    sniff: { type: sniffSchema, default: () => ({}) },
    quic: { type: quicSchema, default: () => ({}) },
    resolver: { type: resolverSchema, default: () => ({}) },
    acl: { type: aclSettingsSchema, default: () => ({}) },
    // Optional panel-side route to the Hysteria traffic API. This may differ
    // from the public subscription address when the stats port is reachable
    // only through a management network. Empty means use `ip`.
    statsHost: { type: String, default: '', trim: true },
    statsPort: { type: Number, default: 9999 },
    statsSecret: { type: String, default: '' },

    // Xray-specific configuration (only used when type === 'xray')
    xray: { type: xrayConfigSchema, default: () => ({}) },

    // Virtual-specific configuration (only used when type === 'virtual')
    virtual: { type: virtualConfigSchema, default: () => ({}) },

    groups: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ServerGroup',
    }],
    
    ssh: {
        port: { type: Number, default: 22 },
        username: { type: String, default: 'root' },
        privateKey: { type: String, default: '' },
        password: { type: String, default: '' },
    },
    
    paths: {
        config: { type: String, default: '/etc/hysteria/config.yaml' },
        cert: { type: String, default: '/etc/hysteria/cert.pem' },
        key: { type: String, default: '/etc/hysteria/key.pem' },
    },
    
    outbounds: { type: [outboundSchema], default: [] },
    aclRules: { type: [String], default: [] },
    
    active: { type: Boolean, default: true },
    status: { type: String, enum: ['online', 'offline', 'error', 'syncing'], default: 'offline' },
    lastError: { type: String, default: '' },
    lastSync: { type: Date, default: null },

    // Agent & Xray version info (populated by health checks)
    xrayVersion: { type: String, default: '' },
    agentVersion: { type: String, default: '' },
    agentStatus: { type: String, enum: ['online', 'offline', 'unknown'], default: 'unknown' },
    agentLastSeen: { type: Date, default: null },
    onlineUsers: { type: Number, default: 0 },
    maxOnlineUsers: { type: Number, default: 0 },
    healthFailures: { type: Number, default: 0 },
    
    traffic: {
        tx: { type: Number, default: 0 },
        rx: { type: Number, default: 0 },
        lastUpdate: { type: Date, default: null },
        // Average load over the last stats-collection interval (cron */5 * * * *),
        // computed as bits transferred / interval seconds / 1e6. Not instantaneous —
        // see collectXrayTrafficStats / _collectHysteriaTrafficStats in syncService.
        txMbps: { type: Number, default: 0 },
        rxMbps: { type: Number, default: 0 },
        speedUpdatedAt: { type: Date, default: null },
    },
    
    rankingCoefficient: { type: Number, default: 1.0 },
    settings: { type: Object, default: {} },
    customConfig: { type: String, default: '' },
    useCustomConfig: { type: Boolean, default: false },
    useTlsFiles: { type: Boolean, default: false },
    initScript: { type: String, default: '' },

    // Cascade topology fields
    cascadeRole: {
        type: String,
        enum: ['standalone', 'portal', 'relay', 'bridge'],
        default: 'standalone',
    },
    mapPosition: {
        x: { type: Number, default: null },
        y: { type: Number, default: null },
    },
    country: { type: String, default: '' },

}, { timestamps: true });

// One IP may host at most one node per protocol type. Virtual nodes have no IP
// (null), so the partial filter excludes them from the unique constraint.
hyNodeSchema.index(
    { ip: 1, type: 1 },
    { unique: true, partialFilterExpression: { ip: { $type: 'string' } } }
);
hyNodeSchema.index({ active: 1 });
hyNodeSchema.index({ groups: 1 });
hyNodeSchema.index({ status: 1 });

// Type-conditional validation: hysteria/xray require ip; virtual requires either
// a non-empty sources list (manual) or a sourceGroup (group mode), and must not
// reference another virtual node (anti-cycle).
hyNodeSchema.pre('validate', function(next) {
    if (this.type === 'virtual') {
        const v = this.virtual || {};
        if (v.selectMode === 'manual' && (!v.sources || v.sources.length === 0)) {
            return next(new Error('Virtual node (manual): at least one source required'));
        }
        if (v.selectMode === 'group' && !v.sourceGroup) {
            return next(new Error('Virtual node (group): sourceGroup required'));
        }
        return next();
    }
    if (!this.ip) {
        return next(new Error(`Node type ${this.type} requires ip`));
    }
    return next();
});

hyNodeSchema.virtual('serverAddress').get(function() {
    if (this.type === 'virtual') return '';
    const host = this.domain || this.ip;
    const range = parsePortRange(this.portRange)?.normalized;
    return `${host}:${range || this.port || 443}`;
});

hyNodeSchema.methods.getSubscriptionAddress = function() {
    if (this.type === 'virtual') return '';
    const host = this.domain || this.ip;
    const range = parsePortRange(this.portRange)?.normalized;
    if (range) {
        return `${host}:${range}`;
    }
    return `${host}:${this.port}`;
};

module.exports = mongoose.model('HyNode', hyNodeSchema);
