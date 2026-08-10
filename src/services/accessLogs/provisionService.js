/**
 * Access-logs provisioning / reconciliation.
 *
 * Reconciles the desired global access-logs setting against the actual per-node
 * state. For each eligible node it:
 *   - ensures (or revokes) an ingest credential,
 *   - flips the node's per-node accessLogs.enabled flag,
 *   - pushes fresh proxy + cc-agent configs so the Xray file or Hysteria
 *     journal source is (de)activated and the agent starts/stops shipping.
 *
 * All node work is best-effort and isolated: one node failing to reconcile never
 * blocks the others and never marks the node offline. This is intentionally
 * decoupled from the request path — callers invoke reconcileAll() via
 * setImmediate so a proxy restart never blocks an HTTP response.
 */

const crypto = require('crypto');
const logger = require('../../utils/logger');
const appConfig = require('../../../config');
const credentialService = require('./credentialService');

const MIN_AGENT_VERSION = '1.5.2';
const MIN_HYSTERIA_AGENT_VERSION = '1.5.2';
const HYSTERIA_JOURNAL_UNIT_RE = /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$/;
const HYSTERIA_JOURNAL_TAG_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

// Minimal semver-ish compare good enough for "x.y.z" agent versions. Missing or
// unparseable versions are treated as too old.
function agentVersionAtLeast(version, min) {
    if (!version || typeof version !== 'string') return false;
    const parsed = value => {
        const match = String(value).trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
        return match ? match.slice(1).map(Number) : null;
    };
    const a = parsed(version);
    const b = parsed(min);
    if (!a || !b) return false;
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const x = a[i] || 0;
        const y = b[i] || 0;
        if (x > y) return true;
        if (x < y) return false;
    }
    return true;
}

// Resolve the ingest URL to hand to agents. Explicit setting wins; otherwise it
// is derived from the panel base URL.
function resolveIngestUrl(settings) {
    const explicit = (settings?.accessLogs?.ingestUrl || '').trim();
    if (explicit) return explicit;
    const base = (appConfig.BASE_URL || '').replace(/\/+$/, '');
    return base ? `${base}/api/access-logs/ingest` : '';
}

// Eligibility: client-facing proxy nodes only (standalone/portal). Bridge/relay
// and virtual nodes never terminate client traffic, so they have no meaningful
// access log.
function isEligibleNode(node) {
    return node
        && ['xray', 'hysteria'].includes(node.type)
        && ['standalone', 'portal'].includes(node.cascadeRole)
        && node.active !== false;
}

function minimumAgentVersionForNode(node) {
    return node?.type === 'hysteria' ? MIN_HYSTERIA_AGENT_VERSION : MIN_AGENT_VERSION;
}

// MongoDB metadata can be stale after a manual uninstall, rollback or restore.
// Probe the authenticated agent endpoint before allowing HY2's fingerprint
// fast-path to report "active" without touching the node.
async function probeAccessLogAgent(node) {
    if (!['xray', 'hysteria'].includes(node?.type) || !node.xray?.agentToken) {
        return { reachable: false, version: '', accessLogs: null };
    }
    try {
        const response = await require('../syncService')._agentRequest(node, 'GET', '/info');
        if (!response || response.status < 200 || response.status >= 300) {
            return { reachable: false, version: '', accessLogs: null };
        }
        const data = response.data || {};
        return {
            reachable: true,
            version: String(data.agent_version || ''),
            accessLogs: data.access_logs && typeof data.access_logs === 'object'
                ? data.access_logs : null,
        };
    } catch (error) {
        logger.warn(`[AccessLogs] Node ${node.name}: cc-agent probe failed: ${error.message}`);
        return { reachable: false, version: '', accessLogs: null };
    }
}

// Backward-compatible export name used by existing callers/tests.
const probeHysteriaAgent = probeAccessLogAgent;

async function waitForAccessLogAgentSourceReady(node, expected, options = {}) {
    const attempts = Math.max(1, options.attempts === undefined ? 20 : Number(options.attempts));
    const delayMs = Math.max(0, options.delayMs === undefined ? 250 : Number(options.delayMs));
    let lastError = 'source is not ready';
    for (let attempt = 0; attempt < attempts; attempt++) {
        const probe = await probeAccessLogAgent(node);
        const status = probe.accessLogs || {};
        const matches = probe.reachable
            && status.enabled === true
            && status.source === expected.source
            && status.format === expected.format
            && journalSourceStatusMatches(status, expected);
        if (matches && status.source_ready === true && !status.source_error) return probe;
        lastError = status.source_error
            || (!probe.reachable ? 'agent is unreachable' : `source status is ready=${status.source_ready === true}`);
        if (attempt + 1 < attempts && delayMs > 0) {
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    throw new Error(`cc-agent access-log source not ready: ${lastError}`);
}

function normalizeHysteriaJournalSources(accessLogs = {}) {
    const configured = Array.isArray(accessLogs?.journalSources)
        ? accessLogs.journalSources : [];
    const fallbackUnit = String(
        accessLogs?.journalUnit || require('../configGenerator').HYSTERIA_SYSTEMD_UNIT
    ).trim();
    const sources = configured.length > 0
        ? configured.map(source => ({
            unit: String(source?.unit || '').trim(),
            tag: String(source?.tag || '').trim(),
        }))
        : [{ unit: fallbackUnit, tag: '' }];
    const seenUnits = new Set();
    const seenTags = new Set();
    for (const source of sources) {
        if (!HYSTERIA_JOURNAL_UNIT_RE.test(source.unit) || source.unit.includes('..')) {
            throw new Error(`Invalid Hysteria journal systemd unit: ${source.unit || '(empty)'}`);
        }
        if (sources.length > 1 && !source.tag) {
            throw new Error(`Hysteria journal source ${source.unit} needs a runtime tag`);
        }
        if (source.tag && !HYSTERIA_JOURNAL_TAG_RE.test(source.tag)) {
            throw new Error(`Invalid Hysteria journal runtime tag: ${source.tag}`);
        }
        if (seenUnits.has(source.unit)) {
            throw new Error(`Duplicate Hysteria journal systemd unit: ${source.unit}`);
        }
        if (source.tag && seenTags.has(source.tag)) {
            throw new Error(`Duplicate Hysteria journal runtime tag: ${source.tag}`);
        }
        seenUnits.add(source.unit);
        if (source.tag) seenTags.add(source.tag);
    }
    return sources;
}

function journalSourceStatusMatches(status, expected) {
    if (expected.source !== 'journal') return true;
    const expectedSources = Array.isArray(expected.journalSources) && expected.journalSources.length > 0
        ? expected.journalSources : [{ unit: expected.journalUnit || '', tag: '' }];
    const reported = Array.isArray(status?.journal_sources) && status.journal_sources.length > 0
        ? status.journal_sources.map(source => ({
            unit: String(source?.unit || ''),
            tag: String(source?.tag || ''),
        }))
        : [{ unit: String(status?.journal_unit || ''), tag: '' }];
    return expectedSources.length === reported.length
        && expectedSources.every((source, index) => source.unit === reported[index].unit
            && source.tag === reported[index].tag);
}

// Source-specific fields consumed by cc-agent. Xray keeps its established file
// tailer; Hysteria reads the official systemd unit and normalizes JSON events
// before sending them through the same ingest endpoint.
function accessLogSourceForNode(node) {
    if (node?.type === 'hysteria') {
        const journalSources = normalizeHysteriaJournalSources(node.xray?.accessLogs || {});
        return {
            source: 'journal',
            format: 'hysteria2-json',
            journalUnit: journalSources[0].unit,
            journalSources,
            path: '',
        };
    }
    return {
        source: 'journal',
        format: 'xray',
        journalUnit: require('../configGenerator').XRAY_SYSTEMD_UNIT,
        path: '',
    };
}

function isXrayRuntimeSource(source) {
    return source === 'xray-file' || source === 'xray-journal';
}

function runtimeSourceForNodeType(type) {
    return type === 'hysteria' ? 'hysteria-journal' : 'xray-journal';
}

// Should THIS node be shipping, given the global setting + scope?
function nodeShouldShip(node, settings) {
    const al = settings?.accessLogs;
    if (!al || !al.enabled) return false;
    if (!isEligibleNode(node)) return false;
    if (node.xray?.accessLogs?.deletePending) return false;
    if (al.nodeScope === 'selected') {
        const ids = (al.nodeIds || []).map(String);
        return ids.includes(String(node._id));
    }
    return true;
}

/**
 * Build the access_logs block for a node's cc-agent config. Returns a disabled
 * block when the node should not ship (so a previously-enabled agent gets turned
 * off cleanly). Used by nodeSetup.reloadCcAgent.
 */
async function buildNodeAccessLogsConfig(node) {
    const Settings = require('../../models/settingsModel');
    const settings = await Settings.get();

    const source = accessLogSourceForNode(node);
    if (!nodeShouldShip(node, settings)) {
        return { enabled: false, ...source };
    }

    const ingestUrl = resolveIngestUrl(settings);
    if (!ingestUrl) {
        return { enabled: false, ...source };
    }

    const { token } = await credentialService.ensureIngestToken(node);
    const insecureTls = !!(settings?.nodeAuth?.insecure);

    return {
        enabled: true,
        ...source,
        ingestUrl,
        ingestToken: token,
        insecureTls,
        spoolMaxBytes: 200 * 1024 * 1024,
        batchMaxEvents: 500,
        flushIntervalSeconds: 5,
        fileMaxBytes: 64 * 1024 * 1024,
    };
}

// Fingerprint of the effective access-log config for a node. When it matches
// the stored appliedFingerprint, the node already runs this exact config and
// the expensive push + proxy restart can be skipped. Covers EVERY input that
// lands in the agent's access_logs block: ingest URL, token (via hash), the
// TLS-verification mode, and the log path — so changing any of them forces a
// re-push, while unrelated settings saves stay no-ops.
function desiredFingerprint(shouldShip, settings, tokenHash, node) {
    if (!shouldShip) return 'disabled';
    const ingestUrl = resolveIngestUrl(settings);
    const insecureTls = !!(settings?.nodeAuth?.insecure);
    const source = accessLogSourceForNode(node);
    return crypto.createHash('sha256')
        .update('v4|enabled|')
        .update(String(ingestUrl))
        .update('|')
        .update(String(tokenHash || ''))
        .update('|')
        .update(insecureTls ? 'itls1' : 'itls0')
        .update('|')
        .update(String(source.source))
        .update('|')
        .update(String(source.format))
        .update('|')
        .update(String(source.journalUnit))
        .update('|')
        .update(JSON.stringify(source.journalSources || []))
        .update('|')
        .update(String(source.path))
        .digest('hex')
        .slice(0, 32);
}

function runtimeSshSnapshot(ssh) {
    const source = typeof ssh?.toObject === 'function' ? ssh.toObject() : (ssh || {});
    return {
        port: Number(source.port) || 22,
        username: String(source.username || 'root'),
        privateKey: String(source.privateKey || ''),
        password: String(source.password || ''),
    };
}

function hasRuntimeSshCredentials(ssh) {
    return !!(ssh?.password || ssh?.privateKey);
}

function runtimeSshForTarget(accessLogs, targetIp, fallback, current = {}) {
    const target = String(targetIp || '');
    const pending = accessLogs?.pendingSsh;
    const applied = accessLogs?.appliedSsh;
    if (target && target === String(current.ip || '')
        && hasRuntimeSshCredentials(current.ssh)) {
        return runtimeSshSnapshot(current.ssh);
    }
    if (target && target === String(accessLogs?.pendingIp || '')
        && (pending?.password || pending?.privateKey)) {
        return runtimeSshSnapshot(pending);
    }
    if (target && target === String(accessLogs?.appliedIp || '')
        && (applied?.password || applied?.privateKey)) {
        return runtimeSshSnapshot(applied);
    }
    return runtimeSshSnapshot(fallback);
}

function mergeRuntimeAccessLogs(current = {}, previous = {}) {
    const merged = { ...current, ...previous };
    for (const marker of ['applied', 'pending']) {
        const sourceKey = `${marker}Source`;
        const ipKey = `${marker}Ip`;
        const sshKey = `${marker}Ssh`;
        if (!previous[sourceKey]) merged[sourceKey] = current[sourceKey] || '';
        if (!previous[ipKey]) merged[ipKey] = current[ipKey] || '';
        if (!hasRuntimeSshCredentials(previous[sshKey])) {
            merged[sshKey] = current[sshKey] || previous[sshKey] || {};
        }
    }
    if (!previous.journalUnit) merged.journalUnit = current.journalUnit || '';
    if (!Array.isArray(previous.journalSources) || previous.journalSources.length === 0) {
        merged.journalSources = current.journalSources || previous.journalSources || [];
    }
    return merged;
}

function buildHysteriaTeardownNode(fresh, previousRuntime, appliedIp) {
    const teardown = typeof fresh?.toObject === 'function'
        ? fresh.toObject({ depopulate: true })
        : { ...(fresh || {}) };
    const previous = previousRuntime || {};
    const previousXray = previous.xray || {};
    const currentXray = teardown.xray || {};
    const currentIp = teardown.ip;
    const currentSsh = teardown.ssh;
    const runtimeAccessLogs = mergeRuntimeAccessLogs(
        currentXray.accessLogs,
        previousXray.accessLogs
    );

    teardown.type = 'hysteria';
    teardown.ip = appliedIp || previous.ip || teardown.ip;
    teardown.ssh = runtimeSshForTarget(
        runtimeAccessLogs,
        teardown.ip,
        previous.ssh || currentSsh,
        { ip: currentIp, ssh: currentSsh }
    );
    teardown.xray = {
        ...currentXray,
        agentToken: previousXray.agentToken || currentXray.agentToken,
        agentPort: previousXray.agentPort || currentXray.agentPort,
        apiPort: previousXray.apiPort || currentXray.apiPort,
        agentTls: previousXray.agentTls !== undefined
            ? previousXray.agentTls : currentXray.agentTls,
        accessLogs: runtimeAccessLogs,
    };
    return teardown;
}

function buildXrayTeardownNode(node, previousRuntime, appliedIp) {
    const teardown = typeof node?.toObject === 'function'
        ? node.toObject({ depopulate: true })
        : { ...(node || {}) };
    const previous = previousRuntime || {};
    const previousXray = previous.xray || {};
    const currentIp = teardown.ip;
    const currentSsh = teardown.ssh;
    const runtimeAccessLogs = mergeRuntimeAccessLogs(
        teardown.xray?.accessLogs,
        previousXray.accessLogs
    );
    teardown.type = 'xray';
    teardown.ip = appliedIp || previous.ip || teardown.ip;
    teardown.ssh = runtimeSshForTarget(
        runtimeAccessLogs,
        teardown.ip,
        previous.ssh || currentSsh,
        { ip: currentIp, ssh: currentSsh }
    );
    teardown.xray = { ...(teardown.xray || {}), ...previousXray };
    teardown.xray.accessLogs = {
        ...runtimeAccessLogs,
        enabled: false,
        deletePending: true,
    };
    return teardown;
}

function buildRuntimeTeardownCandidates(builder, fresh, previousRuntime, targetIp, preferredMarker) {
    const current = typeof fresh?.toObject === 'function'
        ? fresh.toObject({ depopulate: true })
        : { ...(fresh || {}) };
    const previous = previousRuntime || {};
    const accessLogs = mergeRuntimeAccessLogs(
        current.xray?.accessLogs,
        previous.xray?.accessLogs
    );
    const target = String(targetIp || '');
    const candidates = [];
    const seen = new Set();
    const add = ssh => {
        if (!hasRuntimeSshCredentials(ssh)) return;
        const snapshot = runtimeSshSnapshot(ssh);
        const key = JSON.stringify(snapshot);
        if (seen.has(key)) return;
        seen.add(key);
        candidates.push(snapshot);
    };

    // The current credential is most likely to work when the target did not
    // move. The durable pending/applied credentials remain fallbacks, covering
    // both "old revoked, new works" and "new invalid, old still works".
    if (target && target === String(current.ip || '')) add(current.ssh);
    if (preferredMarker === 'pending') add(accessLogs.pendingSsh);
    if (preferredMarker === 'applied') add(accessLogs.appliedSsh);
    add(accessLogs.pendingSsh);
    add(accessLogs.appliedSsh);
    if (target && target === String(previous.ip || '')) add(previous.ssh);
    if (candidates.length === 0) add(previous.ssh || current.ssh);

    return (candidates.length > 0 ? candidates : [runtimeSshSnapshot({})]).map(ssh => {
        const teardown = builder(current, previous, targetIp);
        teardown.ssh = ssh;
        return teardown;
    });
}

async function disableHysteriaAccessLogRuntime(fresh, previousRuntime, targetIp, preferredMarker = '') {
    const nodeSetup = require('../nodeSetup');
    let lastError = null;
    for (const teardownNode of buildRuntimeTeardownCandidates(
        buildHysteriaTeardownNode,
        fresh,
        previousRuntime,
        targetIp,
        preferredMarker
    )) {
        try {
            await nodeSetup.reconcileHysteriaAccessLogs(
                teardownNode,
                { enabled: false, ...accessLogSourceForNode(teardownNode) },
                { installAgent: false }
            );
            return teardownNode;
        } catch (error) {
            lastError = error;
        }
    }
    throw lastError || new Error('HY2 access-log cleanup failed: no usable SSH credential');
}

async function disableXrayAccessLogRuntime(
    fresh,
    previousRuntime,
    targetIp,
    preferredMarker,
    queueService
) {
    let lastError = null;
    for (const teardownNode of buildRuntimeTeardownCandidates(
        buildXrayTeardownNode,
        fresh,
        previousRuntime,
        targetIp,
        preferredMarker
    )) {
        try {
            const updated = fresh.active === false
                ? await module.exports.disableInactiveXrayAccessLogs(teardownNode)
                : await queueService.updateXrayNodeConfig(teardownNode);
            if (updated === false) throw new Error('Xray access-log cleanup failed');
            return teardownNode;
        } catch (error) {
            lastError = error;
        }
    }
    throw lastError || new Error('Xray access-log cleanup failed: no usable SSH credential');
}

async function disableInactiveXrayAccessLogs(teardownNode, options = {}) {
    const NodeSSH = options.NodeSSH || require('../nodeSSH');
    const nodeSetup = require('../nodeSetup');
    const ssh = new NodeSSH(teardownNode);
    try {
        await ssh.connect();
        const xray = teardownNode.xray || {};
        const token = xray.agentToken || '';
        await nodeSetup.assertNodeSshCcAgentConfigOwnership(ssh, token);
        const stopResult = await ssh.exec(
            'if systemctl is-active xray >/dev/null 2>&1; then systemctl stop xray; fi; '
            + 'if systemctl is-active cc-agent >/dev/null 2>&1; then systemctl stop cc-agent; fi; '
            + 'systemctl disable cc-agent >/dev/null 2>&1 || true; '
            + '! systemctl is-active xray >/dev/null 2>&1 && '
            + '! systemctl is-active cc-agent >/dev/null 2>&1'
        );
        if (stopResult && typeof stopResult.code === 'number' && stopResult.code !== 0) {
            throw new Error('could not keep inactive Xray service stopped');
        }

        const configPath = '/usr/local/etc/xray/config.json';
        const tempPath = `${configPath}.celerity-access-logs.tmp`;
        const raw = await ssh.readFile(configPath);
        const config = JSON.parse(raw);
        config.log = { ...(config.log || {}), access: 'none' };
        await ssh.uploadContent(JSON.stringify(config, null, 2), tempPath);
        const replace = await ssh.exec(`chmod 600 ${tempPath} && mv -f ${tempPath} ${configPath}`);
        if (replace && typeof replace.code === 'number' && replace.code !== 0) {
            throw new Error('could not replace inactive Xray config');
        }

        // Persist a disabled agent config without restarting it. Xray-mode
        // cc-agent has a delayed startup-heal path that may restart Xray, so a
        // deleting inactive node must leave both services stopped.
        const agentConfig = nodeSetup.buildAgentConfig(
            teardownNode,
            token,
            xray.agentPort || 62080,
            xray.apiPort || 61000,
            xray.agentTls !== false,
            { enabled: false, ...accessLogSourceForNode(teardownNode) }
        );
        const agentTemp = '/etc/cc-agent/config.json.celerity-delete.tmp';
        await ssh.uploadContent(JSON.stringify(agentConfig, null, 2), agentTemp);
        const replaceAgent = await ssh.exec(
            `chmod 600 ${agentTemp} && mv -f ${agentTemp} /etc/cc-agent/config.json`
        );
        if (replaceAgent && typeof replaceAgent.code === 'number' && replaceAgent.code !== 0) {
            throw new Error('could not persist disabled cc-agent config');
        }
        return true;
    } finally {
        ssh.disconnect();
    }
}

async function disableRecordedAccessLogRuntimes(fresh, initial, queueService) {
    const initialAccessLogs = initial.xray?.accessLogs || {};
    const accessLogs = fresh.xray?.accessLogs || initialAccessLogs;
    const appliedSource = accessLogs.appliedSource || initialAccessLogs.appliedSource || '';
    const appliedIp = accessLogs.appliedIp || initialAccessLogs.appliedIp || fresh.ip || initial.ip;
    const pendingSource = accessLogs.pendingSource || initialAccessLogs.pendingSource || '';
    const pendingIp = accessLogs.pendingIp || initialAccessLogs.pendingIp || fresh.ip || initial.ip;
    const cleanupRequired = !!(initialAccessLogs.cleanupRequired
        || initialAccessLogs.enabled
        || appliedSource
        || pendingSource);

    const hysteriaTargets = new Map();
    if (pendingSource === 'hysteria-journal' && pendingIp) {
        hysteriaTargets.set(String(pendingIp), 'pending');
    }
    if (appliedSource === 'hysteria-journal' && appliedIp
        && !hysteriaTargets.has(String(appliedIp))) {
        hysteriaTargets.set(String(appliedIp), 'applied');
    }
    if (hysteriaTargets.size === 0 && fresh.type === 'hysteria' && cleanupRequired) {
        hysteriaTargets.set(String(fresh.ip || initial.ip || ''), '');
    }
    for (const [targetIp, marker] of hysteriaTargets) {
        if (targetIp) {
            await disableHysteriaAccessLogRuntime(fresh, initial, targetIp, marker);
        }
    }

    const xrayTargets = new Map();
    if (isXrayRuntimeSource(pendingSource) && pendingIp) {
        xrayTargets.set(String(pendingIp), 'pending');
    }
    if (isXrayRuntimeSource(appliedSource) && appliedIp
        && !xrayTargets.has(String(appliedIp))) {
        xrayTargets.set(String(appliedIp), 'applied');
    }
    if (xrayTargets.size === 0 && hysteriaTargets.size === 0
        && fresh.type === 'xray' && cleanupRequired) {
        xrayTargets.set(String(fresh.ip || initial.ip || ''), '');
    }
    for (const [targetIp, marker] of xrayTargets) {
        if (targetIp) {
            await disableXrayAccessLogRuntime(fresh, initial, targetIp, marker, queueService);
        }
    }
}

/**
 * Delete a node only after its remote access-log source has been disabled.
 * The whole remote-cleanup + DB-delete section shares syncService's per-node
 * queue, so an in-flight config push cannot re-enable logging after teardown.
 */
async function deleteNodeWithAccessLogCleanup(nodeOrId) {
    const HyNode = require('../../models/hyNodeModel');
    const id = nodeOrId?._id || nodeOrId;
    const initial = nodeOrId?._id ? nodeOrId : await HyNode.findById(id);
    if (!initial) return null;

    await HyNode.updateOne({ _id: id }, {
        $set: {
            'xray.accessLogs.enabled': false,
            'xray.accessLogs.deletePending': true,
            'xray.accessLogs.status': 'pending',
            'xray.accessLogs.lastError': '',
            'xray.accessLogs.lastReconcileAt': new Date(),
        },
    });
    let revokeError = null;
    try {
        await credentialService.revokeIngestToken(id);
    } catch (error) {
        revokeError = error;
        logger.error(`[AccessLogs] Node ${initial.name}: token revoke failed before delete cleanup: ${error.message}`);
    }

    const queueService = require('../syncService');
    return queueService.enqueueNodeTask(id, async () => {
        const fresh = await HyNode.findById(id);
        if (!fresh) return null;
        await disableRecordedAccessLogRuntimes(fresh, initial, queueService);
        if (revokeError) {
            // Remote privacy cleanup must not be blocked by a transient DB/
            // crypto failure. Retry after collection is stopped, and keep the
            // deletion tombstone if credential revocation still cannot commit.
            await credentialService.revokeIngestToken(id);
        }

        return HyNode.findByIdAndDelete(id);
    });
}

/**
 * Reconcile a single node to its desired state. Xray goes through syncService;
 * Hysteria gets a logging-only systemd/agent reconcile. Skips the push entirely
 * when the node already runs the desired config.
 */
async function reconcileNode(node, settings, options = {}) {
    const HyNode = require('../../models/hyNodeModel');
    const shouldShip = nodeShouldShip(node, settings);
    const minimumVersion = minimumAgentVersionForNode(node);
    const previousRuntime = options.previousRuntime || node;
    const previousAppliedSource = previousRuntime.xray?.accessLogs?.appliedSource
        || node.xray?.accessLogs?.appliedSource || '';
    const previousAppliedIp = previousRuntime.xray?.accessLogs?.appliedIp
        || node.xray?.accessLogs?.appliedIp || '';
    const previousPendingSource = previousRuntime.xray?.accessLogs?.pendingSource
        || node.xray?.accessLogs?.pendingSource || '';
    const previousPendingIp = previousRuntime.xray?.accessLogs?.pendingIp
        || node.xray?.accessLogs?.pendingIp || '';
    const liveAgent = shouldShip
        ? await probeAccessLogAgent(node)
        : null;
    const effectiveVersion = liveAgent?.reachable ? liveAgent.version : node.agentVersion;
    const needsAgentInstall = shouldShip && (
        !agentVersionAtLeast(effectiveVersion, minimumVersion)
        || (node.type === 'hysteria' && !liveAgent?.reachable)
    );
    let remoteEnabledRuntime = null;
    let queueService = null;
    let reconcileStarted = false;

    if (liveAgent?.reachable && liveAgent.version) {
        await HyNode.updateOne({ _id: node._id }, {
            $set: { agentVersion: liveAgent.version, agentStatus: 'online', agentLastSeen: new Date() },
        });
        node.agentVersion = liveAgent.version;
    }

    const prerequisiteWillBlock = needsAgentInstall && (
        node.type !== 'hysteria'
        || !(node.ssh?.password || node.ssh?.privateKey)
    );
    const desiredRuntimeSource = runtimeSourceForNodeType(node.type);
    const runtimeMarkerIsStale = (source, ip) => !!source && (
        source !== desiredRuntimeSource
        || String(ip || '') !== String(node.ip || '')
    );
    const staleRuntimeMustBeStopped = prerequisiteWillBlock && (
        runtimeMarkerIsStale(previousAppliedSource, previousAppliedIp)
        || runtimeMarkerIsStale(previousPendingSource, previousPendingIp)
    );
    if (staleRuntimeMustBeStopped) {
        try {
            queueService = require('../syncService');
            await queueService.enqueueNodeTask(node._id, async () => {
                const fresh = await HyNode.findById(node._id);
                if (!fresh) throw new Error('node disappeared during stale access-log cleanup');
                await disableRecordedAccessLogRuntimes(fresh, previousRuntime, queueService);
                const cleared = await HyNode.updateOne({ _id: node._id }, {
                    $set: {
                        'xray.accessLogs.enabled': false,
                        'xray.accessLogs.appliedFingerprint': '',
                        'xray.accessLogs.appliedSource': '',
                        'xray.accessLogs.appliedIp': '',
                        'xray.accessLogs.appliedSsh': {},
                        'xray.accessLogs.pendingSource': '',
                        'xray.accessLogs.pendingIp': '',
                        'xray.accessLogs.pendingSsh': {},
                        'xray.accessLogs.cleanupRequired': false,
                    },
                });
                if (Number(cleared?.matchedCount) === 0) {
                    throw new Error('node disappeared while committing stale access-log cleanup');
                }
            });
        } catch (error) {
            await HyNode.updateOne({ _id: node._id }, {
                $set: {
                    'xray.accessLogs.enabled': false,
                    'xray.accessLogs.cleanupRequired': true,
                    'xray.accessLogs.status': 'error',
                    'xray.accessLogs.lastError': String(error.message || error).slice(0, 500),
                    'xray.accessLogs.lastReconcileAt': new Date(),
                },
            });
            logger.error(`[AccessLogs] Node ${node.name}: stale runtime cleanup failed before prerequisite check: ${error.message}`);
            return { node: node.name, status: 'error', error: error.message };
        }
    }

    // Xray agents are installed as part of normal node setup, so an old/missing
    // version remains an explicit operator action. Hysteria historically had no
    // agent at all; its access-log reconcile auto-installs/upgrades one over SSH.
    if (needsAgentInstall && node.type !== 'hysteria') {
        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.enabled': false,
                'xray.accessLogs.status': 'agent-outdated',
                'xray.accessLogs.lastError': `cc-agent ${minimumVersion}+ required`,
                'xray.accessLogs.lastReconcileAt': new Date(),
            },
        });
        logger.warn(`[AccessLogs] Node ${node.name}: agent too old for access logs`);
        return { node: node.name, status: 'agent-outdated' };
    }

    if (needsAgentInstall && !(node.ssh?.password || node.ssh?.privateKey)) {
        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.enabled': false,
                'xray.accessLogs.status': 'agent-missing',
                'xray.accessLogs.lastError': `cc-agent ${minimumVersion}+ requires SSH credentials for installation`,
                'xray.accessLogs.lastReconcileAt': new Date(),
            },
        });
        logger.warn(`[AccessLogs] Node ${node.name}: SSH credentials required to install cc-agent`);
        return { node: node.name, status: 'agent-missing' };
    }

    try {
        let tokenHash = '';
        let revokeError = null;
        if (shouldShip) {
            await credentialService.ensureIngestToken(node);
            const withHash = await HyNode.findById(node._id).select('xray.accessLogs.ingestTokenHash');
            tokenHash = withHash?.xray?.accessLogs?.ingestTokenHash || '';
        }

        let fingerprint = desiredFingerprint(shouldShip, settings, tokenHash, node);
        const applied = node.xray?.accessLogs?.appliedFingerprint || '';
        const currentStatus = node.xray?.accessLogs?.status || 'disabled';

        // No-op fast paths (skip the config push + Xray restart):
        //  - the node already runs this exact config and is healthy, OR
        //  - target is "disabled" and the node was never provisioned for access
        //    logs at all (disabled is the default state — nothing to undo).
        const neverProvisioned = !applied
            && !(node.xray?.accessLogs?.enabled)
            && !node.xray?.accessLogs?.ingestTokenHash
            && !previousAppliedSource
            && !previousPendingSource
            && !node.xray?.accessLogs?.cleanupRequired;
        const expectedSource = accessLogSourceForNode(node);
        const liveConfigApplied = !shouldShip || (
            liveAgent?.reachable
            && liveAgent.accessLogs?.enabled === true
            && liveAgent.accessLogs?.source === expectedSource.source
            && liveAgent.accessLogs?.format === expectedSource.format
            && journalSourceStatusMatches(liveAgent.accessLogs, expectedSource)
            && liveAgent.accessLogs?.source_ready === true
            && !liveAgent.accessLogs?.source_error
        );
        const statusAllowsSkip = liveConfigApplied
            && !['error', 'pending', 'agent-outdated', 'agent-missing'].includes(currentStatus);
        const alreadyApplied = !needsAgentInstall && liveConfigApplied
            && statusAllowsSkip
            && !previousPendingSource
            && (!shouldShip || !previousAppliedIp || String(previousAppliedIp) === String(node.ip || ''))
            && fingerprint === applied;
        if (alreadyApplied || (!shouldShip && neverProvisioned)) {
            const effectiveStatus = shouldShip ? 'active' : 'disabled';
            await HyNode.updateOne({ _id: node._id }, {
                $set: {
                    'xray.accessLogs.status': effectiveStatus,
                    'xray.accessLogs.lastError': '',
                    'xray.accessLogs.lastReconcileAt': new Date(),
                    'xray.accessLogs.appliedFingerprint': fingerprint,
                    'xray.accessLogs.appliedSource': shouldShip
                        ? runtimeSourceForNodeType(node.type)
                        : '',
                    'xray.accessLogs.appliedIp': shouldShip ? String(node.ip || '') : '',
                    // Do not overwrite appliedSsh on a config-only fast path:
                    // the current SSH credential was not actually exercised.
                    // Same-host teardown tries current first and keeps the last
                    // verified applied credential as a durable fallback.
                    ...(shouldShip ? {} : { 'xray.accessLogs.appliedSsh': {} }),
                    'xray.accessLogs.cleanupRequired': shouldShip,
                },
            });
            return { node: node.name, status: effectiveStatus, skipped: true };
        }

        if (!shouldShip) {
            try {
                await credentialService.revokeIngestToken(node._id);
            } catch (error) {
                revokeError = error;
                logger.error(`[AccessLogs] Node ${node.name}: token revoke failed before remote cleanup: ${error.message}`);
            }
        }

        // Persist the desired per-node flag BEFORE pushing config so the config
        // generator + agent-config builder read the new state.
        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.enabled': shouldShip,
                'xray.accessLogs.cleanupRequired': shouldShip
                    || !!previousAppliedSource
                    || !!previousPendingSource
                    || !!node.xray?.accessLogs?.cleanupRequired,
                'xray.accessLogs.status': shouldShip ? 'pending' : 'disabled',
                'xray.accessLogs.lastError': '',
                'xray.accessLogs.lastReconcileAt': new Date(),
            },
        });
        reconcileStarted = true;

        // Push config. Xray uses its existing full-sync path. Hysteria only
        // reconciles the logging drop-in and agent: proxy YAML/user auth remain
        // untouched. Reload the fresh node doc so the updated flag is reflected.
        let appliedType = node.type;
        let appliedIp = String(node.ip || '');
        let appliedSsh = runtimeSshSnapshot(node.ssh);
        queueService = require('../syncService');
        // Serialize with ordinary node config pushes. A role/type edit schedules
        // both paths; without the shared per-node queue they could race while
        // writing cc-agent config or restarting Hysteria/Xray.
        await queueService.enqueueNodeTask(node._id, async () => {
            const fresh = await HyNode.findById(node._id);
            if (!fresh) throw new Error('node was deleted during access-log reconciliation');
            if (fresh.xray?.accessLogs?.deletePending && shouldShip) {
                throw new Error('node deletion is in progress');
            }
            if (fresh.active === false && fresh.type === 'xray') {
                // The operator intentionally stopped this proxy. A normal Xray
                // config update would restart it, so use the dedicated teardown
                // path that keeps both Xray and cc-agent stopped while disabling
                // their access-log configs. Do not report the node disabled until
                // the remote collector is actually stopped.
                await disableRecordedAccessLogRuntimes(fresh, previousRuntime, queueService);
                logger.info(`[AccessLogs] Node ${fresh.name}: disabled access logs on inactive Xray runtime`);
                return;
            }
            appliedType = fresh.type;
            appliedIp = String(fresh.ip || '');
            appliedSsh = runtimeSshSnapshot(fresh.ssh);

            const hysteriaTargetMoved = previousAppliedIp
                && String(previousAppliedIp) !== String(fresh.ip || '');
            let remainingPendingSource = previousPendingSource;
            let remainingPendingIp = previousPendingIp;
            let previousHysteriaTornDown = false;
            let previousXrayTornDown = false;

            const pendingHysteriaMoved = previousPendingIp
                && String(previousPendingIp) !== String(fresh.ip || '');
            if (previousPendingSource === 'hysteria-journal'
                && (!shouldShip || fresh.type !== 'hysteria' || pendingHysteriaMoved)) {
                await disableHysteriaAccessLogRuntime(
                    fresh,
                    previousRuntime,
                    previousPendingIp,
                    'pending'
                );
                remainingPendingSource = '';
                remainingPendingIp = '';
                const clearedPending = await HyNode.updateOne({ _id: node._id }, {
                    $set: {
                        'xray.accessLogs.pendingSource': '',
                        'xray.accessLogs.pendingIp': '',
                        'xray.accessLogs.pendingSsh': {},
                    },
                });
                if (Number(clearedPending?.matchedCount) === 0) {
                    throw new Error('node disappeared while clearing pending HY2 runtime');
                }
            }
            const pendingXrayMoved = previousPendingIp
                && String(previousPendingIp) !== String(fresh.ip || '');
            if (isXrayRuntimeSource(previousPendingSource)
                && (!shouldShip || fresh.type !== 'xray' || pendingXrayMoved)) {
                await disableXrayAccessLogRuntime(
                    fresh,
                    previousRuntime,
                    previousPendingIp,
                    'pending',
                    queueService
                );
                remainingPendingSource = '';
                remainingPendingIp = '';
                const clearedPending = await HyNode.updateOne({ _id: node._id }, {
                    $set: {
                        'xray.accessLogs.pendingSource': '',
                        'xray.accessLogs.pendingIp': '',
                        'xray.accessLogs.pendingSsh': {},
                    },
                });
                if (Number(clearedPending?.matchedCount) === 0) {
                    throw new Error('node disappeared while clearing pending Xray runtime');
                }
            }
            if (previousAppliedSource === 'hysteria-journal'
                && (!shouldShip || fresh.type !== 'hysteria' || hysteriaTargetMoved)) {
                // The node type may have changed after HY2 logging was enabled.
                // Tear down the runtime that was actually provisioned rather than
                // trusting the new type and leaving debug journaling active.
                await disableHysteriaAccessLogRuntime(
                    fresh,
                    previousRuntime,
                    previousAppliedIp,
                    'applied'
                );
                previousHysteriaTornDown = true;
                const clearedApplied = await HyNode.updateOne({ _id: node._id }, {
                    $set: {
                        'xray.accessLogs.appliedFingerprint': '',
                        'xray.accessLogs.appliedSource': '',
                        'xray.accessLogs.appliedIp': '',
                        'xray.accessLogs.appliedSsh': {},
                        'xray.accessLogs.cleanupRequired': !!remainingPendingSource,
                    },
                });
                if (Number(clearedApplied?.matchedCount) === 0) {
                    throw new Error('node disappeared while clearing old HY2 runtime');
                }
            }
            const xrayTargetMoved = previousAppliedIp
                && String(previousAppliedIp) !== String(fresh.ip || '');
            if (isXrayRuntimeSource(previousAppliedSource)
                && (!shouldShip || fresh.type !== 'xray' || xrayTargetMoved)) {
                await disableXrayAccessLogRuntime(
                    fresh,
                    previousRuntime,
                    previousAppliedIp,
                    'applied',
                    queueService
                );
                previousXrayTornDown = true;
                const clearedApplied = await HyNode.updateOne({ _id: node._id }, {
                    $set: {
                        'xray.accessLogs.appliedFingerprint': '',
                        'xray.accessLogs.appliedSource': '',
                        'xray.accessLogs.appliedIp': '',
                        'xray.accessLogs.appliedSsh': {},
                        'xray.accessLogs.cleanupRequired': !!remainingPendingSource,
                    },
                });
                if (Number(clearedApplied?.matchedCount) === 0) {
                    throw new Error('node disappeared while clearing old Xray runtime');
                }
            }

            if (fresh.type === 'hysteria' && !(previousHysteriaTornDown && !shouldShip)) {
                const nodeSetup = require('../nodeSetup');
                const accessLogs = await buildNodeAccessLogsConfig(fresh);
                if (shouldShip) {
                    const pendingState = await HyNode.updateOne({ _id: node._id }, {
                        $set: {
                            'xray.accessLogs.pendingSource': 'hysteria-journal',
                            'xray.accessLogs.pendingIp': String(fresh.ip || ''),
                            'xray.accessLogs.pendingSsh': runtimeSshSnapshot(fresh.ssh),
                            'xray.accessLogs.cleanupRequired': true,
                        },
                    });
                    if (Number(pendingState?.matchedCount) === 0) {
                        throw new Error('node disappeared before pending HY2 runtime was recorded');
                    }
                    // A later step can fail after the remote logging override is
                    // already active. Once the durable pending target exists,
                    // the catch path must always attempt a remote teardown.
                    remoteEnabledRuntime = fresh;
                }
                const result = await nodeSetup.reconcileHysteriaAccessLogs(fresh, accessLogs, {
                    installAgent: needsAgentInstall,
                    minimumAgentVersion: minimumVersion,
                });
                if (needsAgentInstall && !agentVersionAtLeast(result?.agentVersion, minimumVersion)) {
                    throw new Error(`installed cc-agent version ${result?.agentVersion || 'unknown'} does not satisfy ${minimumVersion}+`);
                }
                if (result?.agentVersion) {
                    await HyNode.updateOne({ _id: node._id }, {
                        $set: {
                            agentVersion: result.agentVersion,
                            agentStatus: 'unknown',
                        },
                    });
                }
                if (result?.journalUnit) {
                    fresh.xray.accessLogs.journalUnit = result.journalUnit;
                    if (Array.isArray(result.journalSources) && result.journalSources.length > 0) {
                        fresh.xray.accessLogs.journalSources = result.journalSources;
                    }
                    fingerprint = desiredFingerprint(shouldShip, settings, tokenHash, fresh);
                    await HyNode.updateOne({ _id: node._id }, {
                        $set: {
                            'xray.accessLogs.journalUnit': result.journalUnit,
                            ...(Array.isArray(result.journalSources) && result.journalSources.length > 0
                                ? { 'xray.accessLogs.journalSources': result.journalSources }
                                : {}),
                        },
                    });
                }
            } else if (fresh.type === 'xray' && !(previousXrayTornDown && !shouldShip)) {
                if (shouldShip) {
                    const pendingState = await HyNode.updateOne({ _id: node._id }, {
                        $set: {
                            'xray.accessLogs.pendingSource': 'xray-journal',
                            'xray.accessLogs.pendingIp': String(fresh.ip || ''),
                            'xray.accessLogs.pendingSsh': runtimeSshSnapshot(fresh.ssh),
                            'xray.accessLogs.cleanupRequired': true,
                        },
                    });
                    if (Number(pendingState?.matchedCount) === 0) {
                        throw new Error('node disappeared before pending Xray runtime was recorded');
                    }
                    // Upload/restart may succeed before a later /sync or health
                    // check reports failure. Treat the target as rollback-eligible
                    // from the first possible remote mutation onward.
                    remoteEnabledRuntime = fresh;
                }
                const updated = await queueService.updateXrayNodeConfig(fresh, {
                    previousAccessLogSource: liveAgent?.accessLogs?.source
                        || (previousAppliedSource === 'xray-file' || previousPendingSource === 'xray-file'
                            ? 'file' : ''),
                });
                if (updated === false) {
                    throw new Error('Xray config update failed while applying access logs');
                }
                if (shouldShip) {
                    await waitForAccessLogAgentSourceReady(fresh, accessLogSourceForNode(fresh));
                }
            } else if (shouldShip) {
                throw new Error(`unsupported access-log node type: ${fresh.type}`);
            } else {
                // A formerly physical node can be converted to a virtual entry.
                // Its ingest token is already revoked above, so local cleanup is
                // sufficient and no invalid remote config push is attempted.
                logger.warn(`[AccessLogs] Node ${fresh.name}: revoked stale access-log credential after type change`);
            }
        });

        if (!shouldShip && revokeError) {
            await credentialService.revokeIngestToken(node._id);
        }

        const finalState = {
            'xray.accessLogs.enabled': shouldShip,
            'xray.accessLogs.status': shouldShip ? 'active' : 'disabled',
            'xray.accessLogs.lastError': '',
            'xray.accessLogs.lastReconcileAt': new Date(),
            'xray.accessLogs.appliedFingerprint': fingerprint,
            'xray.accessLogs.appliedSource': shouldShip
                ? runtimeSourceForNodeType(appliedType)
                : '',
            'xray.accessLogs.appliedIp': shouldShip ? appliedIp : '',
            'xray.accessLogs.appliedSsh': shouldShip ? appliedSsh : {},
            'xray.accessLogs.pendingSource': '',
            'xray.accessLogs.pendingIp': '',
            'xray.accessLogs.pendingSsh': {},
            'xray.accessLogs.cleanupRequired': shouldShip,
        };
        const appliedState = await HyNode.updateOne({ _id: node._id }, { $set: finalState });
        if (Number(appliedState?.matchedCount) === 0) {
            throw new Error('node disappeared before access-log state could be committed');
        }

        return { node: node.name, status: shouldShip ? 'active' : 'disabled' };
    } catch (err) {
        let rollbackError = null;
        if (shouldShip && remoteEnabledRuntime) {
            try {
                const queue = queueService || require('../syncService');
                await queue.enqueueNodeTask(node._id, async () => {
                    if (remoteEnabledRuntime.type === 'hysteria') {
                        const nodeSetup = require('../nodeSetup');
                        const teardownNode = buildHysteriaTeardownNode(
                            remoteEnabledRuntime,
                            remoteEnabledRuntime,
                            // This is the runtime enabled during the current
                            // attempt. A stale appliedIp can point at the old
                            // host after A -> B migration, so always roll back
                            // the fresh target's actual IP.
                            remoteEnabledRuntime.ip
                        );
                        await nodeSetup.reconcileHysteriaAccessLogs(
                            teardownNode,
                            { enabled: false, ...accessLogSourceForNode(teardownNode) },
                            { installAgent: false }
                        );
                    } else if (remoteEnabledRuntime.type === 'xray') {
                        await disableXrayAccessLogRuntime(
                            remoteEnabledRuntime,
                            remoteEnabledRuntime,
                            remoteEnabledRuntime.ip,
                            'pending',
                            queue
                        );
                    }
                });
                logger.warn(`[AccessLogs] Node ${node.name}: rolled back remote enable after panel state failure`);
            } catch (error) {
                rollbackError = error;
                logger.error(`[AccessLogs] Node ${node.name}: remote rollback failed: ${error.message}`);
            }
        }
        if (shouldShip) {
            try {
                await credentialService.revokeIngestToken(node._id);
            } catch (revokeError) {
                logger.error(`[AccessLogs] Node ${node.name}: failed to revoke token after reconcile error: ${revokeError.message}`);
            }
        }
        const errorMessage = rollbackError
            ? `${err.message || err}; remote rollback failed: ${rollbackError.message}`
            : String(err.message || err);
        const cleanupStillRequired = shouldShip
            ? reconcileStarted && !(remoteEnabledRuntime && !rollbackError)
            : reconcileStarted && !!(
                previousAppliedSource
                || previousPendingSource
                || node.xray?.accessLogs?.cleanupRequired
                || node.xray?.accessLogs?.enabled
            );
        try {
            await HyNode.updateOne({ _id: node._id }, {
                $set: {
                    'xray.accessLogs.enabled': false,
                    // A failed disable must retain its durable cleanup marker;
                    // otherwise an inactive node could keep collecting remotely
                    // while the panel permanently reports it disabled.
                    'xray.accessLogs.cleanupRequired': cleanupStillRequired,
                    ...(remoteEnabledRuntime && !rollbackError ? {
                        'xray.accessLogs.pendingSource': '',
                        'xray.accessLogs.pendingIp': '',
                        'xray.accessLogs.pendingSsh': {},
                    } : {}),
                    'xray.accessLogs.status': 'error',
                    'xray.accessLogs.lastError': errorMessage.slice(0, 500),
                    'xray.accessLogs.lastReconcileAt': new Date(),
                },
            });
        } catch (stateError) {
            logger.error(`[AccessLogs] Node ${node.name}: failed to persist reconcile error: ${stateError.message}`);
        }
        logger.error(`[AccessLogs] Node ${node.name}: reconcile failed: ${err.message}`);
        return { node: node.name, status: 'error', error: errorMessage };
    }
}

// Single-flight guard: two quick settings saves must not run two overlapping
// reconciles (double Xray restarts). A save that lands mid-run schedules one
// follow-up pass so the latest desired state always wins.
let reconcileRunning = false;
let reconcileQueued = false;
const pendingPreviousRuntimes = new Map();

function scheduleReconcile(options = {}) {
    const previousNode = options.previousNode;
    if (previousNode?._id) {
        pendingPreviousRuntimes.set(String(previousNode._id), previousNode);
    }
    setImmediate(() => {
        reconcileAll().catch(error => {
            logger.error(`[AccessLogs] scheduled reconcile failed: ${error.message}`);
        });
    });
}

/**
 * Reconcile every eligible node against the current global setting, then update
 * the global state (active/disabled/error) accordingly.
 */
async function reconcileAll() {
    if (reconcileRunning) {
        reconcileQueued = true;
        return { state: 'queued', results: [] };
    }
    reconcileRunning = true;
    try {
        const Settings = require('../../models/settingsModel');
        const HyNode = require('../../models/hyNodeModel');
        const settings = await Settings.get();
        const wantEnabled = !!settings?.accessLogs?.enabled;

        const nodes = await HyNode.find({
            $or: [
                {
                    type: { $in: ['xray', 'hysteria'] },
                    cascadeRole: { $in: ['standalone', 'portal'] },
                    active: { $ne: false },
                },
                // Also reconcile nodes that used to be eligible. Otherwise a
                // role/type change can leave an enabled shipper and credential
                // behind forever because the node disappears from this query.
                { 'xray.accessLogs.enabled': true },
                {
                    'xray.accessLogs.appliedFingerprint': {
                        $exists: true,
                        $nin: ['', 'disabled'],
                    },
                },
                { 'xray.accessLogs.appliedSource': { $exists: true, $ne: '' } },
                { 'xray.accessLogs.pendingSource': { $exists: true, $ne: '' } },
                { 'xray.accessLogs.ingestTokenHash': { $exists: true, $ne: '' } },
                { 'xray.accessLogs.cleanupRequired': true },
                { 'xray.accessLogs.deletePending': true },
            ],
        });

        const results = [];
        for (const node of nodes) {
            const key = String(node._id);
            const previousRuntime = pendingPreviousRuntimes.get(key);
            let result;
            try {
                result = await reconcileNode(node, settings, { previousRuntime });
                results.push(result);
            } finally {
                // Keep the one-shot old-host/SSH snapshot after a failed move
                // so a later reconcile can retry remote teardown. Dropping it
                // on error would leave only the new host credentials and make
                // cleanup of the old HY2 runtime impossible.
                const completed = result
                    && !['error', 'agent-outdated', 'agent-missing'].includes(result.status);
                if (completed && pendingPreviousRuntimes.get(key) === previousRuntime) {
                    pendingPreviousRuntimes.delete(key);
                }
            }
        }

        const anyError = results.some(r => ['error', 'agent-outdated', 'agent-missing'].includes(r.status));
        let globalState;
        if (anyError) {
            globalState = 'error';
        } else if (!wantEnabled) {
            globalState = 'disabled';
        } else {
            globalState = 'active';
        }
        await Settings.update({ 'accessLogs.state': globalState });

        const skipped = results.filter(r => r.skipped).length;
        logger.info(`[AccessLogs] Reconcile complete: state=${globalState}, nodes=${results.length} (${skipped} unchanged)`);
        return { state: globalState, results };
    } finally {
        reconcileRunning = false;
        if (reconcileQueued) {
            reconcileQueued = false;
            setImmediate(() => { reconcileAll().catch(e => logger.error(`[AccessLogs] queued reconcile failed: ${e.message}`)); });
        }
    }
}

module.exports = {
    MIN_AGENT_VERSION,
    MIN_HYSTERIA_AGENT_VERSION,
    agentVersionAtLeast,
    minimumAgentVersionForNode,
    probeHysteriaAgent,
    probeAccessLogAgent,
    waitForAccessLogAgentSourceReady,
    resolveIngestUrl,
    isEligibleNode,
    normalizeHysteriaJournalSources,
    journalSourceStatusMatches,
    accessLogSourceForNode,
    buildHysteriaTeardownNode,
    buildXrayTeardownNode,
    buildRuntimeTeardownCandidates,
    disableHysteriaAccessLogRuntime,
    disableXrayAccessLogRuntime,
    runtimeSshSnapshot,
    disableInactiveXrayAccessLogs,
    disableRecordedAccessLogRuntimes,
    deleteNodeWithAccessLogCleanup,
    nodeShouldShip,
    buildNodeAccessLogsConfig,
    reconcileNode,
    reconcileAll,
    scheduleReconcile,
};
