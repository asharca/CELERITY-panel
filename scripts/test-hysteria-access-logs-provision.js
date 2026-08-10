/**
 * HY2 access-log provisioning contract tests (no MongoDB/SSH required).
 *
 * Covers node eligibility/version gates, the reversible systemd logging
 * override, and the cc-agent journal-source JSON shape shared with the Go
 * agent. Route-query assertions protect the settings/status UI from silently
 * regressing back to Xray-only node discovery.
 */

process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';
process.env.PANEL_DOMAIN ||= 'panel.example.invalid';
process.env.ACME_EMAIL ||= 'admin@example.invalid';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { Readable } = require('stream');

const provision = require('../src/services/accessLogs/provisionService');
const configGenerator = require('../src/services/configGenerator');
const nodeSetup = require('../src/services/nodeSetup');
const HyNode = require('../src/models/hyNodeModel');
const sshPoolService = require('../src/services/sshPoolService');

const hy = { _id: 'hy-1', type: 'hysteria', cascadeRole: 'standalone' };
const xray = { _id: 'xr-1', type: 'xray', cascadeRole: 'portal' };

assert.notStrictEqual(
    sshPoolService.connectionIdentity({ _id: 'same', ip: '198.51.100.1', ssh: { password: 'old' } }),
    sshPoolService.connectionIdentity({ _id: 'same', ip: '198.51.100.2', ssh: { password: 'new' } }),
    'pooled SSH identity binds both target and credentials'
);
assert.notStrictEqual(
    sshPoolService.connectionIdentity({ _id: 'same', ip: '198.51.100.1', ssh: { password: 'old' } }),
    sshPoolService.connectionIdentity({ _id: 'same', ip: '198.51.100.1', ssh: { password: 'rotated' } }),
    'same-host credential rotation must open a fresh SSH connection'
);

assert.strictEqual(provision.isEligibleNode(hy), true);
assert.strictEqual(provision.isEligibleNode(xray), true);
assert.strictEqual(provision.isEligibleNode({ ...hy, cascadeRole: 'bridge' }), false);
assert.strictEqual(provision.isEligibleNode({ ...hy, type: 'virtual' }), false);
assert.strictEqual(provision.isEligibleNode({ ...hy, active: false }), false);

assert.strictEqual(provision.minimumAgentVersionForNode(hy), '1.5.2');
assert.strictEqual(provision.minimumAgentVersionForNode(xray), '1.5.2');
assert.strictEqual(provision.agentVersionAtLeast('v1.5.2', '1.5.2'), true);
assert.strictEqual(provision.agentVersionAtLeast('1.5.1', '1.5.2'), false);
assert.strictEqual(provision.agentVersionAtLeast('installed', '1.5.1'), false);
assert.strictEqual(nodeSetup.parseAgentVersion('cc-agent 1.5.0'), '1.5.0');
assert.strictEqual(nodeSetup.parseAgentVersion('2026/08/10 cc-agent v1.5.1'), '1.5.1');
assert.strictEqual(nodeSetup.parseAgentVersion('download complete'), '');
assert.strictEqual(nodeSetup.isAgentVersionAtLeast('1.5.2', '1.5.2'), true);
assert.strictEqual(nodeSetup.isAgentVersionAtLeast('1.5.1', '1.5.2'), false);
assert.strictEqual(nodeSetup.normalizeFirewallSource('203.0.113.10/32'), '203.0.113.10/32');
assert.strictEqual(nodeSetup.normalizeFirewallSource('[2001:db8::1]/64'), '2001:db8::1/64');
assert.strictEqual(nodeSetup.normalizeFirewallSource('https://panel.example.invalid:8443/path'), 'panel.example.invalid');
assert.strictEqual(nodeSetup.normalizeFirewallSource('203.0.113.10; touch /tmp/pwned'), '');
assert.strictEqual(nodeSetup.normalizeFirewallSource('panel.example.invalid$(id)'), '');

// A panel operator may deliberately SSH as an unprivileged service account
// with passwordless sudo. Agent provisioning must stage uploads in /tmp and
// elevate only the fixed system mutations, rather than requiring a root SSH
// login or attempting to write /usr/local directly.
const privilegedDaemonReload = nodeSetup.buildPrivilegedShellCommand('systemctl daemon-reload');
assert(privilegedDaemonReload.includes('id -u'), 'root logins must stay supported without sudo');
assert(privilegedDaemonReload.includes('sudo -n sh -c'), 'non-root SSH uses non-interactive sudo');
assert(privilegedDaemonReload.includes("'systemctl daemon-reload'"));
const agentInstallerSource = nodeSetup.installCCAgent.toString();
assert(agentInstallerSource.includes('`/tmp/.cc-agent-download-'));
assert(!agentInstallerSource.includes('/usr/local/bin/.cc-agent-download-'));
assert(agentInstallerSource.includes('execPrivilegedSSH'));
assert(agentInstallerSource.includes('uploadPrivilegedFile'));

assert.strictEqual(
    provision.nodeShouldShip(hy, { accessLogs: { enabled: true, nodeScope: 'all' } }),
    true
);
assert.strictEqual(
    provision.nodeShouldShip(hy, {
        accessLogs: { enabled: true, nodeScope: 'selected', nodeIds: ['another-node'] },
    }),
    false
);

assert.deepStrictEqual(provision.accessLogSourceForNode(hy), {
    source: 'journal',
    format: 'hysteria2-json',
    journalUnit: 'hysteria-server',
    journalSources: [{ unit: 'hysteria-server', tag: '' }],
    path: '',
});
assert.strictEqual(
    provision.accessLogSourceForNode({ ...hy, xray: { accessLogs: { journalUnit: 'hysteria' } } }).journalUnit,
    'hysteria'
);
assert.deepStrictEqual(provision.accessLogSourceForNode(xray), {
    source: 'journal',
    format: 'xray',
    journalUnit: 'xray',
    path: '',
});

const multiJournalSources = [
    { unit: 'hysteria-server', tag: 'main' },
    { unit: 'hysteria-server@mobile', tag: 'mobile' },
    { unit: 'hysteria-server@telecom', tag: 'telecom' },
    { unit: 'hysteria-dev', tag: 'dev' },
];
assert.deepStrictEqual(
    provision.normalizeHysteriaJournalSources({ journalSources: multiJournalSources }),
    multiJournalSources,
    'a physical HY2 host can publish several tagged systemd sources'
);
assert.throws(
    () => provision.normalizeHysteriaJournalSources({
        journalSources: [{ unit: 'hysteria-server' }, { unit: 'hysteria-dev', tag: 'dev' }],
    }),
    /needs a runtime tag/
);
assert.throws(
    () => provision.normalizeHysteriaJournalSources({
        journalSources: [{ unit: 'hysteria-server; reboot', tag: 'main' }],
    }),
    /Invalid Hysteria journal systemd unit/
);
const multiHy = { ...hy, xray: { accessLogs: { journalSources: multiJournalSources } } };
assert.deepStrictEqual(provision.accessLogSourceForNode(multiHy), {
    source: 'journal',
    format: 'hysteria2-json',
    journalUnit: 'hysteria-server',
    journalSources: multiJournalSources,
    path: '',
});
assert.strictEqual(provision.journalSourceStatusMatches({
    journal_sources: multiJournalSources,
}, provision.accessLogSourceForNode(multiHy)), true);
assert.strictEqual(provision.journalSourceStatusMatches({
    journal_sources: multiJournalSources.slice(0, 3),
}, provision.accessLogSourceForNode(multiHy)), false);
assert.strictEqual(
    configGenerator.buildXrayLogSection({ xray: { accessLogs: { enabled: true } } }).access,
    '',
    'Xray access lines go to stdout/journald instead of an unbounded active file'
);
assert.strictEqual(configGenerator.buildXrayLogSection({ xray: { accessLogs: { enabled: false } } }).access, 'none');

const override = configGenerator.generateHysteriaAccessLogSystemdOverride(true);
assert(override.includes('Environment=HYSTERIA_LOG_LEVEL=debug'));
assert(override.includes('Environment=HYSTERIA_LOG_FORMAT=json'));
assert(!override.includes('ExecStart='), 'drop-in must preserve the node\'s existing ExecStart');
assert.strictEqual(configGenerator.generateHysteriaAccessLogSystemdOverride(false), '');
assert(configGenerator.generateSystemdService({ accessLogsEnabled: true }).includes('HYSTERIA_LOG_FORMAT=json'));
assert(!configGenerator.generateSystemdService().includes('HYSTERIA_LOG_FORMAT=json'));
assert.strictEqual(
    nodeSetup.HYSTERIA_ACCESS_LOG_OVERRIDE_PATH,
    '/etc/systemd/system/hysteria-server.service.d/20-celerity-access-logs.conf'
);
assert.strictEqual(
    nodeSetup.hysteriaAccessLogOverridePath('hysteria'),
    '/etc/systemd/system/hysteria.service.d/20-celerity-access-logs.conf'
);
assert.strictEqual(
    nodeSetup.hysteriaAccessLogOverridePath('hysteria-server@mobile'),
    '/etc/systemd/system/hysteria-server@mobile.service.d/20-celerity-access-logs.conf'
);
assert.deepStrictEqual(
    nodeSetup.normalizeHysteriaJournalSources({ journalSources: multiJournalSources }),
    multiJournalSources
);
assert.strictEqual(nodeSetup.journalSourcesMatchAgentStatus({
    journal_sources: multiJournalSources.map(source => ({ ...source, source_ready: true })),
}, { source: 'journal', journalSources: multiJournalSources }), true);
assert.throws(() => nodeSetup.hysteriaAccessLogOverridePath('hysteria; reboot'), /Unsupported/);
assert.doesNotThrow(() => nodeSetup.assertHysteriaExecStartLoggingCompatible(
    '{ argv[]=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml ; }'
));
assert.doesNotThrow(() => nodeSetup.assertHysteriaExecStartLoggingCompatible(
    '/usr/local/bin/hysteria server -l debug --log-format=json'
));
assert.throws(
    () => nodeSetup.assertHysteriaExecStartLoggingCompatible('/usr/local/bin/hysteria server --log-level info'),
    /debug is required/
);
assert.throws(
    () => nodeSetup.assertHysteriaExecStartLoggingCompatible(
        '/usr/local/bin/hysteria server --log-level=debug --log-level=info --log-format=json'
    ),
    /debug is required/,
    'the last repeated pflag value is effective'
);
assert.throws(
    () => nodeSetup.assertHysteriaExecStartLoggingCompatible(
        '/usr/local/bin/hysteria server --log-level=debug -linfo --log-format=json'
    ),
    /debug is required/,
    'compact short pflags must participate in last-value semantics'
);
assert.throws(
    () => nodeSetup.assertHysteriaExecStartLoggingCompatible(
        '/usr/local/bin/hysteria server -ldebug -fconsole'
    ),
    /json is required/,
    'compact short log-format overrides must be rejected'
);
assert.throws(
    () => nodeSetup.assertHysteriaExecStartLoggingCompatible(
        '/usr/local/bin/hysteria server -l debug --log-level info -f json'
    ),
    /debug is required/,
    'short and long log flags share the same last-value semantics'
);
assert.throws(
    () => nodeSetup.assertHysteriaExecStartLoggingCompatible('/usr/local/bin/hysteria server -f console'),
    /json is required/
);
assert.doesNotThrow(() => nodeSetup.assertHysteriaEffectiveLoggingEnvironment(
    'HYSTERIA_LOG_LEVEL=info HYSTERIA_LOG_LEVEL=debug HYSTERIA_LOG_FORMAT=json'
));
assert.throws(
    () => nodeSetup.assertHysteriaEffectiveLoggingEnvironment(
        'HYSTERIA_LOG_LEVEL=debug HYSTERIA_LOG_FORMAT=json HYSTERIA_LOG_LEVEL=info'
    ),
    /debug\/json/,
    'a later custom drop-in must not silently disable request events'
);
assert.doesNotThrow(() => nodeSetup.assertHysteriaEffectiveLoggingEnvironment(
    'HYSTERIA_LOG_LEVEL=debug\0HYSTERIA_LOG_FORMAT=json\0OTHER=value with spaces\0'
));
assert.throws(
    () => nodeSetup.assertHysteriaEffectiveLoggingEnvironment(
        'HYSTERIA_LOG_LEVEL=debug \0HYSTERIA_LOG_FORMAT=json\0'
    ),
    /debug\/json/,
    'process environment values are exact and must not be trimmed into validity'
);
assert.throws(
    () => nodeSetup.assertHysteriaEffectiveLoggingEnvironment(
        'HYSTERIA_LOG_LEVEL=info\0OTHER=x HYSTERIA_LOG_LEVEL=debug\0HYSTERIA_LOG_FORMAT=json\0'
    ),
    /debug\/json/,
    'a key-like substring inside another process environment value must not pass validation'
);
assert.strictEqual(
    nodeSetup.hasStructuredHysteriaStartupLog('plain line\n{"level":"info","msg":"server up and running"}'),
    true
);
assert.strictEqual(nodeSetup.hasStructuredHysteriaStartupLog('plain line only'), false);
const nodeSetupSource = fs.readFileSync(path.join(__dirname, '..', 'src/services/nodeSetup.js'), 'utf8');
const reconcileStart = nodeSetupSource.indexOf('async function reconcileHysteriaAccessLogsUnlocked');
const reconcileEnd = nodeSetupSource.indexOf('\nfunction reconcileHysteriaAccessLogs(', reconcileStart);
const reconcileSource = nodeSetupSource.slice(reconcileStart, reconcileEnd);
assert(reconcileSource.includes('normalizeHysteriaJournalSources(accessLogs)'));
assert(reconcileSource.includes('systemctl restart ${source.unit}'));
assert(reconcileSource.includes('systemctl restart cc-agent'));
assert(
    reconcileSource.indexOf('systemctl restart cc-agent') < reconcileSource.indexOf('systemctl restart ${source.unit}'),
    'agent must follow the journal before Hysteria starts emitting request events'
);
assert(reconcileSource.includes("execPrivilegedSSH(conn, 'systemctl daemon-reload')"));
assert(reconcileSource.includes('assertHysteriaEffectiveLoggingEnvironment(effectiveEnvironment.output)'));
assert(reconcileSource.includes('/proc/$PID/environ'), 'running HY2 process environment is verified after restart');
assert(reconcileSource.includes('/proc/$PID/exe'), 'the systemd MainPID must directly execute Hysteria');
assert(reconcileSource.includes('MainPID does not run Hysteria directly'));
assert(reconcileSource.includes('MainPID executable does not match ExecStart'));
assert(nodeSetup.removeHysteriaAccessLogOverride.toString().includes('rm -f ${overridePath} || exit 1'));

const agentConfig = nodeSetup.buildAgentConfig(
    { type: 'hysteria', xray: {} },
    'agent-token',
    62080,
    61000,
    true,
    {
        enabled: true,
        source: 'journal',
        format: 'hysteria2-json',
        journalUnit: 'hysteria-server',
        path: '',
        ingestUrl: 'https://panel.example.invalid/api/access-logs/ingest',
        ingestToken: 'ingest-token',
    }
);
assert.strictEqual(agentConfig.access_logs.enabled, true);
assert.strictEqual(agentConfig.access_logs.source, 'journal');
assert.strictEqual(agentConfig.access_logs.format, 'hysteria2-json');
assert.strictEqual(agentConfig.access_logs.journal_unit, 'hysteria-server');
assert.strictEqual(agentConfig.access_logs.path, '');
assert.strictEqual(agentConfig.access_logs.ingest_token, 'ingest-token');
const multiAgentConfig = nodeSetup.buildAgentConfig(
    { type: 'hysteria', xray: {} },
    'agent-token',
    62080,
    61000,
    true,
    {
        ...provision.accessLogSourceForNode(multiHy),
        enabled: true,
        ingestUrl: 'https://panel.example.invalid/api/access-logs/ingest',
        ingestToken: 'ingest-token',
    }
);
assert.deepStrictEqual(multiAgentConfig.access_logs.journal_sources, multiJournalSources);

const modelNode = new HyNode({ type: 'hysteria', name: 'hy', ip: '203.0.113.10' });
modelNode.xray.accessLogs.status = 'agent-missing';
modelNode.xray.accessLogs.appliedSource = 'hysteria-journal';
modelNode.xray.accessLogs.appliedIp = '203.0.113.10';
modelNode.xray.accessLogs.appliedSsh.password = 'encrypted-old-password';
modelNode.xray.accessLogs.pendingSsh.privateKey = 'encrypted-pending-key';
modelNode.xray.accessLogs.journalUnit = 'hysteria';
modelNode.xray.accessLogs.journalSources = multiJournalSources;
assert.strictEqual(modelNode.validateSync(), undefined, 'HY2 can persist agent-missing state');
assert.strictEqual(modelNode.xray.accessLogs.appliedSsh.password, 'encrypted-old-password');
assert.strictEqual(modelNode.xray.accessLogs.pendingSsh.privateKey, 'encrypted-pending-key');

const teardownNode = provision.buildHysteriaTeardownNode(
    { _id: 'moved', name: 'Moved node', type: 'virtual', ip: null, ssh: { password: 'new-secret' }, xray: {} },
    {
        _id: 'moved',
        name: 'Moved node',
        type: 'hysteria',
        ip: '198.51.100.20',
        ssh: { password: 'old-secret' },
        xray: {
            agentToken: 'old-agent-token',
            accessLogs: { appliedSource: 'hysteria-journal', appliedIp: '198.51.100.20', journalUnit: 'hysteria' },
        },
    },
    '198.51.100.20'
);
assert.strictEqual(teardownNode.type, 'hysteria');
assert.strictEqual(teardownNode.ip, '198.51.100.20', 'teardown uses the old host after HY2 -> virtual');
assert.strictEqual(teardownNode.ssh.password, 'old-secret', 'teardown uses the old SSH credential snapshot');
assert.strictEqual(teardownNode.xray.agentToken, 'old-agent-token');
assert.strictEqual(teardownNode.xray.accessLogs.journalUnit, 'hysteria');

for (const relative of ['src/routes/panel/settings.js', 'src/routes/panel/accessLogs.js']) {
    const source = fs.readFileSync(path.join(__dirname, '..', relative), 'utf8');
    assert(
        /type:\s*\{\s*\$in:\s*\[['"]xray['"],\s*['"]hysteria['"]\]\s*\}/.test(source),
        `${relative} must query both Xray and Hysteria nodes`
    );
}
const nodeApiSource = fs.readFileSync(path.join(__dirname, '..', 'src/routes/nodes.js'), 'utf8');
assert(nodeApiSource.includes("error: 'xray must be an object'"), 'API must reject xray:null tombstone erasure');
assert(nodeApiSource.includes('+xray.accessLogs.ingestTokenEncrypted'));
const panelNodeSource = fs.readFileSync(path.join(__dirname, '..', 'src/routes/panel/nodes.js'), 'utf8');
assert(
    panelNodeSource.includes('+xray.accessLogs.ingestTokenEncrypted'),
    'Xray form saves must preserve the select:false ingest token ciphertext'
);

// The first enable on a legacy HY2 node (no agentVersion) must take the
// install/upgrade path, not stop at agent-outdated. Patch the small set of DB /
// SSH boundaries so reconcileNode itself is exercised without external I/O.
(async () => {
    const hungStream = new EventEmitter();
    hungStream.stderr = new EventEmitter();
    hungStream.close = () => {};
    const timeoutResult = await nodeSetup.execSSH(
        { exec: (_command, callback) => callback(null, hungStream) },
        'never-closes',
        { timeoutMs: 20 }
    );
    assert.strictEqual(timeoutResult.success, false);
    assert.match(timeoutResult.error, /timed out/);

    const noisyStream = new EventEmitter();
    noisyStream.stderr = new EventEmitter();
    noisyStream.close = () => {};
    const outputLimitPromise = nodeSetup.execSSH(
        {
            exec: (_command, callback) => {
                callback(null, noisyStream);
                setImmediate(() => noisyStream.emit('data', Buffer.alloc(2048, 65)));
            },
        },
        'too-noisy',
        { maxOutputBytes: 1024 }
    );
    const outputLimitResult = await outputLimitPromise;
    assert.strictEqual(outputLimitResult.success, false);
    assert.match(outputLimitResult.error, /output exceeded/);
    await assert.rejects(
        nodeSetup.uploadFile({ sftp: () => {} }, 'content', '/tmp/never', { timeoutMs: 20 }),
        /timed out/
    );
    await assert.rejects(
        nodeSetup.readRemoteFileIfExists({ sftp: () => {} }, '/tmp/never', 1024, { timeoutMs: 20 }),
        /timed out/
    );

    let readinessCalls = 0;
    const readyStatus = await nodeSetup.waitForAgentAccessLogSourceReady(null, {
        token: 'test-token',
        attempts: 2,
        delayMs: 0,
        accessLogs: { source: 'journal', format: 'hysteria2-json', journalUnit: 'hysteria-server' },
        execCommand: async () => {
            readinessCalls++;
            return {
                success: true,
                output: JSON.stringify({
                    access_logs: {
                        enabled: true,
                        source: 'journal',
                        format: 'hysteria2-json',
                        journal_unit: 'hysteria-server',
                        source_ready: readinessCalls > 1,
                        source_error: readinessCalls > 1 ? '' : 'journalctl starting',
                    },
                }),
            };
        },
    });
    assert.strictEqual(readyStatus.source_ready, true);
    await assert.rejects(
        nodeSetup.waitForAgentAccessLogSourceReady(null, {
            token: 'test-token',
            attempts: 1,
            delayMs: 0,
            accessLogs: { source: 'journal', format: 'hysteria2-json', journalUnit: 'hysteria-server' },
            execCommand: async () => ({
                success: true,
                output: JSON.stringify({
                    access_logs: {
                        enabled: true,
                        source: 'journal',
                        format: 'hysteria2-json',
                        journal_unit: 'hysteria-server',
                        source_error: '',
                    },
                }),
            }),
        }),
        /source not ready/,
        'an old agent without source_ready must not be reported active'
    );

    const readinessSyncService = require('../src/services/syncService');
    const originalAgentRequestForReady = readinessSyncService._agentRequest;
    let xrayReadyCalls = 0;
    try {
        readinessSyncService._agentRequest = async () => ({
            status: 200,
            data: {
                agent_version: '1.5.2',
                access_logs: {
                    enabled: true,
                    source: 'journal',
                    format: 'xray',
                    journal_unit: 'xray',
                    source_ready: ++xrayReadyCalls > 1,
                    source_error: xrayReadyCalls > 1 ? '' : 'waiting for xray journal',
                },
            },
        });
        const probe = await provision.waitForAccessLogAgentSourceReady(
            { type: 'xray', xray: { agentToken: 'agent-token' } },
            { source: 'journal', format: 'xray', journalUnit: 'xray' },
            { attempts: 2, delayMs: 0 }
        );
        assert.strictEqual(probe.accessLogs.source_ready, true);
    } finally {
        readinessSyncService._agentRequest = originalAgentRequestForReady;
    }

    const inactiveTeardownActions = [];
    let inactiveConfig = null;
    class FakeInactiveXraySsh {
        async connect() { inactiveTeardownActions.push('connect'); }
        async exec(command) {
            if (command.includes('systemctl stop xray')) inactiveTeardownActions.push('stop-xray');
            if (command.includes('mv -f')) inactiveTeardownActions.push('replace-config');
            return { code: 0 };
        }
        async readFile(remotePath) {
            if (remotePath === '/etc/cc-agent/config.json') {
                return JSON.stringify({ token: 'agent-token' });
            }
            return JSON.stringify({ log: { loglevel: 'warning', access: '/var/log/xray/access.log' } });
        }
        async uploadContent(content, remotePath) {
            if (remotePath.includes('/xray/')) inactiveConfig = JSON.parse(content);
        }
        disconnect() { inactiveTeardownActions.push('disconnect'); }
    }
    await provision.disableInactiveXrayAccessLogs(
        { name: 'Inactive Xray', xray: { agentToken: 'agent-token', accessLogs: { deletePending: true } } },
        {
            NodeSSH: FakeInactiveXraySsh,
        }
    );
    assert.strictEqual(inactiveConfig.log.access, 'none');
    assert(inactiveTeardownActions.includes('stop-xray'));
    assert(inactiveTeardownActions.includes('replace-config'));

    const originalBuildAccessLogs = provision.buildNodeAccessLogsConfig;
    let uploadedAfterBuilderFailure = false;
    try {
        provision.buildNodeAccessLogsConfig = async () => {
            throw new Error('simulated credential read failure');
        };
        await assert.rejects(
            nodeSetup.reloadCcAgent(
                {
                    _id: 'xray-builder-error',
                    name: 'Xray builder error',
                    type: 'xray',
                    ip: '203.0.113.70',
                    xray: { agentToken: 'same-token' },
                },
                {
                    readFile: async () => JSON.stringify({ token: 'same-token' }),
                    uploadContent: async () => { uploadedAfterBuilderFailure = true; },
                    exec: async () => ({ code: 0 }),
                }
            ),
            /simulated credential read failure/
        );
        assert.strictEqual(uploadedAfterBuilderFailure, false, 'builder failure preserves the existing agent config');
    } finally {
        provision.buildNodeAccessLogsConfig = originalBuildAccessLogs;
    }

    const fakeConfigConnection = config => ({
        sftp(callback) {
            const content = Buffer.from(config);
            callback(null, {
                stat(_remotePath, done) { done(null, { size: content.length }); },
                createReadStream() { return Readable.from([content]); },
            });
        },
    });
    await nodeSetup.assertCcAgentConfigOwnership(
        fakeConfigConnection(JSON.stringify({ token: 'same-token' })),
        'same-token'
    );
    await assert.rejects(
        nodeSetup.assertCcAgentConfigOwnership(
            fakeConfigConnection(JSON.stringify({ token: 'xray-owner-token' })),
            'hy2-owner-token'
        ),
        /belongs to another node or proxy service/,
        'HY2 must not overwrite a co-located Xray agent config'
    );
    assert.strictEqual(
        nodeSetup.ccAgentHostKey({ ip: '[2001:DB8::10]' }),
        '2001:db8::10',
        'shared-host lock normalizes bracketed/case-variant IPv6'
    );
    const hostOrder = [];
    const firstHostTask = nodeSetup.enqueueCcAgentHostTask({ ip: '203.0.113.9' }, async () => {
        hostOrder.push('first:start');
        await new Promise(resolve => setTimeout(resolve, 10));
        hostOrder.push('first:end');
    });
    const secondHostTask = nodeSetup.enqueueCcAgentHostTask({ ip: '203.0.113.9' }, async () => {
        hostOrder.push('second');
    });
    await Promise.all([firstHostTask, secondHostTask]);
    assert.deepStrictEqual(hostOrder, ['first:start', 'first:end', 'second'], 'cc-agent host mutations serialize');

    const Settings = require('../src/models/settingsModel');
    const credentialService = require('../src/services/accessLogs/credentialService');
    const syncService = require('../src/services/syncService');
    let unhandledQueueError = null;
    const onUnhandledQueueError = error => { unhandledQueueError = error; };
    process.on('unhandledRejection', onUnhandledQueueError);
    await syncService.enqueueNodeTask('access-log-rejection-test', async () => {
        throw new Error('expected queue rejection');
    }).catch(() => {});
    await new Promise(resolve => setImmediate(resolve));
    process.removeListener('unhandledRejection', onUnhandledQueueError);
    assert.strictEqual(unhandledQueueError, null, 'caught node queue failures must not create unhandled rejections');
    const original = {
        settingsGet: Settings.get,
        updateOne: HyNode.updateOne,
        findById: HyNode.findById,
        ensureIngestToken: credentialService.ensureIngestToken,
        revokeIngestToken: credentialService.revokeIngestToken,
        reconcileHysteriaAccessLogs: nodeSetup.reconcileHysteriaAccessLogs,
        agentRequest: syncService._agentRequest,
    };

    const settings = {
        accessLogs: {
            enabled: true,
            nodeScope: 'all',
            ingestUrl: 'https://panel.example.invalid/api/access-logs/ingest',
        },
        nodeAuth: { insecure: false },
    };
    const legacyHy = {
        _id: 'legacy-hy',
        name: 'Legacy HY2',
        type: 'hysteria',
        cascadeRole: 'standalone',
        agentVersion: '',
        ssh: { password: 'test-only' },
        xray: { accessLogs: { enabled: false, status: 'disabled', appliedFingerprint: '' } },
    };
    const freshHy = {
        ...legacyHy,
        xray: {
            agentToken: 'agent-token',
            accessLogs: { ...legacyHy.xray.accessLogs, enabled: true, status: 'pending' },
        },
    };
    const staleHy = {
        ...legacyHy,
        _id: 'stale-hy',
        name: 'Stale HY2 metadata',
        agentVersion: '1.5.2',
        xray: {
            agentToken: 'agent-token',
            accessLogs: { ...legacyHy.xray.accessLogs },
        },
    };
    const freshStaleHy = {
        ...staleHy,
        xray: {
            ...staleHy.xray,
            accessLogs: { ...staleHy.xray.accessLogs, enabled: true, status: 'pending' },
        },
    };
    const movedBlockedHy = {
        ...legacyHy,
        _id: 'moved-blocked-hy',
        name: 'Moved blocked HY2',
        ip: '198.51.100.20',
        ssh: {},
        xray: {
            accessLogs: {
                enabled: true,
                cleanupRequired: true,
                appliedSource: 'hysteria-journal',
                appliedIp: '198.51.100.10',
                appliedSsh: { username: 'root', password: 'old-host-secret' },
                status: 'active',
            },
        },
    };
    let installOptions = null;
    let finalStatus = '';
    let remoteCalls = 0;
    let failFinalStateOnce = false;
    const remoteEnabledActions = [];

    try {
        Settings.get = async () => settings;
        credentialService.ensureIngestToken = async () => ({ token: 'ingest-token', created: false });
        credentialService.revokeIngestToken = async () => {};
        HyNode.updateOne = async (_filter, update) => {
            if (update?.$set?.['xray.accessLogs.status']) {
                finalStatus = update.$set['xray.accessLogs.status'];
                if (failFinalStateOnce && finalStatus === 'active') {
                    failFinalStateOnce = false;
                    throw new Error('simulated final state write failure');
                }
            }
        };
        HyNode.findById = id => ({
            select: async () => ({ xray: { accessLogs: { ingestTokenHash: 'token-hash' } } }),
            then: (resolve, reject) => Promise.resolve(
                String(id) === 'stale-hy' ? freshStaleHy
                    : String(id) === 'moved-blocked-hy' ? movedBlockedHy
                        : freshHy
            ).then(resolve, reject),
        });
        nodeSetup.reconcileHysteriaAccessLogs = async (_node, accessLogs, options) => {
            remoteCalls++;
            installOptions = options;
            remoteEnabledActions.push(accessLogs.enabled);
            assert.strictEqual(accessLogs.source, 'journal');
            assert.strictEqual(accessLogs.format, 'hysteria2-json');
            return { success: true, agentVersion: '1.5.2' };
        };

        const result = await provision.reconcileNode(legacyHy, settings);
        assert.strictEqual(result.status, 'active');
        assert.strictEqual(installOptions?.installAgent, true, 'legacy HY2 must auto-install cc-agent');
        assert.strictEqual(finalStatus, 'active');
        assert.deepStrictEqual(remoteEnabledActions, [true]);

        finalStatus = '';
        const withoutSsh = { ...legacyHy, _id: 'legacy-hy-no-ssh', ssh: {} };
        const missingResult = await provision.reconcileNode(withoutSsh, settings);
        assert.strictEqual(missingResult.status, 'agent-missing');
        assert.strictEqual(finalStatus, 'agent-missing');
        assert.strictEqual(remoteCalls, 1, 'missing SSH must not attempt remote installation');

        // In selected-node mode, sibling logical entries may retain the local
        // `disabled` fingerprint from a previous reconciliation. That marker
        // is not a remote runtime and must not cause an SSH cleanup attempt.
        const selectedSettings = {
            ...settings,
            accessLogs: {
                ...settings.accessLogs,
                nodeScope: 'selected',
                nodeIds: ['legacy-hy'],
            },
        };
        const unselectedLogicalNode = {
            ...legacyHy,
            _id: 'unselected-logical-node',
            ssh: {},
            xray: {
                accessLogs: {
                    enabled: false,
                    status: 'error',
                    appliedFingerprint: 'disabled',
                    appliedSource: '',
                    pendingSource: '',
                    cleanupRequired: false,
                },
            },
        };
        finalStatus = '';
        const callsBeforeScopeSkip = remoteCalls;
        const scopeSkipResult = await provision.reconcileNode(unselectedLogicalNode, selectedSettings);
        assert.strictEqual(scopeSkipResult.status, 'disabled');
        assert.strictEqual(finalStatus, 'disabled');
        assert.strictEqual(remoteCalls, callsBeforeScopeSkip,
            'an unselected logical entry must not require SSH cleanup');

        const movedBlockedResult = await provision.reconcileNode(movedBlockedHy, settings);
        assert.strictEqual(movedBlockedResult.status, 'agent-missing');
        assert.strictEqual(remoteCalls, 2, 'old host cleanup runs before the new-host prerequisite returns');
        assert.strictEqual(remoteEnabledActions.at(-1), false);
        remoteCalls = 1;
        remoteEnabledActions.pop();

        // A version cached in MongoDB is not proof that the binary/service is
        // still present. A failed authenticated /info probe must force repair.
        syncService._agentRequest = async () => { throw new Error('connection refused'); };
        finalStatus = '';
        installOptions = null;
        const staleResult = await provision.reconcileNode(staleHy, settings);
        assert.strictEqual(staleResult.status, 'active');
        assert.strictEqual(installOptions?.installAgent, true, 'unreachable stale agent metadata must trigger reinstall');
        assert.strictEqual(finalStatus, 'active');
        assert.strictEqual(remoteCalls, 2);

        // If the remote enable succeeds but the final Mongo state write fails,
        // reconciliation must disable the remote source again. Otherwise exact
        // endpoint logs would keep accumulating while the panel reports error.
        remoteEnabledActions.length = 0;
        failFinalStateOnce = true;
        finalStatus = '';
        const rollbackResult = await provision.reconcileNode(legacyHy, settings);
        assert.strictEqual(rollbackResult.status, 'error');
        assert.deepStrictEqual(remoteEnabledActions, [true, false]);
        assert.strictEqual(finalStatus, 'error');
    } finally {
        Settings.get = original.settingsGet;
        HyNode.updateOne = original.updateOne;
        HyNode.findById = original.findById;
        credentialService.ensureIngestToken = original.ensureIngestToken;
        credentialService.revokeIngestToken = original.revokeIngestToken;
        nodeSetup.reconcileHysteriaAccessLogs = original.reconcileHysteriaAccessLogs;
        syncService._agentRequest = original.agentRequest;
        require('../src/services/sshPoolService').closeAll();
    }

    const inactiveOriginal = {
        updateOne: HyNode.updateOne,
        findById: HyNode.findById,
        revokeIngestToken: credentialService.revokeIngestToken,
        updateXrayNodeConfig: syncService.updateXrayNodeConfig,
        disableInactiveXrayAccessLogs: provision.disableInactiveXrayAccessLogs,
    };
    try {
        const inactiveXray = {
            _id: 'inactive-xray',
            name: 'Inactive Xray',
            type: 'xray',
            active: false,
            cascadeRole: 'standalone',
            agentVersion: '1.5.2',
            xray: {
                accessLogs: {
                    enabled: true,
                    cleanupRequired: true,
                    appliedFingerprint: 'old-enabled-fingerprint',
                    appliedSource: 'xray-file',
                    appliedIp: '203.0.113.99',
                    status: 'active',
                },
            },
        };
        let inactiveRemotePushes = 0;
        let inactiveRemoteCleanups = 0;
        const inactiveStateWrites = [];
        HyNode.updateOne = async (_filter, update) => {
            inactiveStateWrites.push(update?.$set || {});
            return { matchedCount: 1 };
        };
        HyNode.findById = async () => inactiveXray;
        credentialService.revokeIngestToken = async () => {};
        syncService.updateXrayNodeConfig = async () => { inactiveRemotePushes++; return true; };
        provision.disableInactiveXrayAccessLogs = async teardown => {
            inactiveRemoteCleanups++;
            assert.strictEqual(teardown.xray.accessLogs.enabled, false);
            assert.strictEqual(teardown.xray.accessLogs.deletePending, true);
            return true;
        };

        for (const source of ['xray-file', 'xray-journal']) {
            inactiveXray.xray.accessLogs.appliedSource = source;
            const inactiveResult = await provision.reconcileNode(inactiveXray, settings);
            assert.strictEqual(inactiveResult.status, 'disabled');
        }
        assert.strictEqual(inactiveRemoteCleanups, 2, 'inactive legacy and journal runtimes are remotely disabled');
        assert.strictEqual(inactiveRemotePushes, 0, 'access-log reconcile must not restart an inactive Xray node');

        provision.disableInactiveXrayAccessLogs = async () => {
            throw new Error('simulated inactive cleanup failure');
        };
        inactiveXray.xray.accessLogs.appliedSource = 'xray-journal';
        const failedInactiveResult = await provision.reconcileNode(inactiveXray, settings);
        assert.strictEqual(failedInactiveResult.status, 'error');
        const failedState = inactiveStateWrites.at(-1);
        assert.strictEqual(failedState['xray.accessLogs.status'], 'error');
        assert.strictEqual(failedState['xray.accessLogs.cleanupRequired'], true,
            'failed inactive cleanup must retain its durable retry marker');
    } finally {
        HyNode.updateOne = inactiveOriginal.updateOne;
        HyNode.findById = inactiveOriginal.findById;
        credentialService.revokeIngestToken = inactiveOriginal.revokeIngestToken;
        syncService.updateXrayNodeConfig = inactiveOriginal.updateXrayNodeConfig;
        provision.disableInactiveXrayAccessLogs = inactiveOriginal.disableInactiveXrayAccessLogs;
    }

    // Xray can upload/restart successfully and then fail during /sync, health,
    // or source-ready verification. The durable pending marker must make that
    // partial apply rollback-eligible before updateXrayNodeConfig returns.
    const partialOriginal = {
        settingsGet: Settings.get,
        updateOne: HyNode.updateOne,
        findById: HyNode.findById,
        ensureIngestToken: credentialService.ensureIngestToken,
        revokeIngestToken: credentialService.revokeIngestToken,
        agentRequest: syncService._agentRequest,
        updateXrayNodeConfig: syncService.updateXrayNodeConfig,
    };
    try {
        const partialXray = {
            _id: 'partial-xray',
            name: 'Partial Xray apply',
            type: 'xray',
            active: true,
            cascadeRole: 'standalone',
            agentVersion: '1.5.2',
            ip: '203.0.113.77',
            ssh: { username: 'root', password: 'test-only' },
            xray: {
                agentToken: 'agent-token',
                accessLogs: {
                    enabled: false,
                    cleanupRequired: false,
                    appliedFingerprint: '',
                    appliedSource: '',
                    pendingSource: '',
                    status: 'disabled',
                },
            },
        };
        const stateWrites = [];
        Settings.get = async () => settings;
        credentialService.ensureIngestToken = async () => ({ token: 'ingest-token', created: false });
        credentialService.revokeIngestToken = async () => {};
        HyNode.updateOne = async (_filter, update) => {
            stateWrites.push(update?.$set || {});
            return { matchedCount: 1 };
        };
        HyNode.findById = () => ({
            select: async () => ({ xray: { accessLogs: { ingestTokenHash: 'token-hash' } } }),
            then: (resolve, reject) => Promise.resolve(partialXray).then(resolve, reject),
        });
        syncService._agentRequest = async () => ({
            status: 200,
            data: {
                agent_version: '1.5.2',
                access_logs: {
                    enabled: false,
                    source: 'journal',
                    format: 'xray',
                    journal_unit: 'xray',
                    source_ready: false,
                },
            },
        });

        const remoteUpdates = [];
        syncService.updateXrayNodeConfig = async runtime => {
            remoteUpdates.push(runtime);
            return remoteUpdates.length > 1;
        };
        const rolledBack = await provision.reconcileNode(partialXray, settings);
        assert.strictEqual(rolledBack.status, 'error');
        assert.strictEqual(remoteUpdates.length, 2, 'partial Xray apply triggers immediate rollback');
        assert.strictEqual(remoteUpdates[1].xray.accessLogs.enabled, false);
        assert.strictEqual(remoteUpdates[1].xray.accessLogs.deletePending, true,
            'rollback config must override the global desired state');
        assert.strictEqual(stateWrites.at(-1)['xray.accessLogs.cleanupRequired'], false);
        assert.strictEqual(stateWrites.at(-1)['xray.accessLogs.pendingSource'], '');

        remoteUpdates.length = 0;
        stateWrites.length = 0;
        syncService.updateXrayNodeConfig = async runtime => {
            remoteUpdates.push(runtime);
            return false;
        };
        const rollbackFailed = await provision.reconcileNode(partialXray, settings);
        assert.strictEqual(rollbackFailed.status, 'error');
        assert.match(rollbackFailed.error, /remote rollback failed/);
        assert.strictEqual(stateWrites.at(-1)['xray.accessLogs.cleanupRequired'], true,
            'failed rollback retains the durable pending target for retry');
        assert.strictEqual(stateWrites.at(-1)['xray.accessLogs.pendingSource'], undefined,
            'failed rollback must not clear the pending runtime marker');
    } finally {
        Settings.get = partialOriginal.settingsGet;
        HyNode.updateOne = partialOriginal.updateOne;
        HyNode.findById = partialOriginal.findById;
        credentialService.ensureIngestToken = partialOriginal.ensureIngestToken;
        credentialService.revokeIngestToken = partialOriginal.revokeIngestToken;
        syncService._agentRequest = partialOriginal.agentRequest;
        syncService.updateXrayNodeConfig = partialOriginal.updateXrayNodeConfig;
    }

    // An A -> B update may replace both node.ip and node.ssh before a later
    // reconcile runs. The durable runtime marker must still build teardown for
    // A with A's encrypted credentials after a simulated panel restart.
    const movedHy = {
        _id: 'moving-hy',
        name: 'Moving HY2',
        type: 'hysteria',
        active: true,
        ip: '198.51.100.20',
        ssh: { username: 'admin', password: 'new-encrypted-secret' },
        xray: {
            agentToken: 'old-agent-token',
            accessLogs: {
                enabled: true,
                cleanupRequired: true,
                appliedSource: 'hysteria-journal',
                appliedIp: '198.51.100.10',
                appliedSsh: { username: 'root', port: 22, password: 'old-encrypted-secret' },
                journalUnit: 'hysteria-server',
            },
        },
    };
    const movedTeardown = provision.buildHysteriaTeardownNode(
        movedHy,
        movedHy,
        movedHy.xray.accessLogs.appliedIp
    );
    assert.strictEqual(movedTeardown.ip, '198.51.100.10');
assert.strictEqual(movedTeardown.ssh.password, 'old-encrypted-secret');
assert.strictEqual(movedTeardown.ssh.username, 'root');

const rotatedCredentialTeardown = provision.buildHysteriaTeardownNode(
    {
        ...movedHy,
        ip: '198.51.100.10',
        ssh: { username: 'root', password: 'new-working-secret' },
    },
    {
        ...movedHy,
        ip: '198.51.100.10',
        ssh: { username: 'root', password: 'new-working-secret' },
    },
    '198.51.100.10'
);
assert.strictEqual(
    rotatedCredentialTeardown.ssh.password,
    'new-working-secret',
    'same-host cleanup prefers the currently configured SSH credential over a revoked applied snapshot'
);

const fallbackNode = {
    ...movedHy,
    ip: '198.51.100.10',
    ssh: { username: 'root', password: 'new-but-invalid-secret' },
};
const fallbackAttempts = [];
const originalFallbackReconcile = nodeSetup.reconcileHysteriaAccessLogs;
try {
    nodeSetup.reconcileHysteriaAccessLogs = async teardown => {
        fallbackAttempts.push(teardown.ssh.password);
        if (teardown.ssh.password === 'new-but-invalid-secret') {
            throw new Error('authentication failed');
        }
        return { success: true };
    };
    const fallbackTeardown = await provision.disableHysteriaAccessLogRuntime(
        fallbackNode,
        fallbackNode,
        '198.51.100.10',
        'pending'
    );
    assert.strictEqual(fallbackTeardown.ssh.password, 'old-encrypted-secret');
    assert.deepStrictEqual(fallbackAttempts, [
        'new-but-invalid-secret',
        'old-encrypted-secret',
    ]);
} finally {
    nodeSetup.reconcileHysteriaAccessLogs = originalFallbackReconcile;
}

    // Node deletion is serialized behind in-flight config work and its final
    // remote action is always disable before the DB document disappears.
    const deleteOriginal = {
        updateOne: HyNode.updateOne,
        findById: HyNode.findById,
        findByIdAndDelete: HyNode.findByIdAndDelete,
        revokeIngestToken: credentialService.revokeIngestToken,
        reconcileHysteriaAccessLogs: nodeSetup.reconcileHysteriaAccessLogs,
        updateXrayNodeConfig: syncService.updateXrayNodeConfig,
    };
    const deleteActions = [];
    const deletingHy = {
        _id: 'delete-hy',
        name: 'Delete HY2',
        type: 'hysteria',
        ip: '203.0.113.88',
        ssh: { password: 'test-only' },
        xray: {
            agentToken: 'agent-token',
            accessLogs: {
                enabled: true,
                cleanupRequired: true,
                appliedSource: 'hysteria-journal',
                appliedIp: '203.0.113.88',
                journalUnit: 'hysteria-server',
            },
        },
    };
    try {
        HyNode.updateOne = async () => { deleteActions.push('mark-delete'); };
        HyNode.findById = async () => deletingHy;
        HyNode.findByIdAndDelete = async () => {
            deleteActions.push('db-delete');
            return deletingHy;
        };
        credentialService.revokeIngestToken = async () => { deleteActions.push('revoke-token'); };
        nodeSetup.reconcileHysteriaAccessLogs = async (_node, accessLogs) => {
            deleteActions.push(accessLogs.enabled ? 'remote-enable' : 'remote-disable');
            return { success: true };
        };

        let releaseInFlight;
        const inFlightGate = new Promise(resolve => { releaseInFlight = resolve; });
        const inFlight = syncService.enqueueNodeTask(deletingHy._id, async () => {
            deleteActions.push('in-flight-enable');
            await inFlightGate;
        });
        const deleting = provision.deleteNodeWithAccessLogCleanup(deletingHy);
        await new Promise(resolve => setImmediate(resolve));
        assert(!deleteActions.includes('remote-disable'), 'delete waits behind the in-flight node task');
        releaseInFlight();
        await Promise.all([inFlight, deleting]);
        assert(deleteActions.indexOf('remote-disable') > deleteActions.indexOf('in-flight-enable'));
        assert(deleteActions.indexOf('db-delete') > deleteActions.indexOf('remote-disable'));

        const deletingXray = {
            ...deletingHy,
            _id: 'delete-xray',
            name: 'Delete Xray',
            type: 'xray',
            xray: {
                ...deletingHy.xray,
                accessLogs: {
                    ...deletingHy.xray.accessLogs,
                    appliedSource: 'xray-file',
                },
            },
        };
        HyNode.findById = async () => deletingXray;
        HyNode.findByIdAndDelete = async () => deletingXray;
        syncService.updateXrayNodeConfig = async teardown => {
            assert.strictEqual(teardown.xray.accessLogs.enabled, false);
            assert.strictEqual(teardown.xray.accessLogs.deletePending, true);
            return true;
        };
        assert.strictEqual(await provision.deleteNodeWithAccessLogCleanup(deletingXray), deletingXray);
    } finally {
        HyNode.updateOne = deleteOriginal.updateOne;
        HyNode.findById = deleteOriginal.findById;
        HyNode.findByIdAndDelete = deleteOriginal.findByIdAndDelete;
        credentialService.revokeIngestToken = deleteOriginal.revokeIngestToken;
        nodeSetup.reconcileHysteriaAccessLogs = deleteOriginal.reconcileHysteriaAccessLogs;
        syncService.updateXrayNodeConfig = deleteOriginal.updateXrayNodeConfig;
    }

    console.log('test-hysteria-access-logs-provision: OK');
})().catch(error => {
    console.error('test-hysteria-access-logs-provision FAILED:', error);
    process.exit(1);
});
