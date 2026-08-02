const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
    normalizePortRange,
    parsePortRange,
    canonicalizePortRange,
    buildPortHoppingReconcileScript,
} = require('../src/utils/portRange');
const { getNodeConfigs } = require('../src/utils/hysteriaNodeConfigs');
const HyNode = require('../src/models/hyNodeModel');

assert.strictEqual(normalizePortRange(undefined), '');
assert.strictEqual(normalizePortRange(null), '');
assert.strictEqual(normalizePortRange(''), '');
assert.strictEqual(normalizePortRange('   '), '');
assert.strictEqual(normalizePortRange(' 20000-50000 '), '20000-50000');
assert.deepStrictEqual(parsePortRange('20000 - 50000'), {
    start: 20000,
    end: 50000,
    normalized: '20000-50000',
});
assert.strictEqual(parsePortRange('0-50000'), null);
assert.strictEqual(parsePortRange('50000-20000'), null);
assert.strictEqual(parsePortRange('20000; touch /tmp/x'), null);
assert.strictEqual(canonicalizePortRange(' 20000 - 50000 '), '20000-50000');
assert.throws(() => canonicalizePortRange('not-a-range'), /portRange must use start-end/);
assert.throws(() => canonicalizePortRange(20000), /portRange must be a string/);

const defaultNode = new HyNode({ name: 'No hopping by default', ip: '203.0.113.10' });
assert.strictEqual(defaultNode.portRange, '', 'new nodes must not enable port hopping implicitly');

const explicitNode = new HyNode({
    name: 'Explicit hopping',
    ip: '203.0.113.11',
    portRange: ' 20000-50000 ',
});
assert.strictEqual(explicitNode.portRange, '20000-50000', 'explicit ranges remain supported');
const invalidNode = new HyNode({ name: 'Invalid hopping', ip: '203.0.113.12', portRange: 'invalid' });
assert(invalidNode.validateSync()?.errors?.portRange, 'invalid ranges must fail model validation');
assert.strictEqual(defaultNode.serverAddress, '203.0.113.10:443');
assert.strictEqual(explicitNode.serverAddress, '203.0.113.11:20000-50000');

const fixedConfigs = getNodeConfigs({
    type: 'hysteria',
    ip: '203.0.113.10',
    port: 443,
    portRange: '',
    hopInterval: '30s',
});
assert.strictEqual(fixedConfigs.length, 1);
assert.strictEqual(fixedConfigs[0].name, 'TLS');
assert.strictEqual(fixedConfigs[0].portRange, '');

const hoppingConfigs = getNodeConfigs({
    type: 'hysteria',
    ip: '203.0.113.11',
    port: 443,
    portRange: '20000-50000',
});
assert.deepStrictEqual(hoppingConfigs.map(config => config.name), ['TLS', 'Hopping']);
assert.strictEqual(hoppingConfigs[1].portRange, '20000-50000');
assert.deepStrictEqual(
    getNodeConfigs({
        type: 'hysteria',
        ip: '127.0.0.1',
        port: 443,
        portRange: '20000-50000',
    }, { allowPortHopping: false }).map(config => config.name),
    ['TLS']
);
assert.deepStrictEqual(
    getNodeConfigs({
        type: 'hysteria',
        ip: '203.0.113.13',
        port: 443,
        portRange: 'invalid',
    }).map(config => config.name),
    ['TLS'],
    'legacy invalid ranges must not be published'
);
assert.strictEqual(
    getNodeConfigs({
        type: 'hysteria',
        ip: '127.0.0.1',
        portConfigs: [{ name: 'Custom', port: 443, portRange: '20000-50000', enabled: true }],
    }, { allowPortHopping: false })[0].portRange,
    '',
    'same-VPS protection must also cover legacy portConfigs'
);

const cleanupScript = buildPortHoppingReconcileScript({
    desiredRange: '',
    previousRange: '20000-50000',
    mainPort: 443,
});
assert(cleanupScript.includes('-D PREROUTING'));
assert(cleanupScript.includes('ufw --force delete allow 20000:50000/udp'));
assert(!cleanupScript.includes('-A PREROUTING'), 'cleanup-only transitions must not add hopping rules');
assert(!cleanupScript.includes('ufw allow 20000:50000/udp'));

const changedRangeScript = buildPortHoppingReconcileScript({
    desiredRange: '30000-40000',
    previousRange: '20000-50000',
    mainPort: 443,
});
assert(changedRangeScript.includes('--dport 20000:50000'));
assert(changedRangeScript.includes('--dport 30000:40000'));
assert(changedRangeScript.includes('-A PREROUTING'));

const changedMainPortScript = buildPortHoppingReconcileScript({
    desiredRange: '20000-50000',
    previousRange: '20000-50000',
    mainPort: 8443,
    previousMainPort: 443,
});
assert(changedMainPortScript.includes('--to-port 443'), 'old main-port rule must be removed');
assert(changedMainPortScript.includes('--to-port 8443'), 'range must be redirected to the new main port');
assert(changedMainPortScript.includes('--dport 8443 -j ACCEPT'), 'new service port must be opened');
assert(changedMainPortScript.includes('allow 8443/udp'));
assert(!changedMainPortScript.includes('delete allow 443/udp'), 'unowned shared-port rules must be preserved');

const fixedPortMigrationScript = buildPortHoppingReconcileScript({
    desiredRange: '',
    previousRange: '',
    mainPort: 8443,
    previousMainPort: 443,
});
assert(fixedPortMigrationScript.includes('--dport 8443 -j ACCEPT'));
assert(!fixedPortMigrationScript.includes('delete allow 443/udp'));
assert.throws(
    () => buildPortHoppingReconcileScript({ desiredRange: 'invalid', previousRange: '', mainPort: 443 }),
    /Invalid port hopping range/
);

const root = path.join(__dirname, '..');
const entryPoints = [
    'src/routes/panel/nodes.js',
    'src/routes/nodes.js',
    'src/mcp/tools/nodes.js',
];

for (const relativePath of entryPoints) {
    const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
    assert(
        source.includes('normalizePortRange'),
        `${relativePath} must normalize optional port ranges`
    );
    assert(
        !/portRange\s*:\s*[^\n]*\|\|\s*['"]20000-50000['"]/.test(source),
        `${relativePath} must not restore an implicit hopping range`
    );
}

const form = fs.readFileSync(path.join(root, 'views/partials/node-form/network.ejs'), 'utf8');
assert(
    form.includes("node?.portRange ?? ''"),
    'the node form must preserve an explicitly empty port range'
);

const configSource = fs.readFileSync(path.join(root, 'config.js'), 'utf8');
assert(
    /DEFAULT_NODE_CONFIG:\s*{[^}]*portRange:\s*''/s.test(configSource),
    'the global node defaults must keep port hopping opt-in'
);

const wizardSource = fs.readFileSync(path.join(root, 'src/routes/panel/wizard.js'), 'utf8');
assert(
    wizardSource.includes("hyPortRange: ''"),
    'the setup wizard must not suggest an implicit hopping range'
);

const subscriptionSource = fs.readFileSync(path.join(root, 'src/routes/subscription.js'), 'utf8');
assert(
    /if \(cfg\.portRange\) \{[\s\S]*hop-interval/.test(subscriptionSource),
    'Clash hop interval must be guarded by a configured hopping range'
);
assert(
    /if \(cfg\.portRange\) \{[\s\S]*outbound\.hop_interval/.test(subscriptionSource),
    'sing-box hop interval must be guarded by a configured hopping range'
);

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';

(async () => {
    const NodeSSH = require('../src/services/nodeSSH');
    const syncService = require('../src/services/syncService');
    const ssh = new NodeSSH({ name: 'Test node', port: 443 });
    let executedScript = '';
    ssh.exec = async script => {
        executedScript = script;
        return { code: 0, stdout: '', stderr: '' };
    };

    assert.strictEqual(await ssh.setupPortHopping(''), false);
    assert.strictEqual(executedScript, '', 'empty ranges must be rejected before command execution');
    assert.strictEqual(await ssh.reconcilePortHopping('', '20000-50000'), true);
    assert(executedScript.includes('-D PREROUTING'));
    assert(!executedScript.includes('-A PREROUTING'));

    ssh.exec = async () => ({ code: 1, stdout: '', stderr: 'permission denied' });
    assert.strictEqual(
        await ssh.reconcilePortHopping('', '20000-50000'),
        false,
        'non-zero firewall command exits must not report success'
    );
    ssh.exec = async () => ({ code: null, stdout: '', stderr: '' });
    assert.strictEqual(await ssh.reconcilePortHopping('', '20000-50000'), false);

    const originalFindById = HyNode.findById;
    const originalUpdateNodeConfig = syncService.updateNodeConfig;
    const originalReconcile = syncService.reconcilePortHopping;
    let scheduledTransition = null;
    try {
        HyNode.findById = async () => ({
            _id: 'test-node',
            name: 'Changed type',
            type: 'xray',
            active: true,
            cascadeRole: 'standalone',
            port: 443,
            portRange: '20000-50000',
            ssh: { password: 'encrypted' },
            xray: {},
        });
        syncService.updateNodeConfig = async () => true;
        syncService.reconcilePortHopping = async (...args) => {
            scheduledTransition = args;
            return true;
        };

        syncService.schedulePush('test-node', { type: 'xray' }, {
            previousType: 'hysteria',
            previousPortRange: '20000-50000',
            previousPort: 443,
        });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));

        assert(scheduledTransition, 'changing away from Hysteria must schedule firewall cleanup');
        assert.strictEqual(scheduledTransition[1], '20000-50000');

        scheduledTransition = null;
        HyNode.findById = async () => ({
            _id: 'moved-off-panel',
            name: 'Moved off panel',
            type: 'hysteria',
            active: true,
            cascadeRole: 'standalone',
            ip: '203.0.113.22',
            domain: 'remote.invalid',
            port: 443,
            portRange: '20000-50000',
            ssh: { password: 'encrypted' },
            xray: {},
        });
        syncService.schedulePush('moved-off-panel', { domain: 'remote.invalid' }, {
            previousType: 'hysteria',
            previousPortRange: '20000-50000',
            previousPort: 443,
            previousIp: '203.0.113.22',
            previousDomain: 'TEST.INVALID.',
            previousSsh: { password: 'encrypted' },
        });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));
        assert(scheduledTransition, 'moving off the panel VPS must install the explicit range');
        assert.strictEqual(scheduledTransition[1], '');
        assert.strictEqual(scheduledTransition[3], '20000-50000');

        scheduledTransition = null;
        HyNode.findById = async () => ({
            _id: 'reactivated-node',
            name: 'Reactivated node',
            type: 'hysteria',
            active: true,
            cascadeRole: 'standalone',
            ip: '203.0.113.23',
            domain: 'remote.invalid',
            port: 11443,
            portRange: '30000-40000',
            ssh: { password: 'encrypted' },
            xray: {},
        });
        syncService.schedulePush('reactivated-node', { active: true }, {
            previousType: 'hysteria',
            previousPortRange: '30000-40000',
            previousPort: 11443,
            previousIp: '203.0.113.23',
            previousDomain: 'remote.invalid',
            previousActive: false,
            previousSsh: { password: 'encrypted' },
        });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));
        assert(scheduledTransition, 'reactivation must reapply the current firewall state');
        assert.strictEqual(scheduledTransition[1], '30000-40000');
        assert.strictEqual(scheduledTransition[3], '30000-40000');
        assert.strictEqual(scheduledTransition[4].previousMainPortEnabled, false);

        scheduledTransition = null;
        syncService.updateNodeConfig = async () => false;
        HyNode.findById = async () => ({
            _id: 'failed-push',
            name: 'Failed config push',
            type: 'hysteria',
            active: true,
            cascadeRole: 'standalone',
            ip: '203.0.113.30',
            port: 8443,
            portRange: '30000-40000',
            ssh: { password: 'encrypted' },
            xray: {},
        });
        syncService.schedulePush('failed-push', { portRange: '30000-40000' }, {
            previousType: 'hysteria',
            previousPortRange: '20000-50000',
            previousPort: 443,
            previousIp: '203.0.113.30',
            previousSsh: { password: 'encrypted' },
        });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(scheduledTransition, null, 'failed config pushes must leave firewall state unchanged');

        scheduledTransition = null;
        syncService.updateNodeConfig = async () => true;
        HyNode.findById = async () => ({
            _id: 'test-node',
            name: 'Changed target',
            type: 'virtual',
            active: true,
            cascadeRole: 'standalone',
            ip: null,
            port: 443,
            portRange: '20000-50000',
            ssh: { password: 'new-encrypted' },
            xray: {},
        });
        syncService.schedulePush('test-node', { type: 'virtual' }, {
            previousType: 'hysteria',
            previousPortRange: '20000-50000',
            previousPort: 443,
            previousIp: '203.0.113.20',
            previousSsh: { password: 'old-encrypted' },
        });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));

        assert(scheduledTransition, 'changing the SSH target must still clean the old host');
        assert.strictEqual(scheduledTransition[0].ip, '203.0.113.20');
        assert.strictEqual(scheduledTransition[3], '', 'the old host transition must be cleanup-only');

        scheduledTransition = null;
        HyNode.findById = async () => null;
        syncService.schedulePush('deleted-during-update', { portRange: '30000-40000' }, {
            previousType: 'hysteria',
            previousPortRange: '20000-50000',
            previousPort: 443,
            previousIp: '203.0.113.21',
            previousDomain: '',
            previousSsh: { password: 'old-encrypted' },
        });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));
        assert(scheduledTransition, 'deletion during an update must clean the pre-update range');
        assert.strictEqual(scheduledTransition[0].ip, '203.0.113.21');
        assert.strictEqual(scheduledTransition[1], '20000-50000');

        let updateCalls = 0;
        let releaseFirstPush;
        const firstPushGate = new Promise(resolve => { releaseFirstPush = resolve; });
        HyNode.findById = async () => ({
            _id: 'queued-node',
            name: 'Queued updates',
            type: 'hysteria',
            active: true,
            cascadeRole: 'standalone',
            ip: '203.0.113.40',
            port: 443,
            portRange: '',
            ssh: { password: 'encrypted' },
            xray: {},
        });
        syncService.updateNodeConfig = async () => {
            updateCalls++;
            if (updateCalls === 1) await firstPushGate;
            return true;
        };
        syncService.schedulePush('queued-node', { domain: 'first.invalid' });
        syncService.schedulePush('queued-node', { domain: 'second.invalid' });
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(updateCalls, 1, 'same-node config pushes must run serially');
        releaseFirstPush();
        await new Promise(resolve => setImmediate(resolve));
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(updateCalls, 2);
    } finally {
        HyNode.findById = originalFindById;
        syncService.updateNodeConfig = originalUpdateNodeConfig;
        syncService.reconcilePortHopping = originalReconcile;
    }

    require('../src/services/sshPoolService').closeAll();
    console.log('optional port hopping tests passed');
})().catch(error => {
    console.error(error);
    process.exit(1);
});
