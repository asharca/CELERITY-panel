const assert = require('assert');
const fs = require('fs');
const path = require('path');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';

const HyNode = require('../src/models/hyNodeModel');

const fallbackNode = new HyNode({
    name: 'Fallback stats host',
    ip: '203.0.113.10',
});
assert.strictEqual(fallbackNode.statsHost, '', 'statsHost defaults to empty so callers fall back to ip');

const routedNode = new HyNode({
    name: 'Routed stats host',
    ip: '198.51.100.20',
    statsHost: '  10.20.30.40  ',
});
assert.strictEqual(routedNode.statsHost, '10.20.30.40', 'statsHost is trimmed at the model boundary');

const persistedNode = HyNode.hydrate({
    _id: '64f000000000000000000001',
    name: 'Persisted stats host',
    type: 'hysteria',
    ip: '198.51.100.30',
    port: 443,
    portRange: '',
    statsHost: '',
    statsPort: 9999,
});
persistedNode.set({
    name: 'Persisted stats host',
    type: 'hysteria',
    ip: '198.51.100.30',
    port: 443,
    portRange: '',
    statsHost: ' 10.20.30.42 ',
    statsPort: 9999,
});
assert.deepStrictEqual(
    persistedNode.modifiedPaths(),
    ['statsHost'],
    'panel change tracking can distinguish a statsHost-only edit from runtime config changes'
);

(async () => {
    const axios = require('axios');
    const HyUser = require('../src/models/hyUserModel');
    const syncService = require('../src/services/syncService');

    const originalAxiosGet = axios.get;
    const originalAxiosPost = axios.post;
    const originalNodeFindById = HyNode.findById;
    const originalNodeUpdateOne = HyNode.updateOne;
    const originalNodeFindOneAndUpdate = HyNode.findOneAndUpdate;
    const originalUserFindOne = HyUser.findOne;

    const getUrls = [];
    const postUrls = [];
    let kickPopulateFields = '';

    try {
        axios.get = async url => {
            getUrls.push(url);
            return { data: url.includes('/online') ? { alice: 1 } : {} };
        };
        axios.post = async url => {
            postUrls.push(url);
            return { data: {} };
        };
        HyNode.updateOne = async () => ({ matchedCount: 1, modifiedCount: 1 });
        HyNode.findOneAndUpdate = async () => ({ status: 'online', healthFailures: 0 });

        const managedNode = {
            _id: 'managed-node',
            name: 'Managed stats route',
            type: 'hysteria',
            ip: '198.51.100.20',
            statsHost: '  10.20.30.40  ',
            statsPort: 10001,
            statsSecret: 'secret',
            traffic: {},
        };
        await syncService.collectTrafficStats(managedNode);
        await syncService.getOnlineUsers(managedNode);

        const fallbackAddressNode = {
            ...managedNode,
            _id: 'fallback-node',
            name: 'Fallback stats route',
            ip: '203.0.113.77',
            statsHost: '   ',
            statsPort: 10002,
        };
        await syncService.getOnlineUsers(fallbackAddressNode);

        HyUser.findOne = () => ({
            populate: async (_path, fields) => {
                kickPopulateFields = fields;
                return {
                    nodes: [{
                        name: 'Kick route',
                        type: 'hysteria',
                        ip: '198.51.100.21',
                        statsHost: '  10.20.30.41 ',
                        statsPort: 10003,
                        statsSecret: 'secret',
                    }],
                };
            },
        });
        await syncService.kickUser('alice');

        assert.deepStrictEqual(getUrls, [
            'http://10.20.30.40:10001/traffic?clear=true',
            'http://10.20.30.40:10001/online',
            'http://203.0.113.77:10002/online',
        ]);
        assert.deepStrictEqual(postUrls, ['http://10.20.30.41:10003/kick']);
        assert.match(kickPopulateFields, /\bstatsHost\b/, 'kick user lookup must load statsHost');

        let configLookupCount = 0;
        HyNode.findById = async () => {
            configLookupCount += 1;
            return null;
        };
        syncService.schedulePush('managed-node', { statsHost: '10.20.30.50' });
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(configLookupCount, 0, 'statsHost-only updates must not schedule a remote config push');

        const { schemas } = require('../src/mcp/tools/nodes');
        const parsedMcp = schemas.manageNode.parse({
            action: 'update',
            id: 'managed-node',
            data: { statsHost: '10.20.30.40' },
        });
        assert.strictEqual(parsedMcp.data.statsHost, '10.20.30.40', 'MCP schema exposes statsHost');

        const { buildSpec } = require('../src/docs/openapi');
        const englishStatsHost = buildSpec('en').components.schemas.NodeCreate.properties.statsHost;
        assert(englishStatsHost, 'OpenAPI NodeCreate documents statsHost');
        assert.match(englishStatsHost.description, /management|panel/i);
        assert(buildSpec('en').components.schemas.NodeUpdate.properties.statsHost, 'OpenAPI NodeUpdate documents statsHost');
        assert(buildSpec('en').components.schemas.Node.properties.statsHost, 'OpenAPI Node response documents statsHost');
        assert.notStrictEqual(
            buildSpec('ru').components.schemas.NodeCreate.properties.statsHost.description,
            englishStatsHost.description,
            'Russian OpenAPI translates the statsHost description'
        );

        for (const locale of ['en', 'zh-CN', 'ru']) {
            const messages = require(`../src/locales/${locale}.json`);
            assert(messages.nodes.statsHost, `${locale} locale has nodes.statsHost`);
            assert(messages.nodes.statsHostHint, `${locale} locale has nodes.statsHostHint`);
        }

        const root = path.join(__dirname, '..');
        const formSource = fs.readFileSync(path.join(root, 'views/partials/node-form/hysteria.ejs'), 'utf8');
        const restSource = fs.readFileSync(path.join(root, 'src/routes/nodes.js'), 'utf8');
        const panelSource = fs.readFileSync(path.join(root, 'src/routes/panel/nodes.js'), 'utf8');
        const mcpSource = fs.readFileSync(path.join(root, 'src/mcp/tools/nodes.js'), 'utf8');
        const subscriptionSource = fs.readFileSync(path.join(root, 'src/routes/subscription.js'), 'utf8');
        const configGeneratorSource = fs.readFileSync(path.join(root, 'src/services/configGenerator.js'), 'utf8');

        assert.match(formSource, /name="statsHost"/, 'panel add/edit form exposes statsHost');
        assert.match(restSource, /['"]statsHost['"]/, 'REST create/update accepts statsHost');
        assert.match(panelSource, /statsHost:\s*[^,]+trim\(\)/, 'panel create/update trims statsHost');
        assert.match(mcpSource, /statsHost:\s*z\.string\(\)/, 'MCP accepts statsHost');
        assert(!subscriptionSource.includes('statsHost'), 'statsHost must not leak into subscriptions');
        assert(!configGeneratorSource.includes('statsHost'), 'statsHost must not leak into remote Hysteria config');
    } finally {
        axios.get = originalAxiosGet;
        axios.post = originalAxiosPost;
        HyNode.findById = originalNodeFindById;
        HyNode.updateOne = originalNodeUpdateOne;
        HyNode.findOneAndUpdate = originalNodeFindOneAndUpdate;
        HyUser.findOne = originalUserFindOne;
        require('../src/services/sshPoolService').closeAll();
    }

    console.log('stats host tests passed');
})().catch(error => {
    console.error(error);
    process.exit(1);
});
