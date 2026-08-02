#!/usr/bin/env node

const assert = require('assert');
const YAML = require('yaml');

// subscription.js loads the regular application config at module scope.
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'clash-template-subscription-test';

const subscription = require('../src/routes/subscription');
const {
    buildClashServerData,
    generateClashYAML,
    buildClashCacheFormat,
} = subscription._clashTemplateHelpers;

function user(overrides = {}) {
    return {
        userId: 'alice',
        password: 'alice-password',
        xrayUuid: '11111111-1111-4111-8111-111111111111',
        ...overrides,
    };
}

const hysteriaNode = {
    _id: 'hysteria-node',
    type: 'hysteria',
    name: 'Development',
    flag: 'H',
    ip: '203.0.113.10',
    domain: 'hy.test.invalid',
    port: 11443,
    portRange: '',
    portConfigs: [],
    obfs: {},
};

const xrayNode = {
    _id: 'xray-node',
    type: 'xray',
    name: 'Xray',
    flag: 'X',
    ip: '203.0.113.11',
    domain: 'xray.test.invalid',
    port: 443,
    xray: {
        transport: 'tcp',
        security: 'reality',
        flow: 'xtls-rprx-vision',
        fingerprint: 'chrome',
        realityPublicKey: 'public-key',
        realitySni: ['reality.test.invalid'],
        realityShortIds: ['', 'abcd1234'],
        extraInbounds: [{
            port: 8443,
            label: 'WebSocket',
            transport: 'ws',
            security: 'tls',
            fingerprint: 'safari',
            wsPath: '/ws',
        }],
        tlsSource: 'panel',
    },
};

const virtualNode = {
    _id: 'virtual-node',
    type: 'virtual',
    name: 'Automatic',
    flag: 'V',
    virtual: {
        strategy: 'leastPing',
        observatory: { interval: '30s' },
    },
    _resolvedSources: [hysteriaNode, xrayNode],
};

const nodes = [virtualNode, hysteriaNode, xrayNode];
const routing = {
    enabled: true,
    rules: [{ enabled: true, type: 'geoip', value: 'CN', action: 'direct' }],
    dns: { domestic: '223.5.5.5', remote: 'tls://1.1.1.1' },
};

// All protocol-specific values remain structured until final serialization.
const serverData = buildClashServerData(user(), nodes);
assert(serverData.proxies.every(proxy => proxy && typeof proxy === 'object' && !Array.isArray(proxy)));
assert.strictEqual(serverData.proxies[0].type, 'hysteria2');
assert.strictEqual(serverData.proxies[0].password, 'alice:alice-password');
assert.strictEqual(serverData.proxies[1].type, 'vless');
assert.strictEqual(serverData.proxies[1]['reality-opts']['public-key'], 'public-key');
assert.strictEqual(serverData.proxies[2].network, 'ws');
assert.strictEqual(serverData.proxies[2]['ws-opts'].path, '/ws');
assert(serverData.virtualGroups.some(group => group.name === 'V Automatic'));
assert(serverData.proxyNames.includes('V Automatic'));

const legacyYaml = generateClashYAML(user(), nodes, routing);
const legacy = YAML.parse(legacyYaml);
assert.strictEqual(legacy.proxies.length, 3);
assert(legacy['proxy-groups'].some(group => group.name === 'V Automatic'));
assert(legacy.rules.includes('GEOIP,CN,DIRECT,no-resolve'));
assert(legacy.rules.includes('MATCH,Proxy'));

// Node labels are data, even when they contain YAML-looking text.
const hostileNode = {
    ...hysteriaNode,
    _id: 'hostile-node',
    name: 'quoted"\nrules:\n  - MATCH,DIRECT',
};
const hostileYaml = generateClashYAML(user(), [hostileNode], null);
const hostileConfig = YAML.parse(hostileYaml);
assert.strictEqual(hostileConfig.proxies.length, 1);
assert.strictEqual(hostileConfig.rules, undefined);
assert.strictEqual(hostileConfig.proxies[0].name, 'H quoted"\nrules:\n  - MATCH,DIRECT TLS');

const template = {
    _id: '0123456789abcdef01234567',
    active: true,
    revision: 7,
    yaml: [
        'port: 7890',
        'socks-port: 7891',
        'mode: rule',
        'proxy-groups:',
        '  - name: PROXY',
        '    type: select',
        '    proxies:',
        '      - __CELERITY_PROXIES__',
        '      - DIRECT',
        'rules:',
        '  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
        '  - MATCH,PROXY',
    ].join('\n'),
};

const templated = YAML.parse(generateClashYAML(user(), nodes, routing, template));
assert.strictEqual(templated.port, 7890);
assert.strictEqual(templated['socks-port'], 7891);
assert.strictEqual(templated.proxies[0].password, 'alice:alice-password');
assert.deepStrictEqual(templated.rules, [
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'MATCH,PROXY',
]);
const selectGroup = templated['proxy-groups'].find(group => group.name === 'PROXY');
assert(selectGroup.proxies.includes('H Development TLS'));
assert(selectGroup.proxies.includes('V Automatic'));
assert(selectGroup.proxies.includes('DIRECT'));
assert(templated['proxy-groups'].some(group => group.name === 'V Automatic'));

// A template cannot hijack a server-owned virtual-group name.
const collidingTemplate = {
    ...template,
    yaml: [
        'proxy-groups:',
        '  - name: PROXY',
        '    type: select',
        '    proxies:',
        '      - __CELERITY_PROXIES__',
        '  - name: V Automatic',
        '    type: select',
        '    proxies:',
        '      - DIRECT',
    ].join('\n'),
};
const collisionConfig = YAML.parse(generateClashYAML(user(), nodes, null, collidingTemplate));
const virtualGroups = collisionConfig['proxy-groups'].filter(group => group.name === 'V Automatic');
assert.strictEqual(virtualGroups.length, 1);
assert.strictEqual(virtualGroups[0].type, 'url-test');
assert(virtualGroups[0].proxies.includes('H Development TLS'));

// Invalid templates never break subscriptions and never replace credentials.
const badTemplate = { ...template, yaml: 'proxies: []\nrules:\n  - MATCH,DIRECT\n' };
const fallback = YAML.parse(generateClashYAML(user(), nodes, routing, badTemplate));
assert(fallback.rules.includes('MATCH,Proxy'));
assert(!fallback.rules.includes('MATCH,DIRECT'));
assert.strictEqual(fallback.proxies[0].password, 'alice:alice-password');

assert.strictEqual(
    buildClashCacheFormat('clash', template),
    'clash+template:0123456789abcdef01234567:7',
);
assert.strictEqual(
    buildClashCacheFormat('clash', { ...template, revision: 8 }),
    'clash+template:0123456789abcdef01234567:8',
);
assert.strictEqual(buildClashCacheFormat('clash', null), 'clash');

const bob = user({
    userId: 'bob',
    password: 'bob-password',
    xrayUuid: '22222222-2222-4222-8222-222222222222',
});
const aliceConfig = YAML.parse(generateClashYAML(user(), [hysteriaNode], null, template));
const bobConfig = YAML.parse(generateClashYAML(bob, [hysteriaNode], null, template));
assert.strictEqual(aliceConfig.proxies[0].password, 'alice:alice-password');
assert.strictEqual(bobConfig.proxies[0].password, 'bob:bob-password');
assert.notStrictEqual(generateClashYAML(user(), [hysteriaNode], null, template), generateClashYAML(bob, [hysteriaNode], null, template));

console.log('Clash template subscription tests passed');
