'use strict';

const assert = require('assert');
const {
    MAX_TEMPLATE_BYTES,
    PROXIES_PLACEHOLDER,
    ClashTemplateError,
    validateTemplateSource,
    normalizeTemplateInput,
    compileTemplate,
} = require('../src/services/clashTemplateService');
const ClashTemplate = require('../src/models/clashTemplateModel');

function expectError(fn, code) {
    assert.throws(fn, error => {
        assert(error instanceof ClashTemplateError, `expected ClashTemplateError, got ${error?.constructor?.name}`);
        assert.strictEqual(error.code, code);
        return true;
    });
}

const validTemplate = `
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
      - ${PROXIES_PLACEHOLDER}
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`;

// Valid input is parsed to a canonical, comment-free representation.
const validated = validateTemplateSource(validTemplate);
assert.strictEqual(validated.hasProxyGroups, true);
assert.strictEqual(validated.config.port, 7890);
assert.strictEqual(validated.config['proxy-groups'][0].proxies[1], PROXIES_PLACEHOLDER);
assert.deepStrictEqual(validateTemplateSource(validated.yaml).config, validated.config);

// Strict YAML: duplicate keys, extra documents, aliases/anchors, explicit tags,
// non-string map keys and non-finite values must fail closed.
expectError(() => validateTemplateSource('port: 1\nport: 2\n'), 'TEMPLATE_YAML_PARSE');
expectError(() => validateTemplateSource('port: 1\n---\nport: 2\n'), 'TEMPLATE_YAML_DOCUMENTS');
expectError(() => validateTemplateSource('value: &shared test\nother: *shared\n'), 'TEMPLATE_YAML_ALIAS_FORBIDDEN');
expectError(() => validateTemplateSource('value: !!str test\n'), 'TEMPLATE_YAML_TAG_FORBIDDEN');
expectError(() => validateTemplateSource('1: value\n'), 'TEMPLATE_YAML_KEY_TYPE');
expectError(() => validateTemplateSource('value: .inf\n'), 'TEMPLATE_VALUE_INVALID');

// Generated/dynamic and sensitive fields never belong in persisted templates.
expectError(() => validateTemplateSource(`proxies: ${PROXIES_PLACEHOLDER}\n`), 'TEMPLATE_TOP_LEVEL_FIELD_FORBIDDEN');
expectError(() => validateTemplateSource('external-controller: 0.0.0.0:9090\n'), 'TEMPLATE_TOP_LEVEL_FIELD_FORBIDDEN');
expectError(() => validateTemplateSource('proxy-providers:\n  remote:\n    url: https://example.invalid/sub\n'), 'TEMPLATE_TOP_LEVEL_FIELD_FORBIDDEN');
expectError(() => validateTemplateSource('dns:\n  password: hard-coded\n'), 'TEMPLATE_SENSITIVE_FIELD');
expectError(() => validateTemplateSource('"__proto__": polluted\n'), 'TEMPLATE_KEY_FORBIDDEN');

// Placeholder placement and group behavior are deliberately narrow.
expectError(() => validateTemplateSource(`rules:\n  - ${PROXIES_PLACEHOLDER}\n`), 'TEMPLATE_PLACEHOLDER_PATH');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\n`), 'TEMPLATE_PLACEHOLDER_REQUIRED');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: ${PROXIES_PLACEHOLDER}\n`), 'TEMPLATE_PLACEHOLDER_PATH');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: DIRECT\n    type: select\n    proxies: [${PROXIES_PLACEHOLDER}]\n`), 'TEMPLATE_PROXY_GROUP_NAME_RESERVED');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: Proxy\n    type: select\n    proxies: [${PROXIES_PLACEHOLDER}]\n  - name: proxy\n    type: select\n    proxies: [DIRECT]\n`), 'TEMPLATE_PROXY_GROUP_NAME_DUPLICATE');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [${PROXIES_PLACEHOLDER}, Hard-coded node]\n`), 'TEMPLATE_PROXY_GROUP_REFERENCE_UNKNOWN');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: A\n    type: select\n    proxies: [${PROXIES_PLACEHOLDER}, B]\n  - name: B\n    type: select\n    proxies: [A]\n`), 'TEMPLATE_PROXY_GROUP_CYCLE');

// Rules are validated while saving, including the implicit default group.
assert.strictEqual(validateTemplateSource('mode: rule\nrules:\n  - MATCH,PROXY\n').hasProxyGroups, false);
expectError(() => validateTemplateSource('mode: rule\nrules: not-an-array\n'), 'TEMPLATE_RULES_TYPE');
expectError(() => validateTemplateSource('mode: rule\nrules:\n  - MATCH,Hard-coded node\n'), 'TEMPLATE_RULE_TARGET_UNKNOWN');
expectError(() => validateTemplateSource(`proxy-groups:\n  - name: Custom\n    type: select\n    proxies: [${PROXIES_PLACEHOLDER}]\nrules:\n  - GEOIP,CN,PROXY\n`), 'TEMPLATE_RULE_TARGET_UNKNOWN');
assert.strictEqual(validateTemplateSource(`proxy-groups:\n  - name: Custom\n    type: select\n    proxies: [${PROXIES_PLACEHOLDER}]\nrules:\n  - AND,((NETWORK,TCP),(DST-PORT,443)),Custom\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,Custom\n`).config.rules.length, 3);

const generatedProxies = [
    { name: 'Node A', type: 'hysteria2', server: 'a.example', port: 443, password: 'generated-a' },
    { name: 'Node B', type: 'vless', server: 'b.example', port: 443, uuid: 'generated-b' },
];
const originalProxies = structuredClone(generatedProxies);
const compiled = compileTemplate(validTemplate, {
    proxies: generatedProxies,
    proxyNames: ['Node A', 'Node B'],
});
assert.deepStrictEqual(compiled.proxies, generatedProxies);
assert.notStrictEqual(compiled.proxies, generatedProxies, 'compiler must not retain caller-owned arrays');
assert.deepStrictEqual(compiled['proxy-groups'][0].proxies, ['DIRECT', 'Node A', 'Node B']);
assert.strictEqual(JSON.stringify(compiled).includes(PROXIES_PLACEHOLDER), false);
assert.deepStrictEqual(generatedProxies, originalProxies, 'compiler must not mutate generated proxies');

// A template without proxy-groups receives a safe default group.
const defaultGroupConfig = compileTemplate('mode: rule\nrules:\n  - MATCH,PROXY\n', {
    proxies: generatedProxies,
});
assert.deepStrictEqual(defaultGroupConfig['proxy-groups'], [{
    name: 'PROXY',
    type: 'select',
    proxies: ['Node A', 'Node B'],
}]);
assert.deepStrictEqual(defaultGroupConfig.proxies, generatedProxies);

expectError(() => compileTemplate('mode: rule\n', { proxies: [{}] }), 'GENERATED_PROXY_NAME');
expectError(() => compileTemplate('mode: rule\n', { proxies: generatedProxies, proxyNames: 'Node A' }), 'GENERATED_PROXY_NAMES_TYPE');

// 64 KiB is a UTF-8 byte boundary, not a JavaScript character boundary.
const sizeBase = 'mode: rule\n';
const exactLimit = `${sizeBase}#${'x'.repeat(MAX_TEMPLATE_BYTES - Buffer.byteLength(sizeBase) - 1)}`;
assert.strictEqual(Buffer.byteLength(exactLimit), MAX_TEMPLATE_BYTES);
assert.strictEqual(validateTemplateSource(exactLimit).config.mode, 'rule');
expectError(() => validateTemplateSource(`${exactLimit}x`), 'TEMPLATE_YAML_TOO_LARGE');

const normalizedInput = normalizeTemplateInput({
    name: '  中国直连  ',
    description: '  国内直连，国外代理  ',
    yaml: validTemplate,
    active: 'on',
});
assert.deepStrictEqual(Object.keys(normalizedInput).sort(), ['active', 'description', 'name', 'yaml']);
assert.strictEqual(normalizedInput.name, '中国直连');
assert.strictEqual(normalizedInput.active, true);
assert.strictEqual(normalizedInput.yaml, validated.yaml);
expectError(() => normalizeTemplateInput({ name: 'x', yaml: validTemplate, revision: 99 }), 'TEMPLATE_INPUT_FIELD');
expectError(() => normalizeTemplateInput({}, { partial: true }), 'TEMPLATE_UPDATE_EMPTY');

// Model contract: route-level code can rely on these fields and defaults.
const doc = new ClashTemplate({ name: 'Template', yaml: validTemplate });
const validationError = doc.validateSync();
assert.strictEqual(validationError, undefined);
assert.strictEqual(doc.active, true);
assert.strictEqual(doc.revision, 1);
assert.strictEqual(doc.description, '');
assert.strictEqual(ClashTemplate.schema.path('revision').options.min, 1);
const invalidDoc = new ClashTemplate({ name: 'Unsafe', yaml: 'proxies: []\n' });
assert(invalidDoc.validateSync()?.errors?.yaml, 'model writes must reject an unsafe template');

console.log('Clash template service tests passed');
