/**
 * Safe Clash template parsing and compilation.
 *
 * Templates deliberately never contain generated proxy records. The only
 * supported placeholder is a sequence item inside a proxy group's `proxies`
 * list:
 *
 *   proxy-groups:
 *     - name: PROXY
 *       type: select
 *       proxies:
 *         - __CELERITY_PROXIES__
 *
 * At subscription time the placeholder expands to the generated proxy names,
 * while the generated proxy objects are force-written to the top-level
 * `proxies` key. This keeps credentials out of reusable templates.
 */

const YAML = require('yaml');

const MAX_TEMPLATE_BYTES = 64 * 1024;
const MAX_TEMPLATE_DEPTH = 40;
const MAX_TEMPLATE_NODES = 10_000;
const MAX_GENERATED_PROXIES = 2_048;
const MAX_PROXY_GROUPS = 128;
const MAX_GROUP_PROXIES = 512;
const MAX_RULES = 4_096;
const MAX_RULE_BYTES = 1_024;
const MAX_REFERENCE_BYTES = 256;
const PROXIES_PLACEHOLDER = '__CELERITY_PROXIES__';

// Mihomo/Clash built-in policies may be referenced by rules and groups, but
// cannot be shadowed by a template-defined group.
const BUILTIN_POLICIES = new Set([
    'DIRECT',
    'REJECT',
    'REJECT-DROP',
    'PASS',
    'COMPATIBLE',
    'GLOBAL',
]);

const FORBIDDEN_TOP_LEVEL_FIELDS = new Set([
    // Generated or remotely-loaded proxy/rule material.
    'proxies',
    'proxy-providers',
    'rule-providers',
    'providers',

    // Local controller/API and UI exposure must remain a client-side choice,
    // not something an administrator can silently ship in a subscription.
    'external-controller',
    'external-controller-tls',
    'external-controller-unix',
    'external-controller-pipe',
    'external-ui',
    'external-ui-name',
    'external-ui-url',
    'external-doh-server',
    'secret',
    'authentication',

    // Executable/dynamic configuration surfaces.
    'script',
    'listeners',
]);

const SENSITIVE_FIELD_NAMES = new Set([
    'password',
    'passwd',
    'secret',
    'token',
    'uuid',
    'private-key',
    'private_key',
    'api-key',
    'api_key',
    'client-secret',
    'client_secret',
    'authorization',
]);

const UNSAFE_OBJECT_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

class ClashTemplateError extends Error {
    constructor(code, message, details) {
        super(message);
        this.name = 'ClashTemplateError';
        this.code = code;
        this.status = 400;
        if (details !== undefined) this.details = details;
    }
}

function fail(code, message, details) {
    throw new ClashTemplateError(code, message, details);
}

function byteLength(value) {
    return Buffer.byteLength(value, 'utf8');
}

function canonicalFieldName(value) {
    return String(value).trim().toLowerCase().replace(/_/g, '-');
}

function pathLabel(path) {
    if (!path.length) return '<root>';
    return path.map((part, index) => (
        typeof part === 'number'
            ? `[${part}]`
            : `${index === 0 ? '' : '.'}${part}`
    )).join('');
}

function assertSource(source) {
    if (typeof source !== 'string') {
        fail('TEMPLATE_YAML_TYPE', 'Template YAML must be a string');
    }
    if (source.trim().length === 0) {
        fail('TEMPLATE_YAML_EMPTY', 'Template YAML cannot be empty');
    }
    const bytes = byteLength(source);
    if (bytes > MAX_TEMPLATE_BYTES) {
        fail(
            'TEMPLATE_YAML_TOO_LARGE',
            `Template YAML exceeds the ${MAX_TEMPLATE_BYTES}-byte limit`,
            { bytes, maxBytes: MAX_TEMPLATE_BYTES },
        );
    }
    if (/\u0000|[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(source)) {
        fail('TEMPLATE_YAML_CONTROL_CHAR', 'Template YAML contains a disallowed control character');
    }
}

function inspectYamlAst(doc) {
    let nodeCount = 0;
    let astError = null;

    YAML.visit(doc, (key, node, path) => {
        nodeCount += 1;
        if (nodeCount > MAX_TEMPLATE_NODES) {
            astError = new ClashTemplateError(
                'TEMPLATE_YAML_TOO_COMPLEX',
                `Template YAML exceeds the ${MAX_TEMPLATE_NODES}-node limit`,
            );
            return YAML.visit.BREAK;
        }

        if (path.length > MAX_TEMPLATE_DEPTH) {
            astError = new ClashTemplateError(
                'TEMPLATE_YAML_TOO_DEEP',
                `Template YAML exceeds the maximum nesting depth of ${MAX_TEMPLATE_DEPTH}`,
            );
            return YAML.visit.BREAK;
        }

        if (YAML.isAlias(node) || node.anchor) {
            astError = new ClashTemplateError(
                'TEMPLATE_YAML_ALIAS_FORBIDDEN',
                'YAML anchors and aliases are not allowed in Clash templates',
            );
            return YAML.visit.BREAK;
        }

        // An explicit YAML tag is unnecessary for Clash configuration and can
        // change the resulting JavaScript type in surprising ways.
        if (node.tag) {
            astError = new ClashTemplateError(
                'TEMPLATE_YAML_TAG_FORBIDDEN',
                'Explicit YAML tags are not allowed in Clash templates',
            );
            return YAML.visit.BREAK;
        }

        if (YAML.isMap(node)) {
            for (const pair of node.items) {
                if (!YAML.isScalar(pair.key) || typeof pair.key.value !== 'string') {
                    astError = new ClashTemplateError(
                        'TEMPLATE_YAML_KEY_TYPE',
                        'Every YAML mapping key must be a string',
                    );
                    return YAML.visit.BREAK;
                }
            }
        }

        return undefined;
    });

    if (astError) throw astError;
}

function cloneSafe(value, path = [], state = { nodes: 0 }, depth = 0) {
    state.nodes += 1;
    if (state.nodes > MAX_TEMPLATE_NODES) {
        fail('TEMPLATE_YAML_TOO_COMPLEX', `Configuration exceeds the ${MAX_TEMPLATE_NODES}-node limit`);
    }
    if (depth > MAX_TEMPLATE_DEPTH) {
        fail('TEMPLATE_YAML_TOO_DEEP', `Configuration exceeds the maximum nesting depth of ${MAX_TEMPLATE_DEPTH}`);
    }

    if (value === null || typeof value === 'boolean' || typeof value === 'string') {
        return value;
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            fail('TEMPLATE_VALUE_INVALID', `Non-finite number at ${pathLabel(path)} is not allowed`);
        }
        return value;
    }
    if (Array.isArray(value)) {
        return value.map((item, index) => cloneSafe(item, [...path, index], state, depth + 1));
    }
    if (!value || typeof value !== 'object') {
        fail('TEMPLATE_VALUE_INVALID', `Unsupported value at ${pathLabel(path)}`);
    }

    const output = {};
    for (const [rawKey, rawValue] of Object.entries(value)) {
        if (UNSAFE_OBJECT_KEYS.has(rawKey)) {
            fail('TEMPLATE_KEY_FORBIDDEN', `Unsafe key "${rawKey}" at ${pathLabel(path)} is not allowed`);
        }
        output[rawKey] = cloneSafe(rawValue, [...path, rawKey], state, depth + 1);
    }
    return output;
}

function parseStrictYaml(source) {
    assertSource(source);

    let documents;
    try {
        documents = YAML.parseAllDocuments(source, {
            schema: 'core',
            strict: true,
            uniqueKeys: true,
            prettyErrors: true,
            merge: false,
        });
    } catch (error) {
        fail('TEMPLATE_YAML_PARSE', `Invalid YAML: ${error.message}`);
    }

    if (documents.length !== 1) {
        fail('TEMPLATE_YAML_DOCUMENTS', 'A Clash template must contain exactly one YAML document');
    }

    const [doc] = documents;
    if (doc.errors.length > 0) {
        fail('TEMPLATE_YAML_PARSE', `Invalid YAML: ${doc.errors[0].message}`);
    }
    if (doc.warnings.length > 0) {
        fail('TEMPLATE_YAML_WARNING', `Unsupported YAML: ${doc.warnings[0].message}`);
    }

    inspectYamlAst(doc);

    let parsed;
    try {
        parsed = doc.toJS({ mapAsMap: false, maxAliasCount: 0 });
    } catch (error) {
        fail('TEMPLATE_YAML_PARSE', `Invalid YAML: ${error.message}`);
    }

    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
        fail('TEMPLATE_ROOT_TYPE', 'The Clash template root must be a YAML mapping');
    }
    return cloneSafe(parsed);
}

function isPlaceholderPath(path) {
    return path.length === 4
        && path[0] === 'proxy-groups'
        && Number.isInteger(path[1])
        && path[2] === 'proxies'
        && Number.isInteger(path[3]);
}

function inspectTemplateValue(value, path = [], state = { markers: 0 }) {
    if (typeof value === 'string') {
        if (value.includes(PROXIES_PLACEHOLDER)) {
            if (value !== PROXIES_PLACEHOLDER || !isPlaceholderPath(path)) {
                fail(
                    'TEMPLATE_PLACEHOLDER_PATH',
                    `${PROXIES_PLACEHOLDER} is only allowed as an item in proxy-groups[*].proxies`,
                );
            }
            state.markers += 1;
        }
        return;
    }
    if (Array.isArray(value)) {
        value.forEach((item, index) => inspectTemplateValue(item, [...path, index], state));
        return;
    }
    if (!value || typeof value !== 'object') return;

    for (const [key, nested] of Object.entries(value)) {
        const canonical = canonicalFieldName(key);
        if (SENSITIVE_FIELD_NAMES.has(key.toLowerCase()) || SENSITIVE_FIELD_NAMES.has(canonical)) {
            fail(
                'TEMPLATE_SENSITIVE_FIELD',
                `Sensitive field "${key}" at ${pathLabel([...path, key])} is not allowed in a reusable template`,
            );
        }
        inspectTemplateValue(nested, [...path, key], state);
    }
}

function validateProxyGroups(config) {
    if (!Object.prototype.hasOwnProperty.call(config, 'proxy-groups')) {
        return { hasProxyGroups: false, markerCount: 0, groupNames: new Set() };
    }

    const groups = config['proxy-groups'];
    if (!Array.isArray(groups) || groups.length === 0) {
        fail('TEMPLATE_PROXY_GROUPS_TYPE', 'proxy-groups must be a non-empty array when provided');
    }
    if (groups.length > MAX_PROXY_GROUPS) {
        fail('TEMPLATE_PROXY_GROUPS_TOO_MANY', `proxy-groups exceed the ${MAX_PROXY_GROUPS}-item limit`);
    }

    const groupNames = new Set();
    const canonicalNames = new Set();
    let markerCount = 0;
    groups.forEach((group, index) => {
        if (!group || Array.isArray(group) || typeof group !== 'object') {
            fail('TEMPLATE_PROXY_GROUP_TYPE', `proxy-groups[${index}] must be a mapping`);
        }
        if (typeof group.name !== 'string' || !group.name.trim()) {
            fail('TEMPLATE_PROXY_GROUP_NAME', `proxy-groups[${index}].name must be a non-empty string`);
        }
        if (group.name.length > 128) {
            fail('TEMPLATE_PROXY_GROUP_NAME', `proxy-groups[${index}].name exceeds 128 characters`);
        }
        if (byteLength(group.name) > MAX_REFERENCE_BYTES) {
            fail('TEMPLATE_PROXY_GROUP_NAME', `proxy-groups[${index}].name exceeds ${MAX_REFERENCE_BYTES} bytes`);
        }
        const canonicalName = group.name.toUpperCase();
        if (BUILTIN_POLICIES.has(canonicalName)) {
            fail('TEMPLATE_PROXY_GROUP_NAME_RESERVED', `Proxy group name "${group.name}" is reserved by Clash`);
        }
        if (canonicalNames.has(canonicalName)) {
            fail('TEMPLATE_PROXY_GROUP_NAME_DUPLICATE', `Duplicate proxy group name "${group.name}"`);
        }
        canonicalNames.add(canonicalName);
        groupNames.add(group.name);

        if (typeof group.type !== 'string' || !group.type.trim() || group.type.length > 64) {
            fail('TEMPLATE_PROXY_GROUP_TYPE_NAME', `proxy-groups[${index}].type must be a short non-empty string`);
        }

        if (!Array.isArray(group.proxies) || group.proxies.length === 0) {
            fail('TEMPLATE_PROXY_GROUP_PROXIES', `proxy-groups[${index}].proxies must be a non-empty array`);
        }
        if (group.proxies.length > MAX_GROUP_PROXIES) {
            fail(
                'TEMPLATE_PROXY_GROUP_PROXIES_TOO_MANY',
                `proxy-groups[${index}].proxies exceeds the ${MAX_GROUP_PROXIES}-item limit`,
            );
        }
        markerCount += group.proxies.filter(item => item === PROXIES_PLACEHOLDER).length;
    });

    if (markerCount === 0) {
        fail(
            'TEMPLATE_PLACEHOLDER_REQUIRED',
            `At least one proxy group must include ${PROXIES_PLACEHOLDER}`,
        );
    }

    // After collecting all names, validate each static entry as either a
    // built-in policy or another template group. Anything else is a hard-coded
    // node name, which would become stale and could bypass generated access.
    const references = new Map();
    groups.forEach((group, groupIndex) => {
        const seen = new Set();
        const groupReferences = new Set();
        group.proxies.forEach((item, itemIndex) => {
            if (typeof item !== 'string' || !item.trim()) {
                fail(
                    'TEMPLATE_PROXY_GROUP_REFERENCE',
                    `proxy-groups[${groupIndex}].proxies[${itemIndex}] must be a non-empty string`,
                );
            }
            if (byteLength(item) > MAX_REFERENCE_BYTES) {
                fail(
                    'TEMPLATE_PROXY_GROUP_REFERENCE',
                    `proxy-groups[${groupIndex}].proxies[${itemIndex}] exceeds ${MAX_REFERENCE_BYTES} bytes`,
                );
            }
            if (seen.has(item)) {
                fail(
                    'TEMPLATE_PROXY_GROUP_REFERENCE_DUPLICATE',
                    `Duplicate proxy reference "${item}" in group "${group.name}"`,
                );
            }
            seen.add(item);

            if (item === PROXIES_PLACEHOLDER) return;
            if (BUILTIN_POLICIES.has(item)) return;
            if (!groupNames.has(item)) {
                fail(
                    'TEMPLATE_PROXY_GROUP_REFERENCE_UNKNOWN',
                    `Proxy reference "${item}" in group "${group.name}" is not a template group or built-in policy`,
                );
            }
            groupReferences.add(item);
        });
        references.set(group.name, groupReferences);
    });

    // Cyclic group references make Clash reject or endlessly recurse through
    // group selection. Catch them while the administrator is saving.
    const visiting = new Set();
    const visited = new Set();
    function visitGroup(name) {
        if (visiting.has(name)) {
            fail('TEMPLATE_PROXY_GROUP_CYCLE', `Proxy group reference cycle detected at "${name}"`);
        }
        if (visited.has(name)) return;
        visiting.add(name);
        for (const referencedName of references.get(name) || []) visitGroup(referencedName);
        visiting.delete(name);
        visited.add(name);
    }
    for (const name of groupNames) visitGroup(name);

    return { hasProxyGroups: true, markerCount, groupNames };
}

function splitClashRule(rule, index) {
    const parts = [];
    let current = '';
    let depth = 0;
    let quote = '';
    let escaped = false;

    for (const char of rule) {
        if (escaped) {
            current += char;
            escaped = false;
            continue;
        }
        if (quote && char === '\\') {
            current += char;
            escaped = true;
            continue;
        }
        if (quote) {
            current += char;
            if (char === quote) quote = '';
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            current += char;
            continue;
        }
        if (char === '(') depth += 1;
        if (char === ')') {
            depth -= 1;
            if (depth < 0) fail('TEMPLATE_RULE_SYNTAX', `rules[${index}] has unbalanced parentheses`);
        }
        if (char === ',' && depth === 0) {
            parts.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    if (quote || depth !== 0) {
        fail('TEMPLATE_RULE_SYNTAX', `rules[${index}] has unbalanced quoting or parentheses`);
    }
    parts.push(current.trim());
    if (parts.some(part => !part)) {
        fail('TEMPLATE_RULE_SYNTAX', `rules[${index}] contains an empty rule component`);
    }
    return parts;
}

function validateRules(config, { hasProxyGroups, groupNames }) {
    if (!Object.prototype.hasOwnProperty.call(config, 'rules')) return;
    if (!Array.isArray(config.rules)) {
        fail('TEMPLATE_RULES_TYPE', 'rules must be an array of strings');
    }
    if (config.rules.length > MAX_RULES) {
        fail('TEMPLATE_RULES_TOO_MANY', `rules exceed the ${MAX_RULES}-item limit`);
    }

    const allowedTargets = new Set(BUILTIN_POLICIES);
    if (hasProxyGroups) {
        for (const groupName of groupNames) allowedTargets.add(groupName);
    } else {
        // compileTemplate creates this group when the template omits groups.
        allowedTargets.add('PROXY');
    }
    const trailingModifiers = new Set(['no-resolve', 'src']);

    config.rules.forEach((rule, index) => {
        if (typeof rule !== 'string' || !rule.trim()) {
            fail('TEMPLATE_RULE_TYPE', `rules[${index}] must be a non-empty string`);
        }
        if (byteLength(rule) > MAX_RULE_BYTES) {
            fail('TEMPLATE_RULE_TOO_LONG', `rules[${index}] exceeds ${MAX_RULE_BYTES} bytes`);
        }

        const parts = splitClashRule(rule, index);
        const ruleType = parts[0].toUpperCase();
        let targetIndex;
        if (ruleType === 'MATCH' || ruleType === 'FINAL') {
            if (parts.length !== 2) {
                fail('TEMPLATE_RULE_SYNTAX', `rules[${index}] ${ruleType} must contain exactly one policy target`);
            }
            targetIndex = 1;
        } else {
            targetIndex = parts.length - 1;
            while (targetIndex > 1 && trailingModifiers.has(parts[targetIndex].toLowerCase())) {
                targetIndex -= 1;
            }
            if (targetIndex < 2) {
                fail('TEMPLATE_RULE_SYNTAX', `rules[${index}] does not contain a policy target`);
            }
        }

        const target = parts[targetIndex];
        if (!allowedTargets.has(target)) {
            fail(
                'TEMPLATE_RULE_TARGET_UNKNOWN',
                `Policy target "${target}" in rules[${index}] is not a template group or built-in policy`,
            );
        }
    });
}

/**
 * Validate and canonicalize a Clash template source.
 *
 * @param {string} source
 * @returns {{config: object, yaml: string, hasProxyGroups: boolean}}
 */
function validateTemplateSource(source) {
    const config = parseStrictYaml(source);

    for (const key of Object.keys(config)) {
        if (FORBIDDEN_TOP_LEVEL_FIELDS.has(canonicalFieldName(key))) {
            fail('TEMPLATE_TOP_LEVEL_FIELD_FORBIDDEN', `Top-level field "${key}" is not allowed in a Clash template`);
        }
    }

    const markerState = { markers: 0 };
    inspectTemplateValue(config, [], markerState);
    const groupValidation = validateProxyGroups(config);
    const { hasProxyGroups, markerCount } = groupValidation;
    if (markerState.markers !== markerCount) {
        // Defensive invariant: inspectTemplateValue already rejects markers at
        // all other paths, so these counts should always match.
        fail('TEMPLATE_PLACEHOLDER_PATH', `Invalid ${PROXIES_PLACEHOLDER} placement`);
    }
    validateRules(config, groupValidation);

    const normalizedYaml = YAML.stringify(config, { lineWidth: 0 });
    if (byteLength(normalizedYaml) > MAX_TEMPLATE_BYTES) {
        fail('TEMPLATE_YAML_TOO_LARGE', `Normalized template exceeds the ${MAX_TEMPLATE_BYTES}-byte limit`);
    }

    return {
        config,
        yaml: normalizedYaml,
        hasProxyGroups,
    };
}

function normalizeActive(value) {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        if (['true', '1', 'on'].includes(normalized)) return true;
        if (['false', '0', 'off'].includes(normalized)) return false;
    }
    fail('TEMPLATE_ACTIVE_TYPE', 'active must be a boolean');
}

/**
 * Whitelist and normalize fields accepted by template create/update routes.
 * Revision is intentionally absent: callers increment it atomically with
 * `$inc` rather than accepting a client-provided value.
 *
 * @param {object} input
 * @param {{partial?: boolean}} options
 * @returns {{name?: string, description?: string, yaml?: string, active?: boolean}}
 */
function normalizeTemplateInput(input, { partial = false } = {}) {
    if (!input || Array.isArray(input) || typeof input !== 'object') {
        fail('TEMPLATE_INPUT_TYPE', 'Template input must be an object');
    }

    const allowed = new Set(['name', 'description', 'yaml', 'active']);
    for (const key of Object.keys(input)) {
        if (!allowed.has(key)) {
            fail('TEMPLATE_INPUT_FIELD', `Template field "${key}" is not allowed`);
        }
    }

    const output = {};
    if (Object.prototype.hasOwnProperty.call(input, 'name')) {
        if (typeof input.name !== 'string') fail('TEMPLATE_NAME_TYPE', 'Template name must be a string');
        const name = input.name.trim();
        if (!name) fail('TEMPLATE_NAME_EMPTY', 'Template name cannot be empty');
        if (name.length > 80) fail('TEMPLATE_NAME_TOO_LONG', 'Template name exceeds 80 characters');
        if (/\p{Cc}/u.test(name)) fail('TEMPLATE_NAME_CONTROL_CHAR', 'Template name contains a control character');
        output.name = name;
    } else if (!partial) {
        fail('TEMPLATE_NAME_REQUIRED', 'Template name is required');
    }

    if (Object.prototype.hasOwnProperty.call(input, 'description')) {
        if (typeof input.description !== 'string') {
            fail('TEMPLATE_DESCRIPTION_TYPE', 'Template description must be a string');
        }
        const description = input.description.trim();
        if (description.length > 500) {
            fail('TEMPLATE_DESCRIPTION_TOO_LONG', 'Template description exceeds 500 characters');
        }
        output.description = description;
    } else if (!partial) {
        output.description = '';
    }

    if (Object.prototype.hasOwnProperty.call(input, 'yaml')) {
        output.yaml = validateTemplateSource(input.yaml).yaml;
    } else if (!partial) {
        fail('TEMPLATE_YAML_REQUIRED', 'Template YAML is required');
    }

    if (Object.prototype.hasOwnProperty.call(input, 'active')) {
        output.active = normalizeActive(input.active);
    } else if (!partial) {
        output.active = true;
    }

    if (partial && Object.keys(output).length === 0) {
        fail('TEMPLATE_UPDATE_EMPTY', 'Template update does not contain any editable fields');
    }
    return output;
}

function templateSource(templateOrYaml) {
    if (typeof templateOrYaml === 'string') return templateOrYaml;
    if (templateOrYaml && typeof templateOrYaml.yaml === 'string') return templateOrYaml.yaml;
    fail('TEMPLATE_YAML_TYPE', 'Template must be a YAML string or an object with a yaml field');
}

function normalizeGeneratedProxies(proxies, explicitNames) {
    if (!Array.isArray(proxies)) {
        fail('GENERATED_PROXIES_TYPE', 'Generated proxies must be an array');
    }
    if (proxies.length > MAX_GENERATED_PROXIES) {
        fail('GENERATED_PROXIES_TOO_MANY', `Generated proxies exceed the ${MAX_GENERATED_PROXIES}-item limit`);
    }

    const safeProxies = cloneSafe(proxies, ['proxies']);
    const derivedNames = safeProxies.map((proxy, index) => {
        if (!proxy || Array.isArray(proxy) || typeof proxy !== 'object') {
            fail('GENERATED_PROXY_TYPE', `Generated proxy at index ${index} must be a mapping`);
        }
        if (typeof proxy.name !== 'string' || !proxy.name.trim()) {
            fail('GENERATED_PROXY_NAME', `Generated proxy at index ${index} must have a non-empty name`);
        }
        return proxy.name;
    });

    const proxyNames = explicitNames === undefined ? derivedNames : explicitNames;
    if (!Array.isArray(proxyNames)) {
        fail('GENERATED_PROXY_NAMES_TYPE', 'proxyNames must be an array when provided');
    }
    if (proxyNames.length > MAX_GENERATED_PROXIES) {
        fail('GENERATED_PROXY_NAMES_TOO_MANY', `proxyNames exceed the ${MAX_GENERATED_PROXIES}-item limit`);
    }

    const safeNames = proxyNames.map((name, index) => {
        if (typeof name !== 'string' || !name.trim()) {
            fail('GENERATED_PROXY_NAME', `proxyNames[${index}] must be a non-empty string`);
        }
        if (name.includes(PROXIES_PLACEHOLDER)) {
            fail('GENERATED_PROXY_NAME', `proxyNames[${index}] cannot contain the template placeholder`);
        }
        return name;
    });

    return { proxies: safeProxies, proxyNames: safeNames };
}

function expandProxyNames(groups, proxyNames) {
    return groups.map(group => ({
        ...group,
        proxies: group.proxies.flatMap(item => (
            item === PROXIES_PLACEHOLDER ? proxyNames : [item]
        )),
    }));
}

/**
 * Compile a stored template with service-generated proxy records.
 *
 * @param {string|{yaml: string}} templateOrYaml
 * @param {{proxies: object[], proxyNames?: string[]}} generated
 * @returns {object} a new plain Clash configuration object
 */
function compileTemplate(templateOrYaml, { proxies, proxyNames } = {}) {
    const validated = validateTemplateSource(templateSource(templateOrYaml));
    const generated = normalizeGeneratedProxies(proxies, proxyNames);
    const config = cloneSafe(validated.config);

    // Force-write trusted generated proxy objects. A template is never allowed
    // to supply or override this field.
    config.proxies = generated.proxies;

    if (validated.hasProxyGroups) {
        config['proxy-groups'] = expandProxyNames(config['proxy-groups'], generated.proxyNames);
    } else {
        config['proxy-groups'] = [{
            name: 'PROXY',
            type: 'select',
            proxies: generated.proxyNames,
        }];
    }

    return config;
}

module.exports = {
    MAX_TEMPLATE_BYTES,
    PROXIES_PLACEHOLDER,
    ClashTemplateError,
    validateTemplateSource,
    normalizeTemplateInput,
    compileTemplate,
};
