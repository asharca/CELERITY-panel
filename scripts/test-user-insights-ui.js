const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');

const root = path.join(__dirname, '..');
const templatePath = path.join(root, 'views/user-detail.ejs');
const clientPath = path.join(root, 'public/js/user-insights.js');
const accessClientPath = path.join(root, 'public/js/access-logs.js');
const stylePath = path.join(root, 'public/css/style.css');

const template = fs.readFileSync(templatePath, 'utf8');
const client = fs.readFileSync(clientPath, 'utf8');
const accessClient = fs.readFileSync(accessClientPath, 'utf8');
const style = fs.readFileSync(stylePath, 'utf8');

assert.match(template, /id="userInsights"/, 'user detail exposes the account activity region');
assert.match(template, /role="tablist"/, 'traffic and access views use accessible tabs');
for (const range of ['24h', '7d', '30d']) {
    assert.match(template, new RegExp(`data-range="${range}"`), `${range} range control is rendered`);
}
assert.match(
    template,
    /\/panel\/access-logs\?email=<%= encodeURIComponent\(user\.userId\) %>/,
    'the full access-log link carries the encoded subscription account'
);
assert.match(template, /jsonForScript/, 'inline account configuration uses script-safe JSON');

assert.match(client, /encodeURIComponent\(config\.userId\)[\s\S]*\/traffic-history\?range=/, 'traffic history is fetched by encoded userId');
assert.match(client, /\/panel\/access-logs\/api\/analytics\?/, 'the account view loads access analytics');
assert.match(client, /\/panel\/access-logs\/api\/search\?/, 'the account view loads recent access events');
assert.match(client, /email:\s*String\(config\.userId\)/, 'access queries filter by the subscription account');
assert.match(client, /Date\.now\(\)\s*-\s*\(7\s*\*\s*24/, 'account access summaries are bounded to seven days');
assert.match(
    client,
    /series\[series\.length\s*-\s*1\]\.ts/,
    'the displayed period ends at the last returned bucket, not the exclusive API boundary'
);

assert.match(accessClient, /function hydrateFiltersFromLocation\(/, 'the full access-log page hydrates deep-link filters');
assert.match(accessClient, /email:\s*'alEmail'/, 'the account query parameter maps to the user filter');
assert.match(
    accessClient,
    /if \(enabled\) \{\s*hydrateFiltersFromLocation\(\);\s*setDefaultRange\(\);/,
    'deep-link filters are applied before the default time range'
);

assert.match(style, /@media \(max-width: 640px\)[\s\S]*\.user-insights-panel/, 'account insights adapt to mobile widths');
assert.match(style, /@media \(prefers-reduced-motion: reduce\)/, 'account insights respect reduced motion');

const localeNames = ['en', 'zh-CN', 'ru'];
const localeInsights = localeNames.map(name => {
    const parsed = JSON.parse(fs.readFileSync(path.join(root, `src/locales/${name}.json`), 'utf8'));
    assert(parsed.userInsights, `${name} defines userInsights strings`);
    return parsed.userInsights;
});
const expectedKeys = Object.keys(localeInsights[0]).sort();
for (let index = 1; index < localeInsights.length; index += 1) {
    assert.deepStrictEqual(Object.keys(localeInsights[index]).sort(), expectedKeys, `${localeNames[index]} userInsights keys match English`);
}

const maliciousUserId = '</script><script>globalThis.__injected=true</script>';
const rendered = ejs.render(template, {
    t: key => key,
    user: {
        userId: maliciousUserId,
        username: 'QA',
        password: 'secret',
        enabled: true,
        groups: [],
        nodes: [],
        traffic: { tx: 0, rx: 0 },
        trafficLimit: 0,
        maxDevices: -1,
        subscriptionToken: 'token',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        expireAt: null,
    },
    baseUrl: 'https://panel.example.invalid',
    effectiveNodes: [],
    hwidEnabled: false,
    hwidDevices: [],
    formatTraffic: () => '0 B',
    dateLocale: 'en-US',
}, { filename: templatePath });

assert(!rendered.includes(maliciousUserId), 'a malicious userId cannot terminate an inline script');
const inlineScripts = Array.from(rendered.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi), match => match[1]);
assert(inlineScripts.length >= 2, 'rendered account page contains its inline configuration scripts');
for (const source of inlineScripts) {
    assert.doesNotThrow(() => new Function(source), 'rendered inline scripts remain syntactically valid');
}

const { buildSpec } = require('../src/docs/openapi');
const operation = buildSpec('en').paths['/users/{userId}/traffic-history']?.get;
assert(operation, 'OpenAPI documents the traffic-history endpoint');
assert.deepStrictEqual(operation['x-requiredScopes'], ['users:read']);
assert.deepStrictEqual(operation.parameters[0].schema.enum, ['24h', '7d', '30d']);

console.log('user insights UI tests passed');
