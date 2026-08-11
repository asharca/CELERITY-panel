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
    /\/panel\/access-logs\?email=<%= encodeURIComponent\(user\.userId\) %>&amp;from=<%= encodeURIComponent\(accessLogWindowFrom\) %>/,
    'the full access-log link carries the encoded account and the same seven-day window'
);
assert.match(template, /jsonForScript/, 'inline account configuration uses script-safe JSON');
assert.match(template, /class="traffic-quota traffic-quota-<%= accountTrafficState %>"/,
    'the account exposes a cumulative quota overview independently from history');
assert.match(template, /role="progressbar"[\s\S]*aria-valuetext=/,
    'limited accounts receive an accessible quota meter');
assert.doesNotMatch(template, /user\.traffic\?\.lastUpdate/,
    'the quota summary does not claim a timestamp whose reset semantics are ambiguous');
assert.match(template, /id="trafficPeak"/, 'the selected-period summary exposes a completed-interval peak');
assert.match(template, /id="trafficChart"[^>]*tabindex="0"[^>]*role="img"/,
    'the traffic chart is keyboard focusable and named as a graphic');
assert.match(template, /id="trafficChartTooltip"/, 'the traffic chart exposes exact interval values');

assert.match(client, /encodeURIComponent\(config\.userId\)[\s\S]*\/traffic-history\?range=/, 'traffic history is fetched by encoded userId');
assert.match(client, /\/panel\/access-logs\/api\/analytics\?/, 'the account view loads access analytics');
assert.match(client, /\/panel\/access-logs\/api\/search\?/, 'the account view loads recent access events');
assert.match(client, /email:\s*String\(config\.userId\)/, 'access queries filter by the subscription account');
assert.match(client, /Date\.now\(\)\s*-\s*\(7\s*\*\s*24/, 'account access summaries are bounded to seven days');
assert.match(template, /nodeNames:\s*<%- jsonForScript\(accessLogNodeNames\) %>/,
    'the account view receives a safe node-name lookup');
assert.match(client, /formatNode\(event\.node_id\)/,
    'account access rows identify the panel node, not a transport route');
assert.match(
    client,
    /series\[series\.length\s*-\s*1\]\.ts/,
    'the displayed period ends at the last returned bucket, not the exclusive API boundary'
);
assert.match(client, /allPoints\.length > 1 \? allPoints\.slice\(0, -1\)/,
    'averages and peaks exclude the in-progress final bucket');
assert.match(client, /traffic-chart-bar traffic-chart-bar-(?:rx|tx)/,
    'bucketed traffic is rendered as directional stacked bars');
assert.match(client, /addEventListener\('pointermove'/,
    'the chart supports pointer inspection');
assert.match(client, /event\.key === 'ArrowLeft'[\s\S]*event\.key === 'ArrowRight'/,
    'the chart supports keyboard interval inspection');
assert.match(client, /activeNodes\.reduce\(\(sum, node\) => sum \+ node\.total, 0\)/,
    'node bars use attributed traffic as their percentage denominator');

assert.match(accessClient, /function hydrateFiltersFromLocation\(/, 'the full access-log page hydrates deep-link filters');
assert.match(accessClient, /email:\s*'alEmail'/, 'the account query parameter maps to the user filter');
assert.match(
    accessClient,
    /hydrateFiltersFromLocation\(\);\s*if \(!\$\('alFrom'\) \|\| !\$\('alFrom'\)\.value\) setDefaultRange\(\);/,
    'deep-link filters are applied before the default time range'
);

assert.match(style, /@media \(max-width: 640px\)[\s\S]*\.user-insights-panel/, 'account insights adapt to mobile widths');
assert.match(style, /@media \(max-width: 980px\)[\s\S]*\.user-detail-layout > \.col-8,[\s\S]*flex-basis: 100%/,
    'the user detail columns stack before the narrow desktop layout becomes crowded');
assert.match(style, /@media \(prefers-reduced-motion: reduce\)/, 'account insights respect reduced motion');
assert.match(style, /--traffic-upload:[^;]+;[\s\S]*--traffic-download:[^;]+;/,
    'traffic directions use dedicated data-visualization tokens');
assert.match(style, /@media \(max-width: 640px\)[\s\S]*\.traffic-range-btn[\s\S]*min-height: 44px/,
    'mobile traffic controls meet the minimum touch target');

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
const placeholders = value => Array.from(String(value).matchAll(/\{([a-zA-Z0-9_]+)\}/g), match => match[1]).sort();
for (const key of expectedKeys) {
    const expectedPlaceholders = placeholders(localeInsights[0][key]);
    for (let index = 1; index < localeInsights.length; index += 1) {
        assert.deepStrictEqual(
            placeholders(localeInsights[index][key]),
            expectedPlaceholders,
            `${localeNames[index]} userInsights.${key} placeholders match English`
        );
    }
}

const maliciousUserId = '</script><script>globalThis.__injected=true</script>';
const renderLocals = {
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
};
const rendered = ejs.render(template, renderLocals, { filename: templatePath });

assert(!rendered.includes(maliciousUserId), 'a malicious userId cannot terminate an inline script');
assert.match(rendered, /traffic-quota-unlimited/, 'unlimited accounts render an explicit quota state');

const gibibyte = 1024 ** 3;
const renderQuota = (usedGibibytes, limitGibibytes) => ejs.render(template, {
    ...renderLocals,
    user: {
        ...renderLocals.user,
        userId: 'quota-boundary',
        traffic: { tx: usedGibibytes * gibibyte, rx: 0 },
        trafficLimit: limitGibibytes * gibibyte,
    },
}, { filename: templatePath });
const nearLimit = renderQuota(99.5, 100);
assert.match(nearLimit, /traffic-quota-warning/, 'an account below its limit remains in the warning state');
assert.match(nearLimit, /aria-valuenow="99\.50"/, 'the progress meter preserves the near-limit value');
assert.match(nearLimit, /aria-valuetext="99\.5%"/, 'the near-limit label is not rounded up to 100%');
assert.doesNotMatch(nearLimit, /userInsights\.quotaReached/, 'a near-limit account is not announced as exhausted');

const atLimit = renderQuota(100, 100);
assert.match(atLimit, /traffic-quota-danger/, 'an account at its limit renders the danger state');
assert.match(atLimit, /aria-valuenow="100\.00"/, 'the at-limit progress value is exactly 100%');
assert.match(atLimit, /aria-valuetext="100%"/, 'the at-limit label is exactly 100%');
assert.match(atLimit, /userInsights\.quotaReached/, 'an at-limit account is announced as exhausted');

const exceeded = renderQuota(110, 100);
assert.match(exceeded, /traffic-quota-danger/, 'an over-quota account renders the danger state');
assert.match(exceeded, /aria-valuenow="100\.00"/, 'the visual progress value is capped at 100%');
assert.match(exceeded, /aria-valuetext="110%"/, 'the accessible label preserves over-quota usage');
assert.match(exceeded, /userInsights\.quotaReached/, 'an over-quota account is announced as exhausted');

const slightlyExceeded = renderQuota(100.01, 100);
assert.match(slightlyExceeded, /aria-valuetext="100\.1%"/,
    'even a small overage remains visible instead of being rounded back to 100%');

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
