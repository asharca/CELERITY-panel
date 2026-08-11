const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');

const root = path.join(__dirname, '..');
const templatePath = path.join(root, 'views/access-logs.ejs');
const clientPath = path.join(root, 'public/js/access-logs.js');
const stylePath = path.join(root, 'public/css/style.css');
const layoutPath = path.join(root, 'views/layout.ejs');
const template = fs.readFileSync(templatePath, 'utf8');
const client = fs.readFileSync(clientPath, 'utf8');
const style = fs.readFileSync(stylePath, 'utf8');
const layout = fs.readFileSync(layoutPath, 'utf8');

const localeNames = ['en', 'zh-CN', 'ru'];
const localeSections = localeNames.map((name) => {
    const locale = JSON.parse(fs.readFileSync(path.join(root, `src/locales/${name}.json`), 'utf8'));
    assert(locale.accessLogs, `${name} defines accessLogs strings`);
    return locale.accessLogs;
});
const expectedKeys = Object.keys(localeSections[0]).sort();
const placeholders = (value) => Array.from(
    String(value).matchAll(/\{([a-zA-Z0-9_]+)\}/g),
    (match) => match[1]
).sort();
for (let localeIndex = 1; localeIndex < localeSections.length; localeIndex += 1) {
    assert.deepStrictEqual(
        Object.keys(localeSections[localeIndex]).sort(),
        expectedKeys,
        `${localeNames[localeIndex]} accessLogs keys match English`
    );
}
for (const key of expectedKeys) {
    const expected = placeholders(localeSections[0][key]);
    for (let localeIndex = 1; localeIndex < localeSections.length; localeIndex += 1) {
        assert.deepStrictEqual(
            placeholders(localeSections[localeIndex][key]),
            expected,
            `${localeNames[localeIndex]} accessLogs.${key} placeholders match English`
        );
    }
}

const maliciousNodeName = '</script><script>globalThis.__accessLogInjected=true</script>';
const locals = {
    t: (key) => key,
    enabled: true,
    state: 'active',
    lang: 'en',
    dateLocale: 'en-US',
    nodes: [{ _id: 'node-1', name: maliciousNodeName }],
};
const rendered = ejs.render(template, locals, { filename: templatePath });
const disabled = ejs.render(template, { ...locals, enabled: false }, { filename: templatePath });

assert(!rendered.includes(maliciousNodeName), 'node names cannot terminate the inline configuration script');
assert.match(disabled, /\/panel\/settings\?tab=accessLogs/, 'the disabled state opens the correct settings tab');
assert.doesNotMatch(disabled, /id="alFilters"/, 'the disabled page does not render an inert explorer');
assert.match(rendered, /<label for="alQuery">/, 'raw search has an associated label');
assert.match(rendered, /<label for="alEmail">/, 'user filtering has an associated label');
assert.match(rendered, /<label for="alFrom">/, 'time filtering has an associated label');
assert.match(rendered, /data-hours="24"[\s\S]*data-hours="168"[\s\S]*data-hours="720"/, 'quick ranges cover 24h, 7d, and 30d');
assert.match(rendered, /id="alAdvancedFilters"/, 'secondary filters are progressively disclosed');
assert.match(rendered, /id="alLoadMore"/, 'recent events support bounded pagination');
assert.match(rendered, /<caption class="ui-visually-hidden">/, 'data tables expose captions');
assert.match(rendered, /<th scope="col">/, 'data-table headers declare column scope');
assert.match(rendered, /role="status" aria-live="polite"/, 'dynamic updates use a polite live region');
assert.match(rendered, /role="img"[^>]*aria-label=/, 'the timeline canvas has an accessible graphic role and name');

const inlineScripts = Array.from(
    rendered.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi),
    (match) => match[1]
);
assert(inlineScripts.length >= 1, 'the enabled page contains script-safe runtime configuration');
for (const source of inlineScripts) {
    assert.doesNotThrow(() => new Function(source), 'rendered inline configuration remains valid JavaScript');
}

assert.match(client, /new AbortController\(\)/, 'stale analytics and search requests are cancellable');
assert.match(client, /Promise\.allSettled\(\[/, 'event search and analytics refresh concurrently');
assert.match(client, /history\.replaceState\(/, 'applied filters are reflected in the URL');
assert.match(client, /SEARCH_PAGE_SIZE = 100/, 'raw events use a bounded page size');
assert.match(client, /data\.hasMore/, 'the next-page control follows the API sentinel');
assert.match(client, /if \(!requestParams\.has\('to'\)\) requestParams\.set\('to', new Date\(\)\.toISOString\(\)\)/,
    'open-ended searches freeze an upper bound before offset pagination');
assert.match(client, /data-label=/, 'event cells carry mobile field labels');
assert.match(client, /aria-expanded="false"/, 'source-detail controls expose their collapsed state');
assert.match(client, /button\.setAttribute\('aria-expanded'/, 'source-detail controls announce expansion');
assert.match(client, /Number\(row\.parse_ok\) === 0/, 'unparsed diagnostic rows are distinguished from parsed analytics');
assert.match(client, /unknown: Math\.max\(0, value\.hits/, 'timeline action totals retain unknown actions');
assert.match(client, /Math\.ceil\(rawBucketCount \/ 720\)/,
    'long timelines increase their bucket size instead of silently truncating early dates');
assert.match(client, /year: 'numeric'/, 'range and timeline labels remain unambiguous across years');
assert.match(client, /data\.usersByFanout \|\| data\.users/, 'fan-out uses the dedicated global ranking with compatibility fallback');
assert.match(client, /wrapper\.dataset\.loading === '1'/,
    'source-detail rows suppress duplicate in-flight requests');
assert.match(client, /partialErrors\.series[\s\S]*renderTimelineFailure/,
    'a failed timeline query is not presented as a real empty series');
assert.match(client, /function prepareRefreshSurfaces\(\)[\s\S]*searchRows = \[\][\s\S]*alAnalyticsContent/,
    'a newly applied filter clears stale search and analytics surfaces before loading');
assert.doesNotMatch(client, /form\.addEventListener\('(input|change)', updateActiveFilters\)/,
    'unapplied form edits are not announced as active filters');
assert.match(client, /date\.setTime\(date\.getTime\(\) \+ 59999\)/, 'a datetime-local end includes its selected minute');
assert.match(client, /fromDate && toDate && fromDate\.getTime\(\) > toDate\.getTime\(\)/, 'reversed time windows are rejected client-side');

assert.match(layout, /data-language-option/, 'language links expose the parameter-preserving enhancement');
assert.match(layout, /url\.searchParams\.set\('lang'/, 'language switching preserves the current access-log query');
assert.match(layout, /\['pointerdown', 'focus', 'contextmenu', 'click'\]/,
    'language links refresh their target after in-page filter URL updates');

assert.match(style, /\.al-filter-toolbar/, 'the access-log filter toolbar has dedicated layout styles');
assert.match(style, /@media \(max-width: 640px\)[\s\S]*\.al-events-table/, 'event rows adapt at phone widths');
assert.match(style, /@media \(max-width: 640px\)[\s\S]*content: attr\(data-label\)/, 'mobile event cards retain field labels');
assert.match(style, /@media \(prefers-reduced-motion: reduce\)[\s\S]*\.al-/, 'access-log motion respects reduced-motion preferences');

console.log('access logs UI tests passed');
