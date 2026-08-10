const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Module = require('module');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret';

const root = path.join(__dirname, '..');
const serviceFile = path.join(root, 'src/services/userTrafficHistoryService.js');
const usersRouteFile = path.join(root, 'src/routes/users.js');

function clone(value) {
    if (value === undefined) return undefined;
    return structuredClone(value);
}

function createQuery(value) {
    return {
        select() { return this; },
        populate() { return this; },
        lean() { return Promise.resolve(clone(value)); },
        then(resolve, reject) {
            return Promise.resolve(clone(value)).then(resolve, reject);
        },
    };
}

function createResponse() {
    return {
        statusCode: 200,
        body: undefined,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(value) {
            this.body = value;
            return this;
        },
        send(value) {
            this.body = value;
            return this;
        },
    };
}

async function invokeRoute(router, method, routePath, req) {
    const layer = router.stack.find(item => item.route?.path === routePath && item.route.methods[method]);
    assert(layer, `missing route ${method.toUpperCase()} ${routePath}`);

    const res = createResponse();
    let index = 0;
    const next = async error => {
        if (error) throw error;
        const handler = layer.route.stack[index++]?.handle;
        if (handler) return handler(req, res, next);
        return undefined;
    };
    await next();
    return res;
}

function loadHistoryService(model) {
    const originalLoad = Module._load;
    Module._load = function patchedLoad(request, parent, isMain) {
        if (parent?.filename === serviceFile && request === '../models/userTrafficHourlyModel') {
            return model;
        }
        return originalLoad.call(this, request, parent, isMain);
    };

    try {
        delete require.cache[require.resolve('../src/services/userTrafficHistoryService')];
        return require('../src/services/userTrafficHistoryService');
    } finally {
        Module._load = originalLoad;
        delete require.cache[require.resolve('../src/services/userTrafficHistoryService')];
    }
}

function createHistoryModelHarness() {
    const state = {
        bulkCalls: [],
        deleteCalls: [],
        findCalls: [],
        rows: [],
    };
    const bulkResult = { acknowledged: true, modifiedCount: 2 };

    const model = {
        async bulkWrite(operations, options) {
            state.bulkCalls.push({ operations: clone(operations), options: clone(options) });
            return bulkResult;
        },
        find(filter) {
            const call = { filter: clone(filter), sort: null };
            state.findCalls.push(call);
            return {
                sort(spec) {
                    call.sort = clone(spec);
                    return this;
                },
                lean: async () => clone(state.rows),
            };
        },
        async deleteMany(filter) {
            state.deleteCalls.push(clone(filter));
            return { acknowledged: true, deletedCount: 3 };
        },
    };

    return { state, model, bulkResult };
}

async function testServiceWritesAndBoundaries() {
    const harness = createHistoryModelHarness();
    const service = loadHistoryService(harness.model);

    assert.strictEqual(
        service.getUserHistory,
        service.getUserTrafficHistory,
        'the concise API name and descriptive service name stay compatible'
    );

    assert.strictEqual(service.normalizeByteCount(12.9), 12, 'byte deltas are integer counts');
    for (const value of [0, -1, NaN, Infinity, -Infinity, '12', null, undefined]) {
        assert.strictEqual(service.normalizeByteCount(value), 0, `${String(value)} is not a valid byte delta`);
    }

    assert.strictEqual(
        service.floorToUtcHour('2026-08-10T23:37:48.999+08:00').toISOString(),
        '2026-08-10T15:00:00.000Z',
        'traffic samples use UTC hour buckets'
    );
    assert.strictEqual(service.floorToUtcHour('not-a-date'), null);

    const result = await service.recordUserTrafficDeltas({
        nodeId: ' node-1 ',
        nodeName: 'Taipei A',
        nodeType: 'xray',
        timestamp: '2026-08-10T23:37:48.999+08:00',
        deltas: [
            { userId: 'alice', tx: 10.9, rx: 20 },
            { userId: 'alice', tx: 5, rx: NaN },
            { userId: 'bob', tx: -8, rx: 8.8 },
            { userId: 'zero', tx: 0, rx: 0 },
            { userId: 'numeric-string', tx: '100', rx: '200' },
            { userId: 'infinite', tx: Infinity, rx: -Infinity },
            { userId: '', tx: 1, rx: 1 },
            null,
        ],
    });

    assert.strictEqual(result, harness.bulkResult);
    assert.strictEqual(harness.state.bulkCalls.length, 1, 'one unordered bulk write stores the bucket');
    assert.deepStrictEqual(harness.state.bulkCalls[0], {
        operations: [
            {
                updateOne: {
                    filter: {
                        userId: 'alice',
                        nodeId: 'node-1',
                        ts: new Date('2026-08-10T15:00:00.000Z'),
                    },
                    update: {
                        $inc: { tx: 15, rx: 20 },
                        $set: { nodeName: 'Taipei A', nodeType: 'xray' },
                    },
                    upsert: true,
                },
            },
            {
                updateOne: {
                    filter: {
                        userId: 'bob',
                        nodeId: 'node-1',
                        ts: new Date('2026-08-10T15:00:00.000Z'),
                    },
                    update: {
                        $inc: { tx: 0, rx: 8 },
                        $set: { nodeName: 'Taipei A', nodeType: 'xray' },
                    },
                    upsert: true,
                },
            },
        ],
        options: { ordered: false },
    });

    const emptyResult = await service.recordUserTrafficDeltas({
        nodeId: 'node-1',
        timestamp: '2026-08-10T15:59:59.999Z',
        deltas: [
            { userId: 'alice', tx: 0, rx: 0 },
            { userId: 'bob', tx: -1, rx: NaN },
        ],
    });
    assert.strictEqual(emptyResult, null, 'all-invalid batches avoid a database call');
    assert.strictEqual(harness.state.bulkCalls.length, 1);

    for (const sample of [
        { nodeId: '', deltas: [{ userId: 'alice', tx: 1, rx: 1 }] },
        { nodeId: 'node-1', timestamp: 'invalid', deltas: [{ userId: 'alice', tx: 1, rx: 1 }] },
        { nodeId: 'node-1', deltas: {} },
    ]) {
        assert.strictEqual(await service.recordUserTrafficDeltas(sample), null);
    }
    assert.strictEqual(harness.state.bulkCalls.length, 1, 'invalid samples never reach bulkWrite');

    assert.throws(
        () => service.getRangeConfig('forever'),
        error => error instanceof RangeError && error.code === 'INVALID_TRAFFIC_HISTORY_RANGE'
    );
    assert.throws(
        () => service.getRangeWindow('24h', 'not-a-date'),
        /Invalid traffic history reference time/
    );

    assert.deepStrictEqual(
        await service.deleteUserTrafficHistory(''),
        { acknowledged: true, deletedCount: 0 },
        'empty account ids do not issue broad deletes'
    );
    assert.strictEqual(harness.state.deleteCalls.length, 0);
    assert.deepStrictEqual(
        await service.deleteUserTrafficHistory('alice'),
        { acknowledged: true, deletedCount: 3 }
    );
    assert.deepStrictEqual(harness.state.deleteCalls, [{ userId: 'alice' }]);
}

function assertWindow(history, { userId, range, granularity, from, to, points }) {
    assert.strictEqual(history.userId, userId);
    assert.strictEqual(history.range, range);
    assert.strictEqual(history.granularity, granularity);
    assert.strictEqual(history.from.toISOString(), from);
    assert.strictEqual(history.to.toISOString(), to);
    assert.strictEqual(history.series.length, points, `${range} returns a dense ${points}-point series`);
}

async function testServiceQueries() {
    const harness = createHistoryModelHarness();
    const service = loadHistoryService(harness.model);
    const now = new Date('2026-08-10T15:37:48.000Z');

    harness.state.rows = [
        { userId: 'alice', nodeId: 'node-a', nodeName: 'Alpha old', nodeType: 'xray', ts: new Date('2026-08-09T16:05:00Z'), tx: 10, rx: 20 },
        { userId: 'alice', nodeId: 'node-b', nodeName: 'Beta', nodeType: 'hysteria', ts: new Date('2026-08-09T16:50:00Z'), tx: 5, rx: 0 },
        { userId: 'alice', nodeId: 'node-a', nodeName: 'Alpha renamed', nodeType: 'xray', ts: new Date('2026-08-10T15:05:00Z'), tx: 0, rx: 30 },
        { userId: 'alice', nodeId: 'ignored-invalid', ts: new Date('2026-08-10T12:00:00Z'), tx: -5, rx: NaN },
        { userId: 'alice', nodeId: 'ignored-before', ts: new Date('2026-08-09T15:59:59.999Z'), tx: 900, rx: 900 },
        { userId: 'alice', nodeId: 'ignored-after', ts: new Date('2026-08-10T16:00:00Z'), tx: 900, rx: 900 },
    ];
    const hourly = await service.getUserTrafficHistory('alice', '24h', { now });
    assertWindow(hourly, {
        userId: 'alice',
        range: '24h',
        granularity: 'hour',
        from: '2026-08-09T16:00:00.000Z',
        to: '2026-08-10T16:00:00.000Z',
        points: 24,
    });
    assert.deepStrictEqual(hourly.totals, { tx: 15, rx: 50, total: 65 });
    assert.deepStrictEqual(hourly.series[0], {
        ts: new Date('2026-08-09T16:00:00.000Z'),
        tx: 15,
        rx: 20,
        total: 35,
    });
    assert.deepStrictEqual(hourly.series[23], {
        ts: new Date('2026-08-10T15:00:00.000Z'),
        tx: 0,
        rx: 30,
        total: 30,
    });
    assert(hourly.series.slice(1, 23).every(point => point.total === 0), 'missing hours are zero-filled');
    assert.deepStrictEqual(hourly.nodes, [
        { nodeId: 'node-a', nodeName: 'Alpha renamed', nodeType: 'xray', tx: 10, rx: 50, total: 60 },
        { nodeId: 'node-b', nodeName: 'Beta', nodeType: 'hysteria', tx: 5, rx: 0, total: 5 },
    ]);
    assert.deepStrictEqual(harness.state.findCalls[0], {
        filter: {
            userId: 'alice',
            ts: {
                $gte: new Date('2026-08-09T16:00:00.000Z'),
                $lt: new Date('2026-08-10T16:00:00.000Z'),
            },
        },
        sort: { ts: 1 },
    });

    harness.state.rows = [
        { nodeId: 'node-a', nodeName: 'Alpha', nodeType: 'xray', ts: new Date('2026-08-04T01:00:00Z'), tx: 1, rx: 2 },
        { nodeId: 'node-b', nodeName: 'Beta', nodeType: 'hysteria', ts: new Date('2026-08-04T23:00:00Z'), tx: 3, rx: 4 },
        { nodeId: 'node-a', nodeName: 'Alpha', nodeType: 'xray', ts: new Date('2026-08-10T09:00:00Z'), tx: 5, rx: 6 },
    ];
    const weekly = await service.getUserTrafficHistory('alice', '7d', { now });
    assertWindow(weekly, {
        userId: 'alice',
        range: '7d',
        granularity: 'day',
        from: '2026-08-04T00:00:00.000Z',
        to: '2026-08-11T00:00:00.000Z',
        points: 7,
    });
    assert.deepStrictEqual(weekly.totals, { tx: 9, rx: 12, total: 21 });
    assert.deepStrictEqual(weekly.series[0], {
        ts: new Date('2026-08-04T00:00:00.000Z'), tx: 4, rx: 6, total: 10,
    });
    assert.deepStrictEqual(weekly.series[6], {
        ts: new Date('2026-08-10T00:00:00.000Z'), tx: 5, rx: 6, total: 11,
    });

    harness.state.rows = [
        { nodeId: 'node-a', nodeName: 'Alpha', nodeType: 'xray', ts: new Date('2026-07-12T03:00:00Z'), tx: 7, rx: 8 },
        { nodeId: 'node-a', nodeName: 'Alpha', nodeType: 'xray', ts: new Date('2026-08-10T09:00:00Z'), tx: 9, rx: 10 },
    ];
    const monthly = await service.getUserTrafficHistory('alice', '30d', { now });
    assertWindow(monthly, {
        userId: 'alice',
        range: '30d',
        granularity: 'day',
        from: '2026-07-12T00:00:00.000Z',
        to: '2026-08-11T00:00:00.000Z',
        points: 30,
    });
    assert.deepStrictEqual(monthly.totals, { tx: 16, rx: 18, total: 34 });
    assert.strictEqual(monthly.series[0].total, 15);
    assert.strictEqual(monthly.series[29].total, 19);

    const findCount = harness.state.findCalls.length;
    await assert.rejects(
        service.getUserTrafficHistory('alice', 'forever', { now }),
        error => error instanceof RangeError && error.code === 'INVALID_TRAFFIC_HISTORY_RANGE'
    );
    assert.strictEqual(harness.state.findCalls.length, findCount, 'invalid ranges fail before querying MongoDB');
}

function testModelAndIntegrationContracts() {
    const UserTrafficHourly = require('../src/models/userTrafficHourlyModel');
    const indexes = UserTrafficHourly.schema.indexes();
    const hasIndex = (keys, optionCheck = () => true) => indexes.some(([actualKeys, options]) => (
        JSON.stringify(actualKeys) === JSON.stringify(keys) && optionCheck(options)
    ));

    assert(
        hasIndex({ userId: 1, nodeId: 1, ts: 1 }, options => options.unique === true),
        'one account/node/hour tuple is uniquely upsertable'
    );
    assert(hasIndex({ userId: 1, ts: 1 }), 'account range queries have a covering index prefix');
    assert(
        hasIndex({ ts: 1 }, options => options.expireAfterSeconds >= 45 * 24 * 60 * 60),
        'hourly history is retained for at least 45 days'
    );
    assert(UserTrafficHourly.RETENTION_SECONDS >= 45 * 24 * 60 * 60);

    const syncSource = fs.readFileSync(path.join(root, 'src/services/syncService.js'), 'utf8');
    const historyWriteCount = (syncSource.match(/userTrafficHistory\.recordUserTrafficDeltas\s*\(/g) || []).length;
    assert.strictEqual(historyWriteCount, 2, 'both Xray and Hysteria collectors record account history');
    assert.match(syncSource, /deltas:\s*trafficDeltas/, 'collectors pass sanitized subscription deltas');

    const routeSource = fs.readFileSync(usersRouteFile, 'utf8');
    const historyRouteAt = routeSource.indexOf("router.get('/:userId/traffic-history'");
    const genericUserRouteAt = routeSource.indexOf("router.get('/:userId',");
    assert(historyRouteAt >= 0, 'traffic history API route exists');
    assert(genericUserRouteAt < 0 || historyRouteAt < genericUserRouteAt, 'specific history API is registered before the generic user route');
}

async function testApiRoute() {
    const originalLoad = Module._load;
    const requestedScopes = [];
    const historyCalls = [];
    const userLookups = [];
    let user = { userId: 'alice' };
    let historyError = null;

    const historyPayload = {
        userId: 'alice',
        range: '7d',
        from: '2026-08-03T15:00:00.000Z',
        to: '2026-08-10T15:00:00.000Z',
        totals: { tx: 30, rx: 70, total: 100 },
        series: [],
        nodes: [],
    };

    const routeStubs = {
        '../models/hyUserModel': {
            findOne(filter) {
                userLookups.push(clone(filter));
                return createQuery(user && filter.userId === user.userId ? user : null);
            },
        },
        '../models/hyNodeModel': {},
        '../models/userDeviceModel': {},
        '../models/serverGroupModel': {},
        '../services/cryptoService': {},
        '../services/hwidDeviceService': {},
        '../utils/logger': { debug() {}, info() {}, warn() {}, error() {} },
        '../utils/helpers': {},
        '../utils/userActivity': {},
        '../services/expireScheduler': {},
        '../services/webhookService': { EVENTS: {} },
        '../middleware/auth': {
            requireScope(scope) {
                requestedScopes.push(scope);
                return (_req, _res, next) => next();
            },
        },
        '../services/userTrafficHistoryService': {
            getRangeConfig(range) {
                if (!['24h', '7d', '30d'].includes(range)) {
                    const error = new RangeError('Invalid traffic history range');
                    error.code = 'INVALID_TRAFFIC_HISTORY_RANGE';
                    throw error;
                }
                return { range };
            },
            async getUserHistory(userId, range) {
                historyCalls.push({ userId, range });
                if (historyError) throw historyError;
                return clone({ ...historyPayload, userId, range });
            },
        },
    };
    routeStubs['../services/userTrafficHistoryService'].getUserTrafficHistory =
        routeStubs['../services/userTrafficHistoryService'].getUserHistory;

    Module._load = function patchedLoad(request, parent, isMain) {
        if (parent?.filename === usersRouteFile && Object.prototype.hasOwnProperty.call(routeStubs, request)) {
            return routeStubs[request];
        }
        return originalLoad.call(this, request, parent, isMain);
    };

    let router;
    try {
        delete require.cache[require.resolve('../src/routes/users')];
        router = require('../src/routes/users');
    } finally {
        Module._load = originalLoad;
        delete require.cache[require.resolve('../src/routes/users')];
    }

    const routePath = '/:userId/traffic-history';
    const historyLayer = router.stack.find(item => item.route?.path === routePath && item.route.methods.get);
    assert(historyLayer, `GET ${routePath} is registered`);
    assert(requestedScopes.includes('users:read'), 'traffic history API requires users:read');

    let res = await invokeRoute(router, 'get', routePath, {
        params: { userId: 'alice' },
        query: { range: '7d' },
    });
    assert.strictEqual(res.statusCode, 200);
    assert.deepStrictEqual(res.body, historyPayload);
    assert.deepStrictEqual(historyCalls, [{ userId: 'alice', range: '7d' }]);

    res = await invokeRoute(router, 'get', routePath, {
        params: { userId: 'alice' },
        query: {},
    });
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.range, '24h', 'missing range defaults to 24h');
    assert.deepStrictEqual(historyCalls[1], { userId: 'alice', range: '24h' });

    user = null;
    res = await invokeRoute(router, 'get', routePath, {
        params: { userId: 'missing' },
        query: { range: '24h' },
    });
    assert.strictEqual(res.statusCode, 404, 'unknown subscription account returns 404');
    assert.strictEqual(historyCalls.length, 2, 'unknown account does not run a history query');

    user = { userId: 'alice' };
    const lookupCount = userLookups.length;
    res = await invokeRoute(router, 'get', routePath, {
        params: { userId: 'alice' },
        query: { range: 'forever' },
    });
    assert.strictEqual(res.statusCode, 400, 'unsupported ranges are rejected');
    assert.strictEqual(historyCalls.length, 2, 'unsupported ranges fail before history lookup');
    assert.strictEqual(userLookups.length, lookupCount, 'unsupported ranges fail before account lookup');

    historyError = new Error('history backend unavailable');
    res = await invokeRoute(router, 'get', routePath, {
        params: { userId: 'alice' },
        query: { range: '30d' },
    });
    assert.strictEqual(res.statusCode, 500, 'unexpected history failures reach the API error boundary');
}

async function main() {
    assert(fs.existsSync(serviceFile), 'userTrafficHistoryService.js exists');
    const routeSource = fs.readFileSync(usersRouteFile, 'utf8');
    assert.match(routeSource, /router\.get\(['"]\/:userId\/traffic-history['"]/, 'API source exposes user traffic history');

    await testServiceWritesAndBoundaries();
    await testServiceQueries();
    testModelAndIntegrationContracts();
    await testApiRoute();

    console.log('user traffic history tests passed');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
