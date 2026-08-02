const assert = require('assert');

const {
    DEFAULT_SUBSCRIPTION_TITLE,
    getSubscriptionTitle,
    getSubscriptionResponseTitle,
    getSubscriptionContentDisposition,
} = require('../src/utils/subscriptionTitle');

assert.strictEqual(
    getSubscriptionTitle({ groups: [{ name: 'ashark', subscriptionTitle: '' }] }),
    DEFAULT_SUBSCRIPTION_TITLE,
    'an internal group name must not become the subscription profile title'
);
assert.strictEqual(
    getSubscriptionTitle({ groups: [{ subscriptionTitle: '备用节点-电信线路' }] }, 'clash'),
    DEFAULT_SUBSCRIPTION_TITLE,
    'a group-specific title must not override the Clash import name'
);
assert.strictEqual(
    getSubscriptionTitle({ groups: [{ subscriptionTitle: '  My VPN  ' }] }, 'uri'),
    'My VPN',
    'a group-specific title remains available to non-Clash clients'
);
assert.strictEqual(
    getSubscriptionTitle({ groups: [] }),
    DEFAULT_SUBSCRIPTION_TITLE,
    'users without a group receive the branded profile title'
);
assert.strictEqual(
    getSubscriptionResponseTitle('备用节点-电信线路', 'clash'),
    DEFAULT_SUBSCRIPTION_TITLE,
    'a cached Clash subscription must not restore a legacy group title'
);

const defaultDisposition = getSubscriptionContentDisposition(DEFAULT_SUBSCRIPTION_TITLE);
assert.match(defaultDisposition, /filename="renhedata-vpn"/);
assert.match(defaultDisposition, /filename\*=UTF-8''renhedata-vpn/);
assert(!defaultDisposition.includes('ashark'), 'download names must not use the account username');

const unicodeDisposition = getSubscriptionContentDisposition('我的 VPN\r\n配置');
assert(!/[\r\n]/.test(unicodeDisposition), 'download header must not contain line breaks');
assert.match(unicodeDisposition, /filename\*=UTF-8''/);

console.log('subscription profile title tests passed');
