const assert = require('assert');

const {
    DEFAULT_SUBSCRIPTION_TITLE,
    getSubscriptionTitle,
    getSubscriptionContentDisposition,
} = require('../src/utils/subscriptionTitle');

assert.strictEqual(
    getSubscriptionTitle({ groups: [{ name: 'ashark', subscriptionTitle: '' }] }),
    DEFAULT_SUBSCRIPTION_TITLE,
    'an internal group name must not become the subscription profile title'
);
assert.strictEqual(
    getSubscriptionTitle({ groups: [{ subscriptionTitle: '  My VPN  ' }] }),
    'My VPN',
    'a group-specific profile title remains configurable'
);
assert.strictEqual(
    getSubscriptionTitle({ groups: [] }),
    DEFAULT_SUBSCRIPTION_TITLE,
    'users without a group receive the branded profile title'
);

const defaultDisposition = getSubscriptionContentDisposition(DEFAULT_SUBSCRIPTION_TITLE);
assert.match(defaultDisposition, /filename="renhedata-vpn"/);
assert.match(defaultDisposition, /filename\*=UTF-8''renhedata-vpn/);
assert(!defaultDisposition.includes('ashark'), 'download names must not use the account username');

const unicodeDisposition = getSubscriptionContentDisposition('我的 VPN\r\n配置');
assert(!/[\r\n]/.test(unicodeDisposition), 'download header must not contain line breaks');
assert.match(unicodeDisposition, /filename\*=UTF-8''/);

console.log('subscription profile title tests passed');
