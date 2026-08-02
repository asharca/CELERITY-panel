/**
 * Subscription naming helpers.
 *
 * The user-facing profile name is deliberately separate from a server-group
 * name and a user name. Those are internal administration labels and should
 * not unexpectedly become the name displayed by a subscription client.
 */

const DEFAULT_SUBSCRIPTION_TITLE = 'renhedata-vpn';
const CLASH_SUBSCRIPTION_FORMATS = new Set(['clash', 'yaml']);

function isClashSubscriptionFormat(format) {
    return CLASH_SUBSCRIPTION_FORMATS.has(String(format || '').toLowerCase());
}

/**
 * Return the profile title for a user's subscription.
 *
 * Clash imports always use the product name. Other subscription clients may
 * opt in to a group-specific title through `subscriptionTitle`.
 *
 * @param {{ groups?: Array<{ subscriptionTitle?: string }> }} user
 * @param {string} [format]
 * @returns {string}
 */
function getSubscriptionTitle(user, format) {
    if (isClashSubscriptionFormat(format)) return DEFAULT_SUBSCRIPTION_TITLE;

    const title = user?.groups?.[0]?.subscriptionTitle;
    return typeof title === 'string' && title.trim()
        ? title.trim()
        : DEFAULT_SUBSCRIPTION_TITLE;
}

/**
 * Resolve the title to send for an already-cached subscription response.
 * This keeps legacy cache entries from restoring an old group name in Clash.
 *
 * @param {string} profileTitle
 * @param {string} [format]
 * @returns {string}
 */
function getSubscriptionResponseTitle(profileTitle, format) {
    return isClashSubscriptionFormat(format)
        ? DEFAULT_SUBSCRIPTION_TITLE
        : String(profileTitle || DEFAULT_SUBSCRIPTION_TITLE).trim() || DEFAULT_SUBSCRIPTION_TITLE;
}

/**
 * Build a safe Content-Disposition value for subscription downloads.
 *
 * Keep an ASCII `filename` fallback for older clients and RFC 5987's
 * `filename*` for clients that support Unicode profile names.
 *
 * @param {string} profileTitle
 * @returns {string}
 */
function getSubscriptionContentDisposition(profileTitle) {
    const title = String(profileTitle || DEFAULT_SUBSCRIPTION_TITLE)
        .replace(/[\r\n]+/g, ' ')
        .trim()
        .slice(0, 120) || DEFAULT_SUBSCRIPTION_TITLE;

    const asciiFilename = title
        .normalize('NFKD')
        .replace(/[^\x20-\x7E]/g, '')
        .replace(/[^A-Za-z0-9._-]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 120) || 'renhedata-vpn';
    const encodedFilename = encodeURIComponent(title)
        .replace(/['()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

    return `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`;
}

module.exports = {
    DEFAULT_SUBSCRIPTION_TITLE,
    getSubscriptionTitle,
    getSubscriptionResponseTitle,
    getSubscriptionContentDisposition,
};
