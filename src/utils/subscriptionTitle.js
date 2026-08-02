/**
 * Subscription naming helpers.
 *
 * The user-facing profile name is deliberately separate from a server-group
 * name and a user name. Those are internal administration labels and should
 * not unexpectedly become the name displayed by a subscription client.
 */

const DEFAULT_SUBSCRIPTION_TITLE = 'renhedata-vpn';

/**
 * Return the profile title for a user's subscription.
 *
 * A group may opt in to a custom title through `subscriptionTitle`. When it
 * is empty, retain the product name instead of falling back to the group name.
 *
 * @param {{ groups?: Array<{ subscriptionTitle?: string }> }} user
 * @returns {string}
 */
function getSubscriptionTitle(user) {
    const title = user?.groups?.[0]?.subscriptionTitle;
    return typeof title === 'string' && title.trim()
        ? title.trim()
        : DEFAULT_SUBSCRIPTION_TITLE;
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
    getSubscriptionContentDisposition,
};
