/**
 * Normalize the optional Hysteria port-hopping range.
 * An empty value explicitly disables port hopping.
 */
function normalizePortRange(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function parsePortRange(value) {
    const normalized = normalizePortRange(value);
    const match = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(normalized);
    if (!match) return null;

    const start = Number(match[1]);
    const end = Number(match[2]);
    if (start < 1 || end > 65535 || start > end) return null;

    return { start, end, normalized: `${start}-${end}` };
}

function canonicalizePortRange(value) {
    if (value !== undefined && value !== null && typeof value !== 'string') {
        throw new RangeError('portRange must be a string in start-end format');
    }
    const normalized = normalizePortRange(value);
    if (!normalized) return '';

    const parsed = parsePortRange(normalized);
    if (!parsed) {
        throw new RangeError('portRange must use start-end with ports between 1 and 65535');
    }
    return parsed.normalized;
}

function cleanupCommands({ start, end }, mainPort, { access = true, redirect = true } = {}) {
    const accessCommands = access ? `
while iptables -D INPUT -p udp --dport ${start}:${end} -j ACCEPT 2>/dev/null; do :; done
while ip6tables -D INPUT -p udp --dport ${start}:${end} -j ACCEPT 2>/dev/null; do :; done

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw --force delete allow ${start}:${end}/udp >/dev/null 2>&1 || exit 1
fi` : '';

    const redirectCommands = redirect ? `
while iptables -t nat -D PREROUTING -p udp --dport ${start}:${end} -j REDIRECT --to-port ${mainPort} 2>/dev/null; do :; done
while ip6tables -t nat -D PREROUTING -p udp --dport ${start}:${end} -j REDIRECT --to-port ${mainPort} 2>/dev/null; do :; done

for iface in eth0 eth1 ens3 ens5 enp0s3 eno1; do
    while iptables -t nat -D PREROUTING -i $iface -p udp --dport ${start}:${end} -j REDIRECT --to-port ${mainPort} 2>/dev/null; do :; done
    while ip6tables -t nat -D PREROUTING -i $iface -p udp --dport ${start}:${end} -j REDIRECT --to-port ${mainPort} 2>/dev/null; do :; done
done` : '';

    if (!accessCommands && !redirectCommands) return '';
    return `
# Remove superseded hopping rules only after the desired rules are ready.
${accessCommands}
${redirectCommands}`;
}

function configureMainPortCommands(mainPort) {
    return `
# Open the current service port for TCP and Hysteria's UDP transport.
for proto in tcp udp; do
    iptables -C INPUT -p $proto --dport ${mainPort} -j ACCEPT 2>/dev/null || iptables -I INPUT -p $proto --dport ${mainPort} -j ACCEPT || exit 1
    ip6tables -C INPUT -p $proto --dport ${mainPort} -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p $proto --dport ${mainPort} -j ACCEPT 2>/dev/null || true
done

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow ${mainPort}/tcp >/dev/null 2>&1 || exit 1
    ufw allow ${mainPort}/udp >/dev/null 2>&1 || exit 1
fi`;
}

/**
 * Build an idempotent transition from a previous hopping range to a desired
 * range. Empty desiredRange means cleanup-only (port hopping disabled).
 */
function buildPortHoppingReconcileScript({
    desiredRange,
    previousRange,
    mainPort,
    previousMainPort = mainPort,
    previousMainPortEnabled = true,
    desiredMainPortEnabled = true,
}) {
    const desiredRaw = normalizePortRange(desiredRange);
    const previousRaw = normalizePortRange(previousRange);
    const desired = desiredRaw ? parsePortRange(desiredRaw) : null;
    const previous = previousRaw ? parsePortRange(previousRaw) : null;
    const port = Number(mainPort);
    const oldPort = Number(previousMainPort);

    if (desiredRaw && !desired) throw new Error('Invalid port hopping range');
    if (previousRaw && !previous) throw new Error('Invalid previous port hopping range');
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Invalid Hysteria main port');
    }
    if (!Number.isInteger(oldPort) || oldPort < 1 || oldPort > 65535) {
        throw new Error('Invalid previous Hysteria main port');
    }
    // Old main-port rules may be shared with another service (commonly 443),
    // so only ensure the new Hysteria port is open; never delete unowned rules.
    const shouldConfigureMainPort = desiredMainPortEnabled
        && (!previousMainPortEnabled || oldPort !== port);
    if (!desired && !previous && !shouldConfigureMainPort) return '';

    const sameRange = !!previous && !!desired && previous.normalized === desired.normalized;
    const sameRedirect = sameRange && oldPort === port;
    const cleanup = previous
        ? cleanupCommands(previous, oldPort, {
            access: !sameRange,
            redirect: !sameRedirect,
        })
        : '';

    const configureMainPort = shouldConfigureMainPort
        ? configureMainPortCommands(port)
        : '';

    const configure = desired ? `
# Configure the desired hopping range.
iptables -C INPUT -p udp --dport ${desired.start}:${desired.end} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${desired.start}:${desired.end} -j ACCEPT || exit 1
ip6tables -C INPUT -p udp --dport ${desired.start}:${desired.end} -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport ${desired.start}:${desired.end} -j ACCEPT 2>/dev/null || true
iptables -t nat -C PREROUTING -p udp --dport ${desired.start}:${desired.end} -j REDIRECT --to-port ${port} 2>/dev/null || iptables -t nat -A PREROUTING -p udp --dport ${desired.start}:${desired.end} -j REDIRECT --to-port ${port} || exit 1
ip6tables -t nat -C PREROUTING -p udp --dport ${desired.start}:${desired.end} -j REDIRECT --to-port ${port} 2>/dev/null || ip6tables -t nat -A PREROUTING -p udp --dport ${desired.start}:${desired.end} -j REDIRECT --to-port ${port} 2>/dev/null || true

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow ${desired.start}:${desired.end}/udp >/dev/null 2>&1 || exit 1
fi` : '';

    let result;
    if (desired) {
        result = `Port hopping configured: ${desired.normalized} -> ${port}`;
    } else if (previous) {
        result = `Port hopping disabled: removed ${previous.normalized}`;
    } else if (desiredMainPortEnabled) {
        result = `Service port migrated: ${oldPort} -> ${port}`;
    } else {
        result = `Service port closed: ${oldPort}`;
    }

    return `command -v iptables >/dev/null 2>&1 || { echo "iptables is required" >&2; exit 1; }
iptables -L INPUT >/dev/null 2>&1 || { echo "iptables is not accessible" >&2; exit 1; }

${configureMainPort}
${configure}
${cleanup}

# Persist the reconciled firewall state when netfilter-persistent is available.
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || exit 1
elif command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables || exit 1
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || exit 1
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || exit 1
    fi
fi

echo "${result}"`;
}

module.exports = {
    normalizePortRange,
    parsePortRange,
    canonicalizePortRange,
    buildPortHoppingReconcileScript,
};
