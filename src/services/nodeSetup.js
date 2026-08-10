/**
 * Hysteria node auto-setup service via SSH
 */

const { Client } = require('ssh2');
const fs = require('fs');
const net = require('net');
const path = require('path');
const logger = require('../utils/logger');
const config = require('../../config');
const cryptoService = require('./cryptoService');
const Settings = require('../models/settingsModel');
const configGenerator = require('./configGenerator');
const { parsePortRange, buildPortHoppingReconcileScript } = require('../utils/portRange');

/**
 * Check if a node is on the same VPS as the panel
 * Uses domain, localhost, and configured panel-IP matching heuristics.
 * @param {Object} node - Node object with ip and domain fields
 * @returns {boolean} true if node appears to be on the same server as the panel
 */
function isSameVpsAsPanel(node) {
    const normalizeHost = value => String(value || '').trim().toLowerCase().replace(/\.$/, '');
    const panelDomain = normalizeHost(config.PANEL_DOMAIN);
    
    // 1. Domain match - most reliable indicator
    const nodeDomain = normalizeHost(node.domain);
    if (nodeDomain && nodeDomain === panelDomain) {
        logger.debug(`[NodeSetup] Same VPS detected: domain match (${node.domain})`);
        return true;
    }
    
    // 2. Localhost / loopback detection
    const nodeIp = normalizeHost(node.ip);
    if (panelDomain && nodeIp === panelDomain) {
        logger.debug(`[NodeSetup] Same VPS detected: node IP/host matches panel domain (${nodeIp})`);
        return true;
    }
    if (nodeIp === 'localhost' || nodeIp === '127.0.0.1' || nodeIp === '::1') {
        logger.debug(`[NodeSetup] Same VPS detected: localhost IP (${nodeIp})`);
        return true;
    }
    
    // 3. Compare against explicitly configured host addresses. Multiple
    // IPv4/IPv6 values can be comma-separated for multi-homed deployments.
    const panelIps = String(process.env.PANEL_IP || '')
        .split(',')
        .map(normalizeHost)
        .filter(Boolean);
    if (nodeIp && panelIps.includes(nodeIp)) {
        logger.debug(`[NodeSetup] Same VPS detected: IP match via PANEL_IP env (${nodeIp})`);
        return true;
    }
    
    return false;
}

// Accept only an IP[/CIDR] or a conservative DNS hostname before placing a
// panel source in root-owned firewall commands. This is defense in depth on top
// of shell quoting: PANEL_IP is operator input and must never become shell code.
function normalizeFirewallSource(value) {
    let candidate = String(value || '').split(',')[0].trim();
    if (!candidate) return '';

    if (/^https?:\/\//i.test(candidate)) {
        try {
            candidate = new URL(candidate).hostname;
        } catch (_) {
            return '';
        }
    }
    const bracketed = /^\[([^\]]+)\](?:\/(\d{1,3}))?$/.exec(candidate);
    if (bracketed) candidate = bracketed[1] + (bracketed[2] ? `/${bracketed[2]}` : '');

    const slash = candidate.lastIndexOf('/');
    const host = slash === -1 ? candidate : candidate.slice(0, slash);
    const prefixText = slash === -1 ? '' : candidate.slice(slash + 1);
    const ipVersion = net.isIP(host);
    if (ipVersion) {
        if (!prefixText) return host;
        if (!/^\d{1,3}$/.test(prefixText)) return '';
        const prefix = Number(prefixText);
        const maxPrefix = ipVersion === 4 ? 32 : 128;
        return prefix <= maxPrefix ? `${host}/${prefix}` : '';
    }
    if (prefixText) return '';

    const hostname = host.replace(/\.$/, '');
    if (hostname.length > 253) return '';
    const labels = hostname.split('.');
    if (!labels.every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) {
        return '';
    }
    return hostname;
}

function resolvePanelFirewallSource() {
    const explicit = normalizeFirewallSource(process.env.PANEL_IP || '');
    if (explicit) return explicit;
    return normalizeFirewallSource(config.BASE_URL || '');
}

function shellSingleQuote(value) {
    return "'" + String(value || '').replace(/'/g, "'\\''") + "'";
}

// cc-agent uses one canonical config/service path per host. Serialize all
// panel-side mutations by host (not node id) so two protocol records sharing a
// VPS cannot both observe an empty config and then overwrite each other.
const ccAgentHostQueues = new Map();
function ccAgentHostKey(node) {
    const host = String(node?.ip || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
    return host || `node:${String(node?._id || node?.id || 'unknown')}`;
}

function enqueueCcAgentHostTask(node, task) {
    const key = ccAgentHostKey(node);
    const previous = ccAgentHostQueues.get(key) || Promise.resolve();
    const current = previous.catch(() => {}).then(task);
    ccAgentHostQueues.set(key, current);
    const cleanup = () => {
        if (ccAgentHostQueues.get(key) === current) ccAgentHostQueues.delete(key);
    };
    current.then(cleanup, cleanup);
    return current;
}

/**
 * Read panel's SSL certificates from Greenlock or Caddy directory
 * @param {string} domain - Panel domain
 * @returns {Object|null} { cert, key } or null if not found
 */
function getPanelCertificates(domain) {
    try {
        let cert, key;
        
        // Try Caddy certificates first (when USE_CADDY=true)
        // Caddy stores certs in /caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/{domain}/
        const caddyDir = path.join('/caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory', domain);
        const caddyCertPath = path.join(caddyDir, `${domain}.crt`);
        const caddyKeyPath = path.join(caddyDir, `${domain}.key`);
        
        if (fs.existsSync(caddyCertPath) && fs.existsSync(caddyKeyPath)) {
            cert = fs.readFileSync(caddyCertPath, 'utf8');
            key = fs.readFileSync(caddyKeyPath, 'utf8');
            logger.info(`[NodeSetup] Found Caddy certificates for ${domain}`);
            return { cert, key };
        }
        
        // Try Greenlock certificates (when USE_CADDY is not set)
        // Greenlock stores certs in greenlock.d/live/{domain}/:
        //   - cert.pem      : leaf certificate only (1 BEGIN CERTIFICATE)
        //   - fullchain.pem : leaf + intermediates (the bundle TLS servers must serve)
        //   - privkey.pem   : private key
        // We MUST prefer fullchain.pem; otherwise Hysteria serves an incomplete TLS
        // chain and strict clients (insecure=false) fail with x509: certificate
        // signed by unknown authority. See issue #63.
        const greenlockDir = path.join(__dirname, '../../greenlock.d/live', domain);
        const certPath = path.join(greenlockDir, 'cert.pem');
        const keyPath = path.join(greenlockDir, 'privkey.pem');
        const fullchainPath = path.join(greenlockDir, 'fullchain.pem');
        
        if (fs.existsSync(fullchainPath)) {
            cert = fs.readFileSync(fullchainPath, 'utf8');
            logger.info(`[NodeSetup] Using Greenlock fullchain.pem for ${domain}`);
        } else if (fs.existsSync(certPath)) {
            cert = fs.readFileSync(certPath, 'utf8');
            logger.warn(`[NodeSetup] fullchain.pem missing for ${domain}, falling back to cert.pem (TLS chain may be incomplete)`);
        }
        
        if (fs.existsSync(keyPath)) {
            key = fs.readFileSync(keyPath, 'utf8');
        }
        
        if (cert && key) {
            logger.info(`[NodeSetup] Found Greenlock certificates for ${domain}`);
            return { cert, key };
        }
        
        logger.warn(`[NodeSetup] Panel certificates not found (checked Caddy: ${caddyDir}, Greenlock: ${greenlockDir})`);
        return null;
        
    } catch (error) {
        logger.error(`[NodeSetup] Error reading panel certificates: ${error.message}`);
        return null;
    }
}

// Reusable shell snippet: persist iptables rules across reboots
const IPTABLES_SAVE_SNIPPET = `
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save 2>/dev/null
    echo "Done: Rules saved with netfilter-persistent"
elif [ -f /etc/debian_version ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y netfilter-persistent iptables-persistent 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || true
elif command -v iptables-save &> /dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    echo "Done: Rules saved with iptables-save"
fi`;

const INSTALL_SCRIPT = `#!/bin/bash
set -e

echo "=== [0/5] System diagnostics ==="
echo "--- OS info ---"
cat /etc/os-release 2>/dev/null | grep -E "^(NAME|VERSION|ID)=" || echo "(os-release not found)"
uname -a 2>/dev/null || true
echo "--- Disk space ---"
df -h / 2>/dev/null || true
echo "--- Memory ---"
free -h 2>/dev/null || true
echo "--- Network interfaces ---"
ip addr show 2>/dev/null | grep -E "^[0-9]+:|inet " || ifconfig 2>/dev/null | grep -E "^[a-z]|inet " || true
echo "--- Checking required tools ---"

MISSING_TOOLS=""

if command -v curl &> /dev/null; then
    echo "OK: curl $(curl --version 2>&1 | head -1)"
else
    echo "MISSING: curl is not installed — trying to install..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y curl
        if command -v curl &> /dev/null; then
            echo "Done: curl installed via apt-get"
        else
            echo "ERROR: Failed to install curl via apt-get"
            MISSING_TOOLS="$MISSING_TOOLS curl"
        fi
    elif command -v yum &> /dev/null; then
        yum install -y curl
        if command -v curl &> /dev/null; then
            echo "Done: curl installed via yum"
        else
            echo "ERROR: Failed to install curl via yum"
            MISSING_TOOLS="$MISSING_TOOLS curl"
        fi
    elif command -v dnf &> /dev/null; then
        dnf install -y curl
        if command -v curl &> /dev/null; then
            echo "Done: curl installed via dnf"
        else
            echo "ERROR: Failed to install curl via dnf"
            MISSING_TOOLS="$MISSING_TOOLS curl"
        fi
    else
        echo "ERROR: No package manager found (apt-get/yum/dnf). Cannot install curl."
        MISSING_TOOLS="$MISSING_TOOLS curl"
    fi
fi

if command -v bash &> /dev/null; then
    echo "OK: bash $(bash --version 2>&1 | head -1)"
else
    echo "ERROR: bash is not available — this is very unusual"
    MISSING_TOOLS="$MISSING_TOOLS bash"
fi

if command -v systemctl &> /dev/null; then
    echo "OK: systemctl available ($(systemctl --version 2>&1 | head -1))"
else
    echo "WARNING: systemctl not found — service management may fail"
fi

if command -v openssl &> /dev/null; then
    echo "OK: openssl $(openssl version 2>&1)"
else
    echo "WARNING: openssl not installed (needed for self-signed cert)"
fi

if [ -n "$MISSING_TOOLS" ]; then
    echo "ERROR: Required tools are missing:$MISSING_TOOLS"
    echo "Cannot continue setup. Please install missing tools and try again."
    exit 1
fi

echo "--- Checking connectivity ---"
if curl -s --max-time 5 https://get.hy2.sh/ -o /dev/null -w "HTTPS connectivity: HTTP %{http_code}\\n"; then
    echo "OK: HTTPS connectivity confirmed"
else
    echo "WARNING: Could not reach get.hy2.sh — internet access may be limited"
fi

echo "=== [1/5] Checking Hysteria installation ==="

if ! command -v hysteria &> /dev/null; then
    echo "Hysteria not found. Installing..."
    echo "Running: bash <(curl -fsSL https://get.hy2.sh/)"
    INSTALL_EXIT=0
    bash <(curl -fsSL https://get.hy2.sh/) || INSTALL_EXIT=$?
    if [ "$INSTALL_EXIT" -ne 0 ]; then
        echo "WARNING: Install script exited with code $INSTALL_EXIT"
    fi
    if command -v hysteria &> /dev/null; then
        echo "Done: Hysteria installed successfully"
    else
        echo "ERROR: Hysteria binary not found after installation script"
        echo "Install script exit code: $INSTALL_EXIT"
        echo "Checking common paths:"
        ls -la /usr/local/bin/hysteria 2>/dev/null || echo "  /usr/local/bin/hysteria — not found"
        ls -la /usr/bin/hysteria 2>/dev/null || echo "  /usr/bin/hysteria — not found"
        echo "Checking PATH:"
        echo "  PATH=$PATH"
        which hysteria 2>/dev/null || echo "  which hysteria — not found"
        exit 1
    fi
else
    echo "Done: Hysteria already installed"
fi

mkdir -p /etc/hysteria
echo "Done: Directory /etc/hysteria ready"

echo "Hysteria version:"
hysteria version
`;

function getPortHoppingScript(portRange, mainPort) {
    const parsedRange = parsePortRange(portRange);
    if (!parsedRange) return '';

    return buildPortHoppingReconcileScript({
        desiredRange: parsedRange.normalized,
        previousRange: parsedRange.normalized,
        mainPort,
        previousMainPortEnabled: false,
        desiredMainPortEnabled: true,
    });
}

const SELF_SIGNED_CERT_SCRIPT = `
echo "=== [2/5] Generating self-signed certificate ==="

if ! command -v openssl &> /dev/null; then
    echo "Installing openssl..."
    apt-get update && apt-get install -y openssl
fi

echo "Checking existing certificates..."
ls -la /etc/hysteria/*.pem 2>/dev/null || echo "No existing cert files"

CERT_VALID=0
if [ -f /etc/hysteria/cert.pem ] && [ -s /etc/hysteria/cert.pem ] && [ -f /etc/hysteria/key.pem ] && [ -s /etc/hysteria/key.pem ]; then
    if openssl x509 -in /etc/hysteria/cert.pem -noout 2>/dev/null; then
        echo "Done: Valid certificate already exists"
        CERT_VALID=1
        openssl x509 -in /etc/hysteria/cert.pem -noout -subject -dates
    else
        echo "Warning: Certificate file exists but is invalid, regenerating..."
    fi
fi

if [ "$CERT_VALID" = "0" ]; then
    echo "Generating new certificate..."
    
    rm -f /etc/hysteria/cert.pem /etc/hysteria/key.pem /tmp/ecparam.pem
    mkdir -p /etc/hysteria
    
    echo "Step 1: Generating EC parameters..."
    openssl ecparam -name prime256v1 -out /tmp/ecparam.pem
    if [ ! -f /tmp/ecparam.pem ]; then
        echo "Error: Failed to create EC parameters"
        exit 1
    fi
    echo "Done: EC parameters created"
    
    echo "Step 2: Generating certificate..."
    openssl req -x509 -nodes -newkey ec:/tmp/ecparam.pem \\
        -keyout /etc/hysteria/key.pem \\
        -out /etc/hysteria/cert.pem \\
        -subj "/CN=bing.com" \\
        -days 36500 2>&1
    
    if [ ! -f /etc/hysteria/cert.pem ] || [ ! -s /etc/hysteria/cert.pem ]; then
        echo "Error: Certificate file not created or empty!"
        echo "Trying alternative method with RSA..."
        
        openssl req -x509 -nodes -newkey rsa:2048 \\
            -keyout /etc/hysteria/key.pem \\
            -out /etc/hysteria/cert.pem \\
            -subj "/CN=bing.com" \\
            -days 36500 2>&1
    fi
    
    if [ ! -f /etc/hysteria/key.pem ] || [ ! -s /etc/hysteria/key.pem ]; then
        echo "Error: Key file not created or empty!"
        exit 1
    fi
    
    # Set correct ownership for hysteria user (if exists)
    if id "hysteria" &>/dev/null; then
        chown hysteria:hysteria /etc/hysteria/key.pem /etc/hysteria/cert.pem
        echo "Done: Ownership set to hysteria:hysteria"
    fi
    chmod 600 /etc/hysteria/key.pem
    chmod 644 /etc/hysteria/cert.pem
    rm -f /tmp/ecparam.pem
    
    echo "Step 3: Verifying certificate..."
    if openssl x509 -in /etc/hysteria/cert.pem -noout 2>/dev/null; then
        echo "Done: Certificate generated successfully!"
        openssl x509 -in /etc/hysteria/cert.pem -noout -subject -dates
        ls -la /etc/hysteria/*.pem
    else
        echo "Error: Certificate verification failed!"
        cat /etc/hysteria/cert.pem
        exit 1
    fi
fi
`;

function connectSSH(node) {
    return new Promise((resolve, reject) => {
        const conn = new Client();
        
        const connConfig = {
            host: node.ip,
            port: node.ssh?.port || 22,
            username: node.ssh?.username || 'root',
            readyTimeout: 30000,
        };
        
        if (node.ssh?.privateKey) {
            connConfig.privateKey = cryptoService.decryptPrivateKey(node.ssh.privateKey);
        } else if (node.ssh?.password) {
            connConfig.password = cryptoService.decryptSafe(node.ssh.password);
        } else {
            return reject(new Error('SSH credentials not provided'));
        }
        
        conn.on('ready', () => resolve(conn));
        conn.on('error', (err) => reject(err));
        conn.connect(connConfig);
    });
}

function execSSH(conn, command, options = {}) {
    return new Promise((resolve, reject) => {
        const timeoutMs = Math.max(10, Number(options.timeoutMs) || 120000);
        const maxOutputBytes = Math.max(1024, Number(options.maxOutputBytes) || (4 * 1024 * 1024));
        let stdout = '';
        let stderr = '';
        let outputBytes = 0;
        let stream = null;
        let settled = false;

        const finish = result => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(result);
        };
        const failSetup = error => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            reject(error);
        };
        const timer = setTimeout(() => {
            const output = stdout + (stderr ? '\n[STDERR]:\n' + stderr : '');
            finish({ success: false, output, code: null, error: `SSH command timed out after ${timeoutMs}ms` });
            try { stream?.close(); } catch (_) { /* best effort */ }
        }, timeoutMs);

        const append = (data, isStderr) => {
            if (settled) return;
            const chunk = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
            outputBytes += chunk.length;
            if (outputBytes > maxOutputBytes) {
                const output = stdout + (stderr ? '\n[STDERR]:\n' + stderr : '');
                finish({
                    success: false,
                    output,
                    code: null,
                    error: `SSH command output exceeded ${maxOutputBytes} bytes`,
                });
                try { stream?.close(); } catch (_) { /* best effort */ }
                return;
            }
            if (isStderr) stderr += chunk.toString();
            else stdout += chunk.toString();
        };

        try {
            conn.exec(command, (err, openedStream) => {
                if (err) return failSetup(err);
                if (settled) {
                    try { openedStream?.close(); } catch (_) { /* best effort */ }
                    return;
                }
                stream = openedStream;
                stream.on('close', code => {
                    const output = stdout + (stderr ? '\n[STDERR]:\n' + stderr : '');
                    if (code === 0) finish({ success: true, output, code });
                    else finish({ success: false, output, code, error: `Exit code: ${code}` });
                });
                stream.on('data', data => append(data, false));
                stream.stderr.on('data', data => append(data, true));
                stream.on('error', failSetup);
            });
        } catch (error) {
            failSetup(error);
        }
    });
}

function resolveNodeServiceCandidates(node) {
    if (!node || node.type === 'virtual') return [];
    if (node.type === 'xray') return ['xray'];
    return ['hysteria-server', 'hysteria'];
}

function hasSshCredentials(node) {
    return !!(node?.ssh?.password || node?.ssh?.privateKey);
}

function serviceExistsCommand(serviceName) {
    return `systemctl list-unit-files ${serviceName}.service --no-legend 2>/dev/null | grep -q . || systemctl status ${serviceName} >/dev/null 2>&1`;
}

async function runRuntimeServiceCommand(node, action, buildCommand) {
    const candidates = resolveNodeServiceCandidates(node);
    if (candidates.length === 0) {
        return { success: true, attempted: false, reason: 'virtual node' };
    }

    if (!hasSshCredentials(node)) {
        return { success: false, attempted: false, reason: 'SSH credentials not configured' };
    }

    let conn;
    const failures = [];
    try {
        conn = await connectSSH(node);

        for (const service of candidates) {
            const command = buildCommand(service);
            const result = await execSSH(conn, command);
            const output = (result.output || '').trim();
            const missing = result.code === 3 || output.includes(`SERVICE_MISSING ${service}`);

            if (missing && candidates.length > 1) {
                failures.push({ service, output, error: 'Service not found' });
                continue;
            }

            if (result.success) {
                return { success: true, attempted: true, action, service, output };
            }

            failures.push({
                service,
                output,
                error: result.error || `${action} failed`,
            });
        }
    } catch (error) {
        failures.push({ error: error.message });
    } finally {
        if (conn) conn.end();
    }

    const last = failures[failures.length - 1] || {};
    return {
        success: false,
        attempted: true,
        action,
        service: last.service || candidates[candidates.length - 1],
        output: last.output || '',
        error: last.error || `${action} failed`,
        failures,
    };
}

async function stopNodeRuntime(node) {
    return runRuntimeServiceCommand(node, 'stop', service => `
${serviceExistsCommand(service)} || { echo "SERVICE_MISSING ${service}"; exit 3; }
systemctl stop ${service} 2>&1 || true
systemctl disable ${service} 2>&1 || true
sleep 1
STATE="$(systemctl is-active ${service} 2>/dev/null || true)"
echo "STATE:$STATE"
[ "$STATE" != "active" ]
`);
}

async function startNodeRuntime(node) {
    return runRuntimeServiceCommand(node, 'start', service => `
${serviceExistsCommand(service)} || { echo "SERVICE_MISSING ${service}"; exit 3; }
systemctl daemon-reload 2>&1 || true
systemctl enable ${service} 2>&1
systemctl restart ${service} 2>&1
sleep 2
STATE="$(systemctl is-active ${service} 2>/dev/null || true)"
echo "STATE:$STATE"
[ "$STATE" = "active" ]
`);
}

function uploadFile(conn, content, remotePath, options = {}) {
    return new Promise((resolve, reject) => {
        const timeoutMs = Math.max(10, Number(options.timeoutMs) || 60000);
        let settled = false;
        let writeStream = null;
        const finish = error => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (error) reject(error);
            else resolve();
        };
        const timer = setTimeout(() => {
            try { writeStream?.destroy(); } catch (_) { /* best effort */ }
            finish(new Error(`SFTP upload timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        conn.sftp((err, sftp) => {
            if (err) return finish(err);
            if (settled) return;
            
            writeStream = sftp.createWriteStream(remotePath);
            writeStream.on('close', () => finish());
            writeStream.on('error', finish);
            writeStream.write(content);
            writeStream.end();
        });
    });
}

// Read a small remote file without sending its contents through a shell or
// command output. This is used for ownership checks on credential-bearing
// config files, so their tokens never appear in logs.
function readRemoteFileIfExists(conn, remotePath, maxBytes = 1024 * 1024, options = {}) {
    return new Promise((resolve, reject) => {
        const timeoutMs = Math.max(10, Number(options.timeoutMs) || 30000);
        let settled = false;
        let readStream = null;
        const finish = (error, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (error) reject(error);
            else resolve(value);
        };
        const timer = setTimeout(() => {
            try { readStream?.destroy(); } catch (_) { /* best effort */ }
            finish(new Error(`SFTP read timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        conn.sftp((sftpError, sftp) => {
            if (sftpError) return finish(sftpError);
            if (settled) return;
            sftp.stat(remotePath, (statError, stats) => {
                if (statError) {
                    if (statError.code === 2 || /no such file/i.test(statError.message || '')) {
                        return finish(null, null);
                    }
                    return finish(statError);
                }
                if (!stats || stats.size > maxBytes) {
                    return finish(new Error(`Remote file ${remotePath} exceeds the safety limit`));
                }

                const chunks = [];
                let total = 0;
                readStream = sftp.createReadStream(remotePath);
                readStream.on('data', chunk => {
                    total += chunk.length;
                    if (total > maxBytes) {
                        readStream.destroy(new Error(`Remote file ${remotePath} exceeds the safety limit`));
                        return;
                    }
                    chunks.push(Buffer.from(chunk));
                });
                readStream.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
                readStream.on('error', finish);
            });
        });
    });
}

// A host has one canonical cc-agent service/config path. Refuse to overwrite a
// config carrying another node's token: otherwise enabling HY2 logs on a host
// that also runs an Xray agent would silently switch that agent into
// Hysteria-only mode and break Xray sync/stats.
function assertCcAgentConfigContentOwnership(content, expectedToken) {
    if (content === null) return;

    let current;
    try {
        current = JSON.parse(content);
    } catch (_) {
        throw new Error('Existing cc-agent config is not valid JSON; refusing to overwrite it');
    }
    if (!current.token || current.token !== expectedToken) {
        throw new Error('Existing cc-agent config belongs to another node or proxy service; shared-host collection requires a separate agent instance');
    }
}

async function assertCcAgentConfigOwnership(conn, expectedToken) {
    const content = await readRemoteFileIfExists(conn, '/etc/cc-agent/config.json');
    assertCcAgentConfigContentOwnership(content, expectedToken);
}

async function assertNodeSshCcAgentConfigOwnership(ssh, expectedToken) {
    let content;
    try {
        content = await ssh.readFile('/etc/cc-agent/config.json');
    } catch (error) {
        if (error?.code === 2 || /no such file/i.test(error?.message || '')) return;
        throw error;
    }
    assertCcAgentConfigContentOwnership(content, expectedToken);
}

/**
 * Execute a user-defined init script on the remote node via SSH.
 * Non-fatal: failures are logged but do not abort the main setup.
 * Injects NODE_IP, NODE_NAME, NODE_TYPE, NODE_DOMAIN as env variables.
 *
 * @param {Object} conn - Active SSH connection
 * @param {Object} node - Node document
 * @param {Function} log - Logging function from the parent setup context
 * @param {Array} logs - Log accumulator from the parent setup context
 */
async function runInitScript(conn, node, log, logs) {
    const script = (node.initScript || '').trim();
    if (!script) return;

    log('=== Running user init script ===');

    // Single-quote escaping for bash: replace ' with '\'' (end quote, escaped quote, start quote)
    const sq = (v) => "'" + String(v || '').replace(/'/g, "'\\''") + "'";

    const envPrefix = [
        `export NODE_IP=${sq(node.ip)}`,
        `export NODE_NAME=${sq(node.name)}`,
        `export NODE_TYPE=${sq(node.type || 'hysteria')}`,
        `export NODE_DOMAIN=${sq(node.domain)}`,
    ].join('\n');

    const wrappedScript = `#!/bin/bash\nset +e\n${envPrefix}\n\n${script}`;

    try {
        const result = await execSSH(conn, wrappedScript);
        if (result.output) logs.push(result.output);

        if (result.success) {
            log('Init script completed successfully');
        } else {
            log(`Init script exited with code ${result.code} (non-fatal, continuing setup)`);
        }
    } catch (err) {
        log(`Init script error: ${err.message} (non-fatal, continuing setup)`);
    }
}

async function setupNode(node, options = {}) {
    const { installHysteria = true, setupPortHopping = true, restartService = true } = options;
    
    const logs = [];
    const log = (msg) => {
        const line = `[${new Date().toISOString()}] ${msg}`;
        logs.push(line);
        logger.info(`[NodeSetup] ${msg}`);
    };
    
    log(`Starting setup for ${node.name} (${node.ip})`);
    
    // Get settings for auth insecure option
    const settings = await Settings.get();
    const authInsecure = settings?.nodeAuth?.insecure ?? true;
    
    const authUrl = `${config.BASE_URL}/api/auth`;
    log(`Auth URL: ${authUrl} (insecure: ${authInsecure})`);
    
    let conn;
    
    try {
        log('Connecting via SSH...');
        conn = await connectSSH(node);
        log('SSH connected');

        await runInitScript(conn, node, log, logs);
        
        if (installHysteria) {
            log('Running system diagnostics and installing Hysteria...');
            const installResult = await execSSH(conn, INSTALL_SCRIPT);
            logs.push(installResult.output);
            
            if (!installResult.success) {
                log(`ERROR: Installation script failed (exit code: ${installResult.code})`);
                log('Last output lines:');
                const lastLines = (installResult.output || '').split('\n').slice(-10).join('\n');
                log(lastLines);
                throw new Error(`Hysteria installation failed (exit code ${installResult.code}): ${installResult.error}`);
            }
            log('System diagnostics passed, Hysteria installed');
        }
        
        // Determine TLS mode: same-VPS (copy panel certs), ACME, or self-signed
        // Use improved detection: checks domain match, localhost, and PANEL_IP env
        const isSameVpsSetup = isSameVpsAsPanel(node);
        let useTlsFiles = false;
        
        if (isSameVpsSetup) {
            // Same server as panel - try to copy panel's certificates
            log(`Same-VPS setup detected (node IP: ${node.ip}, panel domain: ${config.PANEL_DOMAIN})`);
            log('Attempting to copy panel certificates to node...');
            
            const panelCerts = getPanelCertificates(config.PANEL_DOMAIN);
            
            if (panelCerts) {
                // Upload certificates to node
                await uploadFile(conn, panelCerts.cert, '/etc/hysteria/cert.pem');
                await uploadFile(conn, panelCerts.key, '/etc/hysteria/key.pem');
                
                // Set correct permissions
                await execSSH(conn, `
chmod 644 /etc/hysteria/cert.pem
chmod 600 /etc/hysteria/key.pem
if id "hysteria" &>/dev/null; then
    chown hysteria:hysteria /etc/hysteria/cert.pem /etc/hysteria/key.pem
fi
echo "Done: Panel certificates copied to node"
ls -la /etc/hysteria/*.pem
                `);
                
                log('Panel certificates copied successfully');
                useTlsFiles = true;
            } else {
                log('Warning: Could not read panel certificates, falling back to self-signed');
                const certResult = await execSSH(conn, SELF_SIGNED_CERT_SCRIPT);
                logs.push(certResult.output);
                useTlsFiles = true;
            }
            
        } else if (!node.domain) {
            // No domain and not same VPS - use self-signed certificate
            log('No domain specified, generating self-signed certificate...');
            const certResult = await execSSH(conn, SELF_SIGNED_CERT_SCRIPT);
            logs.push(certResult.output);
            
            if (!certResult.success) {
                throw new Error(`Certificate generation failed: ${certResult.error}`);
            }
            log('Certificate ready (self-signed)');
            useTlsFiles = true;
            
        } else {
            // Different domain on different VPS - use ACME
            log(`Domain detected (${node.domain}), ACME will be used`);
            log('⚠️  WARNING: If this node is on the same VPS as the panel, ACME may fail!');
            log('⚠️  Port 80 is used by the panel for its own ACME challenges.');
            log('⚠️  Consider using the panel domain or no domain (self-signed) for same-VPS setup.');
            log('Opening port 80 for ACME HTTP-01 challenge...');
            
            const acmeSetup = await execSSH(conn, `
echo "=== Setting up for ACME ==="

mkdir -p /etc/hysteria/acme
chmod 777 /etc/hysteria/acme
chmod 755 /etc/hysteria
echo "Done: ACME directory created with correct permissions"

ls -la /etc/hysteria/

if command -v iptables &> /dev/null; then
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 80 -j ACCEPT 2>/dev/null || true
    echo "Done: Port 80 opened in iptables"
fi

if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow 80/udp 2>/dev/null || true
    echo "Done: Port 80 opened in ufw"
fi

${IPTABLES_SAVE_SNIPPET}

if ss -tlnp | grep -q ':80 '; then
    echo "⚠️  Warning: Port 80 is already in use (likely by the panel):"
    ss -tlnp | grep ':80 '
    echo "ACME challenge will likely fail if panel is on the same server!"
else
    echo "Done: Port 80 is free"
fi

echo "Done: ACME preparation complete"
echo "Note: Make sure DNS for ${node.domain} points to this server's IP!"
            `);
            logs.push(acmeSetup.output);
            log('ACME preparation done');
        }
        
        log('Uploading config...');
        const hysteriaConfig = configGenerator.generateNodeConfig(node, authUrl, { authInsecure, useTlsFiles });
        await uploadFile(conn, hysteriaConfig, '/etc/hysteria/config.yaml');
        log('Config uploaded to /etc/hysteria/config.yaml');
        logs.push('--- Config content ---');
        logs.push(hysteriaConfig);
        logs.push('--- End config ---');
        
        if (setupPortHopping && node.portRange) {
            if (isSameVpsAsPanel(node)) {
                log('Skipping port hopping for self-hosted node (incompatible with Docker networking)');
            } else {
                log(`Setting up port hopping (${node.portRange})...`);
                const portHoppingScript = getPortHoppingScript(node.portRange, node.port || 443);
                if (!portHoppingScript) {
                    throw new Error('Invalid port hopping range');
                }

                const hopResult = await execSSH(conn, portHoppingScript);
                logs.push(hopResult.output);
                if (!hopResult.success) {
                    throw new Error(`Port hopping setup failed: ${hopResult.error}`);
                }
                log('Port hopping configured');
            }
        }
        
        const statsPort = node.statsPort || 9999;
        const mainPort = node.port || 443;
        log(`Opening firewall ports (${mainPort}, ${statsPort})...`);
        const mainPortScript = buildPortHoppingReconcileScript({
            desiredRange: '',
            previousRange: '',
            mainPort,
            previousMainPortEnabled: false,
            desiredMainPortEnabled: true,
        });
        const firewallResult = await execSSH(conn, `${mainPortScript}

echo "=== [5/6] Opening firewall ports ==="

iptables -C INPUT -p tcp --dport ${statsPort} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport ${statsPort} -j ACCEPT || exit 1
echo "Done: Ports ${mainPort}, ${statsPort} opened in iptables"

if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    ufw allow ${statsPort}/tcp >/dev/null 2>&1 || exit 1
    echo "Done: Ports ${mainPort}, ${statsPort} opened in ufw"
fi

${IPTABLES_SAVE_SNIPPET}

echo "Done: Firewall configured"
        `);
        logs.push(firewallResult.output);
        if (!firewallResult.success) {
            throw new Error(`Firewall setup failed: ${firewallResult.error}`);
        }
        log('Firewall ports opened');
        
        if (restartService) {
            log('Restarting Hysteria service...');
            const restartResult = await execSSH(conn, `
echo "=== [6/6] Restarting Hysteria service ==="
systemctl enable hysteria-server 2>/dev/null || true
systemctl restart hysteria-server
sleep 3
echo "Service status:"
systemctl status hysteria-server --no-pager -l || true
echo ""
echo "Journal logs (last 20 lines):"
journalctl -u hysteria-server -n 20 --no-pager || true
            `);
            logs.push(restartResult.output);
            
            if (!restartResult.success) {
                log(`Service restart warning: ${restartResult.error}`);
            } else {
                log('Service restarted');
            }
        }
        
        log('Setup completed successfully!');

        if (node.initScript) {
            await Settings.update({ lastInitScript: node.initScript }).catch(() => {});
        }

        return { success: true, logs, useTlsFiles };
        
    } catch (error) {
        log(`Error: ${error.message}`);
        return { success: false, error: error.message, logs, useTlsFiles: false };
        
    } finally {
        if (conn) {
            conn.end();
        }
    }
}

async function checkNodeStatus(node) {
    try {
        const conn = await connectSSH(node);
        
        try {
            const result = await execSSH(conn, 'systemctl is-active hysteria-server');
            return result.output.trim() === 'active' ? 'online' : 'offline';
        } finally {
            conn.end();
        }
    } catch (error) {
        return 'error';
    }
}

async function getNodeLogs(node, lines = 50) {
    try {
        const conn = await connectSSH(node);
        
        try {
            const result = await execSSH(conn, `journalctl -u hysteria-server -n ${lines} --no-pager`);
            return { success: true, logs: result.output };
        } finally {
            conn.end();
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// ==================== XRAY SETUP ====================

const XRAY_INSTALL_SCRIPT = `#!/bin/bash

echo "=== [1/4] Installing Xray-core ==="
echo "Checking system..."
echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -a)"
echo "Arch: $(uname -m)"

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo "curl not found, installing..."
    apt-get update && apt-get install -y curl || yum install -y curl || apk add curl
fi

if ! command -v xray &> /dev/null; then
    echo "Xray not found. Installing via official script..."
    curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh
    chmod +x /tmp/xray-install.sh
    bash /tmp/xray-install.sh install 2>&1
    INSTALL_EXIT=$?
    rm -f /tmp/xray-install.sh
    if [ $INSTALL_EXIT -ne 0 ]; then
        echo "ERROR: Xray installation script exited with code $INSTALL_EXIT"
        exit 1
    fi
    # Verify installation
    if ! command -v xray &> /dev/null; then
        echo "ERROR: xray command not found after installation"
        exit 1
    fi
    echo "Done: Xray installed ($(xray version | head -1))"
else
    echo "Done: Xray already installed ($(xray version | head -1))"
fi

mkdir -p /usr/local/etc/xray
echo "Done: Directory /usr/local/etc/xray ready"
`;

// ACME (acme.sh) setup for tlsSource='acme': issue LE cert for `domain` via
// HTTP-01 standalone, install to /usr/local/etc/xray/{cert,key}.pem, register
// acme.sh cron for autonomous renewal. Inputs sanitized at the call-site.
function buildAcmeSetupScript({ domain, email, nodeIp }) {
    const safe = (raw, allowed, max) => String(raw || '').replace(allowed, '').slice(0, max);
    const d = safe(domain, /[^A-Za-z0-9.\-]/g, 253);
    const e = safe(email, /[^A-Za-z0-9.\-_+@]/g, 254);
    const ip = safe(nodeIp, /[^A-Za-z0-9.:]/g, 45);
    if (!d) throw new Error('buildAcmeSetupScript: domain is required');
    if (!e) throw new Error('buildAcmeSetupScript: email is required');

    return `#!/bin/bash
set -e
DOMAIN="${d}"
EMAIL="${e}"
NODE_IP="${ip}"
CERT_PATH=/usr/local/etc/xray/cert.pem
KEY_PATH=/usr/local/etc/xray/key.pem

echo "=== ACME setup for \${DOMAIN} ==="

# Pre-flight 1: domain must resolve (warn on mismatch, fail on no resolution).
RESOLVED=$(getent hosts "\${DOMAIN}" 2>/dev/null | awk '{print $1; exit}' || true)
if [ -z "\${RESOLVED}" ]; then
    echo "ERROR: DNS resolution failed for \${DOMAIN}. Set an A record pointing to \${NODE_IP} before retrying."
    exit 11
fi
if [ "\${RESOLVED}" != "\${NODE_IP}" ] && [ -n "\${NODE_IP}" ]; then
    echo "WARN: \${DOMAIN} resolves to \${RESOLVED}, expected \${NODE_IP}. Continuing — anycast/CDN may legitimately differ."
fi

# Pre-flight 2: port 80 must be free for HTTP-01 standalone.
if ss -tlnH 'sport = :80' 2>/dev/null | grep -q LISTEN; then
    echo "ERROR: Port 80 is busy on the node. Stop the listener (nginx/apache/caddy/etc.) and retry."
    ss -tlnp 'sport = :80' 2>/dev/null || true
    exit 12
fi

if [ ! -f "\${HOME}/.acme.sh/acme.sh" ]; then
    echo "Installing acme.sh..."
    if ! command -v curl &> /dev/null; then
        apt-get update && apt-get install -y curl || yum install -y curl || apk add --no-cache curl
    fi
    curl -fsSL https://get.acme.sh | sh -s email="\${EMAIL}" >/dev/null 2>&1 || {
        echo "ERROR: acme.sh installer failed."
        exit 13
    }
fi
ACME="\${HOME}/.acme.sh/acme.sh"

# Pin CA to LE (acme.sh default has flipped between ZeroSSL and LE).
"\${ACME}" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

# Skip --issue if cert already present; renewals run via acme.sh cron.
CERT_FILE="\${HOME}/.acme.sh/\${DOMAIN}_ecc/\${DOMAIN}.cer"
if [ ! -f "\${CERT_FILE}" ]; then
    echo "Issuing LE cert for \${DOMAIN} via HTTP-01 standalone..."
    "\${ACME}" --issue --standalone --server letsencrypt -d "\${DOMAIN}" --keylength ec-256
else
    echo "Existing cert present for \${DOMAIN}; skipping --issue (renewals run via acme.sh cron)."
fi

mkdir -p /usr/local/etc/xray

# Xray runs as User=nobody; acme.sh writes as root → chown is required for the
# unprivileged service to read the key. Re-applied via --reloadcmd on renewal.
# 'nobody' primary group differs by distro (nogroup on Debian/Ubuntu).
NOBODY_GROUP="\$(id -gn nobody 2>/dev/null || echo nobody)"
RELOAD_CMD="chown 'nobody:\${NOBODY_GROUP}' '\${KEY_PATH}' '\${CERT_PATH}' 2>/dev/null || true; chmod 644 '\${CERT_PATH}' 2>/dev/null || true; chmod 600 '\${KEY_PATH}' 2>/dev/null || true; systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null || true"

"\${ACME}" --install-cert -d "\${DOMAIN}" --ecc \\
    --key-file       "\${KEY_PATH}" \\
    --fullchain-file "\${CERT_PATH}" \\
    --reloadcmd "\${RELOAD_CMD}"

chown "nobody:\${NOBODY_GROUP}" "\${KEY_PATH}" "\${CERT_PATH}" 2>/dev/null || true
chmod 644 "\${CERT_PATH}" 2>/dev/null || true
chmod 600 "\${KEY_PATH}"  2>/dev/null || true

if crontab -l 2>/dev/null | grep -q '\\.acme\\.sh/acme\\.sh.*--cron'; then
    echo "Done: cert installed; acme.sh cron is active."
else
    echo "WARN: acme.sh cron entry missing — auto-renewal may not run. Re-run 'acme.sh --install-cronjob' on the node."
fi

echo "ACME setup completed for \${DOMAIN}"
`;
}

/**
 * Setup Xray node via SSH:
 * 1. Install xray-core
 * 2. Generate x25519 Reality keys (if security=reality and no keys yet)
 * 3. Upload config.json
 * 4. Open firewall ports
 * 5. Enable and restart xray service
 *
 * @param {Object} node - Node document
 * @param {Object} options - { restartService }
 * @returns {{ success, logs, realityKeys? }}
 */
async function setupXrayNode(node, options = {}) {
    const { restartService = true, exitOnly = false } = options;

    const logs = [];
    const log = (msg) => {
        const line = `[${new Date().toISOString()}] ${msg}`;
        logs.push(line);
        logger.info(`[XraySetup] ${msg}`);
    };

    log(`Starting Xray setup for ${node.name} (${node.ip})${exitOnly ? ' [exit/bridge mode]' : ''}`);

    if (!exitOnly) {
        // Detect port conflict: Xray on the same VPS as the panel (Caddy) using port 443/80
        const sameVps = isSameVpsAsPanel(node);
        const nodePort = node.port || 443;
        if (sameVps && (nodePort === 443 || nodePort === 80)) {
            const msg = `Port conflict detected: Xray port ${nodePort} is already used by the panel (Caddy) on this server. ` +
                `Use a different port (e.g. 8443) for the Xray node. ` +
                `After changing the port, save the node and run Auto Setup again.`;
            log(`ERROR: ${msg}`);
            return { success: false, error: msg, logs, realityKeys: null };
        }

        // ACME on same-VPS is incompatible (port 80 held by panel Caddy).
        const xrayCfgEarly = node?.xray || {};
        if (sameVps && xrayCfgEarly.security === 'tls' && xrayCfgEarly.tlsSource === 'acme') {
            const msg = `tlsSource='acme' is incompatible with same-VPS deployment: ` +
                `port 80 is held by the panel's Caddy and cannot be used for HTTP-01. ` +
                `Switch the node to tlsSource='panel' (panel's LE cert is reused) or move the node to a separate VPS.`;
            log(`ERROR: ${msg}`);
            return { success: false, error: msg, logs, realityKeys: null };
        }

        if (sameVps) {
            log(`Same-VPS setup detected (node port: ${nodePort}, panel domain: ${config.PANEL_DOMAIN})`);
        }
    }

    let conn;
    let generatedKeys = null;

    try {
        log('Connecting via SSH...');
        conn = await connectSSH(node);
        log('SSH connected');

        await runInitScript(conn, node, log, logs);

        // Install Xray
        log('Installing Xray-core...');
        const installResult = await execSSH(conn, XRAY_INSTALL_SCRIPT);
        logs.push(installResult.output);
        if (!installResult.success) {
            throw new Error(`Xray installation failed: ${installResult.error}`);
        }
        log('Xray-core installed');

        // Exit (Bridge) nodes: skip config, Reality keys, firewall, and service start.
        // Their actual config is deployed via cascade links.
        if (exitOnly) {
            log('Exit node setup completed (Xray binary only). Deploy a cascade link to configure.');
            if (conn) conn.end();
            return { success: true, logs, realityKeys: null };
        }

        // Generate Reality keys and shortId if needed
        const xrayCfg = node.xray || {};
        if (xrayCfg.security === 'reality') {
            const updates = {};
            let needsUpdate = false;

            // Generate x25519 keys if not set (locally, no dependency on xray binary)
            if (!xrayCfg.realityPrivateKey) {
                log('Generating x25519 Reality keys...');
                generatedKeys = cryptoService.generateX25519KeysLocal();
                log(`Reality keys generated. PublicKey: ${generatedKeys.publicKey}`);
                updates['xray.realityPrivateKey'] = generatedKeys.privateKey;
                updates['xray.realityPublicKey'] = generatedKeys.publicKey;
                node.xray = { ...node.xray, realityPrivateKey: generatedKeys.privateKey, realityPublicKey: generatedKeys.publicKey };
                needsUpdate = true;
            }

            // Generate shortId if not set or only contains empty string
            const currentShortIds = xrayCfg.realityShortIds || [''];
            const hasRealShortId = currentShortIds.some(id => id && id.length > 0);
            if (!hasRealShortId) {
                const shortId = require('crypto').randomBytes(8).toString('hex'); // 16 hex chars
                log(`Generated shortId: ${shortId}`);
                updates['xray.realityShortIds'] = ['', shortId]; // empty + random
                node.xray = { ...node.xray, realityShortIds: ['', shortId] };
                needsUpdate = true;
            }

            // Save to DB
            if (needsUpdate) {
                const HyNode = require('../models/hyNodeModel');
                await HyNode.updateOne({ _id: node._id }, { $set: updates });
                log('Reality settings saved to database');
            }
        }

        // Generate and upload config
        log('Generating Xray config...');
        const configGenerator = require('./configGenerator');
        const syncService = require('./syncService');
        // Lazy-load manualKey for nodes using tlsSource==='manual' since the
        // private key is select:false at the schema layer.
        if (typeof syncService.ensureManualKeyLoaded === 'function') {
            await syncService.ensureManualKeyLoaded(node);
        }
        const users = await syncService._getUsersForNode(node);
        let configContent;
        try {
            configContent = configGenerator.generateXrayConfig(node, users);
        } catch (genErr) {
            if (genErr.code === 'PANEL_CERT_UNAVAILABLE' || genErr.code === 'MANUAL_CERT_UNAVAILABLE') {
                const human = genErr.code === 'PANEL_CERT_UNAVAILABLE'
                    ? `Panel certificate is not available on disk yet — issue/renew the panel cert (${config.PANEL_DOMAIN || '<PANEL_DOMAIN unset>'}) and re-run install.`
                    : 'Manual TLS PEM is missing — paste both certificate and private key in the node form before installing.';
                throw new Error(human);
            }
            throw genErr;
        }
        const configPath = '/usr/local/etc/xray/config.json';

        await uploadFile(conn, configContent, configPath);
        log(`Config uploaded to ${configPath} (${users.length} users)`);
        logs.push('--- Config preview ---');
        logs.push(configContent.substring(0, 500) + (configContent.length > 500 ? '\n...' : ''));
        logs.push('--- End config preview ---');

        // Self-signed TLS: openssl is only invoked when explicitly requested.
        // For tlsSource=panel/manual the certificate is inlined into config.json
        // by configGenerator and never written to disk on the remote node.
        if (xrayCfg.security === 'tls' && xrayCfg.tlsSource === 'self-signed') {
            log('Generating self-signed TLS certificate (testing only)...');
            // Strip shell metacharacters from CN (node.sni is admin-only but
            // not strictly validated) and cap at the X.509 64-char CN limit.
            const rawCn = String(node.domain || node.sni || node.ip || 'xray');
            const cn = (rawCn.replace(/[^A-Za-z0-9.\-:]/g, '').slice(0, 64)) || 'xray';
            const certResult = await execSSH(conn, `
mkdir -p /usr/local/etc/xray
if [ ! -f /usr/local/etc/xray/cert.pem ] || [ ! -s /usr/local/etc/xray/cert.pem ] \\
   || [ ! -f /usr/local/etc/xray/key.pem ] || [ ! -s /usr/local/etc/xray/key.pem ]; then
    if openssl ecparam -name prime256v1 -genkey -noout -out /usr/local/etc/xray/key.pem 2>/dev/null; then
        openssl req -x509 -new -key /usr/local/etc/xray/key.pem \\
            -out /usr/local/etc/xray/cert.pem \\
            -subj "/CN=${cn}" -days 36500 2>&1 || true
    fi
    if [ ! -s /usr/local/etc/xray/cert.pem ]; then
        # Fallback to RSA for ancient OpenSSL builds without prime256v1
        openssl req -x509 -nodes -newkey rsa:2048 \\
            -keyout /usr/local/etc/xray/key.pem \\
            -out /usr/local/etc/xray/cert.pem \\
            -subj "/CN=${cn}" -days 36500 2>&1 || true
    fi
    chmod 600 /usr/local/etc/xray/key.pem
    chmod 644 /usr/local/etc/xray/cert.pem
    echo "OK: Self-signed certificate generated for CN=${cn}"
else
    echo "Skipped: certificate already exists"
fi
`);
            logs.push(certResult.output);
            if (!certResult.success) {
                log(`Self-signed cert generation warning: ${certResult.error}`);
            }
        } else if (xrayCfg.security === 'tls' && xrayCfg.tlsSource === 'acme') {
            const domain = String(node.domain || '').trim();
            const email = (String(xrayCfg.acmeEmail || '').trim()) ||
                          (String(config.ACME_EMAIL || '').trim());
            if (!domain) {
                throw new Error('tlsSource=acme requires node.domain to be set in the Network section.');
            }
            if (!email) {
                throw new Error('tlsSource=acme requires acmeEmail (or the panel-wide ACME_EMAIL env var).');
            }
            log(`TLS source: acme — installing acme.sh and issuing LE cert for ${domain}...`);
            const acmeScript = buildAcmeSetupScript({ domain, email, nodeIp: node.ip });
            const acmeResult = await execSSH(conn, acmeScript);
            logs.push(acmeResult.output);
            if (!acmeResult.success) {
                throw new Error(`ACME setup failed: ${acmeResult.error || 'see logs above'}`);
            }
            log('ACME cert installed and auto-renewal cron registered on the node.');
        } else if (xrayCfg.security === 'tls') {
            log(`TLS source: ${xrayCfg.tlsSource || 'panel'} — certificate inlined in config.json (no on-node openssl)`);
        }

        // Collect all client-facing ports: main inbound + extra inbounds.
        // apiPort is local-only (127.0.0.1) and does not need a firewall rule.
        const mainPort = node.port || 443;
        const apiPort = (node.xray || {}).apiPort || 61000;
        const extraPorts = ((node.xray || {}).extraInbounds || [])
            .map(i => parseInt(i.port, 10))
            .filter(p => Number.isInteger(p) && p > 0 && p < 65536 && p !== mainPort);
        const allPorts = [mainPort, ...extraPorts];

        log(`Opening firewall ports (${allPorts.join(', ')}, api:${apiPort})...`);
        const portRules = allPorts.map(p => `
    iptables -I INPUT -p tcp --dport ${p} -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport ${p} -j ACCEPT 2>/dev/null || true`).join('');
        const ufwRules = allPorts.map(p => `
    ufw allow ${p}/tcp 2>/dev/null || true
    ufw allow ${p}/udp 2>/dev/null || true`).join('');

        const firewallResult = await execSSH(conn, `
echo "=== Opening firewall ports ==="
if command -v iptables &> /dev/null; then${portRules}
    echo "Done: iptables rules added"
fi
if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then${ufwRules}
    echo "Done: UFW rules added"
fi
${IPTABLES_SAVE_SNIPPET}
echo "Done: Firewall configured"
        `);
        logs.push(firewallResult.output);
        log('Firewall configured');

        if (restartService) {
            log('Installing systemd service and starting Xray...');
            const serviceContent = configGenerator.generateXraySystemdService();
            await uploadFile(conn, serviceContent, '/etc/systemd/system/xray.service');
            const restartResult = await execSSH(conn, `
echo "=== Starting Xray service ==="
systemctl daemon-reload
systemctl enable xray
systemctl restart xray
sleep 2
echo "Service status:"
systemctl status xray --no-pager -l || true
echo ""
echo "Journal (last 15 lines):"
journalctl -u xray -n 15 --no-pager || true
            `);
            logs.push(restartResult.output);
            if (!restartResult.success) {
                log(`Service restart warning: ${restartResult.error}`);
            } else {
                log('Xray service started');
            }
        }

        log('Xray setup completed successfully!');

        if (node.initScript) {
            await Settings.update({ lastInitScript: node.initScript }).catch(() => {});
        }

        return { success: true, logs, realityKeys: generatedKeys };

    } catch (error) {
        log(`Error: ${error.message}`);
        return { success: false, error: error.message, logs, realityKeys: generatedKeys };

    } finally {
        if (conn) conn.end();
    }
}

/**
 * Check Xray service status via SSH
 */
async function checkXrayNodeStatus(node) {
    try {
        const conn = await connectSSH(node);
        try {
            const result = await execSSH(conn, 'systemctl is-active xray');
            return result.output.trim() === 'active' ? 'online' : 'offline';
        } finally {
            conn.end();
        }
    } catch (error) {
        return 'error';
    }
}

/**
 * Get Xray node logs via SSH
 */
async function getXrayNodeLogs(node, lines = 50) {
    try {
        const conn = await connectSSH(node);
        try {
            const result = await execSSH(conn, `journalctl -u xray -n ${lines} --no-pager`);
            return { success: true, logs: result.output };
        } finally {
            conn.end();
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// ==================== CC AGENT SETUP ====================

/**
 * Generate a secure random token for the CC Agent
 */
function generateAgentToken() {
    return require('crypto').randomBytes(32).toString('hex');
}

// cc-agent uses Go's log package, so release builds may print a timestamp and
// either `cc-agent 1.5.0` or the historical `cc-agent v1.5.0` spelling.
function parseAgentVersion(output) {
    const match = String(output || '').match(/cc-agent[:\s]+v?(\d+\.\d+\.\d+)(?:[-+][^\s]+)?/i);
    return match?.[1] || '';
}

function isAgentVersionAtLeast(version, minimum) {
    const parse = value => {
        const match = String(value || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
        return match ? match.slice(1).map(Number) : null;
    };
    const current = parse(version);
    const required = parse(minimum);
    if (!current || !required) return false;
    for (let i = 0; i < 3; i++) {
        if (current[i] > required[i]) return true;
        if (current[i] < required[i]) return false;
    }
    return true;
}

/**
 * Ensure a physical proxy node has a persisted agent token in MongoDB.
 * MongoDB remains the source of truth; the installer only consumes the saved token.
 *
 * @param {Object} node - Node document
 * @returns {{ node: Object, token: string, created: boolean }}
 */
async function ensureNodeAgentToken(node) {
    if (!['xray', 'hysteria'].includes(node.type)) {
        throw new Error(`Node ${node.name} cannot run cc-agent`);
    }

    const existingToken = (node.xray || {}).agentToken;
    if (existingToken) {
        return { node, token: existingToken, created: false };
    }

    const HyNode = require('../models/hyNodeModel');
    const generatedToken = generateAgentToken();

    const updatedNode = await HyNode.findOneAndUpdate(
        {
            _id: node._id,
            $or: [
                { 'xray.agentToken': { $exists: false } },
                { 'xray.agentToken': '' },
            ],
        },
        { $set: { 'xray.agentToken': generatedToken } },
        { new: true }
    );

    const freshNode = updatedNode || await HyNode.findById(node._id);
    const token = freshNode?.xray?.agentToken || '';

    if (!token) {
        throw new Error(`Could not persist agent token for node ${node.name}`);
    }

    return {
        node: freshNode,
        token,
        created: !!updatedNode,
    };
}

// Backward-compatible Xray-only wrapper used by the existing node setup flow.
async function ensureXrayAgentToken(node) {
    if (node.type !== 'xray') {
        throw new Error(`Node ${node.name} is not an Xray node`);
    }
    return ensureNodeAgentToken(node);
}

/**
 * Install and configure cc-agent on a physical proxy node via SSH.
 *
 * Flow:
 *  1. Download binary from GitHub releases (or fallback URL)
 *  2. Write /etc/cc-agent/config.json with token + TLS settings
 *  3. If TLS: generate self-signed cert with openssl
 *  4. Open port in firewall for the panel source or local Docker networks
 *  5. Install & start cc-agent.service
 *
 * @param {Object} conn  - Active ssh2 connection
 * @param {Object} node  - Node document
 * @param {string} token - Pre-generated agent token
 * @param {string} panelSource - Panel firewall source (IP/host hint for remote nodes)
 * @param {boolean} sameVps - Whether the node is on the same VPS as the panel
 * @param {Function} log - Logging callback
 * @returns {{ success, agentVersion }}
 */
async function installCCAgent(conn, node, token, panelSource, sameVps, log, accessLogs) {
    await assertCcAgentConfigOwnership(conn, token);
    const requestedAgentPort = Number((node.xray || {}).agentPort);
    const agentPort = Number.isInteger(requestedAgentPort) && requestedAgentPort > 0 && requestedAgentPort <= 65535
        ? requestedAgentPort : 62080;
    const useTls = (node.xray || {}).agentTls !== false;
    const requestedApiPort = Number((node.xray || {}).apiPort);
    const apiPort = Number.isInteger(requestedApiPort) && requestedApiPort > 0 && requestedApiPort <= 65535
        ? requestedApiPort : 61000;

    const agentConfig = buildAgentConfig(node, token, agentPort, apiPort, useTls, accessLogs);
    const configJson = JSON.stringify(agentConfig, null, 2);

    // Build firewall rules based on setup type. Normalize again here so direct
    // callers cannot bypass the root-command input boundary.
    const safePanelSource = normalizeFirewallSource(panelSource);
    const quotedPanelSource = shellSingleQuote(safePanelSource);
    let firewallRules = '';
    if (sameVps) {
        firewallRules = `
echo "Same-VPS setup: allowing loopback and Docker networks"
if command -v iptables &> /dev/null; then
    iptables -I INPUT -p tcp -s 127.0.0.1/32 --dport ${agentPort} -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp -s 172.16.0.0/12 --dport ${agentPort} -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp -s 192.168.0.0/16 --dport ${agentPort} -j ACCEPT 2>/dev/null || true
    echo "Done: iptables rules added"
fi
if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow from 127.0.0.1 to any port ${agentPort} proto tcp 2>/dev/null || true
    ufw allow from 172.16.0.0/12 to any port ${agentPort} proto tcp 2>/dev/null || true
    ufw allow from 192.168.0.0/16 to any port ${agentPort} proto tcp 2>/dev/null || true
    echo "Done: ufw rules added"
fi`;
    } else if (safePanelSource) {
        firewallRules = `
echo "Remote setup: allowing panel source" ${quotedPanelSource}
if command -v iptables &> /dev/null; then
    iptables -I INPUT -p tcp -s ${quotedPanelSource} --dport ${agentPort} -j ACCEPT 2>/dev/null || true
    echo "Done: iptables rule added"
fi
if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow from ${quotedPanelSource} to any port ${agentPort} proto tcp 2>/dev/null || true
    echo "Done: ufw rule added"
fi`;
    } else {
        firewallRules = 'echo "WARNING: Panel source unknown, skipping firewall rules"';
    }

    // Persist iptables rules across reboots
    if (firewallRules && !firewallRules.includes('WARNING')) {
        firewallRules += '\n' + IPTABLES_SAVE_SNIPPET;
    }

    // Step 1: Download binary
    log('Downloading cc-agent binary...');
    const downloadResult = await execSSH(conn, `
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    BIN="cc-agent-linux-arm64"
else
    BIN="cc-agent-linux-amd64"
fi
URL="https://github.com/ClickDevTech/CELERITY-panel/releases/latest/download/$BIN"
TMP="/usr/local/bin/.cc-agent-download-$$"
trap 'rm -f "$TMP"' EXIT
echo "Downloading $URL ..."
curl -fsSL --max-time 120 "$URL" -o "$TMP"
if [ ! -s "$TMP" ]; then
    echo "ERROR: Download failed or file is empty"
    exit 1
fi
chmod +x "$TMP"
"$TMP" -version 2>&1 || { echo "ERROR: Downloaded cc-agent cannot execute"; exit 1; }
mv -f "$TMP" /usr/local/bin/cc-agent || exit 1
trap - EXIT
echo "OK: cc-agent binary ready"
ls -la /usr/local/bin/cc-agent
`);

    if (!downloadResult.success) {
        log(`Binary download failed: ${downloadResult.output}`);
        return { success: false, agentVersion: '', output: downloadResult.output };
    }
    log('Binary downloaded');

    // Step 2: Write config
    log('Writing agent config...');
    const configDirsResult = await execSSH(conn, 'mkdir -p /etc/cc-agent /var/lib/cc-agent');
    if (!configDirsResult.success) {
        return { success: false, agentVersion: '', output: configDirsResult.output || configDirsResult.error };
    }
    await uploadFile(conn, configJson, '/etc/cc-agent/config.json');
    const configModeResult = await execSSH(conn, 'chmod 600 /etc/cc-agent/config.json');
    if (!configModeResult.success) {
        return { success: false, agentVersion: '', output: configModeResult.output || configModeResult.error };
    }
    log('Config written');

    // Step 3: Generate TLS cert if needed
    if (useTls) {
        log('Generating TLS certificate...');
        const tlsResult = await execSSH(conn, `
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/cc-agent/key.pem \
    -out /etc/cc-agent/cert.pem \
    -subj "/CN=cc-agent" -days 36500 2>&1
chmod 600 /etc/cc-agent/key.pem /etc/cc-agent/cert.pem
echo "OK: TLS cert generated"
`);
        if (!tlsResult.success) {
            return { success: false, agentVersion: '', output: tlsResult.output || tlsResult.error };
        }
        log('TLS certificate ready');
    }

    // Step 4: Install systemd service
    log('Installing systemd service...');
    const hysteriaUnit = ['hysteria-server', 'hysteria'].includes(accessLogs?.journalUnit)
        ? accessLogs.journalUnit : 'hysteria-server';
    const proxyService = node.type === 'hysteria' ? `${hysteriaUnit}.service` : 'xray.service';
    const serviceUnit = `[Unit]
Description=CC Proxy Agent
After=network.target ${proxyService}

[Service]
Type=simple
ExecStart=/usr/local/bin/cc-agent
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`;
    await uploadFile(conn, serviceUnit, '/etc/systemd/system/cc-agent.service');
    log('Service unit installed');

    // Step 5: Firewall + start service
    log('Configuring firewall and starting service...');
    const startResult = await execSSH(conn, `
${firewallRules}
systemctl daemon-reload
systemctl enable cc-agent
systemctl restart cc-agent
sleep 2
if systemctl is-active cc-agent > /dev/null 2>&1; then
    echo "OK: cc-agent running"
    /usr/local/bin/cc-agent -version 2>&1 || true
else
    echo "ERROR: cc-agent failed to start"
    journalctl -u cc-agent -n 10 --no-pager 2>/dev/null || true
fi
`);

    const allOutput = [downloadResult.output, startResult.output].join('\n');
    const agentVersion = parseAgentVersion(allOutput) || 'installed';
    const isRunning = startResult.output.includes('OK: cc-agent running');

    return { success: isRunning, agentVersion, output: allOutput };
}

/**
 * Setup Xray node + CC Agent via SSH.
 * Extends setupXrayNode to also install the agent.
 */
async function setupXrayNodeWithAgent(node, options = {}) {
    let preparedNode = node;
    let agentToken = '';

    try {
        const ensured = await ensureXrayAgentToken(node);
        preparedNode = ensured.node;
        agentToken = ensured.token;
    } catch (error) {
        const line = `[${new Date().toISOString()}] Agent token error: ${error.message}`;
        logger.error(`[AgentSetup] ${error.message}`);
        return { success: false, error: error.message, logs: [line] };
    }

    const result = await setupXrayNode(preparedNode, options);

    if (!result.success) {
        return result;
    }

    const log = (msg) => {
        const line = `[${new Date().toISOString()}] ${msg}`;
        result.logs.push(line);
        logger.info(`[AgentSetup] ${msg}`);
    };

    let conn;
    try {
        if ((node.xray || {}).agentToken !== agentToken) {
            log('Agent token ensured in database');
        }

        log('Connecting via SSH for agent installation...');
        conn = await connectSSH(preparedNode);

        // Same-VPS setups must allow Docker bridge traffic to reach the host agent.
        const sameVps = isSameVpsAsPanel(preparedNode);
        const panelSource = resolvePanelFirewallSource();
        log(`Agent firewall mode: ${sameVps ? 'same-vps' : 'remote'}`);
        if (!sameVps) {
            log(`Panel source for firewall: ${panelSource || 'not provided'}`);
        }

        log('Installing CC Agent...');
        const agentResult = await enqueueCcAgentHostTask(
            preparedNode,
            () => installCCAgent(conn, preparedNode, agentToken, panelSource, sameVps, log)
        );
        if (agentResult.output) {
            result.logs.push(agentResult.output);
        }

        if (!agentResult.success) {
            throw new Error('CC Agent installation failed');
        }
        log(`Agent installed: ${agentResult.agentVersion}`);

        const HyNode = require('../models/hyNodeModel');
        const updates = {
            'xray.agentToken': agentToken,
            agentVersion: agentResult.agentVersion,
            agentStatus: 'unknown', // will be updated on first health check
        };
        await HyNode.updateOne({ _id: preparedNode._id }, { $set: updates });
        log('Agent metadata saved to database');

        result.agentToken = agentToken;

    } catch (error) {
        const line = `[${new Date().toISOString()}] Agent install error: ${error.message}`;
        result.logs.push(line);
        logger.error(`[AgentSetup] ${error.message}`);
        return { ...result, success: false, error: error.message };
    } finally {
        if (conn) conn.end();
    }

    return result;
}

/**
 * Compute the XTLS flow value for a given inbound config block.
 * Flow only applies to tcp + reality/tls; for other transports it must be
 * empty, otherwise Xray rejects user additions.
 *
 * @param {Object} inbound - Object with `transport`, `security`, `flow` fields
 * @returns {string} The flow string or '' when flow is not applicable
 */
function computeInboundFlow(inbound) {
    if (!inbound) return '';
    const transport = inbound.transport || 'tcp';
    const security = inbound.security || 'reality';
    if ((security === 'reality' || security === 'tls') && transport === 'tcp') {
        return inbound.flow || 'xtls-rprx-vision';
    }
    return '';
}

/**
 * Build the JSON config object written to /etc/cc-agent/config.json on the
 * remote node. Includes both the legacy `inbound_tag` (for old agents) and
 * the new `inbounds[]` array describing per-tag flow for all VLESS inbounds
 * (main + extras). Old agents read inbound_tag; new agents read inbounds[].
 */
function buildAgentConfig(node, token, agentPort, apiPort, useTls, accessLogs) {
    const xray = node.xray || {};
    const mainTag = xray.inboundTag || 'vless-in';

    const inbounds = [
        { tag: mainTag, flow: computeInboundFlow(xray) },
        ...(Array.isArray(xray.extraInbounds) ? xray.extraInbounds : [])
            .filter(i => i && i.inboundTag)
            .map(i => ({ tag: i.inboundTag, flow: computeInboundFlow(i) })),
    ];

    const cfg = {
        listen: `0.0.0.0:${agentPort}`,
        token: token,
        xray_api: `127.0.0.1:${apiPort}`,
        // Legacy single-tag field kept for backward compatibility with cc-agent
        // versions that do not understand `inbounds`.
        inbound_tag: mainTag,
        inbounds,
        data_dir: '/var/lib/cc-agent',
        tls: {
            enabled: useTls,
            cert: '/etc/cc-agent/cert.pem',
            key: '/etc/cc-agent/key.pem',
        },
    };

    // Opt-in access-log module. Only written when a caller supplies the block;
    // otherwise it stays absent so older agents and the disabled state are
    // untouched (the agent treats an absent block as disabled).
    if (accessLogs && typeof accessLogs === 'object') {
        cfg.access_logs = {
            enabled: !!accessLogs.enabled,
            // Source/format are understood by journal-capable agents. The
            // access-log provisioner gates both Xray and HY2 on cc-agent 1.5.1+
            // before it can enable this block.
            source: accessLogs.source || 'file',
            format: accessLogs.format || 'xray',
            journal_unit: accessLogs.journalUnit || '',
            path: accessLogs.path !== undefined ? accessLogs.path : '/var/log/xray/access.log',
            ingest_url: accessLogs.ingestUrl || '',
            ingest_token: accessLogs.ingestToken || '',
            insecure_tls: !!accessLogs.insecureTls,
            spool_max_bytes: accessLogs.spoolMaxBytes || (200 * 1024 * 1024),
            batch_max_events: accessLogs.batchMaxEvents || 500,
            flush_interval_seconds: accessLogs.flushIntervalSeconds || 5,
            file_max_bytes: accessLogs.fileMaxBytes || (64 * 1024 * 1024),
        };
    }

    return cfg;
}

/**
 * Refresh /etc/cc-agent/config.json on the remote node to reflect the current
 * set of Xray inbounds (main + extras), then restart the agent so it picks
 * up the new tag→flow mapping. Safe to call on every config sync — the
 * payload is idempotent.
 *
 * Uses sftp uploadFile (no shell-substitution of user input) and a fixed
 * `systemctl restart cc-agent` command — no injection surface.
 *
 * @param {Object} node - Node document with xray.agentToken/agentPort/...
 * @param {NodeSSH} ssh - Already-connected NodeSSH wrapper from syncService
 */
async function reloadCcAgentUnlocked(node, ssh) {
    const xray = node.xray || {};
    const token = xray.agentToken;
    if (!token) {
        return; // Agent not provisioned — nothing to refresh
    }
    const agentPort = xray.agentPort || 62080;
    const apiPort = xray.apiPort || 61000;
    const useTls = xray.agentTls !== false;
    await assertNodeSshCcAgentConfigOwnership(ssh, token);

    // Resolve the access-log block before touching the remote config. A DB or
    // decryption error must propagate: replacing a known-good enabled config
    // with `{enabled:false}` would silently stop collection while the panel
    // continued reporting the old fingerprint as active.
    const accessLogs = await require('./accessLogs/provisionService').buildNodeAccessLogsConfig(node);

    const agentConfig = buildAgentConfig(node, token, agentPort, apiPort, useTls, accessLogs);
    const configJson = JSON.stringify(agentConfig, null, 2);

    await ssh.uploadContent(configJson, '/etc/cc-agent/config.json');
    await ssh.exec('chmod 600 /etc/cc-agent/config.json');
    // Wait for systemd to confirm cc-agent is active again before returning,
    // so the caller (syncService) can immediately POST /restart to it without
    // racing the bring-up. The loop polls for up to ~5 s and exits 0 as soon
    // as the unit is active again, exit 1 on timeout.
    const waitResult = await ssh.exec(
        'systemctl restart cc-agent && '
        + 'for i in 1 2 3 4 5; do '
        + '  systemctl is-active cc-agent >/dev/null 2>&1 && exit 0; '
        + '  sleep 1; '
        + 'done; '
        + 'exit 1'
    );
    if (waitResult && typeof waitResult.code === 'number' && waitResult.code !== 0) {
        throw new Error(`cc-agent did not become active after restart (exit ${waitResult.code})`);
    }
    logger.info(`[Agent] Node ${node.name}: cc-agent config refreshed (${agentConfig.inbounds.length} inbound(s))`);
}

function reloadCcAgent(node, ssh) {
    return enqueueCcAgentHostTask(node, () => reloadCcAgentUnlocked(node, ssh));
}

const HYSTERIA_ACCESS_LOG_OVERRIDE_PATH =
    '/etc/systemd/system/hysteria-server.service.d/20-celerity-access-logs.conf';
const HYSTERIA_ACCESS_LOG_OVERRIDE_FILE = '20-celerity-access-logs.conf';

function hysteriaAccessLogOverridePath(unit) {
    if (!['hysteria-server', 'hysteria'].includes(unit)) {
        throw new Error(`Unsupported Hysteria systemd unit: ${unit}`);
    }
    return `/etc/systemd/system/${unit}.service.d/${HYSTERIA_ACCESS_LOG_OVERRIDE_FILE}`;
}

async function inspectHysteriaSystemdUnits(conn) {
    const states = [];
    for (const unit of ['hysteria-server', 'hysteria']) {
        const [existsResult, activeResult] = await Promise.all([
            execSSH(conn, `systemctl cat ${unit}.service >/dev/null 2>&1`),
            execSSH(conn, `systemctl is-active ${unit}.service >/dev/null 2>&1`),
        ]);
        states.push({ unit, exists: !!existsResult.success, active: !!activeResult.success });
    }
    return states;
}

async function detectHysteriaSystemdUnit(conn, preferred = '') {
    const candidates = preferred === 'hysteria'
        ? ['hysteria', 'hysteria-server']
        : ['hysteria-server', 'hysteria'];
    const states = await inspectHysteriaSystemdUnits(conn);
    const active = states.filter(state => state.active).map(state => state.unit);
    if (active.length > 1) {
        throw new Error('Both hysteria-server.service and hysteria.service are active; refusing ambiguous journal collection');
    }
    if (active.length === 1) return active[0];

    for (const unit of candidates) {
        if (states.some(state => state.unit === unit && state.exists)) return unit;
    }
    throw new Error('Neither hysteria-server.service nor hysteria.service exists');
}

function assertHysteriaExecStartLoggingCompatible(execStart) {
    const command = String(execStart || '');
    const readFlag = (longName, shortName) => {
        const pattern = new RegExp(
            `(?:^|\\s)(?:--${longName}(?:=|\\s+)([^\\s;]+)|-${shortName}(?:=([^\\s;]+)|([^\\s;=]+)|\\s+([^\\s;]+)))`,
            'gi'
        );
        let match;
        let value = '';
        // Cobra/pflag uses the last repeated value. Validate the same effective
        // value so an earlier safe flag cannot hide a later override. Short
        // flags also accept the compact pflag form (for example, -linfo).
        while ((match = pattern.exec(command)) !== null) {
            const rawValue = match.slice(1).find(candidate => candidate !== undefined) || '';
            value = rawValue.replace(/^['"]|['"]$/g, '').toLowerCase();
        }
        return value;
    };
    const level = readFlag('log-level', 'l');
    const format = readFlag('log-format', 'f');
    if (level && level !== 'debug') {
        throw new Error(`Hysteria ExecStart overrides log level with ${level}; debug is required`);
    }
    if (format && format !== 'json') {
        throw new Error(`Hysteria ExecStart overrides log format with ${format}; json is required`);
    }
}

function assertHysteriaEffectiveLoggingEnvironment(environment) {
    const text = String(environment || '');
    let entries;

    if (text.includes('\0')) {
        // /proc/<pid>/environ: NUL-delimited, with arbitrary whitespace in a
        // value. Treat every record as one assignment so a value containing
        // " HYSTERIA_LOG_LEVEL=debug" cannot masquerade as another variable.
        entries = text.split('\0');
    } else {
        // systemctl show Environment emits shell-style, whitespace-separated
        // assignments and quotes values containing spaces. Parse just enough
        // shell quoting/escaping to recover exact assignment tokens; never
        // search for a key inside another variable's value.
        entries = [];
        let token = '';
        let quote = '';
        let escaped = false;
        const push = () => {
            if (token) entries.push(token);
            token = '';
        };
        for (const character of text) {
            if (escaped) {
                token += character;
                escaped = false;
            } else if (character === '\\' && quote !== "'") {
                escaped = true;
            } else if (quote) {
                if (character === quote) quote = '';
                else token += character;
            } else if (character === '"' || character === "'") {
                quote = character;
            } else if (/\s/.test(character)) {
                push();
            } else {
                token += character;
            }
        }
        if (escaped) token += '\\';
        push();
    }

    const values = new Map();
    for (const rawEntry of entries) {
        const entry = String(rawEntry || '');
        const separator = entry.indexOf('=');
        if (separator <= 0) continue;
        const name = entry.slice(0, separator);
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
        values.set(name, entry.slice(separator + 1));
    }
    const level = String(values.get('HYSTERIA_LOG_LEVEL') || '').toLowerCase();
    const format = String(values.get('HYSTERIA_LOG_FORMAT') || '').toLowerCase();
    if (level !== 'debug' || format !== 'json') {
        throw new Error(`effective Hysteria logging environment must be debug/json (got ${level || 'unset'}/${format || 'unset'})`);
    }
}

async function waitForAgentAccessLogSourceReady(conn, options = {}) {
    const agentPort = Number(options.agentPort) || 62080;
    const protocol = options.useTls === false ? 'http' : 'https';
    const token = String(options.token || '');
    const attempts = Math.max(1, options.attempts === undefined ? 20 : Number(options.attempts));
    const delayMs = Math.max(0, options.delayMs === undefined ? 250 : Number(options.delayMs));
    const run = options.execCommand || execSSH;
    const expected = options.accessLogs || {};
    const authHeader = shellSingleQuote(`Authorization: Bearer ${token}`);
    const url = shellSingleQuote(`${protocol}://127.0.0.1:${agentPort}/info`);
    let lastError = 'source is not ready';

    for (let attempt = 0; attempt < attempts; attempt++) {
        const result = await run(
            conn,
            `curl --silent --show-error --fail --insecure --noproxy '*' --max-time 3 --header ${authHeader} ${url}`
        );
        if (result?.success) {
            try {
                const info = JSON.parse(String(result.output || '').trim());
                const status = info?.access_logs || {};
                const matches = status.enabled === true
                    && status.source === expected.source
                    && status.format === expected.format
                    && status.journal_unit === expected.journalUnit;
                if (matches && status.source_ready === true && !status.source_error) {
                    return status;
                }
                lastError = status.source_error
                    || `source status is enabled=${status.enabled === true}, ready=${status.source_ready === true}`;
            } catch (error) {
                lastError = `invalid cc-agent /info response: ${error.message}`;
            }
        } else {
            lastError = result?.output || result?.error || 'cc-agent /info request failed';
        }
        if (attempt + 1 < attempts && delayMs > 0) {
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    throw new Error(`cc-agent access-log source not ready: ${lastError}`);
}

function hasStructuredHysteriaStartupLog(output) {
    return String(output || '').split('\n').some(line => {
        try {
            const event = JSON.parse(line.trim());
            return event && typeof event === 'object'
                && typeof event.msg === 'string'
                && event.msg.length > 0;
        } catch (_) {
            return false;
        }
    });
}

async function removeHysteriaAccessLogOverride(conn, unit) {
    const overridePath = hysteriaAccessLogOverridePath(unit);
    const overrideDir = `/etc/systemd/system/${unit}.service.d`;
    const result = await execSSH(conn, `if [ -e ${overridePath} ] || [ -L ${overridePath} ]; then
    rm -f ${overridePath} || exit 1
fi
rmdir ${overrideDir} 2>/dev/null || true`);
    if (!result.success) {
        throw new Error(`cannot remove ${unit} logging drop-in: ${result.output || result.error}`);
    }
}

async function disableHysteriaAccessLogsRuntime(
    conn,
    preparedNode,
    token,
    accessLogs,
    manageAgent,
    log
) {
    const states = await inspectHysteriaSystemdUnits(conn);
    const preferred = ['hysteria-server', 'hysteria'].includes(accessLogs?.journalUnit)
        ? accessLogs.journalUnit : '';
    const selected = states.find(state => state.unit === preferred && state.exists)
        || states.find(state => state.active)
        || states.find(state => state.exists);
    const journalUnit = selected?.unit || preferred || 'hysteria-server';
    const errors = [];

    // Privacy first: stop future debug request events even when the agent is
    // missing/broken. Every cleanup action is attempted independently.
    for (const unit of ['hysteria-server', 'hysteria']) {
        try {
            await removeHysteriaAccessLogOverride(conn, unit);
        } catch (error) {
            errors.push(error.message);
        }
    }
    const reload = await execSSH(conn, 'systemctl daemon-reload');
    if (!reload.success) errors.push(`systemd daemon-reload failed: ${reload.output || reload.error}`);

    for (const state of states.filter(item => item.active)) {
        const restart = await execSSH(conn, `systemctl restart ${state.unit} && systemctl is-active ${state.unit} >/dev/null 2>&1`);
        if (!restart.success) {
            errors.push(`cannot restart ${state.unit}: ${restart.output || restart.error}`);
        }
    }
    if (!states.some(state => state.exists)) {
        errors.push('Neither hysteria-server.service nor hysteria.service exists');
    }

    if (manageAgent) {
        try {
            const xray = preparedNode.xray || {};
            const agentConfig = buildAgentConfig(
                preparedNode,
                token,
                xray.agentPort || 62080,
                xray.apiPort || 61000,
                xray.agentTls !== false,
                {
                    ...accessLogs,
                    enabled: false,
                    journalUnit,
                    ingestUrl: '',
                    ingestToken: '',
                }
            );
            const mkdir = await execSSH(conn, 'mkdir -p /etc/cc-agent /var/lib/cc-agent');
            if (!mkdir.success) throw new Error(mkdir.output || mkdir.error || 'cannot prepare cc-agent directories');
            await uploadFile(conn, JSON.stringify(agentConfig, null, 2), '/etc/cc-agent/config.json');
            const mode = await execSSH(conn, 'chmod 600 /etc/cc-agent/config.json');
            if (!mode.success) throw new Error(mode.output || mode.error || 'cannot protect cc-agent config');
            const restart = await execSSH(
                conn,
                'systemctl restart cc-agent && systemctl is-active cc-agent >/dev/null 2>&1'
            );
            if (!restart.success) throw new Error(restart.output || restart.error || 'cc-agent restart failed');
        } catch (error) {
            errors.push(`cannot disable cc-agent shipper: ${error.message}`);
        }
    }

    if (errors.length > 0) {
        throw new Error(`Hysteria access-log disable incomplete: ${errors.join('; ')}`);
    }
    log('disabled Hysteria JSON journal shipping');
    return { success: true, agentVersion: preparedNode.agentVersion || '', journalUnit };
}

/**
 * Reconcile Hysteria's structured journald source and the cc-agent shipper.
 * Existing HY2 nodes did not historically have an agent, so the first enable
 * can install/upgrade it over the same SSH connection. The Hysteria YAML is
 * deliberately untouched; only a reversible systemd drop-in controls logging.
 */
async function reconcileHysteriaAccessLogsUnlocked(node, accessLogs, options = {}) {
    if (node?.type !== 'hysteria') {
        throw new Error('Hysteria access-log reconcile requires a hysteria node');
    }
    if (!node.ssh?.password && !node.ssh?.privateKey) {
        throw new Error('SSH credentials are required to configure Hysteria access logs');
    }

    const ensured = await ensureNodeAgentToken(node);
    const preparedNode = ensured.node;
    const token = ensured.token;
    const xray = preparedNode.xray || {};
    const agentPort = xray.agentPort || 62080;
    const apiPort = xray.apiPort || 61000;
    const useTls = xray.agentTls !== false;
    const enabled = !!accessLogs?.enabled;
    const log = message => logger.info(`[AccessLogs] Node ${preparedNode.name}: ${message}`);

    let conn;
    let agentVersion = preparedNode.agentVersion || '';
    let journalUnit = '';
    let effectiveAccessLogs = null;
    let manageAgent = true;
    let runtimeMutated = false;
    try {
        conn = await connectSSH(preparedNode);
        try {
            await assertCcAgentConfigOwnership(conn, token);
        } catch (ownershipError) {
            if (enabled) throw ownershipError;
            // Disabling must still remove HY2 debug logging even if another
            // proxy now owns the host's singleton cc-agent. Leave that agent's
            // config/service untouched and clean only the Hysteria drop-in.
            manageAgent = false;
            log(`leaving shared cc-agent untouched during disable: ${ownershipError.message}`);
        }
        if (!enabled) {
            return await disableHysteriaAccessLogsRuntime(
                conn,
                preparedNode,
                token,
                accessLogs,
                manageAgent,
                log
            );
        }
        journalUnit = await detectHysteriaSystemdUnit(conn, accessLogs?.journalUnit);
        effectiveAccessLogs = { ...accessLogs, journalUnit };

        if (enabled) {
            const execStartResult = await execSSH(
                conn,
                `systemctl show ${journalUnit}.service --property=ExecStart --value`
            );
            if (!execStartResult.success) {
                throw new Error(`cannot inspect Hysteria ExecStart: ${execStartResult.output || execStartResult.error}`);
            }
            assertHysteriaExecStartLoggingCompatible(execStartResult.output);
        }

        if (manageAgent && options.installAgent) {
            runtimeMutated = true;
            const sameVps = isSameVpsAsPanel(preparedNode);
            const panelSource = resolvePanelFirewallSource();
            const installed = await installCCAgent(
                conn,
                preparedNode,
                token,
                panelSource,
                sameVps,
                log,
                effectiveAccessLogs
            );
            if (!installed.success) {
                throw new Error(`cc-agent installation failed: ${installed.output || 'unknown error'}`);
            }
            agentVersion = installed.agentVersion;
            if (options.minimumAgentVersion
                && !isAgentVersionAtLeast(agentVersion, options.minimumAgentVersion)) {
                throw new Error(`cc-agent ${options.minimumAgentVersion}+ required; downloaded ${agentVersion || 'unknown'}`);
            }
        } else if (manageAgent) {
            runtimeMutated = true;
            const agentConfig = buildAgentConfig(
                preparedNode,
                token,
                agentPort,
                apiPort,
                useTls,
                effectiveAccessLogs
            );
            const mkdirResult = await execSSH(conn, 'mkdir -p /etc/cc-agent /var/lib/cc-agent');
            if (!mkdirResult.success) {
                throw new Error(`cannot prepare cc-agent directories: ${mkdirResult.output || mkdirResult.error}`);
            }
            await uploadFile(conn, JSON.stringify(agentConfig, null, 2), '/etc/cc-agent/config.json');
            const chmodResult = await execSSH(conn, 'chmod 600 /etc/cc-agent/config.json');
            if (!chmodResult.success) {
                throw new Error(`cannot protect cc-agent config: ${chmodResult.output || chmodResult.error}`);
            }
        }

        const override = configGenerator.generateHysteriaAccessLogSystemdOverride(enabled);
        const overridePath = hysteriaAccessLogOverridePath(journalUnit);
        const overrideDir = `/etc/systemd/system/${journalUnit}.service.d`;
        runtimeMutated = true;
        if (override) {
            const alternateUnit = journalUnit === 'hysteria-server' ? 'hysteria' : 'hysteria-server';
            await removeHysteriaAccessLogOverride(conn, alternateUnit);
            const mkdirResult = await execSSH(conn, `mkdir -p ${overrideDir}`);
            if (!mkdirResult.success) {
                throw new Error(`cannot create Hysteria drop-in directory: ${mkdirResult.output || mkdirResult.error}`);
            }
            await uploadFile(conn, override, overridePath);
        } else {
            for (const unit of ['hysteria-server', 'hysteria']) {
                await removeHysteriaAccessLogOverride(conn, unit);
            }
        }

        const daemonReloadResult = await execSSH(conn, 'systemctl daemon-reload');
        if (!daemonReloadResult.success) {
            throw new Error(`systemd daemon-reload failed: ${daemonReloadResult.output || daemonReloadResult.error}`);
        }
        const effectiveEnvironment = await execSSH(
            conn,
            `systemctl show ${journalUnit}.service --property=Environment --value`
        );
        if (!effectiveEnvironment.success) {
            throw new Error(`cannot inspect Hysteria environment: ${effectiveEnvironment.output || effectiveEnvironment.error}`);
        }
        assertHysteriaEffectiveLoggingEnvironment(effectiveEnvironment.output);

        if (manageAgent) {
            const agentRestartResult = await execSSH(
                conn,
                'systemctl restart cc-agent && systemctl is-active cc-agent >/dev/null 2>&1'
            );
            if (!agentRestartResult.success) {
                throw new Error(`cc-agent restart failed: ${agentRestartResult.output || agentRestartResult.error}`);
            }
            await waitForAgentAccessLogSourceReady(conn, {
                agentPort,
                useTls,
                token,
                accessLogs: effectiveAccessLogs,
            });
        }

        const remoteClockResult = await execSSH(conn, 'date +%s');
        const remoteEpoch = Number.parseInt(remoteClockResult.output, 10);
        if (!remoteClockResult.success || !Number.isFinite(remoteEpoch)) {
            throw new Error(`cannot read node clock before Hysteria restart: ${remoteClockResult.output || remoteClockResult.error}`);
        }

        const restartResult = await execSSH(conn, `
systemctl restart ${journalUnit} || exit 1
for i in 1 2 3 4 5; do
    systemctl is-active ${journalUnit} >/dev/null 2>&1 && break
    sleep 1
done
systemctl is-active ${journalUnit} >/dev/null 2>&1 || exit 1
`);
        if (!restartResult.success) {
            throw new Error(`service restart failed: ${restartResult.output || restartResult.error}`);
        }

        if (enabled) {
            // systemctl show Environment does not include every EnvironmentFile,
            // UnsetEnvironment or `/usr/bin/env KEY=value` override. Validate
            // the environment of the process that is actually running so debug
            // request events cannot be silently suppressed by a later drop-in.
            const processEnvironment = await execSSH(conn, `
PID="$(systemctl show ${journalUnit}.service --property=MainPID --value)"
case "$PID" in ''|0|*[!0-9]*) exit 1 ;; esac
EXECUTABLE="$(readlink -f "/proc/$PID/exe")" || exit 1
EXPECTED_EXECUTABLE="$(systemctl show ${journalUnit}.service --property=ExecStart --value | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -n 1)"
[ -n "$EXPECTED_EXECUTABLE" ] || { echo "Cannot resolve Hysteria ExecStart path" >&2; exit 2; }
EXPECTED_EXECUTABLE="$(readlink -f "$EXPECTED_EXECUTABLE")" || exit 2
[ "$EXECUTABLE" = "$EXPECTED_EXECUTABLE" ] || {
    echo "MainPID executable does not match ExecStart: $EXECUTABLE != $EXPECTED_EXECUTABLE" >&2
    exit 2
}
case "$(basename "$EXECUTABLE")" in
    hysteria|hy2) ;;
    *) echo "MainPID does not run Hysteria directly: $EXECUTABLE" >&2; exit 2 ;;
esac
cat "/proc/$PID/environ"
`);
            if (!processEnvironment.success) {
                throw new Error(`cannot inspect running Hysteria environment: ${processEnvironment.output || processEnvironment.error}`);
            }
            assertHysteriaEffectiveLoggingEnvironment(processEnvironment.output);

            const journalResult = await execSSH(
                conn,
                `journalctl --unit=${journalUnit} --since=@${remoteEpoch} --lines=100 --output=cat --no-pager`
            );
            if (!journalResult.success || !hasStructuredHysteriaStartupLog(journalResult.output)) {
                throw new Error('Hysteria did not emit structured JSON logs; check custom log flags and journald');
            }
        }

        log(`${enabled ? 'enabled' : 'disabled'} Hysteria JSON journal shipping`);
        return { success: true, agentVersion, journalUnit };
    } catch (error) {
        if (enabled && runtimeMutated && conn) {
            // Enabling is transactional from the operator's perspective. If a
            // later restart/readiness check fails, best-effort restore a
            // disabled shipper and remove our debug drop-in so the node does
            // not keep collecting exact endpoints while the panel says error.
            try {
                if (manageAgent && effectiveAccessLogs) {
                    const disabledConfig = buildAgentConfig(
                        preparedNode,
                        token,
                        agentPort,
                        apiPort,
                        useTls,
                        { ...effectiveAccessLogs, enabled: false, ingestUrl: '', ingestToken: '' }
                    );
                    await uploadFile(conn, JSON.stringify(disabledConfig, null, 2), '/etc/cc-agent/config.json');
                    await execSSH(conn, 'chmod 600 /etc/cc-agent/config.json');
                }
                for (const unit of ['hysteria-server', 'hysteria']) {
                    await removeHysteriaAccessLogOverride(conn, unit);
                }
                const agentRollback = manageAgent
                    ? 'systemctl restart cc-agent >/dev/null 2>&1 || true' : '';
                await execSSH(conn, `systemctl daemon-reload >/dev/null 2>&1 || true
${agentRollback}
${journalUnit ? `systemctl restart ${journalUnit} >/dev/null 2>&1 || true` : ''}`);
                log('rolled back failed Hysteria access-log enable');
            } catch (rollbackError) {
                logger.error(`[AccessLogs] Node ${preparedNode.name}: rollback failed: ${rollbackError.message}`);
            }
        }
        throw error;
    } finally {
        if (conn) conn.end();
    }
}

function reconcileHysteriaAccessLogs(node, accessLogs, options = {}) {
    return enqueueCcAgentHostTask(
        node,
        () => reconcileHysteriaAccessLogsUnlocked(node, accessLogs, options)
    );
}

module.exports = {
    setupNode,
    checkNodeStatus,
    getNodeLogs,
    connectSSH,
    execSSH,
    uploadFile,
    readRemoteFileIfExists,
    assertCcAgentConfigContentOwnership,
    assertCcAgentConfigOwnership,
    assertNodeSshCcAgentConfigOwnership,
    ccAgentHostKey,
    enqueueCcAgentHostTask,
    setupXrayNode,
    setupXrayNodeWithAgent,
    installCCAgent,
    buildAgentConfig,
    reloadCcAgent,
    reconcileHysteriaAccessLogs,
    HYSTERIA_ACCESS_LOG_OVERRIDE_PATH,
    hysteriaAccessLogOverridePath,
    detectHysteriaSystemdUnit,
    inspectHysteriaSystemdUnits,
    assertHysteriaExecStartLoggingCompatible,
    assertHysteriaEffectiveLoggingEnvironment,
    waitForAgentAccessLogSourceReady,
    hasStructuredHysteriaStartupLog,
    removeHysteriaAccessLogOverride,
    disableHysteriaAccessLogsRuntime,
    resolveNodeServiceCandidates,
    stopNodeRuntime,
    startNodeRuntime,
    generateAgentToken,
    normalizeFirewallSource,
    resolvePanelFirewallSource,
    parseAgentVersion,
    isAgentVersionAtLeast,
    ensureNodeAgentToken,
    ensureXrayAgentToken,
    checkXrayNodeStatus,
    getXrayNodeLogs,
    getPanelCertificates,
    isSameVpsAsPanel,
};
