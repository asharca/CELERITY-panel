/**
 * SSH Connection Pool Service
 * 
 * Optimizations:
 * - Connection reuse (saves ~200-500ms on handshake)
 * - Lazy connection (created on first request)
 * - Auto-cleanup of idle connections (memory release)
 * - Keepalive to maintain connections through NAT
 * - Auto-reconnect on disconnect
 * - Graceful shutdown
 */

const { Client } = require('ssh2');
const crypto = require('crypto');
const logger = require('../utils/logger');
const cryptoService = require('./cryptoService');

class SSHPool {
    constructor() {
        // Connection pool: nodeId -> { client, meta }
        this.connections = new Map();
        
        // Default settings (will be updated from DB)
        this.config = {
            enabled: true,
            maxIdleTime: 2 * 60 * 1000,      // 2 min idle → close
            keepAliveInterval: 30000,         // keepalive every 30 sec
            connectTimeout: 15000,            // connection timeout
            maxRetries: 2,                    // reconnect attempts
            cleanupInterval: 30000,           // idle check every 30 sec
        };
        
        this.settingsLoaded = false;
        
        // Cleanup timer
        this.cleanupTimer = setInterval(() => this.cleanup(), this.config.cleanupInterval);
        
        // Graceful shutdown
        const shutdown = () => this.closeAll();
        process.once('SIGTERM', shutdown);
        process.once('SIGINT', shutdown);
        
        logger.info('[SSHPool] Initialized');
    }
    
    /**
     * Load settings from database
     */
    async loadSettings() {
        try {
            const Settings = require('../models/settingsModel');
            const settings = await Settings.get();
            
            if (settings?.sshPool) {
                this.config.enabled = settings.sshPool.enabled !== false;
                this.config.maxIdleTime = (settings.sshPool.maxIdleTime || 120) * 1000;
                this.config.keepAliveInterval = (settings.sshPool.keepAliveInterval || 30) * 1000;
                this.config.connectTimeout = (settings.sshPool.connectTimeout || 15) * 1000;
                this.config.maxRetries = settings.sshPool.maxRetries || 2;
                
                logger.info(`[SSHPool] Settings loaded: enabled=${this.config.enabled}, idle=${settings.sshPool.maxIdleTime}s`);
            }
            
            this.settingsLoaded = true;
        } catch (error) {
            logger.warn(`[SSHPool] Failed to load settings: ${error.message}`);
        }
    }
    
    /**
     * Check if pool is enabled
     */
    isEnabled() {
        return this.config.enabled;
    }

    connectionIdentity(node) {
        const ssh = node?.ssh || {};
        return crypto.createHash('sha256').update(JSON.stringify([
            String(node?.ip || ''),
            Number(ssh.port) || 22,
            String(ssh.username || 'root'),
            String(ssh.privateKey || ''),
            String(ssh.password || ''),
        ])).digest('hex');
    }
    
    /**
     * Get or create connection
     * @param {Object} node - node object with ssh credentials
     * @returns {Client} - SSH client
     */
    async getConnection(node) {
        // Load settings on first request
        if (!this.settingsLoaded) {
            await this.loadSettings();
        }
        
        // If pool disabled, throw to trigger direct connection
        if (!this.config.enabled) {
            throw new Error('SSH Pool disabled');
        }
        
        const nodeId = node._id?.toString() || node.id;
        let existing = this.connections.get(nodeId);
        const identity = this.connectionIdentity(node);

        // A node may move hosts or rotate SSH credentials while a pooled
        // socket is alive. Never reuse that socket for the new runtime: doing
        // so can upload teardown/config files to the wrong server and falsely
        // "verify" credentials that were never used.
        if (existing && existing.identity !== identity) {
            this.removeConnection(nodeId, 'target or credential changed');
            existing = null;
        }
        
        // 1. Handshake in progress for this node - reuse the same promise
        //    (issue #70: prevents parallel handshakes during the race window
        //    between createConnection() and its 'ready' handler).
        if (existing && existing.connecting && existing.promise) {
            return existing.promise;
        }
        
        // 2. Alive connection - reuse.
        if (existing && existing.client && existing.client._sock?.writable) {
            existing.lastUsed = Date.now();
            existing.useCount++;
            return existing.client;
        }
        
        // 3. Dead connection - cleanup before creating a new one.
        if (existing) {
            this.removeConnection(nodeId, 'dead');
        }
        
        // createConnection registers its own placeholder (with client identity)
        // so all event handlers can verify they are still the active attempt.
        return this.createConnection(node);
    }
    
    /**
     * Create new SSH connection.
     *
     * Registers a placeholder { connecting, client, promise } in this.connections
     * BEFORE calling .connect(). All event handlers verify that the registered
     * entry still references THIS specific Client instance before mutating
     * this.connections — this prevents late 'close'/'end' events from a prior
     * (already-terminated) connection from clobbering a newly-registered
     * placeholder for the same nodeId.
     */
    createConnection(node, retryCount = 0) {
        const nodeId = node._id?.toString() || node.id;
        const nodeName = node.name || nodeId;
        const identity = this.connectionIdentity(node);
        
        let resolveOuter;
        let rejectOuter;
        const outerPromise = new Promise((resolve, reject) => {
            resolveOuter = resolve;
            rejectOuter = reject;
        });
        
        const client = new Client();
        
        // Connection timeout (covers cases where ssh2 emits no error event)
        const timeout = setTimeout(() => {
            try { client.end(); } catch (e) {}
            rejectOuter(new Error(`Connection timeout (${this.config.connectTimeout}ms)`));
        }, this.config.connectTimeout);
        
        const sshConfig = {
            host: node.ip,
            port: node.ssh?.port || 22,
            username: node.ssh?.username || 'root',
            readyTimeout: this.config.connectTimeout,
            keepaliveInterval: this.config.keepAliveInterval,
            keepaliveCountMax: 3,
        };
        
        if (node.ssh?.privateKey) {
            sshConfig.privateKey = cryptoService.decryptPrivateKey(node.ssh.privateKey);
        } else if (node.ssh?.password) {
            sshConfig.password = cryptoService.decryptSafe(node.ssh.password);
        } else {
            clearTimeout(timeout);
            rejectOuter(new Error('SSH: no key or password'));
            return outerPromise;
        }
        
        // Register placeholder with client identity so every handler
        // can verify ownership before mutating this.connections.
        this.connections.set(nodeId, {
            connecting: true,
            client,
            promise: outerPromise,
            identity,
            lastUsed: Date.now(),
        });
        
        client
            .on('ready', () => {
                clearTimeout(timeout);
                
                // Promote placeholder to full meta only if WE are still
                // the registered attempt for this nodeId.
                const cur = this.connections.get(nodeId);
                if (!cur || cur.client === client) {
                    this.connections.set(nodeId, {
                        client,
                        nodeId,
                        nodeName,
                        host: node.ip,
                        identity,
                        createdAt: Date.now(),
                        lastUsed: Date.now(),
                        useCount: 1,
                    });
                }
                
                logger.info(`[SSHPool] ✓ Connected: ${nodeName} (${node.ip}) [pool: ${this.connections.size}]`);
                resolveOuter(client);
            })
            .on('error', async (err) => {
                clearTimeout(timeout);
                
                // Identity-aware delete: never touch another attempt's entry.
                const cur = this.connections.get(nodeId);
                if (cur && cur.client === client) {
                    this.connections.delete(nodeId);
                }
                
                if (retryCount < this.config.maxRetries) {
                    const delay = Math.pow(2, retryCount) * 500;
                    logger.warn(`[SSHPool] ${nodeName}: retry ${retryCount + 1}/${this.config.maxRetries} in ${delay}ms`);
                    
                    await new Promise(r => setTimeout(r, delay));
                    
                    try {
                        const newClient = await this.createConnection(node, retryCount + 1);
                        resolveOuter(newClient);
                    } catch (retryErr) {
                        rejectOuter(retryErr);
                    }
                } else {
                    logger.error(`[SSHPool] ✗ Failed: ${nodeName} - ${err.message}`);
                    rejectOuter(err);
                }
            })
            .on('close', () => {
                // Late 'close' from a terminated connection must not
                // clobber a newly-registered attempt for the same nodeId.
                const cur = this.connections.get(nodeId);
                if (cur && cur.client === client) {
                    this.removeConnection(nodeId, 'closed');
                }
            })
            .on('end', () => {
                const cur = this.connections.get(nodeId);
                if (cur && cur.client === client) {
                    this.removeConnection(nodeId, 'ended');
                }
            });
        
        // ssh2's .connect() can throw synchronously on invalid configs
        // (bad host, unparseable key). Without this guard the outerPromise
        // would stay pending and the placeholder would leak until cleanup.
        try {
            client.connect(sshConfig);
        } catch (err) {
            clearTimeout(timeout);
            const cur = this.connections.get(nodeId);
            if (cur && cur.client === client) {
                this.connections.delete(nodeId);
            }
            rejectOuter(err);
        }
        
        return outerPromise;
    }
    
    /**
     * Remove connection from pool
     */
    removeConnection(nodeId, reason = 'unknown') {
        const conn = this.connections.get(nodeId);
        if (conn) {
            try {
                conn.client.end();
            } catch (e) {}
            this.connections.delete(nodeId);
            logger.debug(`[SSHPool] Removed: ${conn.nodeName || nodeId} (${reason})`);
        }
    }
    
    /**
     * Execute command with auto-reconnect
     */
    async exec(node, command, options = {}) {
        const client = await this.getConnection(node);
        const nodeId = node._id?.toString() || node.id;
        
        return new Promise((resolve, reject) => {
            const execTimeout = options.timeout || 30000;
            
            const timer = setTimeout(() => {
                reject(new Error(`Exec timeout (${execTimeout}ms): ${command.substring(0, 50)}`));
            }, execTimeout);
            
            client.exec(command, (err, stream) => {
                if (err) {
                    clearTimeout(timer);
                    // Connection broken - remove from pool
                    this.removeConnection(nodeId, 'exec error');
                    reject(err);
                    return;
                }
                
                let stdout = '';
                let stderr = '';
                
                stream
                    .on('close', (code) => {
                        clearTimeout(timer);
                        resolve({ code, stdout, stderr });
                    })
                    .on('data', (data) => {
                        stdout += data.toString();
                    })
                    .stderr.on('data', (data) => {
                        stderr += data.toString();
                    });
            });
        });
    }
    
    /**
     * Write file via SFTP
     */
    async writeFile(node, remotePath, content) {
        const client = await this.getConnection(node);
        const nodeId = node._id?.toString() || node.id;
        
        return new Promise((resolve, reject) => {
            client.sftp((err, sftp) => {
                if (err) {
                    this.removeConnection(nodeId, 'sftp error');
                    reject(err);
                    return;
                }
                
                const writeStream = sftp.createWriteStream(remotePath);
                
                writeStream
                    .on('close', () => {
                        logger.debug(`[SSHPool] Written: ${remotePath}`);
                        resolve();
                    })
                    .on('error', (err) => {
                        reject(err);
                    });
                
                writeStream.write(content);
                writeStream.end();
            });
        });
    }
    
    /**
     * Read file via SFTP
     */
    async readFile(node, remotePath) {
        const client = await this.getConnection(node);
        const nodeId = node._id?.toString() || node.id;
        
        return new Promise((resolve, reject) => {
            client.sftp((err, sftp) => {
                if (err) {
                    this.removeConnection(nodeId, 'sftp error');
                    reject(err);
                    return;
                }
                
                let content = '';
                const readStream = sftp.createReadStream(remotePath);
                
                readStream
                    .on('data', (data) => {
                        content += data.toString();
                    })
                    .on('close', () => {
                        resolve(content);
                    })
                    .on('error', (err) => {
                        reject(err);
                    });
            });
        });
    }
    
    /**
     * Check if connection exists in pool and is alive
     */
    hasConnection(nodeId) {
        const conn = this.connections.get(nodeId?.toString());
        return conn && conn.client._sock?.writable;
    }
    
    /**
     * Close specific connection
     */
    async close(nodeId) {
        this.removeConnection(nodeId?.toString(), 'manual');
    }
    
    /**
     * Cleanup idle connections
     */
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [nodeId, conn] of this.connections) {
            const idleTime = now - conn.lastUsed;
            
            if (idleTime > this.config.maxIdleTime) {
                this.removeConnection(nodeId, `idle ${Math.round(idleTime / 1000)}s`);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            logger.info(`[SSHPool] Cleanup: ${cleaned} idle connections removed [pool: ${this.connections.size}]`);
        }
    }
    
    /**
     * Close all connections
     */
    closeAll() {
        logger.info(`[SSHPool] Shutting down (${this.connections.size} connections)`);
        
        clearInterval(this.cleanupTimer);
        
        for (const [nodeId, conn] of this.connections) {
            try {
                conn.client.end();
            } catch (e) {}
        }
        
        this.connections.clear();
    }
    
    /**
     * Pool statistics
     */
    getStats() {
        const now = Date.now();
        const connections = [];
        
        for (const [nodeId, conn] of this.connections) {
            connections.push({
                nodeId,
                name: conn.nodeName || nodeId,
                host: conn.host || '',
                alive: conn.client?._sock?.writable || false,
                connecting: !!conn.connecting,
                idleMs: now - (conn.lastUsed || now),
                useCount: conn.useCount || 0,
                uptimeMs: conn.createdAt ? now - conn.createdAt : 0,
            });
        }
        
        return {
            enabled: this.config.enabled,
            total: this.connections.size,
            config: {
                maxIdleTimeSec: this.config.maxIdleTime / 1000,
                keepAliveIntervalSec: this.config.keepAliveInterval / 1000,
                connectTimeoutSec: this.config.connectTimeout / 1000,
                maxRetries: this.config.maxRetries,
            },
            connections,
        };
    }
    
    /**
     * Reload settings from database
     */
    async reloadSettings() {
        this.settingsLoaded = false;
        await this.loadSettings();
    }
}

// Singleton (settings loaded from DB on first use)
module.exports = new SSHPool();
