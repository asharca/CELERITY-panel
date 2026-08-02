require('dotenv').config();

// Required environment variables check
const requiredEnv = ['PANEL_DOMAIN', 'ACME_EMAIL', 'ENCRYPTION_KEY', 'SESSION_SECRET'];
for (const key of requiredEnv) {
    if (!process.env[key]) {
        console.error(`[Config] Error: ${key} is required`);
        console.error('[Config] Copy docker.env.example to .env and configure');
        process.exit(1);
    }
}

if (process.env.ENCRYPTION_KEY.length < 32) {
    console.error('[Config] Error: ENCRYPTION_KEY must be at least 32 characters');
    process.exit(1);
}

module.exports = {
    PANEL_DOMAIN: process.env.PANEL_DOMAIN,
    ACME_EMAIL: process.env.ACME_EMAIL,
    BASE_URL: `https://${process.env.PANEL_DOMAIN}`,
    MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/hysteria',
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY,
    SESSION_SECRET: process.env.SESSION_SECRET,
    PANEL_IP_WHITELIST: process.env.PANEL_IP_WHITELIST || '',
    SYNC_INTERVAL: parseInt(process.env.SYNC_INTERVAL) || 2,
    API_DOCS_ENABLED: process.env.API_DOCS_ENABLED === 'true',
    DEFAULT_NODE_CONFIG: {
        portRange: '',
        mainPort: 443,
        statsPort: 9999,
    },
};
