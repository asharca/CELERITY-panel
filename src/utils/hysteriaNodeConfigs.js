const { parsePortRange } = require('./portRange');

function getNodeConfigs(node, { allowPortHopping = true } = {}) {
    if (node.type !== 'hysteria') return [];

    const configs = [];
    const host = node.domain || node.ip;
    const sni = node.domain ? node.domain : (node.sni || '');
    const hasCert = !!node.domain;
    const hopInterval = node.hopInterval || '';
    const obfs = node.obfs?.type || '';
    const obfsPassword = node.obfs?.password || '';

    if (node.portConfigs && node.portConfigs.length > 0) {
        node.portConfigs.filter(config => config.enabled).forEach(config => {
            const parsedRange = allowPortHopping ? parsePortRange(config.portRange) : null;
            configs.push({
                name: config.name || `Port ${config.port}`,
                host,
                port: config.port,
                portRange: parsedRange?.normalized || '',
                hopInterval,
                sni,
                hasCert,
                obfs,
                obfsPassword,
            });
        });
    } else {
        configs.push({
            name: 'TLS',
            host,
            port: node.port || 443,
            portRange: '',
            hopInterval,
            sni,
            hasCert,
            obfs,
            obfsPassword,
        });

        const parsedRange = allowPortHopping ? parsePortRange(node.portRange) : null;
        if (parsedRange) {
            configs.push({
                name: 'Hopping',
                host,
                port: node.port || 443,
                portRange: parsedRange.normalized,
                hopInterval,
                sni,
                hasCert,
                obfs,
                obfsPassword,
            });
        }
    }

    return configs;
}

module.exports = { getNodeConfigs };
