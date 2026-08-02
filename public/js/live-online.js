(function initLiveOnline() {
    'use strict';

    const i18n = window.CelerityLiveOnlineI18n || {};
    const panel = document.getElementById('liveOnlinePanel');
    if (!panel) return;

    const rows = document.getElementById('liveOnlineRows');
    const status = document.getElementById('liveOnlineStatus');
    const age = document.getElementById('liveOnlineAge');
    const dot = document.getElementById('liveOnlineDot');
    const totalUsers = document.getElementById('onlineCount');
    const totalClients = document.getElementById('onlineConnections');

    let socket = null;
    let reconnectTimer = null;
    let fallbackTimer = null;
    let stopped = false;
    let lastSnapshot = null;

    function makeElement(tag, className, text) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text !== undefined) element.textContent = String(text);
        return element;
    }

    function setConnectionState(stateName, label) {
        dot.className = 'live-online-dot ' + stateName;
        status.textContent = label;
    }

    function updateAge() {
        if (!lastSnapshot?.generatedAt) {
            age.textContent = '';
            return;
        }
        const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(lastSnapshot.generatedAt)) / 1000));
        age.textContent = seconds < 2
            ? (i18n.updatedNow || 'now')
            : String(i18n.updatedSeconds || '{seconds}s ago').replace('{seconds}', seconds);
    }

    function updateNodeCounts(snapshot) {
        const nodeCounts = new Map(snapshot.nodes.map(node => [String(node.nodeId), node.onlineUsers]));
        document.querySelectorAll('[data-nodeid]').forEach(container => {
            const count = nodeCounts.get(String(container.dataset.nodeid));
            if (count === undefined) return;
            container.querySelectorAll('.online-count').forEach(cell => {
                const limit = cell.querySelector('.online-limit');
                cell.replaceChildren(document.createTextNode(String(count)));
                if (limit) cell.appendChild(limit);
            });
        });
    }

    function appendBadge(container, className, label) {
        container.appendChild(makeElement('span', 'live-presence-badge ' + className, label));
    }

    function renderPresenceRow(presence) {
        const row = document.createElement('tr');

        const userCell = document.createElement('td');
        const userWrap = makeElement('div', 'live-presence-user');
        userWrap.appendChild(makeElement('i', 'ti ti-user'));
        const userText = document.createElement('div');
        const userLink = makeElement('a', 'live-presence-name', presence.displayName);
        userLink.href = '/panel/users/' + encodeURIComponent(presence.userId);
        userText.appendChild(userLink);
        if (presence.displayName !== presence.userId) {
            userText.appendChild(makeElement('code', 'live-presence-id', presence.userId));
        }
        if (!presence.known) appendBadge(userText, 'unknown', i18n.unknownUser || 'Unknown');
        if (presence.enabled === false) appendBadge(userText, 'disabled', i18n.disabled || 'Disabled');
        if (presence.stale) appendBadge(userText, 'stale', i18n.stale || 'Stale');
        userWrap.appendChild(userText);
        userCell.appendChild(userWrap);

        const nodeCell = document.createElement('td');
        const nodeWrap = makeElement('div', 'live-presence-node');
        if (presence.nodeFlag) nodeWrap.appendChild(makeElement('span', 'live-presence-flag', presence.nodeFlag));
        nodeWrap.appendChild(makeElement('span', '', presence.nodeName));
        nodeCell.appendChild(nodeWrap);

        const clientsCell = makeElement('td', 'live-presence-clients', presence.clientInstances);
        clientsCell.title = i18n.clients || 'Clients';

        row.append(userCell, nodeCell, clientsCell);
        return row;
    }

    function renderSnapshot(snapshot) {
        if (!snapshot || !Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.presences)) return;
        if (!snapshot.version) return;

        lastSnapshot = snapshot;
        totalUsers.textContent = String(snapshot.totals.distinctUsers || 0);
        totalClients.textContent = String(snapshot.totals.clientInstances || 0);
        updateNodeCounts(snapshot);

        const content = document.createDocumentFragment();
        if (snapshot.presences.length === 0) {
            const emptyRow = makeElement('tr', 'live-online-empty');
            const emptyCell = makeElement('td', '', i18n.empty || 'No users online');
            emptyCell.colSpan = 3;
            emptyRow.appendChild(emptyCell);
            content.appendChild(emptyRow);
        } else {
            snapshot.presences.forEach(presence => content.appendChild(renderPresenceRow(presence)));
        }
        rows.replaceChildren(content);

        setConnectionState(
            snapshot.partial ? 'partial' : 'connected',
            snapshot.partial ? (i18n.partial || 'Partial') : (i18n.connected || 'Live')
        );
        updateAge();
    }

    async function fetchSnapshot() {
        try {
            const response = await fetch('/panel/presence', {
                credentials: 'include',
                cache: 'no-store',
                headers: { Accept: 'application/json' },
            });
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const payload = await response.json();
            if (payload.success && payload.snapshot) renderSnapshot(payload.snapshot);
        } catch (_) {
            setConnectionState('disconnected', i18n.reconnecting || 'Reconnecting');
        }
    }

    function stopFallback() {
        if (fallbackTimer) clearTimeout(fallbackTimer);
        fallbackTimer = null;
    }

    function scheduleFallback(delayMs) {
        stopFallback();
        if (stopped) return;
        fallbackTimer = setTimeout(async () => {
            await fetchSnapshot();
            scheduleFallback(Math.max(2000, lastSnapshot?.intervalMs || 2000));
        }, delayMs);
    }

    function connect() {
        if (stopped) return;
        setConnectionState('connecting', i18n.connecting || 'Connecting');
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        socket = new WebSocket(protocol + '//' + window.location.host + '/ws/presence');

        socket.addEventListener('open', () => {
            stopFallback();
            if (!lastSnapshot) setConnectionState('connected', i18n.connected || 'Live');
        });
        socket.addEventListener('message', event => {
            try {
                const message = JSON.parse(event.data);
                if (message.type === 'presence') renderSnapshot(message.snapshot);
            } catch (_) {
                setConnectionState('partial', i18n.partial || 'Partial');
            }
        });
        socket.addEventListener('close', () => {
            if (stopped) return;
            setConnectionState('disconnected', i18n.reconnecting || 'Reconnecting');
            scheduleFallback(0);
            clearTimeout(reconnectTimer);
            reconnectTimer = setTimeout(connect, 3000);
        });
        socket.addEventListener('error', () => socket.close());
    }

    window.refreshLiveOnline = fetchSnapshot;
    window.addEventListener('beforeunload', () => {
        stopped = true;
        stopFallback();
        clearTimeout(reconnectTimer);
        if (socket) socket.close();
    });
    setInterval(updateAge, 1000);
    connect();
}());
