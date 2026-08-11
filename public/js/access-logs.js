// Access-log explorer: task-first filtering, resilient analytics, paged events,
// and collection-pipeline diagnostics. The API intentionally treats parsed
// analytics and raw diagnostic rows as separate (but concurrently loaded) views.
(function () {
    'use strict';

    const app = document.getElementById('accessLogsApp');
    if (!app || app.dataset.enabled !== '1') return;

    const I18N = window.__AL_I18N || {};
    const L = I18N.labels || {};
    const NODES = window.__AL_NODES || {};
    const FILTER_MAP = {
        q: 'alQuery',
        from: 'alFrom',
        to: 'alTo',
        nodeId: 'alNode',
        email: 'alEmail',
        sourceIp: 'alSourceIp',
        destination: 'alDest',
        network: 'alNetwork',
        action: 'alAction',
    };
    const ADVANCED_FILTERS = ['nodeId', 'sourceIp', 'network'];
    const SEARCH_PAGE_SIZE = 100;
    const numberFormatter = new Intl.NumberFormat(I18N.locale || undefined);
    const percentFormatter = new Intl.NumberFormat(I18N.locale || undefined, {
        maximumFractionDigits: 1,
    });
    const dateTimeFormatter = new Intl.DateTimeFormat(I18N.locale || undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    });
    const compactDateFormatter = new Intl.DateTimeFormat(I18N.locale || undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
    const reducedMotion = window.matchMedia
        ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
        : false;
    const $ = (id) => document.getElementById(id);

    let busyCount = 0;
    let refreshGeneration = 0;
    let analyticsController = null;
    let searchController = null;
    let timelineChart = null;
    let searchRows = [];
    let searchHasMore = false;
    let currentFilterParams = new URLSearchParams();

    function escapeHtml(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, (character) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
        }[character]));
    }

    function interpolate(template, values) {
        return String(template || '').replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) => (
            Object.prototype.hasOwnProperty.call(values || {}, key) ? String(values[key]) : match
        ));
    }

    function setHidden(element, hidden) {
        if (element) element.hidden = !!hidden;
    }

    function announce(message) {
        const live = $('alLive');
        if (!live) return;
        live.textContent = '';
        window.setTimeout(() => { live.textContent = message || ''; }, 20);
    }

    function toast(message, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type);
            return;
        }
        const element = $('toast');
        if (!element) return;
        element.textContent = message;
        element.className = `toast show ${type || ''}`;
        window.setTimeout(() => { element.className = 'toast'; }, 3500);
    }

    function setBusy(isBusy) {
        busyCount = Math.max(0, busyCount + (isBusy ? 1 : -1));
        const busy = busyCount > 0;
        const progress = $('alProgress');
        const searchButton = $('alSearchBtn');
        const searchIcon = $('alSearchIcon');
        if (progress) progress.classList.toggle('active', busy);
        app.setAttribute('aria-busy', String(busy));
        if (searchButton) searchButton.disabled = busy;
        if (searchIcon) searchIcon.className = busy ? 'ti ti-loader-2 al-spin' : 'ti ti-search';
    }

    async function getJson(url, options) {
        setBusy(true);
        try {
            const response = await fetch(url, {
                credentials: 'include',
                ...(options || {}),
            });
            let data = null;
            try {
                data = await response.json();
            } catch (_) {
                data = {};
            }
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            return data;
        } finally {
            setBusy(false);
        }
    }

    function formatNumber(value) {
        const number = Number(value);
        return numberFormatter.format(Number.isFinite(number) ? number : 0);
    }

    function formatPercent(value) {
        const number = Number(value);
        return `${percentFormatter.format(Number.isFinite(number) ? number * 100 : 0)}%`;
    }

    function formatBytes(value) {
        let number = Number(value);
        if (!Number.isFinite(number) || number < 0) number = 0;
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let index = 0;
        while (number >= 1024 && index < units.length - 1) {
            number /= 1024;
            index += 1;
        }
        return `${numberFormatter.format(Number(number.toFixed(index ? 1 : 0)))} ${units[index]}`;
    }

    // ClickHouse rows use epoch seconds; node status may use ISO timestamps.
    // Reject ambiguous date strings instead of letting Date guess a local zone.
    function parseTimestamp(value) {
        if (value == null || value === '') return null;
        if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
        if (typeof value === 'number' || /^\d+$/.test(String(value))) {
            let numeric = Number(value);
            if (!Number.isFinite(numeric)) return null;
            if (numeric < 1e11) numeric *= 1000;
            const date = new Date(numeric);
            return Number.isNaN(date.getTime()) ? null : date;
        }
        const string = String(value);
        if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(string)) {
            const date = new Date(`${string.replace(' ', 'T')}Z`);
            return Number.isNaN(date.getTime()) ? null : date;
        }
        if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(string)) {
            const date = new Date(string);
            return Number.isNaN(date.getTime()) ? null : date;
        }
        return null;
    }

    function formatTime(value) {
        const date = parseTimestamp(value);
        return date ? dateTimeFormatter.format(date) : (value ? String(value) : (I18N.never || '—'));
    }

    function formatCompactTime(value) {
        const date = parseTimestamp(value);
        return date ? compactDateFormatter.format(date) : '—';
    }

    function localInputValue(date) {
        const localDate = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
        return localDate.toISOString().slice(0, 16);
    }

    function endpoint(host, port) {
        const cleanHost = String(host || '');
        const cleanPort = Number(port) || 0;
        if (!cleanHost) return cleanPort ? String(cleanPort) : '';
        const displayHost = cleanHost.includes(':') && !cleanHost.startsWith('[')
            ? `[${cleanHost}]`
            : cleanHost;
        return cleanPort ? `${displayHost}:${cleanPort}` : cleanHost;
    }

    function nodeName(id) {
        return NODES[String(id)] || id || '—';
    }

    function actionLabel(value) {
        return L[value] || value || L.unknown || '—';
    }

    function actionBadge(value) {
        const action = String(value || '');
        if (!action) return '<span class="al-badge">—</span>';
        const className = ['accepted', 'rejected', 'blocked'].includes(action)
            ? ` al-badge-${action}`
            : '';
        return `<span class="al-badge${className}">${escapeHtml(actionLabel(action))}</span>`;
    }

    function networkBadge(value) {
        const network = String(value || '').toLowerCase();
        if (!network) return '<span class="al-badge">—</span>';
        const className = network === 'udp' ? ' al-badge-udp' : ' al-badge-net';
        return `<span class="al-badge${className}">${escapeHtml(L[network] || network.toUpperCase())}</span>`;
    }

    function setDefaultRange() {
        const from = $('alFrom');
        const to = $('alTo');
        if (!from) return;
        from.value = localInputValue(new Date(Date.now() - 24 * 60 * 60 * 1000));
        if (to) to.value = '';
    }

    function setQuickRange(hours) {
        const from = $('alFrom');
        const to = $('alTo');
        if (!from) return;
        from.value = localInputValue(new Date(Date.now() - Number(hours) * 60 * 60 * 1000));
        if (to) to.value = '';
        updateRangeButtons(Number(hours));
    }

    function updateRangeButtons(forcedHours) {
        let activeHours = forcedHours || null;
        const from = $('alFrom');
        const to = $('alTo');
        if (!activeHours && from && from.value && (!to || !to.value)) {
            const hours = (Date.now() - new Date(from.value).getTime()) / 3600000;
            [24, 168, 720].forEach((candidate) => {
                if (Math.abs(hours - candidate) < 0.12) activeHours = candidate;
            });
        }
        document.querySelectorAll('.al-range-btn').forEach((button) => {
            const active = Number(button.dataset.hours) === activeHours;
            button.classList.toggle('active', active);
            button.setAttribute('aria-pressed', String(active));
        });
    }

    function hydrateFiltersFromLocation() {
        const params = new URLSearchParams(window.location.search);
        Object.entries(FILTER_MAP).forEach(([key, id]) => {
            const input = $(id);
            const value = params.get(key);
            if (!input || !value) return;
            if (key === 'from' || key === 'to') {
                const date = new Date(value);
                if (!Number.isNaN(date.getTime())) input.value = localInputValue(date);
            } else {
                input.value = value;
            }
        });
    }

    function collectFilterParams() {
        const params = new URLSearchParams();
        let fromDate = null;
        let toDate = null;
        Object.entries(FILTER_MAP).forEach(([key, id]) => {
            const input = $(id);
            const value = input ? String(input.value || '').trim() : '';
            if (!value) return;
            if (key === 'from' || key === 'to') {
                const date = new Date(value);
                if (Number.isNaN(date.getTime())) return;
                if (key === 'to') date.setTime(date.getTime() + 59999);
                if (key === 'from') fromDate = date;
                else toDate = date;
                params.set(key, date.toISOString());
            } else {
                params.set(key, value);
            }
        });
        if (fromDate && toDate && fromDate.getTime() > toDate.getTime()) return null;
        return params;
    }

    function updateUrl(params) {
        const url = new URL(window.location.href);
        [...Object.keys(FILTER_MAP), 'limit', 'offset'].forEach((key) => url.searchParams.delete(key));
        params.forEach((value, key) => url.searchParams.set(key, value));
        window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
    }

    function updateRangeSummary() {
        const summary = $('alRangeSummary');
        const from = $('alFrom');
        const to = $('alTo');
        if (!summary || !from || !from.value) return;
        const fromText = formatCompactTime(new Date(from.value));
        if (to && to.value) {
            summary.textContent = interpolate(I18N.rangeBetween, {
                from: fromText,
                to: formatCompactTime(new Date(to.value)),
            });
        } else {
            summary.textContent = interpolate(I18N.rangeUntilNow, { from: fromText });
        }
    }

    function displayFilterValue(key, value) {
        if (key === 'nodeId') return nodeName(value);
        if (key === 'action' || key === 'network') return L[value] || value.toUpperCase();
        return value;
    }

    function updateActiveFilters() {
        const container = $('alActiveFilters');
        if (!container) return;
        container.replaceChildren();
        const chips = [];
        Object.entries(FILTER_MAP).forEach(([key, id]) => {
            if (key === 'from' || key === 'to') return;
            const input = $(id);
            const value = input ? String(input.value || '').trim() : '';
            if (!value) return;
            const label = L[key] || key;
            const displayValue = displayFilterValue(key, value);
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'al-filter-chip';
            button.dataset.filter = key;
            button.setAttribute('aria-label', interpolate(I18N.removeFilter, { label }));
            const text = document.createElement('span');
            text.textContent = interpolate(I18N.activeFilter, { label, value: displayValue });
            const icon = document.createElement('i');
            icon.className = 'ti ti-x';
            icon.setAttribute('aria-hidden', 'true');
            button.append(text, icon);
            chips.push(button);
        });
        chips.forEach((chip) => container.appendChild(chip));
        setHidden(container, !chips.length);

        const advancedCount = ADVANCED_FILTERS.filter((key) => {
            const input = $(FILTER_MAP[key]);
            return input && input.value;
        }).length;
        const count = $('alAdvancedCount');
        if (count) {
            count.textContent = advancedCount ? formatNumber(advancedCount) : '';
            setHidden(count, !advancedCount);
        }
        const advanced = $('alAdvancedFilters');
        if (advancedCount && advanced) advanced.open = true;
        updateRangeSummary();
        updateRangeButtons();
    }

    function showFilterError(message) {
        const error = $('alFilterError');
        if (!error) return;
        error.textContent = message || '';
        setHidden(error, !message);
        if (message) error.focus?.();
    }

    function emptyRow(columnCount) {
        return `<tr><td class="al-empty" colspan="${columnCount}">—</td></tr>`;
    }

    function messageRow(columnCount, message) {
        return `<tr><td class="al-empty al-query-warning" colspan="${columnCount}">${escapeHtml(message || '—')}</td></tr>`;
    }

    function skeletonRow(columnCount) {
        return `<tr>${Array.from({ length: columnCount }, () => '<td><span class="al-skel"></span></td>').join('')}</tr>`;
    }

    function paintSkeletons() {
        ['alTotal', 'alUsers', 'alIps', 'alDests', 'alRisk'].forEach((id) => {
            const element = $(id);
            if (element) element.innerHTML = '<span class="al-skel"></span>';
        });
        const tables = {
            alResults: 7,
            alUsersByIp: 4,
            alUsersByFanout: 4,
            alTopDest: 2,
            alTopPorts: 2,
            alTopBlocked: 2,
        };
        Object.entries(tables).forEach(([id, columns]) => {
            const body = $(id);
            if (body) body.innerHTML = Array.from({ length: id === 'alResults' ? 6 : 4 }, () => skeletonRow(columns)).join('');
        });
    }

    function prepareRefreshSurfaces() {
        searchRows = [];
        searchHasMore = false;
        const results = $('alResults');
        if (results) results.innerHTML = Array.from({ length: 6 }, () => skeletonRow(7)).join('');
        setHidden($('alEventsTableWrap'), false);
        setHidden($('alNoResults'), true);
        setHidden($('alLoadMore'), true);
        const resultCount = $('alResultCount');
        if (resultCount) resultCount.textContent = '';

        ['alTotal', 'alUsers', 'alIps', 'alDests', 'alRisk'].forEach((id) => {
            const element = $(id);
            if (element) element.innerHTML = '<span class="al-skel"></span>';
        });
        setHidden($('alAnalyticsContent'), true);
        setHidden($('alAnalyticsEmpty'), true);
    }

    function renderEvents(rows) {
        const body = $('alResults');
        if (!body) return;
        body.innerHTML = rows.map((row) => {
            const unparsed = Number(row.parse_ok) === 0 || row.parse_ok === false;
            const source = endpoint(row.source_ip, row.source_port);
            const destination = endpoint(row.dest_host || row.dest_ip, row.dest_port);
            const raw = String(row.raw || '');
            const destinationCell = unparsed
                ? `<span class="al-raw-line" title="${escapeHtml(raw)}">${escapeHtml(raw || I18N.unparsed)}</span>`
                : `<span class="al-endpoint" title="${escapeHtml(destination)}">${escapeHtml(destination || '—')}</span>`;
            const userCell = unparsed
                ? `<span class="al-badge al-badge-unparsed">${escapeHtml(I18N.unparsed)}</span>`
                : escapeHtml(row.email || '—');
            return `<tr class="${unparsed ? 'al-event-unparsed' : ''}">
                <td class="al-time" data-label="${escapeHtml(L.time)}">${escapeHtml(formatTime(row.ts))}</td>
                <td data-label="${escapeHtml(L.node)}">${escapeHtml(nodeName(row.node_id))}</td>
                <td data-label="${escapeHtml(L.user)}">${userCell}</td>
                <td class="al-mono" data-label="${escapeHtml(L.source)}" title="${escapeHtml(source)}">${escapeHtml(source || '—')}</td>
                <td class="al-mono al-destination-cell" data-label="${escapeHtml(L.destinationLabel)}">${destinationCell}</td>
                <td data-label="${escapeHtml(L.protocol)}">${networkBadge(row.network)}</td>
                <td data-label="${escapeHtml(L.actionLabel)}">${actionBadge(row.action)}</td>
            </tr>`;
        }).join('');
    }

    function updateSearchState() {
        const hasRows = searchRows.length > 0;
        setHidden($('alEventsTableWrap'), !hasRows);
        setHidden($('alNoResults'), hasRows);
        setHidden($('alLoadMore'), !searchHasMore);
        const count = $('alResultCount');
        if (count) count.textContent = hasRows
            ? interpolate(I18N.showingEvents, { count: formatNumber(searchRows.length) })
            : '';
    }

    async function loadSearch(params, options) {
        const append = !!(options && options.append);
        const generation = options && options.generation != null
            ? options.generation
            : refreshGeneration;
        if (searchController) searchController.abort();
        searchController = new AbortController();
        const controller = searchController;
        const errorState = $('alSearchError');
        setHidden(errorState, true);

        const query = new URLSearchParams(params);
        query.set('limit', String(SEARCH_PAGE_SIZE));
        query.set('offset', String(append ? searchRows.length : 0));
        if (append) {
            const button = $('alLoadMore');
            if (button) button.disabled = true;
        }

        try {
            const data = await getJson(`/panel/access-logs/api/search?${query}`, {
                signal: controller.signal,
            });
            if (controller.signal.aborted || generation !== refreshGeneration) return;
            if (data.error) throw new Error(data.error);
            if (data.degraded) {
                setHidden($('alDegraded'), false);
                const text = $('alSearchErrorText');
                if (text) text.textContent = I18N.chRequired;
                setHidden(errorState, false);
                setHidden($('alEventsTableWrap'), true);
                setHidden($('alNoResults'), true);
                setHidden($('alLoadMore'), true);
                return;
            }
            const incoming = Array.isArray(data.rows) ? data.rows : [];
            searchRows = append ? searchRows.concat(incoming) : incoming;
            searchHasMore = data.hasMore != null
                ? !!data.hasMore
                : incoming.length === SEARCH_PAGE_SIZE;
            renderEvents(searchRows);
            updateSearchState();
        } catch (error) {
            if (error.name === 'AbortError') return;
            const text = $('alSearchErrorText');
            if (text) text.textContent = `${I18N.searchErrorDescription || ''}${error.message ? ` (${error.message})` : ''}`;
            setHidden(errorState, false);
            if (!searchRows.length) {
                setHidden($('alEventsTableWrap'), true);
                setHidden($('alNoResults'), true);
                setHidden($('alLoadMore'), true);
            }
        } finally {
            const button = $('alLoadMore');
            if (button) button.disabled = false;
        }
    }

    function normalizeTimeline(series, params) {
        const from = params.get('from') ? new Date(params.get('from')) : new Date(Date.now() - 86400000);
        const to = params.get('to') ? new Date(params.get('to')) : new Date();
        const span = Math.max(0, to.getTime() - from.getTime());
        const baseStep = span > 8 * 86400000 ? 86400000 : 3600000;
        const rawBucketCount = Math.floor(span / baseStep) + 1;
        const step = baseStep * Math.max(1, Math.ceil(rawBucketCount / 720));
        const align = (date) => new Date(Math.floor(date.getTime() / step) * step);
        const values = new Map();
        (series || []).forEach((row) => {
            const date = parseTimestamp(row.bucket);
            if (!date) return;
            const key = align(date).getTime();
            const current = values.get(key) || { hits: 0, accepted: 0, rejected: 0, blocked: 0 };
            current.hits += Number(row.hits) || 0;
            current.accepted += Number(row.accepted) || 0;
            current.rejected += Number(row.rejected) || 0;
            current.blocked += Number(row.blocked) || 0;
            values.set(key, current);
        });
        const rows = [];
        let cursor = align(from).getTime();
        const end = align(to).getTime();
        while (cursor <= end) {
            const value = values.get(cursor) || { hits: 0, accepted: 0, rejected: 0, blocked: 0 };
            rows.push({
                bucket: new Date(cursor),
                ...value,
                unknown: Math.max(0, value.hits - value.accepted - value.rejected - value.blocked),
            });
            cursor += step;
        }
        return rows;
    }

    const COLORS = {
        accepted: '#22c55e',
        rejected: '#f59e0b',
        blocked: '#ef4444',
        tcp: '#818cf8',
        udp: '#22d3ee',
        unknown: '#71717a',
    };

    function renderTimeline(series, params, totals) {
        const canvas = $('alTimeline');
        const fallback = $('alTimelineFallback');
        if (!canvas) return;
        const rows = normalizeTimeline(series, params);
        const totalPoints = rows.reduce((sum, row) => (
            sum + row.accepted + row.rejected + row.blocked + row.unknown
        ), 0);
        canvas.setAttribute('aria-label', interpolate(I18N.timelineAria, {
            accepted: formatNumber(totals.accepted),
            rejected: formatNumber(totals.rejected),
            blocked: formatNumber(totals.blocked),
        }));
        if (!window.Chart) {
            if (fallback) {
                fallback.textContent = I18N.chartUnavailable;
                setHidden(fallback, false);
            }
            setHidden(canvas, true);
            return;
        }
        if (!rows.length || totalPoints === 0) {
            if (fallback) {
                fallback.textContent = I18N.timelineEmpty;
                setHidden(fallback, false);
            }
            setHidden(canvas, true);
            if (timelineChart) {
                timelineChart.destroy();
                timelineChart = null;
            }
            return;
        }
        setHidden(fallback, true);
        setHidden(canvas, false);
        window.Chart.defaults.color = '#a1a1aa';
        window.Chart.defaults.borderColor = '#27272a';
        window.Chart.defaults.font.family = "Inter, ui-sans-serif, system-ui, sans-serif";
        const data = {
            labels: rows.map((row) => formatCompactTime(row.bucket)),
            datasets: ['accepted', 'rejected', 'blocked', 'unknown'].map((key) => ({
                label: actionLabel(key),
                data: rows.map((row) => row[key]),
                backgroundColor: COLORS[key],
                borderWidth: 0,
                borderRadius: 2,
                maxBarThickness: 20,
            })),
        };
        const options = {
            responsive: true,
            maintainAspectRatio: false,
            animation: reducedMotion ? false : { duration: 220 },
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { maxRotation: 0, autoSkipPadding: 24 },
                },
                y: {
                    beginAtZero: true,
                    stacked: true,
                    ticks: { precision: 0 },
                },
            },
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 10, boxHeight: 10 } },
            },
        };
        if (timelineChart) {
            timelineChart.data = data;
            timelineChart.options = options;
            timelineChart.update();
        } else {
            timelineChart = new window.Chart(canvas.getContext('2d'), { type: 'bar', data, options });
        }
    }

    function renderTimelineFailure(message) {
        const canvas = $('alTimeline');
        const fallback = $('alTimelineFallback');
        if (timelineChart) {
            timelineChart.destroy();
            timelineChart = null;
        }
        setHidden(canvas, true);
        if (fallback) {
            fallback.textContent = message;
            setHidden(fallback, false);
        }
    }

    function renderBreakdown(barId, legendId, entries, total) {
        const bar = $(barId);
        const legend = $(legendId);
        if (!bar || !legend) return;
        const safeTotal = Math.max(0, Number(total) || 0);
        bar.replaceChildren();
        legend.replaceChildren();
        const descriptions = [];
        entries.forEach((entry) => {
            const value = Math.max(0, Number(entry.value) || 0);
            const percentage = safeTotal > 0 ? (value / safeTotal) * 100 : 0;
            if (value > 0) {
                const segment = document.createElement('span');
                segment.className = `al-segment al-segment-${entry.key}`;
                segment.style.flexGrow = String(value);
                segment.title = `${entry.label}: ${formatNumber(value)} (${percentFormatter.format(percentage)}%)`;
                bar.appendChild(segment);
            }
            const item = document.createElement('li');
            const label = document.createElement('span');
            const swatch = document.createElement('i');
            swatch.className = `al-legend-swatch al-segment-${entry.key}`;
            swatch.setAttribute('aria-hidden', 'true');
            label.append(swatch, document.createTextNode(entry.label));
            const count = document.createElement('strong');
            count.textContent = `${formatNumber(value)} · ${percentFormatter.format(percentage)}%`;
            item.append(label, count);
            legend.appendChild(item);
            descriptions.push(interpolate(I18N.breakdownAria, {
                label: entry.label,
                value: formatNumber(value),
                percent: percentFormatter.format(percentage),
            }));
        });
        bar.setAttribute('aria-label', descriptions.join('; '));
        bar.classList.toggle('al-segmented-empty', safeTotal === 0);
    }

    function renderBarRows(body, rows, columns) {
        if (!body) return;
        const safeRows = Array.isArray(rows) ? rows : [];
        if (!safeRows.length) {
            body.innerHTML = emptyRow(columns.length);
            return;
        }
        const barColumn = columns.find((column) => column.bar);
        const max = barColumn
            ? Math.max(1, ...safeRows.map((row) => Number(row[barColumn.key]) || 0))
            : 1;
        body.innerHTML = safeRows.map((row) => `<tr>${columns.map((column) => {
            const raw = row[column.key];
            const formatted = column.format ? column.format(raw, row) : raw;
            const classes = [column.className || '', column.numeric ? 'al-num' : ''].filter(Boolean).join(' ');
            if (column.bar) {
                const width = Math.max(0, Math.min(100, ((Number(raw) || 0) / max) * 100));
                return `<td class="al-bar-cell al-num"><span class="al-bar" style="width:${width}%"></span><span class="al-bar-label">${escapeHtml(formatted)}</span></td>`;
            }
            return `<td${classes ? ` class="${classes}"` : ''}>${column.html ? formatted : escapeHtml(formatted == null ? '—' : formatted)}</td>`;
        }).join('')}</tr>`).join('');
    }

    function renderUsersBySource(users) {
        const body = $('alUsersByIp');
        if (!body) return;
        const rows = Array.isArray(users) ? users : [];
        if (!rows.length) {
            body.innerHTML = emptyRow(4);
            return;
        }
        const max = Math.max(1, ...rows.map((row) => Number(row.ips) || 0));
        body.innerHTML = rows.map((row, index) => {
            const email = String(row.email || '—');
            const detailId = `alSources-${index}`;
            const width = Math.max(0, Math.min(100, ((Number(row.ips) || 0) / max) * 100));
            return `<tr class="al-user-row">
                <td><button type="button" class="al-user-expand" data-email="${escapeHtml(email)}" aria-expanded="false" aria-controls="${detailId}"><i class="ti ti-chevron-right" aria-hidden="true"></i><span>${escapeHtml(email)}</span></button></td>
                <td class="al-bar-cell al-num"><span class="al-bar" style="width:${width}%"></span><span class="al-bar-label">${formatNumber(row.ips)}</span></td>
                <td class="al-num">${formatNumber(row.events)}</td>
                <td class="al-time">${escapeHtml(formatTime(row.last_seen))}</td>
            </tr>
            <tr class="al-source-detail" hidden><td colspan="4"><div id="${detailId}" class="al-source-wrap" data-loaded="0"></div></td></tr>`;
        }).join('');
        body.querySelectorAll('.al-user-expand').forEach((button) => {
            button.addEventListener('click', () => toggleUserSources(button));
        });
    }

    async function toggleUserSources(button) {
        const row = button.closest('tr');
        const detail = row ? row.nextElementSibling : null;
        const wrapper = detail ? detail.querySelector('.al-source-wrap') : null;
        if (!detail || !wrapper) return;
        const opening = detail.hidden;
        detail.hidden = !opening;
        button.setAttribute('aria-expanded', String(opening));
        button.classList.toggle('open', opening);
        if (!opening || wrapper.dataset.loaded === '1' || wrapper.dataset.loading === '1') return;
        wrapper.dataset.loading = '1';
        wrapper.innerHTML = '<span class="al-skel al-skel-wide"></span>';
        try {
            const params = new URLSearchParams(currentFilterParams);
            params.set('email', button.dataset.email || '');
            const data = await getJson(`/panel/access-logs/api/user-ips?${params}`);
            if (data.error) throw new Error(data.error);
            const rows = Array.isArray(data.rows) ? data.rows : [];
            if (!rows.length) {
                wrapper.textContent = I18N.noSources || '—';
            } else {
                wrapper.innerHTML = rows.map((source) => {
                    const value = source.ip || '—';
                    const meta = interpolate(I18N.userSourcesMeta, {
                        events: formatNumber(source.events),
                        destinations: formatNumber(source.dests),
                        lastSeen: formatTime(source.last_seen),
                    });
                    return `<span class="al-source-chip"><span class="al-mono" title="${escapeHtml(value)}">${escapeHtml(value)}</span><span>${escapeHtml(meta)}</span></span>`;
                }).join('');
            }
            wrapper.dataset.loaded = '1';
        } catch (error) {
            wrapper.textContent = interpolate(I18N.sourceLoadError, { error: error.message });
        } finally {
            wrapper.dataset.loading = '0';
        }
    }

    function renderUsersByFanout(users) {
        const rows = Array.isArray(users) ? users : [];
        renderBarRows($('alUsersByFanout'), rows, [
            { key: 'email', format: (value) => value || '—' },
            { key: 'dests', numeric: true, bar: true, format: formatNumber },
            { key: 'udp_share', numeric: true, format: formatPercent },
            { key: 'events', numeric: true, format: formatNumber },
        ]);
    }

    function renderTopTables(data, partialErrors) {
        const warning = I18N.partialAnalyticsWarning || I18N.analyticsErrorDescription;
        if (partialErrors.topDestinations) $('alTopDest').innerHTML = messageRow(2, warning);
        else renderBarRows($('alTopDest'), data.topDestinations, [
            { key: 'dest', className: 'al-mono al-trunc', format: (value) => value || '—' },
            { key: 'hits', numeric: true, bar: true, format: formatNumber },
        ]);
        if (partialErrors.topPorts) $('alTopPorts').innerHTML = messageRow(2, warning);
        else renderBarRows($('alTopPorts'), data.topPorts, [
            { key: 'port', className: 'al-mono', format: (value) => value == null ? '—' : value },
            { key: 'hits', numeric: true, bar: true, format: formatNumber },
        ]);
        if (partialErrors.topBlocked) $('alTopBlocked').innerHTML = messageRow(2, warning);
        else renderBarRows($('alTopBlocked'), data.topBlocked, [
            { key: 'dest', className: 'al-mono al-trunc', format: (value) => value || '—' },
            { key: 'hits', numeric: true, bar: true, format: formatNumber },
        ]);
    }

    function setSummary(totals) {
        const safe = totals || {};
        $('alTotal').textContent = formatNumber(safe.total);
        $('alUsers').textContent = formatNumber(safe.users);
        $('alIps').textContent = safe.ips == null ? '—' : formatNumber(safe.ips);
        $('alDests').textContent = safe.dests == null ? '—' : formatNumber(safe.dests);
        $('alRisk').textContent = formatNumber((Number(safe.rejected) || 0) + (Number(safe.blocked) || 0));
    }

    function clearSummary() {
        ['alTotal', 'alUsers', 'alIps', 'alDests', 'alRisk'].forEach((id) => {
            const element = $(id);
            if (element) element.textContent = '—';
        });
    }

    async function loadAnalytics(params, generation) {
        if (analyticsController) analyticsController.abort();
        analyticsController = new AbortController();
        const controller = analyticsController;
        setHidden($('alAnalyticsError'), true);
        setHidden($('alAnalyticsWarning'), true);
        try {
            const data = await getJson(`/panel/access-logs/api/analytics?${params}`, {
                signal: controller.signal,
            });
            if (controller.signal.aborted || generation !== refreshGeneration) return;
            if (data.error && !data.partial) throw new Error(data.error);
            // A partial overview has its own warning and still contains useful
            // data; reserve the ClickHouse configuration banner for a complete
            // storage outage/misconfiguration.
            const degraded = !!data.degraded && !data.partial;
            setHidden($('alDegraded'), !degraded);
            if (degraded && data.chRequired) {
                clearSummary();
                setHidden($('alAnalyticsContent'), true);
                setHidden($('alAnalyticsEmpty'), true);
                const text = $('alAnalyticsErrorText');
                if (text) text.textContent = I18N.chRequired;
                setHidden($('alAnalyticsError'), false);
                return;
            }
            const totals = data.totals || {};
            setSummary(totals);
            const empty = Number(totals.total || 0) === 0;
            setHidden($('alAnalyticsEmpty'), !empty);
            setHidden($('alAnalyticsContent'), empty);
            setHidden($('alAnalyticsWarning'), !data.partial);
            if (empty) return;

            const partialErrors = data.partialErrors || {};
            if (partialErrors.series) {
                renderTimelineFailure(I18N.partialAnalyticsWarning || I18N.analyticsErrorDescription);
            } else {
                renderTimeline(data.series || [], params, totals);
            }
            const knownActions = ['accepted', 'rejected', 'blocked'].reduce(
                (sum, key) => sum + (Number(totals[key]) || 0),
                0,
            );
            const actionEntries = ['accepted', 'rejected', 'blocked'].map((key) => ({
                key,
                label: actionLabel(key),
                value: totals[key],
            }));
            if (Number(totals.total) > knownActions) {
                actionEntries.push({
                    key: 'unknown',
                    label: L.unknown || '—',
                    value: Number(totals.total) - knownActions,
                });
            }
            renderBreakdown('alActionBar', 'alActionLegend', actionEntries, totals.total);

            const knownProtocols = (Number(totals.tcp) || 0) + (Number(totals.udp) || 0);
            renderBreakdown('alProtoBar', 'alProtoLegend', [
                { key: 'tcp', label: L.tcp || 'TCP', value: totals.tcp },
                { key: 'udp', label: L.udp || 'UDP', value: totals.udp },
                {
                    key: 'unknown',
                    label: L.unknown || '—',
                    value: Math.max(0, (Number(totals.total) || 0) - knownProtocols),
                },
            ], totals.total);
            if (partialErrors.usersByIp) {
                $('alUsersByIp').innerHTML = messageRow(4, I18N.partialAnalyticsWarning);
            } else {
                renderUsersBySource(data.usersByIp || data.users || []);
            }
            if (partialErrors.usersByFanout) {
                $('alUsersByFanout').innerHTML = messageRow(4, I18N.partialAnalyticsWarning);
            } else {
                renderUsersByFanout(data.usersByFanout || data.users || []);
            }
            renderTopTables(data, partialErrors);
        } catch (error) {
            if (error.name === 'AbortError') return;
            const text = $('alAnalyticsErrorText');
            if (text) text.textContent = `${I18N.analyticsErrorDescription || ''}${error.message ? ` (${error.message})` : ''}`;
            setHidden($('alAnalyticsError'), false);
            clearSummary();
            setHidden($('alAnalyticsContent'), true);
            setHidden($('alAnalyticsEmpty'), true);
        }
    }

    function statusBadge(status) {
        const value = String(status || 'pending');
        const label = I18N.statuses && I18N.statuses[value]
            ? I18N.statuses[value]
            : value;
        return `<span class="al-status al-status-${escapeHtml(value)}"><i aria-hidden="true"></i>${escapeHtml(label)}</span>`;
    }

    async function loadStatus() {
        const badge = $('alHealthBadge');
        try {
            const data = await getJson('/panel/access-logs/api/status');
            const nodes = Array.isArray(data.nodes) ? data.nodes : [];
            const active = nodes.filter((node) => node.status === 'active').length;
            const unhealthy = nodes.some((node) => node.status && !['active', 'disabled'].includes(node.status));
            const pipelineText = interpolate(I18N.pipelineSummary, {
                active: formatNumber(active),
                total: formatNumber(nodes.length),
            });
            const spool = data.spool || {};
            const spoolText = interpolate(I18N.spoolSummary, {
                count: formatNumber(spool.count),
                bytes: formatBytes(spool.bytes),
            });
            if (badge) {
                badge.className = `al-health-badge ${unhealthy || data.clickhouse === false ? 'al-health-warning' : 'al-health-ok'}`;
                badge.innerHTML = `<i class="ti ${unhealthy || data.clickhouse === false ? 'ti-alert-triangle' : 'ti-circle-check'}" aria-hidden="true"></i>${escapeHtml(pipelineText)}`;
            }
            const spoolSummary = $('alSpoolSummary');
            if (spoolSummary) spoolSummary.textContent = `${pipelineText} · ${spoolText}`;
            const body = $('alNodeStatus');
            if (body) {
                body.innerHTML = nodes.length ? nodes.map((node) => `<tr>
                    <td>${escapeHtml(node.name || '—')}</td>
                    <td class="al-mono">${escapeHtml(node.agentVersion || '—')}</td>
                    <td>${statusBadge(node.status)}</td>
                    <td class="al-time">${escapeHtml(formatTime(node.lastBatchAt))}</td>
                    <td class="al-status-error" title="${escapeHtml(node.lastError || '')}">${escapeHtml(node.lastError || '—')}</td>
                </tr>`).join('') : emptyRow(5);
            }
        } catch (_) {
            if (badge) {
                badge.className = 'al-health-badge al-health-warning';
                const degraded = I18N.statuses && I18N.statuses.degraded
                    ? I18N.statuses.degraded
                    : '—';
                badge.innerHTML = `<i class="ti ti-alert-triangle" aria-hidden="true"></i>${escapeHtml(degraded)}`;
            }
        }
    }

    async function refreshAll() {
        const params = collectFilterParams();
        if (!params) {
            showFilterError(I18N.invalidRange);
            return;
        }
        showFilterError('');
        refreshGeneration += 1;
        const generation = refreshGeneration;
        const requestParams = new URLSearchParams(params);
        // Freeze an open-ended result set for this refresh so offset pagination
        // cannot drift when newer events arrive between page requests.
        if (!requestParams.has('to')) requestParams.set('to', new Date().toISOString());
        currentFilterParams = requestParams;
        prepareRefreshSurfaces();
        updateUrl(params);
        updateActiveFilters();
        announce(I18N.loading);
        await Promise.allSettled([
            loadAnalytics(requestParams, generation),
            loadSearch(requestParams, { append: false, generation }),
        ]);
        if (generation === refreshGeneration) announce(I18N.loaded);
    }

    function wireEvents() {
        const form = $('alFilters');
        if (form) {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                refreshAll();
            });
        }
        document.querySelectorAll('.al-range-btn').forEach((button) => {
            button.addEventListener('click', () => {
                setQuickRange(Number(button.dataset.hours));
                refreshAll();
            });
        });
        const activeFilters = $('alActiveFilters');
        if (activeFilters) {
            activeFilters.addEventListener('click', (event) => {
                const button = event.target.closest('.al-filter-chip');
                const input = button ? $(FILTER_MAP[button.dataset.filter]) : null;
                if (!input) return;
                input.value = '';
                refreshAll();
            });
        }
        const reset = $('alReset');
        if (reset) {
            reset.addEventListener('click', () => {
                if (form) form.reset();
                const advanced = $('alAdvancedFilters');
                if (advanced) advanced.open = false;
                setDefaultRange();
                refreshAll();
            });
        }
        const loadMore = $('alLoadMore');
        if (loadMore) {
            loadMore.addEventListener('click', () => loadSearch(currentFilterParams, {
                append: true,
                generation: refreshGeneration,
            }));
        }
        const retrySearch = $('alRetrySearch');
        if (retrySearch) retrySearch.addEventListener('click', () => loadSearch(currentFilterParams, {
            append: false,
            generation: refreshGeneration,
        }));
        const retryAnalytics = $('alRetryAnalytics');
        if (retryAnalytics) retryAnalytics.addEventListener('click', () => loadAnalytics(
            currentFilterParams,
            refreshGeneration,
        ));
        const purge = $('alPurge');
        if (purge) {
            purge.addEventListener('click', async () => {
                if (!window.confirm(I18N.purgeConfirm)) return;
                purge.disabled = true;
                try {
                    const data = await getJson('/panel/access-logs/api/purge', { method: 'POST' });
                    if (data.error) throw new Error(data.error);
                    toast(I18N.purgeSuccess, 'success');
                    await Promise.all([refreshAll(), loadStatus()]);
                } catch (error) {
                    toast(interpolate(I18N.purgeError, { error: error.message }), 'error');
                } finally {
                    purge.disabled = false;
                }
            });
        }
        window.addEventListener('popstate', () => {
            if (form) form.reset();
            hydrateFiltersFromLocation();
            if (!$('alFrom').value) setDefaultRange();
            refreshAll();
        });
    }

    hydrateFiltersFromLocation();
    if (!$('alFrom') || !$('alFrom').value) setDefaultRange();
    updateActiveFilters();
    paintSkeletons();
    wireEvents();
    loadStatus();
    refreshAll();

    // Small, deterministic seam used by the source-level UI regression tests.
    window.__accessLogsTest = Object.freeze({
        interpolate,
        parseTimestamp,
        endpoint,
        normalizeTimeline,
    });
}());
