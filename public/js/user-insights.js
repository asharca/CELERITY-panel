// Per-subscription activity on the user detail page: traffic history and
// Xray access events. Kept dependency-free so the summary remains useful even
// when the optional access-log analytics stack is unavailable.
(function () {
    'use strict';

    const app = document.getElementById('userInsights');
    const config = window.__USER_INSIGHTS__ || {};
    if (!app || !config.userId) return;

    const I18N = config.i18n || {};
    const NODE_NAMES = config.nodeNames || {};
    const locale = document.documentElement.lang || undefined;
    const SVG_NS = 'http://www.w3.org/2000/svg';
    const validRanges = new Set(['24h', '7d', '30d']);
    const trafficCache = new Map();

    let activeRange = '7d';
    let activeTraffic = null;
    let trafficController = null;
    let accessLoading = false;
    let accessLoaded = false;
    let resizeFrame = 0;
    let chartInteraction = null;

    const $ = (id) => document.getElementById(id);
    const numberFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });
    const decimalFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
    const percentFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });

    function finiteNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) ? Math.max(0, number) : 0;
    }

    function formatNumber(value) {
        return numberFormatter.format(finiteNumber(value));
    }

    function formatBytes(value) {
        let bytes = finiteNumber(value);
        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        let unit = 0;
        while (bytes >= 1024 && unit < units.length - 1) {
            bytes /= 1024;
            unit += 1;
        }
        const formatted = unit === 0 ? numberFormatter.format(bytes) : decimalFormatter.format(bytes);
        return formatted + ' ' + units[unit];
    }

    function formatPercent(value) {
        return percentFormatter.format(finiteNumber(value));
    }

    function formatAxisBytes(value) {
        let bytes = finiteNumber(value);
        const units = ['B', 'K', 'M', 'G', 'T', 'P'];
        let unit = 0;
        while (bytes >= 1024 && unit < units.length - 1) {
            bytes /= 1024;
            unit += 1;
        }
        return decimalFormatter.format(bytes) + units[unit];
    }

    function interpolate(template, values) {
        return String(template || '').replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) => (
            Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : match
        ));
    }

    function announce(message) {
        const status = $('userInsightsStatus');
        if (!status) return;
        status.textContent = '';
        window.requestAnimationFrame(() => { status.textContent = message || ''; });
    }

    async function getJson(url, signal) {
        const response = await fetch(url, { credentials: 'include', signal });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const error = new Error(data.error || ('HTTP ' + response.status));
            error.status = response.status;
            throw error;
        }
        return data;
    }

    function parseTimestamp(value) {
        if (value == null || value === '') return null;
        if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;

        if (typeof value === 'number' || /^\d+$/.test(String(value))) {
            let timestamp = Number(value);
            if (timestamp < 1e11) timestamp *= 1000;
            const date = new Date(timestamp);
            return Number.isNaN(date.getTime()) ? null : date;
        }

        const text = String(value);
        if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(text)) {
            const date = new Date(text.replace(' ', 'T') + 'Z');
            return Number.isNaN(date.getTime()) ? null : date;
        }
        if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(text)) {
            const date = new Date(text);
            return Number.isNaN(date.getTime()) ? null : date;
        }
        return null;
    }

    function formatPeriodDate(value, range) {
        const date = parseTimestamp(value);
        if (!date) return '—';
        const options = range === '24h'
            ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
            : { year: 'numeric', month: 'short', day: 'numeric' };
        return new Intl.DateTimeFormat(locale, options).format(date);
    }

    function formatPeriodEnd(value, range, series) {
        // The API's `to` is exclusive. Show the start of the final returned
        // bucket instead, which remains correct in every viewer timezone and
        // avoids making 7d/30d look one day longer than the data.
        const lastPoint = Array.isArray(series) && series.length
            ? parseTimestamp(series[series.length - 1].ts)
            : null;
        return formatPeriodDate(lastPoint || value, range);
    }

    function formatEventTime(value) {
        const date = parseTimestamp(value);
        if (!date) return '—';
        return new Intl.DateTimeFormat(locale, {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        }).format(date);
    }

    function rangeLabel(range) {
        const labels = {
            '24h': I18N.range24Hours,
            '7d': I18N.range7Days,
            '30d': I18N.range30Days,
        };
        return labels[range] || range;
    }

    function setTrafficState(state) {
        const loading = state === 'loading';
        $('trafficSkeleton').hidden = !loading;
        $('trafficError').hidden = state !== 'error';
        $('trafficContent').hidden = state !== 'ready';
        $('userTrafficPanel').setAttribute('aria-busy', loading ? 'true' : 'false');
    }

    function setAccessState(state) {
        const loading = state === 'loading';
        const states = {
            accessDisabled: 'disabled',
            accessDegraded: 'degraded',
            accessError: 'error',
            accessContent: 'ready',
        };
        $('accessSkeleton').hidden = !loading;
        Object.entries(states).forEach(([id, matchingState]) => {
            $(id).hidden = state !== matchingState;
        });
        $('userAccessPanel').setAttribute('aria-busy', loading ? 'true' : 'false');
    }

    function selectRange(range) {
        activeRange = validRanges.has(range) ? range : '7d';
        document.querySelectorAll('.traffic-range-btn').forEach((button) => {
            const active = button.dataset.range === activeRange;
            button.classList.toggle('active', active);
            button.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
    }

    function normaliseTraffic(payload, fallbackRange) {
        const range = validRanges.has(payload && payload.range) ? payload.range : fallbackRange;
        const rawTotals = (payload && payload.totals) || {};
        const tx = finiteNumber(rawTotals.tx);
        const rx = finiteNumber(rawTotals.rx);
        const total = tx + rx;
        const series = Array.isArray(payload && payload.series) ? payload.series.map((point) => {
            const pointTx = finiteNumber(point && point.tx);
            const pointRx = finiteNumber(point && point.rx);
            return {
                ts: point && point.ts,
                tx: pointTx,
                rx: pointRx,
                total: pointTx + pointRx,
            };
        }).sort((a, b) => {
            const aDate = parseTimestamp(a.ts);
            const bDate = parseTimestamp(b.ts);
            return (aDate ? aDate.getTime() : 0) - (bDate ? bDate.getTime() : 0);
        }) : [];
        const nodes = Array.isArray(payload && payload.nodes) ? payload.nodes.map((node) => {
            const nodeTx = finiteNumber(node && node.tx);
            const nodeRx = finiteNumber(node && node.rx);
            return {
                nodeId: String((node && node.nodeId) || ''),
                nodeName: String((node && node.nodeName) || (node && node.nodeId) || I18N.unknownNode || 'Node'),
                nodeType: String((node && node.nodeType) || ''),
                tx: nodeTx,
                rx: nodeRx,
                total: nodeTx + nodeRx,
            };
        }).sort((a, b) => b.total - a.total) : [];

        return {
            range,
            granularity: payload && payload.granularity === 'day' ? 'day' : 'hour',
            from: payload && payload.from,
            to: payload && payload.to,
            totals: { tx, rx, total },
            series,
            nodes,
        };
    }

    async function loadTraffic(range, options) {
        const requestedRange = validRanges.has(range) ? range : '7d';
        const force = !!(options && options.force);
        selectRange(requestedRange);

        if (!force && trafficCache.has(requestedRange)) {
            renderTraffic(trafficCache.get(requestedRange));
            return;
        }

        if (trafficController) trafficController.abort();
        const controller = new AbortController();
        trafficController = controller;
        setTrafficState('loading');
        $('trafficPeriod').textContent = I18N.loadingTraffic || '';
        announce(I18N.loadingTraffic);

        try {
            const url = '/api/users/' + encodeURIComponent(config.userId)
                + '/traffic-history?range=' + encodeURIComponent(requestedRange);
            const payload = await getJson(url, controller.signal);
            if (trafficController !== controller) return;
            const data = normaliseTraffic(payload, requestedRange);
            trafficCache.set(requestedRange, data);
            renderTraffic(data);
        } catch (error) {
            if (error && error.name === 'AbortError') return;
            if (trafficController !== controller) return;
            setTrafficState('error');
            $('trafficPeriod').textContent = I18N.error || 'Error';
            announce(I18N.error);
        } finally {
            if (trafficController === controller) trafficController = null;
        }
    }

    function completedTrafficSummary(data) {
        const allPoints = Array.isArray(data.series) ? data.series : [];
        const completed = allPoints.length > 1 ? allPoints.slice(0, -1) : allPoints;
        const total = completed.reduce((sum, point) => sum + finiteNumber(point.total), 0);
        const peak = completed.reduce((current, point) => (
            !current || finiteNumber(point.total) > finiteNumber(current.total) ? point : current
        ), null);

        return {
            average: completed.length ? total / completed.length : 0,
            peak,
        };
    }

    function renderTraffic(data) {
        activeTraffic = data;
        selectRange(data.range);
        setTrafficState('ready');
        $('trafficTotal').textContent = formatBytes(data.totals.total);
        $('trafficTx').textContent = formatBytes(data.totals.tx);
        $('trafficRx').textContent = formatBytes(data.totals.rx);
        const granularityLabel = data.granularity === 'day'
            ? (I18N.daily || '') : (I18N.hourly || '');
        $('trafficGranularity').textContent = [granularityLabel, I18N.currentBucketHint]
            .filter(Boolean).join(' · ');

        const total = data.totals.total;
        const txShare = total > 0 ? (data.totals.tx / total) * 100 : 0;
        const rxShare = total > 0 ? (data.totals.rx / total) * 100 : 0;
        const completed = completedTrafficSummary(data);
        const averageTemplate = data.granularity === 'day' ? I18N.averageDaily : I18N.averageHourly;
        $('trafficAverage').textContent = interpolate(averageTemplate, {
            value: formatBytes(completed.average),
        });
        $('trafficTxShare').textContent = interpolate(I18N.shareOfPeriod, {
            percent: formatPercent(txShare),
        });
        $('trafficRxShare').textContent = interpolate(I18N.shareOfPeriod, {
            percent: formatPercent(rxShare),
        });
        $('trafficPeak').textContent = completed.peak ? formatBytes(completed.peak.total) : '—';
        $('trafficPeakTime').textContent = completed.peak && completed.peak.total > 0
            ? formatChartDetailTime(completed.peak.ts, data.granularity)
            : '—';

        const period = interpolate(I18N.currentPeriod, {
            from: formatPeriodDate(data.from, data.range),
            to: formatPeriodEnd(data.to, data.range, data.series),
        });
        $('trafficPeriod').textContent = period;

        const hasTraffic = data.totals.total > 0
            || data.series.some((point) => point.total > 0)
            || data.nodes.some((node) => node.total > 0);
        $('trafficEmpty').hidden = hasTraffic;
        $('trafficVisuals').hidden = !hasTraffic;

        if (hasTraffic) {
            renderTrafficChart(data);
            renderTrafficNodes(data.nodes);
        } else {
            $('trafficChart').replaceChildren();
            $('trafficNodes').replaceChildren();
            hideChartSelection();
        }
        announce(I18N.trafficLoaded);
    }

    function svgElement(name, attributes, text) {
        const element = document.createElementNS(SVG_NS, name);
        Object.entries(attributes || {}).forEach(([key, value]) => element.setAttribute(key, String(value)));
        if (text != null) element.textContent = text;
        return element;
    }

    function formatChartTime(value, granularity) {
        const date = parseTimestamp(value);
        if (!date) return '—';
        const options = granularity === 'day'
            ? { month: 'short', day: 'numeric' }
            : { weekday: 'short', hour: '2-digit' };
        return new Intl.DateTimeFormat(locale, options).format(date);
    }

    function formatChartDetailTime(value, granularity) {
        const date = parseTimestamp(value);
        if (!date) return '—';
        const options = granularity === 'day'
            ? { year: 'numeric', month: 'short', day: 'numeric' }
            : { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
        return new Intl.DateTimeFormat(locale, options).format(date);
    }

    function renderTrafficChart(data) {
        const container = $('trafficChart');
        hideChartSelection();
        chartInteraction = null;
        const validSeries = data.series.filter((point) => parseTimestamp(point.ts));
        const noPoints = validSeries.length === 0;
        container.hidden = noPoints;
        $('trafficChartEmpty').hidden = !noPoints;
        container.replaceChildren();
        if (noPoints) return;

        const width = Math.max(220, Math.floor(container.clientWidth || 720));
        const height = width < 480 ? 230 : 260;
        const padding = { top: 18, right: 10, bottom: 36, left: width < 420 ? 44 : 54 };
        const plotWidth = width - padding.left - padding.right;
        const plotHeight = height - padding.top - padding.bottom;
        const maxValue = Math.max(1, ...validSeries.map((point) => point.total));
        const baseline = height - padding.bottom;
        const slot = plotWidth / validSeries.length;
        const barWidth = Math.max(3, Math.min(18, slot * 0.68));
        const baseLabel = interpolate(I18N.chartAria, {
            range: rangeLabel(data.range),
            tx: formatBytes(data.totals.tx),
            rx: formatBytes(data.totals.rx),
            total: formatBytes(data.totals.total),
        });

        const svg = svgElement('svg', {
            viewBox: '0 0 ' + width + ' ' + height,
            width: '100%', height,
            'aria-hidden': 'true',
            focusable: 'false',
        });
        container.setAttribute('aria-label', baseLabel);

        [0, 0.5, 1].forEach((fraction) => {
            const y = padding.top + (1 - fraction) * plotHeight;
            svg.appendChild(svgElement('line', {
                x1: padding.left, x2: width - padding.right, y1: y, y2: y,
                class: 'traffic-chart-gridline',
            }));
            svg.appendChild(svgElement('text', {
                x: padding.left - 9, y: y + 4,
                class: 'traffic-chart-axis-label', 'text-anchor': 'end',
            }, formatAxisBytes(maxValue * fraction)));
        });

        const selection = svgElement('rect', {
            x: padding.left,
            y: padding.top,
            width: slot,
            height: plotHeight,
            rx: 4,
            class: 'traffic-chart-selection',
        });
        selection.hidden = true;
        svg.appendChild(selection);

        const bars = [];
        const geometry = [];
        validSeries.forEach((point, index) => {
            const center = padding.left + (slot * index) + (slot / 2);
            const x = center - (barWidth / 2);
            const rxHeight = (point.rx / maxValue) * plotHeight;
            const txHeight = (point.tx / maxValue) * plotHeight;
            const totalHeight = rxHeight + txHeight;
            const group = svgElement('g', {
                class: 'traffic-chart-bar-group' + (index === validSeries.length - 1 ? ' is-current' : ''),
            });

            if (point.rx > 0) {
                group.appendChild(svgElement('rect', {
                    x, y: baseline - rxHeight, width: barWidth, height: Math.max(1, rxHeight),
                    rx: Math.min(3, barWidth / 3),
                    class: 'traffic-chart-bar traffic-chart-bar-rx',
                }));
            }
            if (point.tx > 0) {
                group.appendChild(svgElement('rect', {
                    x, y: baseline - totalHeight, width: barWidth, height: Math.max(1, txHeight),
                    rx: Math.min(3, barWidth / 3),
                    class: 'traffic-chart-bar traffic-chart-bar-tx',
                }));
            }

            bars.push(group);
            geometry.push({
                center,
                top: baseline - Math.max(1, totalHeight),
                slotX: padding.left + (slot * index),
            });
            svg.appendChild(group);
        });

        const completedCount = Math.max(1, validSeries.length - 1);
        let peakIndex = 0;
        for (let index = 1; index < completedCount; index += 1) {
            if (validSeries[index].total > validSeries[peakIndex].total) peakIndex = index;
        }
        if (validSeries[peakIndex].total > 0) {
            svg.appendChild(svgElement('circle', {
                cx: geometry[peakIndex].center,
                cy: Math.max(padding.top + 3, geometry[peakIndex].top - 5),
                r: 2.5,
                class: 'traffic-chart-peak',
            }));
        }

        const lastIndex = validSeries.length - 1;
        const tickIndexes = width < 420
            ? Array.from(new Set([0, Math.round(lastIndex / 2), lastIndex]))
            : Array.from(new Set([0, Math.round(lastIndex / 3), Math.round(lastIndex * 2 / 3), lastIndex]));
        tickIndexes.forEach((index) => {
            const anchor = index === 0 ? 'start' : (index === lastIndex ? 'end' : 'middle');
            svg.appendChild(svgElement('text', {
                x: geometry[index].center, y: height - 9,
                class: 'traffic-chart-axis-label', 'text-anchor': anchor,
            }, formatChartTime(validSeries[index].ts, data.granularity)));
        });

        container.appendChild(svg);
        chartInteraction = {
            container,
            data,
            points: validSeries,
            bars,
            geometry,
            selection,
            width,
            padding,
            slot,
            baseLabel,
            selectedIndex: null,
        };
    }

    function pointAriaLabel(point, data) {
        return interpolate(I18N.chartPointAria, {
            time: formatChartDetailTime(point.ts, data.granularity),
            total: formatBytes(point.total),
            tx: formatBytes(point.tx),
            rx: formatBytes(point.rx),
        });
    }

    function updateChartSelection(index, options) {
        const state = chartInteraction;
        if (!state || !state.points.length) return;
        const nextIndex = Math.max(0, Math.min(state.points.length - 1, index));
        const point = state.points[nextIndex];
        const position = state.geometry[nextIndex];
        const tooltip = $('trafficChartTooltip');

        state.selectedIndex = nextIndex;
        state.bars.forEach((bar, barIndex) => bar.classList.toggle('is-selected', barIndex === nextIndex));
        state.selection.hidden = false;
        state.selection.setAttribute('x', position.slotX.toFixed(2));
        state.selection.setAttribute('width', state.slot.toFixed(2));

        $('trafficTooltipTime').textContent = formatChartDetailTime(point.ts, state.data.granularity);
        $('trafficTooltipTotal').textContent = formatBytes(point.total);
        $('trafficTooltipTx').textContent = formatBytes(point.tx);
        $('trafficTooltipRx').textContent = formatBytes(point.rx);
        tooltip.style.left = ((position.center / state.width) * 100).toFixed(2) + '%';
        tooltip.style.top = Math.max(state.padding.top + 2, position.top - 8).toFixed(2) + 'px';
        tooltip.dataset.align = position.center < state.width * 0.25
            ? 'start' : (position.center > state.width * 0.75 ? 'end' : 'center');
        tooltip.dataset.side = position.top < 90 ? 'bottom' : 'top';
        if (tooltip.dataset.side === 'bottom') {
            tooltip.style.top = (position.top + 10).toFixed(2) + 'px';
        }
        tooltip.hidden = false;
        tooltip.setAttribute('aria-hidden', 'false');

        const label = pointAriaLabel(point, state.data);
        state.container.setAttribute('aria-label', label);
        if (options && options.announce) announce(label);
    }

    function hideChartSelection() {
        const state = chartInteraction;
        const tooltip = $('trafficChartTooltip');
        if (tooltip) {
            tooltip.hidden = true;
            tooltip.setAttribute('aria-hidden', 'true');
        }
        if (!state) return;
        state.selectedIndex = null;
        state.selection.hidden = true;
        state.bars.forEach((bar) => bar.classList.remove('is-selected'));
        state.container.setAttribute('aria-label', state.baseLabel);
    }

    function chartIndexFromPointer(event) {
        const state = chartInteraction;
        if (!state) return null;
        const rect = state.container.getBoundingClientRect();
        if (!rect.width) return null;
        const localX = ((event.clientX - rect.left) / rect.width) * state.width;
        const index = Math.floor((localX - state.padding.left) / state.slot);
        return Math.max(0, Math.min(state.points.length - 1, index));
    }

    function bindChartInteractions() {
        const container = $('trafficChart');
        container.addEventListener('pointermove', (event) => {
            if (event.pointerType === 'touch') return;
            const index = chartIndexFromPointer(event);
            if (index != null) updateChartSelection(index);
        });
        container.addEventListener('pointerleave', () => {
            if (document.activeElement !== container) hideChartSelection();
        });
        container.addEventListener('pointerdown', (event) => {
            const index = chartIndexFromPointer(event);
            if (index == null) return;
            updateChartSelection(index);
            container.focus({ preventScroll: true });
        });
        container.addEventListener('focus', () => {
            if (!chartInteraction) return;
            const index = chartInteraction.selectedIndex == null
                ? chartInteraction.points.length - 1
                : chartInteraction.selectedIndex;
            updateChartSelection(index);
        });
        container.addEventListener('blur', hideChartSelection);
        container.addEventListener('keydown', (event) => {
            const state = chartInteraction;
            if (!state) return;
            const current = state.selectedIndex == null ? state.points.length - 1 : state.selectedIndex;
            let next = null;
            if (event.key === 'ArrowLeft') next = current - 1;
            if (event.key === 'ArrowRight') next = current + 1;
            if (event.key === 'Home') next = 0;
            if (event.key === 'End') next = state.points.length - 1;
            if (event.key === 'Escape') {
                hideChartSelection();
                return;
            }
            if (next == null) return;
            event.preventDefault();
            updateChartSelection(next, { announce: true });
        });
    }

    function renderTrafficNodes(nodes) {
        const container = $('trafficNodes');
        const activeNodes = nodes.filter((node) => node.total > 0);
        container.replaceChildren();
        container.hidden = activeNodes.length === 0;
        $('trafficNodesEmpty').hidden = activeNodes.length > 0;
        if (!activeNodes.length) return;

        const attributedTotal = Math.max(1, activeNodes.reduce((sum, node) => sum + node.total, 0));
        activeNodes.forEach((node) => {
            const row = document.createElement('div');
            row.className = 'traffic-node';

            const header = document.createElement('div');
            header.className = 'traffic-node-header';
            const identity = document.createElement('span');
            identity.className = 'traffic-node-identity';
            const name = document.createElement('strong');
            name.textContent = node.nodeName;
            name.title = node.nodeName;
            identity.appendChild(name);
            if (node.nodeType) {
                const type = document.createElement('small');
                type.textContent = node.nodeType;
                identity.appendChild(type);
            }
            const total = document.createElement('span');
            total.className = 'traffic-node-total';
            const amount = document.createElement('strong');
            amount.textContent = formatBytes(node.total);
            const share = document.createElement('small');
            const sharePercent = (node.total / attributedTotal) * 100;
            share.textContent = interpolate(I18N.nodeShare, { percent: formatPercent(sharePercent) });
            total.append(amount, share);
            header.append(identity, total);

            const track = document.createElement('div');
            track.className = 'traffic-node-track';
            track.setAttribute('role', 'img');
            track.setAttribute('aria-label', interpolate(I18N.nodeTrafficAria, {
                node: node.nodeName,
                total: formatBytes(node.total),
                tx: formatBytes(node.tx),
                rx: formatBytes(node.rx),
            }));
            const fill = document.createElement('span');
            fill.className = 'traffic-node-fill';
            fill.style.width = Math.min(100, sharePercent).toFixed(2) + '%';
            const tx = document.createElement('i');
            tx.className = 'traffic-node-segment traffic-node-segment-tx';
            tx.style.width = ((node.tx / Math.max(1, node.total)) * 100).toFixed(2) + '%';
            const rx = document.createElement('i');
            rx.className = 'traffic-node-segment traffic-node-segment-rx';
            rx.style.width = ((node.rx / Math.max(1, node.total)) * 100).toFixed(2) + '%';
            fill.append(tx, rx);
            track.appendChild(fill);

            const split = document.createElement('div');
            split.className = 'traffic-node-split';
            const txText = document.createElement('span');
            txText.textContent = (I18N.uploaded || 'Upload') + ' ' + formatBytes(node.tx);
            const rxText = document.createElement('span');
            rxText.textContent = (I18N.downloaded || 'Download') + ' ' + formatBytes(node.rx);
            split.append(txText, rxText);

            row.append(header, track, split);
            container.appendChild(row);
        });
    }

    async function loadAccess(options) {
        const force = !!(options && options.force);
        if (accessLoading || (accessLoaded && !force)) return;
        accessLoading = true;
        if (force) accessLoaded = false;
        setAccessState('loading');
        announce(I18N.loadingAccess);

        try {
            const query = new URLSearchParams({
                email: String(config.userId),
                from: config.accessFrom || new Date(Date.now() - (7 * 24 * 60 * 60 * 1000)).toISOString(),
            }).toString();
            const [analytics, search] = await Promise.all([
                getJson('/panel/access-logs/api/analytics?' + query),
                getJson('/panel/access-logs/api/search?' + query + '&limit=50'),
            ]);

            if (!analytics.enabled || !search.enabled) {
                setAccessState('disabled');
                accessLoaded = true;
                announce(I18N.accessDisabledTitle);
                return;
            }
            if (analytics.degraded || search.degraded || analytics.chRequired) {
                setAccessState('degraded');
                accessLoaded = true;
                announce(I18N.accessDegradedTitle);
                return;
            }
            if (analytics.error || search.error) {
                throw new Error(analytics.error || search.error);
            }

            renderAccess(analytics, search.rows || []);
            setAccessState('ready');
            accessLoaded = true;
            announce(I18N.accessLoaded);
        } catch (error) {
            setAccessState('error');
            announce(I18N.accessErrorTitle || I18N.error);
        } finally {
            accessLoading = false;
        }
    }

    function formatEndpoint(host, port) {
        let value = String(host || '');
        if (!value) return '—';
        if (value.includes(':') && !value.startsWith('[')) value = '[' + value + ']';
        return port ? value + ':' + port : value;
    }

    function formatNode(nodeId) {
        const id = String(nodeId || '');
        return NODE_NAMES[id] || id || I18N.unknownNode || '—';
    }

    function createCell(text, className) {
        const cell = document.createElement('td');
        if (className) cell.className = className;
        cell.textContent = text;
        return cell;
    }

    function createEndpointCell(host, port, className) {
        const endpoint = formatEndpoint(host, port);
        const cell = createCell(endpoint, className);
        cell.title = endpoint;
        return cell;
    }

    function createBadge(value, kind) {
        const badge = document.createElement('span');
        const normalized = String(value || '').toLowerCase();
        const classToken = normalized.replace(/[^a-z0-9_-]/g, '');
        badge.className = 'user-event-badge user-event-badge-' + kind
            + (classToken ? ' user-event-badge-' + classToken : '');
        if (kind === 'action') {
            badge.textContent = I18N[normalized] || normalized || I18N.unknownAction || '—';
        } else {
            badge.textContent = normalized ? normalized.toUpperCase() : '—';
        }
        return badge;
    }

    function renderAccess(analytics, rows) {
        const totals = analytics.totals || {};
        $('accessEvents').textContent = formatNumber(totals.total);
        $('accessIps').textContent = totals.ips == null ? '—' : formatNumber(totals.ips);
        $('accessDestinations').textContent = totals.dests == null ? '—' : formatNumber(totals.dests);

        const tbody = $('accessEventRows');
        tbody.replaceChildren();
        rows.forEach((event) => {
            const row = document.createElement('tr');
            row.appendChild(createCell(formatEventTime(event.ts), 'user-event-time'));
            row.appendChild(createCell(formatNode(event.node_id), 'user-event-node'));
            row.appendChild(createEndpointCell(
                event.source_ip,
                event.source_port,
                'user-event-endpoint'
            ));
            row.appendChild(createEndpointCell(
                event.dest_host || event.dest_ip,
                event.dest_port,
                'user-event-endpoint user-event-destination'
            ));
            const protocol = document.createElement('td');
            protocol.appendChild(createBadge(event.network, 'network'));
            const action = document.createElement('td');
            action.appendChild(createBadge(event.action, 'action'));
            row.append(protocol, action);
            tbody.appendChild(row);
        });

        const empty = rows.length === 0;
        $('accessEmpty').hidden = !empty;
        $('accessEventsWrap').hidden = empty;
    }

    function activateTab(tab) {
        if (!tab) return;
        const tabs = Array.from(document.querySelectorAll('.user-insights-tab'));
        tabs.forEach((button) => {
            const selected = button === tab;
            button.classList.toggle('active', selected);
            button.setAttribute('aria-selected', selected ? 'true' : 'false');
            button.tabIndex = selected ? 0 : -1;
            const panel = $(button.getAttribute('aria-controls'));
            if (panel) panel.hidden = !selected;
        });

        if (tab.id === 'userAccessTab') {
            loadAccess();
        } else if (activeTraffic) {
            window.requestAnimationFrame(() => renderTrafficChart(activeTraffic));
        }
    }

    const tabs = Array.from(document.querySelectorAll('.user-insights-tab'));
    tabs.forEach((tab, index) => {
        tab.addEventListener('click', () => activateTab(tab));
        tab.addEventListener('keydown', (event) => {
            let nextIndex = null;
            if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
            if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
            if (event.key === 'Home') nextIndex = 0;
            if (event.key === 'End') nextIndex = tabs.length - 1;
            if (nextIndex == null) return;
            event.preventDefault();
            tabs[nextIndex].focus();
            activateTab(tabs[nextIndex]);
        });
    });

    document.querySelectorAll('.traffic-range-btn').forEach((button) => {
        button.addEventListener('click', () => loadTraffic(button.dataset.range));
    });
    $('trafficRetry').addEventListener('click', () => loadTraffic(activeRange, { force: true }));
    $('accessRetry').addEventListener('click', () => loadAccess({ force: true }));

    if (typeof window.ResizeObserver === 'function') {
        const observer = new ResizeObserver(() => {
            if (!activeTraffic || $('userTrafficPanel').hidden) return;
            window.cancelAnimationFrame(resizeFrame);
            resizeFrame = window.requestAnimationFrame(() => renderTrafficChart(activeTraffic));
        });
        observer.observe($('trafficChart'));
    } else {
        window.addEventListener('resize', () => {
            if (!activeTraffic || $('userTrafficPanel').hidden) return;
            window.cancelAnimationFrame(resizeFrame);
            resizeFrame = window.requestAnimationFrame(() => renderTrafficChart(activeTraffic));
        }, { passive: true });
    }

    bindChartInteractions();
    loadTraffic(activeRange);
})();
