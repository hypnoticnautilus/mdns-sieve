// Global state
let currentTheme = localStorage.getItem('theme') || 'system';
let autoRefreshInterval = parseInt(localStorage.getItem('refreshInterval') || '8', 10);
let chartWindowSize = parseInt(localStorage.getItem('chartWindow') || '30', 10);
let refreshTimer = null;
let lastStatsData = null;
let knownInterfaces = new Set();

// Sieve daemon details (updated dynamically from API responses)
let daemonCommit = '-';
let guiCommit = '-';
let daemonVersion = '-';
let guiVersion = '-';

// Chart.js Instances
let mainChart = null;
let sparklines = {};

// Enum & DNS Type Helpers
function dnsTypeToString(t) {
  switch (t) {
    case 1: return 'A';
    case 2: return 'NS';
    case 5: return 'CNAME';
    case 6: return 'SOA';
    case 12: return 'PTR';
    case 15: return 'MX';
    case 16: return 'TXT';
    case 28: return 'AAAA';
    case 33: return 'SRV';
    case 47: return 'NSEC';
    case 255: return 'ANY';
    default: return `TYPE(${t})`;
  }
}

function dnsClassToString(c) {
  switch (c) {
    case 1: return 'IN';
    case 255: return 'ANY';
    default: return `CLASS(${c})`;
  }
}

function sectionToString(s) {
  switch (s) {
    case 0: return 'Question';
    case 1: return 'Answer';
    case 2: return 'Authority';
    case 3: return 'Additional';
    default: return 'Unknown';
  }
}

function packetTypeInfo(pt) {
  if (pt === 1) {
    return { css: 'response', label: 'Response' };
  }
  return { css: 'query', label: 'Query' };
}

function dispositionInfo(disp, fwdStr, dropStr) {
  const fwd = (fwdStr || '').split(',').map(s => s.trim()).filter(Boolean);
  const drop = (dropStr || '').split(',').map(s => s.trim()).filter(Boolean);

  let label = 'Dropped';
  let cssClass = 'dropped';

  if (disp === 1) {
    label = 'Forwarded';
    cssClass = 'forwarded';
  } else if (disp === 2) {
    label = 'Partially Forwarded';
    cssClass = 'partially-forwarded';
  }

  let details = [];
  if (fwd.length > 0) {
    details.push(`forwarded: ${fwd.join(', ')}`);
  }
  if (drop.length > 0) {
    details.push(`dropped: ${drop.join(', ')}`);
  }

  const tooltip = details.length > 0 ? `${label} (${details.join(' | ')})` : label;
  return { label, cssClass, tooltip };
}

function renderDispositionDot(disp, fwdStr, dropStr, small = false) {
  const info = dispositionInfo(disp, fwdStr, dropStr);
  const sizeClass = small ? ' sm' : '';
  const escapedTooltip = escapeHtml(info.tooltip);
  return `<span class="disp-dot ${info.cssClass}${sizeClass}" title="${escapedTooltip}" data-tooltip="${escapedTooltip}"></span>`;
}

// Shorten long service names by ellipsizing leading parts while preserving last 3 components
function shortenServiceName(name) {
  if (!name) return name;
  const parts = name.split('.');
  if (parts.length <= 3) {
    return name;
  }
  const leading = parts.slice(0, -3);
  const trailing = parts.slice(-3);
  const shortenedLeading = leading.map(part => {
    if (part.length > 10) {
      return part.substring(0, 3) + '...' + part.substring(part.length - 3);
    }
    return part;
  });
  return shortenedLeading.concat(trailing).join('.');
}

// Initialize application on load
window.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initTheme();

  const autoRefreshToggle = document.getElementById('autoRefreshToggle');
  autoRefreshToggle.addEventListener('change', (e) => {
    if (e.target.checked) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });

  initCharts();
  refreshData();

  if (autoRefreshToggle.checked) {
    startAutoRefresh();
  }

  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        toggleModal(overlay.id, false);
      }
    });
  });
});

/* ==========================================================================
   Theme Management (Light / Dark / System)
   ========================================================================== */
function initTheme() {
  const toggleBtn = document.getElementById('themeToggleBtn');
  const menu = document.getElementById('themeMenu');

  toggleBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.classList.toggle('hidden');
  });

  document.addEventListener('click', () => {
    menu.classList.add('hidden');
  });

  applyTheme(currentTheme);

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (currentTheme === 'system') {
      applyTheme('system');
    }
  });
}

function setTheme(theme) {
  currentTheme = theme;
  localStorage.setItem('theme', theme);
  applyTheme(theme);
}

function applyTheme(theme) {
  let activeTheme = theme;
  if (theme === 'system') {
    activeTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  document.documentElement.setAttribute('data-theme', activeTheme);

  const icon = document.getElementById('themeIcon');
  if (activeTheme === 'dark') {
    icon.setAttribute('data-lucide', 'moon');
  } else {
    icon.setAttribute('data-lucide', 'sun');
  }
  lucide.createIcons({ attrs: { id: 'themeIcon' } });
}

/* ==========================================================================
   Modal Controls & Overlay Toggles
   ========================================================================== */
function toggleModal(modalId, show) {
  const modal = document.getElementById(modalId);
  if (show) {
    modal.classList.remove('hidden');
    if (modalId === 'settingsModal') {
      document.getElementById('setRefreshInterval').value = autoRefreshInterval;
      document.getElementById('setChartWindow').value = chartWindowSize;
    }
    if (modalId === 'infoModal') {
      document.getElementById('infoDaemonVersion').textContent = `${daemonVersion} (${daemonCommit})`;
      document.getElementById('infoGuiVersion').textContent = `${guiVersion} (${guiCommit})`;
    }
  } else {
    modal.classList.add('hidden');
  }
}

async function copyToClipboard(text, btn, event) {
  if (event) {
    event.stopPropagation();
  }
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.top = '-9999px';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      const successful = document.execCommand('copy');
      document.body.removeChild(textarea);
      if (!successful) {
        throw new Error('execCommand copy failed');
      }
    }

    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<i data-lucide="check" style="color: var(--color-green);"></i>';
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
    setTimeout(() => {
      btn.innerHTML = originalHtml;
      if (typeof lucide !== 'undefined') {
        lucide.createIcons();
      }
    }, 1500);
  } catch (err) {
    console.error('Failed to copy text: ', err);
  }
}

function saveSettings() {
  const rateInput = document.getElementById('setRefreshInterval');
  const windowInput = document.getElementById('setChartWindow');

  let rate = parseInt(rateInput.value, 10);
  let size = parseInt(windowInput.value, 10);

  if (isNaN(rate) || rate < 1) rate = 8;
  if (isNaN(size) || size < 10) size = 30;

  autoRefreshInterval = rate;
  chartWindowSize = size;

  localStorage.setItem('refreshInterval', rate);
  localStorage.setItem('chartWindow', size);

  toggleModal('settingsModal', false);

  if (document.getElementById('autoRefreshToggle').checked) {
    stopAutoRefresh();
    startAutoRefresh();
  }

  if (mainChart) {
    updateChartWindow();
  }
}

/* ==========================================================================
   Auto-Refresh & Polling Loop
   ========================================================================== */
function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = setInterval(refreshData, autoRefreshInterval * 1000);
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

/* ==========================================================================
   HTTP API Requests
   ========================================================================== */
async function fetchApi(endpoint, options = {}) {
  const res = await fetch(endpoint, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  }
  const data = await res.json();
  if (data.status === 'error') {
    throw new Error(data.error || 'Server reported API error');
  }
  return data;
}

function updateInterfaceDropdowns(interfacesList) {
  if (!Array.isArray(interfacesList)) return;
  interfacesList.forEach(iface => {
    if (iface && iface.trim()) knownInterfaces.add(iface.trim());
  });

  const sorted = Array.from(knownInterfaces).sort();

  const srcSelect = document.getElementById('historyInterfaceFilter');
  if (srcSelect) {
    const currentVal = srcSelect.value;
    srcSelect.innerHTML = '<option value="">All Ingress Interfaces</option>';
    sorted.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface;
      opt.textContent = `Ingress: ${iface}`;
      if (iface === currentVal) opt.selected = true;
      srcSelect.appendChild(opt);
    });
  }

  const dstSelect = document.getElementById('historyDstInterfaceFilter');
  if (dstSelect) {
    const currentVal = dstSelect.value;
    dstSelect.innerHTML = '<option value="">All Destination Interfaces</option>';
    sorted.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface;
      opt.textContent = `Forwarded To: ${iface}`;
      if (iface === currentVal) opt.selected = true;
      dstSelect.appendChild(opt);
    });
  }
}

async function refreshData() {
  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) refreshBtn.disabled = true;

  try {
    const statsRes = await fetchApi('/api/stats');
    updateStats(statsRes.data);
    hideOfflineOverlay();

    if (statsRes.interfaces) {
      updateInterfaceDropdowns(statsRes.interfaces);
    }
    if (statsRes.commit) daemonCommit = statsRes.commit;
    if (statsRes.gui_commit) guiCommit = statsRes.gui_commit;
    if (statsRes.version) daemonVersion = statsRes.version;
    if (statsRes.gui_version) guiVersion = statsRes.gui_version;

    if (currentMainView === 'history') {
      await loadHistoryData(currentHistoryPage, true);
    }

    const statusLabel = document.getElementById('infoDaemonStatus');
    statusLabel.textContent = 'Online';
    statusLabel.className = 'status-indicator online';
  } catch (err) {
    showOfflineOverlay(err.message);
    const statusLabel = document.getElementById('infoDaemonStatus');
    statusLabel.textContent = 'Offline';
    statusLabel.className = 'status-indicator offline';
  } finally {
    if (refreshBtn) refreshBtn.disabled = false;
  }
}

function showOfflineOverlay(errorMsg) {
  document.getElementById('offlineOverlay').classList.remove('hidden');
  document.getElementById('offlineDetails').textContent = errorMsg || 'Unknown connection error';
}

function hideOfflineOverlay() {
  document.getElementById('offlineOverlay').classList.add('hidden');
}

/* ==========================================================================
   Dashboard Data Updates & Chart Renderers
   ========================================================================== */
function updateStats(data) {
  const totalEl = document.getElementById('valTotal');
  const forwardedEl = document.getElementById('valForwarded');
  const partialEl = document.getElementById('valPartiallyForwarded');
  const droppedEl = document.getElementById('valDropped');

  const total = data.total || 0;
  const forwarded = data.forwarded || 0;
  const partiallyForwarded = data.partially_forwarded || 0;
  const dropped = data.dropped || 0;

  totalEl.textContent = total.toLocaleString();
  forwardedEl.textContent = forwarded.toLocaleString();
  partialEl.textContent = partiallyForwarded.toLocaleString();
  droppedEl.textContent = dropped.toLocaleString();

  updateChartsData({ total, forwarded, partially_forwarded: partiallyForwarded, dropped });
  lastStatsData = { total, forwarded, partially_forwarded: partiallyForwarded, dropped };
}

function initCharts() {
  const ctx = document.getElementById('metricsChart').getContext('2d');
  const getGridColor = () => getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim();
  const getTextColor = () => getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();

  mainChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Total',
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.05)',
          borderWidth: 2,
          pointRadius: 1,
          pointHoverRadius: 4,
          data: [],
          fill: true,
          tension: 0.3
        },
        {
          label: 'Forwarded',
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.02)',
          borderWidth: 2,
          pointRadius: 1,
          pointHoverRadius: 4,
          data: [],
          fill: false,
          tension: 0.3
        },
        {
          label: 'Partially Forwarded',
          borderColor: '#f59e0b',
          backgroundColor: 'rgba(245, 158, 11, 0.02)',
          borderWidth: 2,
          pointRadius: 1,
          pointHoverRadius: 4,
          data: [],
          fill: false,
          tension: 0.3
        },
        {
          label: 'Dropped',
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.02)',
          borderWidth: 2,
          pointRadius: 1,
          pointHoverRadius: 4,
          data: [],
          fill: false,
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: getGridColor(), drawBorder: false },
          ticks: { color: getTextColor(), font: { size: 10, family: 'Inter' } }
        },
        y: {
          grid: { color: getGridColor(), drawBorder: false },
          ticks: { color: getTextColor(), font: { size: 10, family: 'Inter' }, precision: 0 }
        }
      },
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: getTextColor(),
            font: { size: 11, weight: '500', family: 'Inter' },
            boxWidth: 10,
            boxHeight: 10,
            usePointStyle: true
          }
        },
        tooltip: {
          mode: 'index',
          intersect: false,
          bodyFont: { family: 'Inter' },
          titleFont: { family: 'Inter' }
        }
      }
    }
  });

  initSparkline('Total', 'sparklineTotal', '#06b6d4');
  initSparkline('Forwarded', 'sparklineForwarded', '#10b981');
  initSparkline('PartiallyForwarded', 'sparklinePartiallyForwarded', '#f59e0b');
  initSparkline('Dropped', 'sparklineDropped', '#ef4444');
}

function initSparkline(id, canvasId, color) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  sparklines[id] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array(15).fill(''),
      datasets: [{
        data: Array(15).fill(0),
        borderColor: color,
        borderWidth: 1.5,
        pointRadius: 0,
        fill: false,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { display: false },
        y: { display: false }
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false }
      }
    }
  });
}

function updateChartsData(data) {
  if (!mainChart) return;

  const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  let deltaTotal = 0;
  let deltaForwarded = 0;
  let deltaPartial = 0;
  let deltaDropped = 0;

  if (lastStatsData) {
    deltaTotal = Math.max(0, data.total - lastStatsData.total);
    deltaForwarded = Math.max(0, data.forwarded - lastStatsData.forwarded);
    deltaPartial = Math.max(0, data.partially_forwarded - lastStatsData.partially_forwarded);
    deltaDropped = Math.max(0, data.dropped - lastStatsData.dropped);
  }

  mainChart.data.labels.push(timestamp);
  mainChart.data.datasets[0].data.push(deltaTotal);
  mainChart.data.datasets[1].data.push(deltaForwarded);
  mainChart.data.datasets[2].data.push(deltaPartial);
  mainChart.data.datasets[3].data.push(deltaDropped);

  if (mainChart.data.labels.length > chartWindowSize) {
    mainChart.data.labels.shift();
    mainChart.data.datasets.forEach(dataset => dataset.data.shift());
  }

  const getGridColor = () => getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim();
  const getTextColor = () => getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();
  
  mainChart.options.scales.x.grid.color = getGridColor();
  mainChart.options.scales.x.ticks.color = getTextColor();
  mainChart.options.scales.y.grid.color = getGridColor();
  mainChart.options.scales.y.ticks.color = getTextColor();
  mainChart.options.plugins.legend.labels.color = getTextColor();

  mainChart.update('none');

  updateSparklineData('Total', deltaTotal);
  updateSparklineData('Forwarded', deltaForwarded);
  updateSparklineData('PartiallyForwarded', deltaPartial);
  updateSparklineData('Dropped', deltaDropped);
}

function updateSparklineData(id, val) {
  const chart = sparklines[id];
  if (!chart) return;
  chart.data.datasets[0].data.push(val);
  chart.data.datasets[0].data.shift();
  chart.update('none');
}

function updateChartWindow() {
  if (!mainChart) return;
  while (mainChart.data.labels.length > chartWindowSize) {
    mainChart.data.labels.shift();
    mainChart.data.datasets.forEach(dataset => dataset.data.shift());
  }
  mainChart.update();
}

/* ==========================================================================
   Clear Statistics Action Handler
   ========================================================================== */
function confirmClearStats() {
  const chk = document.getElementById('chkClearTracking');
  if (chk) chk.checked = false;
  toggleModal('clearStatsModal', true);
}

async function executeClearStats() {
  toggleModal('clearStatsModal', false);
  const clearTracking = document.getElementById('chkClearTracking')?.checked || false;

  try {
    const res = await fetchApi('/api/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clear_tracking: clearTracking })
    });
    if (res.status === 'ok') {
      if (mainChart) {
        mainChart.data.labels = [];
        mainChart.data.datasets.forEach(dataset => dataset.data = []);
        mainChart.update();
      }
      Object.keys(sparklines).forEach(id => {
        sparklines[id].data.datasets[0].data = Array(15).fill(0);
        sparklines[id].update();
      });
      lastStatsData = null;

      if (clearTracking && currentMainView === 'history') {
        loadHistoryData(1);
      }

      refreshData();
    }
  } catch (err) {
    alert(`Failed to clear statistics: ${err.message}`);
  }
}

/* ==========================================================================
   Main View Switcher (Live Dashboard / Message History)
   ========================================================================== */
let currentMainView = 'live';

function switchMainView(view) {
  currentMainView = view;
  const btnLive = document.getElementById('viewBtnLive');
  const btnHistory = document.getElementById('viewBtnHistory');
  const viewLive = document.getElementById('liveDashboardView');
  const viewHistory = document.getElementById('messageHistoryView');

  if (view === 'live') {
    btnLive.classList.add('active');
    btnHistory.classList.remove('active');
    viewLive.classList.remove('hidden');
    viewHistory.classList.add('hidden');
  } else {
    btnLive.classList.remove('active');
    btnHistory.classList.add('active');
    viewLive.classList.add('hidden');
    viewHistory.classList.remove('hidden');
    loadHistoryData(currentHistoryPage);
  }

  lucide.createIcons();
}

/* ==========================================================================
   Message History Logic & Rendering
   ========================================================================== */
let currentHistoryPage = 1;
let totalHistoryPages = 1;
let expandedHistoryIds = new Set();
let currentHistoryRecords = [];

function onHistoryPresetChange() {
  const preset = document.getElementById('historyTimePreset').value;
  const customRow = document.getElementById('historyCustomTimeRow');
  if (preset === 'custom') {
    customRow.classList.remove('hidden');
  } else {
    customRow.classList.add('hidden');
    loadHistoryData(1);
  }
}

function getHistoryTimeRange() {
  const preset = document.getElementById('historyTimePreset').value;
  const now = Date.now() / 1000;

  if (preset === '15m') return { from: now - 15 * 60, to: null };
  if (preset === '1h') return { from: now - 3600, to: null };
  if (preset === '24h') return { from: now - 86400, to: null };
  if (preset === '7d') return { from: now - 7 * 86400, to: null };
  if (preset === 'all') return { from: null, to: null };
  if (preset === 'custom') {
    const fromVal = document.getElementById('historyTimeFrom').value;
    const toVal = document.getElementById('historyTimeTo').value;
    const from = fromVal ? new Date(fromVal).getTime() / 1000 : null;
    const to = toVal ? new Date(toVal).getTime() / 1000 : null;
    return { from, to };
  }
  return { from: now - 7 * 86400, to: null };
}

function resetHistoryFilters() {
  document.getElementById('historyQuerySearch').value = '';
  document.getElementById('historyResponseSearch').value = '';
  document.getElementById('historySrcIpFilter').value = '';
  document.getElementById('historyInterfaceFilter').value = '';
  document.getElementById('historyDstInterfaceFilter').value = '';
  document.getElementById('historyDispositionFilter').value = '';
  document.getElementById('historyTypeFilter').value = '';
  document.getElementById('historyTimePreset').value = '7d';
  document.getElementById('historyCustomTimeRow').classList.add('hidden');
  document.getElementById('historyTimeFrom').value = '';
  document.getElementById('historyTimeTo').value = '';
  loadHistoryData(1);
}

function historyGoToPage(page) {
  if (page < 1 || page > totalHistoryPages) return;
  loadHistoryData(page);
}

async function loadHistoryData(page = 1, silent = false) {
  currentHistoryPage = page;
  const pageSize = parseInt(document.getElementById('historyPageSize')?.value || '50', 10);
  const querySearch = document.getElementById('historyQuerySearch')?.value.trim() || '';
  const responseSearch = document.getElementById('historyResponseSearch')?.value.trim() || '';
  const srcIp = document.getElementById('historySrcIpFilter')?.value.trim() || '';
  const srcIface = document.getElementById('historyInterfaceFilter')?.value || '';
  const dstIface = document.getElementById('historyDstInterfaceFilter')?.value || '';
  const disposition = document.getElementById('historyDispositionFilter')?.value ?? '';
  const packetType = document.getElementById('historyTypeFilter')?.value ?? '';
  const { from, to } = getHistoryTimeRange();

  const tbody = document.getElementById('historyTableBody');
  if (!silent && currentHistoryRecords.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="table-empty">Loading message history...</td></tr>';
  }

  let url = `/api/history?page=${page}&limit=${pageSize}`;
  if (querySearch) url += `&query_search=${encodeURIComponent(querySearch)}`;
  if (responseSearch) url += `&response_search=${encodeURIComponent(responseSearch)}`;
  if (srcIp) url += `&src_ip=${encodeURIComponent(srcIp)}`;
  if (srcIface) url += `&src_interface=${encodeURIComponent(srcIface)}`;
  if (dstIface) url += `&dst_interface=${encodeURIComponent(dstIface)}`;
  if (disposition !== '') url += `&disposition=${encodeURIComponent(disposition)}`;
  if (packetType !== '') url += `&packet_type=${encodeURIComponent(packetType)}`;
  if (from !== null && !isNaN(from)) url += `&from_time=${from}`;
  if (to !== null && !isNaN(to)) url += `&to_time=${to}`;

  try {
    const res = await fetchApi(url);
    const data = res.data;
    if (data.interfaces) {
      updateInterfaceDropdowns(data.interfaces);
    }
    currentHistoryRecords = data.records || [];
    const total = data.total || 0;
    totalHistoryPages = data.total_pages || 1;

    renderHistoryTable(currentHistoryRecords, total, page, pageSize);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty">Error loading history: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function toggleHistoryExpand(recordId, e) {
  if (e) e.stopPropagation();
  if (expandedHistoryIds.has(recordId)) {
    expandedHistoryIds.delete(recordId);
  } else {
    expandedHistoryIds.add(recordId);
  }
  renderHistoryTableRows();
}

function renderRoutingBadges(fwdStr, dropStr) {
  const fwd = (fwdStr || '').split(',').map(x => x.trim()).filter(Boolean);
  const drop = (dropStr || '').split(',').map(x => x.trim()).filter(Boolean);
  const badges = [];
  fwd.forEach(iface => {
    badges.push(`<span class="route-badge-fwd" title="Forwarded to ${escapeHtml(iface)}">${escapeHtml(iface)}</span>`);
  });
  drop.forEach(iface => {
    badges.push(`<span class="route-badge-drop" title="Dropped on ${escapeHtml(iface)}">${escapeHtml(iface)}</span>`);
  });
  if (badges.length === 0) {
    return '<span style="color: var(--text-muted); font-size: 11px;">None</span>';
  }
  return badges.join(' ');
}

function renderHistoryTable(records, total, page, pageSize) {
  const startIdx = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const endIdx = Math.min(page * pageSize, total);
  document.getElementById('historyPaginationInfo').textContent = `Showing ${startIdx.toLocaleString()} - ${endIdx.toLocaleString()} of ${total.toLocaleString()} messages`;
  document.getElementById('historyPageIndicator').textContent = `Page ${page} of ${totalHistoryPages}`;

  document.getElementById('btnHistFirst').disabled = page <= 1;
  document.getElementById('btnHistPrev').disabled = page <= 1;
  document.getElementById('btnHistNext').disabled = page >= totalHistoryPages;
  document.getElementById('btnHistLast').disabled = page >= totalHistoryPages;

  renderHistoryTableRows();
}

function renderHistoryTableRows() {
  const tbody = document.getElementById('historyTableBody');
  tbody.innerHTML = '';

  if (currentHistoryRecords.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No matching mDNS messages found.</td></tr>';
    return;
  }

  currentHistoryRecords.forEach((record, index) => {
    const recordId = record.id !== undefined && record.id !== null ? record.id : index;
    const isExpanded = expandedHistoryIds.has(recordId);
    const items = Array.isArray(record.items) ? record.items : [];
    const questions = items.filter(i => i.section === 0);
    const rrItems = items.filter(i => i.section !== 0);

    const d = new Date(record.timestamp * 1000);
    const timeFormatted = d.toLocaleDateString() + ' ' + d.toLocaleTimeString();

    const ptype = packetTypeInfo(record.packet_type);
    const msgDotHtml = renderDispositionDot(record.disposition, record.forwarded_interfaces, record.dropped_interfaces, false);

    let dstBadges = '<span style="color: var(--text-muted); font-size: 11px;">None</span>';
    if (record.forwarded_interfaces) {
      dstBadges = record.forwarded_interfaces.split(',').map(x => x.trim()).filter(Boolean)
        .map(x => `<span class="route-badge-fwd" title="Forwarded to ${escapeHtml(x)}">${escapeHtml(x)}</span>`)
        .join(' ');
    }

    // Build inline item pills with red/yellow/green dots & tooltips
    const maxPreviewItems = 5;
    const previewPills = items.slice(0, maxPreviewItems).map(item => {
      const dot = renderDispositionDot(item.disposition, item.forwarded_interfaces, item.dropped_interfaces, true);
      const tName = dnsTypeToString(item.rr_type);
      const prefix = item.section === 0 ? 'Q' : 'R';
      const label = `${prefix}: ${shortenServiceName(item.name)} (${tName})`;
      const fullTitle = item.rdata_summary
        ? `${sectionToString(item.section)}: ${item.name} (${tName}) -> ${item.rdata_summary}`
        : `${sectionToString(item.section)}: ${item.name} (${tName})`;
      return `<span class="preview-item-pill">${dot}<span class="preview-item-text" title="${escapeHtml(fullTitle)}">${escapeHtml(label)}</span></span>`;
    });
    if (items.length > maxPreviewItems) {
      previewPills.push(`<span class="badge" style="font-size: 11px;">+${items.length - maxPreviewItems} more</span>`);
    }
    const previewHtml = previewPills.length > 0
      ? `<div class="preview-items-wrap">${previewPills.join('')}</div>`
      : '<span style="color: var(--text-muted); font-size: 12px;">None</span>';

    const tr = document.createElement('tr');
    tr.className = `history-row ${isExpanded ? 'expanded' : ''}`;
    tr.onclick = (e) => toggleHistoryExpand(recordId, e);

    tr.innerHTML = `
      <td>
        <span class="history-expand-icon">
          <i data-lucide="${isExpanded ? 'chevron-down' : 'chevron-right'}"></i>
        </span>
      </td>
      <td style="text-align: center;">${msgDotHtml}</td>
      <td title="${record.timestamp} (UNIX)">${timeFormatted}</td>
      <td><strong>${escapeHtml(record.src_ip)}</strong></td>
      <td><span class="badge" style="font-size: 11px;">${escapeHtml(record.src_interface)}</span></td>
      <td><span class="badge-type ${ptype.css}">${ptype.label}</span></td>
      <td><div style="display: flex; gap: 4px; flex-wrap: wrap;">${dstBadges}</div></td>
      <td>${previewHtml}</td>
    `;
    tbody.appendChild(tr);

    if (isExpanded) {
      const detailTr = document.createElement('tr');
      detailTr.className = 'history-detail-tr';
      const msgDispInfo = dispositionInfo(record.disposition, record.forwarded_interfaces, record.dropped_interfaces);

      let questionsHtml = '<tr><td colspan="5" class="table-empty" style="padding: 12px 0 !important;">No questions in packet.</td></tr>';
      if (questions.length > 0) {
        questionsHtml = questions.map(q => {
          const qDot = renderDispositionDot(q.disposition, q.forwarded_interfaces, q.dropped_interfaces, false);
          const qType = dnsTypeToString(q.rr_type);
          const qClass = dnsClassToString(q.rr_class);
          const qRoutes = renderRoutingBadges(q.forwarded_interfaces, q.dropped_interfaces);
          return `
            <tr>
              <td style="text-align: center; width: 42px;">${qDot}</td>
              <td>
                <div class="service-name-wrapper">
                  <span title="${escapeHtml(q.name)}">${escapeHtml(shortenServiceName(q.name))}</span>
                  <button class="copy-name-btn" title="Copy name" onclick="copyToClipboard('${escapeHtml(q.name)}', this, event)">
                    <i data-lucide="copy"></i>
                  </button>
                </div>
              </td>
              <td><span class="badge-type query">${escapeHtml(qType)}</span></td>
              <td>${escapeHtml(qClass)}</td>
              <td><div style="display: flex; gap: 4px; flex-wrap: wrap;">${qRoutes}</div></td>
            </tr>
          `;
        }).join('');
      }

      let answersHtml = '<tr><td colspan="7" class="table-empty" style="padding: 12px 0 !important;">No resource records in packet.</td></tr>';
      if (rrItems.length > 0) {
        answersHtml = rrItems.map(r => {
          const rDot = renderDispositionDot(r.disposition, r.forwarded_interfaces, r.dropped_interfaces, false);
          const secName = sectionToString(r.section);
          const rType = dnsTypeToString(r.rr_type);
          const rRoutes = renderRoutingBadges(r.forwarded_interfaces, r.dropped_interfaces);
          const ttlText = r.ttl !== null && r.ttl !== undefined ? `${r.ttl}s` : '-';
          const rdataHtml = r.rdata_summary
            ? `<div class="service-name-wrapper">
                 <span title="${escapeHtml(r.rdata_summary)}">${escapeHtml(shortenServiceName(r.rdata_summary))}</span>
                 <button class="copy-name-btn" title="Copy record data" onclick="copyToClipboard('${escapeHtml(r.rdata_summary)}', this, event)">
                   <i data-lucide="copy"></i>
                 </button>
               </div>`
            : '<span style="color: var(--text-muted);">-</span>';

          return `
            <tr>
              <td style="text-align: center; width: 42px;">${rDot}</td>
              <td><span class="badge-section">${escapeHtml(secName)}</span></td>
              <td>
                <div class="service-name-wrapper">
                  <span title="${escapeHtml(r.name)}">${escapeHtml(shortenServiceName(r.name))}</span>
                  <button class="copy-name-btn" title="Copy name" onclick="copyToClipboard('${escapeHtml(r.name)}', this, event)">
                    <i data-lucide="copy"></i>
                  </button>
                </div>
              </td>
              <td><span class="badge-type response">${escapeHtml(rType)}</span></td>
              <td>${escapeHtml(ttlText)}</td>
              <td>${rdataHtml}</td>
              <td><div style="display: flex; gap: 4px; flex-wrap: wrap;">${rRoutes}</div></td>
            </tr>
          `;
        }).join('');
      }

      detailTr.innerHTML = `
        <td colspan="8">
          <div class="history-detail-content">
            <div class="routing-summary-box">
              <div class="routing-summary-item">
                <span class="routing-summary-label">Disposition:</span>
                ${msgDotHtml}
                <strong>${escapeHtml(msgDispInfo.label)}</strong>
              </div>
              <div class="routing-summary-item">
                <span class="routing-summary-label">Source:</span>
                <span><strong>${escapeHtml(record.src_ip)}</strong> on <code>${escapeHtml(record.src_interface)}</code></span>
              </div>
              <div class="routing-summary-item">
                <span class="routing-summary-label">Interface Routing:</span>
                <div style="display: flex; gap: 4px; flex-wrap: wrap;">${renderRoutingBadges(record.forwarded_interfaces, record.dropped_interfaces)}</div>
              </div>
              <div class="routing-summary-item">
                <span class="routing-summary-label">Exact Timestamp:</span>
                <code>${record.timestamp}</code>
              </div>
            </div>

            <div class="detail-grid">
              <div class="detail-card">
                <div class="detail-card-title">
                  <i data-lucide="help-circle" style="width: 14px; height: 14px;"></i>
                  <span>Questions (${questions.length})</span>
                </div>
                <table class="detail-card-table">
                  <thead>
                    <tr>
                      <th style="width: 42px; text-align: center;">Status</th>
                      <th>Query Name</th>
                      <th>Type</th>
                      <th>Class</th>
                      <th>Routing</th>
                    </tr>
                  </thead>
                  <tbody>${questionsHtml}</tbody>
                </table>
              </div>

              <div class="detail-card">
                <div class="detail-card-title">
                  <i data-lucide="database" style="width: 14px; height: 14px;"></i>
                  <span>Resource Records (${rrItems.length})</span>
                </div>
                <table class="detail-card-table">
                  <thead>
                    <tr>
                      <th style="width: 42px; text-align: center;">Status</th>
                      <th>Section</th>
                      <th>Record Name</th>
                      <th>Type</th>
                      <th>TTL</th>
                      <th>Decoded Data</th>
                      <th>Routing</th>
                    </tr>
                  </thead>
                  <tbody>${answersHtml}</tbody>
                </table>
              </div>
            </div>
          </div>
        </td>
      `;
      tbody.appendChild(detailTr);
    }
  });

  lucide.createIcons();
}
