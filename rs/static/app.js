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

async function copyToClipboard(btnOrText, btnOrEvent, maybeEvent) {
  let text = '';
  let btn = null;
  let event = null;

  if (typeof btnOrText === 'string') {
    text = btnOrText;
    btn = btnOrEvent;
    event = maybeEvent;
  } else if (btnOrText && btnOrText.dataset) {
    text = btnOrText.dataset.copy || '';
    btn = btnOrText;
    event = btnOrEvent;
  }

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
   Main View Switcher (Live Dashboard / Message History / Configuration)
   ========================================================================== */
let currentMainView = 'live';

function switchMainView(view) {
  currentMainView = view;
  const btnLive = document.getElementById('viewBtnLive');
  const btnHistory = document.getElementById('viewBtnHistory');
  const btnSsdp = document.getElementById('viewBtnSsdp');
  const btnConfig = document.getElementById('viewBtnConfig');
  const viewLive = document.getElementById('liveDashboardView');
  const viewHistory = document.getElementById('messageHistoryView');
  const viewSsdp = document.getElementById('ssdpHistoryView');
  const viewConfig = document.getElementById('configurationView');

  btnLive.classList.toggle('active', view === 'live');
  btnHistory.classList.toggle('active', view === 'history');
  if (btnSsdp) btnSsdp.classList.toggle('active', view === 'ssdp');
  if (btnConfig) btnConfig.classList.toggle('active', view === 'config');

  viewLive.classList.toggle('hidden', view !== 'live');
  viewHistory.classList.toggle('hidden', view !== 'history');
  if (viewSsdp) viewSsdp.classList.toggle('hidden', view !== 'ssdp');
  if (viewConfig) viewConfig.classList.toggle('hidden', view !== 'config');

  if (view === 'history') {
    loadHistoryData(currentHistoryPage);
  } else if (view === 'ssdp') {
    loadSsdpHistory(1);
  } else if (view === 'config') {
    ensureConfigViewInitialized();
  }

  lucide.createIcons();
}

async function loadSsdpHistory(page = 1) {
  const tbody = document.getElementById('ssdpHistoryTableBody');
  const totalBadge = document.getElementById('ssdpTotalCount');
  if (!tbody) return;
  try {
    const res = await fetch(`/api/ssdp/history?page=${page}&limit=50`);
    const data = await res.json();
    if (totalBadge) totalBadge.textContent = `${data.total || 0} records`;
    const items = data.items || [];
    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center">No SSDP messages recorded yet.</td></tr>';
      return;
    }
    const dispLabel = (d) => d === 0 ? '<span class="badge badge-success">Forwarded</span>'
      : d === 1 ? '<span class="badge badge-warning">Partial</span>'
      : '<span class="badge badge-danger">Dropped</span>';
    tbody.innerHTML = items.map(item => {
      const ts = new Date(item.timestamp * 1000).toLocaleTimeString();
      return `<tr>
        <td>${ts}</td>
        <td><code>${item.src_ip}</code></td>
        <td>${item.src_interface}</td>
        <td><strong>${item.method}</strong></td>
        <td>${item.st || '-'}</td>
        <td>${item.usn || '-'}</td>
        <td>${dispLabel(item.disposition)}</td>
        <td>${(item.forwarded_interfaces || []).join(', ') || '-'}</td>
        <td>${(item.dropped_interfaces || []).join(', ') || '-'}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center">Failed to load SSDP history: ${e}</td></tr>`;
  }
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

      let questionsHtml = '<tr><td colspan="6" class="table-empty" style="padding: 12px 0 !important;">No questions in packet.</td></tr>';
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
                  <button class="copy-name-btn" title="Copy name" data-copy="${escapeHtml(q.name)}" onclick="copyToClipboard(this, event)">
                    <i data-lucide="copy"></i>
                  </button>
                </div>
              </td>
              <td><span class="badge-type query">${escapeHtml(qType)}</span></td>
              <td>${escapeHtml(qClass)}</td>
              <td><div style="display: flex; gap: 4px; flex-wrap: wrap;">${qRoutes}</div></td>
              <td style="text-align: right; width: 72px;">
                <button class="btn-quick-rule" title="Create filtering rule from this question"
                  data-src="${escapeHtml(record.src_interface)}"
                  data-disp="${q.disposition}"
                  data-section="questions"
                  data-name="${escapeHtml(q.name)}"
                  data-rrtype="${q.rr_type}"
                  onclick="createQuickRuleFromHistory(this, event)">
                  <i data-lucide="plus"></i>
                  <span>Rule</span>
                </button>
              </td>
            </tr>
          `;
        }).join('');
      }

      let answersHtml = '<tr><td colspan="8" class="table-empty" style="padding: 12px 0 !important;">No resource records in packet.</td></tr>';
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
                 <button class="copy-name-btn" title="Copy record data" data-copy="${escapeHtml(r.rdata_summary)}" onclick="copyToClipboard(this, event)">
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
                  <button class="copy-name-btn" title="Copy name" data-copy="${escapeHtml(r.name)}" onclick="copyToClipboard(this, event)">
                    <i data-lucide="copy"></i>
                  </button>
                </div>
              </td>
              <td><span class="badge-type response">${escapeHtml(rType)}</span></td>
              <td>${escapeHtml(ttlText)}</td>
              <td>${rdataHtml}</td>
              <td><div style="display: flex; gap: 4px; flex-wrap: wrap;">${rRoutes}</div></td>
              <td style="text-align: right; width: 72px;">
                <button class="btn-quick-rule" title="Create filtering rule from this resource record"
                  data-src="${escapeHtml(record.src_interface)}"
                  data-disp="${r.disposition}"
                  data-section="answers"
                  data-name="${escapeHtml(r.name)}"
                  data-rrtype="${r.rr_type}"
                  onclick="createQuickRuleFromHistory(this, event)">
                  <i data-lucide="plus"></i>
                  <span>Rule</span>
                </button>
              </td>
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
                      <th style="width: 72px; text-align: right;">Action</th>
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
                      <th style="width: 72px; text-align: right;">Action</th>
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

/* ==========================================================================
   Configuration Manager & Visual Rule Builder
   ========================================================================== */
let configInitialized = false;
let savedConfigData = null;
let draftConfigData = null;
let lastServerYaml = '';
let configFilePath = '/etc/mdns-sieve.yaml';
let detectedSystemInterfaces = [];
let serverRestartRequired = false;
let boundWebServer = null;
let highlightedRuleIndex = null;
let draggedRuleIndex = null;

function defaultConfigTemplate() {
  return {
    interfaces: [],
    default_action: 'forward',
    rewrite_mixed_packets: false,
    forward_known_answers: false,
    web_server: {
      enabled: true,
      host: '0.0.0.0',
      port: 8080,
    },
    tracking: {
      enabled: true,
      max_records: 50000,
      db_path: '/var/lib/mdns-sieve/responses.db',
      flush_interval_seconds: 3600,
      retention_days: 7,
    },
    rules: [],
    ssdp: {
      enabled: false,
      interfaces: [],
      default_action: 'forward',
      rules: [],
    },
  };
}

function normalizeConfigData(raw) {
  const base = defaultConfigTemplate();
  if (!raw || typeof raw !== 'object') return base;

  const interfaces = Array.isArray(raw.interfaces)
    ? raw.interfaces.map(s => String(s).trim()).filter(Boolean)
    : [];

  const default_action = String(raw.default_action || 'forward').toLowerCase() === 'drop' ? 'drop' : 'forward';
  const rewrite_mixed_packets = Boolean(raw.rewrite_mixed_packets);
  const forward_known_answers = Boolean(raw.forward_known_answers);

  const ws = raw.web_server || {};
  const web_server = {
    enabled: true,
    host: String(ws.host || '0.0.0.0').trim() || '0.0.0.0',
    port: Number(ws.port) > 0 ? Number(ws.port) : 8080,
  };

  const tr = raw.tracking || {};
  const retention = tr.retention_days !== undefined && tr.retention_days !== null
    ? Number(tr.retention_days)
    : (tr.history_retention_days !== undefined && tr.history_retention_days !== null ? Number(tr.history_retention_days) : 7);
  const maxRecs = tr.max_records !== undefined && tr.max_records !== null
    ? Number(tr.max_records)
    : (tr.max_history_records !== undefined && tr.max_history_records !== null ? Number(tr.max_history_records) : 50000);

  const tracking = {
    enabled: tr.enabled !== undefined ? Boolean(tr.enabled) : true,
    max_records: !isNaN(maxRecs) && maxRecs >= 0 ? maxRecs : 50000,
    db_path: String(tr.db_path || '/var/lib/mdns-sieve/responses.db').trim() || '/var/lib/mdns-sieve/responses.db',
    flush_interval_seconds: Number(tr.flush_interval_seconds) > 0 ? Number(tr.flush_interval_seconds) : 3600,
    retention_days: !isNaN(retention) && retention > 0 ? retention : 7,
  };

  const rules = Array.isArray(raw.rules)
    ? raw.rules.map(normalizeRuleItem)
    : [];

  const rawSsdp = raw.ssdp || {};
  const ssdp = {
    enabled: Boolean(rawSsdp.enabled),
    interfaces: Array.isArray(rawSsdp.interfaces)
      ? rawSsdp.interfaces.map(s => String(s).trim()).filter(Boolean)
      : [],
    default_action: String(rawSsdp.default_action || 'forward').toLowerCase() === 'drop' ? 'drop' : 'forward',
    rules: Array.isArray(rawSsdp.rules)
      ? rawSsdp.rules.map(r => ({
          action: String((r && r.action) || 'allow').toLowerCase() === 'deny' ? 'deny' : 'allow',
          method: r && r.method ? String(r.method).trim().toUpperCase() : null,
          from: Array.isArray(r && r.from) ? r.from.map(s => String(s).trim()).filter(Boolean) : null,
          to: Array.isArray(r && r.to) ? r.to.map(s => String(s).trim()).filter(Boolean) : null,
          st: r && r.st ? String(r.st).trim() : null,
          usn: r && r.usn ? String(r.usn).trim() : null,
        }))
      : [],
  };

  return {
    interfaces,
    default_action,
    rewrite_mixed_packets,
    forward_known_answers,
    web_server,
    tracking,
    rules,
    ssdp,
  };
}

function normalizeEndpointList(val) {
  if (!val) return ['*'];
  if (Array.isArray(val)) {
    const cleaned = val.map(v => String(v).trim()).filter(Boolean);
    if (cleaned.length === 0 || cleaned.includes('*')) return ['*'];
    return Array.from(new Set(cleaned));
  }
  const s = String(val).trim();
  if (!s || s === '*') return ['*'];
  return [s];
}

function serializeEndpointValue(list) {
  const arr = normalizeEndpointList(list);
  if (arr.length === 1) return arr[0];
  return arr;
}

function normalizeRuleItem(r) {
  if (!r || typeof r !== 'object') {
    return {
      action: 'forward',
      section: 'any',
      src: '*',
      dst: '*',
      services: [],
      hosts: [],
    };
  }
  const action = String(r.action || 'forward').toLowerCase() === 'drop' ? 'drop' : 'forward';
  const rawSec = String(r.section || 'any').toLowerCase();
  const section = (rawSec === 'questions' || rawSec === 'answers') ? rawSec : 'any';
  const services = Array.isArray(r.services) ? r.services.map(s => String(s).trim()).filter(Boolean) : [];
  const hosts = Array.isArray(r.hosts) ? r.hosts.map(s => String(s).trim()).filter(Boolean) : [];
  const src = serializeEndpointValue(r.src);
  const dst = serializeEndpointValue(r.dst);

  return {
    action,
    section,
    src,
    dst,
    services,
    hosts,
  };
}

function cloneConfig(cfg) {
  return normalizeConfigData(JSON.parse(JSON.stringify(cfg)));
}

function isConfigDirty() {
  if (!savedConfigData || !draftConfigData) return false;
  return JSON.stringify(savedConfigData) !== JSON.stringify(draftConfigData);
}

async function ensureConfigViewInitialized() {
  if (!configInitialized) {
    configInitialized = true;
    await Promise.all([loadConfigFromServer(), loadSystemInterfaces()]);
  } else {
    loadSystemInterfaces();
    renderConfigView();
  }
}

async function loadConfigFromServer() {
  try {
    const res = await fetch('/api/config');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (payload.status !== 'ok' || !payload.data) {
      throw new Error(payload.error || 'Failed to load configuration');
    }

    const data = payload.data;
    savedConfigData = normalizeConfigData(data.config);
    draftConfigData = cloneConfig(savedConfigData);
    lastServerYaml = data.yaml || '';
    configFilePath = data.config_path || '/etc/mdns-sieve.yaml';
    serverRestartRequired = Boolean(data.restart_required);
    boundWebServer = data.bound_web_server || null;

    renderConfigView();
  } catch (err) {
    console.error('Failed to load config from server:', err);
    if (!savedConfigData) {
      savedConfigData = defaultConfigTemplate();
      draftConfigData = cloneConfig(savedConfigData);
    }
    showConfigFeedback('error', `Failed to load configuration: ${err.message}`);
    renderConfigView();
  }
}

async function loadSystemInterfaces() {
  try {
    const res = await fetch('/api/interfaces');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (payload.status === 'ok' && payload.data) {
      detectedSystemInterfaces = Array.isArray(payload.data.detected) ? payload.data.detected : [];
      renderInterfacesSection();
      renderRulesList();
      lucide.createIcons();
    }
  } catch (err) {
    console.error('Failed to scan system interfaces:', err);
  }
}

function updateDirtyStateUI() {
  const dirty = isConfigDirty();
  const navBadge = document.getElementById('configDirtyBadge');
  const stateBadge = document.getElementById('configStateBadge');
  const stateText = document.getElementById('configStateText');
  const btnDiscard = document.getElementById('btnDiscardConfig');
  const btnSave = document.getElementById('btnSaveConfig');
  const pathEl = document.getElementById('configFilePath');
  const restartBanner = document.getElementById('configRestartBanner');

  if (pathEl) pathEl.textContent = configFilePath;

  if (navBadge) {
    navBadge.classList.toggle('hidden', !dirty);
  }

  if (stateBadge && stateText) {
    if (dirty) {
      stateBadge.className = 'config-state-badge dirty';
      stateText.textContent = 'Unsaved configuration changes';
    } else {
      stateBadge.className = 'config-state-badge saved';
      stateText.textContent = 'All changes saved & active';
    }
  }

  if (btnDiscard) btnDiscard.disabled = !dirty;
  if (btnSave) btnSave.disabled = !dirty;

  if (restartBanner) {
    restartBanner.classList.toggle('hidden', !serverRestartRequired);
  }
}

function renderConfigView() {
  if (!draftConfigData) return;

  updateDirtyStateUI();
  renderInterfacesSection();
  renderGlobalPolicySection();
  renderRulesList();
  renderTrackingAndWebSection();
  renderSsdpConfigSection();
  lucide.createIcons();
}

function renderSsdpConfigSection() {
  if (!draftConfigData) return;
  const ssdp = draftConfigData.ssdp || { enabled: false, interfaces: [], default_action: 'forward', rules: [] };
  const enabledEl = document.getElementById('cfgSsdpEnabled');
  const defaultActionEl = document.getElementById('cfgSsdpDefaultAction');
  const ifacesEl = document.getElementById('cfgSsdpInterfacesContainer');
  const rulesEl = document.getElementById('cfgSsdpRulesContainer');

  if (enabledEl) enabledEl.checked = Boolean(ssdp.enabled);
  if (defaultActionEl) defaultActionEl.value = ssdp.default_action || 'forward';

  if (ifacesEl) {
    const activeSet = new Set(ssdp.interfaces || []);
    const allIfaces = allKnownInterfaceNames();
    if (allIfaces.length === 0) {
      ifacesEl.innerHTML = '<span class="help-text">No interfaces detected.</span>';
    } else {
      ifacesEl.innerHTML = allIfaces.map(name => {
        const isSelected = activeSet.has(name);
        const iconName = isSelected ? 'check-square' : 'square';
        return `
          <div class="iface-chip ${isSelected ? 'selected' : ''}" onclick="toggleSsdpInterface('${escapeHtml(name)}')">
            <i data-lucide="${iconName}"></i>
            <span>${escapeHtml(name)}</span>
          </div>
        `;
      }).join('');
    }
  }

  if (rulesEl) {
    const rules = ssdp.rules || [];
    if (rules.length === 0) {
      rulesEl.innerHTML = '<p class="help-text">No SSDP rules configured. The SSDP default action applies to all packets.</p>';
    } else {
      rulesEl.innerHTML = rules.map((r, idx) => `
        <div class="rule-card" style="margin-bottom: 8px; padding: 10px;">
          <div class="config-form-grid">
            <div class="form-group">
              <label>Action</label>
              <select class="config-input" onchange="updateSsdpRule(${idx}, 'action', this.value)">
                <option value="allow" ${r.action === 'allow' ? 'selected' : ''}>Allow</option>
                <option value="deny" ${r.action === 'deny' ? 'selected' : ''}>Deny</option>
              </select>
            </div>
            <div class="form-group">
              <label>Method</label>
              <select class="config-input" onchange="updateSsdpRule(${idx}, 'method', this.value)">
                <option value="" ${!r.method ? 'selected' : ''}>Any (*)</option>
                <option value="M-SEARCH" ${r.method === 'M-SEARCH' ? 'selected' : ''}>M-SEARCH</option>
                <option value="NOTIFY" ${r.method === 'NOTIFY' ? 'selected' : ''}>NOTIFY</option>
                <option value="RESPONSE" ${r.method === 'RESPONSE' ? 'selected' : ''}>RESPONSE (200 OK)</option>
              </select>
            </div>
            <div class="form-group">
              <label>From Interfaces (comma-sep)</label>
              <input type="text" class="config-input" placeholder="* or eth0,wlan0" value="${escapeHtml((r.from || []).join(','))}" onchange="updateSsdpRule(${idx}, 'from', this.value)">
            </div>
            <div class="form-group">
              <label>To Interfaces (comma-sep)</label>
              <input type="text" class="config-input" placeholder="* or eth0,wlan0" value="${escapeHtml((r.to || []).join(','))}" onchange="updateSsdpRule(${idx}, 'to', this.value)">
            </div>
            <div class="form-group">
              <label>ST / NT Pattern</label>
              <input type="text" class="config-input" placeholder="e.g. urn:schemas-upnp-org:*" value="${escapeHtml(r.st || '')}" onchange="updateSsdpRule(${idx}, 'st', this.value)">
            </div>
            <div class="form-group">
              <label>USN Pattern</label>
              <input type="text" class="config-input" placeholder="e.g. uuid:*" value="${escapeHtml(r.usn || '')}" onchange="updateSsdpRule(${idx}, 'usn', this.value)">
            </div>
          </div>
          <div style="margin-top: 8px; text-align: right;">
            <button type="button" class="btn btn-secondary" onclick="deleteSsdpRule(${idx})">
              <i data-lucide="trash-2"></i>
              <span>Delete Rule</span>
            </button>
          </div>
        </div>
      `).join('');
    }
  }
}

function onSsdpConfigChange() {
  if (!draftConfigData) return;
  if (!draftConfigData.ssdp) draftConfigData.ssdp = { enabled: false, interfaces: [], default_action: 'forward', rules: [] };
  const enabledEl = document.getElementById('cfgSsdpEnabled');
  const defaultActionEl = document.getElementById('cfgSsdpDefaultAction');
  if (enabledEl) draftConfigData.ssdp.enabled = enabledEl.checked;
  if (defaultActionEl) draftConfigData.ssdp.default_action = defaultActionEl.value;
  updateDirtyStateUI();
}

function toggleSsdpInterface(name) {
  if (!draftConfigData) return;
  if (!draftConfigData.ssdp) draftConfigData.ssdp = { enabled: false, interfaces: [], default_action: 'forward', rules: [] };
  const list = draftConfigData.ssdp.interfaces || [];
  const idx = list.indexOf(name);
  if (idx >= 0) {
    list.splice(idx, 1);
  } else {
    list.push(name);
  }
  draftConfigData.ssdp.interfaces = list;
  renderSsdpConfigSection();
  updateDirtyStateUI();
  lucide.createIcons();
}

function addSsdpRule() {
  if (!draftConfigData) return;
  if (!draftConfigData.ssdp) draftConfigData.ssdp = { enabled: false, interfaces: [], default_action: 'forward', rules: [] };
  draftConfigData.ssdp.rules.push({
    action: 'allow',
    method: null,
    from: null,
    to: null,
    st: null,
    usn: null,
  });
  renderSsdpConfigSection();
  updateDirtyStateUI();
  lucide.createIcons();
}

function deleteSsdpRule(idx) {
  if (!draftConfigData || !draftConfigData.ssdp) return;
  draftConfigData.ssdp.rules.splice(idx, 1);
  renderSsdpConfigSection();
  updateDirtyStateUI();
  lucide.createIcons();
}

function updateSsdpRule(idx, field, val) {
  if (!draftConfigData || !draftConfigData.ssdp || !draftConfigData.ssdp.rules[idx]) return;
  const rule = draftConfigData.ssdp.rules[idx];
  if (field === 'from' || field === 'to') {
    const arr = String(val).split(',').map(s => s.trim()).filter(Boolean);
    rule[field] = arr.length > 0 ? arr : null;
  } else if (field === 'method' || field === 'st' || field === 'usn') {
    const trimmed = String(val).trim();
    rule[field] = trimmed.length > 0 ? trimmed : null;
  } else {
    rule[field] = val;
  }
  updateDirtyStateUI();
}

function allKnownInterfaceNames() {
  const names = new Set();
  detectedSystemInterfaces.forEach(item => {
    if (item && item.name) names.add(item.name);
  });
  if (draftConfigData && Array.isArray(draftConfigData.interfaces)) {
    draftConfigData.interfaces.forEach(iface => names.add(iface));
  }
  return Array.from(names);
}

function renderInterfacesSection() {
  if (!draftConfigData) return;
  const detectedWrap = document.getElementById('detectedInterfacesContainer');
  const activeWrap = document.getElementById('activeInterfacesContainer');
  const activeSet = new Set(draftConfigData.interfaces);

  if (detectedWrap) {
    if (detectedSystemInterfaces.length === 0) {
      detectedWrap.innerHTML = '<span class="help-text">No physical/virtual network interfaces detected in /sys/class/net. Use the custom input below.</span>';
    } else {
      detectedWrap.innerHTML = detectedSystemInterfaces.map(iface => {
        const isSelected = activeSet.has(iface.name);
        const oper = String(iface.operstate || 'unknown').toLowerCase();
        const isUp = oper === 'up' || oper === 'unknown';
        const badgeClass = isUp ? 'up' : 'down';
        const badgeLabel = oper === 'up' ? 'UP' : (oper === 'down' ? 'DOWN' : oper.toUpperCase());
        const iconName = isSelected ? 'check-square' : 'square';
        return `
          <div class="iface-chip ${isSelected ? 'selected' : ''}" onclick="toggleInterfaceSelection('${escapeHtml(iface.name)}')" title="Click to ${isSelected ? 'remove' : 'add'} ${escapeHtml(iface.name)}">
            <i data-lucide="${iconName}"></i>
            <span>${escapeHtml(iface.name)}</span>
            <span class="iface-oper-badge ${badgeClass}">${escapeHtml(badgeLabel)}</span>
          </div>
        `;
      }).join('');
    }
  }

  if (activeWrap) {
    if (draftConfigData.interfaces.length === 0) {
      activeWrap.innerHTML = '<span class="help-text" style="color: var(--color-warning);">No interfaces selected. Select at least two interfaces to reflect mDNS packets between networks.</span>';
    } else {
      activeWrap.innerHTML = draftConfigData.interfaces.map(name => `
        <span class="iface-active-pill">
          <i data-lucide="network" style="width: 13px; height: 13px; color: var(--color-primary);"></i>
          <span>${escapeHtml(name)}</span>
          <button type="button" onclick="removeConfiguredInterface('${escapeHtml(name)}')" title="Remove ${escapeHtml(name)}">
            <i data-lucide="x"></i>
          </button>
        </span>
      `).join('');
    }
  }
}

function toggleInterfaceSelection(ifaceName) {
  if (!draftConfigData) return;
  const idx = draftConfigData.interfaces.indexOf(ifaceName);
  if (idx >= 0) {
    draftConfigData.interfaces.splice(idx, 1);
  } else {
    draftConfigData.interfaces.push(ifaceName);
  }
  updateDirtyStateUI();
  renderInterfacesSection();
  renderRulesList();
  lucide.createIcons();
}

function removeConfiguredInterface(ifaceName) {
  if (!draftConfigData) return;
  draftConfigData.interfaces = draftConfigData.interfaces.filter(i => i !== ifaceName);
  updateDirtyStateUI();
  renderInterfacesSection();
  renderRulesList();
  lucide.createIcons();
}

function addCustomInterface() {
  if (!draftConfigData) return;
  const input = document.getElementById('customInterfaceInput');
  if (!input) return;
  const raw = input.value.trim();
  if (!raw) return;

  if (/\s|\/|\\/.test(raw)) {
    showConfigFeedback('error', `Invalid interface name "${raw}": cannot contain whitespace or slashes.`);
    return;
  }

  if (!draftConfigData.interfaces.includes(raw)) {
    draftConfigData.interfaces.push(raw);
  }
  input.value = '';
  updateDirtyStateUI();
  renderInterfacesSection();
  renderRulesList();
  lucide.createIcons();
}

function renderGlobalPolicySection() {
  if (!draftConfigData) return;
  const btnFwd = document.getElementById('btnDefaultForward');
  const btnDrop = document.getElementById('btnDefaultDrop');
  const chkRewrite = document.getElementById('cfgRewriteMixed');
  const chkKnown = document.getElementById('cfgForwardKnownAnswers');

  const isFwd = draftConfigData.default_action !== 'drop';
  if (btnFwd) btnFwd.classList.toggle('active', isFwd);
  if (btnDrop) btnDrop.classList.toggle('active', !isFwd);
  if (chkRewrite) chkRewrite.checked = Boolean(draftConfigData.rewrite_mixed_packets);
  if (chkKnown) chkKnown.checked = Boolean(draftConfigData.forward_known_answers);
}

function setConfigDefaultAction(action) {
  if (!draftConfigData) return;
  draftConfigData.default_action = action === 'drop' ? 'drop' : 'forward';
  updateDirtyStateUI();
  renderGlobalPolicySection();
}

function onGlobalPolicyChange() {
  if (!draftConfigData) return;
  const chkRewrite = document.getElementById('cfgRewriteMixed');
  const chkKnown = document.getElementById('cfgForwardKnownAnswers');
  if (chkRewrite) draftConfigData.rewrite_mixed_packets = Boolean(chkRewrite.checked);
  if (chkKnown) draftConfigData.forward_known_answers = Boolean(chkKnown.checked);
  updateDirtyStateUI();
}

function renderTrackingAndWebSection() {
  if (!draftConfigData) return;
  const tr = draftConfigData.tracking || {};
  const ws = draftConfigData.web_server || {};

  const chkEnabled = document.getElementById('cfgTrackingEnabled');
  const fieldsWrap = document.getElementById('cfgTrackingFieldsWrap');
  const inpRetention = document.getElementById('cfgTrackingRetention');
  const inpMaxRecords = document.getElementById('cfgTrackingMaxRecords');
  const inpFlush = document.getElementById('cfgTrackingFlushInterval');
  const inpDbPath = document.getElementById('cfgTrackingDbPath');

  if (chkEnabled) chkEnabled.checked = Boolean(tr.enabled);
  if (fieldsWrap) {
    fieldsWrap.style.opacity = tr.enabled ? '1' : '0.5';
  }
  if (inpRetention) inpRetention.value = tr.retention_days ?? 7;
  if (inpMaxRecords) inpMaxRecords.value = tr.max_records ?? 50000;
  if (inpFlush) inpFlush.value = tr.flush_interval_seconds ?? 3600;
  if (inpDbPath) inpDbPath.value = tr.db_path || '/var/lib/mdns-sieve/responses.db';

  const inpHost = document.getElementById('cfgWebHost');
  const inpPort = document.getElementById('cfgWebPort');
  if (inpHost) inpHost.value = ws.host || '0.0.0.0';
  if (inpPort) inpPort.value = ws.port || 8080;
}

function onTrackingConfigChange() {
  if (!draftConfigData) return;
  const chkEnabled = document.getElementById('cfgTrackingEnabled');
  const fieldsWrap = document.getElementById('cfgTrackingFieldsWrap');
  const inpRetention = document.getElementById('cfgTrackingRetention');
  const inpMaxRecords = document.getElementById('cfgTrackingMaxRecords');
  const inpFlush = document.getElementById('cfgTrackingFlushInterval');
  const inpDbPath = document.getElementById('cfgTrackingDbPath');

  const enabled = chkEnabled ? Boolean(chkEnabled.checked) : true;
  if (fieldsWrap) {
    fieldsWrap.style.opacity = enabled ? '1' : '0.5';
  }

  const retention = Math.max(1, parseInt(inpRetention ? inpRetention.value : '7', 10) || 7);
  const maxRecords = Math.max(0, parseInt(inpMaxRecords ? inpMaxRecords.value : '50000', 10) || 0);
  const flushSecs = Math.max(1, parseInt(inpFlush ? inpFlush.value : '3600', 10) || 3600);
  const dbPath = (inpDbPath ? inpDbPath.value.trim() : '') || '/var/lib/mdns-sieve/responses.db';

  draftConfigData.tracking = {
    enabled,
    max_records: maxRecords,
    db_path: dbPath,
    flush_interval_seconds: flushSecs,
    retention_days: retention,
  };
  updateDirtyStateUI();
}

function onWebServerConfigChange() {
  if (!draftConfigData) return;
  const inpHost = document.getElementById('cfgWebHost');
  const inpPort = document.getElementById('cfgWebPort');
  const host = (inpHost ? inpHost.value.trim() : '') || '0.0.0.0';
  const port = Math.min(65535, Math.max(1, parseInt(inpPort ? inpPort.value : '8080', 10) || 8080));

  draftConfigData.web_server = {
    enabled: true,
    host,
    port,
  };
  updateDirtyStateUI();
}

function renderRulesList() {
  if (!draftConfigData) return;
  const listEl = document.getElementById('configRulesList');
  const countBadge = document.getElementById('configRulesCountBadge');
  if (!listEl) return;

  const rules = draftConfigData.rules || [];
  if (countBadge) {
    countBadge.textContent = `${rules.length} ${rules.length === 1 ? 'rule' : 'rules'}`;
  }

  if (rules.length === 0) {
    listEl.innerHTML = `
      <div class="table-empty" style="padding: 36px 20px !important; border: 1px dashed var(--border-color); border-radius: 12px;">
        <p style="margin-bottom: 10px; font-weight: 600; color: var(--text-primary);">No filtering rules configured</p>
        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
          All mDNS traffic between configured interfaces will use the global default action (<strong>${escapeHtml(draftConfigData.default_action.toUpperCase())}</strong>).
        </p>
        <button onclick="addConfigRule()" class="btn btn-primary" style="margin: 0 auto;">
          <i data-lucide="plus"></i>
          <span>Create First Rule</span>
        </button>
      </div>
    `;
    return;
  }

  const candidateIfaces = allKnownInterfaceNames();

  listEl.innerHTML = rules.map((rule, idx) => {
    const isFwd = rule.action !== 'drop';
    const srcList = normalizeEndpointList(rule.src);
    const dstList = normalizeEndpointList(rule.dst);

    // Include any rule-specific custom interfaces so they remain visible as pills
    const srcCandidates = Array.from(new Set([...candidateIfaces, ...srcList.filter(i => i !== '*')]));
    const dstCandidates = Array.from(new Set([...candidateIfaces, ...dstList.filter(i => i !== '*')]));

    const srcPillsHtml = [
      `<span class="rule-iface-pill ${srcList.includes('*') ? 'active' : ''}" onclick="toggleRuleInterface(${idx}, 'src', '*')">* (Any)</span>`,
      ...srcCandidates.map(iface => `
        <span class="rule-iface-pill ${!srcList.includes('*') && srcList.includes(iface) ? 'active' : ''}" onclick="toggleRuleInterface(${idx}, 'src', '${escapeHtml(iface)}')">${escapeHtml(iface)}</span>
      `),
    ].join('');

    const dstPillsHtml = [
      `<span class="rule-iface-pill ${dstList.includes('*') ? 'active' : ''}" onclick="toggleRuleInterface(${idx}, 'dst', '*')">* (Any)</span>`,
      ...dstCandidates.map(iface => `
        <span class="rule-iface-pill ${!dstList.includes('*') && dstList.includes(iface) ? 'active' : ''}" onclick="toggleRuleInterface(${idx}, 'dst', '${escapeHtml(iface)}')">${escapeHtml(iface)}</span>
      `),
    ].join('');

    const serviceTagsHtml = (rule.services || []).map((svc, tIdx) => `
      <span class="pattern-tag">
        <span>${escapeHtml(svc)}</span>
        <button type="button" onclick="removeRulePatternTag(${idx}, 'services', ${tIdx})" title="Remove pattern">&times;</button>
      </span>
    `).join('');

    const hostTagsHtml = (rule.hosts || []).map((host, tIdx) => `
      <span class="pattern-tag">
        <span>${escapeHtml(host)}</span>
        <button type="button" onclick="removeRulePatternTag(${idx}, 'hosts', ${tIdx})" title="Remove pattern">&times;</button>
      </span>
    `).join('');

    const highlightClass = highlightedRuleIndex === idx ? 'highlight-new' : '';

    return `
      <div class="rule-card ${isFwd ? 'rule-forward' : 'rule-drop'} ${highlightClass}"
           id="configRuleCard_${idx}"
           draggable="true"
           ondragstart="onRuleDragStart(event, ${idx})"
           ondragover="onRuleDragOver(event, ${idx})"
           ondragleave="onRuleDragLeave(event, ${idx})"
           ondrop="onRuleDrop(event, ${idx})"
           ondragend="onRuleDragEnd(event)">
        <div class="rule-card-top">
          <div class="rule-top-left">
            <span class="rule-drag-handle" title="Drag to reorder rule">
              <i data-lucide="grip-vertical"></i>
            </span>
            <span class="rule-index-badge">Rule #${idx + 1}</span>
            <div class="rule-action-pill-group">
              <button type="button" class="rule-action-opt forward ${isFwd ? 'active' : ''}" onclick="setRuleAction(${idx}, 'forward')">Forward</button>
              <button type="button" class="rule-action-opt drop ${!isFwd ? 'active' : ''}" onclick="setRuleAction(${idx}, 'drop')">Drop</button>
            </div>
            <div style="display: inline-flex; align-items: center; gap: 6px;">
              <span class="rule-field-label" style="margin: 0;">Section:</span>
              <select class="filter-select select-sm" style="width: auto; min-width: 135px;" onchange="setRuleSection(${idx}, this.value)">
                <option value="any" ${rule.section === 'any' ? 'selected' : ''}>Any (All Records)</option>
                <option value="questions" ${rule.section === 'questions' ? 'selected' : ''}>Questions Only</option>
                <option value="answers" ${rule.section === 'answers' ? 'selected' : ''}>Answers Only</option>
              </select>
            </div>
          </div>
          <div class="rule-top-right">
            <button type="button" class="btn btn-icon btn-sm" onclick="moveConfigRule(${idx}, -1)" ${idx === 0 ? 'disabled' : ''} title="Move Rule Up">
              <i data-lucide="arrow-up"></i>
            </button>
            <button type="button" class="btn btn-icon btn-sm" onclick="moveConfigRule(${idx}, 1)" ${idx === rules.length - 1 ? 'disabled' : ''} title="Move Rule Down">
              <i data-lucide="arrow-down"></i>
            </button>
            <button type="button" class="btn btn-icon btn-sm" onclick="duplicateConfigRule(${idx})" title="Duplicate Rule">
              <i data-lucide="copy"></i>
            </button>
            <button type="button" class="btn btn-icon btn-sm" style="color: var(--color-red);" onclick="deleteConfigRule(${idx})" title="Delete Rule">
              <i data-lucide="trash-2"></i>
            </button>
          </div>
        </div>

        <div class="rule-body-grid">
          <div class="rule-field-group">
            <label class="rule-field-label">
              <i data-lucide="log-in" style="width: 13px; height: 13px;"></i>
              <span>Ingress Source Interface (src)</span>
            </label>
            <div class="rule-iface-selector">${srcPillsHtml}</div>
          </div>

          <div class="rule-field-group">
            <label class="rule-field-label">
              <i data-lucide="log-out" style="width: 13px; height: 13px;"></i>
              <span>Egress Destination Interface (dst)</span>
            </label>
            <div class="rule-iface-selector">${dstPillsHtml}</div>
          </div>

          <div class="rule-field-group">
            <label class="rule-field-label">
              <i data-lucide="radio" style="width: 13px; height: 13px;"></i>
              <span>Service Patterns (PTR / SRV / TXT / NSEC — wildcards supported)</span>
            </label>
            <div class="tag-editor-box" onclick="this.querySelector('input').focus()">
              ${serviceTagsHtml}
              <input type="text" class="tag-inline-input"
                     placeholder="${(rule.services || []).length === 0 ? 'e.g. *.local, *_googlecast._tcp.local (Enter to add)' : 'Add pattern...'}"
                     onkeydown="handleRuleTagInputKeydown(event, ${idx}, 'services')"
                     onblur="handleRuleTagInputBlur(this, ${idx}, 'services')">
            </div>
          </div>

          <div class="rule-field-group">
            <label class="rule-field-label">
              <i data-lucide="server" style="width: 13px; height: 13px;"></i>
              <span>Host Patterns (A / AAAA records — wildcards supported)</span>
            </label>
            <div class="tag-editor-box" onclick="this.querySelector('input').focus()">
              ${hostTagsHtml}
              <input type="text" class="tag-inline-input"
                     placeholder="${(rule.hosts || []).length === 0 ? 'e.g. printer.local, *.iot.local (Enter to add)' : 'Add host...'}"
                     onkeydown="handleRuleTagInputKeydown(event, ${idx}, 'hosts')"
                     onblur="handleRuleTagInputBlur(this, ${idx}, 'hosts')">
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function addConfigRule(initialRule = null, insertAtTop = false) {
  if (!draftConfigData) return;
  const newRule = normalizeRuleItem(initialRule || {
    action: draftConfigData.default_action === 'forward' ? 'drop' : 'forward',
    section: 'any',
    src: '*',
    dst: '*',
    services: ['*.local'],
    hosts: [],
  });

  if (insertAtTop) {
    draftConfigData.rules.unshift(newRule);
    highlightedRuleIndex = 0;
  } else {
    draftConfigData.rules.push(newRule);
    highlightedRuleIndex = draftConfigData.rules.length - 1;
  }

  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();

  setTimeout(() => {
    highlightedRuleIndex = null;
  }, 2400);
}

function duplicateConfigRule(idx) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return;
  const copy = normalizeRuleItem(JSON.parse(JSON.stringify(draftConfigData.rules[idx])));
  draftConfigData.rules.splice(idx + 1, 0, copy);
  highlightedRuleIndex = idx + 1;
  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();
  setTimeout(() => { highlightedRuleIndex = null; }, 2400);
}

function deleteConfigRule(idx) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return;
  draftConfigData.rules.splice(idx, 1);
  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();
}

function moveConfigRule(idx, delta) {
  if (!draftConfigData) return;
  const target = idx + delta;
  if (target < 0 || target >= draftConfigData.rules.length) return;
  const [item] = draftConfigData.rules.splice(idx, 1);
  draftConfigData.rules.splice(target, 0, item);
  highlightedRuleIndex = target;
  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();
  setTimeout(() => { highlightedRuleIndex = null; }, 1500);
}

function setRuleAction(idx, action) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return;
  draftConfigData.rules[idx].action = action === 'drop' ? 'drop' : 'forward';
  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();
}

function setRuleSection(idx, section) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return;
  draftConfigData.rules[idx].section = (section === 'questions' || section === 'answers') ? section : 'any';
  updateDirtyStateUI();
}

function toggleRuleInterface(idx, field, iface) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return;
  const rule = draftConfigData.rules[idx];
  let list = normalizeEndpointList(rule[field]);

  if (iface === '*') {
    list = ['*'];
  } else {
    list = list.filter(item => item !== '*');
    const pos = list.indexOf(iface);
    if (pos >= 0) {
      list.splice(pos, 1);
    } else {
      list.push(iface);
    }
    if (list.length === 0) {
      list = ['*'];
    }
  }

  rule[field] = serializeEndpointValue(list);
  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();
}

function addRulePatternTag(idx, field, rawVal) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return false;
  const parts = String(rawVal)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return false;

  const arr = draftConfigData.rules[idx][field] || [];
  let changed = false;
  parts.forEach(p => {
    if (!arr.includes(p)) {
      arr.push(p);
      changed = true;
    }
  });
  draftConfigData.rules[idx][field] = arr;

  if (changed) {
    updateDirtyStateUI();
    renderRulesList();
    lucide.createIcons();
  }
  return changed;
}

function removeRulePatternTag(idx, field, tagIdx) {
  if (!draftConfigData || !draftConfigData.rules[idx]) return;
  const arr = draftConfigData.rules[idx][field] || [];
  if (tagIdx >= 0 && tagIdx < arr.length) {
    arr.splice(tagIdx, 1);
    updateDirtyStateUI();
    renderRulesList();
    lucide.createIcons();
  }
}

function handleRuleTagInputKeydown(event, idx, field) {
  const input = event.target;
  if (event.key === 'Enter' || event.key === ',') {
    event.preventDefault();
    const val = input.value.trim();
    if (val) {
      addRulePatternTag(idx, field, val);
    }
  } else if (event.key === 'Backspace' && input.value === '') {
    const arr = (draftConfigData && draftConfigData.rules[idx] && draftConfigData.rules[idx][field]) || [];
    if (arr.length > 0) {
      removeRulePatternTag(idx, field, arr.length - 1);
    }
  }
}

function handleRuleTagInputBlur(inputEl, idx, field) {
  const val = inputEl.value.trim();
  if (val) {
    inputEl.value = '';
    addRulePatternTag(idx, field, val);
  }
}

/* Drag and Drop Reordering for Rule Cards */
function onRuleDragStart(event, idx) {
  // Avoid starting card drag when interacting with inputs or buttons
  const tag = event.target && event.target.tagName ? event.target.tagName.toLowerCase() : '';
  if (tag === 'input' || tag === 'select' || tag === 'button') {
    event.preventDefault();
    return;
  }
  draggedRuleIndex = idx;
  event.currentTarget.classList.add('dragging');
  if (event.dataTransfer) {
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', String(idx));
  }
}

function onRuleDragOver(event, idx) {
  event.preventDefault();
  if (draggedRuleIndex === null || draggedRuleIndex === idx) return;
  event.currentTarget.classList.add('drag-over');
}

function onRuleDragLeave(event) {
  event.currentTarget.classList.remove('drag-over');
}

function onRuleDrop(event, targetIdx) {
  event.preventDefault();
  event.currentTarget.classList.remove('drag-over');
  if (draggedRuleIndex === null || draggedRuleIndex === targetIdx || !draftConfigData) return;

  const [moved] = draftConfigData.rules.splice(draggedRuleIndex, 1);
  draftConfigData.rules.splice(targetIdx, 0, moved);
  draggedRuleIndex = null;
  highlightedRuleIndex = targetIdx;

  updateDirtyStateUI();
  renderRulesList();
  lucide.createIcons();
  setTimeout(() => { highlightedRuleIndex = null; }, 1500);
}

function onRuleDragEnd(event) {
  draggedRuleIndex = null;
  event.currentTarget.classList.remove('dragging');
  document.querySelectorAll('.rule-card.drag-over').forEach(el => el.classList.remove('drag-over'));
}

function discardConfigChanges() {
  if (!savedConfigData) return;
  draftConfigData = cloneConfig(savedConfigData);
  hideConfigFeedback();
  renderConfigView();
  showConfigFeedback('info', 'Reverted unsaved changes back to the active daemon configuration.');
}

async function saveAndApplyConfig() {
  if (!draftConfigData) return;
  const btnSave = document.getElementById('btnSaveConfig');
  if (btnSave) btnSave.disabled = true;

  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config: draftConfigData }),
    });
    const payload = await res.json();
    if (!res.ok || payload.status !== 'ok') {
      throw new Error(payload.error || `HTTP ${res.status}`);
    }

    const data = payload.data;
    savedConfigData = normalizeConfigData(data.config);
    draftConfigData = cloneConfig(savedConfigData);
    lastServerYaml = data.yaml || '';
    configFilePath = data.config_path || configFilePath;
    serverRestartRequired = Boolean(data.restart_required);
    boundWebServer = data.bound_web_server || boundWebServer;

    renderConfigView();
    showConfigFeedback(
      'success',
      `Configuration saved to ${configFilePath} (backup written to ${configFilePath}.bak) and hot-reloaded in memory.`
    );
    refreshData();
  } catch (err) {
    console.error('Failed to save configuration:', err);
    showConfigFeedback('error', `Failed to save configuration: ${err.message}`);
    updateDirtyStateUI();
  }
}

function showConfigFeedback(type, message) {
  const banner = document.getElementById('configFeedbackBanner');
  const icon = document.getElementById('configFeedbackIcon');
  const text = document.getElementById('configFeedbackText');
  if (!banner || !text) return;

  banner.className = `config-banner ${type === 'error' ? 'error' : (type === 'success' ? 'success' : 'warning')}`;
  if (icon) {
    const iconName = type === 'error' ? 'alert-circle' : (type === 'success' ? 'check-circle-2' : 'info');
    icon.setAttribute('data-lucide', iconName);
  }
  text.textContent = message;
  lucide.createIcons();
}

function hideConfigFeedback() {
  const banner = document.getElementById('configFeedbackBanner');
  if (banner) banner.classList.add('hidden');
}

/* Raw YAML Preview & Import Modal */
function yamlQuoteScalar(val) {
  const s = String(val ?? '');
  if (
    s === '' ||
    s === '*' ||
    s.startsWith('*') ||
    s.includes(':') ||
    s.includes('#') ||
    s.includes('[') ||
    s.includes(']') ||
    s.includes('{') ||
    s.includes('}') ||
    s.includes(',') ||
    s.includes(' ') ||
    s === 'true' ||
    s === 'false' ||
    s === 'null'
  ) {
    return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  return s;
}

function generateClientSideYamlPreview(cfg) {
  if (!cfg) return '';
  const lines = [];
  lines.push('# ==============================================================================');
  lines.push('# mDNS Sieve Configuration File');
  lines.push('# ==============================================================================');
  lines.push('');
  lines.push('# 1. Network Interfaces');
  if (!cfg.interfaces || cfg.interfaces.length === 0) {
    lines.push('interfaces: []');
  } else {
    lines.push('interfaces:');
    cfg.interfaces.forEach(iface => {
      lines.push(`  - ${yamlQuoteScalar(iface)}`);
    });
  }
  lines.push('');
  lines.push('# 2. Global Routing Policy');
  lines.push(`default_action: ${yamlQuoteScalar(cfg.default_action || 'forward')}`);
  lines.push(`rewrite_mixed_packets: ${Boolean(cfg.rewrite_mixed_packets)}`);
  lines.push(`forward_known_answers: ${Boolean(cfg.forward_known_answers)}`);
  lines.push('');

  const ws = cfg.web_server || { enabled: true, host: '0.0.0.0', port: 8080 };
  lines.push('# 3. Web Dashboard Server');
  lines.push('web_server:');
  lines.push(`  enabled: ${Boolean(ws.enabled)}`);
  lines.push(`  host: "${ws.host || '0.0.0.0'}"`);
  lines.push(`  port: ${ws.port || 8080}`);
  lines.push('');

  const tr = cfg.tracking || {
    enabled: true,
    max_records: 50000,
    db_path: '/var/lib/mdns-sieve/responses.db',
    flush_interval_seconds: 3600,
    retention_days: 7,
  };
  lines.push('# 4. Telemetry & Message History Database');
  lines.push('tracking:');
  lines.push(`  enabled: ${Boolean(tr.enabled)}`);
  lines.push(`  max_records: ${tr.max_records ?? 50000}`);
  lines.push(`  db_path: "${tr.db_path || '/var/lib/mdns-sieve/responses.db'}"`);
  lines.push(`  flush_interval_seconds: ${tr.flush_interval_seconds ?? 3600}`);
  lines.push(`  retention_days: ${tr.retention_days ?? 7}`);
  lines.push('');

  lines.push('# 5. Filtering Rules (First match wins)');
  if (!cfg.rules || cfg.rules.length === 0) {
    lines.push('rules: []');
  } else {
    lines.push('rules:');
    cfg.rules.forEach((rule, idx) => {
      lines.push(`  # Rule #${idx + 1}`);
      lines.push(`  - action: ${yamlQuoteScalar(rule.action || 'forward')}`);
      if (rule.section && rule.section !== 'any') {
        lines.push(`    section: ${yamlQuoteScalar(rule.section)}`);
      }
      const writeEndpoint = (key, val) => {
        if (Array.isArray(val)) {
          if (val.length === 1) {
            lines.push(`    ${key}: ${yamlQuoteScalar(val[0])}`);
          } else {
            lines.push(`    ${key}: [${val.map(yamlQuoteScalar).join(', ')}]`);
          }
        } else {
          lines.push(`    ${key}: ${yamlQuoteScalar(val || '*')}`);
        }
      };
      writeEndpoint('src', rule.src);
      writeEndpoint('dst', rule.dst);
      if (Array.isArray(rule.services) && rule.services.length > 0) {
        lines.push('    services:');
        rule.services.forEach(s => lines.push(`      - ${yamlQuoteScalar(s)}`));
      }
      if (Array.isArray(rule.hosts) && rule.hosts.length > 0) {
        lines.push('    hosts:');
        rule.hosts.forEach(h => lines.push(`      - ${yamlQuoteScalar(h)}`));
      }
    });
  }

  return lines.join('\n') + '\n';
}

function openYamlModal() {
  const errBanner = document.getElementById('yamlModalError');
  if (errBanner) errBanner.classList.add('hidden');

  const textarea = document.getElementById('yamlEditorTextarea');
  if (textarea) {
    textarea.value = (!isConfigDirty() && lastServerYaml)
      ? lastServerYaml
      : generateClientSideYamlPreview(draftConfigData);
  }
  toggleModal('yamlModal', true);
}

function copyYamlFromModal(btn) {
  const textarea = document.getElementById('yamlEditorTextarea');
  if (!textarea) return;
  navigator.clipboard.writeText(textarea.value).then(() => {
    const span = btn.querySelector('span');
    const orig = span ? span.textContent : 'Copy YAML';
    if (span) span.textContent = 'Copied!';
    setTimeout(() => {
      if (span) span.textContent = orig;
    }, 1500);
  });
}

function downloadYamlFile() {
  const textarea = document.getElementById('yamlEditorTextarea');
  const content = textarea ? textarea.value : generateClientSideYamlPreview(draftConfigData);
  const blob = new Blob([content], { type: 'text/yaml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'mdns-sieve.yaml';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function saveYamlDirectlyFromModal() {
  const textarea = document.getElementById('yamlEditorTextarea');
  const errBanner = document.getElementById('yamlModalError');
  const errText = document.getElementById('yamlModalErrorText');
  if (!textarea) return;

  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yaml: textarea.value }),
    });
    const payload = await res.json();
    if (!res.ok || payload.status !== 'ok') {
      throw new Error(payload.error || `HTTP ${res.status}`);
    }

    const data = payload.data;
    savedConfigData = normalizeConfigData(data.config);
    draftConfigData = cloneConfig(savedConfigData);
    lastServerYaml = data.yaml || '';
    configFilePath = data.config_path || configFilePath;
    serverRestartRequired = Boolean(data.restart_required);
    boundWebServer = data.bound_web_server || boundWebServer;

    toggleModal('yamlModal', false);
    renderConfigView();
    showConfigFeedback(
      'success',
      `YAML configuration validated, saved to ${configFilePath}, and hot-reloaded in memory.`
    );
    refreshData();
  } catch (err) {
    if (errBanner && errText) {
      errText.textContent = err.message;
      errBanner.classList.remove('hidden');
      lucide.createIcons();
    }
  }
}

/* Quick "+ Rule" Action from Message History */
async function createQuickRuleFromHistory(btnEl, event) {
  if (event) event.stopPropagation();
  if (!btnEl) return;

  const srcIface = btnEl.getAttribute('data-src') || '*';
  const disp = Number(btnEl.getAttribute('data-disp') || 0);
  const section = btnEl.getAttribute('data-section') || 'any';
  const rawName = (btnEl.getAttribute('data-name') || '').trim().replace(/\.$/, '');
  const rrType = Number(btnEl.getAttribute('data-rrtype') || 0);

  if (!configInitialized) {
    configInitialized = true;
    await Promise.all([loadConfigFromServer(), loadSystemInterfaces()]);
  }

  // Toggle opposite action of current item disposition (2 = Dropped -> forward, otherwise drop)
  const targetAction = disp === 2 ? 'forward' : 'drop';
  const isAddressRecord = rrType === 1 || rrType === 28; // A or AAAA

  const draftRule = {
    action: targetAction,
    section: (section === 'questions' || section === 'answers') ? section : 'any',
    src: srcIface || '*',
    dst: '*',
    services: !isAddressRecord && rawName ? [rawName] : [],
    hosts: isAddressRecord && rawName ? [rawName] : [],
  };

  switchMainView('config');
  addConfigRule(draftRule, true);
  showConfigFeedback(
    'info',
    `Drafted a new ${targetAction.toUpperCase()} rule #1 for "${rawName || '*'}" from ${srcIface}. Click "Save & Apply" to activate.`
  );

  setTimeout(() => {
    const card = document.getElementById('configRuleCard_0');
    if (card) {
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, 100);
}

