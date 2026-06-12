// Global state
let currentTheme = localStorage.getItem('theme') || 'system';
let autoRefreshInterval = parseInt(localStorage.getItem('refreshInterval') || '8', 10);
let chartWindowSize = parseInt(localStorage.getItem('chartWindow') || '30', 10);
let refreshTimer = null;
let currentTab = 'forwarded_queries';
let lastStatsData = null;

// Active hosts sorting state
let hostsSortCol = 'packets';
let hostsSortDir = 'desc';
let latestHostsData = {};

// Sieve daemon details (updated dynamically from API responses)
let daemonHost = '127.0.0.1';
let daemonPort = 5354;

// Cache stats for domain filtering
let fwdQueriesCache = {};
let fwdResponsesCache = {};
let dropQueriesCache = {};
let dropResponsesCache = {};
let expandedDomains = new Set();

// Chart.js Instances
let mainChart = null;
let sparklines = {};

// Initialize application on load
window.addEventListener('DOMContentLoaded', () => {
  // Setup Lucide icons
  lucide.createIcons();

  // Setup Theme Event Listeners
  initTheme();

  // Setup Auto-Refresh Toggle Event Listener
  const autoRefreshToggle = document.getElementById('autoRefreshToggle');
  autoRefreshToggle.addEventListener('change', (e) => {
    if (e.target.checked) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });

  // Setup Charts
  initCharts();

  // Initial Data Fetch
  refreshData();

  // Start polling if enabled
  if (autoRefreshToggle.checked) {
    startAutoRefresh();
  }

  // Setup Modal Background Click Listeners
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

  // Listen for system theme changes if set to system
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

  // Update theme button icon
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
    // Pre-populate input values for Settings modal
    if (modalId === 'settingsModal') {
      document.getElementById('setRefreshInterval').value = autoRefreshInterval;
      document.getElementById('setChartWindow').value = chartWindowSize;
    }
    // Update daemon configuration details for Info modal
    if (modalId === 'infoModal') {
      document.getElementById('infoDaemonHost').textContent = daemonHost;
      document.getElementById('infoDaemonPort').textContent = daemonPort;
    }
  } else {
    modal.classList.add('hidden');
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

  // Restart refresh interval with new rate
  if (document.getElementById('autoRefreshToggle').checked) {
    stopAutoRefresh();
    startAutoRefresh();
  }

  // Update main chart window sizes
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
   HTTP API Proxy Requests
   ========================================================================== */
async function fetchApi(endpoint, options = {}) {
  try {
    const res = await fetch(endpoint, options);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    const data = await res.json();
    if (data.status === 'error') {
      throw new Error(data.error || 'Server reported API error');
    }
    return data;
  } catch (err) {
    throw err;
  }
}

async function refreshData() {
  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) refreshBtn.disabled = true;

  try {
    // 1. Fetch Stats
    const statsRes = await fetchApi('/api/stats');
    updateStats(statsRes.data);
    hideOfflineOverlay();

    // Update daemon metadata from connection config info
    if (statsRes.host) daemonHost = statsRes.host;
    if (statsRes.port) daemonPort = statsRes.port;

    // 2. Fetch Hosts
    const hostsRes = await fetchApi('/api/hosts');
    updateHosts(hostsRes.data);

    // 3. Fetch Names
    const namesRes = await fetchApi('/api/names');
    updateDomains(namesRes.data);

    // Update Info connection details
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
   Dashboard Data Updates & Renderers
   ========================================================================== */
function updateStats(data) {
  const totalEl = document.getElementById('valTotal');
  const forwardedEl = document.getElementById('valForwarded');
  const droppedEl = document.getElementById('valDropped');
  const rewrittenEl = document.getElementById('valRewritten');

  totalEl.textContent = data.total.toLocaleString();
  forwardedEl.textContent = data.forwarded.toLocaleString();
  droppedEl.textContent = data.dropped.toLocaleString();
  rewrittenEl.textContent = data.rewritten.toLocaleString();

  // Draw or update charts
  updateChartsData(data);

  lastStatsData = data;
}

function updateHosts(data) {
  latestHostsData = data || {};
  renderHostsTable();
}

function setHostsSort(col) {
  if (hostsSortCol === col) {
    hostsSortDir = hostsSortDir === 'asc' ? 'desc' : 'asc';
  } else {
    hostsSortCol = col;
    hostsSortDir = (col === 'packets' || col === 'last_seen') ? 'desc' : 'asc';
  }
  renderHostsTable();
}

function renderHostsTable() {
  const tbody = document.getElementById('hostsTableBody');
  if (!tbody) return;

  const hosts = Object.entries(latestHostsData);
  
  // Update sort icons in table headers
  const cols = ['ip', 'interface', 'packets', 'status', 'last_seen'];
  cols.forEach(c => {
    const iconSpan = document.getElementById(`sortIcon-${c}`);
    if (iconSpan) {
      if (hostsSortCol === c) {
        iconSpan.textContent = hostsSortDir === 'asc' ? ' ▲' : ' ▼';
        iconSpan.style.opacity = '1';
      } else {
        iconSpan.textContent = '';
        iconSpan.style.opacity = '0.3';
      }
    }
  });

  if (hosts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="table-empty">No active hosts discovered.</td></tr>`;
    return;
  }

  const nowSecs = Date.now() / 1000;

  hosts.sort((a, b) => {
    let valA, valB;
    if (hostsSortCol === 'ip') {
      valA = a[0];
      valB = b[0];
    } else if (hostsSortCol === 'interface') {
      valA = a[1].last_interface;
      valB = b[1].last_interface;
    } else if (hostsSortCol === 'packets') {
      valA = a[1].packets_sent;
      valB = b[1].packets_sent;
    } else if (hostsSortCol === 'status') {
      const elapsedA = nowSecs - a[1].last_seen_time;
      const elapsedB = nowSecs - b[1].last_seen_time;
      valA = elapsedA < 60 ? 1 : 0;
      valB = elapsedB < 60 ? 1 : 0;
    } else if (hostsSortCol === 'last_seen') {
      valA = a[1].last_seen_time;
      valB = b[1].last_seen_time;
    }

    if (typeof valA === 'string') {
      return hostsSortDir === 'asc' 
        ? valA.localeCompare(valB) 
        : valB.localeCompare(valA);
    } else {
      return hostsSortDir === 'asc'
        ? valA - valB
        : valB - valA;
    }
  });

  tbody.innerHTML = '';
  hosts.forEach(([ip, info]) => {
    const elapsed = nowSecs - info.last_seen_time;
    const isActive = elapsed < 60;
    const statusText = isActive ? 'Active' : 'Idle';
    const statusClass = isActive ? 'active' : 'idle';

    let relativeActive = '';
    if (elapsed < 1) {
      relativeActive = 'Just now';
    } else if (elapsed < 60) {
      relativeActive = `${Math.floor(elapsed)}s ago`;
    } else if (elapsed < 3600) {
      relativeActive = `${Math.floor(elapsed / 60)}m ago`;
    } else {
      relativeActive = `${Math.floor(elapsed / 3600)}h ago`;
    }

    const tr = document.createElement('tr');
    tr.onclick = () => showHostDetails(ip);
    tr.innerHTML = `
      <td><strong>${ip}</strong></td>
      <td><code>${info.last_interface}</code></td>
      <td>${info.packets_sent.toLocaleString()}</td>
      <td>
        <span class="badge-status ${statusClass}">
          <span class="status-dot"></span>
          ${statusText}
        </span>
      </td>
      <td>${relativeActive}</td>
    `;
    tbody.appendChild(tr);
  });
}

function updateDomains(data) {
  fwdQueriesCache = data.forwarded_queries || {};
  fwdResponsesCache = data.forwarded_responses || {};
  dropQueriesCache = data.dropped_queries || {};
  dropResponsesCache = data.dropped_responses || {};

  // Update tabs badges count
  document.getElementById('badgeFwdQueries').textContent = Object.keys(fwdQueriesCache).length;
  document.getElementById('badgeFwdResponses').textContent = Object.keys(fwdResponsesCache).length;
  document.getElementById('badgeDropQueries').textContent = Object.keys(dropQueriesCache).length;
  document.getElementById('badgeDropResponses').textContent = Object.keys(dropResponsesCache).length;

  filterDomains();
}

function switchDomainTab(tab) {
  currentTab = tab;
  document.getElementById('tabFwdQueries').classList.toggle('active', tab === 'forwarded_queries');
  document.getElementById('tabFwdResponses').classList.toggle('active', tab === 'forwarded_responses');
  document.getElementById('tabDropQueries').classList.toggle('active', tab === 'dropped_queries');
  document.getElementById('tabDropResponses').classList.toggle('active', tab === 'dropped_responses');
  filterDomains();
}

function filterDomains() {
  const query = document.getElementById('domainSearch').value.toLowerCase().trim();
  const listContainer = document.getElementById('domainList');
  listContainer.innerHTML = '';

  const cacheMap = {
    'forwarded_queries': fwdQueriesCache,
    'forwarded_responses': fwdResponsesCache,
    'dropped_queries': dropQueriesCache,
    'dropped_responses': dropResponsesCache
  };
  const cache = cacheMap[currentTab] || {};
  const entries = Object.entries(cache);

  const filtered = entries.filter(([name]) => name.toLowerCase().includes(query));

  if (filtered.length === 0) {
    listContainer.innerHTML = `<div class="list-empty">No matching domain statistics found.</div>`;
    return;
  }

  // Sort domains alphabetically
  filtered.sort((a, b) => a[0].localeCompare(b[0]));

  filtered.forEach(([name, ipCounts]) => {
    const totalHits = Object.values(ipCounts).reduce((a, b) => a + b, 0);
    const isExpanded = expandedDomains.has(name);

    const itemDiv = document.createElement('div');
    itemDiv.className = `domain-item ${isExpanded ? 'open' : ''}`;

    const headerDiv = document.createElement('div');
    headerDiv.className = 'domain-header';
    headerDiv.onclick = () => toggleDomainExpand(name);

    const arrowIcon = isExpanded ? 'chevron-down' : 'chevron-right';
    headerDiv.innerHTML = `
      <div class="domain-name">
        <i data-lucide="${arrowIcon}"></i>
        <span>${name}</span>
      </div>
      <span class="domain-total-hits">${totalHits.toLocaleString()} hits</span>
    `;

    itemDiv.appendChild(headerDiv);

    if (isExpanded) {
      const detailsDiv = document.createElement('div');
      detailsDiv.className = 'domain-details';

      // Sort source IPs by count descending
      const sortedIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]);
      sortedIps.forEach(([ip, hits]) => {
        const ipRow = document.createElement('div');
        ipRow.className = 'detail-ip-row';
        ipRow.innerHTML = `
          <span>${ip}</span>
          <span><strong>${hits.toLocaleString()} hits</strong></span>
        `;
        detailsDiv.appendChild(ipRow);
      });

      itemDiv.appendChild(detailsDiv);
    }

    listContainer.appendChild(itemDiv);
  });

  lucide.createIcons();
}

function toggleDomainExpand(name) {
  if (expandedDomains.has(name)) {
    expandedDomains.delete(name);
  } else {
    expandedDomains.add(name);
  }
  filterDomains();
}

/* ==========================================================================
   Chart.js Metrics Rendering
   ========================================================================== */
function initCharts() {
  const ctx = document.getElementById('metricsChart').getContext('2d');
  
  // Set fonts color dynamically based on theme
  const getGridColor = () => getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim();
  const getTextColor = () => getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();

  mainChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Total',
          borderColor: '#06b6d4', // Cyan
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
          borderColor: '#10b981', // Emerald
          backgroundColor: 'rgba(16, 185, 129, 0.02)',
          borderWidth: 2,
          pointRadius: 1,
          pointHoverRadius: 4,
          data: [],
          fill: false,
          tension: 0.3
        },
        {
          label: 'Dropped',
          borderColor: '#ef4444', // Rose
          backgroundColor: 'rgba(239, 68, 68, 0.02)',
          borderWidth: 2,
          pointRadius: 1,
          pointHoverRadius: 4,
          data: [],
          fill: false,
          tension: 0.3
        },
        {
          label: 'Rewritten',
          borderColor: '#8b5cf6', // Violet
          backgroundColor: 'rgba(139, 92, 246, 0.02)',
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
          grid: {
            color: getGridColor(),
            drawBorder: false
          },
          ticks: {
            color: getTextColor(),
            font: { size: 10, family: 'Inter' }
          }
        },
        y: {
          grid: {
            color: getGridColor(),
            drawBorder: false
          },
          ticks: {
            color: getTextColor(),
            font: { size: 10, family: 'Inter' },
            precision: 0
          }
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

  // Init mini sparklines for cards
  initSparkline('Total', 'sparklineTotal', '#06b6d4');
  initSparkline('Forwarded', 'sparklineForwarded', '#10b981');
  initSparkline('Dropped', 'sparklineDropped', '#ef4444');
  initSparkline('Rewritten', 'sparklineRewritten', '#8b5cf6');
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

  // Calculate deltas (rates per interval) if we have previous data
  let deltaTotal = 0;
  let deltaForwarded = 0;
  let deltaDropped = 0;
  let deltaRewritten = 0;

  if (lastStatsData) {
    deltaTotal = Math.max(0, data.total - lastStatsData.total);
    deltaForwarded = Math.max(0, data.forwarded - lastStatsData.forwarded);
    deltaDropped = Math.max(0, data.dropped - lastStatsData.dropped);
    deltaRewritten = Math.max(0, data.rewritten - lastStatsData.rewritten);
  }

  // 1. Update Main Trend Chart
  mainChart.data.labels.push(timestamp);
  mainChart.data.datasets[0].data.push(deltaTotal);
  mainChart.data.datasets[1].data.push(deltaForwarded);
  mainChart.data.datasets[2].data.push(deltaDropped);
  mainChart.data.datasets[3].data.push(deltaRewritten);

  // Apply chart display size limit
  if (mainChart.data.labels.length > chartWindowSize) {
    mainChart.data.labels.shift();
    mainChart.data.datasets.forEach(dataset => dataset.data.shift());
  }

  // Update line grid colors based on theme switches
  const getGridColor = () => getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim();
  const getTextColor = () => getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();
  
  mainChart.options.scales.x.grid.color = getGridColor();
  mainChart.options.scales.x.ticks.color = getTextColor();
  mainChart.options.scales.y.grid.color = getGridColor();
  mainChart.options.scales.y.ticks.color = getTextColor();
  mainChart.options.plugins.legend.labels.color = getTextColor();

  mainChart.update('none'); // Update without full recalculation animations for smoothness

  // 2. Update Sparklines
  updateSparklineData('Total', deltaTotal);
  updateSparklineData('Forwarded', deltaForwarded);
  updateSparklineData('Dropped', deltaDropped);
  updateSparklineData('Rewritten', deltaRewritten);
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
async function confirmClearStats() {
  const confirmed = confirm("Are you sure you want to reset all mDNS Sieve server statistics? This will clear all packet counts, hosts activity, and domain lookup logs.");
  if (!confirmed) return;

  try {
    const res = await fetchApi('/api/clear', { method: 'POST' });
    if (res.status === 'ok') {
      alert("Statistics successfully cleared.");
      // Reset chart lines
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
      refreshData();
    }
  } catch (err) {
    alert(`Failed to clear statistics: ${err.message}`);
  }
}

/* ==========================================================================
   Host Details Modal Action Handler
   ========================================================================== */
async function showHostDetails(ip) {
  document.getElementById('hostDetailsTitle').textContent = `Host Details: ${ip}`;
  
  const content = document.getElementById('hostDetailsContent');
  const empty = document.getElementById('hostDetailsEmpty');
  const loading = document.getElementById('hostDetailsLoading');
  
  content.classList.add('hidden');
  empty.classList.add('hidden');
  loading.classList.remove('hidden');
  
  toggleModal('hostDetailsModal', true);
  
  try {
    const res = await fetchApi(`/api/host_details?ip=${encodeURIComponent(ip)}`);
    const queries = res.data.queries || [];
    const responses = res.data.responses || [];
    
    loading.classList.add('hidden');
    
    if (queries.length === 0 && responses.length === 0) {
      empty.textContent = 'No tracking data available for this host. Ensure tracking is enabled in configuration.';
      empty.classList.remove('hidden');
    } else {
      content.classList.remove('hidden');
      
      const qList = document.getElementById('hostQueriesList');
      qList.innerHTML = '';
      queries.forEach(q => {
        const li = document.createElement('li');
        li.textContent = q;
        qList.appendChild(li);
      });
      if (queries.length === 0) qList.innerHTML = '<li style="color: var(--text-muted)">None recorded</li>';
      
      const rList = document.getElementById('hostResponsesList');
      rList.innerHTML = '';
      responses.forEach(r => {
        const li = document.createElement('li');
        li.textContent = r;
        rList.appendChild(li);
      });
      if (responses.length === 0) rList.innerHTML = '<li style="color: var(--text-muted)">None recorded</li>';
    }
  } catch (err) {
    loading.classList.add('hidden');
    empty.textContent = 'Error fetching host details: ' + err.message;
    empty.classList.remove('hidden');
  }
}
