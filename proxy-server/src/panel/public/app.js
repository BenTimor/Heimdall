// Guardian Admin Panel — Vanilla JS SPA
// No build step, no framework, no dependencies.

'use strict';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
  loggedIn: false,
  mustChangePassword: false,
  username: '',
  systemInfo: null,
  theme: localStorage.getItem('guardian-theme') || 'light',
};

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------
async function api(method, path, body) {
  const opts = {
    method,
    headers: {},
    credentials: 'same-origin',
  };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  try {
    const res = await fetch(`/panel/api${path}`, opts);
    if (res.status === 401) {
      state.loggedIn = false;
      state.mustChangePassword = false;
      render();
      return null;
    }
    // 204 No Content
    if (res.status === 204) return {};
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'An error occurred', 'error');
      return null;
    }
    return data;
  } catch (err) {
    showToast('Network error — could not reach server', 'error');
    return null;
  }
}

// ---------------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------------
function getToastContainer() {
  let c = document.querySelector('.toast-container');
  if (!c) {
    c = document.createElement('div');
    c.className = 'toast-container';
    document.body.appendChild(c);
  }
  return c;
}

function showToast(message, type = 'success') {
  const container = getToastContainer();
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 300ms';
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
function applyTheme() {
  document.documentElement.setAttribute('data-theme', state.theme);
  localStorage.setItem('guardian-theme', state.theme);
}
applyTheme();

function toggleTheme() {
  state.theme = state.theme === 'light' ? 'dark' : 'light';
  applyTheme();
  // Update toggle button text if visible
  const btn = document.querySelector('.theme-toggle');
  if (btn) btn.textContent = state.theme === 'light' ? 'Dark mode' : 'Light mode';
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------
function esc(str) {
  const d = document.createElement('div');
  d.textContent = String(str ?? '');
  return d.innerHTML;
}

// ---------------------------------------------------------------------------
// Date formatting
// ---------------------------------------------------------------------------
function fmtDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function fmtRelative(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
function currentRoute() {
  return window.location.hash.slice(1) || 'clients';
}

function navigate(hash) {
  window.location.hash = hash;
}

window.addEventListener('hashchange', () => {
  if (state.loggedIn && !state.mustChangePassword) renderApp();
});

// ---------------------------------------------------------------------------
// Modal helper
// ---------------------------------------------------------------------------
function showModal(title, bodyHtml, footerHtml) {
  closeModal();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });
  overlay.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3>${esc(title)}</h3>
        <button class="modal-close" onclick="closeModal()">&times;</button>
      </div>
      <div class="modal-body">${bodyHtml}</div>
      ${footerHtml ? `<div class="modal-footer">${footerHtml}</div>` : ''}
    </div>`;
  document.body.appendChild(overlay);
  // Focus first input if present
  const firstInput = overlay.querySelector('input, select, textarea');
  if (firstInput) setTimeout(() => firstInput.focus(), 50);
  return overlay;
}

function closeModal() {
  const m = document.querySelector('.modal-overlay');
  if (m) m.remove();
}
window.closeModal = closeModal;

// ---------------------------------------------------------------------------
// Token display modal
// ---------------------------------------------------------------------------
function showTokenModal(token, title = 'Client Token') {
  const body = `
    <p>Save this token now. It will <strong>not</strong> be shown again.</p>
    <div class="token-display">
      <code id="token-value">${esc(token)}</code>
      <button class="copy-btn" onclick="copyToken()">Copy</button>
    </div>
    <p class="token-warning">This token will only be shown once!</p>`;
  showModal(title, body, `<button class="btn btn-primary" onclick="closeModal()">Done</button>`);
}

window.copyToken = async function () {
  const val = document.getElementById('token-value');
  if (!val) return;
  try {
    await navigator.clipboard.writeText(val.textContent);
    showToast('Token copied to clipboard');
    const btn = document.querySelector('.token-display .copy-btn');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 1500); }
  } catch {
    // Fallback: select text
    const range = document.createRange();
    range.selectNodeContents(val);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    showToast('Press Ctrl+C to copy', 'error');
  }
};

// ---------------------------------------------------------------------------
// Confirm dialog
// ---------------------------------------------------------------------------
function confirmAction(message) {
  return window.confirm(message);
}

// ---------------------------------------------------------------------------
// Login view
// ---------------------------------------------------------------------------
function renderLogin() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="login-wrapper">
      <div class="login-card">
        <h1>Guardian</h1>
        <p class="login-subtitle">Admin Panel</p>
        <div id="login-error"></div>
        <form id="login-form">
          <div class="form-group">
            <label for="login-user">Username</label>
            <input type="text" id="login-user" autocomplete="username" required>
          </div>
          <div class="form-group">
            <label for="login-pass">Password</label>
            <input type="password" id="login-pass" autocomplete="current-password" required>
          </div>
          <div class="form-actions" style="justify-content:stretch">
            <button type="submit" class="btn btn-primary" style="flex:1" id="login-btn">Sign in</button>
          </div>
        </form>
      </div>
    </div>`;

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('login-btn');
    const errDiv = document.getElementById('login-error');
    const username = document.getElementById('login-user').value.trim();
    const password = document.getElementById('login-pass').value;
    if (!username || !password) return;

    btn.disabled = true;
    btn.textContent = 'Signing in...';
    errDiv.innerHTML = '';

    const res = await fetch('/panel/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json().catch(() => null);
    btn.disabled = false;
    btn.textContent = 'Sign in';

    if (!res.ok) {
      errDiv.innerHTML = `<div class="login-error">${esc(data?.error || 'Login failed')}</div>`;
      return;
    }

    state.loggedIn = true;
    state.username = data.username;
    state.mustChangePassword = data.mustChangePassword;
    render();
  });
}

// ---------------------------------------------------------------------------
// Force change password view
// ---------------------------------------------------------------------------
function renderChangePasswordForce() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="login-wrapper">
      <div class="login-card">
        <h1>Change Password</h1>
        <p class="login-subtitle">You must change the default password before continuing.</p>
        <div id="cp-error"></div>
        <form id="cp-form">
          <div class="form-group">
            <label for="cp-current">Current password</label>
            <input type="password" id="cp-current" autocomplete="current-password" required>
          </div>
          <div class="form-group">
            <label for="cp-new">New password</label>
            <input type="password" id="cp-new" autocomplete="new-password" required minlength="8">
            <p class="form-hint">Minimum 8 characters</p>
          </div>
          <div class="form-group">
            <label for="cp-confirm">Confirm new password</label>
            <input type="password" id="cp-confirm" autocomplete="new-password" required minlength="8">
          </div>
          <div class="form-actions" style="justify-content:stretch">
            <button type="submit" class="btn btn-primary" style="flex:1" id="cp-btn">Change password</button>
          </div>
        </form>
      </div>
    </div>`;

  document.getElementById('cp-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errDiv = document.getElementById('cp-error');
    const btn = document.getElementById('cp-btn');
    const currentPassword = document.getElementById('cp-current').value;
    const newPassword = document.getElementById('cp-new').value;
    const confirm = document.getElementById('cp-confirm').value;

    if (newPassword !== confirm) {
      errDiv.innerHTML = '<div class="login-error">Passwords do not match</div>';
      return;
    }
    if (newPassword.length < 8) {
      errDiv.innerHTML = '<div class="login-error">Password must be at least 8 characters</div>';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Changing...';
    errDiv.innerHTML = '';

    const data = await api('POST', '/auth/change-password', { currentPassword, newPassword });
    btn.disabled = false;
    btn.textContent = 'Change password';

    if (data) {
      state.mustChangePassword = false;
      showToast('Password changed successfully');
      render();
    }
  });
}

// ---------------------------------------------------------------------------
// App shell
// ---------------------------------------------------------------------------
async function fetchSystemInfo() {
  const data = await api('GET', '/system/info');
  if (data) state.systemInfo = data;
}

function renderApp() {
  const app = document.getElementById('app');
  const route = currentRoute();

  const navItems = [
    { id: 'clients', label: 'Clients', icon: '\u{1F5A5}' },
    { id: 'secrets', label: 'Secrets', icon: '\u{1F511}' },
    { id: 'audit', label: 'Audit Log', icon: '\u{1F4CB}' },
    { id: 'settings', label: 'Settings', icon: '\u{2699}' },
  ];

  const navHtml = navItems.map(n =>
    `<a href="#${n.id}" class="${route === n.id ? 'active' : ''}">
      <span class="nav-icon">${n.icon}</span> ${n.label}
    </a>`
  ).join('');

  const warningHtml = state.systemInfo?.isExposed
    ? `<div class="warning-banner">
        <span class="banner-icon">\u26A0</span>
        Admin panel is exposed on all interfaces (0.0.0.0). Use an SSH tunnel for production access.
      </div>`
    : '';

  app.innerHTML = `
    <div class="layout">
      <nav class="sidebar">
        <div class="sidebar-brand">Guardian <span>admin</span></div>
        <div class="sidebar-nav">${navHtml}</div>
        <div class="sidebar-footer">
          <button class="theme-toggle" onclick="window._toggleTheme()">${state.theme === 'light' ? 'Dark mode' : 'Light mode'}</button>
          <button onclick="window._logout()">Sign out (${esc(state.username)})</button>
        </div>
      </nav>
      <main class="main-content">
        ${warningHtml}
        <div id="view"></div>
      </main>
    </div>`;

  // Route to view
  const viewEl = document.getElementById('view');
  switch (route) {
    case 'clients':  renderClientsView(viewEl); break;
    case 'secrets':  renderSecretsView(viewEl); break;
    case 'audit':    renderAuditView(viewEl); break;
    case 'settings': renderSettingsView(viewEl); break;
    default:         navigate('clients'); break;
  }
}

window._toggleTheme = toggleTheme;

window._logout = async function () {
  await api('POST', '/auth/logout', {});
  state.loggedIn = false;
  state.username = '';
  state.systemInfo = null;
  render();
};

// ---------------------------------------------------------------------------
// Clients view
// ---------------------------------------------------------------------------
async function renderClientsView(el) {
  el.innerHTML = `
    <div class="page-header">
      <h2>Clients</h2>
      <button class="btn btn-primary" onclick="window._addClient()">+ Add Client</button>
    </div>
    <div class="card">
      <div class="loading"><span class="spinner"></span> Loading clients...</div>
    </div>`;

  const clients = await api('GET', '/clients');
  if (!clients) return;

  const card = el.querySelector('.card');

  if (clients.length === 0) {
    card.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">\u{1F5A5}</div>
        <p>No clients configured yet.</p>
        <button class="btn btn-primary" onclick="window._addClient()">Add your first client</button>
      </div>`;
    return;
  }

  card.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Machine ID</th>
          <th>Description</th>
          <th>Status</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${clients.map(c => `
          <tr>
            <td><span class="text-mono">${esc(c.machineId)}</span></td>
            <td>${esc(c.description) || '<span class="text-muted">-</span>'}</td>
            <td>
              <span class="badge ${c.enabled ? 'badge-success' : 'badge-danger'}">
                ${c.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </td>
            <td class="text-muted text-sm">${fmtDate(c.createdAt)}</td>
            <td>
              <div class="table-actions">
                <button class="btn btn-sm btn-ghost" onclick="window._toggleClient(${c.id}, ${c.enabled})"
                  title="${c.enabled ? 'Disable' : 'Enable'}">
                  ${c.enabled ? 'Disable' : 'Enable'}
                </button>
                <button class="btn btn-sm btn-ghost" onclick="window._regenToken(${c.id}, '${esc(c.machineId)}')"
                  title="Regenerate token">Regen</button>
                <button class="btn btn-sm btn-danger" onclick="window._deleteClient(${c.id}, '${esc(c.machineId)}')"
                  title="Delete client">Delete</button>
              </div>
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

window._addClient = function () {
  const body = `
    <form id="add-client-form">
      <div class="form-group">
        <label for="ac-mid">Machine ID</label>
        <input type="text" id="ac-mid" required placeholder="e.g. dev-laptop-01">
        <p class="form-hint">Unique identifier for this client machine</p>
      </div>
      <div class="form-group">
        <label for="ac-desc">Description</label>
        <input type="text" id="ac-desc" placeholder="e.g. Alice's development laptop">
      </div>
    </form>`;
  const footer = `
    <button class="btn" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="window._submitAddClient()">Create Client</button>`;
  showModal('Add Client', body, footer);
};

window._submitAddClient = async function () {
  const machineId = document.getElementById('ac-mid')?.value.trim();
  const description = document.getElementById('ac-desc')?.value.trim() || '';
  if (!machineId) { showToast('Machine ID is required', 'error'); return; }

  const data = await api('POST', '/clients', { machineId, description });
  if (data) {
    closeModal();
    showTokenModal(data.token, 'New Client Token');
    // Refresh list after modal closes (user will close it)
    const viewEl = document.getElementById('view');
    if (viewEl) renderClientsView(viewEl);
  }
};

window._toggleClient = async function (id, currentlyEnabled) {
  const data = await api('PUT', `/clients/${id}`, { enabled: !currentlyEnabled });
  if (data) {
    showToast(`Client ${data.enabled ? 'enabled' : 'disabled'}`);
    const viewEl = document.getElementById('view');
    if (viewEl) renderClientsView(viewEl);
  }
};

window._regenToken = async function (id, machineId) {
  if (!confirmAction(`Regenerate token for "${machineId}"? The old token will stop working immediately.`)) return;
  const data = await api('POST', `/clients/${id}/regenerate-token`, {});
  if (data) {
    showTokenModal(data.token, 'Regenerated Token');
  }
};

window._deleteClient = async function (id, machineId) {
  if (!confirmAction(`Delete client "${machineId}"? This action cannot be undone.`)) return;
  const data = await api('DELETE', `/clients/${id}`);
  if (data) {
    showToast('Client deleted');
    const viewEl = document.getElementById('view');
    if (viewEl) renderClientsView(viewEl);
  }
};

// ---------------------------------------------------------------------------
// Secrets view
// ---------------------------------------------------------------------------
async function renderSecretsView(el) {
  el.innerHTML = `
    <div class="page-header">
      <h2>Secrets</h2>
      <button class="btn btn-primary" onclick="window._addSecret()">+ Add Secret</button>
    </div>
    <div class="card">
      <div class="loading"><span class="spinner"></span> Loading secrets...</div>
    </div>`;

  const secrets = await api('GET', '/secrets');
  if (!secrets) return;

  const card = el.querySelector('.card');

  if (secrets.length === 0) {
    card.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">\u{1F511}</div>
        <p>No secrets configured yet.</p>
        <button class="btn btn-primary" onclick="window._addSecret()">Add your first secret</button>
      </div>`;
    return;
  }

  card.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Provider</th>
          <th>Path</th>
          <th>Has Value</th>
          <th>Allowed Domains</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${secrets.map(s => `
          <tr>
            <td><span class="text-mono">${esc(s.name)}</span></td>
            <td><span class="badge badge-primary">${esc(s.provider)}</span></td>
            <td class="text-mono text-sm">${esc(s.path) || '<span class="text-muted">-</span>'}</td>
            <td>
              <span class="badge ${s.hasValue ? 'badge-success' : 'badge-warning'}">
                ${s.hasValue ? 'Yes' : 'No'}
              </span>
            </td>
            <td>
              ${s.allowedDomains.length > 0
                ? s.allowedDomains.map(d => `<span class="badge badge-primary" style="margin:1px">${esc(d)}</span>`).join(' ')
                : '<span class="text-muted text-sm">Any</span>'}
            </td>
            <td>
              <div class="table-actions">
                <button class="btn btn-sm btn-ghost" onclick='window._editSecret(${JSON.stringify(s).replace(/'/g, "&#39;")})'>Edit</button>
                <button class="btn btn-sm btn-danger" onclick="window._deleteSecret(${s.id}, '${esc(s.name)}')">Delete</button>
              </div>
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function secretFormHtml(secret) {
  const isEdit = !!secret;
  const s = secret || { name: '', provider: 'env', path: '', field: '', allowedDomains: [] };
  return `
    <form id="secret-form">
      <div class="form-group">
        <label for="sf-name">Secret Name (placeholder pattern)</label>
        <input type="text" id="sf-name" required placeholder="e.g. OPENAI_API_KEY" value="${esc(s.name)}" ${isEdit ? 'readonly style="opacity:0.6"' : ''}>
        <p class="form-hint">Used as __NAME__ in request headers</p>
      </div>
      <div class="form-group">
        <label for="sf-provider">Provider</label>
        <select id="sf-provider" onchange="window._onProviderChange()">
          <option value="env" ${s.provider === 'env' ? 'selected' : ''}>Environment Variable</option>
          <option value="aws" ${s.provider === 'aws' ? 'selected' : ''}>AWS Secrets Manager</option>
          <option value="stored" ${s.provider === 'stored' ? 'selected' : ''}>Stored (encrypted in DB)</option>
        </select>
      </div>
      <div class="form-group" id="sf-path-group">
        <label for="sf-path">Path / Variable Name</label>
        <input type="text" id="sf-path" placeholder="e.g. OPENAI_API_KEY or aws/secret/path" value="${esc(s.path)}">
        <p class="form-hint">Environment variable name or AWS secret path</p>
      </div>
      <div class="form-group" id="sf-field-group">
        <label for="sf-field">Field (optional)</label>
        <input type="text" id="sf-field" placeholder="e.g. api_key (for JSON secrets)" value="${esc(s.field)}">
        <p class="form-hint">JSON field within the secret (AWS only)</p>
      </div>
      <div class="form-group" id="sf-value-group" style="display:${s.provider === 'stored' || s.provider === 'aws' ? 'block' : 'none'}">
        <label for="sf-value">Secret Value</label>
        <input type="password" id="sf-value" placeholder="${isEdit ? '(leave empty to keep current)' : 'Enter secret value'}">
        <p class="form-hint" id="sf-value-hint">${s.provider === 'aws' ? 'Optional — will be written directly to AWS Secrets Manager' : 'Will be encrypted at rest'}</p>
      </div>
      <div class="form-group">
        <label for="sf-domains">Allowed Domains</label>
        <input type="text" id="sf-domains" placeholder="e.g. api.openai.com, *.anthropic.com" value="${esc(s.allowedDomains.join(', '))}">
        <p class="form-hint">Comma-separated. Leave empty to allow all domains.</p>
      </div>
    </form>`;
}

window._onProviderChange = function () {
  const provider = document.getElementById('sf-provider')?.value;
  const valueGroup = document.getElementById('sf-value-group');
  const pathGroup = document.getElementById('sf-path-group');
  const fieldGroup = document.getElementById('sf-field-group');
  if (valueGroup) valueGroup.style.display = (provider === 'stored' || provider === 'aws') ? 'block' : 'none';
  const valueHint = document.getElementById('sf-value-hint');
  if (valueHint) {
    valueHint.textContent = provider === 'aws'
      ? 'Optional — will be written directly to AWS Secrets Manager'
      : 'Will be encrypted at rest';
  }
  if (pathGroup) {
    const label = pathGroup.querySelector('label');
    const hint = pathGroup.querySelector('.form-hint');
    if (provider === 'stored') {
      if (label) label.textContent = 'Path (optional)';
      if (hint) hint.textContent = 'Not required for stored secrets';
    } else if (provider === 'aws') {
      if (label) label.textContent = 'Secret Path';
      if (hint) hint.textContent = 'AWS Secrets Manager secret name/ARN';
    } else {
      if (label) label.textContent = 'Environment Variable';
      if (hint) hint.textContent = 'Name of the environment variable';
    }
  }
  if (fieldGroup) fieldGroup.style.display = provider === 'aws' ? 'block' : 'none';
};

window._addSecret = function () {
  const body = secretFormHtml(null);
  const footer = `
    <button class="btn" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="window._submitSecret()">Create Secret</button>`;
  showModal('Add Secret', body, footer);
  window._onProviderChange();
};

window._editSecret = function (secret) {
  const body = secretFormHtml(secret);
  const footer = `
    <button class="btn" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="window._submitSecret(${secret.id})">Save Changes</button>`;
  showModal('Edit Secret', body, footer);
  window._onProviderChange();
};

window._submitSecret = async function (editId) {
  const name = document.getElementById('sf-name')?.value.trim();
  const provider = document.getElementById('sf-provider')?.value;
  const path = document.getElementById('sf-path')?.value.trim();
  const field = document.getElementById('sf-field')?.value.trim();
  const value = document.getElementById('sf-value')?.value;
  const domainsRaw = document.getElementById('sf-domains')?.value.trim();
  const allowedDomains = domainsRaw ? domainsRaw.split(',').map(d => d.trim()).filter(Boolean) : [];

  if (!name) { showToast('Secret name is required', 'error'); return; }
  if (!provider) { showToast('Provider is required', 'error'); return; }

  const payload = { name, provider, path, field, allowedDomains };
  if ((provider === 'stored' || provider === 'aws') && value) payload.value = value;

  if (editId) {
    // Edit — don't send name
    delete payload.name;
    if ((provider === 'stored' || provider === 'aws') && !value) delete payload.value; // keep existing
    const data = await api('PUT', `/secrets/${editId}`, payload);
    if (data) {
      closeModal();
      showToast('Secret updated');
      const viewEl = document.getElementById('view');
      if (viewEl) renderSecretsView(viewEl);
    }
  } else {
    if (provider === 'stored' && !value) { showToast('Value is required for stored secrets', 'error'); return; }
    if (provider !== 'stored' && !path) { showToast('Path is required for this provider', 'error'); return; }
    const data = await api('POST', '/secrets', payload);
    if (data) {
      closeModal();
      showToast('Secret created');
      const viewEl = document.getElementById('view');
      if (viewEl) renderSecretsView(viewEl);
    }
  }
};

window._deleteSecret = async function (id, name) {
  if (!confirmAction(`Delete secret "${name}"? This action cannot be undone.`)) return;
  const data = await api('DELETE', `/secrets/${id}`);
  if (data) {
    showToast('Secret deleted');
    const viewEl = document.getElementById('view');
    if (viewEl) renderSecretsView(viewEl);
  }
};

// ---------------------------------------------------------------------------
// Audit view
// ---------------------------------------------------------------------------
const auditState = { page: 1, limit: 25, machineId: '', action: '' };

async function renderAuditView(el) {
  el.innerHTML = `
    <div class="page-header">
      <h2>Audit Log</h2>
    </div>
    <div id="audit-stats" class="stats-grid">
      <div class="stat-card"><div class="stat-value">-</div><div class="stat-label">Loading...</div></div>
    </div>
    <div class="card">
      <div class="filter-bar">
        <div class="form-group">
          <label for="af-mid">Machine ID</label>
          <input type="text" id="af-mid" placeholder="Filter by machine ID" value="${esc(auditState.machineId)}">
        </div>
        <div class="form-group">
          <label for="af-action">Action</label>
          <select id="af-action">
            <option value="">All actions</option>
            <option value="mitm" ${auditState.action === 'mitm' ? 'selected' : ''}>MITM</option>
            <option value="passthrough" ${auditState.action === 'passthrough' ? 'selected' : ''}>Passthrough</option>
            <option value="blocked" ${auditState.action === 'blocked' ? 'selected' : ''}>Blocked</option>
          </select>
        </div>
        <div class="form-group">
          <label>&nbsp;</label>
          <button class="btn btn-sm" onclick="window._applyAuditFilters()">Apply</button>
        </div>
      </div>
      <div id="audit-table">
        <div class="loading"><span class="spinner"></span> Loading audit entries...</div>
      </div>
    </div>`;

  // Load stats and entries in parallel
  await Promise.all([loadAuditStats(), loadAuditEntries()]);
}

async function loadAuditStats() {
  const stats = await api('GET', '/audit/stats');
  const container = document.getElementById('audit-stats');
  if (!stats || !container) return;

  const injections = stats.byAction?.mitm ?? 0;
  container.innerHTML = `
    <div class="stat-card">
      <div class="stat-value">${stats.total.toLocaleString()}</div>
      <div class="stat-label">Total Requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${injections.toLocaleString()}</div>
      <div class="stat-label">Injections (MITM)</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${stats.uniqueClients}</div>
      <div class="stat-label">Unique Clients</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${stats.last24h.toLocaleString()}</div>
      <div class="stat-label">Last 24 Hours</div>
    </div>`;
}

async function loadAuditEntries() {
  const params = new URLSearchParams();
  params.set('page', String(auditState.page));
  params.set('limit', String(auditState.limit));
  if (auditState.machineId) params.set('machineId', auditState.machineId);
  if (auditState.action) params.set('action', auditState.action);

  const data = await api('GET', `/audit?${params.toString()}`);
  const container = document.getElementById('audit-table');
  if (!data || !container) return;

  if (data.entries.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">\u{1F4CB}</div>
        <p>No audit entries found.</p>
      </div>`;
    return;
  }

  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Machine ID</th>
          <th>Method</th>
          <th>Target</th>
          <th>Action</th>
          <th>Injected Secrets</th>
        </tr>
      </thead>
      <tbody>
        ${data.entries.map(e => `
          <tr>
            <td class="text-sm text-muted">${fmtDate(e.timestamp)}</td>
            <td><span class="text-mono">${esc(e.machineId) || '<span class="text-muted">-</span>'}</span></td>
            <td>${esc(e.method)}</td>
            <td><span class="truncate" title="${esc(e.target)}">${esc(e.target)}</span></td>
            <td>
              <span class="badge ${e.action === 'mitm' ? 'badge-warning' : e.action === 'blocked' ? 'badge-danger' : 'badge-success'}">
                ${esc(e.action)}
              </span>
            </td>
            <td>
              ${e.injectedSecrets.length > 0
                ? e.injectedSecrets.map(s => `<span class="badge badge-primary" style="margin:1px">${esc(s)}</span>`).join(' ')
                : '<span class="text-muted text-sm">-</span>'}
            </td>
          </tr>`).join('')}
      </tbody>
    </table>
    ${renderPagination(data.page, data.totalPages, data.total)}`;
}

function renderPagination(currentPage, totalPages, total) {
  if (totalPages <= 1) return '';

  let buttons = '';
  // Previous
  buttons += `<button ${currentPage <= 1 ? 'disabled' : ''} onclick="window._auditPage(${currentPage - 1})">&laquo; Prev</button>`;

  // Page numbers — show max 7 pages
  const start = Math.max(1, currentPage - 3);
  const end = Math.min(totalPages, start + 6);
  for (let i = start; i <= end; i++) {
    buttons += `<button class="${i === currentPage ? 'active' : ''}" onclick="window._auditPage(${i})">${i}</button>`;
  }

  // Next
  buttons += `<button ${currentPage >= totalPages ? 'disabled' : ''} onclick="window._auditPage(${currentPage + 1})">Next &raquo;</button>`;

  return `
    <div class="pagination">
      ${buttons}
      <span class="page-info">${total.toLocaleString()} entries</span>
    </div>`;
}

window._applyAuditFilters = function () {
  auditState.machineId = document.getElementById('af-mid')?.value.trim() || '';
  auditState.action = document.getElementById('af-action')?.value || '';
  auditState.page = 1;
  loadAuditEntries();
};

window._auditPage = function (page) {
  auditState.page = page;
  loadAuditEntries();
};

// ---------------------------------------------------------------------------
// Settings view
// ---------------------------------------------------------------------------
async function renderSettingsView(el) {
  el.innerHTML = `
    <div class="page-header">
      <h2>Settings</h2>
    </div>
    <div class="card">
      <h3 style="font-size:1rem; margin-bottom:1rem">Change Password</h3>
      <form id="settings-cp-form" style="max-width:400px">
        <div class="form-group">
          <label for="scp-current">Current password</label>
          <input type="password" id="scp-current" autocomplete="current-password" required>
        </div>
        <div class="form-group">
          <label for="scp-new">New password</label>
          <input type="password" id="scp-new" autocomplete="new-password" required minlength="8">
          <p class="form-hint">Minimum 8 characters</p>
        </div>
        <div class="form-group">
          <label for="scp-confirm">Confirm new password</label>
          <input type="password" id="scp-confirm" autocomplete="new-password" required minlength="8">
        </div>
        <div class="form-actions" style="justify-content:flex-start">
          <button type="submit" class="btn btn-primary" id="scp-btn">Update Password</button>
        </div>
      </form>
    </div>
    <div class="card" style="margin-top:1rem">
      <h3 style="font-size:1rem; margin-bottom:1rem">System Information</h3>
      <div id="sys-info">
        <div class="loading"><span class="spinner"></span> Loading...</div>
      </div>
    </div>`;

  // Change password handler
  document.getElementById('settings-cp-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('scp-btn');
    const currentPassword = document.getElementById('scp-current').value;
    const newPassword = document.getElementById('scp-new').value;
    const confirm = document.getElementById('scp-confirm').value;

    if (newPassword !== confirm) { showToast('Passwords do not match', 'error'); return; }
    if (newPassword.length < 8) { showToast('Password must be at least 8 characters', 'error'); return; }

    btn.disabled = true;
    btn.textContent = 'Updating...';

    const data = await api('POST', '/auth/change-password', { currentPassword, newPassword });
    btn.disabled = false;
    btn.textContent = 'Update Password';

    if (data) {
      showToast('Password updated successfully');
      document.getElementById('scp-current').value = '';
      document.getElementById('scp-new').value = '';
      document.getElementById('scp-confirm').value = '';
    }
  });

  // System info
  const info = await api('GET', '/system/info');
  const infoEl = document.getElementById('sys-info');
  if (info && infoEl) {
    state.systemInfo = info;
    infoEl.innerHTML = `
      <dl class="info-grid">
        <dt>Version</dt>
        <dd>${esc(info.version)}</dd>
        <dt>Uptime</dt>
        <dd>${fmtRelative(info.uptime)}</dd>
        <dt>Panel Port</dt>
        <dd>${info.panelPort}</dd>
        <dt>Proxy Port</dt>
        <dd>${info.proxyPort}</dd>
        <dt>Tunnel Port</dt>
        <dd>${info.tunnelPort ?? 'Not configured'}</dd>
        <dt>Exposed</dt>
        <dd>
          <span class="badge ${info.isExposed ? 'badge-danger' : 'badge-success'}">
            ${info.isExposed ? 'Yes (0.0.0.0)' : 'No (localhost)'}
          </span>
        </dd>
      </dl>`;
  }
}

// ---------------------------------------------------------------------------
// Main render
// ---------------------------------------------------------------------------
function render() {
  if (!state.loggedIn) {
    renderLogin();
    return;
  }
  if (state.mustChangePassword) {
    renderChangePasswordForce();
    return;
  }
  fetchSystemInfo().then(() => renderApp());
}

// Kick off
render();
