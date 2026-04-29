/* ═══════════════════════════════════════════════════════════════
   ReqVault — app.js
   Full-featured API client (Insomnia-like) in Vanilla JS
   ═══════════════════════════════════════════════════════════════ */

// ─────────────────────────────────────────────
// CONFIG — API Endpoints (placeholders)
// ─────────────────────────────────────────────
const API = {
  structured:    '/request/rest',           // POST { url, method, headers?, body? }
  raw:           '/request/raw',            // POST { url, request }
  getRequest:    '/data/requests',          // GET  /api/requests/:id
  chat:          '/api/chat',             // POST { message, requetesId }
  collections:   '/api/collections',       // GET  → list all collections/folders/requests
  createFolder:  '/api/collections/folder',// POST { name, parentId? }
  createRequest: '/api/collections/request',// POST { name, method, url, folderId?, ... }
  updateRequest: '/api/collections/request',// PUT  /:id { name, method, url, ... }
  deleteRequest: '/api/collections/request',// DELETE /:id
  deleteFolder:  '/api/collections/folder', // DELETE /:id
};

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
const state = {
  currentRequestId: null,
  history: [],
  chatOpen: false,
  sidebarTab: 'collections',  // 'collections' | 'history'
  collections: [],             // tree: [{ id, name, type:'folder', children:[], expanded }, { id, name, type:'request', method, url }]
};

// ─────────────────────────────────────────────
// DOM REFERENCES
// ─────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
  // Tabs
  tabBtns:       $$('.tab-btn'),
  tabPanels:     $$('.tab-panel'),
  subtabBtns:    $$('.subtab-btn'),
  subtabPanels:  $$('.subtab-panel'),
  resptabBtns:   $$('.resptab-btn'),
  resptabPanels: $$('.resptab-panel'),

  // Structured
  reqMethod:     $('#req-method'),
  reqUrl:        $('#req-url'),
  reqBody:       $('#req-body'),
  bodyContentType: $('#body-content-type'),
  headersList:   $('#headers-list'),
  btnAddHeader:  $('#btn-add-header'),
  btnSendStruct: $('#btn-send-structured'),

  // Query Params
  paramsList:      $('#params-list'),
  btnAddParam:     $('#btn-add-param'),
  btnParseUrl:     $('#btn-parse-url-params'),
  paramsCount:     $('#params-count'),

  // Raw
  rawUrl:        $('#raw-url'),
  rawRequest:    $('#raw-request'),
  btnSendRaw:    $('#btn-send-raw'),

  // Response
  responseZone:     $('#response-zone'),
  respStatus:       $('#resp-status'),
  respTime:         $('#resp-time'),
  respEmpty:        $('#resp-empty'),
  respBodyContent:  $('#resp-body-content'),
  respHeadersContent: $('#resp-headers-content'),

  // Sidebar — tabs
  sidebarTabBtns: $$('.sidebar-tab-btn'),
  sidebarPanels:  $$('.sidebar-panel'),

  // Sidebar — collections
  collectionsTree:  $('#collections-tree'),
  collectionsEmpty: $('#collections-empty'),
  searchCollections: $('#search-collections'),
  btnNewFolder:     $('#btn-new-folder'),
  btnNewRequest:    $('#btn-new-request'),
  btnCreateFirst:   $('#btn-create-first-collection'),

  // Sidebar — history
  historyList:   $('#history-list'),
  historyEmpty:  $('#history-empty'),
  searchHistory: $('#search-history'),
  btnRefresh:    $('#btn-refresh-history'),

  // Chat
  chatPanel:     $('#chat-panel'),
  chatMessages:  $('#chat-messages'),
  chatInput:     $('#chat-input'),
  btnSendChat:   $('#btn-send-chat'),
  btnToggleChat: $('#btn-toggle-chat'),
  btnCloseChat:  $('#btn-close-chat'),
  chatContext:   $('#chat-context'),
  chatContextId: $('#chat-context-id'),

  // Loading
  loadingOverlay: $('#loading-overlay'),
};

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
function init() {
  setupSidebarTabs();
  setupTabs();
  setupSubtabs();
  setupRespTabs();
  setupParams();
  setupHeaders();
  setupChat();
  setupSend();
  setupHistory();
  setupCollections();
  setupResizeHandle();
  setupKeyboardShortcuts();

  // Add initial empty rows
  addParamRow('', '', true);
  addHeaderRow('', '');

  // Load collections (mock for now)
  loadCollections();
}

// ─────────────────────────────────────────────
// SIDEBAR TABS (Collections / History)
// ─────────────────────────────────────────────
function setupSidebarTabs() {
  dom.sidebarTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.sidebar;
      state.sidebarTab = target;
      dom.sidebarTabBtns.forEach(b => b.classList.toggle('active', b.dataset.sidebar === target));
      dom.sidebarPanels.forEach(p => {
        const isTarget = p.id === `sidebar-${target}`;
        p.classList.toggle('hidden', !isTarget);
        p.classList.toggle('active', isTarget);
      });
    });
  });
}

// ─────────────────────────────────────────────
// TABS
// ─────────────────────────────────────────────
function setupTabs() {
  dom.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      dom.tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;
      dom.tabPanels.forEach(p => {
        p.classList.toggle('hidden', p.id !== `tab-${target}`);
        p.classList.toggle('active', p.id === `tab-${target}`);
      });
    });
  });
}

function setupSubtabs() {
  dom.subtabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      dom.subtabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.subtab;
      dom.subtabPanels.forEach(p => {
        const isTarget = p.id === `subtab-${target}`;
        p.classList.toggle('hidden', !isTarget);
        p.classList.toggle('active', isTarget);
      });
    });
  });
}

function setupRespTabs() {
  dom.resptabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      dom.resptabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.resptab;
      dom.resptabPanels.forEach(p => {
        const isTarget = p.id === `resptab-${target}`;
        p.classList.toggle('hidden', !isTarget);
        p.classList.toggle('active', isTarget);
      });
    });
  });
}

// ─────────────────────────────────────────────
// QUERY PARAMS EDITOR
// ─────────────────────────────────────────────
let syncingFromUrl = false;
let syncingFromParams = false;

function setupParams() {
  dom.btnAddParam.addEventListener('click', () => addParamRow('', '', true));
  dom.btnParseUrl.addEventListener('click', parseUrlToParams);

  // Sync URL → params when user types in the URL field
  dom.reqUrl.addEventListener('input', () => {
    if (syncingFromParams) return;
    syncingFromUrl = true;
    parseUrlToParams();
    syncingFromUrl = false;
  });
}

function addParamRow(key = '', value = '', enabled = true) {
  const row = document.createElement('div');
  row.className = 'param-row' + (enabled ? '' : ' is-disabled');
  row.innerHTML = `
    <button class="btn-toggle-param ${enabled ? 'enabled' : 'disabled'}" title="Activer/Désactiver">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
    </button>
    <input type="text" placeholder="Clé" value="${escapeHtml(key)}" class="flex-1" />
    <input type="text" placeholder="Valeur" value="${escapeHtml(value)}" class="flex-[2]" />
    <button class="btn-remove-param" title="Supprimer">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  `;

  const toggleBtn = row.querySelector('.btn-toggle-param');
  toggleBtn.addEventListener('click', () => {
    const isEnabled = toggleBtn.classList.contains('enabled');
    toggleBtn.classList.toggle('enabled', !isEnabled);
    toggleBtn.classList.toggle('disabled', isEnabled);
    row.classList.toggle('is-disabled', isEnabled);
    syncParamsToUrl();
  });

  row.querySelector('.btn-remove-param').addEventListener('click', () => {
    row.remove();
    syncParamsToUrl();
    updateParamsCount();
  });

  // Sync params → URL on input change
  row.querySelectorAll('input').forEach(input => {
    input.addEventListener('input', () => syncParamsToUrl());
  });

  dom.paramsList.appendChild(row);
  updateParamsCount();
}

function getParams() {
  const params = [];
  dom.paramsList.querySelectorAll('.param-row').forEach(row => {
    const inputs = row.querySelectorAll('input');
    const toggleBtn = row.querySelector('.btn-toggle-param');
    const enabled = toggleBtn.classList.contains('enabled');
    const k = inputs[0].value.trim();
    const v = inputs[1].value.trim();
    params.push({ key: k, value: v, enabled });
  });
  return params;
}

function getEnabledParams() {
  return getParams().filter(p => p.enabled && p.key);
}

function clearParams() {
  dom.paramsList.innerHTML = '';
  updateParamsCount();
}

function parseUrlToParams() {
  const urlStr = dom.reqUrl.value.trim();
  if (!urlStr) return;

  try {
    const url = new URL(urlStr);
    const searchParams = url.searchParams;

    clearParams();
    let count = 0;
    searchParams.forEach((v, k) => {
      addParamRow(k, v, true);
      count++;
    });

    // Always have at least one empty row
    if (count === 0) {
      addParamRow('', '', true);
    }
  } catch {
    // If URL is not valid, try to parse query string manually
    const qIndex = urlStr.indexOf('?');
    if (qIndex === -1) return;

    const qs = urlStr.substring(qIndex + 1);
    clearParams();
    let count = 0;
    qs.split('&').forEach(pair => {
      if (!pair) return;
      const [k, ...vParts] = pair.split('=');
      const v = vParts.join('=');
      addParamRow(decodeURIComponent(k || ''), decodeURIComponent(v || ''), true);
      count++;
    });
    if (count === 0) {
      addParamRow('', '', true);
    }
  }
}

function syncParamsToUrl() {
  if (syncingFromUrl) return;
  syncingFromParams = true;

  const urlStr = dom.reqUrl.value.trim();
  let baseUrl = urlStr;

  // Strip existing query string
  try {
    const url = new URL(urlStr);
    baseUrl = url.origin + url.pathname;
  } catch {
    const qIndex = urlStr.indexOf('?');
    if (qIndex !== -1) {
      baseUrl = urlStr.substring(0, qIndex);
    }
  }

  const enabledParams = getEnabledParams();
  if (enabledParams.length > 0) {
    const qs = enabledParams
      .map(p => `${encodeURIComponent(p.key)}=${encodeURIComponent(p.value)}`)
      .join('&');
    dom.reqUrl.value = `${baseUrl}?${qs}`;
  } else {
    dom.reqUrl.value = baseUrl;
  }

  updateParamsCount();
  syncingFromParams = false;
}

function updateParamsCount() {
  const count = getEnabledParams().length;
  if (count > 0) {
    dom.paramsCount.textContent = count;
    dom.paramsCount.classList.remove('hidden');
  } else {
    dom.paramsCount.classList.add('hidden');
  }
}

// ─────────────────────────────────────────────
// HEADERS KEY-VALUE EDITOR
// ─────────────────────────────────────────────
function setupHeaders() {
  dom.btnAddHeader.addEventListener('click', () => addHeaderRow('', ''));
}

function addHeaderRow(key = '', value = '') {
  const row = document.createElement('div');
  row.className = 'header-row';
  row.innerHTML = `
    <input type="text" placeholder="Header name" value="${escapeHtml(key)}" class="flex-1" />
    <input type="text" placeholder="Value" value="${escapeHtml(value)}" class="flex-[2]" />
    <button class="btn-remove-header" title="Supprimer">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  `;
  row.querySelector('.btn-remove-header').addEventListener('click', () => {
    row.remove();
  });
  dom.headersList.appendChild(row);
}

function getHeaders() {
  const headers = {};
  dom.headersList.querySelectorAll('.header-row').forEach(row => {
    const inputs = row.querySelectorAll('input');
    const k = inputs[0].value.trim();
    const v = inputs[1].value.trim();
    if (k) headers[k] = v;
  });
  return headers;
}

function clearHeaders() {
  dom.headersList.innerHTML = '';
}

// ─────────────────────────────────────────────
// SEND REQUESTS
// ─────────────────────────────────────────────
function setupSend() {
  dom.btnSendStruct.addEventListener('click', sendStructured);
  dom.btnSendRaw.addEventListener('click', sendRaw);
}

async function sendStructured() {
  const baseUrl = dom.reqUrl.value.trim();
  const method = dom.reqMethod.value;
  if (!baseUrl) {
    shakeElement(dom.reqUrl);
    return;
  }

  // Build final URL with query params already baked in via sync
  const url = baseUrl;

  const headers = getHeaders();
  const body = dom.reqBody.value.trim();

  const payload = { url, method };
  if (Object.keys(headers).length > 0) payload.headers = headers;
  if (body) payload.body = body;

  showLoading();
  const startTime = performance.now();

  try {
    const res = await fetch(API.structured, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const elapsed = Math.round(performance.now() - startTime);

    // Store in history
    const entry = {
      id: data.requestId || data.id || generateId(),
      method,
      url,
      statusCode: data.statusCode,
      headers: data.headers || {},
      body: data.body || '',
      type: 'structured',
      reqHeaders: headers,
      reqBody: body,
      reqParams: getParams(),
      timestamp: Date.now(),
    };
    addToHistory(entry);
    displayResponse(entry, elapsed);
  } catch (err) {
    displayError(err.message);
  } finally {
    hideLoading();
  }
}

async function sendRaw() {
  const url = dom.rawUrl.value.trim();
  const request = dom.rawRequest.value.trim();
  if (!url) { shakeElement(dom.rawUrl); return; }
  if (!request) { shakeElement(dom.rawRequest); return; }

  const payload = { url, request };

  showLoading();
  const startTime = performance.now();

  try {
    const res = await fetch(API.raw, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const elapsed = Math.round(performance.now() - startTime);

    // Detect method from raw
    const methodMatch = rawRequest.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'RAW';

    const entry = {
      id: data.requestId || data.id || generateId(),
      method,
      url,
      statusCode: data.statusCode,
      headers: data.headers || {},
      body: data.body || '',
      type: 'raw',
      rawRequest,
      timestamp: Date.now(),
    };
    addToHistory(entry);
    displayResponse(entry, elapsed);
  } catch (err) {
    displayError(err.message);
  } finally {
    hideLoading();
  }
}

// ─────────────────────────────────────────────
// RESPONSE DISPLAY
// ─────────────────────────────────────────────
function displayResponse(entry, elapsed) {
  state.currentRequestId = entry.id;
  updateChatContext();

  // Status badge
  const code = entry.statusCode || 0;
  const statusClass = code >= 500 ? 's5xx' : code >= 400 ? 's4xx' : code >= 300 ? 's3xx' : 's2xx';
  const statusText = getStatusText(code);

  dom.respStatus.className = `status-badge ${statusClass} flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold`;
  dom.respStatus.innerHTML = `<span>${code}</span><span class="font-normal opacity-70">${statusText}</span>`;
  dom.respStatus.classList.remove('hidden');
  dom.respStatus.classList.add('flex');

  dom.respTime.textContent = `${elapsed}ms`;
  dom.respTime.classList.remove('hidden');
  dom.respTime.classList.add('inline');

  // Body
  dom.respEmpty.classList.add('hidden');
  dom.respBodyContent.classList.remove('hidden');

  let bodyContent = entry.body || '';
  try {
    const parsed = JSON.parse(bodyContent);
    bodyContent = JSON.stringify(parsed, null, 2);
  } catch {}
  dom.respBodyContent.textContent = bodyContent;

  // Headers
  dom.respHeadersContent.innerHTML = '';
  const respHeaders = entry.headers || {};
  if (typeof respHeaders === 'object') {
    Object.entries(respHeaders).forEach(([k, v]) => {
      const row = document.createElement('div');
      row.className = 'resp-header-row';
      row.innerHTML = `<span class="key">${escapeHtml(k)}</span><span class="val">${escapeHtml(String(v))}</span>`;
      dom.respHeadersContent.appendChild(row);
    });
  }
}

function displayError(message) {
  dom.respStatus.className = 'status-badge s5xx flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold';
  dom.respStatus.innerHTML = `<span>ERR</span><span class="font-normal opacity-70">Network Error</span>`;
  dom.respStatus.classList.remove('hidden');
  dom.respStatus.classList.add('flex');
  dom.respTime.classList.add('hidden');

  dom.respEmpty.classList.add('hidden');
  dom.respBodyContent.classList.remove('hidden');
  dom.respBodyContent.textContent = `Error: ${message}`;
}

// ─────────────────────────────────────────────
// COLLECTIONS (Directory)
// ─────────────────────────────────────────────
function setupCollections() {
  dom.btnNewFolder.addEventListener('click', () => createFolder());
  dom.btnNewRequest.addEventListener('click', () => createCollectionRequest());
  dom.btnCreateFirst.addEventListener('click', () => createFolder());
  dom.searchCollections.addEventListener('input', renderCollections);
}

async function loadCollections() {
  // TODO: Replace with real API call
  // try {
  //   const res = await fetch(API.collections);
  //   state.collections = await res.json();
  // } catch { }

  // Mock data for UI preview
  state.collections = [
    {
      id: 'f1', name: 'Auth Service', type: 'folder', expanded: true,
      children: [
        { id: 'r1', name: 'Login', type: 'request', method: 'POST', url: 'https://api.example.com/auth/login' },
        { id: 'r2', name: 'Register', type: 'request', method: 'POST', url: 'https://api.example.com/auth/register' },
        { id: 'r3', name: 'Refresh Token', type: 'request', method: 'POST', url: 'https://api.example.com/auth/refresh' },
      ]
    },
    {
      id: 'f2', name: 'Users', type: 'folder', expanded: false,
      children: [
        { id: 'r4', name: 'List Users', type: 'request', method: 'GET', url: 'https://api.example.com/users' },
        { id: 'r5', name: 'Get User', type: 'request', method: 'GET', url: 'https://api.example.com/users/:id' },
        { id: 'r6', name: 'Update User', type: 'request', method: 'PUT', url: 'https://api.example.com/users/:id' },
        { id: 'r7', name: 'Delete User', type: 'request', method: 'DELETE', url: 'https://api.example.com/users/:id' },
      ]
    },
    {
      id: 'f3', name: 'Orders', type: 'folder', expanded: false,
      children: [
        {
          id: 'f4', name: 'CRUD', type: 'folder', expanded: false,
          children: [
            { id: 'r8', name: 'Create Order', type: 'request', method: 'POST', url: 'https://api.example.com/orders' },
            { id: 'r9', name: 'List Orders', type: 'request', method: 'GET', url: 'https://api.example.com/orders' },
          ]
        },
        { id: 'r10', name: 'Cancel Order', type: 'request', method: 'PATCH', url: 'https://api.example.com/orders/:id/cancel' },
      ]
    },
    { id: 'r11', name: 'Health Check', type: 'request', method: 'GET', url: 'https://api.example.com/health' },
  ];

  renderCollections();
}

function renderCollections() {
  const query = dom.searchCollections.value.toLowerCase().trim();

  // Remove previous rendered items (keep empty state)
  dom.collectionsTree.querySelectorAll('.collection-folder, .collection-request').forEach(el => el.remove());

  const filtered = query ? filterCollectionTree(state.collections, query) : state.collections;

  dom.collectionsEmpty.classList.toggle('hidden', filtered.length > 0);

  filtered.forEach(node => {
    const el = renderCollectionNode(node, 0);
    dom.collectionsTree.insertBefore(el, dom.collectionsEmpty);
  });
}

function filterCollectionTree(nodes, query) {
  const result = [];
  for (const node of nodes) {
    if (node.type === 'request') {
      if (node.name.toLowerCase().includes(query) || (node.url && node.url.toLowerCase().includes(query)) || (node.method && node.method.toLowerCase().includes(query))) {
        result.push({ ...node });
      }
    } else if (node.type === 'folder') {
      const filteredChildren = filterCollectionTree(node.children || [], query);
      if (filteredChildren.length > 0 || node.name.toLowerCase().includes(query)) {
        result.push({ ...node, children: filteredChildren, expanded: true });
      }
    }
  }
  return result;
}

function renderCollectionNode(node, depth) {
  if (node.type === 'folder') {
    return renderFolderNode(node, depth);
  } else {
    return renderRequestNode(node);
  }
}

function renderFolderNode(folder, depth) {
  const wrapper = document.createElement('div');
  wrapper.className = 'collection-folder';
  wrapper.dataset.id = folder.id;

  const header = document.createElement('div');
  header.className = 'collection-folder-header';
  header.innerHTML = `
    <svg class="folder-chevron ${folder.expanded ? 'open' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5"/></svg>
    <svg class="folder-icon ${folder.expanded ? 'open' : 'closed'}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
      ${folder.expanded
        ? '<path stroke-linecap="round" stroke-linejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776"/>'
        : '<path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"/>'
      }
    </svg>
    <span class="text-xs font-medium text-gray-300 flex-1 truncate">${escapeHtml(folder.name)}</span>
    <span class="text-[10px] text-gray-600 font-mono mr-1">${(folder.children || []).length}</span>
    <div class="folder-actions">
      <button title="Ajouter une requête" data-action="add-request">
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
      </button>
      <button title="Supprimer" data-action="delete-folder">
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg>
      </button>
    </div>
  `;

  const childrenContainer = document.createElement('div');
  childrenContainer.className = 'collection-folder-children' + (folder.expanded ? '' : ' collapsed');
  if (folder.expanded) {
    childrenContainer.style.maxHeight = 'none';
  } else {
    childrenContainer.style.maxHeight = '0';
  }

  (folder.children || []).forEach(child => {
    childrenContainer.appendChild(renderCollectionNode(child, depth + 1));
  });

  // Toggle expand/collapse
  header.addEventListener('click', (e) => {
    if (e.target.closest('.folder-actions')) return;
    folder.expanded = !folder.expanded;
    const chevron = header.querySelector('.folder-chevron');
    chevron.classList.toggle('open', folder.expanded);

    // Update folder icon
    const folderIcon = header.querySelector('.folder-icon');
    folderIcon.classList.toggle('open', folder.expanded);
    folderIcon.classList.toggle('closed', !folder.expanded);
    folderIcon.innerHTML = folder.expanded
      ? '<path stroke-linecap="round" stroke-linejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776"/>'
      : '<path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"/>';

    if (folder.expanded) {
      childrenContainer.classList.remove('collapsed');
      childrenContainer.style.maxHeight = childrenContainer.scrollHeight + 'px';
      setTimeout(() => { childrenContainer.style.maxHeight = 'none'; }, 250);
    } else {
      childrenContainer.style.maxHeight = childrenContainer.scrollHeight + 'px';
      requestAnimationFrame(() => {
        childrenContainer.style.maxHeight = '0';
        childrenContainer.classList.add('collapsed');
      });
    }
  });

  // Folder action: add request
  header.querySelector('[data-action="add-request"]').addEventListener('click', (e) => {
    e.stopPropagation();
    createCollectionRequest(folder.id);
  });

  // Folder action: delete
  header.querySelector('[data-action="delete-folder"]').addEventListener('click', (e) => {
    e.stopPropagation();
    deleteCollectionFolder(folder.id);
  });

  wrapper.appendChild(header);
  wrapper.appendChild(childrenContainer);
  return wrapper;
}

function renderRequestNode(req) {
  const item = document.createElement('div');
  item.className = 'collection-request';
  item.dataset.id = req.id;

  const methodLower = (req.method || 'GET').toLowerCase();
  item.innerHTML = `
    <span class="method-badge ${methodLower}" style="font-size:8px;padding:1px 4px;min-width:30px;">${escapeHtml(req.method || 'GET')}</span>
    <span class="text-xs text-gray-300 truncate flex-1">${escapeHtml(req.name)}</span>
    <div class="req-actions">
      <button title="Supprimer" data-action="delete-request">
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg>
      </button>
    </div>
  `;

  // Click to load request into builder
  item.addEventListener('click', (e) => {
    if (e.target.closest('.req-actions')) return;
    loadCollectionRequest(req);
    // Highlight active
    dom.collectionsTree.querySelectorAll('.collection-request').forEach(el => el.classList.remove('active'));
    item.classList.add('active');
  });

  // Delete action
  item.querySelector('[data-action="delete-request"]').addEventListener('click', (e) => {
    e.stopPropagation();
    deleteCollectionRequest(req.id);
  });

  return item;
}

function loadCollectionRequest(req) {
  // Switch to structured tab & populate
  dom.tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === 'structured'));
  dom.tabPanels.forEach(p => {
    p.classList.toggle('hidden', p.id !== 'tab-structured');
    p.classList.toggle('active', p.id === 'tab-structured');
  });

  dom.reqMethod.value = req.method || 'GET';
  dom.reqUrl.value = req.url || '';
  dom.reqBody.value = req.body || '';

  // Parse params from URL
  clearParams();
  parseUrlToParams();
  if (dom.paramsList.querySelectorAll('.param-row').length === 0) {
    addParamRow('', '', true);
  }

  // Headers
  clearHeaders();
  const reqHeaders = req.headers || {};
  const headerEntries = Object.entries(reqHeaders);
  if (headerEntries.length === 0) {
    addHeaderRow('', '');
  } else {
    headerEntries.forEach(([k, v]) => addHeaderRow(k, v));
  }
}

function createFolder(parentId) {
  const name = prompt('Nom du dossier :');
  if (!name || !name.trim()) return;

  const newFolder = {
    id: 'f-' + generateId().substring(0, 8),
    name: name.trim(),
    type: 'folder',
    expanded: true,
    children: [],
  };

  // TODO: API call
  // await fetch(API.createFolder, { method:'POST', body: JSON.stringify({ name, parentId }) });

  if (parentId) {
    const parent = findNodeById(state.collections, parentId);
    if (parent && parent.children) {
      parent.children.push(newFolder);
    }
  } else {
    state.collections.push(newFolder);
  }
  renderCollections();
}

function createCollectionRequest(folderId) {
  const name = prompt('Nom de la requête :');
  if (!name || !name.trim()) return;

  const newReq = {
    id: 'r-' + generateId().substring(0, 8),
    name: name.trim(),
    type: 'request',
    method: 'GET',
    url: '',
  };

  // TODO: API call
  // await fetch(API.createRequest, { method:'POST', body: JSON.stringify({ name, folderId }) });

  if (folderId) {
    const folder = findNodeById(state.collections, folderId);
    if (folder && folder.children) {
      folder.children.push(newReq);
      folder.expanded = true;
    }
  } else {
    state.collections.push(newReq);
  }
  renderCollections();
}

function deleteCollectionFolder(id) {
  if (!confirm('Supprimer ce dossier et son contenu ?')) return;
  // TODO: API call
  state.collections = removeNodeById(state.collections, id);
  renderCollections();
}

function deleteCollectionRequest(id) {
  if (!confirm('Supprimer cette requête ?')) return;
  // TODO: API call
  state.collections = removeNodeById(state.collections, id);
  renderCollections();
}

function findNodeById(nodes, id) {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.children) {
      const found = findNodeById(node.children, id);
      if (found) return found;
    }
  }
  return null;
}

function removeNodeById(nodes, id) {
  return nodes.filter(n => {
    if (n.id === id) return false;
    if (n.children) n.children = removeNodeById(n.children, id);
    return true;
  });
}

// ─────────────────────────────────────────────
// HISTORY
// ─────────────────────────────────────────────
function setupHistory() {
  dom.searchHistory.addEventListener('input', renderHistory);
  dom.btnRefresh.addEventListener('click', renderHistory);
}

function addToHistory(entry) {
  // Avoid duplicates
  state.history = state.history.filter(h => h.id !== entry.id);
  state.history.unshift(entry);
  renderHistory();
}

function renderHistory() {
  const query = dom.searchHistory.value.toLowerCase().trim();
  const filtered = query
    ? state.history.filter(h => h.url.toLowerCase().includes(query) || h.method.toLowerCase().includes(query) || h.id.toLowerCase().includes(query))
    : state.history;

  // Clear except empty state
  const items = dom.historyList.querySelectorAll('.history-item');
  items.forEach(i => i.remove());

  dom.historyEmpty.classList.toggle('hidden', filtered.length > 0);

  filtered.forEach(entry => {
    const item = document.createElement('div');
    item.className = 'history-item' + (entry.id === state.currentRequestId ? ' active' : '');
    item.dataset.id = entry.id;

    const methodLower = (entry.method || 'get').toLowerCase();
    const urlShort = truncateUrl(entry.url, 28);
    const statusCode = entry.statusCode || '—';
    const statusClass = statusCode >= 500 ? 's5xx' : statusCode >= 400 ? 's4xx' : statusCode >= 300 ? 's3xx' : 's2xx';
    const timeAgo = formatTimeAgo(entry.timestamp);

    item.innerHTML = `
      <span class="method-badge ${methodLower}">${entry.method}</span>
      <div class="flex-1 min-w-0">
        <div class="text-xs text-gray-300 truncate font-['JetBrains_Mono'] leading-tight">${escapeHtml(urlShort)}</div>
        <div class="flex items-center gap-2 mt-0.5">
          <span class="text-[10px] font-mono font-semibold ${statusClass === 's2xx' ? 'text-green-400/70' : statusClass === 's4xx' ? 'text-orange-400/70' : statusClass === 's5xx' ? 'text-red-400/70' : 'text-blue-400/70'}">${statusCode}</span>
          <span class="text-[10px] text-gray-600">${timeAgo}</span>
        </div>
      </div>
    `;

    item.addEventListener('click', () => loadHistoryEntry(entry));
    dom.historyList.insertBefore(item, dom.historyEmpty);
  });
}

async function loadHistoryEntry(entry) {
  state.currentRequestId = entry.id;
  updateChatContext();

  // Try to fetch the latest from the API
  let freshEntry = entry;
  try {
    const res = await fetch(`${API.getRequest}/${entry.id}`);
    if (res.ok) {
      const data = await res.json();
      freshEntry = { ...entry, ...data };
    }
  } catch {
    // Use cached entry
  }

  // Populate the request builder based on type
  if (freshEntry.type === 'raw') {
    // Switch to raw tab
    dom.tabBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.tab === 'raw');
    });
    dom.tabPanels.forEach(p => {
      p.classList.toggle('hidden', p.id !== 'tab-raw');
      p.classList.toggle('active', p.id === 'tab-raw');
    });
    dom.rawUrl.value = freshEntry.url || '';
    dom.rawRequest.value = freshEntry.rawRequest || '';
  } else {
    // Switch to structured tab
    dom.tabBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.tab === 'structured');
    });
    dom.tabPanels.forEach(p => {
      p.classList.toggle('hidden', p.id !== 'tab-structured');
      p.classList.toggle('active', p.id === 'tab-structured');
    });
    dom.reqMethod.value = freshEntry.method || 'GET';
    dom.reqUrl.value = freshEntry.url || '';
    dom.reqBody.value = freshEntry.reqBody || '';

    // Populate query params
    clearParams();
    const reqParams = freshEntry.reqParams || [];
    if (reqParams.length === 0) {
      // Try to parse from URL
      parseUrlToParams();
      // If still empty, add an empty row
      if (dom.paramsList.querySelectorAll('.param-row').length === 0) {
        addParamRow('', '', true);
      }
    } else {
      reqParams.forEach(p => addParamRow(p.key, p.value, p.enabled));
    }

    // Populate headers
    clearHeaders();
    const reqHeaders = freshEntry.reqHeaders || {};
    const headerEntries = Object.entries(reqHeaders);
    if (headerEntries.length === 0) {
      addHeaderRow('', '');
    } else {
      headerEntries.forEach(([k, v]) => addHeaderRow(k, v));
    }
  }

  // Display response
  displayResponse(freshEntry, 0);

  // Update active state in sidebar
  dom.historyList.querySelectorAll('.history-item').forEach(item => {
    item.classList.toggle('active', item.dataset.id === entry.id);
  });
}

// ─────────────────────────────────────────────
// CHAT IA
// ─────────────────────────────────────────────
function setupChat() {
  dom.btnToggleChat.addEventListener('click', toggleChat);
  dom.btnCloseChat.addEventListener('click', toggleChat);
  dom.btnSendChat.addEventListener('click', sendChatMessage);
  dom.chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });
}

function toggleChat() {
  state.chatOpen = !state.chatOpen;
  if (state.chatOpen) {
    dom.chatPanel.classList.remove('hidden');
    dom.chatPanel.classList.add('flex');
    dom.chatInput.focus();
  } else {
    dom.chatPanel.classList.add('hidden');
    dom.chatPanel.classList.remove('flex');
  }
  updateChatContext();
}

function updateChatContext() {
  if (state.currentRequestId) {
    dom.chatContext.classList.remove('hidden');
    dom.chatContextId.textContent = state.currentRequestId;
  } else {
    dom.chatContext.classList.add('hidden');
  }
}

function addChatMessage(content, type = 'user') {
  const wrapper = document.createElement('div');

  if (type === 'user') {
    wrapper.className = 'chat-msg-user';
    wrapper.innerHTML = `<div class="chat-bubble">${escapeHtml(content)}</div>`;
  } else if (type === 'ai') {
    wrapper.className = 'chat-msg-ai';
    wrapper.innerHTML = `
      <div class="w-7 h-7 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">
        <svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>
      </div>
      <div class="chat-bubble">${content}</div>
    `;
  } else if (type === 'loading') {
    wrapper.className = 'chat-msg-ai';
    wrapper.id = 'chat-loading';
    wrapper.innerHTML = `
      <div class="w-7 h-7 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">
        <svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>
      </div>
      <div class="chat-bubble loading-dots"><span></span><span></span><span></span></div>
    `;
  }

  dom.chatMessages.appendChild(wrapper);
  dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
  return wrapper;
}

function removeChatLoading() {
  const el = document.getElementById('chat-loading');
  if (el) el.remove();
}

async function sendChatMessage() {
  const message = dom.chatInput.value.trim();
  if (!message) return;

  dom.chatInput.value = '';
  addChatMessage(message, 'user');
  addChatMessage('', 'loading');

  const payload = {
    message,
    requetesId: state.currentRequestId || null,
  };

  try {
    const res = await fetch(API.chat, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    removeChatLoading();
    addChatMessage(data.response || data.message || 'Réponse reçue.', 'ai');
  } catch (err) {
    removeChatLoading();
    addChatMessage(`Erreur de connexion : ${err.message}`, 'ai');
  }
}

// ─────────────────────────────────────────────
// RESPONSE RESIZE HANDLE
// ─────────────────────────────────────────────
function setupResizeHandle() {
  const handle = $('#response-resize');
  let startY = 0;
  let startHeight = 0;
  let isResizing = false;

  handle.addEventListener('mousedown', (e) => {
    isResizing = true;
    startY = e.clientY;
    startHeight = dom.responseZone.offsetHeight;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;
    const diff = startY - e.clientY;
    const newHeight = Math.max(100, Math.min(window.innerHeight * 0.7, startHeight + diff));
    dom.responseZone.style.height = newHeight + 'px';
  });

  document.addEventListener('mouseup', () => {
    if (isResizing) {
      isResizing = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
  });
}

// ─────────────────────────────────────────────
// KEYBOARD SHORTCUTS
// ─────────────────────────────────────────────
function setupKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Ctrl+I → toggle chat
    if (e.ctrlKey && e.key === 'i') {
      e.preventDefault();
      toggleChat();
    }
    // Ctrl+Enter → send current request
    if (e.ctrlKey && e.key === 'Enter') {
      e.preventDefault();
      const activeTab = document.querySelector('.tab-btn.active');
      if (activeTab && activeTab.dataset.tab === 'raw') {
        sendRaw();
      } else {
        sendStructured();
      }
    }
  });
}

// ─────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────
function showLoading() {
  dom.loadingOverlay.classList.remove('hidden');
  dom.loadingOverlay.classList.add('flex');
}

function hideLoading() {
  dom.loadingOverlay.classList.add('hidden');
  dom.loadingOverlay.classList.remove('flex');
}

function shakeElement(el) {
  el.classList.add('border-red-500/50');
  el.style.animation = 'shake 0.3s ease';
  setTimeout(() => {
    el.classList.remove('border-red-500/50');
    el.style.animation = '';
  }, 500);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function truncateUrl(url, max) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const path = u.pathname + u.search;
    if (path.length <= max) return path;
    return path.substring(0, max - 1) + '…';
  } catch {
    if (url.length <= max) return url;
    return url.substring(0, max - 1) + '…';
  }
}

function formatTimeAgo(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  const secs = Math.floor(diff / 1000);
  if (secs < 5) return 'maintenant';
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}j`;
}

function getStatusText(code) {
  const map = {
    200: 'OK', 201: 'Created', 204: 'No Content',
    301: 'Moved', 302: 'Found', 304: 'Not Modified',
    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
    404: 'Not Found', 405: 'Method Not Allowed', 409: 'Conflict',
    422: 'Unprocessable', 429: 'Too Many Requests',
    500: 'Internal Error', 502: 'Bad Gateway', 503: 'Unavailable', 504: 'Timeout',
  };
  return map[code] || '';
}

function generateId() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ── Shake keyframes (injected once) ──
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20% { transform: translateX(-4px); }
  40% { transform: translateX(4px); }
  60% { transform: translateX(-3px); }
  80% { transform: translateX(3px); }
}`;
document.head.appendChild(shakeStyle);

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
