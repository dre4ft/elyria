/* ═══════════════════════════════════════════════════════════════
   ReqVault — app.js
   Full-featured API client (Insomnia-like) in Vanilla JS
   ═══════════════════════════════════════════════════════════════ */

// ─────────────────────────────────────────────
// CONFIG — API Endpoints
// ─────────────────────────────────────────────
const API = {
  structured:    'api/request',              // POST { url, method, headers?, body? }
  raw:           'api/request/raw',               // POST { url, request }
  getRequest:    'api/requests/byId',        // GET  /:id
  userHistory:   'api/requests/byUserId',    // GET  /:userId?limit=&page=
  chat:          'api/chat',                  // POST { message, conversationId }
  collections:   'api/collections',           // GET  → list all collections/folders/requests
  createFolder:  'api/collections/folder',    // POST { name, parentId? }
  createRequest: 'api/collections/request',   // POST { name, method, url, folderId?, ... }
  updateRequest: 'api/collections/request',   // PUT  /:id { name, method, url, ... }
  deleteRequest: 'api/collections/request',   // DELETE /:id
  deleteFolder:  'api/collections/folder',    // DELETE /:id
  uploadOpenAPI: 'api/document/openapi',       // POST multipart file upload
};

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
const state = {
  conversation_id : null,
  currentRequestId: null,
  history: [],
  chatOpen: false,
  sidebarTab: 'collections',  // 'collections' | 'history'
  collections: [],             // tree: [{ id, name, type:'folder', children:[], expanded }, { id, name, type:'request', method, url }]
  activeCollectionId: null,   // ID de la requête de collection actuellement chargée
};

// Clé localStorage pour la sauvegarde temporaire du builder
const BUILDER_STATE_KEY = 'elyria_builder_state';

// ─────────────────────────────────────────────
// BUILDER STATE PERSISTENCE (localStorage temporaire)
// ─────────────────────────────────────────────
function saveBuilderState() {
  const builderState = {
    method: dom.reqMethod.value,
    url: dom.reqUrl.value,
    body: dom.reqBody.value,
    contentType: dom.bodyContentType.value,
    params: getParams(),
    headers: getHeaders(),
    activeCollectionId: state.activeCollectionId,
    savedAt: Date.now(),
  };
  try {
    localStorage.setItem(BUILDER_STATE_KEY, JSON.stringify(builderState));
  } catch {}
}

function restoreBuilderState() {
  try {
    const raw = localStorage.getItem(BUILDER_STATE_KEY);
    if (!raw) return false;
    const saved = JSON.parse(raw);
    if (!saved || typeof saved !== 'object') return false;

    dom.reqMethod.value = saved.method || 'GET';
    dom.reqUrl.value = saved.url || '';
    dom.reqBody.value = saved.body || '';
    if (saved.contentType) dom.bodyContentType.value = saved.contentType;

    // Restaurer les params
    clearParams();
    const params = saved.params || [];
    if (params.length > 0) {
      params.forEach(p => addParamRow(p.key, p.value, p.enabled !== false));
    } else {
      addParamRow('', '', true);
    }

    // Restaurer les headers
    clearHeaders();
    const headers = saved.headers || {};
    const headerEntries = Object.entries(headers);
    if (headerEntries.length > 0) {
      headerEntries.forEach(([k, v]) => addHeaderRow(k, v));
    } else {
      addHeaderRow('', '');
    }

    state.activeCollectionId = saved.activeCollectionId || null;
    return true;
  } catch {
    return false;
  }
}

function setupBuilderAutoSave() {
  // Sauvegarder à chaque changement dans le builder
  dom.reqMethod.addEventListener('change', saveBuilderState);
  dom.reqUrl.addEventListener('input', saveBuilderState);
  dom.reqBody.addEventListener('input', saveBuilderState);
  dom.bodyContentType.addEventListener('change', saveBuilderState);

  // Observer les changements dans les listes params/headers
  const observer = new MutationObserver(() => saveBuilderState());
  observer.observe(dom.paramsList, { childList: true, subtree: true, characterData: true });
  observer.observe(dom.headersList, { childList: true, subtree: true, characterData: true });

  // Sauvegarder aussi quand on tape dans les inputs params/headers
  dom.paramsList.addEventListener('input', saveBuilderState);
  dom.headersList.addEventListener('input', saveBuilderState);
}

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
  btnRefreshCol:    $('#btn-refresh-collections'),
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
  btnClearChat:  $('#btn-clear-chat'),
  chatContext:   $('#chat-context'),
  chatContextId: $('#chat-context-id'),

  // Modal
  createModal:    $('#create-modal'),
  modalTitle:     $('#modal-title'),
  modalInput:     $('#modal-input'),
  btnModalCancel: $('#btn-modal-cancel'),
  btnModalOk:     $('#btn-modal-ok'),

  // Document upload modal
  docModal:         $('#doc-modal'),
  docDropZone:      $('#doc-drop-zone'),
  docFileInput:     $('#doc-file-input'),
  docDropContent:   $('#doc-drop-content'),
  docFileSelected:  $('#doc-file-selected'),
  docFileName:      $('#doc-file-name'),
  docFileSize:      $('#doc-file-size'),
  docMsg:           $('#doc-msg'),
  btnDocModalClose: $('#btn-doc-modal-close'),
  btnDocModalCancel:$('#btn-doc-modal-cancel'),
  btnDocModalUpload:$('#btn-doc-modal-upload'),
  btnOpenDocs:      $('#btn-open-docs'),

  // Loading
  loadingOverlay: $('#loading-overlay'),
};

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
function init() {
  if (window.__appInitCalled) return;
  window.__appInitCalled = true;
  initAuth();

  // Afficher le nom d'utilisateur et configurer le bouton logout
  const user = getUser();
  const usernameEl = $('#header-username');
  const logoutBtn = $('#btn-logout');
  if (user && usernameEl && logoutBtn) {
    usernameEl.textContent = user.username || user.userId;
    usernameEl.classList.remove('hidden');
    logoutBtn.addEventListener('click', logout);
  }

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
  setupDocModal();
  setupKeyboardShortcuts();

  // Restaurer l'état du builder (ou ajouter des rows vides par défaut)
  const restored = restoreBuilderState();
  if (!restored) {
    addParamRow('', '', true);
    addHeaderRow('', '');
  }

  // Activer l'auto-sauvegarde du builder
  setupBuilderAutoSave();

  // Load collections
  loadCollections();

  // Load user's past requests from backend
  loadHistory();
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
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const elapsed = Math.round(performance.now() - startTime);

    const responseData = data.response || data;

    // Store in history
    const entry = {
      id: data.request_uuid || generateId(),
      method,
      url,
      statusCode: responseData.status_code,
      headers: responseData.headers || {},
      body: responseData.body || '',
      type: 'structured',
      reqHeaders: headers,
      reqBody: body,
      reqParams: getParams(),
      timestamp: Date.now(),
    };
    addToHistory(entry);
    displayResponse(entry, elapsed);

    // Sync collection request if anything changed
    syncCollectionRequest({ method, url, headers, body });
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
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const elapsed = Math.round(performance.now() - startTime);

    const responseData = data.response || data;

    // Detect method from raw
    const methodMatch = rawRequest.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'RAW';

    const entry = {
      id: data.request_uuid || generateId(),
      method,
      url,
      statusCode: responseData.status_code,
      headers: responseData.headers || {},
      body: responseData.body || '',
      type: 'raw',
      rawRequest,
      timestamp: Date.now(),
    };
    addToHistory(entry);
    displayResponse(entry, elapsed);

    syncCollectionRequest({ method, url });
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
  dom.btnNewFolder.addEventListener('click', () => showCreateModal('Créer un dossier', 'Nom du dossier', createFolder));
  dom.btnNewRequest.addEventListener('click', () => showCreateModal('Créer une requête', 'Nom de la requête', createCollectionRequest));
  dom.btnCreateFirst.addEventListener('click', () => showCreateModal('Créer un dossier', 'Nom du dossier', createFolder));
  dom.btnRefreshCol.addEventListener('click', () => loadCollections());
  dom.searchCollections.addEventListener('input', renderCollections);

  // Setup modal
  dom.btnModalCancel.addEventListener('click', hideCreateModal);
  dom.btnModalOk.addEventListener('click', () => {
    const name = dom.modalInput.value.trim();
    if (name && dom.btnModalOk.callback) {
      dom.btnModalOk.callback(name);
    }
    hideCreateModal();
  });
  dom.modalInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      dom.btnModalOk.click();
    } else if (e.key === 'Escape') {
      hideCreateModal();
    }
  });
}

async function loadCollections() {
  // Sauvegarder l'état expanded des dossiers existants
  const expandedMap = {};
  function collectExpanded(nodes) {
    for (const n of nodes) {
      if (n.type === 'folder') {
        expandedMap[n.id] = !!n.expanded;
        if (n.children) collectExpanded(n.children);
      }
    }
  }
  collectExpanded(state.collections);

  try {
    const res = await fetch(API.collections, { headers: { ...getAuthHeader() } });
    if (res.ok) {
      state.collections = await res.json();
      // Restaurer l'état expanded
      function restoreExpanded(nodes) {
        for (const n of nodes) {
          if (n.type === 'folder') {
            if (expandedMap.hasOwnProperty(n.id)) n.expanded = expandedMap[n.id];
            if (n.children) restoreExpanded(n.children);
          }
        }
      }
      restoreExpanded(state.collections);
    }
  } catch { }
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

  // Double-click to rename
  header.addEventListener('dblclick', (e) => {
    if (e.target.closest('.folder-actions')) return;
    e.stopPropagation();
    renameFolder(folder);
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
    showCreateModal('Créer une requête', 'Nom de la requête', (name) => createCollectionRequest(name, folder.id));
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

  const method = req.method || 'GET';
  const methodLower = method.toLowerCase();
  const isActive = req.id === state.activeCollectionId;
  if (isActive) item.classList.add('active');

  const aiBadge = req.isDoneByAI
    ? `<span class="ai-badge" title="Généré par IA"><svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg></span>`
    : '';

  const urlPreview = req.url ? `<span class="text-[10px] text-gray-600 truncate font-['JetBrains_Mono'] block leading-tight">${escapeHtml(truncateUrl(req.url, 40))}</span>` : '';

  item.innerHTML = `
    <span class="method-badge ${methodLower}">${escapeHtml(method)}</span>
    <div class="flex-1 min-w-0">
      <span class="text-xs text-gray-300 truncate block leading-tight">${escapeHtml(req.name)}</span>
      ${urlPreview}
    </div>
    ${aiBadge}
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
  });

  // Double-click to rename
  item.addEventListener('dblclick', (e) => {
    if (e.target.closest('.req-actions')) return;
    e.stopPropagation();
    renameRequest(req);
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

  // Marquer comme actif et sauvegarder
  state.activeCollectionId = req.id;

  // Save snapshot in localStorage for auto-sync on send
  saveCollectionSnapshot(req);
  saveBuilderState();

  // Re-render pour mettre à jour l'état actif visuel
  renderCollections();
}

// ─────────────────────────────────────────────
// COLLECTION REQUEST AUTO-SYNC (localStorage)
// ─────────────────────────────────────────────

function saveCollectionSnapshot(req) {
  const headers = req.headers || {};
  localStorage.setItem('collectionSnap', JSON.stringify({
    id: req.id,
    method: req.method || 'GET',
    url: req.url || '',
    headers: typeof headers === 'string' ? safeJsonParse(headers) || {} : headers,
    body: req.body || '',
  }));
}

async function syncCollectionRequest(current) {
  const raw = localStorage.getItem('collectionSnap');
  if (!raw) return;
  const snap = safeJsonParse(raw);
  if (!snap || !snap.id) return;

  const snapHeaders = sortKeys(snap.headers || {});
  const currHeaders = sortKeys(current.headers || {});

  const changed = (
    (current.method && current.method !== snap.method) ||
    (current.url && current.url !== snap.url) ||
    (current.headers && JSON.stringify(currHeaders) !== JSON.stringify(snapHeaders)) ||
    (current.body !== undefined && current.body !== snap.body)
  );

  if (!changed) return;

  const merged = {
    method: current.method || snap.method,
    url: current.url || snap.url,
    headers: current.headers || snap.headers,
    body: current.body !== undefined ? current.body : snap.body,
  };

  const res = await fetch(`${API.updateRequest}/${snap.id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify(merged),
  });

  if (res.ok) {
    // Mettre à jour le snapshot local
    const updatedSnap = { id: snap.id, ...merged };
    localStorage.setItem('collectionSnap', JSON.stringify(updatedSnap));

    // Rafraîchir l'arbre des collections depuis le backend
    await loadCollections();

    // Mettre à jour le champ url dans l'état builder sauvegardé
    saveBuilderState();
  }
}

function sortKeys(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const sorted = {};
  Object.keys(obj).sort().forEach(k => { sorted[k] = obj[k]; });
  return sorted;
}

// Clear snapshot when switching to non-collection request
function clearCollectionSnapshot() {
  localStorage.removeItem('collectionSnap');
}

async function createFolder(name, parentId) {
  if (!name || !name.trim()) return;

  const res = await fetch(API.createFolder, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify({ name: name.trim(), parentId }),
  });

  if (res.ok) {
    loadCollections(); // Recharger tout depuis le backend
  }
}

async function createCollectionRequest(name, folderId) {
  if (!name || !name.trim()) return;

  const res = await fetch(API.createRequest, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify({
      name: name.trim(),
      method: 'GET',
      url: '',
      folderId,
    }),
  });

  if (res.ok) {
    loadCollections(); // Recharger tout depuis le backend
  }
}

async function deleteCollectionFolder(id) {
  if (!confirm('Supprimer ce dossier et son contenu ?')) return;
  await fetch(`${API.deleteFolder}/${id}`, {
    method: 'DELETE',
    headers: { ...getAuthHeader() },
  });
  loadCollections(); // Recharger tout depuis le backend
}

async function deleteCollectionRequest(id) {
  if (!confirm('Supprimer cette requête ?')) return;
  const res = await fetch(`${API.deleteRequest}/${id}`, {
    method: 'DELETE',
    headers: { ...getAuthHeader() },
  });
  if (res.ok) {
    if (state.activeCollectionId === id) {
      state.activeCollectionId = null;
      clearCollectionSnapshot();
      saveBuilderState();
    }
    loadCollections();
  }
}

async function renameRequest(req) {
  const newName = prompt('Renommer la requête :', req.name);
  if (!newName || !newName.trim() || newName.trim() === req.name) return;

  const res = await fetch(`${API.updateRequest}/${req.id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify({ name: newName.trim() }),
  });

  if (res.ok) {
    await loadCollections();
    if (state.activeCollectionId === req.id) {
      saveCollectionSnapshot({ ...req, name: newName.trim() });
      saveBuilderState();
    }
  }
}

async function renameFolder(folder) {
  const newName = prompt('Renommer le dossier :', folder.name);
  if (!newName || !newName.trim() || newName.trim() === folder.name) return;

  const res = await fetch(`${API.updateRequest}/${folder.id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify({ name: newName.trim() }),
  });

  if (res.ok) {
    loadCollections();
  }
}

function showCreateModal(title, placeholder, callback) {
  dom.modalTitle.textContent = title;
  dom.modalInput.placeholder = placeholder;
  dom.modalInput.value = '';
  dom.btnModalOk.callback = callback;
  dom.createModal.classList.remove('hidden');
  dom.createModal.classList.add('flex');
  dom.modalInput.focus();
}

function hideCreateModal() {
  dom.createModal.classList.add('hidden');
  dom.createModal.classList.remove('flex');
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
  dom.btnRefresh.addEventListener('click', () => loadHistory(true));
}

async function loadHistory(forceRefresh = false) {
  if (state.history.length > 0 && !forceRefresh) return;

  try {
    const user = getUser();
    const userId = user ? user.userId : 'anonymous';
    const url = `${API.userHistory}/${userId}?limit=50&page=1`;
    const res = await fetch(url, { headers: { ...getAuthHeader() } });
    if (!res.ok) return;
    const rows = await res.json();
    if (!Array.isArray(rows)) return;

    rows.reverse().forEach(row => {
      const entry = {
        id: row.request_id,
        method: row.request_method,
        url: row.request_url,
        statusCode: row.request_status_code,
        reqHeaders: safeJsonParse(row.request_headers) || {},
        reqBody: row.request_body || '',
        reqParams: [],
        headers: safeJsonParse(row.response_headers) || {},
        body: row.response_body || '',
        type: 'structured',
        date: row.date || null,
        isDoneByAI: row.is_done_by_ai === 1 || row.is_done_by_ai === true,
        timestamp: row.date ? new Date(row.date).getTime() : Date.now(),
      };
      // Avoid duplicates
      if (!state.history.find(h => h.id === entry.id)) {
        state.history.push(entry);
      }
    });

    state.history.sort((a, b) => b.timestamp - a.timestamp);
    renderHistory();
  } catch { }
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
    const dateDisplay = formatDate(entry.date || entry.timestamp);
    const aiBadge = entry.isDoneByAI
      ? `<span class="ai-badge" title="Généré par IA"><svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg></span>`
      : '';

    item.innerHTML = `
      <span class="method-badge ${methodLower}">${entry.method}</span>
      <div class="flex-1 min-w-0">
        <div class="text-xs text-gray-300 truncate font-['JetBrains_Mono'] leading-tight">${escapeHtml(urlShort)}</div>
        <div class="flex items-center gap-2 mt-0.5">
          <span class="text-[10px] font-mono font-semibold ${statusClass === 's2xx' ? 'text-green-400/70' : statusClass === 's4xx' ? 'text-orange-400/70' : statusClass === 's5xx' ? 'text-red-400/70' : 'text-blue-400/70'}">${statusCode}</span>
          <span class="text-[10px] text-gray-600">${dateDisplay}</span>
          ${aiBadge}
        </div>
      </div>
    `;

    item.addEventListener('click', () => loadHistoryEntry(entry));
    dom.historyList.insertBefore(item, dom.historyEmpty);
  });
}

async function loadHistoryEntry(entry) {
  clearCollectionSnapshot();
  state.activeCollectionId = null;
  state.currentRequestId = entry.id;
  updateChatContext();
  renderCollections();

  // Try to fetch the latest from the API
  let freshEntry = entry;
  try {
    const res = await fetch(`${API.getRequest}/${entry.id}`, {
      headers: { ...getAuthHeader() },
    });
    if (res.ok) {
      const row = await res.json();
      freshEntry = {
        ...entry,
        id: row.request_id || entry.id,
        method: row.request_method || entry.method,
        url: row.request_url || entry.url,
        statusCode: row.request_status_code || entry.statusCode,
        reqHeaders: safeJsonParse(row.request_headers) || entry.reqHeaders,
        reqBody: row.request_body || entry.reqBody,
        headers: safeJsonParse(row.response_headers) || entry.headers,
        body: row.response_body || entry.body,
        date: row.date || entry.date,
        isDoneByAI: row.is_done_by_ai === 1 || row.is_done_by_ai === true,
        timestamp: row.date ? new Date(row.date).getTime() : entry.timestamp,
      };
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
  dom.btnClearChat.addEventListener('click', clearChatHistory);
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

function clearChatHistory() {
  // Clear all messages
  dom.chatMessages.innerHTML = '';

  // Reset conversation ID
  state.conversation_id = null;

  // Add initial welcome message
  const initialMessage = document.createElement('div');
  initialMessage.className = 'flex gap-3';
  initialMessage.innerHTML = `
    <div class="w-7 h-7 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">
      <svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>
    </div>
    <div class="bg-base-700/50 rounded-xl rounded-tl-md px-4 py-3 text-xs text-gray-300 leading-relaxed max-w-[280px]">
      Bonjour ! Je suis votre assistant API. Posez-moi des questions sur vos requêtes ou demandez-moi de l'aide pour débugger vos appels.
    </div>
  `;
  dom.chatMessages.appendChild(initialMessage);

  // Update context
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
    conversationId: state.conversation_id || null,
  };

  try {
    const res = await fetch(API.chat, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    state.conversation_id = data.conversation_id; 
    removeChatLoading();
    addChatMessage(data.response.content, 'ai');
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
// DOCUMENT UPLOAD MODAL
// ─────────────────────────────────────────────
let selectedDocFile = null;

function setupDocModal() {
  // Open modal
  dom.btnOpenDocs.addEventListener('click', openDocModal);

  // Close buttons
  dom.btnDocModalClose.addEventListener('click', closeDocModal);
  dom.btnDocModalCancel.addEventListener('click', closeDocModal);

  // Click outside to close
  dom.docModal.addEventListener('click', (e) => {
    if (e.target === dom.docModal) closeDocModal();
  });

  // File input change
  dom.docFileInput.addEventListener('change', () => {
    const file = dom.docFileInput.files[0];
    if (file) setDocFile(file);
  });

  // Drag & drop
  dom.docDropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dom.docDropZone.classList.add('border-emerald-500/50', 'bg-emerald-500/[0.04]');
  });

  dom.docDropZone.addEventListener('dragleave', () => {
    dom.docDropZone.classList.remove('border-emerald-500/50', 'bg-emerald-500/[0.04]');
  });

  dom.docDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dom.docDropZone.classList.remove('border-emerald-500/50', 'bg-emerald-500/[0.04]');
    const file = e.dataTransfer.files[0];
    if (file) setDocFile(file);
  });

  // Upload button
  dom.btnDocModalUpload.addEventListener('click', uploadDocument);

  // Escape key to close
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !dom.docModal.classList.contains('hidden')) {
      closeDocModal();
    }
  });
}

function openDocModal() {
  resetDocModal();
  dom.docModal.classList.remove('hidden');
  dom.docModal.classList.add('flex');
}

function closeDocModal() {
  dom.docModal.classList.add('hidden');
  dom.docModal.classList.remove('flex');
  resetDocModal();
}

function resetDocModal() {
  selectedDocFile = null;
  dom.docFileInput.value = '';
  dom.docDropContent.classList.remove('hidden');
  dom.docFileSelected.classList.add('hidden');
  dom.docFileName.textContent = '';
  dom.docFileSize.textContent = '';
  dom.docMsg.classList.add('hidden');
  dom.docMsg.innerHTML = '';
  dom.btnDocModalUpload.disabled = true;
  dom.docDropZone.classList.remove('border-emerald-500/30');
}

function setDocFile(file) {
  const validExts = ['.json', '.yaml', '.yml'];
  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!validExts.includes(ext)) {
    showDocMsg(`Format non supporté. Formats acceptés : ${validExts.join(', ')}`, 'error');
    return;
  }

  selectedDocFile = file;
  dom.docDropContent.classList.add('hidden');
  dom.docFileSelected.classList.remove('hidden');
  dom.docFileName.textContent = file.name;
  dom.docFileSize.textContent = formatFileSize(file.size);
  dom.docMsg.classList.add('hidden');
  dom.btnDocModalUpload.disabled = false;
  dom.docDropZone.classList.add('border-emerald-500/30');
}

async function uploadDocument() {
  if (!selectedDocFile) return;

  dom.btnDocModalUpload.disabled = true;
  dom.btnDocModalUpload.innerHTML = `
    <svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182"/></svg>
    Importation…
  `;

  try {
    const formData = new FormData();
    formData.append('file', selectedDocFile);

    const res = await fetch(API.uploadOpenAPI, {
      method: 'POST',
      headers: { ...getAuthHeader() },
      body: formData,
    });

    if (res.ok) {
      const data = await res.json();
      showDocMsg(`Spécification importée avec succès — ${data.collection_name || 'collection créée'}`, 'success');
      loadCollections();
      // Reset file selection but keep modal open for another upload
      selectedDocFile = null;
      dom.docFileInput.value = '';
      dom.docDropContent.classList.remove('hidden');
      dom.docFileSelected.classList.add('hidden');
    } else {
      const errData = await res.json().catch(() => ({}));
      showDocMsg(errData.detail || `Erreur ${res.status} lors de l'importation`, 'error');
    }
  } catch (err) {
    showDocMsg(`Erreur réseau : ${err.message}`, 'error');
  } finally {
    dom.btnDocModalUpload.disabled = false;
    dom.btnDocModalUpload.innerHTML = `
      <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 16.5V9.75m0 0l3 3m-3-3l-3 3M6.75 19.5a4.5 4.5 0 01-1.41-8.775 5.25 5.25 0 0110.233-2.33 3 3 0 013.758 3.848A3.752 3.752 0 0118 19.5H6.75z"/></svg>
      Importer
    `;
  }
}

function showDocMsg(message, type) {
  dom.docMsg.classList.remove('hidden');
  const colors = type === 'error'
    ? 'bg-red-500/10 border-red-500/20 text-red-400'
    : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400';
  dom.docMsg.className = `mt-3 p-3 rounded-lg border text-xs ${colors}`;
  dom.docMsg.textContent = message;
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' o';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' Ko';
  return (bytes / (1024 * 1024)).toFixed(1) + ' Mo';
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

function formatDate(dateOrTs) {
  if (!dateOrTs) return '';
  const d = typeof dateOrTs === 'string' ? new Date(dateOrTs) : new Date(dateOrTs);
  if (isNaN(d.getTime())) return '';
  const now = new Date();
  const diff = now - d;
  const secs = Math.floor(diff / 1000);

  if (secs < 5) return 'maintenant';
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}min`;
  if (secs < 86400) {
    return d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit' });
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

function safeJsonParse(str) {
  if (!str) return null;
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
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
init();
