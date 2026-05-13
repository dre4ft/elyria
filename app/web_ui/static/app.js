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
  statusFilter: '',
  chatOpen: false,
  collections: [],             // tree: [{ id, name, type:'folder', children:[], expanded }, { id, name, type:'request', method, url }]
  activeCollectionId: null,   // ID de la requête de collection actuellement chargée
};

// ─────────────────────────────────────────────
// BUILDER STATE PERSISTENCE (DB)
// ─────────────────────────────────────────────
function getCurrentBuilderState() {
  return {
    method: dom.reqMethod.value,
    url: dom.reqUrl.value,
    body: dom.reqBody.value,
    headers: getHeaders(),
  };
}

async function saveCurrentRequestToDb() {
  if (!state.activeCollectionId) {
    console.log('[save] skipped: no activeCollectionId');
    return;
  }
  const data = getCurrentBuilderState();
  console.log('[save] PUT', state.activeCollectionId, data);
  try {
    const res = await fetch(`${API.updateRequest}/${state.activeCollectionId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.text();
      console.error('[save] failed:', res.status, err);
    } else {
      console.log('[save] ok');
      await loadCollections();
    }
  } catch (e) {
    console.error('[save] error:', e);
  }
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

  // Sidebar — collections
  collectionsTree:  $('#collections-tree'),
  collectionsEmpty: $('#collections-empty'),
  searchCollections: $('#search-collections'),
  btnNewFolder:     $('#btn-new-folder'),
  btnNewRequest:    $('#btn-new-request'),
  btnRefreshCol:    $('#btn-refresh-collections'),
  btnCreateFirst:   $('#btn-create-first-collection'),

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

  initHeaderUser();

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
  setupJWTPanel();
  setupKeyboardShortcuts();

  // Burger menu sidebar toggle
  const btnSidebar = document.getElementById('btn-toggle-sidebar');
  if (btnSidebar) btnSidebar.addEventListener('click', toggleSidebar);

  // Initialiser le builder avec des rows vides
  addParamRow('', '', true);
  addHeaderRow('', '', true);
  syncContentTypeHeader();

  // Sauvegarder la requête en cours dans la DB avant de quitter la page
  window.addEventListener('beforeunload', () => {
    if (!state.activeCollectionId) return;
    const data = getCurrentBuilderState();
    fetch(`${API.updateRequest}/${state.activeCollectionId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(data),
      keepalive: true,
    });
  });

  // Load collections
  loadCollections();

  // Load user's past requests from backend
  loadHistory();
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
let autoContentTypeRow = null;

function setupHeaders() {
  dom.btnAddHeader.addEventListener('click', () => addHeaderRow('', '', true));

  // Sync auto Content-Type header when body content type changes
  dom.bodyContentType.addEventListener('change', syncContentTypeHeader);

  // When user edits the auto Content-Type header value, update the dropdown
  dom.headersList.addEventListener('input', (e) => {
    const row = e.target.closest('.header-row');
    if (!row || !row.classList.contains('header-row-auto')) return;
    const inputs = row.querySelectorAll('input');
    const val = inputs[1].value.trim();
    const ctMap = {
      'application/json': 'application/json',
      'text/plain': 'text/plain',
      'application/xml': 'application/xml',
      'application/x-www-form-urlencoded': 'application/x-www-form-urlencoded',
    };
    if (ctMap[val]) {
      dom.bodyContentType.value = val;
    }
  });
}

function addHeaderRow(key = '', value = '', enabled = true) {
  const row = document.createElement('div');
  row.className = 'header-row' + (enabled ? '' : ' is-disabled');
  row.innerHTML = `
    <button class="btn-toggle-header ${enabled ? 'enabled' : 'disabled'}" title="Activer/Désactiver">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
    </button>
    <input type="text" placeholder="Header name" value="${escapeHtml(key)}" class="flex-1" />
    <input type="text" placeholder="Value" value="${escapeHtml(value)}" class="flex-[2]" />
    <button class="btn-remove-header" title="Supprimer">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  `;

  const toggleBtn = row.querySelector('.btn-toggle-header');
  toggleBtn.addEventListener('click', () => {
    const isEnabled = toggleBtn.classList.contains('enabled');
    toggleBtn.classList.toggle('enabled', !isEnabled);
    toggleBtn.classList.toggle('disabled', isEnabled);
    row.classList.toggle('is-disabled', isEnabled);
  });

  row.querySelector('.btn-remove-header').addEventListener('click', () => {
    if (row === autoContentTypeRow) {
      // Auto row removed by user: mark it as removed, will be recreated on next sync
      autoContentTypeRow = null;
    }
    row.remove();
  });

  dom.headersList.appendChild(row);
  return row;
}

function getHeaders() {
  const headers = {};
  dom.headersList.querySelectorAll('.header-row').forEach(row => {
    const toggleBtn = row.querySelector('.btn-toggle-header');
    const enabled = toggleBtn ? toggleBtn.classList.contains('enabled') : true;
    if (!enabled) return;
    const inputs = row.querySelectorAll('input');
    const k = inputs[0].value.trim();
    const v = inputs[1].value.trim();
    if (k) headers[k] = v;
  });
  return headers;
}

function clearHeaders() {
  autoContentTypeRow = null;
  dom.headersList.innerHTML = '';
}

function syncContentTypeHeader() {
  const ct = dom.bodyContentType.value;

  // Remove any existing Content-Type header rows (auto or manual)
  dom.headersList.querySelectorAll('.header-row').forEach(r => {
    const keyInput = r.querySelectorAll('input')[0];
    if (keyInput.value.trim().toLowerCase() === 'content-type') {
      if (r === autoContentTypeRow) autoContentTypeRow = null;
      r.remove();
    }
  });

  // Create new auto header row
  autoContentTypeRow = addHeaderRow('Content-Type', ct, true);
  autoContentTypeRow.classList.add('header-row-auto');
  const keyInput = autoContentTypeRow.querySelectorAll('input')[0];
  keyInput.readOnly = true;
  keyInput.classList.add('opacity-60', 'cursor-default');
}

// ─────────────────────────────────────────────
// SEND REQUESTS
// ─────────────────────────────────────────────
function populateStructuredFromParsed(method, url, headers, body) {
  dom.reqMethod.value = method;
  dom.reqUrl.value = url;
  dom.reqBody.value = body || '';

  clearHeaders();
  const headerEntries = Object.entries(headers || {});
  if (headerEntries.length === 0) {
    addHeaderRow('', '', true);
  } else {
    headerEntries.forEach(([k, v]) => addHeaderRow(k, v, true));
  }

  // Sync Content-Type header if body has content
  const ctKey = Object.keys(headers || {}).find(k => k.toLowerCase() === 'content-type');
  if (ctKey && headers[ctKey]) {
    const ctVal = headers[ctKey].split(';')[0].trim();
    const knownCT = ['application/json', 'text/plain', 'application/xml', 'application/x-www-form-urlencoded'];
    if (knownCT.includes(ctVal)) dom.bodyContentType.value = ctVal;
  }

  clearParams();
  try {
    const urlObj = new URL(url);
    let count = 0;
    urlObj.searchParams.forEach((v, k) => {
      addParamRow(k, v, true);
      count++;
    });
    if (count === 0) addParamRow('', '', true);
  } catch {
    addParamRow('', '', true);
  }

  syncContentTypeHeader();
}

// ─────────────────────────────────────────────
function setupSend() {
  dom.btnSendStruct.addEventListener('click', sendStructured);
  dom.btnSendRaw.addEventListener('click', sendRaw);
  const btnCurl = $('#btn-export-curl');
  if (btnCurl) btnCurl.addEventListener('click', () => exportAsCurl());
  const btnCopyCurl = $('#btn-copy-curl');
  if (btnCopyCurl) btnCopyCurl.addEventListener('click', () => {
    const curl = $('#curl-content')?.textContent;
    if (curl) { navigator.clipboard.writeText(curl); btnCopyCurl.textContent = 'Copie !'; setTimeout(()=>btnCopyCurl.textContent='Copier', 1500); }
  });
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
    _notifyRequestComplete(entry);
    displayResponse(entry, elapsed);

    // Sync collection request if anything changed
    saveCurrentRequestToDb();
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

    // Parse raw request to extract structured info
    const parsed = parseRawHttp(request);
    const method = parsed.method || 'GET';
    // Build full URL from base URL + parsed path
    let fullUrl = url;
    try {
      const urlObj = new URL(url);
      fullUrl = urlObj.origin + parsed.path;
    } catch {
      // If URL parsing fails, concatenate simply
      if (!url.endsWith('/') && !parsed.path.startsWith('/')) fullUrl += '/';
      fullUrl = url.replace(/\/$/, '') + parsed.path;
    }

    const entry = {
      id: data.request_uuid || generateId(),
      method,
      url: fullUrl,
      statusCode: responseData.status_code,
      headers: responseData.headers || {},
      body: responseData.body || '',
      type: 'raw',
      rawRequest: request,
      reqHeaders: parsed.headers,
      reqBody: parsed.body,
      reqParams: [],
      timestamp: Date.now(),
    };
    _notifyRequestComplete(entry);
    displayResponse(entry, elapsed);

    // Switch to structured tab and populate with parsed info
    dom.tabBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.tab === 'structured');
    });
    dom.tabPanels.forEach(p => {
      p.classList.toggle('hidden', p.id !== 'tab-structured');
      p.classList.toggle('active', p.id === 'tab-structured');
    });
    populateStructuredFromParsed(method, fullUrl, parsed.headers, parsed.body);

    saveCurrentRequestToDb();
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

  // JWT detection
  renderJWTParser(bodyContent);

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
  loadTeamFilterSelect();
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

  // ── cURL Compiler Modal ──
  const curlModal = $('#curl-modal');
  const curlInput = $('#curl-input');
  const curlName = $('#curl-name');
  const curlPreview = $('#curl-preview');
  const curlError = $('#curl-error');
  const curlSuccess = $('#curl-success');

  if ($('#btn-open-curl')) {
    $('#btn-open-curl').addEventListener('click', () => {
      curlModal.classList.remove('hidden');
      curlModal.classList.add('flex');
      curlInput.value = '';
      curlName.value = '';
      curlPreview.classList.add('hidden');
      curlError.classList.add('hidden');
      curlSuccess.classList.add('hidden');
      curlInput.focus();
    });
  }

  if ($('#btn-curl-close')) {
    $('#btn-curl-close').addEventListener('click', () => {
      curlModal.classList.add('hidden');
      curlModal.classList.remove('flex');
    });
  }

  // Close on backdrop click
  curlModal.addEventListener('click', (e) => { if (e.target === curlModal) { curlModal.classList.add('hidden'); curlModal.classList.remove('flex'); } });

  if ($('#btn-curl-compile')) {
    $('#btn-curl-compile').addEventListener('click', async () => {
      const curlCmd = curlInput.value.trim();
      if (!curlCmd) { curlError.textContent = 'Collez une commande cURL'; curlError.classList.remove('hidden'); return; }
      curlError.classList.add('hidden');
      curlSuccess.classList.add('hidden');
      try {
        const res = await fetch('/api/collections/compile-curl', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
          body: JSON.stringify({ curl: curlCmd, name: curlName.value.trim() || '' }),
        });
        const data = await res.json();
        if (!res.ok) { curlError.textContent = data.detail || 'Erreur de compilation'; curlError.classList.remove('hidden'); return; }
        // Show preview
        curlPreview.classList.remove('hidden');
        $('#curl-preview-method').innerHTML = `<span class="text-accent-light">${esc(data.parsed.method)}</span>`;
        $('#curl-preview-url').textContent = data.parsed.url;
        $('#curl-preview-headers').textContent = data.parsed.headers && Object.keys(data.parsed.headers).length ? 'Headers: ' + JSON.stringify(data.parsed.headers) : '';
        $('#curl-preview-body').textContent = data.parsed.body ? 'Body: ' + data.parsed.body.substring(0, 200) : '';
        curlSuccess.textContent = 'Requête sauvegardée : ' + data.name;
        curlSuccess.classList.remove('hidden');
        // Refresh collections
        setTimeout(() => { loadCollections(); curlModal.classList.add('hidden'); curlModal.classList.remove('flex'); }, 800);
      } catch (e) {
        curlError.textContent = 'Erreur réseau : ' + e.message;
        curlError.classList.remove('hidden');
      }
    });
  }

  // Escape to close
  curlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { curlModal.classList.add('hidden'); curlModal.classList.remove('flex'); }
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
    const qs = currentTeamFilter && currentTeamFilter !== '__personal__' ? `?team_id=${currentTeamFilter}` : (currentTeamFilter === '__personal__' ? '?team_id=__personal__' : '');
    const res = await fetch(API.collections + qs, { headers: { ...getAuthHeader() } });
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

async function loadCollectionRequest(req) {
  // Save current request to DB before switching
  await saveCurrentRequestToDb();

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
  // Peek Content-Type from loaded headers to set body content type dropdown
  const ctKey = Object.keys(reqHeaders).find(k => k.toLowerCase() === 'content-type');
  if (ctKey && reqHeaders[ctKey]) {
    const ctVal = reqHeaders[ctKey].split(';')[0].trim();
    const knownCT = ['application/json', 'text/plain', 'application/xml', 'application/x-www-form-urlencoded'];
    if (knownCT.includes(ctVal)) dom.bodyContentType.value = ctVal;
  }
  const otherHeaders = Object.entries(reqHeaders).filter(([k]) => k.toLowerCase() !== 'content-type');
  if (otherHeaders.length === 0) {
    addHeaderRow('', '', true);
  } else {
    otherHeaders.forEach(([k, v]) => addHeaderRow(k, v, true));
  }
  syncContentTypeHeader();

  // Marquer comme actif
  state.activeCollectionId = req.id;

  // Re-render pour mettre à jour l'état actif visuel
  renderCollections();
}

// ─────────────────────────────────────────────
// COLLECTION REQUEST AUTO-SYNC (localStorage)
async function createFolder(name, parentId) {
  if (!name || !name.trim()) return;
  const teamId = ($('#modal-team')||{}).value || '';

  const res = await fetch(API.createFolder, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify({ name: name.trim(), parentId, team_id: teamId }),
  });

  if (res.ok) {
    loadCollections(); // Recharger tout depuis le backend
  }
}

async function createCollectionRequest(name, folderId) {
  if (!name || !name.trim()) return;
  const teamId = ($('#modal-team')||{}).value || '';

  const res = await fetch(API.createRequest, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify({
      name: name.trim(), method: 'GET', url: '',
      folderId, team_id: teamId,
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

async function showCreateModal(title, placeholder, callback) {
  dom.modalTitle.textContent = title;
  dom.modalInput.placeholder = placeholder;
  dom.modalInput.value = '';
  dom.btnModalOk.callback = callback;
  // Populate team dropdown
  const teamSel = $('#modal-team');
  if(teamSel) { teamSel.innerHTML = '<option value="">Personnel</option>';
    try {
      const r = await fetch('/api/teams', {headers:{...getAuthHeader()}});
      const teams = r.ok ? await r.json() : [];
      teams.forEach(t => { teamSel.innerHTML += `<option value="${t.team_id}">${escapeHtml(t.name)}</option>`; });
    } catch {} }
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
// REQUEST WATCHER — event-driven, no polling
// ─────────────────────────────────────────────
const _reqWatchers = [];
function onRequestComplete(fn) { _reqWatchers.push(fn); }
function _notifyRequestComplete(entry) { _reqWatchers.forEach(fn => { try { fn(entry); } catch {} }); }

// ─────────────────────────────────────────────
// HISTORY
// ─────────────────────────────────────────────
function setupHistory() {
  const historyPanel = $('#history-panel');
  const btnToggle = $('#btn-toggle-history');
  const btnClose = $('#btn-close-history');
  const btnClear = $('#btn-clear-history');
  const searchInput = $('#history-search');

  if (!historyPanel) return;

  btnToggle.addEventListener('click', () => toggleHistoryPanel());
  btnClose.addEventListener('click', () => toggleHistoryPanel(false));
  btnClear.addEventListener('click', () => { state.history = []; renderHistoryLog(); });
  searchInput.addEventListener('input', () => renderHistoryLog());

  // Status code filter buttons
  const filterBtns = document.querySelectorAll('#history-status-filter button');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => { b.className = 'h-5 px-2 rounded text-[9px] font-medium text-gray-500 border border-transparent transition-all'; });
      const sc = btn.dataset.sc;
      const active = 'h-5 px-2 rounded text-[9px] font-semibold border transition-all';
      if (sc === '2') btn.className = active + ' bg-green-500/15 text-green-400 border-green-500/20';
      else if (sc === '3') btn.className = active + ' bg-white/5 text-gray-300 border-white/10';
      else if (sc === '4') btn.className = active + ' bg-orange-500/15 text-orange-400 border-orange-500/20';
      else if (sc === '5') btn.className = active + ' bg-red-500/15 text-red-400 border-red-500/20';
      else btn.className = active + ' bg-amber-500/15 text-amber-400 border-amber-500/20';
      state.statusFilter = sc;
      renderHistoryLog();
    });
  });

  // Watch all completed requests — update history in real time
  onRequestComplete((entry) => {
    state.history = state.history.filter(h => h.id !== entry.id);
    state.history.unshift(entry);
    renderHistoryLog();
  });
}

function toggleHistoryPanel(show) {
  const panel = $('#history-panel');
  if (!panel) return;
  const open = typeof show === 'boolean' ? show : panel.classList.contains('hidden');
  panel.classList.toggle('hidden', !open);
  panel.classList.toggle('flex', open);
  if (open) { loadHistory(true); }
}

async function loadHistory(forceRefresh) {
  if (state.history.length > 0 && !forceRefresh) return;
  try {
    const user = getUser();
    const userId = user ? user.userId : 'anonymous';
    const url = `${API.userHistory}/${userId}?limit=100&page=1`;
    const res = await fetch(url, { headers: { ...getAuthHeader() } });
    if (!res.ok) return;
    const rows = await res.json();
    if (!Array.isArray(rows)) return;
    rows.reverse().forEach(row => {
      const entry = {
        id: row.request_id, method: row.request_method, url: row.request_url,
        statusCode: row.request_status_code,
        reqHeaders: safeJsonParse(row.request_headers) || {},
        reqBody: row.request_body || '', reqParams: [],
        headers: safeJsonParse(row.response_headers) || {},
        body: row.response_body || '', type: 'structured',
        date: row.date || null,
        isDoneByAI: row.is_done_by_ai === 1 || row.is_done_by_ai === true,
        timestamp: row.date ? new Date(row.date).getTime() : Date.now(),
      };
      if (!state.history.find(h => h.id === entry.id)) state.history.push(entry);
    });
    state.history.sort((a, b) => b.timestamp - a.timestamp);
    renderHistoryLog();
  } catch {}
}

function renderHistoryLog() {
  const logList = $('#history-log-list');
  const emptyState = $('#history-empty-state');
  const countBadge = $('#history-count-badge');
  const searchInput = $('#history-search');
  if (!logList) return;

  const query = (searchInput ? searchInput.value : '').toLowerCase().trim();
  const scFilter = state.statusFilter || '';
  let filtered = state.history;
  if (query) {
    filtered = filtered.filter(h => (h.url||'').toLowerCase().includes(query) || (h.method||'').toLowerCase().includes(query));
  }
  if (scFilter) {
    const prefix = parseInt(scFilter, 10);
    filtered = filtered.filter(h => {
      const sc = h.statusCode || 0;
      return sc >= prefix * 100 && sc < (prefix + 1) * 100;
    });
  }

  // Remove old rows (keep empty state)
  logList.querySelectorAll('.history-log-row,.history-quick-view').forEach(e => e.remove());
  if (emptyState) emptyState.classList.toggle('hidden', filtered.length > 0);
  if (countBadge) { countBadge.textContent = state.history.length; countBadge.classList.toggle('hidden', state.history.length === 0); }

  filtered.forEach(entry => {
    const sc = entry.statusCode || 0;
    const scC = sc >= 500 ? 'text-red-400' : sc >= 400 ? 'text-orange-400' : sc >= 200 ? 'text-green-400' : 'text-gray-500';
    const mC = {GET:'text-green-400',POST:'text-blue-400',PUT:'text-orange-400',DELETE:'text-red-400',PATCH:'text-purple-400'}[entry.method] || 'text-gray-400';
    const path = (entry.url || '').replace(/^https?:\/\/[^/]+/, '') || '/';
    const time = entry.date ? entry.date.substring(11, 19) : '--:--:--';
    const aiBadge = entry.isDoneByAI
      ? `<span class="hl-ai" title="Requete envoyee par l'agent IA"><span class="px-1 py-0.5 rounded-full bg-purple-500/15 border border-purple-500/20 text-[7px] text-purple-400 font-bold">IA</span></span>`
      : '<span class="hl-ai"></span>';

    const row = document.createElement('div');
    row.className = 'history-log-row';
    row.dataset.hid = entry.id;
    row.innerHTML = `<span class="hl-method ${mC}">${entry.method}</span>
      <span class="hl-status ${scC}">${sc || '—'}</span>
      <span class="hl-path" title="${escapeHtml(entry.url||'')}">${escapeHtml(path)}</span>
      <span class="hl-time">${time}</span>
      ${aiBadge}
      <svg class="hl-chevron" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>`;
    row.addEventListener('click', () => toggleHistoryQuickView(row, entry));
    logList.appendChild(row);

    // Quick-view placeholder (hidden, shown on expand)
    const qv = document.createElement('div');
    qv.className = 'history-quick-view';
    qv.dataset.hidQv = entry.id;
    qv.innerHTML = buildQuickViewHTML(entry);
    logList.appendChild(qv);
    // Setup quick-view buttons after DOM insertion
    setTimeout(() => setupQuickViewButtons(qv, entry), 0);
  });
}

function buildQuickViewHTML(entry) {
  const reqHeadersStr = entry.reqHeaders ? Object.entries(entry.reqHeaders).map(([k,v]) => `${k}: ${v}`).join('\n') : '';
  const reqBodyStr = entry.reqBody || '';
  const respBody = entry.body || '';
  let respBodyFormatted = respBody;
  try { const p = JSON.parse(respBody); respBodyFormatted = JSON.stringify(p, null, 2); } catch {}
  const respHeadersStr = entry.headers ? Object.entries(entry.headers).map(([k,v]) => `${k}: ${v}`).join('\n') : '';
  const sc = entry.statusCode || 0;
  const scC = sc >= 500 ? 'text-red-400' : sc >= 400 ? 'text-orange-400' : sc >= 200 ? 'text-green-400' : 'text-gray-500';
  const qvId = 'qv-' + (entry.id || Math.random().toString(36).slice(2));

  return `<div class="qv-toolbar flex items-center gap-2 mb-3">
    <span class="text-[10px] uppercase text-gray-500 font-semibold">Details</span>
    <div class="flex-1"></div>
    <button class="qv-load-btn h-6 px-3 rounded-md bg-accent/10 hover:bg-accent/20 border border-accent/20 hover:border-accent/40 text-[10px] font-medium text-accent-light transition-all flex items-center gap-1">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>
      Load
    </button>
    <button class="qv-send-btn h-6 px-3 rounded-md bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/20 hover:border-amber-500/40 text-[10px] font-medium text-amber-400 transition-all flex items-center gap-1">
      <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"/></svg>
      Replay
    </button>
  </div>
  <div class="flex border-b border-white/5 mb-2">
    <button class="qv-tab active flex-1 h-7 text-[10px] font-semibold text-gray-400 transition-all" data-qvtab="${qvId}-req" onclick="switchQVTab('${qvId}','req')">Requete</button>
    <button class="qv-tab flex-1 h-7 text-[10px] font-semibold text-gray-500 transition-all" data-qvtab="${qvId}-resp" onclick="switchQVTab('${qvId}','resp')">Reponse</button>
  </div>
  <div id="${qvId}-req" class="qv-panel space-y-2">
    <div><span class="text-[9px] uppercase text-gray-500 font-semibold">URL</span><div class="text-[11px] text-gray-300 font-mono mt-0.5 break-all">${escapeHtml(entry.method)} ${escapeHtml(entry.url||'')}</div></div>
    ${reqHeadersStr ? `<div><span class="text-[9px] uppercase text-gray-500 font-semibold">Headers</span><pre class="text-[10px] text-gray-400 font-mono mt-0.5 bg-base-900/40 p-2 rounded max-h-24 overflow-y-auto">${escapeHtml(reqHeadersStr)}</pre></div>` : ''}
    ${reqBodyStr ? `<div><span class="text-[9px] uppercase text-gray-500 font-semibold">Body</span><pre class="text-[10px] text-gray-300 font-mono mt-0.5 bg-base-900/40 p-2 rounded max-h-32 overflow-y-auto">${escapeHtml(reqBodyStr)}</pre></div>` : ''}
  </div>
  <div id="${qvId}-resp" class="qv-panel hidden space-y-2">
    <div><span class="text-[9px] uppercase text-gray-500 font-semibold">Status</span><div class="text-[11px] font-mono font-bold ${scC} mt-0.5">${sc || '—'}</div></div>
    ${respHeadersStr ? `<div><span class="text-[9px] uppercase text-gray-500 font-semibold">Headers</span><pre class="text-[10px] text-gray-400 font-mono mt-0.5 bg-base-900/40 p-2 rounded max-h-24 overflow-y-auto">${escapeHtml(respHeadersStr)}</pre></div>` : ''}
    ${respBody ? `<div><span class="text-[9px] uppercase text-gray-500 font-semibold">Body</span><pre class="text-[10px] text-gray-300 font-mono mt-0.5 bg-base-900/40 p-2 rounded max-h-48 overflow-y-auto">${escapeHtml(respBodyFormatted)}</pre></div>` : ''}
  </div>`;
}

function switchQVTab(qvId, tab) {
  const panel = document.getElementById(qvId + '-req').parentElement;
  panel.querySelectorAll('.qv-tab').forEach(b => { b.classList.toggle('active', b.dataset.qvtab === qvId + '-' + tab); });
  panel.querySelectorAll('.qv-panel').forEach(p => { p.classList.toggle('hidden', !p.id.startsWith(qvId + '-' + tab)); });
}

function setupQuickViewButtons(qvEl, entry) {
  // Load button — populate the main builder
  qvEl.querySelector('.qv-load-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    loadHistoryEntry(entry);
    // Scroll to top
    document.querySelector('.tab-panel.active')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  // Replay button — re-send the exact same request
  qvEl.querySelector('.qv-send-btn')?.addEventListener('click', async (e) => {
    e.stopPropagation();
    const url = entry.url || '';
    const method = entry.method || 'GET';
    const body = entry.reqBody || '';
    if (!url) return;

    // Build headers from stored reqHeaders
    const headers = entry.reqHeaders || {};
    const resultPanel = qvEl.querySelector('.qv-result');
    if (!resultPanel) {
      const panel = document.createElement('div');
      panel.className = 'qv-result mt-3 p-3 rounded-lg bg-base-900/60 border border-white/5 text-[10px] font-mono text-gray-300 max-h-48 overflow-y-auto';
      panel.textContent = 'Envoi...';
      qvEl.appendChild(panel);
    }
    const resultEl = qvEl.querySelector('.qv-result');
    if (resultEl) {
      resultEl.classList.remove('hidden');
      resultEl.textContent = 'Envoi...';
    }

    try {
      const res = await fetch(API.structured, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
        body: JSON.stringify({ url, method, headers, body: body || undefined }),
      });
      const data = await res.json();
      const resp = data.response || data;
      const statusCode = resp.status_code || 0;
      const respBody = resp.body || '';
      if (resultEl) resultEl.innerHTML = `<span class="${statusCode >= 400 ? 'text-red-400' : 'text-green-400'} font-bold">${statusCode}</span> — ${respBody.substring(0, 500)}`;
      _notifyRequestComplete({
        id: data.request_uuid || generateId(), method, url, statusCode,
        reqHeaders: headers, reqBody: body, reqParams: [],
        headers: resp.headers || {}, body: respBody,
        type: 'structured', timestamp: Date.now(),
      });
    } catch (err) {
      if (resultEl) resultEl.innerHTML = `<span class="text-red-400">Erreur: ${escapeHtml(err.message)}</span>`;
    }
  });
}

function toggleHistoryQuickView(row, entry) {
  const wasExpanded = row.classList.contains('expanded');
  // Collapse all
  document.querySelectorAll('.history-log-row.expanded').forEach(r => r.classList.remove('expanded'));
  if (wasExpanded) return;
  row.classList.add('expanded');
  // Scroll to quick-view
  const qv = row.nextElementSibling;
  if (qv && qv.classList.contains('history-quick-view')) {
    qv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

async function loadHistoryEntry(entry) {
  await saveCurrentRequestToDb();
  state.activeCollectionId = null;
  state.currentRequestId = entry.id;
  updateChatContext();
  renderCollections();
  let freshEntry = entry;
  try {
    const res = await fetch(`${API.getRequest}/${entry.id}`, { headers: { ...getAuthHeader() } });
    if (res.ok) {
      const row = await res.json();
      freshEntry = { ...entry, id: row.request_id || entry.id, method: row.request_method || entry.method,
        url: row.request_url || entry.url, statusCode: row.request_status_code || entry.statusCode,
        reqHeaders: safeJsonParse(row.request_headers) || entry.reqHeaders,
        reqBody: row.request_body || entry.reqBody,
        headers: safeJsonParse(row.response_headers) || entry.headers,
        body: row.response_body || entry.body,
        date: row.date || entry.date,
        isDoneByAI: row.is_done_by_ai === 1 || row.is_done_by_ai === true,
        timestamp: row.date ? new Date(row.date).getTime() : entry.timestamp };
    }
  } catch {}
  // Populate request builder
  dom.tabBtns.forEach(b => { b.classList.toggle('active', b.dataset.tab === 'structured'); });
  dom.tabPanels.forEach(p => { p.classList.toggle('hidden', p.id !== 'tab-structured'); p.classList.toggle('active', p.id === 'tab-structured'); });
  dom.reqMethod.value = freshEntry.method || 'GET';
  dom.reqUrl.value = freshEntry.url || '';
  dom.reqBody.value = freshEntry.reqBody || '';
  clearParams(); parseUrlToParams();
  if (dom.paramsList.querySelectorAll('.param-row').length === 0) addParamRow('', '', true);
  clearHeaders();
  const rh = freshEntry.reqHeaders || {};
  const other = Object.entries(rh).filter(([k]) => k.toLowerCase() !== 'content-type');
  if (other.length === 0) addHeaderRow('', '', true);
  else other.forEach(([k, v]) => addHeaderRow(k, v, true));
  syncContentTypeHeader();
  displayResponse(freshEntry, 0);
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

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const collapsed = sidebar.dataset.collapsed === 'true';
  sidebar.dataset.collapsed = collapsed ? 'false' : 'true';
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
    const content = (data.response && data.response.content) ? data.response.content : (data.content || 'Pas de reponse');
    addChatMessage(content, 'ai');
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

// ── JWT Parser (jwt.io style) ──
function renderJWTParser(bodyText) {
  const panel = document.getElementById("jwt-parser");
  if (!panel) return;
  bodyText = (bodyText||"").trim();
  const jwtMatch = bodyText.match(/^(eyJ[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+)$/);
  if (!jwtMatch && !bodyText.match(/^"?eyJ/)) { panel.classList.add("hidden"); return; }
  const token = jwtMatch ? jwtMatch[1] : bodyText.replace(/^"|"$/g, "").trim();

  if (!jwtMatch && bodyText.startsWith("{")) {
    try {
      const obj = JSON.parse(bodyText);
      const tok = obj.access_token || obj.token || obj.id_token || obj.jwt;
      if (tok && tok.match(/^eyJ/)) { renderJWTParser(tok); return; }
    } catch {}
    panel.classList.add("hidden"); return;
  }

  if (!token.match(/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/)) { panel.classList.add("hidden"); return; }

  const parts = token.split(".");
  const b64Decode = (s) => {
    try {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      return JSON.parse(atob(s));
    } catch { return null; }
  };
  const header = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);
  if (!header || !payload) { panel.classList.add("hidden"); return; }

  const alg = header.alg || "unknown";
  const isSymmetric = alg && alg.startsWith("HS");
  const escFn = (s) => { const d = document.createElement("div"); d.textContent = s||""; return d.innerHTML; };

  panel.classList.remove("hidden");
  panel.innerHTML = `<div class="p-4">
    <div class="flex items-center justify-between mb-3">
      <div class="flex items-center gap-2">
        <svg class="w-4 h-4 text-accent-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/></svg>
        <span class="text-xs font-semibold text-accent-light">JWT Decoder</span>
        <span class="text-[9px] text-gray-500 font-mono">alg: ${escFn(alg)}</span>
      </div>
      <button onclick="document.getElementById(\'jwt-parser\').classList.add(\'hidden\')" class="w-5 h-5 rounded hover:bg-white/5 flex items-center justify-center text-gray-500 hover:text-gray-300"><svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg></button>
    </div>
    <div class="grid grid-cols-2 gap-3">
      <div><div class="text-[9px] uppercase text-gray-500 font-semibold mb-1">Header</div><pre class="text-[11px] text-pink-400 font-mono bg-base-900/60 p-3 rounded-lg overflow-x-auto max-h-32">${escFn(JSON.stringify(header,null,2))}</pre></div>
      <div><div class="text-[9px] uppercase text-gray-500 font-semibold mb-1">Payload</div><pre class="text-[11px] text-purple-400 font-mono bg-base-900/60 p-3 rounded-lg overflow-x-auto max-h-48">${escFn(JSON.stringify(payload,null,2))}</pre></div>
    </div>
    ${isSymmetric ? `<div class="mt-3 flex gap-2 items-end"><div class="flex-1"><label class="text-[9px] uppercase text-gray-500 font-semibold mb-1 block">Cle secrete (${escFn(alg)})</label><input id="jwt-secret-key" type="text" class="input input-mono w-full" placeholder="votre-cle-secrete" oninput="verifyJWTSig()" /></div><div id="jwt-verify-result" class="text-[10px] font-mono pb-1.5"></div></div>` : ""}
  </div>`;

  if (isSymmetric) {
    window._jwtToken = token;
    window.verifyJWTSig = async function() {
      const key = document.getElementById("jwt-secret-key")?.value;
      const result = document.getElementById("jwt-verify-result");
      if (!key) { result.innerHTML = ""; return; }
      try {
        const enc = new TextEncoder();
        const keyData = await crypto.subtle.importKey("raw", enc.encode(key), {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]);
        const sigPart = window._jwtToken.split(".")[2];
        const sigBytes = Uint8Array.from(atob(sigPart.replace(/-/g,"+").replace(/_/g,"/")), c=>c.charCodeAt(0));
        const dataToSign = window._jwtToken.split(".").slice(0,2).join(".");
        const valid = await crypto.subtle.verify("HMAC", keyData, sigBytes, enc.encode(dataToSign));
        result.innerHTML = valid ? "<span class=\"text-green-400\">\u2713 Signature valide</span>" : "<span class=\"text-red-400\">\u2717 Signature invalide</span>";
      } catch(e) { result.innerHTML = "<span class=\"text-gray-500\">Erreur de verification</span>"; }
    };
  }
}



// ── JWT Panel Toggle ──
let jwtPanelOpen = false;
function toggleJWTPanel(show) {
  const panel = $('#jwt-panel');
  if (!panel) return;
  jwtPanelOpen = typeof show === 'boolean' ? show : !jwtPanelOpen;
  panel.classList.toggle('hidden', !jwtPanelOpen);
  panel.classList.toggle('flex', jwtPanelOpen);
  if (jwtPanelOpen) {
    $('#jwt-input').focus();
  }
}

function setupJWTPanel() {
  const btnToggle = $('#btn-toggle-jwt');
  const btnClose = $('#btn-close-jwt');
  const input = $('#jwt-input');
  if (btnToggle) btnToggle.addEventListener('click', () => toggleJWTPanel());
  if (btnClose) btnClose.addEventListener('click', () => toggleJWTPanel(false));
  if (input) {
    input.addEventListener('input', () => {
      const token = input.value.trim();
      const output = $('#jwt-output');
      if (!output) return;
      if (!token) { output.classList.add('hidden'); return; }
      decodeJWT(token);
    });
  }
}

function decodeJWT(token) {
  const output = $('#jwt-output');
  const hdrEl = $('#jwt-header');
  const payloadEl = $('#jwt-payload');
  const sigEl = $('#jwt-signature');
  const claimsEl = $('#jwt-claims');
  const claimsContent = $('#jwt-claims-content');
  if (!output) return;

  const parts = token.split('.');
  if (parts.length !== 3) {
    output.classList.add('hidden');
    return;
  }

  const b64Decode = (s) => {
    try {
      s = s.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const decoded = atob(s);
      try { return JSON.parse(decoded); }
      catch { return decoded; }
    } catch { return null; }
  };

  const header = b64Decode(parts[0]);
  const payload = b64Decode(parts[1]);

  if (!header || !payload) {
    output.classList.add('hidden');
    return;
  }

  output.classList.remove('hidden');
  if (hdrEl) hdrEl.textContent = JSON.stringify(header, null, 2);
  if (payloadEl) payloadEl.textContent = JSON.stringify(payload, null, 2);
  if (sigEl) sigEl.textContent = parts[2].substring(0, 10) + '...';

  // Claims table
  const importantClaims = ['sub','iss','aud','exp','iat','nbf','jti','role','scope','permissions','email','name'];
  const claims = [];
  importantClaims.forEach(k => {
    if (payload[k] !== undefined) {
      let v = payload[k];
      if (k === 'exp' || k === 'iat' || k === 'nbf') {
        v = new Date(v * 1000).toISOString() + ' (' + (Date.now()/1000 > payload[k] ? 'expire' : 'valide') + ')';
      }
      claims.push(`${k}: ${v}`);
    }
  });
  // Add any other claims not in the important list
  Object.keys(payload).forEach(k => {
    if (!importantClaims.includes(k)) claims.push(`${k}: ${payload[k]}`);
  });

  if (claimsEl && claimsContent) {
    if (claims.length) {
      claimsEl.classList.remove('hidden');
      claimsContent.textContent = claims.join('\n');
    } else {
      claimsEl.classList.add('hidden');
    }
  }
}

// ── cURL Export ──
function exportAsCurl() {
  const display = document.getElementById("curl-display");
  const pre = document.getElementById("curl-content");
  if (!display || !pre) return;

  // Toggle: if already visible, hide it
  if (!display.classList.contains("hidden")) {
    display.classList.add("hidden");
    return;
  }

  const method = dom.reqMethod.value;
  const url = dom.reqUrl.value.trim();
  const headers = getHeaders();
  const body = dom.reqBody.value.trim();

  let curl = `curl -X ${method}`;
  if (url) curl += ` "${url}"`;
  Object.entries(headers).forEach(([k, v]) => {
    curl += ` \\\n  -H "${k}: ${v.replace(/"/g, '\\"')}"`;
  });
  if (body) {
    const escaped = body.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    curl += ` \\\n  -d "${escaped}"`;
  }

  pre.textContent = curl;
  display.classList.remove("hidden");
}

// Hide curl display when clicking outside
document.addEventListener('click', (e) => {
  const display = document.getElementById("curl-display");
  const btn = document.getElementById("btn-export-curl");
  if (!display || display.classList.contains("hidden")) return;
  if (!display.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {
    display.classList.add("hidden");
  }
});


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

function parseRawHttp(rawText) {
  // Normalize line endings
  const normalized = rawText.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');

  // First line: METHOD /path HTTP/1.1
  const requestLine = lines[0].trim().split(' ');
  const method = requestLine[0] || 'GET';
  const reqPath = requestLine[1] || '/';

  // Parse headers until empty line
  const headers = {};
  let bodyStart = 1;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') {
      bodyStart = i + 1;
      break;
    }
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      headers[line.substring(0, colonIdx).trim()] = line.substring(colonIdx + 1).trim();
    }
    bodyStart = i + 1;
  }

  // Body is everything after the empty line
  const body = lines.slice(bodyStart).join('\n').trim();

  return { method, path: reqPath, headers, body };
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

// ── Team filter (native <select>, no positioning issues) ──
let currentTeamFilter = '';
function loadTeamFilterSelect() {
  const sel = $('#team-filter-select'); if(!sel) { console.log('team-filter-select not found'); return; }
  sel.innerHTML = '<option value="">Tout</option><option value="__personal__">Personnel</option>';
  sel.value = currentTeamFilter;
  sel.onchange = () => { currentTeamFilter = sel.value; loadCollections(); };
  fetch('/api/user/followed-teams', {headers:{...getAuthHeader()}}).then(r => {
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  }).then(teams => {
    if(teams.length) { teams.forEach(t => { sel.innerHTML += `<option value="${t.team_id}">${escapeHtml(t.name)}</option>`; }); }
    sel.value = currentTeamFilter;
  }).catch(e => { console.log('Team filter load error:', e); });
}

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
init();
