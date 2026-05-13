/* ═══════════════════════════════════════════════════════════════
   ReqVault — Workflow Builder Engine
   Visual no-code API test workflow editor
   ═══════════════════════════════════════════════════════════════ */

const API = {
  structured: '/api/request',
  raw: '/api/request/raw',
  collections: '/api/collections',
};
// AUTH_HEADER fourni dynamiquement par auth.js via getAuthHeader()

// Cache of saved requests loaded from collections
let savedRequestsCache = {};

// ─────────────────────────────────────────────
// BLOCK DEFINITIONS
// ─────────────────────────────────────────────
const BLOCK_DEFS = {
  start: {
    label: 'Start', color: 'green', icon: 'play',
    ports: { in: [], out: ['out'] },
    fields: [],
  },
  http_request: {
    label: 'HTTP Request', color: 'violet', icon: 'send',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'method', label: 'Méthode', type: 'select', options: ['GET','POST','PUT','PATCH','DELETE'], default: 'GET' },
      { key: 'url', label: 'URL', type: 'text', placeholder: 'https://api.example.com/{{ctx.response.id}}' },
      { key: 'headers', label: 'Headers (JSON)', type: 'textarea', placeholder: '{ "Authorization": "Bearer {{ctx.response.token}}" }' },
      { key: 'body', label: 'Body', type: 'textarea', placeholder: '{ "key": "{{ctx.response.value}}" }' },
      { key: 'saveTo', label: 'Sauver réponse dans', type: 'text', placeholder: 'response1', default: 'response' },
    ],
  },
  raw_request: {
    label: 'Raw Request', color: 'teal', icon: 'code',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'url', label: 'URL cible', type: 'text', placeholder: 'https://api.example.com' },
      { key: 'rawRequest', label: 'Requête HTTP brute', type: 'textarea', placeholder: 'GET /api/v1/users HTTP/1.1\nHost: ...' },
      { key: 'saveTo', label: 'Sauver réponse dans', type: 'text', placeholder: 'response1', default: 'response' },
    ],
  },
  set_data: {
    label: 'Set Data', color: 'cyan', icon: 'database',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'saveTo', label: 'Nom du dataset', type: 'text', placeholder: 'myData', default: '' },
      { key: 'variables', label: 'Variables (JSON)', type: 'textarea', placeholder: '{ "token": "{{ctx.response.token}}", "id": {{ctx.response.body.id}} }' },
    ],
  },
  if_else: {
    label: 'If / Else', color: 'amber', icon: 'condition',
    ports: { in: ['in'], out: ['out_true', 'out_false'] },
    fields: [
      { key: 'condition', label: 'Condition (JS)', type: 'textarea', placeholder: 'ctx.response.status_code === 200' },
    ],
  },
  for_loop: {
    label: 'For Loop', color: 'blue', icon: 'loop',
    ports: { in: ['in'], out: ['out_body', 'out_done'] },
    fields: [
      { key: 'iterations', label: 'Nombre d\'itérations', type: 'text', placeholder: '10', default: '5' },
      { key: 'variable', label: 'Variable d\'index', type: 'text', placeholder: 'i', default: 'i' },
    ],
  },
  delay: {
    label: 'Delay', color: 'purple', icon: 'clock',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'ms', label: 'Durée (ms)', type: 'text', placeholder: '1000', default: '1000' },
    ],
  },
  assert: {
    label: 'Assert', color: 'emerald', icon: 'check',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'label', label: 'Nom du test', type: 'text', placeholder: 'Status is 200' },
      { key: 'expression', label: 'Expression (JS)', type: 'textarea', placeholder: 'ctx.response.status_code === 200' },
    ],
  },
  sub_workflow: {
    label: 'Sub-Workflow', color: 'fuchsia', icon: 'send',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'workflowId', label: 'Workflow ID', type: 'text', placeholder: 'uuid du workflow' },
      { key: 'workflowName', label: 'Nom', type: 'text', placeholder: 'Nom affiché' },
    ],
  },
  // ── Red Team blocks ──
  fuzz_params: {
    label: 'Fuzz Requete', color: 'red', icon: 'fuzz',
    desc: 'Boucle de fuzzing : chaque ligne de la wordlist → ctx.fuzz → sortie body (branchez a une requete et faites-la revenir ici) → une fois epuise → sortie done (ctx[saveTo] = tous les resultats).',
    ports: { in: ['in'], out: ['out_body', 'out_done'] },
    fields: [
      { key: 'wordlist', label: 'Wordlist (1 valeur par ligne = 1 iteration)', type: 'textarea', placeholder: 'admin\nuser\ntest\n../../../etc/passwd\n<script>alert(1)</script>', rows: 5 },
      { key: 'saveTo', label: 'Variable de sortie (resultats)', type: 'text', placeholder: 'fuzzResults', default: 'fuzz' },
    ],
  },
  bola_test: {
    label: 'BOLA Test', color: 'orange', icon: 'bola',
    desc: 'Teste les vulnerabilites IDOR (Insecure Direct Object Reference) en substituant {{id}} dans l\'URL par chaque ID de la liste. Si la requete renvoie HTTP 200, la ressource est accessible sans autorisation → branche VULN. Sinon → branche SAFE.',
    ports: { in: ['in'], out: ['out_vuln', 'out_safe'] },
    fields: [
      { key: 'url', label: 'URL avec placeholder {{id}}', type: 'text', placeholder: 'https://api.target.com/users/{{id}}/profile' },
      { key: 'method', label: 'Methode HTTP', type: 'select', options: ['GET','POST','PUT','DELETE'], default: 'GET' },
      { key: 'headers', label: 'Headers (JSON)', type: 'textarea', placeholder: '{"Authorization": "Bearer {{ctx.token}}", "X-Team": "red"}', rows: 2 },
      { key: 'idList', label: 'Liste d\'IDs a tester (JSON)', type: 'textarea', placeholder: '[\n  "user-1",\n  "user-2",\n  "user-3",\n  "admin-1",\n  "0",\n  "99999"\n]', rows: 4 },
      { key: 'saveTo', label: 'Variable de sortie', type: 'text', placeholder: 'bolaResults', default: 'bola' },
    ],
  },
  jwt_analyze: {
    label: 'JWT Analyze', color: 'pink', icon: 'jwt',
    desc: 'Decode un JWT (Base64) sans verifier la signature. Stocke dans ctx.{saveTo} : {header, payload, algorithm, isWeakAlg, expired, expiresAt, issuedAt, hasSensitiveClaims}. Ex: si token avec alg=HS256 et exp depassee → ctx.jwt = {algorithm:"HS256", isWeakAlg:true, expired:true, expiresAt:"2024-01-01T00:00:00.000Z", hasSensitiveClaims:["password"]}.',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'token', label: 'Token JWT a analyser', type: 'text', placeholder: '{{ctx.login.response.access_token}} — utiliser une variable de contexte' },
      { key: 'saveTo', label: 'Variable de sortie', type: 'text', placeholder: 'jwtData', default: 'jwt' },
    ],
  },
  response_diff: {
    label: 'Response Diff', color: 'lime', icon: 'diff',
    desc: 'Compare les reponses de deux requetes identiques avec des headers/auth differents. Utile pour detecter des differences de comportement selon le niveau de privilege (ex: user vs admin). Si les reponses different → branche DIFF, sinon → SAME.',
    ports: { in: ['in'], out: ['out_diff', 'out_same'] },
    fields: [
      { key: 'url', label: 'URL a tester', type: 'text', placeholder: 'https://api.target.com/admin/dashboard' },
      { key: 'method', label: 'Methode HTTP', type: 'select', options: ['GET','POST'], default: 'GET' },
      { key: 'headersA', label: 'Headers requete A (JSON)', type: 'textarea', placeholder: '{\n  "Authorization": "Bearer {{ctx.userA.token}}",\n  "X-Role": "user"\n}', rows: 2 },
      { key: 'headersB', label: 'Headers requete B (JSON)', type: 'textarea', placeholder: '{\n  "Authorization": "Bearer {{ctx.admin.token}}",\n  "X-Role": "admin"\n}', rows: 2 },
      { key: 'saveTo', label: 'Variable de sortie', type: 'text', placeholder: 'diffResult', default: 'diff' },
    ],
  },
  extract_replay: {
    label: 'Extract & Replay', color: 'sky', icon: 'extract',
    desc: 'Extrait une valeur d\'une reponse precedente via expression reguliere, puis la reinjecte dans une nouvelle requete. Ideal pour enchainer : login → extraire le token → acceder a une ressource protegee. La valeur extraite remplace {{extracted}} dans l\'URL.',
    ports: { in: ['in'], out: ['out'] },
    fields: [
      { key: 'source', label: 'Source des donnees', type: 'text', placeholder: 'ctx.login.body — la variable contenant la reponse a parser', default: 'ctx.response.body' },
      { key: 'extractRegex', label: 'Regex d\'extraction (capture group 1)', type: 'text', placeholder: '"access_token"\\s*:\\s*"([^"]+)"' },
      { key: 'url', label: 'URL ou rejouer la valeur', type: 'text', placeholder: 'https://api.target.com/admin?token={{extracted}}' },
      { key: 'method', label: 'Methode HTTP', type: 'select', options: ['GET','POST','PUT'], default: 'GET' },
      { key: 'headers', label: 'Headers (JSON)', type: 'textarea', placeholder: '{"Authorization": "Bearer {{ctx.token}}"}', rows: 2 },
      { key: 'saveTo', label: 'Variable de sortie', type: 'text', placeholder: 'replayResult', default: 'replay' },
    ],
  },
};

const COLOR_MAP = {
  green:   { bg: 'rgba(34,197,94,0.12)',  text: '#4ade80',  border: 'rgba(34,197,94,0.3)' },
  violet:  { bg: 'rgba(139,92,246,0.12)', text: '#a78bfa',  border: 'rgba(139,92,246,0.3)' },
  teal:    { bg: 'rgba(20,184,166,0.12)', text: '#2dd4bf',  border: 'rgba(20,184,166,0.3)' },
  cyan:    { bg: 'rgba(6,182,212,0.12)',   text: '#22d3ee',  border: 'rgba(6,182,212,0.3)' },
  amber:   { bg: 'rgba(245,158,11,0.12)', text: '#fbbf24',  border: 'rgba(245,158,11,0.3)' },
  blue:    { bg: 'rgba(59,130,246,0.12)',  text: '#60a5fa',  border: 'rgba(59,130,246,0.3)' },
  purple:  { bg: 'rgba(168,85,247,0.12)', text: '#a78bfa',  border: 'rgba(168,85,247,0.3)' },
  emerald: { bg: 'rgba(16,185,129,0.12)', text: '#34d399',  border: 'rgba(16,185,129,0.3)' },
  fuchsia: { bg: 'rgba(217,70,239,0.12)', text: '#e879f9',  border: 'rgba(217,70,239,0.3)' },
  red:     { bg: 'rgba(239,68,68,0.12)',   text: '#f87171',  border: 'rgba(239,68,68,0.3)' },
  orange:  { bg: 'rgba(249,115,22,0.12)', text: '#fb923c',  border: 'rgba(249,115,22,0.3)' },
  pink:    { bg: 'rgba(236,72,153,0.12)',  text: '#f472b6',  border: 'rgba(236,72,153,0.3)' },
  lime:    { bg: 'rgba(132,204,22,0.12)',  text: '#a3e635',  border: 'rgba(132,204,22,0.3)' },
  sky:     { bg: 'rgba(14,165,233,0.12)',  text: '#38bdf8',  border: 'rgba(14,165,233,0.3)' },
};

const ICON_SVG = {
  play:      '<path stroke-linecap="round" stroke-linejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"/>',
  send:      '<path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/>',
  code:      '<path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5"/>',
  database:  '<path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125"/>',
  condition: '<path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75"/><circle cx="12" cy="12" r="9"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 17.25h.008v.008H12v-.008z"/>',
  loop:      '<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 12c0-1.232-.046-2.453-.138-3.662a4.006 4.006 0 00-3.7-3.7 48.678 48.678 0 00-7.324 0 4.006 4.006 0 00-3.7 3.7c-.017.22-.032.441-.046.662M19.5 12l3-3m-3 3l-3-3m-12 3c0 1.232.046 2.453.138 3.662a4.006 4.006 0 003.7 3.7 48.656 48.656 0 007.324 0 4.006 4.006 0 003.7-3.7c.017-.22.032-.441.046-.662M4.5 12l3 3m-3-3l-3 3"/>',
  clock:     '<path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5"/><circle cx="12" cy="12" r="9"/>',
  check:     '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75"/><circle cx="12" cy="12" r="9"/>',
  fuzz:      '<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 12c0-1.232-.046-2.453-.138-3.662a4.006 4.006 0 00-3.7-3.7 48.678 48.678 0 00-7.324 0 4.006 4.006 0 00-3.7 3.7c-.017.22-.032.441-.046.662M19.5 12l3-3m-3 3l-3-3m-12 3c0 1.232.046 2.453.138 3.662a4.006 4.006 0 003.7 3.7 48.656 48.656 0 007.324 0 4.006 4.006 0 003.7-3.7c.017-.22.032-.441.046-.662M4.5 12l3 3m-3-3l-3 3"/><circle cx="12" cy="12" r="1.5" fill="currentColor" opacity=".5"/>',
  bola:      '<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"/><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 7.5l15 0M4.5 12h15M4.5 16.5h15" stroke-width="1" opacity=".3"/>',
  jwt:       '<path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/><circle cx="12" cy="16.5" r="1.5" fill="currentColor"/>',
  diff:      '<path stroke-linecap="round" stroke-linejoin="round" d="M3 3v2.25M3 3h2.25M3 3L7 7M3 21v-2.25M3 21h2.25M3 21l4-4M21 3h-2.25M21 3v2.25M21 3l-4 4M21 21h-2.25M21 21v-2.25M21 21l-4-4M12 5v14"/>',
  extract:   '<path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/><path stroke-linecap="round" stroke-linejoin="round" d="M16 5l-3 3m0 0l3 3" stroke-width="1.5" opacity=".4"/>',
};

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
const wf = {
  nodes: [],           // [{ id, type, x, y, data:{}, status:null }]
  connections: [],     // [{ from, fromPort, to, toPort }]
  selectedId: null,
  selectedConnIdx: null,
  dragging: null,      // { nodeId, offsetX, offsetY }
  connecting: null,    // { fromId, fromPort, startX, startY }
  panning: null,       // { startX, startY, panX, panY }
  zoom: 1,
  panX: 0, panY: 0,
  running: false,
  nextId: 1,
};

// ─────────────────────────────────────────────
// DOM
// ─────────────────────────────────────────────
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

const dom = {
  canvas:        $('#wf-canvas'),
  canvasWrapper: $('#wf-canvas-wrapper'),
  svgLayer:      $('#wf-connections'),
  configEmpty:   $('#wf-config-empty'),
  configForm:    $('#wf-config-form'),
  logs:          $('#wf-logs'),
  logCount:      $('#wf-log-count'),
  nodeCount:     $('#wf-node-count'),
  zoomLevel:     $('#wf-zoom-level'),
  panelTabs:     $$('.wf-panel-tab'),
  panels:        $$('.wf-rpanel'),
  ctxContent:     $('#wf-ctx-content'),
  ctxBlockName:   $('#wf-ctx-block-name'),
  btnRun:        $('#btn-run-workflow'),
  btnStop:       $('#btn-stop-workflow'),
  btnClear:      $('#btn-clear-canvas'),
  btnClearLogs:  $('#btn-clear-logs'),
  btnZoomIn:     $('#btn-zoom-in'),
  btnZoomOut:    $('#btn-zoom-out'),
  btnZoomFit:    $('#btn-zoom-fit'),
  btnSave:       $('#btn-save-workflow'),
  btnLoad:       $('#btn-load-workflow'),
  btnImportArazzo: $('#btn-import-arazzo'),
  arazzoModal:     $('#arazzo-import-modal'),
  arazzoModalClose: $('#btn-arazzo-modal-close'),
  arazzoDropZone:  $('#arazzo-drop-zone'),
  arazzoFileInput: $('#arazzo-modal-file-input'),
  arazzoFileLabel: $('#arazzo-file-label'),
  arazzoTargetServer: $('#arazzo-target-server'),
  arazzoOpenapiUrl: $('#arazzo-openapi-url'),
  arazzoOpenapiFile: $('#arazzo-openapi-file'),
  arazzoOpenapiStatus: $('#arazzo-openapi-status'),
  arazzoTeamSelect: $('#arazzo-team-select'),
  arazzoInputsValues: $('#arazzo-inputs-values'),
  arazzoInputsStatus: $('#arazzo-inputs-status'),
  arazzoImportBtn: $('#btn-arazzo-import'),
  arazzoImportStatus: $('#arazzo-import-status'),
  wfName:        $('#wf-name'),
  loadModal:     $('#wf-load-modal'),
  loadList:      $('#wf-load-list'),
  loadCancel:    $('#btn-load-cancel'),
};

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
function init() {
  if (window.__appInitCalled) return;
  window.__appInitCalled = true;
  initAuth();

  // Afficher le nom d'utilisateur et configurer le bouton logout
  initHeaderUser();

  setupPanelTabs();
  setupPaletteDrag();
  setupCanvasInteractions();
  setupToolbar();
  setupSavedRequests();
  setupWorkflowCRUD();
  setupArazzoImport();
  loadWfTeamFilter();
  loadWfSaveTeams();
  loadSavedRequests();
  loadSavedWorkflows();
  applyTransform();
  updateNodeCount();
}

// ─────────────────────────────────────────────
// RIGHT PANEL TABS
// ─────────────────────────────────────────────
function setupPanelTabs() {
  dom.panelTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.wfpanel;
      dom.panelTabs.forEach(b => b.classList.toggle('active', b.dataset.wfpanel === t));
      dom.panels.forEach(p => {
        p.classList.toggle('hidden', p.id !== `wfpanel-${t}`);
        p.classList.toggle('active', p.id === `wfpanel-${t}`);
      });
    });
  });
}

// ─────────────────────────────────────────────
// PALETTE DRAG → CANVAS DROP
// ─────────────────────────────────────────────
function setupPaletteDrag() {
  // Event delegation on the whole palette sidebar
  const palette = document.getElementById('wf-palette');
  palette.addEventListener('dragstart', (e) => {
    const item = e.target.closest('.wf-palette-item, .wf-saved-item');
    if (!item) return;

    if (item.dataset.blockType) {
      e.dataTransfer.setData('block-type', item.dataset.blockType);
    }
    if (item.dataset.workflowId) {
      e.dataTransfer.setData('workflow-id', item.dataset.workflowId);
      e.dataTransfer.setData('workflow-name', item.dataset.workflowName || '');
    }
    if (item.dataset.savedId) {
      e.dataTransfer.setData('saved-id', item.dataset.savedId);
    }

    e.dataTransfer.effectAllowed = 'copy';
  });

  dom.canvasWrapper.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });

  dom.canvasWrapper.addEventListener('drop', (e) => {
    // If dropped on a fuzz container body, let that handler deal with it
    if (e.target.closest('.wf-container-body')) return;
    e.preventDefault();
    const rect = dom.canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / wf.zoom;
    const y = (e.clientY - rect.top) / wf.zoom;

    const savedId = e.dataTransfer.getData('saved-id');
    if (savedId && savedRequestsCache[savedId]) {
      addSavedRequestNode(savedRequestsCache[savedId], x, y);
      return;
    }

    const type = e.dataTransfer.getData('block-type');
    if (type === 'sub_workflow') {
      const wfId = e.dataTransfer.getData('workflow-id');
      const wfName = e.dataTransfer.getData('workflow-name');
      if (wfId) { addSubWorkflowNode(wfId, wfName, x, y); return; }
    }
    if (!type || !BLOCK_DEFS[type]) return;
    addNode(type, x, y);
  });
}

// ─────────────────────────────────────────────
// ADD NODE
// ─────────────────────────────────────────────
function addNode(type, x, y) {
  const def = BLOCK_DEFS[type];
  const data = {};
  def.fields.forEach(f => { data[f.key] = f.default || ''; });

  const node = {
    id: 'n' + (wf.nextId++),
    type,
    x: Math.round(x / 24) * 24,
    y: Math.round(y / 24) * 24,
    data,
    status: null,
  };
  wf.nodes.push(node);
  renderNode(node);
  selectNode(node.id);
  updateNodeCount();
}

// ─────────────────────────────────────────────
// ─────────────────────────────────────────────
// SAVED WORKFLOWS IN PALETTE (sub-workflow blocks)
// ─────────────────────────────────────────────
let wfTeamFilter = '';
function loadWfSaveTeams() {
  const sel = document.getElementById('wf-save-team'); if(!sel) return;
  // Keep the default "Perso" option, add separator
  fetch('/api/teams', {headers:{...getAuthHeader()}}).then(r => {
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  }).then(teams => {
    if(!teams.length) return;
    // Remove any previously loaded team options (keep the first default one)
    while(sel.options.length > 1) sel.remove(1);
    teams.forEach(t => { sel.innerHTML += `<option value="${t.team_id}">${escapeHtml(t.name)}</option>`; });
  }).catch(e => { console.error('loadWfSaveTeams:', e); });
}

function loadWfTeamFilter() {
  const sel = document.getElementById('wf-team-filter-select'); if(!sel) return;
  sel.innerHTML = '<option value="">Tout</option><option value="__personal__">Personnel</option>';
  sel.value = wfTeamFilter;
  sel.onchange = () => { wfTeamFilter = sel.value; loadSavedWorkflows(); loadSavedRequests(); };
  fetch('/api/user/followed-teams', {headers:{...getAuthHeader()}}).then(r => r.json()).then(teams => {
    teams.forEach(t => { sel.innerHTML += `<option value="${t.team_id}">${escapeHtml(t.name)}</option>`; });
    sel.value = wfTeamFilter;
  }).catch(() => {});
}

async function loadSavedWorkflows() {
  const container = document.getElementById('wf-saved-workflows');
  const empty = document.getElementById('wf-saved-workflows-empty');
  if (!container) return;
  container.innerHTML = '';
  if (empty) empty.classList.add('hidden');
  try {
    const qs = wfTeamFilter ? `?team_id=${wfTeamFilter}` : '';
    const res = await fetch('/api/workflows' + qs, { headers: { ...getAuthHeader() } });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const workflows = await res.json();
    if (!workflows.length) { if (empty) empty.classList.remove('hidden'); return; }
    workflows.forEach(wf => {
      const item = document.createElement('div');
      item.className = 'wf-palette-item';
      item.dataset.blockType = 'sub_workflow';
      item.dataset.workflowId = wf.workflow_id;
      item.dataset.workflowName = wf.name;
      item.draggable = true;
      item.innerHTML = `<div class="wf-palette-icon" style="background:rgba(217,70,239,0.12);color:#e879f9"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25a2.25 2.25 0 01-2.25-2.25v-2.25z"/></svg></div><div><div class="wf-palette-label">${escapeHtml(wf.name)}</div><div class="wf-palette-desc">Workflow sauvegardé</div></div>`;
      container.appendChild(item);
    });
  } catch (e) {
    console.error('loadSavedWorkflows:', e);
    if (empty) empty.classList.remove('hidden');
  }
}

// SAVED REQUEST → NODE
// ─────────────────────────────────────────────
function addSubWorkflowNode(wfId, wfName, x, y) {
  const node = {
    id: 'n' + (wf.nextId++),
    type: 'sub_workflow',
    x: Math.round(x / 24) * 24,
    y: Math.round(y / 24) * 24,
    data: { workflowId: wfId, workflowName: wfName || wfId.substring(0, 8) },
    status: null,
  };
  wf.nodes.push(node);
  renderNode(node);
  selectNode(node.id);
  updateNodeCount();
}

function addSavedRequestNode(req, x, y) {
  const data = {
    method: req.method || 'GET',
    url: req.url || '',
    headers: req.headers ? (typeof req.headers === 'string' ? req.headers : JSON.stringify(req.headers)) : '',
    body: req.body || '',
    saveTo: 'response',
  };

  const node = {
    id: 'n' + (wf.nextId++),
    type: 'http_request',
    x: Math.round(x / 24) * 24,
    y: Math.round(y / 24) * 24,
    data,
    status: null,
  };
  wf.nodes.push(node);
  renderNode(node);
  selectNode(node.id);
  updateNodeCount();
}

// ─────────────────────────────────────────────
// WORKFLOW CRUD (SAVE / LOAD / DELETE)
// ─────────────────────────────────────────────
let savedWorkflowId = null;

function setupWorkflowCRUD() {
  dom.btnSave.addEventListener('click', () => saveWorkflow());
  dom.btnLoad.addEventListener('click', () => openLoadModal());
  dom.loadCancel.addEventListener('click', () => {
    dom.loadModal.classList.add('hidden');
    dom.loadModal.classList.remove('flex');
  });
  dom.loadModal.addEventListener('click', (e) => {
    if (e.target === dom.loadModal) {
      dom.loadModal.classList.add('hidden');
      dom.loadModal.classList.remove('flex');
    }
  });
}

function getGraph() {
  return {
    nodes: wf.nodes.map(n => ({ id: n.id, type: n.type, x: n.x, y: n.y, data: n.data })),
    connections: wf.connections.map(c => ({ from: c.from, fromPort: c.fromPort, to: c.to, toPort: c.toPort })),
  };
}

function loadGraph(graph) {
  clearCanvasSilent();
  wf.nextId = 1;
  // Reposition nodes to avoid overlaps
  autoLayout(graph);
  const idMap = {};
  (graph.nodes || []).forEach(n => {
    const newNode = {
      id: 'n' + (wf.nextId++),
      type: n.type,
      x: n.x, y: n.y,
      data: { ...n.data },
      status: null,
    };
    idMap[n.id] = newNode.id;
    newNode._origId = n.id;
    wf.nodes.push(newNode);
    renderNode(newNode);
  });
  (graph.connections || []).forEach(c => {
    wf.connections.push({
      from: idMap[c.from] || c.from,
      fromPort: c.fromPort,
      to: idMap[c.to] || c.to,
      toPort: c.toPort,
    });
  });
  renderConnections();
  updateNodeCount();
}

// ── Auto-layout: staircase positioning (↓ + →) to avoid overlaps ──

function autoLayout(graph) {
  const nodes = graph.nodes || [];
  const connections = graph.connections || [];
  if (nodes.length === 0) return;

  // Build adjacency
  const children = {};
  const parents = {};
  nodes.forEach(n => { children[n.id] = []; parents[n.id] = []; });
  connections.forEach(c => {
    if (children[c.from]) children[c.from].push(c.to);
    if (parents[c.to]) parents[c.to].push(c.from);
  });

  // Find the Start node
  const startNode = nodes.find(n => n.type === 'start');
  const rootId = startNode ? startNode.id : nodes[0].id;

  // Walk the main chain: at each node, follow the FIRST child that has "out" port
  // (the main flow), other children are branches (asserts, etc.)
  const placed = new Set();
  const STEP_X = 240;
  const STEP_Y = 100;
  const START_X = 50;
  const START_Y = 50;

  let idx = 0;
  let currentId = rootId;

  // Walk main chain
  while (currentId && !placed.has(currentId)) {
    const node = nodes.find(n => n.id === currentId);
    if (!node) break;
    node.x = START_X + idx * STEP_X;
    node.y = START_Y + idx * STEP_Y;
    placed.add(currentId);
    idx++;

    // Place branch children (nodes that split off) to the right of the main node
    const kids = children[currentId] || [];
    kids.forEach(cid => {
      if (placed.has(cid)) return;
      // Check if this child is the main continuation (also has children going forward)
      // or a terminal branch (assert, etc.)
      const childKids = children[cid] || [];
      const isBranch = childKids.length === 0; // terminal = branch
      if (isBranch) {
        const childNode = nodes.find(n => n.id === cid);
        if (childNode) {
          childNode.x = node.x + STEP_X;
          childNode.y = node.y + 80;
          placed.add(cid);
        }
      }
    });

    // Follow the main continuation (first non-terminal child)
    let nextId = null;
    for (const cid of kids) {
      if (!placed.has(cid) && (children[cid] || []).length > 0) {
        nextId = cid;
        break;
      }
    }
    // If no non-terminal child found, try any unplaced child
    if (!nextId) {
      for (const cid of kids) {
        if (!placed.has(cid)) { nextId = cid; break; }
      }
    }
    currentId = nextId;
  }

  // Place any remaining unplaced nodes (disconnected)
  nodes.forEach(n => {
    if (!placed.has(n.id)) {
      n.x = START_X + idx * STEP_X;
      n.y = START_Y + idx * STEP_Y;
      placed.add(n.id);
      idx++;
    }
  });
}

async function saveWorkflow() {
  const name = dom.wfName.value.trim() || 'Sans titre';
  const graph = getGraph();
  const teamId = document.getElementById('wf-save-team')?.value || '';
  const payload = { name, graph, team_id: teamId };
  const url = savedWorkflowId
    ? `/api/workflows/${savedWorkflowId}`
    : '/api/workflows';
  const method = savedWorkflowId ? 'PUT' : 'POST';
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify(payload),
  });
  if (res.ok) {
    const data = await res.json();
    if (!savedWorkflowId && data.workflow_id) {
      savedWorkflowId = data.workflow_id;
    }
    await loadSavedWorkflows();
    loadWfSaveTeams(); // refresh team dropdown too
  } else {
    console.error('saveWorkflow failed:', res.status);
  }
}

async function openLoadModal() {
  dom.loadModal.classList.remove('hidden');
  dom.loadModal.classList.add('flex');
  dom.loadList.innerHTML = '<div class="text-xs text-gray-600 text-center py-8">Chargement...</div>';
  try {
    const res = await fetch('/api/workflows', { headers: { ...getAuthHeader() } });
    if (!res.ok) throw new Error('Failed');
    const workflows = await res.json();
    dom.loadList.innerHTML = '';
    if (workflows.length === 0) {
      dom.loadList.innerHTML = '<div class="text-xs text-gray-600 text-center py-8">Aucun workflow sauvegardé</div>';
      return;
    }
    workflows.forEach(wf => {
      const item = document.createElement('div');
      item.className = 'wf-load-item';
      item.innerHTML = `
        <div class="flex items-center justify-between">
          <div class="flex-1 min-w-0">
            <div class="text-xs text-gray-300 font-medium truncate">${escapeHtml(wf.name)}</div>
            <div class="text-[9px] text-gray-600">${(wf.updated_at || wf.created_at || '').substring(0, 16)}</div>
          </div>
          <div class="flex items-center gap-1 ml-2">
            <button class="load-btn w-6 h-6 rounded hover:bg-accent/15 flex items-center justify-center text-gray-500 hover:text-accent-light" title="Charger">
              <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>
            </button>
            <button class="delete-wf-btn w-6 h-6 rounded hover:bg-red-500/15 flex items-center justify-center text-gray-500 hover:text-red-400" title="Supprimer">
              <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg>
            </button>
          </div>
        </div>
      `;
      item.querySelector('.load-btn').addEventListener('click', async () => {
        const res = await fetch(`/api/workflows/${wf.workflow_id}`, { headers: { ...getAuthHeader() } });
        if (res.ok) {
          const data = await res.json();
          loadGraph(data.graph);
          savedWorkflowId = data.workflow_id;
          dom.wfName.value = data.name;
          // Set team selector to match loaded workflow
          const teamSel = document.getElementById('wf-save-team');
          if (teamSel && data.team_id) teamSel.value = data.team_id;
          dom.loadModal.classList.add('hidden');
          dom.loadModal.classList.remove('flex');
        }
      });
      item.querySelector('.delete-wf-btn').addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!confirm(`Supprimer "${wf.name}" ?`)) return;
        await fetch(`/api/workflows/${wf.workflow_id}`, { method: 'DELETE', headers: { ...getAuthHeader() } });
        if (savedWorkflowId === wf.workflow_id) { savedWorkflowId = null; dom.wfName.value = 'Mon workflow de test'; }
        await loadSavedWorkflows();
        openLoadModal();
      });
      dom.loadList.appendChild(item);
    });
  } catch (e) {
    dom.loadList.innerHTML = '<div class="text-xs text-red-400 text-center py-8">Erreur de chargement</div>';
  }
}

// ARAZZO IMPORT MODAL
// ─────────────────────────────────────────────
let arazzoSelectedFile = null;
let arazzoOpenapiSelectedFile = null;

function setupArazzoImport() {
  if (!dom.btnImportArazzo || !dom.arazzoModal) return;

  // Open modal
  dom.btnImportArazzo.addEventListener('click', () => {
    openArazzoModal();
  });

  // Close modal
  dom.arazzoModalClose.addEventListener('click', () => closeArazzoModal());
  dom.arazzoModal.addEventListener('click', (e) => {
    if (e.target === dom.arazzoModal) closeArazzoModal();
  });

  // Arazzo inputs: auto-pair + format button + validation
  dom.arazzoInputsValues.addEventListener('keydown', (e) => {
    if (handleAutoPair(dom.arazzoInputsValues, e)) return;
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
      e.preventDefault();
      formatJsonTextarea(dom.arazzoInputsValues, 'arazzo-inputs-values');
    }
  });
  dom.arazzoInputsValues.addEventListener('input', () => {
    validateJsonFieldById('arazzo-inputs-values');
  });
  // Format button
  const arazzoFmtBtn = dom.arazzoModal.querySelector('[data-json-fmt="arazzo-inputs-values"]');
  if (arazzoFmtBtn) {
    arazzoFmtBtn.addEventListener('click', () => {
      formatJsonTextarea(dom.arazzoInputsValues, 'arazzo-inputs-values');
    });
  }

  // Arazzo file input change
  dom.arazzoFileInput.addEventListener('change', () => {
    const file = dom.arazzoFileInput.files[0];
    if (file) selectArazzoFile(file);
  });

  // OpenAPI file input change
  dom.arazzoOpenapiFile.addEventListener('change', () => {
    const file = dom.arazzoOpenapiFile.files[0];
    if (file) {
      arazzoOpenapiSelectedFile = file;
      dom.arazzoOpenapiStatus.textContent = file.name;
      dom.arazzoOpenapiStatus.className = 'text-[9px] text-emerald-400';
      dom.arazzoOpenapiStatus.classList.remove('hidden');
      dom.arazzoOpenapiUrl.value = ''; // clear URL when file selected
    }
  });

  // OpenAPI URL input: clear file when URL entered
  dom.arazzoOpenapiUrl.addEventListener('input', () => {
    if (dom.arazzoOpenapiUrl.value.trim()) {
      arazzoOpenapiSelectedFile = null;
      dom.arazzoOpenapiFile.value = '';
      dom.arazzoOpenapiStatus.classList.add('hidden');
    }
  });

  // Drag & drop
  const dropZone = dom.arazzoDropZone;
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('border-emerald-400/60', 'bg-emerald-500/[0.08]');
  });
  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('border-emerald-400/60', 'bg-emerald-500/[0.08]');
  });
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-emerald-400/60', 'bg-emerald-500/[0.08]');
    const file = e.dataTransfer.files[0];
    if (file) selectArazzoFile(file);
  });

  // Import button
  dom.arazzoImportBtn.addEventListener('click', () => doArazzoImport());
}

function openArazzoModal() {
  arazzoSelectedFile = null;
  arazzoOpenapiSelectedFile = null;
  dom.arazzoFileInput.value = '';
  dom.arazzoFileLabel.textContent = 'Déposer un fichier .yaml ou .json';
  dom.arazzoImportBtn.disabled = true;
  dom.arazzoImportStatus.classList.add('hidden');
  dom.arazzoTargetServer.value = 'http://localhost:9000';
  dom.arazzoOpenapiUrl.value = '';
  dom.arazzoOpenapiFile.value = '';
  dom.arazzoOpenapiStatus.classList.add('hidden');
  dom.arazzoInputsValues.value = '';
  dom.arazzoInputsStatus.classList.add('hidden');
  loadArazzoTeams();
  dom.arazzoModal.classList.remove('hidden');
  dom.arazzoModal.classList.add('flex');
}

function closeArazzoModal() {
  dom.arazzoModal.classList.add('hidden');
  dom.arazzoModal.classList.remove('flex');
}

async function selectArazzoFile(file) {
  arazzoSelectedFile = file;
  dom.arazzoFileLabel.textContent = file.name;
  dom.arazzoImportBtn.disabled = false;
  await extractArazzoInputs(file);
}

async function extractArazzoInputs(file) {
  try {
    const text = await file.text();
    let inputs = null;
    // Try JSON first
    try {
      const json = JSON.parse(text);
      inputs = extractInputsFromArazzo(json);
    } catch {
      // Try YAML — simple extraction of inputs block
      inputs = extractInputsFromYamlText(text);
    }
    if (inputs) {
      dom.arazzoInputsValues.value = JSON.stringify(inputs, null, 2);
      dom.arazzoInputsStatus.textContent = 'Détectés — remplissez les valeurs';
      dom.arazzoInputsStatus.className = 'text-[9px] text-emerald-400';
    } else {
      dom.arazzoInputsValues.value = '';
      dom.arazzoInputsStatus.textContent = 'Aucun input détecté';
      dom.arazzoInputsStatus.className = 'text-[9px] text-gray-600';
    }
    dom.arazzoInputsStatus.classList.remove('hidden');
  } catch (e) {
    console.error('[arazzo] extractInputs error:', e);
    dom.arazzoInputsStatus.classList.add('hidden');
  }
}

// ── Smart sample value generation ──

const SMART_DEFAULTS = {
  // Noms / identité
  username:        'alice',      name: 'Alice',       firstname: 'Alice',
  lastname:        'Dupont',     fullname: 'Alice Dupont',  nickname: 'alice42',
  email:           'alice@mail.com',  mail: 'alice@mail.com',
  // Auth
  password:        'Test123!',   pass: 'Test123!',    token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.demo',
  apikey:          'sk-demo-1234567890',  api_key: 'sk-demo-1234567890',
  secret:          '********',   auth: 'Bearer eyJhbGciOiJIUzI1NiJ9.demo',
  // IDs
  id:              1,            userid: 42,          user_id: 42,
  uid:             'a1b2c3d4',   uuid: '550e8400-e29b-41d4-a716-446655440000',
  // Web
  url:             'https://example.com',  endpoint: 'https://api.example.com/v1',
  host:            'api.example.com',  port: 443,
  // Dates
  date:            '2025-06-15',  startdate: '2025-06-01',  enddate: '2025-12-31',
  // Pagination
  page:            1,            limit: 10,           offset: 0,
  size:            20,           count: 100,
  // Divers
  role:            'user',       status: 'active',    type: 'standard',
  q:               'search',     query: 'test',       search: 'demo',
  lang:            'fr',         locale: 'fr-FR',     currency: 'EUR',
  phone:           '+33612345678',  description: 'Lorem ipsum dolor sit amet.',
  title:           'Test',       message: 'Hello World',
};

function extractInputsFromArazzo(json) {
  const inputs = {};
  for (const wf of json.workflows || []) {
    const wfInputs = wf.inputs;
    if (!wfInputs || !wfInputs.properties) continue;
    for (const [key, prop] of Object.entries(wfInputs.properties)) {
      inputs[key] = smartSampleValue(key, prop);
    }
  }
  return Object.keys(inputs).length > 0 ? inputs : null;
}

function smartSampleValue(name, prop) {
  // Explicit example or default wins
  if (prop.example !== undefined) return prop.example;
  if (prop.default !== undefined) return prop.default;

  const type = (prop.type || 'string').toLowerCase();

  // Enum: pick first
  if (prop.enum && Array.isArray(prop.enum)) return prop.enum[0];

  // Boolean
  if (type === 'boolean') return false;

  // Array / Object
  if (type === 'array') {
    const itemType = (prop.items && prop.items.type) || 'string';
    if (itemType === 'integer' || itemType === 'number') return [1, 2, 3];
    return ['item1', 'item2'];
  }
  if (type === 'object') return {};

  // Integer / Number — check constraints
  if (type === 'integer' || type === 'number') {
    const min = prop.minimum ?? prop.min ?? null;
    const max = prop.maximum ?? prop.max ?? null;
    if (min !== null && min !== undefined) return type === 'integer' ? Math.ceil(min) : min;
    if (name in SMART_DEFAULTS && typeof SMART_DEFAULTS[name] === 'number') return SMART_DEFAULTS[name];
    return max !== null && max !== undefined ? Math.floor(Math.min(max, 42)) : 42;
  }

  // String — check smart defaults by name
  const nameLower = name.toLowerCase().replace(/[_-]/g, '');
  if (SMART_DEFAULTS[nameLower] !== undefined && typeof SMART_DEFAULTS[nameLower] !== 'number') {
    return SMART_DEFAULTS[nameLower];
  }

  // String — check format
  const fmt = (prop.format || '').toLowerCase();
  if (fmt === 'email') return 'alice@mail.com';
  if (fmt === 'uri' || fmt === 'url') return 'https://example.com';
  if (fmt === 'uuid') return '550e8400-e29b-41d4-a716-446655440000';
  if (fmt === 'date') return '2025-06-15';
  if (fmt === 'date-time') return '2025-06-15T10:30:00Z';
  if (fmt === 'ipv4') return '192.168.1.1';
  if (fmt === 'ipv6') return '::1';
  if (fmt === 'hostname') return 'api.example.com';
  if (fmt === 'byte') return 'ZGVtbw==';

  // String — generate respecting pattern / length constraints
  return randomStringFromConstraints(prop);
}

function randomStringFromConstraints(prop) {
  const minLen = prop.minLength || 0;
  const maxLen = prop.maxLength || 32;
  const pattern = prop.pattern || null;
  const targetLen = Math.max(minLen, Math.min(maxLen, 8));

  // If a regex pattern is provided, try to generate a string that matches (simple approach)
  if (pattern) {
    try {
      const generated = generateFromPattern(pattern, targetLen);
      if (generated) return generated;
    } catch {}
  }

  // Fallback: random alphanum coherent with length
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < targetLen; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function generateFromPattern(pattern, len) {
  // Simple pattern interpreter — handles common regex constructs
  let result = '';
  let i = 0;
  let lastGen = ''; // last generated segment (for quantifier repeat)
  const maxIter = 500;
  let iter = 0;
  while (result.length < len && i < pattern.length && iter < maxIter) {
    iter++;
    if (pattern[i] === '^') { i++; continue; }
    if (pattern[i] === '$') { i++; continue; }
    // Quantifiers {n} or {n,m} — repeat last generated segment
    if (pattern[i] === '{') {
      const close = pattern.indexOf('}', i);
      if (close > i) {
        const q = pattern.substring(i + 1, close);
        const comma = q.indexOf(',');
        const n = parseInt(comma >= 0 ? q.substring(0, comma) : q, 10) || 1;
        const m = comma >= 0 ? parseInt(q.substring(comma + 1), 10) || n + 5 : n;
        const repeat = Math.max(n, Math.min(m, Math.floor(len / Math.max(1, (typeof lastGen === 'string' ? 1 : 1)))));
        for (let r = 1; r < repeat && result.length < len; r++) {
          if (typeof lastGen === 'string' && lastGen.startsWith('__charclass__')) {
            result += randomFromCharClass(lastGen.slice(14));
          } else {
            result += (lastGen || 'x');
          }
        }
        i = close + 1;
        continue;
      }
    }
    // Escape sequences
    if (pattern[i] === '\\' && i + 1 < pattern.length) {
      const next = pattern[i + 1];
      if (next === 'd') lastGen = String(Math.floor(Math.random() * 10));
      else if (next === 'w') lastGen = 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
      else if (next === 's') lastGen = ' ';
      else lastGen = next;
      result += lastGen;
      i += 2;
      continue;
    }
    // Wildcards
    if (pattern[i] === '.') {
      if (pattern[i + 1] === '*') { lastGen = 'abc'; result += lastGen; i += 2; continue; }
      if (pattern[i + 1] === '+') { lastGen = 'a'; result += lastGen; i += 2; continue; }
      lastGen = 'x'; result += lastGen; i++; continue;
    }
    // Character classes [a-z], [0-9], etc.
    if (pattern[i] === '[') {
      const close = pattern.indexOf(']', i);
      if (close > i) {
        const cls = pattern.substring(i + 1, close);
        lastGen = '__charclass__' + cls; // store class for +/* repeat
        result += randomFromCharClass(cls);
        i = close + 1;
        continue;
      }
    }
    if (pattern[i] === '*' || pattern[i] === '+') {
      const extra = pattern[i] === '+' ? Math.min(10, len - result.length) : Math.min(3, len - result.length);
      for (let r = 0; r < extra && result.length < len; r++) {
        if (typeof lastGen === 'string' && lastGen.startsWith('__charclass__')) {
          result += randomFromCharClass(lastGen.slice(14));
        } else {
          result += (lastGen || 'x');
        }
      }
      i++; continue;
    }
    if (pattern[i] === '?') { i++; continue; }
    // Parentheses / pipes — skip groups, keep first alt
    if (pattern[i] === '(') {
      const close = pattern.indexOf(')', i);
      if (close > i) {
        const group = pattern.substring(i + 1, close);
        // Pick first alternative before |
        const alt = group.split('|')[0];
        result += alt;
        i = close + 1;
        continue;
      }
    }
    if (pattern[i] === ')') { i++; continue; }
    if (pattern[i] === '|') {
      const endGroup = pattern.indexOf(')', i);
      if (endGroup > i) { i = endGroup; continue; }
      i++; continue;
    }
    // Regular char
    lastGen = pattern[i];
    result += pattern[i];
    i++;
  }
  return result || 'demo';
}

function randomFromCharClass(cls) {
  // Expand ranges like a-z, 0-9, A-Z
  let chars = '';
  let j = 0;
  while (j < cls.length) {
    if (j + 2 < cls.length && cls[j + 1] === '-') {
      const start = cls.charCodeAt(j);
      const end = cls.charCodeAt(j + 2);
      for (let c = start; c <= end; c++) chars += String.fromCharCode(c);
      j += 3;
    } else {
      chars += cls[j];
      j++;
    }
  }
  return chars ? chars[Math.floor(Math.random() * chars.length)] : 'x';
}

function extractInputsFromYamlText(text) {
  const inputs = {};
  // Find inputs block for each workflow
  const wfRegex = /^[- ]+workflowId:\s*(.+)$/gm;
  // Simpler: find all properties blocks under inputs
  const propsRegex = /^[ \t]+properties:\s*\n([\s\S]*?)(?=\n[ \t]{0,2}\w|\n\w|$)/gm;
  let propsMatch;
  while ((propsMatch = propsRegex.exec(text)) !== null) {
    const propsBlock = propsMatch[1];
    const entries = parseYamlProperties(propsBlock);
    for (const [key, prop] of Object.entries(entries)) {
      inputs[key] = smartSampleValue(key, prop);
    }
  }
  return Object.keys(inputs).length > 0 ? inputs : null;
}

function parseYamlProperties(block) {
  const props = {};
  const lines = block.split('\n');
  let currentKey = null;
  let currentProp = {};
  let baseIndent = null; // first property's indent sets the baseline
  const META_KEYS = new Set(['type','format','example','default','minimum','maximum','min','max','enum','minLength','maxLength','pattern','description','items']);
  for (const line of lines) {
    const propMatch = line.match(/^[ \t]+(\w+):\s*(.*)/);
    if (!propMatch) continue;
    const indent = line.search(/\S/);
    const key = propMatch[1];
    const value = propMatch[2].trim();
    if (baseIndent === null && !META_KEYS.has(key)) baseIndent = indent;
    if (!META_KEYS.has(key) && indent <= (baseIndent || 2)) {
      // New property at base indentation level
      if (currentKey) { props[currentKey] = currentProp; }
      currentKey = key;
      currentProp = {};
      if (value) currentProp.type = value;
    } else if (currentKey) {
      if (key === 'type') currentProp.type = value;
      else if (key === 'format') currentProp.format = value;
      else if (key === 'example') currentProp.example = value;
      else if (key === 'default') currentProp.default = value;
      else if (key === 'minimum' || key === 'min') currentProp.minimum = Number(value);
      else if (key === 'maximum' || key === 'max') currentProp.maximum = Number(value);
      else if (key === 'enum') currentProp.enum = parseYamlArray(value);
      else if (key === 'minLength') currentProp.minLength = Number(value);
      else if (key === 'maxLength') currentProp.maxLength = Number(value);
      else if (key === 'pattern') currentProp.pattern = parseYamlPattern(value);
    }
  }
  if (currentKey) { props[currentKey] = currentProp; }
  return props;
}

function parseYamlArray(val) {
  // Parse YAML inline array: [a, b, c] or multi-line
  const match = val.match(/^\[(.+)\]$/);
  if (match) return match[1].split(',').map(s => s.trim().replace(/^['"]|['"]$/g, ''));
  return [val];
}

function parseYamlPattern(val) {
  // Strip YAML quotes: '^[a-z]+$' → ^[a-z]+$
  return val.replace(/^['"]|['"]$/g, '');
}

async function loadArazzoTeams() {
  const sel = dom.arazzoTeamSelect;
  if (!sel) return;
  sel.innerHTML = '<option value="">Personnel</option>';
  try {
    const res = await fetch('/api/teams', { headers: { ...getAuthHeader() } });
    if (res.ok) {
      const teams = await res.json();
      teams.forEach(t => {
        sel.innerHTML += `<option value="${t.team_id}">${escapeHtml(t.name)}</option>`;
      });
    }
  } catch {}
}

async function doArazzoImport() {
  if (!arazzoSelectedFile) return;
  const targetServer = dom.arazzoTargetServer.value.trim() || 'http://localhost:9000';
  const teamId = dom.arazzoTeamSelect.value;
  const inputsRaw = dom.arazzoInputsValues.value.trim();
  const openapiUrl = dom.arazzoOpenapiUrl.value.trim();

  dom.arazzoImportBtn.disabled = true;
  dom.arazzoImportBtn.innerHTML = `<svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-opacity=".25"/><path stroke-linecap="round" d="M12 2a10 10 0 019.95 8.9" opacity=".8"/></svg> Importation...`;
  dom.arazzoImportStatus.classList.add('hidden');

  try {
    const formData = new FormData();
    formData.append('file', arazzoSelectedFile);
    // Attach OpenAPI spec if provided
    if (arazzoOpenapiSelectedFile) {
      formData.append('openapi_file', arazzoOpenapiSelectedFile);
    }
    let qs = `target_url=${encodeURIComponent(targetServer)}&team_id=${encodeURIComponent(teamId)}`;
    if (openapiUrl) {
      qs += `&openapi_url=${encodeURIComponent(openapiUrl)}`;
    }
    if (inputsRaw) {
      try {
        JSON.parse(inputsRaw); // validate
        qs += `&inputs_values=${encodeURIComponent(inputsRaw)}`;
      } catch { /* ignore invalid JSON */ }
    }
    const res = await fetch(`/api/document/openapi?${qs}`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const result = await res.json();
    dom.arazzoImportStatus.textContent = `${result.collection_name || 'Import réussi'} — ${(result.workflow_ids || []).length} workflow(s)`;
    dom.arazzoImportStatus.className = 'text-[10px] text-center mt-2 text-emerald-400';
    dom.arazzoImportStatus.classList.remove('hidden');
    dom.arazzoImportBtn.disabled = true;
    dom.arazzoImportBtn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg> Importé`;
    await loadSavedWorkflows();
    loadWfSaveTeams();
    setTimeout(() => closeArazzoModal(), 1200);
  } catch (e) {
    dom.arazzoImportStatus.textContent = `Erreur : ${e.message}`;
    dom.arazzoImportStatus.className = 'text-[10px] text-center mt-2 text-red-400';
    dom.arazzoImportStatus.classList.remove('hidden');
    dom.arazzoImportBtn.disabled = false;
    dom.arazzoImportBtn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg> Importer les workflows`;
  }
}

// LOAD SAVED REQUESTS FROM COLLECTIONS
// ─────────────────────────────────────────────
function setupSavedRequests() {
  const refreshBtn = document.getElementById('btn-refresh-saved');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => loadSavedRequests(true));
  }
}

async function loadSavedRequests(force = false) {
  const container = document.getElementById('wf-saved-requests');
  const loading = document.getElementById('wf-saved-loading');
  const empty = document.getElementById('wf-saved-empty');

  if (!container) return;

  // Clear previous rendered items (keep loading/empty placeholders)
  container.querySelectorAll('.wf-saved-folder, .wf-saved-item').forEach(el => el.remove());

  try {
    if (loading) loading.classList.remove('hidden');
    if (empty) empty.classList.add('hidden');

    const res = await fetch(API.collections, { headers: { ...getAuthHeader() } });
    if (!res.ok) throw new Error('Failed');

    const tree = await res.json();
    if (loading) loading.classList.add('hidden');

    if (!tree || tree.length === 0) {
      if (empty) empty.classList.remove('hidden');
      savedRequestsCache = {};
      return;
    }

    // Index all nodes (folders + requests) by ID
    savedRequestsCache = {};
    function indexNodes(nodes) {
      for (const node of nodes) {
        savedRequestsCache[node.id] = node;
        if (node.type === 'folder' && node.children) indexNodes(node.children);
      }
    }
    indexNodes(tree);

    // Render tree with folders
    tree.forEach(node => {
      container.appendChild(renderSavedTreeNode(node));
    });
  } catch (e) {
    console.error('loadSavedRequests:', e);
    if (loading) loading.classList.add('hidden');
    if (empty) empty.classList.remove('hidden');
    savedRequestsCache = {};
  }
}

function renderSavedTreeNode(node, depth = 0) {
  if (node.type === 'folder') {
    return renderSavedFolderNode(node, depth);
  }
  return renderSavedRequestItem(node, depth);
}

function renderSavedFolderNode(folder, depth = 0) {
  const wrapper = document.createElement('div');
  wrapper.className = 'wf-saved-folder';
  wrapper.dataset.id = folder.id;
  const indent = Math.min(depth, 4) * 12; // 12px per level, max 4 levels

  const header = document.createElement('div');
  header.className = 'wf-saved-folder-header';
  header.style.paddingLeft = (indent + 4) + 'px';
  header.innerHTML = `
    <svg class="wf-saved-folder-chevron ${folder.expanded ? 'open' : ''} w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5"/></svg>
    <svg class="wf-saved-folder-icon ${folder.expanded ? 'open' : 'closed'} w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
      ${folder.expanded
        ? '<path stroke-linecap="round" stroke-linejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776"/>'
        : '<path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"/>'
      }
    </svg>
    <span class="text-[10px] text-gray-300 truncate flex-1 font-medium">${escapeHtml(folder.name)}</span>
    <span class="text-[9px] text-gray-600 font-mono mr-1">${(folder.children || []).length}</span>
  `;

  const childrenContainer = document.createElement('div');
  childrenContainer.className = 'wf-saved-folder-children' + (folder.expanded ? '' : ' collapsed');
  if (folder.expanded) {
    childrenContainer.style.maxHeight = 'none';
  } else {
    childrenContainer.style.maxHeight = '0';
  }

  (folder.children || []).forEach(child => {
    childrenContainer.appendChild(renderSavedTreeNode(child, depth + 1));
  });

  // Toggle expand/collapse
  header.addEventListener('click', () => {
    folder.expanded = !folder.expanded;
    const chevron = header.querySelector('.wf-saved-folder-chevron');
    chevron.classList.toggle('open', folder.expanded);

    const folderIcon = header.querySelector('.wf-saved-folder-icon');
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

  wrapper.appendChild(header);
  wrapper.appendChild(childrenContainer);
  return wrapper;
}

function renderSavedRequestItem(req, depth = 0) {
  const item = document.createElement('div');
  item.className = 'wf-saved-item';
  item.dataset.savedId = req.id;
  item.draggable = true;
  const indent = Math.min(depth, 4) * 12 + 16; // 12px/level + 16px to align with folder text (not chevron)
  item.style.paddingLeft = indent + 'px';

  const methodLower = (req.method || 'GET').toLowerCase();
  const aiBadge = req.isDoneByAI
    ? `<span class="ai-badge" title="Généré par IA" style="width:14px;height:14px;margin-left:auto;flex-shrink:0;"><svg class="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg></span>`
    : '';

  item.innerHTML = `
    <span class="method-badge ${methodLower}" style="font-size:7px;padding:1px 3px;min-width:26px;flex-shrink:0;">${escapeHtml(req.method || 'GET')}</span>
    <span class="text-[10px] text-gray-300 truncate flex-1 font-medium">${escapeHtml(req.name)}</span>
    ${aiBadge}
  `;

  return item;
}

// ─────────────────────────────────────────────
// RENDER NODE
// ─────────────────────────────────────────────
function renderNode(node) {
  const def = BLOCK_DEFS[node.type];
  const isEmbedded = node._embedded; // child of a container node
  const colors = COLOR_MAP[def.color];
  const el = document.createElement('div');
  el.className = 'wf-node' + (def.isContainer ? ' wf-node-container' : '') + (isEmbedded ? ' wf-node-embedded' : '');
  el.id = `node-${node.id}`;
  el.style.left = node.x + 'px';
  el.style.top = node.y + 'px';
  if (def.isContainer) { el.style.minWidth = '320px'; el.style.zIndex = '15'; }
  if (isEmbedded) { el.style.zIndex = '25'; }

  // Summary text
  let summary = '';
  if (node.type === 'http_request') summary = `${node.data.method || 'GET'} ${truncate(node.data.url, 30)}`;
  else if (node.type === 'raw_request') summary = truncate(node.data.url, 30);
  else if (node.type === 'set_data') summary = (node.data.saveTo ? `ctx.${node.data.saveTo}` : truncate(node.data.variables, 28));
  else if (node.type === 'if_else') summary = truncate(node.data.condition, 28);
  else if (node.type === 'for_loop') summary = `${node.data.iterations || 5}x — ${node.data.variable || 'i'}`;
  else if (node.type === 'delay') summary = `${node.data.ms || 1000}ms`;
  else if (node.type === 'assert') summary = truncate(node.data.label || node.data.expression, 28);
  else if (node.type === 'sub_workflow') summary = node.data.workflowName || node.data.workflowId;

  // Container node: U-shape with drop zone
  let childHTML = '';
  if (def.isContainer) {
    if (node.data.childNodeId) {
      const child = wf.nodes.find(n => n.id === node.data.childNodeId);
      if (child) {
        const childDef = BLOCK_DEFS[child.type];
        const childColors = COLOR_MAP[childDef.color];
        const cSummary = child.type === 'http_request' || child.type === 'raw_request'
          ? `${child.data.method || 'GET'} ${truncate(child.data.url || '', 40)}`
          : childDef.label;
        childHTML = `<div class="wf-container-child" style="margin:4px 8px;padding:8px 10px;border-radius:6px;background:rgba(255,255,255,.04);border:1px solid ${childColors.border};font-size:10px;color:#d1d5db;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;gap:6px;">
          <span class="method-badge ${(child.data.method||'GET').toLowerCase()}" style="font-size:7px;padding:1px 4px;flex-shrink:0;">${esc(child.data.method||'GET')}</span>
          <span class="truncate flex-1">${esc(cSummary)}</span>
          <button class="wf-detach-child" data-node="${node.id}" style="flex-shrink:0;width:16px;height:16px;border-radius:50%;background:#1a2340;border:1px solid rgba(255,255,255,.15);color:#6b7280;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:10px;line-height:1;">×</button>
        </div>`;
      }
    }
  }

  el.innerHTML = `
    <button class="wf-node-delete" data-delete="${node.id}">
      <svg class="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
    ${def.isContainer ? `<div class="wf-container-top" style="margin:4px 8px 0;border:1px solid ${colors.border};border-bottom:none;border-radius:10px 10px 0 0;height:10px;background:linear-gradient(180deg,${colors.bg},transparent);"></div>` : ''}
    <div class="wf-node-header">
      <div class="wf-node-icon" style="background:${colors.bg}; color:${colors.text}">
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">${ICON_SVG[def.icon]}</svg>
      </div>
      <span class="wf-node-title">${def.label}</span>
      <div class="wf-node-status" id="status-${node.id}"></div>
    </div>
    ${summary ? `<div class="wf-node-body">${escapeHtml(summary)}</div>` : ''}
    ${def.isContainer ? `
      <div class="wf-container-body" data-fuzz-drop="${node.id}" style="min-height:${node.data.childNodeId ? 'auto' : '52px'};margin:0 8px 8px;border:1.5px dashed ${node.data.childNodeId ? 'rgba(239,68,68,.2)' : 'rgba(239,68,68,.3)'};border-radius:8px;display:flex;align-items:center;justify-content:center;transition:all .2s;${node.data.childNodeId ? '' : 'padding:8px;'}">
        ${node.data.childNodeId ? childHTML : '<span class="text-[11px] text-gray-600">Drop HTTP or Raw Request here</span>'}
      </div>
    ` : ''}
  `;

  // Wire detach button
  if (def.isContainer) {
    el.querySelector('.wf-detach-child')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const child = wf.nodes.find(n => n.id === node.data.childNodeId);
      if (child) {
        child._embedded = false;
        child.x = node.x + 350; child.y = node.y;
        // Remove stale inline child HTML from old container rendering
        const oldChildEl = document.getElementById(`node-${child.id}`);
        if (oldChildEl) oldChildEl.remove();
      }
      node.data.childNodeId = '';
      refreshNodeDisplay(node);
      if (child) renderNode(child);
    });
    // Container drop zone
    const body = el.querySelector('.wf-container-body');
    if (body) {
      body.addEventListener('dragover', (e) => { e.preventDefault(); e.stopPropagation(); body.style.borderColor = 'rgba(239,68,68,.6)'; body.style.background = 'rgba(239,68,68,.05)'; });
      body.addEventListener('dragleave', (e) => { body.style.borderColor = node.data.childNodeId ? 'rgba(239,68,68,.2)' : 'rgba(239,68,68,.3)'; body.style.background = 'transparent'; });
      body.addEventListener('drop', (e) => {
        e.preventDefault(); e.stopPropagation();
        body.style.borderColor = node.data.childNodeId ? 'rgba(239,68,68,.2)' : 'rgba(239,68,68,.3)';
        body.style.background = 'transparent';
        const blockType = e.dataTransfer.getData('block-type');
        if (!blockType) return;
        if (blockType !== 'http_request' && blockType !== 'raw_request') return;
        try {
          // Detach previous child if any
          if (node.data.childNodeId) {
            const prev = wf.nodes.find(n => n.id === node.data.childNodeId);
            if (prev) {
              prev._embedded = false;
              prev.x = node.x + 350; prev.y = node.y;
              // Remove any stale DOM for the old child
              const oldEl = document.getElementById(`node-${prev.id}`);
              if (oldEl) oldEl.remove();
            }
            node.data.childNodeId = '';
          }
          // Create embedded child
          const childDef = BLOCK_DEFS[blockType];
          if (!childDef) return;
          const data = {};
          childDef.fields.forEach(f => { data[f.key] = f.default || ''; });
          const child = {
            id: 'n' + (wf.nextId++),
            type: blockType,
            x: node.x + 16,
            y: node.y + 60,
            data,
            status: null,
            _embedded: true,
          };
          wf.nodes.push(child);
          node.data.childNodeId = child.id;
          refreshNodeDisplay(node);
          updateNodeCount();
        } catch (err) {
          console.error('fuzz drop failed', err);
          refreshNodeDisplay(node);
        }
      });
    }
  }

  // Ports — skip for embedded nodes
  if (!isEmbedded) {
    const portDefs = def.ports;
    portDefs.in.forEach(pName => {
      const port = createPort('in', pName, node.id);
      el.appendChild(port);
    });
    portDefs.out.forEach(pName => {
      const port = createPort('out', pName, node.id);
      el.appendChild(port);
    });
  }

  // Events
  el.addEventListener('mousedown', (e) => {
    if (e.target.closest('.wf-port') || e.target.closest('.wf-node-delete') || e.target.closest('.wf-container-body') || e.target.closest('.wf-detach-child')) return;
    // Cancel any pending connection
    if (wf.connecting) { cancelConnecting(); renderConnections(); }
    selectNode(node.id);
    const wrapperRect = dom.canvasWrapper.getBoundingClientRect();
    wf.dragging = {
      nodeId: node.id,
      offsetX: (e.clientX - wrapperRect.left - wf.panX) / wf.zoom - node.x,
      offsetY: (e.clientY - wrapperRect.top - wf.panY) / wf.zoom - node.y,
    };
    e.preventDefault();
  });

  el.querySelector('.wf-node-delete').addEventListener('click', (e) => {
    e.stopPropagation();
    removeNode(node.id);
  });

  // Embedded nodes are rendered inline inside their container — skip canvas append
  if (!isEmbedded) {
    dom.canvas.appendChild(el);
  }
}

function createPort(dir, portName, nodeId) {
  const port = document.createElement('div');
  let cls = 'wf-port';

  if (dir === 'in') {
    cls += ' port-in';
  } else {
    if (portName === 'out') cls += ' port-out';
    else if (portName === 'out_true') cls += ' port-out-true';
    else if (portName === 'out_false') cls += ' port-out-false';
    else if (portName === 'out_vuln') cls += ' port-out-vuln';
    else if (portName === 'out_safe') cls += ' port-out-safe';
    else if (portName === 'out_diff') cls += ' port-out-diff';
    else if (portName === 'out_same') cls += ' port-out-same';
    else if (portName === 'out_body') cls += ' port-out-body';
    else if (portName === 'out_done') cls += ' port-out-done';
  }

  port.className = cls;
  port.dataset.nodeId = nodeId;
  port.dataset.portName = portName;
  port.dataset.portDir = dir;

  // Port label for multi-out
  if (portName === 'out_true') port.innerHTML = '<span class="wf-port-label" style="color:#4ade80">TRUE</span>';
  if (portName === 'out_false') port.innerHTML = '<span class="wf-port-label" style="color:#f87171">FALSE</span>';
  if (portName === 'out_body') port.innerHTML = '<span class="wf-port-label" style="color:#60a5fa">BODY</span>';
  if (portName === 'out_done') port.innerHTML = '<span class="wf-port-label" style="color:#a78bfa">DONE</span>';

  // Click-to-click connection from output port
  port.addEventListener('mousedown', (e) => {
    e.stopPropagation();
    e.preventDefault();
    if (dir === 'out') {
      if (wf.connecting) {
        // Already connecting — cancel
        cancelConnecting();
        return;
      }
      const rect = port.getBoundingClientRect();
      const wrapperRect = dom.canvasWrapper.getBoundingClientRect();
      port.classList.add('connecting');
      wf.connecting = {
        fromId: nodeId,
        fromPort: portName,
        startX: rect.left + rect.width / 2 - wrapperRect.left,
        startY: rect.top + rect.height / 2 - wrapperRect.top,
      };
      // Highlight canvas to show we're in connect mode
      dom.canvasWrapper.classList.add('connecting-mode');
    }
  });

  // Click on input port to complete connection
  if (dir === 'in') {
    port.addEventListener('mousedown', (e) => {
      e.stopPropagation();
      e.preventDefault();
      if (wf.connecting) {
        const toId = nodeId;
        const toPort = portName;
        if (toId !== wf.connecting.fromId) {
          wf.connections = wf.connections.filter(c => !(c.to === toId && c.toPort === toPort));
          wf.connections.push({
            from: wf.connecting.fromId,
            fromPort: wf.connecting.fromPort,
            to: toId,
            toPort: toPort,
          });
        }
        cancelConnecting();
        renderConnections();
      }
    });
  }

  return port;
}

// ─────────────────────────────────────────────
// CANVAS INTERACTIONS (drag, connect, select)
// ─────────────────────────────────────────────
function setupCanvasInteractions() {
  document.addEventListener('mousemove', (e) => {
    // Node dragging
    if (wf.dragging) {
      const node = wf.nodes.find(n => n.id === wf.dragging.nodeId);
      if (!node) return;
      const wrapperRect = dom.canvasWrapper.getBoundingClientRect();
      // Convert screen → canvas coords accounting for pan & zoom
      const cx = (e.clientX - wrapperRect.left - wf.panX) / wf.zoom;
      const cy = (e.clientY - wrapperRect.top - wf.panY) / wf.zoom;
      node.x = Math.round((cx - wf.dragging.offsetX) / 24) * 24;
      node.y = Math.round((cy - wf.dragging.offsetY) / 24) * 24;
      const el = $(`#node-${node.id}`);
      if (el) {
        el.style.left = node.x + 'px';
        el.style.top = node.y + 'px';
      }
      renderConnections();
    }

    // Connection drawing — screen-space (SVG is not zoomed)
    if (wf.connecting) {
      const wrapperRect = dom.canvasWrapper.getBoundingClientRect();
      const mx = e.clientX - wrapperRect.left;
      const my = e.clientY - wrapperRect.top;
      renderTempConnection(wf.connecting.startX, wf.connecting.startY, mx, my);
    }
  });

  document.addEventListener('mouseup', (e) => {
    // Connecting is now click-to-click — mouseup just ends node drag
    wf.dragging = null;
  });

  // Click on canvas background → cancel connection or deselect
  dom.canvas.addEventListener('mousedown', (e) => {
    if (wf.connecting) {
      // Clicked outside any port → cancel
      if (!e.target.closest('.wf-port')) {
        cancelConnecting();
        renderConnections();
      }
    }
    if (e.target === dom.canvas) {
      selectNode(null);
      selectConnection(null);
    }
  });

  // Pan: middle-click drag on canvas wrapper
  dom.canvasWrapper.addEventListener('mousedown', (e) => {
    if (e.button === 1) {
      e.preventDefault();
      wf.panning = { startX: e.clientX, startY: e.clientY, panX: wf.panX, panY: wf.panY };
    }
  });

  document.addEventListener('mousemove', (e) => {
    if (wf.panning) {
      const dx = e.clientX - wf.panning.startX;
      const dy = e.clientY - wf.panning.startY;
      wf.panX = wf.panning.panX + dx;
      wf.panY = wf.panning.panY + dy;
      applyTransform();
      renderConnections();
    }
  });

  document.addEventListener('mouseup', (e) => {
    if (e.button === 1 && wf.panning) {
      wf.panning = null;
      renderConnections();
    }
  });

  // Zoom: Ctrl+wheel centered on cursor
  dom.canvasWrapper.addEventListener('wheel', (e) => {
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const rect = dom.canvasWrapper.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const delta = -e.deltaY * 0.005;
      setZoom(wf.zoom + delta, cx, cy);
    }
  }, { passive: false });

  // Keyboard navigation & shortcuts
  document.addEventListener('keydown', (e) => {
    // Don't intercept when typing in inputs
    if (e.target.closest('input, textarea, select')) return;

    // Pan: WASD / arrow keys
    const STEP = 40;
    switch (e.key) {
      case 'ArrowLeft': case 'a': case 'q': panBy(-STEP, 0); e.preventDefault(); break;
      case 'ArrowRight': case 'd':          panBy(STEP, 0);  e.preventDefault(); break;
      case 'ArrowUp':   case 'w': case 'z': panBy(0, -STEP); e.preventDefault(); break;
      case 'ArrowDown': case 's':           panBy(0, STEP);  e.preventDefault(); break;
    }

    // Delete
    if ((e.key === 'Delete' || e.key === 'Backspace')) {
      if (wf.selectedConnIdx !== null) {
        removeConnection(wf.selectedConnIdx);
      } else if (wf.selectedId) {
        removeNode(wf.selectedId);
      }
    }
  });
}

// ─────────────────────────────────────────────
// SELECT / REMOVE NODE
// ─────────────────────────────────────────────
function selectNode(id) {
  wf.selectedId = id;
  selectConnection(null);
  $$('.wf-node').forEach(el => el.classList.toggle('selected', el.id === `node-${id}`));
  renderConfigPanel(id);
  renderContextPanel(id);
}

// ── Context panel: show ctx variables for selected node ──

function renderContextPanel(nodeId) {
  if (!nodeId) {
    dom.ctxContent.innerHTML = '<div class="text-gray-600 text-center py-8 text-xs">Sélectionnez un bloc pour voir ses variables ctx</div>';
    dom.ctxBlockName.textContent = '';
    return;
  }
  const node = wf.nodes.find(n => n.id === nodeId);
  if (!node) return;

  const def = BLOCK_DEFS[node.type];
  dom.ctxBlockName.textContent = (def && def.label) || node.type;

  // Determine what this node produces and consumes
  const produces = []; // ctx keys this node writes
  const consumes = []; // ctx keys this node reads (from templates)

  // What this node produces (saveTo)
  if (node.data.saveTo) produces.push(node.data.saveTo);

  // Extract ctx.* references from template fields
  const re = /\{\{ctx\.(\w+)/g;
  const textFields = ['url', 'headers', 'body', 'variables', 'expression', 'condition'];
  textFields.forEach(field => {
    const val = node.data[field];
    if (!val || typeof val !== 'string') return;
    const matches = val.matchAll(re);
    for (const m of matches) {
      const key = m[1];
      if (key && !consumes.includes(key)) consumes.push(key);
    }
  });

  // Build HTML
  let html = '';

  // Produces section
  html += '<div class="mb-3"><div class="text-[9px] uppercase tracking-wider text-emerald-400 font-semibold mb-1.5">Produit</div>';
  if (produces.length) {
    produces.forEach(key => {
      const val = ctxValue(key);
      html += '<div class="bg-base-700/50 rounded-md p-2 mb-1 border border-white/5">' +
        '<div class="text-[10px] text-emerald-300 font-medium">ctx.' + escapeHtml(key) + '</div>' +
        (val !== undefined
          ? '<pre class="text-[10px] text-gray-400 mt-1 max-h-32 overflow-y-auto">' + escapeHtml(truncate(formatCtxVal(val), 500)) + '</pre>'
          : '<div class="text-[9px] text-gray-600 mt-0.5">pas encore exécuté</div>') +
        '</div>';
    });
  } else {
    html += '<div class="text-[10px] text-gray-600">—</div>';
  }
  html += '</div>';

  // Consumes section
  html += '<div><div class="text-[9px] uppercase tracking-wider text-amber-400 font-semibold mb-1.5">Consomme</div>';
  if (consumes.length) {
    consumes.forEach(key => {
      const val = ctxValue(key);
      html += '<div class="bg-base-700/50 rounded-md p-2 mb-1 border border-white/5">' +
        '<div class="text-[10px] text-amber-300 font-medium">ctx.' + escapeHtml(key) + '</div>' +
        (val !== undefined
          ? '<pre class="text-[10px] text-gray-400 mt-1 max-h-32 overflow-y-auto">' + escapeHtml(truncate(formatCtxVal(val), 300)) + '</pre>'
          : '<div class="text-[9px] text-gray-600 mt-0.5">non défini</div>') +
        '</div>';
    });
  } else {
    html += '<div class="text-[10px] text-gray-600">—</div>';
  }
  html += '</div>';

  dom.ctxContent.innerHTML = html;
}

// Helper: get a value from the global ctx (populated during execution)
function ctxValue(key) {
  // ctx is a global object set during workflow execution
  if (typeof window.__wfCtx === 'undefined') return undefined;
  const ctx = window.__wfCtx;
  if (key === 'inputs' && ctx.inputs) return ctx.inputs;
  // Direct match: ctx.loginStep, ctx.getPetStep, etc.
  if (ctx[key] !== undefined) return ctx[key];
  // Nested: ctx.loginStep.status_code
  const dot = key.indexOf('.');
  if (dot > 0) {
    const parent = key.substring(0, dot);
    const child = key.substring(dot + 1);
    if (ctx[parent] && ctx[parent][child] !== undefined) return ctx[parent][child];
  }
  return undefined;
}

function formatCtxVal(val) {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'object') {
    // Safe serialize: limit body size
    try {
      const safe = JSON.parse(JSON.stringify(val, (k, v) => {
        if (k === 'body' && typeof v === 'string') {
          if (v.length > 2000) return v.substring(0, 2000) + '…[tronqué]';
          // Try to pretty-print JSON bodies
          try { return JSON.parse(v); } catch { return v; }
        }
        return v;
      }));
      return JSON.stringify(safe, null, 2);
    } catch { return String(val).substring(0, 500); }
  }
  const s = String(val);
  // Try to parse JSON strings for pretty display
  if ((s.startsWith('{') || s.startsWith('[')) && s.length < 5000) {
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch {}
  }
  return s.length > 2000 ? s.substring(0, 2000) + '…[tronqué]' : s;
}

function removeNode(id) {
  wf.nodes = wf.nodes.filter(n => n.id !== id);
  wf.connections = wf.connections.filter(c => c.from !== id && c.to !== id);
  if (wf.selectedConnIdx !== null && wf.selectedConnIdx >= wf.connections.length) {
    selectConnection(null);
  }
  const el = $(`#node-${id}`);
  if (el) el.remove();
  if (wf.selectedId === id) selectNode(null);
  renderConnections();
  updateNodeCount();
}

function selectConnection(idx) {
  wf.selectedConnIdx = idx;
  renderConnections();
}

function removeConnection(idx) {
  if (idx === null || idx >= wf.connections.length) return;
  wf.connections.splice(idx, 1);
  selectConnection(null);
  renderConnections();
}

// ─────────────────────────────────────────────
// CTX TEMPLATE SNIPPETS
// ─────────────────────────────────────────────
function renderCtxSnippets() {
  const snippets = [
    { label: 'ctx.response.status_code', desc: 'Code HTTP (number)', expr: '{{ctx.response.status_code}}' },
    { label: 'ctx.response.body', desc: 'Corps de la réponse (string)', expr: '{{ctx.response.body}}' },
    { label: 'ctx.response.headers["key"]', desc: 'Header de réponse', expr: '{{ctx.response.headers["Content-Type"]}}' },
    { label: 'ctx.response.url', desc: 'URL de la réponse', expr: '{{ctx.response.url}}' },
    { label: 'ctx.dataset.field', desc: 'Champ d\'un dataset nommé', expr: '{{ctx.myData.id}}' },
    { label: 'ctx.maVariable', desc: 'Variable racine (Set Data sans nom)', expr: '{{ctx.maVariable}}' },
  ];

  let html = `
    <div class="wf-config-examples">
      <div class="wf-config-examples-title">
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125"/></svg>
        ctx — Contexte du workflow
      </div>
  `;

  snippets.forEach(s => {
    html += `<div class="wf-config-example" data-expr="${escapeAttr(s.expr)}"><span class="wf-example-key">${escapeHtml(s.label)}</span> : ${escapeHtml(s.desc)}</div>`;
  });

  html += `</div>`;
  return html;
}

function insertAtCursor(el, text) {
  if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
    const start = el.selectionStart;
    const end = el.selectionEnd;
    el.value = el.value.substring(0, start) + text + el.value.substring(end);
    el.selectionStart = el.selectionEnd = start + text.length;
    el.focus();
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

// ─────────────────────────────────────────────
// CONFIG PANEL
// ─────────────────────────────────────────────
function renderConfigPanel(nodeId) {
  if (!nodeId) {
    dom.configEmpty.classList.remove('hidden');
    dom.configForm.classList.add('hidden');
    return;
  }
  const node = wf.nodes.find(n => n.id === nodeId);
  if (!node) return;
  const def = BLOCK_DEFS[node.type];
  const colors = COLOR_MAP[def.color];

  dom.configEmpty.classList.add('hidden');
  dom.configForm.classList.remove('hidden');

  let html = `
    <div class="flex items-center gap-2 mb-3 pb-3 border-b border-white/5">
      <div class="wf-node-icon" style="background:${colors.bg};color:${colors.text}">
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">${ICON_SVG[def.icon]}</svg>
      </div>
      <div>
        <div class="text-xs font-semibold text-white">${def.label}</div>
        <div class="text-[10px] text-gray-600 font-mono">${node.id}</div>
      </div>
    </div>
    ${def.desc ? `<div class="text-[10px] text-gray-500 leading-relaxed mb-3 pb-3 border-b border-white/5">${def.desc}</div>` : ''}
  `;

  def.fields.forEach(f => {
    if (f.type === 'hidden') return;
    const val = node.data[f.key] || '';
    html += `<div class="wf-config-section">`;
    html += `<label class="wf-config-label">${f.label}</label>`;

    if (f.type === 'text') {
      html += `<input class="wf-config-input" data-field="${f.key}" value="${escapeAttr(val)}" placeholder="${f.placeholder || ''}" />`;
    } else if (f.type === 'textarea') {
      const rows = f.rows || 2;
      // JSON fields: headers, body, variables, idList, and anything labeled JSON
      const jsonKeys = ['headers', 'body', 'variables', 'idList', 'headersA', 'headersB'];
      const isJson = jsonKeys.includes(f.key) || f.label.toLowerCase().includes('json');
      if (isJson) {
        html += '<div class="json-editor">';
        html += '<div class="json-editor-toolbar">';
        html += '<span class="json-editor-status" data-json-status="' + f.key + '"></span>';
        html += '<button class="json-editor-fmt" data-json-fmt="' + f.key + '" title="Formatter (Ctrl+Shift+F)">{ }</button>';
        html += '</div>';
        html += `<textarea class="wf-config-textarea json-editor-textarea" data-field="${f.key}" placeholder="${f.placeholder || ''}" rows="${rows}" spellcheck="false">${escapeHtml(val)}</textarea>`;
        html += '</div>';
      } else {
        html += `<textarea class="wf-config-textarea" data-field="${f.key}" placeholder="${f.placeholder || ''}" rows="${rows}" spellcheck="false">${escapeHtml(val)}</textarea>`;
      }
    } else if (f.type === 'select') {
      html += `<select class="wf-config-select" data-field="${f.key}">`;
      (f.options || []).forEach(opt => {
        html += `<option value="${opt}" ${val === opt ? 'selected' : ''}>${opt}</option>`;
      });
      html += `</select>`;
    }
    html += `</div>`;
  });

  dom.configForm.innerHTML = html;

  // Wire JSON editors
  setupJsonEditors();

  // Add ctx template snippets for blocks that use expressions
  if (['http_request', 'raw_request', 'set_data', 'if_else'].includes(node.type)) {
    dom.configForm.innerHTML += renderCtxSnippets();
  }

  // Add examples for assert block
  if (node.type === 'assert') {
    dom.configForm.innerHTML += `
      <div class="wf-config-examples">
        <div class="wf-config-examples-title">
          <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z"/></svg>
          ctx.response
        </div>
        <div class="wf-config-example" data-expr="ctx.response.status_code === 200"><span class="wf-example-key">status_code</span> : number — Code HTTP</div>
        <div class="wf-config-example" data-expr="ctx.response.status_code >= 400"><span class="wf-example-key">status_code</span> : number — Erreur client/serveur</div>
        <div class="wf-config-example" data-expr='ctx.response.headers["content-type"].includes("application/json")'><span class="wf-example-key">headers</span> : object — Content-Type JSON</div>
        <div class="wf-config-example" data-expr='ctx.response.body.includes("success")'><span class="wf-example-key">body</span> : string — Contient "success"</div>
        <div class="wf-config-example" data-expr="JSON.parse(ctx.response.body).token !== undefined"><span class="wf-example-key">body</span> : string — Champ JSON "token" existe</div>
        <div class="wf-config-example" data-expr="ctx.response.status_code < 500"><span class="wf-example-key">status_code</span> : number — Pas d'erreur serveur</div>
        <div class="wf-config-example" data-expr="ctx.response.status_code === 201 || ctx.response.status_code === 200"><span class="wf-example-key">status_code</span> — 200 ou 201 accepté</div>
        <div class="wf-config-example" data-expr='ctx.response.headers["content-length"] > 0'><span class="wf-example-key">headers</span> — Body non vide</div>
        <div class="wf-config-example" data-expr='ctx.response.url.startsWith("https://")'><span class="wf-example-key">url</span> : string — URL en HTTPS</div>
      </div>
    `;

    // Click an example to fill the expression field (assert) or insert at cursor
    dom.configForm.querySelectorAll('.wf-config-example').forEach(el => {
      el.addEventListener('click', () => {
        if (node.type === 'assert') {
          const textarea = dom.configForm.querySelector('[data-field="expression"]');
          if (textarea) {
            textarea.value = el.dataset.expr;
            node.data.expression = el.dataset.expr;
            refreshNodeDisplay(node);
          }
        } else {
          const active = document.activeElement;
          if (active && active.closest('#wf-config-form') && (active.tagName === 'TEXTAREA' || active.tagName === 'INPUT')) {
            insertAtCursor(active, el.dataset.expr);
            const field = active.dataset.field;
            if (field) {
              node.data[field] = active.value;
              refreshNodeDisplay(node);
            }
          }
        }
      });
    });
  }

  // Bind changes
  dom.configForm.querySelectorAll('[data-field]').forEach(input => {
    const eventType = input.tagName === 'SELECT' ? 'change' : 'input';
    input.addEventListener(eventType, () => {
      node.data[input.dataset.field] = input.value;
      refreshNodeDisplay(node);
    });
  });
}

function refreshNodeDisplay(node) {
  const el = $(`#node-${node.id}`);
  if (!el) { renderNode(node); return; }
  el.remove();
  try {
    renderNode(node);
  } catch (e) {
    console.error('refreshNodeDisplay render failed', e);
    renderNode(node); // retry once
  }
  if (wf.selectedId === node.id) {
    const newEl = $(`#node-${node.id}`);
    if (newEl) newEl.classList.add('selected');
  }
  renderConnections();
}

// ─────────────────────────────────────────────
// CONNECTIONS RENDERING
// ─────────────────────────────────────────────
function cancelConnecting() {
  if (wf.connecting) {
    const fromEl = $(`#node-${wf.connecting.fromId}`);
    if (fromEl) {
      const port = fromEl.querySelector(`.wf-port[data-port-name="${wf.connecting.fromPort}"]`);
      if (port) port.classList.remove('connecting');
    }
  }
  wf.connecting = null;
  removeTempConnection();
  dom.canvasWrapper.classList.remove('connecting-mode');
}

function renderConnections() {
  let html = '';
  wf.connections.forEach((conn, idx) => {
    const fromEl = $(`#node-${conn.from}`);
    const toEl = $(`#node-${conn.to}`);
    if (!fromEl || !toEl) return;

    const fromPort = fromEl.querySelector(`.wf-port[data-port-name="${conn.fromPort}"]`);
    const toPort = toEl.querySelector(`.wf-port[data-port-name="${conn.toPort}"]`);
    if (!fromPort || !toPort) return;

    // SVG origin is the wrapper (stable), not the canvas (moves with pan)
    const wrapperRect = dom.canvasWrapper.getBoundingClientRect();
    const fp = fromPort.getBoundingClientRect();
    const tp = toPort.getBoundingClientRect();

    // Port screen positions already include pan+zoom via getBoundingClientRect
    const x1 = fp.left + fp.width / 2 - wrapperRect.left;
    const y1 = fp.top + fp.height / 2 - wrapperRect.top;
    const x2 = tp.left + tp.width / 2 - wrapperRect.left;
    const y2 = tp.top + tp.height / 2 - wrapperRect.top;
    const dy = Math.abs(y2 - y1);
    const cp = Math.max(40, dy * 0.4);

    let cls = 'wf-connection';
    if (conn.fromPort === 'out_true') cls += ' conn-true';
    else if (conn.fromPort === 'out_false') cls += ' conn-false';
    else if (conn.fromPort === 'out_body') cls += ' conn-body';
    else if (conn.fromPort === 'out_done') cls += ' conn-done';

    const selected = idx === wf.selectedConnIdx ? ' selected' : '';
    const d = `M${x1},${y1} C${x1},${y1 + cp} ${x2},${y2 - cp} ${x2},${y2}`;

    html += `<g class="wf-conn-group" data-conn-idx="${idx}">`;
    html += `<path class="wf-connection-hit" d="${d}" />`;
    html += `<path class="${cls}${selected}" d="${d}" />`;
    html += `</g>`;
  });
  dom.svgLayer.innerHTML = html;

  // Click handler on connections
  dom.svgLayer.querySelectorAll('.wf-connection-hit').forEach(hit => {
    hit.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(hit.parentElement.dataset.connIdx, 10);
      selectConnection(idx);
    });
  });
}

function renderTempConnection(x1, y1, x2, y2) {
  const dy = Math.abs(y2 - y1);
  const cp = Math.max(40, dy * 0.4);
  // Keep existing connections + add temp
  let existing = '';
  dom.svgLayer.querySelectorAll('.wf-connection').forEach(p => { existing += p.outerHTML; });
  dom.svgLayer.innerHTML = existing + `<path class="wf-connection-temp" d="M${x1},${y1} C${x1},${y1 + cp} ${x2},${y2 - cp} ${x2},${y2}" />`;
}

function removeTempConnection() {
  const temp = dom.svgLayer.querySelector('.wf-connection-temp');
  if (temp) temp.remove();
}

// ─────────────────────────────────────────────
// TOOLBAR
// ─────────────────────────────────────────────
function applyTransform() {
  dom.canvas.style.transform = `translate(${wf.panX}px, ${wf.panY}px) scale(${wf.zoom})`;
  dom.canvas.style.transformOrigin = '0 0';
}

function setZoom(z, cx, cy) {
  const wrapperRect = dom.canvasWrapper.getBoundingClientRect();
  // Default: zoom toward center of viewport
  if (cx === undefined || cy === undefined) {
    cx = wrapperRect.width / 2;
    cy = wrapperRect.height / 2;
  }
  const oldZoom = wf.zoom;
  wf.zoom = Math.max(0.3, Math.min(2, z));
  const scale = wf.zoom / oldZoom;
  wf.panX = cx - (cx - wf.panX) * scale;
  wf.panY = cy - (cy - wf.panY) * scale;
  applyTransform();
  dom.zoomLevel.textContent = Math.round(wf.zoom * 100) + '%';
  renderConnections();
}

function panBy(dx, dy) {
  wf.panX += dx;
  wf.panY += dy;
  applyTransform();
  renderConnections();
}

function setupToolbar() {
  dom.btnZoomIn.addEventListener('click', () => setZoom(wf.zoom + 0.1));
  dom.btnZoomOut.addEventListener('click', () => setZoom(wf.zoom - 0.1));
  dom.btnZoomFit.addEventListener('click', () => { wf.panX = 0; wf.panY = 0; setZoom(1); });
  dom.btnClear.addEventListener('click', clearCanvas);
  dom.btnClearLogs.addEventListener('click', clearLogs);
  dom.btnRun.addEventListener('click', runWorkflow);
  dom.btnStop.addEventListener('click', stopWorkflow);
}

function clearCanvas() {
  if (wf.nodes.length === 0) return;
  if (!confirm('Supprimer tous les blocs ?')) return;
  clearCanvasSilent();
}

function clearCanvasSilent() {
  wf.nodes = [];
  wf.connections = [];
  wf.selectedId = null;
  wf.selectedConnIdx = null;
  dom.canvas.querySelectorAll('.wf-node').forEach(el => el.remove());
  dom.svgLayer.innerHTML = '';
  selectNode(null);
  updateNodeCount();
}

function updateNodeCount() {
  dom.nodeCount.textContent = `${wf.nodes.length} bloc${wf.nodes.length !== 1 ? 's' : ''}`;
}

// ─────────────────────────────────────────────
// LOGS
// ─────────────────────────────────────────────
let logIdx = 0;

function addLog(msg, level = 'info') {
  logIdx++;
  const time = new Date().toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  const entry = document.createElement('div');
  entry.className = `wf-log-entry log-${level}`;
  entry.innerHTML = `<span class="log-time">${time}</span><span class="log-msg">${escapeHtml(msg)}</span>`;

  // Remove empty placeholder
  const placeholder = dom.logs.querySelector('.text-center');
  if (placeholder) placeholder.remove();

  dom.logs.appendChild(entry);
  dom.logs.scrollTop = dom.logs.scrollHeight;

  dom.logCount.textContent = logIdx;
  dom.logCount.classList.remove('hidden');
}

function clearLogs() {
  logIdx = 0;
  dom.logs.innerHTML = '<div class="text-gray-600 text-center py-8 text-xs">Aucun log pour l\'instant</div>';
  dom.logCount.classList.add('hidden');
}

// ─────────────────────────────────────────────
// WORKFLOW RUNNER
// ─────────────────────────────────────────────
let runAbort = false;

async function runWorkflow() {
  if (wf.running) return;
  wf.running = true;
  runAbort = false;

  dom.btnRun.classList.add('hidden');
  dom.btnStop.classList.remove('hidden');

  // Reset statuses
  wf.nodes.forEach(n => { n.status = null; setNodeStatus(n.id, null); });

  // Find start node
  const startNode = wf.nodes.find(n => n.type === 'start');
  if (!startNode) {
    addLog('Aucun bloc Start trouvé !', 'error');
    finishRun();
    return;
  }

  addLog('Démarrage du workflow…', 'step');

  const ctx = {}; // shared context for variables
  window.__wfCtx = ctx; // expose for context panel

  try {
    await executeNode(startNode.id, ctx);
    if (!runAbort) addLog('Workflow terminé avec succès', 'success');
  } catch (err) {
    addLog(`Erreur fatale : ${err.message}`, 'error');
  }

  finishRun();
}

function stopWorkflow() {
  runAbort = true;
  addLog('Workflow arrêté manuellement', 'warn');
  finishRun();
}

function finishRun() {
  wf.running = false;
  dom.btnRun.classList.remove('hidden');
  dom.btnStop.classList.add('hidden');
}

async function executeNode(nodeId, ctx) {
  if (runAbort) return;
  const node = wf.nodes.find(n => n.id === nodeId);
  if (!node) return;

  setNodeStatus(node.id, 'running');
  addLog(`▶ ${BLOCK_DEFS[node.type].label}${node.data.label ? ' — ' + node.data.label : ''}`, 'step');

  try {
    let nextPort = 'out'; // default

    switch (node.type) {
      case 'start':
        break;

      case 'sub_workflow': {
        const wfId = node.data.workflowId;
        if (!wfId) throw new Error('Sub-workflow: no workflowId configured');
        addLog(`▶ Sub-Workflow: ${node.data.workflowName || wfId}`, 'step');
        const swf = await fetch(`/api/workflows/${wfId}`, { headers: { ...getAuthHeader() } });
        if (!swf.ok) throw new Error(`Sub-workflow not found: ${wfId}`);
        const swfData = await swf.json();
        const graph = swfData.graph;
        // Execute sub-graph inline with shared ctx
        const subNodes = graph.nodes || [];
        const subConns = graph.connections || [];
        const startNode = subNodes.find(n => n.type === 'start');
        if (!startNode) throw new Error('Sub-workflow has no Start block');
        // Build lookup: orig id → real node data
        const subNodeMap = {};
        subNodes.forEach(n => { subNodeMap[n.id] = n; });
        // Find start's outgoing connection
        const nextConn = subConns.find(c => c.from === startNode.id && c.fromPort === 'out');
        if (nextConn) {
          const nextNode = subNodeMap[nextConn.to];
          if (nextNode) {
            // Execute sub-workflow nodes sequentially following the graph
            await executeSubWorkflowNode(nextNode, subNodeMap, subConns, ctx);
          }
        }
        addLog(`✓ Sub-Workflow terminé`, 'success');
        break;
      }

      case 'set_data': {
        try {
          const varsStr = interpolate(node.data.variables || '{}', ctx);
          const vars = JSON.parse(varsStr);
          const interpolatedVars = interpolateValue(vars, ctx);
          const saveTo = node.data.saveTo || '';
          if (saveTo) {
            ctx[saveTo] = interpolatedVars;
            addLog(`Dataset "${saveTo}" défini : ${Object.keys(interpolatedVars).join(', ')}`, 'info');
          } else {
            Object.assign(ctx, interpolatedVars);
            addLog(`Variables définies : ${Object.keys(interpolatedVars).join(', ')}`, 'info');
          }
        } catch (e) {
          throw new Error(`Set Data JSON invalide : ${e.message}`);
        }
        break;
      }

      case 'http_request': {
        const url = interpolate(node.data.url || '', ctx);
        const method = node.data.method || 'GET';
        let headers = {};
        try { headers = JSON.parse(interpolate(node.data.headers || '{}', ctx)); } catch {}
        let body = node.data.body || '';
        try {
          const parsedBody = JSON.parse(body);
          const interpolatedBody = interpolateValue(parsedBody, ctx);
          body = JSON.stringify(interpolatedBody);
        } catch {
          // If not JSON, interpolate as string
          body = interpolate(body, ctx);
        }

        addLog(`${method} ${url}`, 'info');
        const payload = { url, method };
        if (Object.keys(headers).length) payload.headers = headers;
        if (body) payload.body = body;

        const res = await fetch(API.structured, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        const responseData = data.response || data;
        const saveTo = node.data.saveTo || 'response';
        ctx[saveTo] = responseData;
        addLog(`← ${responseData.status_code || '?'} (sauvé dans ctx.${saveTo})`, responseData.status_code >= 400 ? 'warn' : 'info');
        break;
      }

      case 'raw_request': {
        const url = interpolate(node.data.url || '', ctx);
        const rawReq = interpolate(node.data.rawRequest || '', ctx);
        addLog(`RAW → ${url}`, 'info');

        const res = await fetch(API.raw, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
          body: JSON.stringify({ url, request: rawReq }),
        });
        const data = await res.json();
        const responseData = data.response || data;
        const saveTo = node.data.saveTo || 'response';
        ctx[saveTo] = responseData;
        addLog(`← ${responseData.status_code || '?'} (sauvé dans ctx.${saveTo})`, 'info');
        break;
      }

      case 'if_else': {
        const expr = interpolate(node.data.condition || 'true', ctx);
        let result;
        try { result = evalExpression(expr, ctx); } catch (e) { throw new Error(`If/Else erreur : ${e.message}`); }
        addLog(`Condition → ${result ? 'TRUE' : 'FALSE'}`, result ? 'success' : 'warn');
        nextPort = result ? 'out_true' : 'out_false';
        break;
      }

      case 'for_loop': {
        const iterations = parseInt(interpolate(node.data.iterations || '5', ctx), 10) || 1;
        const variable = node.data.variable || 'i';
        addLog(`Boucle : ${iterations} itérations (${variable})`, 'info');

        // Find body connection
        const bodyConn = wf.connections.find(c => c.from === node.id && c.fromPort === 'out_body');

        for (let i = 0; i < iterations && !runAbort; i++) {
          ctx[variable] = i;
          addLog(`  Itération ${i + 1}/${iterations}`, 'info');
          if (bodyConn) {
            await executeNode(bodyConn.to, ctx);
          }
        }
        // After loop, follow 'done'
        nextPort = 'out_done';
        break;
      }

      case 'delay': {
        const ms = parseInt(interpolate(node.data.ms || '1000', ctx), 10);
        addLog(`Pause ${ms}ms…`, 'info');
        await sleep(ms);
        break;
      }

      case 'assert': {
        const expr = interpolate(node.data.expression || 'true', ctx);
        let result;
        try { result = evalExpression(expr, ctx); } catch (e) { throw new Error(`Assert erreur : ${e.message}`); }
        const label = node.data.label || 'Assert';
        if (result) {
          addLog(`✓ ${label}`, 'success');
        } else {
          addLog(`✗ ${label}`, 'error');
          setNodeStatus(node.id, 'error');
          throw new Error(`Assertion échouée : ${label}`);
        }
        break;
      }

      case 'fuzz_params': {
        const wordlist = (node.data.wordlist || '').split('\n').map(l => l.trim()).filter(l => l);
        if (!wordlist.length) { addLog('Fuzz: wordlist vide', 'warn'); nextPort = 'out_done'; break; }
        addLog(`Fuzz: ${wordlist.length} iterations sur $FUZZ$`, 'step');

        const bodyConn = wf.connections.find(c => c.from === node.id && c.fromPort === 'out_body');
        if (!bodyConn) { addLog('Fuzz: branchez la sortie BODY a une requete', 'error'); nextPort = 'out_done'; break; }

        const allResults = [];
        for (const word of wordlist) {
          if (runAbort) break;
          ctx.fuzz = word;
          addLog(`  $FUZZ$="${word}" → execute`, 'info');
          try {
            await executeNode(bodyConn.to, ctx);
          } catch (e) {
            addLog(`  Erreur iteration "${word}": ${e.message}`, 'error');
          }
          if (ctx._lastResponse) {
            allResults.push({ word, status: ctx._lastResponse.status_code, body: (ctx._lastResponse.body || '').substring(0, 200) });
          }
        }
        ctx[node.data.saveTo || 'fuzz'] = { iterations: wordlist.length, results: allResults };
        addLog(`Fuzz termine : ${allResults.length}/${wordlist.length} requetes`, 'success');
        nextPort = 'out_done';
        break;
      }

      case 'bola_test': {
        const urlTpl = interpolate(node.data.url || '', ctx);
        const method = node.data.method || 'GET';
        let ids = [];
        try { ids = JSON.parse(interpolate(node.data.idList || '[]', ctx)); } catch {}
        const results = [];
        let reqHeaders = {};
        try { reqHeaders = JSON.parse(interpolate(node.data.headers || '{}', ctx)); } catch {}
        for (const id of ids) {
          const testUrl = urlTpl.replace(/\{\{id\}\}/g, id).replace(/\{\{ID\}\}/g, id);
          const res = await fetch(API.structured, { method:'POST', headers:{'Content-Type':'application/json',...getAuthHeader()}, body:JSON.stringify({url:testUrl, method, headers: reqHeaders}) });
          const data = await res.json();
          const sc = data.response?.status_code || 0;
          results.push({id, status:sc, body:data.response?.body?.substring(0,300)});
          const isVuln = sc === 200;
          addLog(`BOLA {{id}}=${id} → ${sc} ${isVuln ? '(VULN)' : ''}`, isVuln ? 'error' : 'info');
        }
        ctx[node.data.saveTo || 'bola'] = results;
        const hasVuln = results.some(r => r.status === 200);
        nextPort = hasVuln ? 'out_vuln' : 'out_safe';
        break;
      }

      case 'jwt_analyze': {
        const token = interpolate(node.data.token || '', ctx);
        const parts = token.split('.');
        if (parts.length !== 3) { addLog('JWT malformé', 'error'); break; }
        const decode = (p) => { try { return JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/'))); } catch { return null; } };
        const header = decode(parts[0]);
        const payload = decode(parts[1]);
        const now = Math.floor(Date.now()/1000);
        const analysis = {
          header, payload,
          expired: payload?.exp ? payload.exp < now : null,
          issuedAt: payload?.iat ? new Date(payload.iat*1000).toISOString() : null,
          expiresAt: payload?.exp ? new Date(payload.exp*1000).toISOString() : null,
          algorithm: header?.alg || 'unknown',
          isWeakAlg: ['none','HS256'].includes(header?.alg),
          hasSensitiveClaims: payload ? Object.keys(payload).filter(k => ['password','ssn','secret','credit'].some(s => k.toLowerCase().includes(s))) : [],
        };
        ctx[node.data.saveTo || 'jwt'] = analysis;
        addLog(`JWT: alg=${analysis.algorithm}, exp=${analysis.expiresAt||'none'}${analysis.isWeakAlg?' (WEAK)':''}`, analysis.isWeakAlg||analysis.expired?'warn':'success');
        break;
      }

      case 'response_diff': {
        const url = interpolate(node.data.url || '', ctx);
        const method = node.data.method || 'GET';
        let headersA = {}, headersB = {};
        try { headersA = JSON.parse(interpolate(node.data.headersA || '{}', ctx)); } catch {}
        try { headersB = JSON.parse(interpolate(node.data.headersB || '{}', ctx)); } catch {}
        const [resA, resB] = await Promise.all([
          fetch(API.structured, { method:'POST', headers:{'Content-Type':'application/json',...getAuthHeader()}, body:JSON.stringify({url, method, headers:headersA}) }),
          fetch(API.structured, { method:'POST', headers:{'Content-Type':'application/json',...getAuthHeader()}, body:JSON.stringify({url, method, headers:headersB}) }),
        ]);
        const [dataA, dataB] = await Promise.all([resA.json(), resB.json()]);
        const diff = {
          statusA: dataA.response?.status_code, statusB: dataB.response?.status_code,
          bodyLengthA: dataA.response?.body?.length, bodyLengthB: dataB.response?.body?.length,
          sameStatus: dataA.response?.status_code === dataB.response?.status_code,
          sameBody: dataA.response?.body === dataB.response?.body,
        };
        ctx[node.data.saveTo || 'diff'] = diff;
        addLog(`Diff: status ${diff.statusA} vs ${diff.statusB}, body ${diff.sameBody?'identical':'DIFFERS'}`, diff.sameBody&&diff.sameStatus?'info':'warn');
        nextPort = (diff.sameBody && diff.sameStatus) ? 'out_same' : 'out_diff';
        break;
      }

      case 'extract_replay': {
        const source = node.data.source || 'ctx.response.body';
        const regex = node.data.extractRegex || '';
        const url = interpolate(node.data.url || '', ctx);
        const method = node.data.method || 'GET';
        let sourceVal = ctx;
        for (const k of source.replace('ctx.', '').split('.')) { if (sourceVal) sourceVal = sourceVal[k]; }
        sourceVal = typeof sourceVal === 'string' ? sourceVal : JSON.stringify(sourceVal||'');
        let extracted = null;
        if (regex) {
          const m = sourceVal.match(new RegExp(regex));
          extracted = m ? m[1] || m[0] : null;
        }
        if (extracted) {
          const replayUrl = url.replace(/\{\{extracted\}\}/g, extracted);
          let replayHeaders = {};
          try { replayHeaders = JSON.parse(interpolate(node.data.headers || '{}', ctx)); } catch {}
          const res = await fetch(API.structured, { method:'POST', headers:{'Content-Type':'application/json',...getAuthHeader()}, body:JSON.stringify({url:replayUrl, method, headers: replayHeaders}) });
          const data = await res.json();
          ctx[node.data.saveTo || 'replay'] = {extracted, url:replayUrl, response:data.response};
          addLog(`Extract "${extracted}" → ${method} ${replayUrl} → ${data.response?.status_code||'?'}`, 'success');
        } else {
          addLog('Extract: aucun match regex', 'warn');
        }
        break;
      }
    }

    setNodeStatus(node.id, 'success');

    // Follow connections (skip for_loop body — already handled)
    if (node.type === 'for_loop') {
      const doneConn = wf.connections.find(c => c.from === node.id && c.fromPort === 'out_done');
      if (doneConn) await executeNode(doneConn.to, ctx);
    } else {
      const nextConns = wf.connections.filter(c => c.from === node.id && c.fromPort === nextPort);
      for (const conn of nextConns) {
        await executeNode(conn.to, ctx);
      }
    }

  } catch (err) {
    setNodeStatus(node.id, 'error');
    throw err;
  }
}

async function executeSubWorkflowNode(nodeData, nodeMap, connections, ctx) {
  // Execute a node from a sub-workflow graph using the same logic as executeNode
  // nodeData: { id, type, data: {...} }
  const type = nodeData.type;
  const data = nodeData.data || {};
  if (runAbort) return;
  if (type === 'start') return; // skip start in sub-execution

  addLog(`  [sub] ▶ ${BLOCK_DEFS[type]?.label || type}`, 'info');

  let nextPort = 'out';

  // Simplified execution — handles the main block types
  if (type === 'http_request') {
    const url = interpolate(data.url || '', ctx);
    const method = data.method || 'GET';
    let headers = {};
    try { headers = JSON.parse(interpolate(data.headers || '{}', ctx)); } catch {}
    let body = data.body || '';
    const payload = { url, method };
    if (Object.keys(headers).length) payload.headers = headers;
    if (body) payload.body = body;
    const res = await fetch(API.structured, { method: 'POST', headers: { 'Content-Type': 'application/json', ...getAuthHeader() }, body: JSON.stringify(payload) });
    const respData = await res.json();
    const responseData = respData.response || respData;
    ctx[data.saveTo || 'response'] = responseData;
  } else if (type === 'set_data') {
    try {
      const varsStr = interpolate(data.variables || '{}', ctx);
      const vars = JSON.parse(varsStr);
      const saveTo = data.saveTo || '';
      if (saveTo) { ctx[saveTo] = vars; } else { Object.assign(ctx, vars); }
    } catch {}
  } else if (type === 'if_else') {
    const expr = interpolate(data.condition || 'true', ctx);
    let result = true;
    try { result = evalExpression(expr, ctx); } catch {}
    nextPort = result ? 'out_true' : 'out_false';
  } else if (type === 'delay') {
    const ms = parseInt(interpolate(data.ms || '1000', ctx), 10);
    await sleep(ms);
  } else if (type === 'assert') {
    const expr = interpolate(data.expression || 'true', ctx);
    let result = true;
    try { result = evalExpression(expr, ctx); } catch {}
    if (!result) throw new Error(`Sub-workflow assertion failed: ${data.label || expr}`);
  }

  // Follow connections
  const nextConns = connections.filter(c => c.from === nodeData.id && c.fromPort === nextPort);
  for (const conn of nextConns) {
    const nextNode = nodeMap[conn.to];
    if (nextNode) await executeSubWorkflowNode(nextNode, nodeMap, connections, ctx);
  }
}

function setNodeStatus(id, status) {
  const el = $(`#node-${id}`);
  if (!el) return;
  el.classList.remove('running', 'success', 'error');
  if (status) el.classList.add(status);

  const dot = $(`#status-${id}`);
  if (dot) {
    dot.style.background = status === 'running' ? '#facc15' : status === 'success' ? '#4ade80' : status === 'error' ? '#f87171' : 'transparent';
  }
}

// ─────────────────────────────────────────────
// EXPRESSION EVAL & TEMPLATE
// ─────────────────────────────────────────────
function interpolate(str, ctx) {
  return str.replace(/\{\{(ctx\.)?(\w+(?:\.\w+)*)\}\}/g, (_, ctxPrefix, path) => {
    let val = ctx;
    for (const key of path.split('.')) {
      if (val == null) return '';
      val = val[key];
    }
    return val != null ? String(val) : '';
  });
}

function interpolateValue(value, ctx) {
  if (typeof value === 'string') {
    return interpolate(value, ctx);
  } else if (Array.isArray(value)) {
    return value.map(v => interpolateValue(v, ctx));
  } else if (value && typeof value === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = interpolateValue(v, ctx);
    }
    return result;
  } else {
    return value;
  }
}

function evalExpression(expr, ctx) {
  // Reject dangerous patterns — defense-in-depth against stored XSS
  if (!expr || typeof expr !== 'string' || expr.length > 512) {
    throw new Error('Expression invalide');
  }
  if (/[`$<>]|=>|\\u[0-9a-fA-F]{4}|(?:\b(?:eval|Function|constructor|__proto__|import|require|fetch|XMLHttpRequest|document|window|self|top|parent|alert|prompt|confirm|setTimeout|setInterval|location|open|close|write|writeln|execScript|execCommand|expression|chrome|browser|process|global|globalThis)\b)/i.test(expr)) {
    throw new Error('Expression contient un motif interdit');
  }
  const fn = new Function('ctx', `with(ctx) { return (${expr}); }`);
  return fn(ctx);
}

// ─────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────
// ── JSON Editor helpers ──

function setupJsonEditors() {
  // Format buttons
  dom.configForm.querySelectorAll('.json-editor-fmt').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.jsonFmt;
      const textarea = dom.configForm.querySelector(`textarea[data-field="${key}"]`);
      if (!textarea) return;
      formatJsonTextarea(textarea, key);
    });
  });

  // Validate on input + keyboard shortcut + auto-pairing
  dom.configForm.querySelectorAll('.json-editor-textarea').forEach(textarea => {
    const key = textarea.dataset.field;
    let debounce;
    textarea.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => validateJsonField(key), 400);
    });
    textarea.addEventListener('blur', () => validateJsonField(key));
    textarea.addEventListener('keydown', (e) => {
      // Auto-pair brackets, braces, quotes
      if (handleAutoPair(textarea, e)) return;
      // Ctrl+Shift+F → format
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
        e.preventDefault();
        formatJsonTextarea(textarea, key);
      }
    });
    // Initial validation
    validateJsonField(key);
  });
}

// ── Auto-pair: insert closing bracket/quote, wrap selection ──

const AUTO_PAIRS = { '{': '}', '[': ']', '(': ')', '"': '"', "'": "'" };

function handleAutoPair(textarea, e) {
  const pair = AUTO_PAIRS[e.key];
  if (!pair) return false;

  e.preventDefault();
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const val = textarea.value;
  const hasSelection = start !== end;

  if (hasSelection) {
    // Wrap selection: "hello" → {"hello"}
    const wrapped = e.key + val.substring(start, end) + pair;
    textarea.setRangeText(wrapped, start, end, 'select');
    textarea.selectionStart = start + 1;
    textarea.selectionEnd = start + wrapped.length - 1;
  } else if (e.key === pair) {
    // Same char for open/close (quotes): if next char is same quote, just move cursor
    if (val.charAt(start) === pair) {
      textarea.selectionStart = textarea.selectionEnd = start + 1;
      return true;
    }
    // Insert pair and place cursor inside
    textarea.setRangeText(e.key + pair, start, start, 'end');
    textarea.selectionStart = textarea.selectionEnd = start + 1;
  } else {
    // Brackets/braces: always insert pair and place cursor inside
    textarea.setRangeText(e.key + pair, start, start, 'end');
    textarea.selectionStart = textarea.selectionEnd = start + 1;
  }
  textarea.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
}

function validateJsonField(key) {
  const textarea = dom.configForm.querySelector(`textarea[data-field="${key}"]`);
  if (!textarea) return;
  const val = textarea.value.trim();
  if (!val) { updateJsonStatus(key, 'empty'); return; }
  try { JSON.parse(val); updateJsonStatus(key, 'ok'); } catch { updateJsonStatus(key, 'err'); }
}

function updateJsonStatus(key, state) {
  const status = document.querySelector(`[data-json-status="${key}"]`);
  if (!status) return;
  status.className = 'json-editor-status';
  if (state === 'ok') { status.textContent = '✓'; status.classList.add('ok'); }
  else if (state === 'err') { status.textContent = '✗'; status.classList.add('err'); }
  else { status.textContent = ''; }
}

function formatJsonTextarea(textarea, statusKey) {
  try {
    const parsed = JSON.parse(textarea.value);
    textarea.value = JSON.stringify(parsed, null, 2);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
    updateJsonStatus(statusKey, 'ok');
  } catch {
    updateJsonStatus(statusKey, 'err');
  }
}

function validateJsonFieldById(textareaId) {
  const textarea = document.getElementById(textareaId);
  if (!textarea) return;
  const val = textarea.value.trim();
  if (!val) { updateJsonStatus(textareaId, 'empty'); return; }
  try { JSON.parse(val); updateJsonStatus(textareaId, 'ok'); } catch { updateJsonStatus(textareaId, 'err'); }
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function escapeAttr(s) {
  return (s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

function truncate(s, max) {
  if (!s) return '';
  return s.length > max ? s.substring(0, max - 1) + '…' : s;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
init();
