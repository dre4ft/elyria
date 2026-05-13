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
  condition: '<path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z"/>',
  loop:      '<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 12c0-1.232-.046-2.453-.138-3.662a4.006 4.006 0 00-3.7-3.7 48.678 48.678 0 00-7.324 0 4.006 4.006 0 00-3.7 3.7c-.017.22-.032.441-.046.662M19.5 12l3-3m-3 3l-3-3m-12 3c0 1.232.046 2.453.138 3.662a4.006 4.006 0 003.7 3.7 48.656 48.656 0 007.324 0 4.006 4.006 0 003.7-3.7c.017-.22.032-.441.046-.662M4.5 12l3 3m-3-3l-3 3"/>',
  clock:     '<path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/>',
  check:     '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 016 0z"/>',
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
  btnRun:        $('#btn-run-workflow'),
  btnStop:       $('#btn-stop-workflow'),
  btnClear:      $('#btn-clear-canvas'),
  btnClearLogs:  $('#btn-clear-logs'),
  btnZoomIn:     $('#btn-zoom-in'),
  btnZoomOut:    $('#btn-zoom-out'),
  btnZoomFit:    $('#btn-zoom-fit'),
  btnSave:       $('#btn-save-workflow'),
  btnLoad:       $('#btn-load-workflow'),
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
  loadWfTeamFilter();
  loadWfSaveTeams();
  loadSavedRequests();
  loadSavedWorkflows();
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
        openLoadModal();
      });
      dom.loadList.appendChild(item);
    });
  } catch (e) {
    dom.loadList.innerHTML = '<div class="text-xs text-red-400 text-center py-8">Erreur de chargement</div>';
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
    selectNode(node.id);
    wf.dragging = {
      nodeId: node.id,
      offsetX: e.clientX / wf.zoom - node.x,
      offsetY: e.clientY / wf.zoom - node.y,
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

  // Drag to connect
  port.addEventListener('mousedown', (e) => {
    e.stopPropagation();
    if (dir === 'out') {
      const rect = port.getBoundingClientRect();
      const canvasRect = dom.canvas.getBoundingClientRect();
      wf.connecting = {
        fromId: nodeId,
        fromPort: portName,
        startX: (rect.left + rect.width / 2 - canvasRect.left) / wf.zoom,
        startY: (rect.top + rect.height / 2 - canvasRect.top) / wf.zoom,
      };
    }
  });

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
      const canvasRect = dom.canvas.getBoundingClientRect();
      node.x = Math.round(((e.clientX - canvasRect.left) / wf.zoom - wf.dragging.offsetX + wf.dragging.offsetX) / 24) * 24;
      node.x = Math.round((e.clientX / wf.zoom - wf.dragging.offsetX));
      node.y = Math.round((e.clientY / wf.zoom - wf.dragging.offsetY));
      // Snap
      node.x = Math.round(node.x / 24) * 24;
      node.y = Math.round(node.y / 24) * 24;
      const el = $(`#node-${node.id}`);
      if (el) {
        el.style.left = node.x + 'px';
        el.style.top = node.y + 'px';
      }
      renderConnections();
    }

    // Connection drawing
    if (wf.connecting) {
      const canvasRect = dom.canvas.getBoundingClientRect();
      const mx = (e.clientX - canvasRect.left) / wf.zoom;
      const my = (e.clientY - canvasRect.top) / wf.zoom;
      renderTempConnection(wf.connecting.startX, wf.connecting.startY, mx, my);
    }
  });

  document.addEventListener('mouseup', (e) => {
    if (wf.connecting) {
      // Check if dropped on an input port
      const target = e.target.closest('.wf-port[data-port-dir="in"]');
      if (target) {
        const toId = target.dataset.nodeId;
        const toPort = target.dataset.portName;
        if (toId !== wf.connecting.fromId) {
          // Remove existing connection to this input
          wf.connections = wf.connections.filter(c => !(c.to === toId && c.toPort === toPort));
          wf.connections.push({
            from: wf.connecting.fromId,
            fromPort: wf.connecting.fromPort,
            to: toId,
            toPort: toPort,
          });
        }
      }
      wf.connecting = null;
      removeTempConnection();
      renderConnections();
    }
    wf.dragging = null;
  });

  // Deselect on canvas click
  dom.canvas.addEventListener('mousedown', (e) => {
    if (e.target === dom.canvas) {
      selectNode(null);
      selectConnection(null);
    }
  });

  // Delete on key
  document.addEventListener('keydown', (e) => {
    if ((e.key === 'Delete' || e.key === 'Backspace') && !e.target.closest('input, textarea, select')) {
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
      html += `<textarea class="wf-config-textarea" data-field="${f.key}" placeholder="${f.placeholder || ''}" rows="${rows}">${escapeHtml(val)}</textarea>`;
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
function renderConnections() {
  let html = '';
  wf.connections.forEach((conn, idx) => {
    const fromEl = $(`#node-${conn.from}`);
    const toEl = $(`#node-${conn.to}`);
    if (!fromEl || !toEl) return;

    const fromPort = fromEl.querySelector(`.wf-port[data-port-name="${conn.fromPort}"]`);
    const toPort = toEl.querySelector(`.wf-port[data-port-name="${conn.toPort}"]`);
    if (!fromPort || !toPort) return;

    const canvasRect = dom.canvas.getBoundingClientRect();
    const fp = fromPort.getBoundingClientRect();
    const tp = toPort.getBoundingClientRect();

    const x1 = (fp.left + fp.width / 2 - canvasRect.left) / wf.zoom;
    const y1 = (fp.top + fp.height / 2 - canvasRect.top) / wf.zoom;
    const x2 = (tp.left + tp.width / 2 - canvasRect.left) / wf.zoom;
    const y2 = (tp.top + tp.height / 2 - canvasRect.top) / wf.zoom;

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
function setupToolbar() {
  dom.btnZoomIn.addEventListener('click', () => setZoom(wf.zoom + 0.1));
  dom.btnZoomOut.addEventListener('click', () => setZoom(wf.zoom - 0.1));
  dom.btnZoomFit.addEventListener('click', () => setZoom(1));
  dom.btnClear.addEventListener('click', clearCanvas);
  dom.btnClearLogs.addEventListener('click', clearLogs);
  dom.btnRun.addEventListener('click', runWorkflow);
  dom.btnStop.addEventListener('click', stopWorkflow);
}

function setZoom(z) {
  wf.zoom = Math.max(0.3, Math.min(2, z));
  dom.canvas.style.transform = `scale(${wf.zoom})`;
  dom.canvas.style.transformOrigin = 'top left';
  dom.zoomLevel.textContent = Math.round(wf.zoom * 100) + '%';
  renderConnections();
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
        for (const id of ids) {
          const testUrl = urlTpl.replace(/\{\{id\}\}/g, id).replace(/\{\{ID\}\}/g, id);
          const res = await fetch(API.structured, { method:'POST', headers:{'Content-Type':'application/json',...getAuthHeader()}, body:JSON.stringify({url:testUrl, method}) });
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
          const res = await fetch(API.structured, { method:'POST', headers:{'Content-Type':'application/json',...getAuthHeader()}, body:JSON.stringify({url:replayUrl, method}) });
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
  const fn = new Function('ctx', `with(ctx) { return (${expr}); }`);
  return fn(ctx);
}

// ─────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────
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
