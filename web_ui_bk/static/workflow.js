/* ═══════════════════════════════════════════════════════════════
   ReqVault — Workflow Builder Engine
   Visual no-code API test workflow editor
   ═══════════════════════════════════════════════════════════════ */

const API = {
  structured: '/api/request',
  raw: '/api/raw-request',
};

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
      { key: 'url', label: 'URL', type: 'text', placeholder: 'https://api.example.com/...' },
      { key: 'headers', label: 'Headers (JSON)', type: 'textarea', placeholder: '{ "Authorization": "Bearer {{token}}" }' },
      { key: 'body', label: 'Body', type: 'textarea', placeholder: '{ "key": "value" }' },
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
      { key: 'variables', label: 'Variables (JSON)', type: 'textarea', placeholder: '{ "token": "abc123", "userId": 42 }' },
    ],
  },
  if_else: {
    label: 'If / Else', color: 'amber', icon: 'condition',
    ports: { in: ['in'], out: ['out_true', 'out_false'] },
    fields: [
      { key: 'condition', label: 'Condition (JS)', type: 'textarea', placeholder: 'ctx.response.statusCode === 200' },
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
      { key: 'expression', label: 'Expression (JS)', type: 'textarea', placeholder: 'ctx.response.statusCode === 200' },
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
};

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
const wf = {
  nodes: [],           // [{ id, type, x, y, data:{}, status:null }]
  connections: [],     // [{ from, fromPort, to, toPort }]
  selectedId: null,
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
};

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
function init() {
  setupPanelTabs();
  setupPaletteDrag();
  setupCanvasInteractions();
  setupToolbar();
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
  $$('.wf-palette-item').forEach(item => {
    item.addEventListener('dragstart', (e) => {
      e.dataTransfer.setData('block-type', item.dataset.blockType);
      e.dataTransfer.effectAllowed = 'copy';
    });
  });

  dom.canvasWrapper.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });

  dom.canvasWrapper.addEventListener('drop', (e) => {
    e.preventDefault();
    const type = e.dataTransfer.getData('block-type');
    if (!type || !BLOCK_DEFS[type]) return;
    const rect = dom.canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / wf.zoom;
    const y = (e.clientY - rect.top) / wf.zoom;
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
// RENDER NODE
// ─────────────────────────────────────────────
function renderNode(node) {
  const def = BLOCK_DEFS[node.type];
  const colors = COLOR_MAP[def.color];
  const el = document.createElement('div');
  el.className = 'wf-node';
  el.id = `node-${node.id}`;
  el.style.left = node.x + 'px';
  el.style.top = node.y + 'px';

  // Summary text
  let summary = '';
  if (node.type === 'http_request') summary = `${node.data.method || 'GET'} ${truncate(node.data.url, 22)}`;
  else if (node.type === 'raw_request') summary = truncate(node.data.url, 28);
  else if (node.type === 'set_data') summary = truncate(node.data.variables, 28);
  else if (node.type === 'if_else') summary = truncate(node.data.condition, 28);
  else if (node.type === 'for_loop') summary = `${node.data.iterations || 5}x — ${node.data.variable || 'i'}`;
  else if (node.type === 'delay') summary = `${node.data.ms || 1000}ms`;
  else if (node.type === 'assert') summary = truncate(node.data.label || node.data.expression, 28);

  el.innerHTML = `
    <button class="wf-node-delete" data-delete="${node.id}">
      <svg class="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
    <div class="wf-node-header">
      <div class="wf-node-icon" style="background:${colors.bg}; color:${colors.text}">
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">${ICON_SVG[def.icon]}</svg>
      </div>
      <span class="wf-node-title">${def.label}</span>
      <div class="wf-node-status" id="status-${node.id}"></div>
    </div>
    ${summary ? `<div class="wf-node-body">${escapeHtml(summary)}</div>` : ''}
  `;

  // Ports
  const portDefs = def.ports;
  portDefs.in.forEach(pName => {
    const port = createPort('in', pName, node.id);
    el.appendChild(port);
  });
  portDefs.out.forEach(pName => {
    const port = createPort('out', pName, node.id);
    el.appendChild(port);
  });

  // Events
  el.addEventListener('mousedown', (e) => {
    if (e.target.closest('.wf-port') || e.target.closest('.wf-node-delete')) return;
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

  dom.canvas.appendChild(el);
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
    }
  });

  // Delete on key
  document.addEventListener('keydown', (e) => {
    if ((e.key === 'Delete' || e.key === 'Backspace') && wf.selectedId && !e.target.closest('input, textarea, select')) {
      removeNode(wf.selectedId);
    }
  });
}

// ─────────────────────────────────────────────
// SELECT / REMOVE NODE
// ─────────────────────────────────────────────
function selectNode(id) {
  wf.selectedId = id;
  $$('.wf-node').forEach(el => el.classList.toggle('selected', el.id === `node-${id}`));
  renderConfigPanel(id);
}

function removeNode(id) {
  wf.nodes = wf.nodes.filter(n => n.id !== id);
  wf.connections = wf.connections.filter(c => c.from !== id && c.to !== id);
  const el = $(`#node-${id}`);
  if (el) el.remove();
  if (wf.selectedId === id) selectNode(null);
  renderConnections();
  updateNodeCount();
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
    <div class="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
      <div class="wf-node-icon" style="background:${colors.bg};color:${colors.text}">
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">${ICON_SVG[def.icon]}</svg>
      </div>
      <div>
        <div class="text-xs font-semibold text-white">${def.label}</div>
        <div class="text-[10px] text-gray-600 font-mono">${node.id}</div>
      </div>
    </div>
  `;

  def.fields.forEach(f => {
    const val = node.data[f.key] || '';
    html += `<div class="wf-config-section">`;
    html += `<label class="wf-config-label">${f.label}</label>`;

    if (f.type === 'text') {
      html += `<input class="wf-config-input" data-field="${f.key}" value="${escapeAttr(val)}" placeholder="${f.placeholder || ''}" />`;
    } else if (f.type === 'textarea') {
      html += `<textarea class="wf-config-textarea" data-field="${f.key}" placeholder="${f.placeholder || ''}" rows="3">${escapeHtml(val)}</textarea>`;
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
  if (!el) return;
  el.remove();
  renderNode(node);
  if (wf.selectedId === node.id) {
    $(`#node-${node.id}`).classList.add('selected');
  }
  renderConnections();
}

// ─────────────────────────────────────────────
// CONNECTIONS RENDERING
// ─────────────────────────────────────────────
function renderConnections() {
  let svg = '';
  wf.connections.forEach(conn => {
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

    svg += `<path class="${cls}" d="M${x1},${y1} C${x1},${y1 + cp} ${x2},${y2 - cp} ${x2},${y2}" />`;
  });
  dom.svgLayer.innerHTML = svg;
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
  wf.nodes = [];
  wf.connections = [];
  wf.selectedId = null;
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

      case 'set_data': {
        try {
          const vars = JSON.parse(interpolate(node.data.variables || '{}', ctx));
          Object.assign(ctx, vars);
          addLog(`Variables définies : ${Object.keys(vars).join(', ')}`, 'info');
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
        const body = interpolate(node.data.body || '', ctx);

        addLog(`${method} ${url}`, 'info');
        const payload = { url, method };
        if (Object.keys(headers).length) payload.headers = headers;
        if (body) payload.body = body;

        const res = await fetch(API.structured, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        const saveTo = node.data.saveTo || 'response';
        ctx[saveTo] = data;
        addLog(`← ${data.statusCode || '?'} (sauvé dans ctx.${saveTo})`, data.statusCode >= 400 ? 'warn' : 'info');
        break;
      }

      case 'raw_request': {
        const url = interpolate(node.data.url || '', ctx);
        const rawReq = interpolate(node.data.rawRequest || '', ctx);
        addLog(`RAW → ${url}`, 'info');

        const res = await fetch(API.raw, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, rawRequest: rawReq }),
        });
        const data = await res.json();
        const saveTo = node.data.saveTo || 'response';
        ctx[saveTo] = data;
        addLog(`← ${data.statusCode || '?'} (sauvé dans ctx.${saveTo})`, 'info');
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
  return str.replace(/\{\{(\w+(?:\.\w+)*)\}\}/g, (_, path) => {
    let val = ctx;
    for (const key of path.split('.')) {
      if (val == null) return '';
      val = val[key];
    }
    return val != null ? String(val) : '';
  });
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
