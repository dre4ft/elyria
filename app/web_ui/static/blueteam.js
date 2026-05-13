/* Blue Team — SSDLC Security Analysis UI */

const API = {
  profiles: '/api/blueteam/profiles',
  profile: (id) => `/api/blueteam/profiles/${id}`,
  profileStatus: (id) => `/api/blueteam/profiles/${id}/status`,
  analyze: (pid) => `/api/blueteam/profiles/${pid}/analyze`,
  reports: (pid) => `/api/blueteam/profiles/${pid}/reports`,
  reportDownload: (rid) => `/api/blueteam/reports/${rid}/download`,
};

const $ = s => document.querySelector(s);
const esc = s => { const d = document.createElement('div'); d.textContent = s||''; return d.innerHTML; };

let state = { profiles: [], activePid: null, _pollTimer: null, teamFilter: '' };

const dom = {
  profileList: $('#bt-profile-list'),
  btnNewProfile: $('#btn-new-profile'),
  btnCreateFirst: $('#btn-create-first'),
  btnRunAnalysis: $('#btn-run-analysis'),
  empty: $('#bt-empty'),
  content: $('#bt-content'),
  profileName: $('#bt-profile-name'),
  profileTarget: $('#bt-profile-target'),
  statusBadge: $('#bt-status-badge'),
  proModelBadge: $('#bt-pro-model-badge'),
  progressContainer: $('#bt-progress-container'),
  progressBar: $('#bt-progress-bar'),
  progressPct: $('#bt-progress-pct'),
  progressMsg: $('#bt-progress-msg'),
  liveProgress: $('#bt-live-progress'),
  liveMsg: $('#bt-live-msg'),
  livePct: $('#bt-live-pct'),
  liveBar: $('#bt-live-bar'),
  reportEmpty: $('#bt-report-empty'),
  reportRendered: $('#bt-report-rendered'),
};

let editingProfileId = null;

// ── Init ──
function init() {
  if(window.__btInit) return;
  window.__btInit = true;
  initAuth();
  const u = getUser();
  if(u) { $('#header-username').textContent = u.username||u.userId; $('#header-username').classList.remove('hidden'); }
  setupButtons();
  setupOpenAPIDrop();
  loadProfiles().then(() => {
    // Auto-select profile if ?profile=xxx in URL
    const params = new URLSearchParams(window.location.search);
    const pid = params.get('profile');
    if (pid) { selectProfile(pid); window.history.replaceState({}, '', '/blueteam'); }
  });
}

function setupButtons() {
  dom.btnNewProfile.addEventListener('click', () => openProfileModal());
  dom.btnCreateFirst.addEventListener('click', () => openProfileModal());
  if($('#btn-bt-modal-ok')) $('#btn-bt-modal-ok').addEventListener('click', () => createProfile());
  dom.btnRunAnalysis.addEventListener('click', () => { if(state.activePid) startAnalysis(); });
  const btnStop = $('#btn-stop-analysis');
  if(btnStop) btnStop.addEventListener('click', () => { if(state.activePid) stopAnalysis(); });
  // Edit / Delete
  const btnEdit = $('#btn-edit-profile');
  if(btnEdit) btnEdit.addEventListener('click', () => {
    const p = state.profiles.find(x => x.profile_id === state.activePid);
    if(p) openProfileModal(p);
  });
  const btnDelete = $('#btn-delete-profile');
  if(btnDelete) btnDelete.addEventListener('click', () => {
    if(!state.activePid) return;
    if(!confirm('Supprimer ce profil et tous ses rapports ?')) return;
    deleteProfile(state.activePid);
  });
  // Sidebar toggle
  const btnToggle = $('#btn-toggle-sidebar');
  if(btnToggle) btnToggle.addEventListener('click', toggleSidebar);
  // Team filter
  const teamFilter = $('#bt-team-filter');
  if(teamFilter) {
    loadTeamsForFilter();
    teamFilter.addEventListener('change', () => {
      state.teamFilter = teamFilter.value;
      loadProfiles();
    });
  }
}

async function loadTeamsForFilter() {
  const sel = $('#bt-team-filter'); if(!sel) return;
  try {
    const r = await fetch('/api/teams', {headers:{...getAuthHeader()}});
    if(!r.ok) return;
    const teams = await r.json();
    teams.forEach(t => { sel.innerHTML += `<option value="${t.team_id}">${esc(t.name)}</option>`; });
  } catch {}
}

// ── Sidebar ──
function toggleSidebar() {
  const sidebar = document.getElementById('bt-sidebar');
  if(!sidebar) return;
  const collapsed = sidebar.dataset.collapsed === 'true';
  sidebar.dataset.collapsed = collapsed ? 'false' : 'true';
}

// ── Profiles ──
async function loadProfiles() {
  let url = API.profiles;
  if(state.teamFilter) url += `?team_id=${encodeURIComponent(state.teamFilter)}`;
  const res = await fetch(url, { headers: {...getAuthHeader()} });
  if(!res.ok) return;
  state.profiles = await res.json();
  renderProfileList();
  return state.profiles;
}

function renderProfileList() {
  dom.profileList.innerHTML = '';
  state.profiles.forEach(p => {
    const el = document.createElement('div');
    const statusColors = {pending:'bg-gray-500',running:'bg-yellow-400 animate-pulse',completed:'bg-green-400',stopped:'bg-orange-400',failed:'bg-red-400'};
    const dot = statusColors[p.status] || 'bg-gray-500';
    const isPentest = p.source_type === 'pentest';
    const redIcon = isPentest ? '<span class="flex-shrink-0 text-[10px] mr-0.5" title="Importe depuis Red Team">🔴</span>' : '';
    el.className = 'profile-item' + (p.profile_id===state.activePid ? ' active' : '');
    el.innerHTML = `<span class="flex items-center gap-2 min-w-0 flex-1"><span class="w-2 h-2 rounded-full flex-shrink-0 ${dot}"></span>${redIcon}<span class="text-xs text-gray-300 truncate">${esc(p.name)}</span></span>
      <span class="text-[9px] text-gray-600 font-mono flex-shrink-0">${(p.target_url||'').substring(0,25)}</span>`;
    el.style.cssText = 'display:flex;align-items:center;gap:.5rem;padding:.5rem .625rem;border-radius:.5rem;cursor:pointer;transition:all .15s;border:1px solid transparent;';
    el.addEventListener('click', () => selectProfile(p.profile_id));
    dom.profileList.appendChild(el);
  });
}

async function selectProfile(pid) {
  state.activePid = pid;
  renderProfileList();
  const res = await fetch(API.profile(pid), { headers: {...getAuthHeader()} });
  if(!res.ok) return;
  const p = await res.json();
  dom.empty.classList.add('hidden');
  dom.content.classList.remove('hidden');
  dom.profileName.textContent = p.name;
  dom.profileTarget.textContent = p.target_url;
  updateStatusBadge(p.status);
  if(p.pro_model) { dom.proModelBadge.classList.remove('hidden'); dom.proModelBadge.textContent = p.pro_model; }
  // Toggle run/stop buttons + progress
  const btnRun = $('#btn-run-analysis');
  const btnStop = $('#btn-stop-analysis');
  if(p.status === 'running') {
    if(btnRun) btnRun.classList.add('hidden');
    if(btnStop) btnStop.classList.remove('hidden');
    dom.liveProgress.classList.remove('hidden');
    const pct = p.scan_progress || 0;
    dom.livePct.textContent = pct + '%';
    dom.liveBar.style.width = pct + '%';
    dom.liveMsg.textContent = p.progress_msg || 'Analyse en cours...';
  } else {
    dom.liveProgress.classList.add('hidden');
    if(btnRun) btnRun.classList.remove('hidden');
    if(btnStop) btnStop.classList.add('hidden');
  }
  // Load latest report
  if(p.reports && p.reports.length > 0) {
    renderReport(p.reports[0]);
  } else {
    const content = $('#bt-report-content');
    if(content) content.classList.add('hidden');
    dom.reportEmpty.classList.remove('hidden');
  }
  if(p.status === 'running' && !state._pollTimer) connectSSE(pid);
}

async function deleteProfile(pid) {
  await fetch(API.profile(pid), { method:'DELETE', headers:{...getAuthHeader()} });
  if(state.activePid === pid) {
    state.activePid = null;
    dom.content.classList.add('hidden');
    dom.empty.classList.remove('hidden');
  }
  loadProfiles();
}

function updateStatusBadge(status) {
  const b = dom.statusBadge;
  b.classList.remove('hidden');
  const map = {
    pending: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
    running: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    completed: 'bg-green-500/10 text-green-400 border-green-500/20',
    stopped: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    failed: 'bg-red-500/10 text-red-400 border-red-500/20',
  };
  b.className = 'px-2 py-0.5 rounded-full text-[9px] font-bold border ' + (map[status] || map.pending);
  b.textContent = status.toUpperCase();
}

// ── Profile Modal ──
function openProfileModal(profile = null) {
  editingProfileId = profile ? profile.profile_id : null;
  const modal = $('#bt-modal');
  modal.classList.remove('hidden'); modal.classList.add('flex');
  if(profile) {
    $('#bt-modal-name').value = profile.name || '';
    $('#bt-modal-url').value = profile.target_url || '';
    $('#bt-modal-desc').value = profile.description || '';
    $('#bt-modal-master-prompt').value = profile.master_prompt || '';
    $('#bt-modal-documentation').value = profile.documentation || '';
    $('#bt-modal-openapi-url').value = profile.openapi_spec_url || '';
  } else {
    ['bt-modal-name','bt-modal-url','bt-modal-desc','bt-modal-master-prompt','bt-modal-documentation','bt-modal-openapi-url'].forEach(id => { const el = $('#'+id); if(el) el.value = ''; });
    const fi = $('#bt-modal-openapi-file'); if(fi) fi.value = '';
    const fs = $('#bt-openapi-file-selected'); if(fs) fs.classList.add('hidden');
    const dc = $('#bt-openapi-drop-content'); if(dc) dc.classList.remove('hidden');
  }
  loadCollections(profile?.collection_id);
  loadTeams(profile?.team_ids);
}

async function loadCollections(selectedId = '') {
  const sel = $('#bt-modal-collection'); if(!sel) return;
  try {
    const r = await fetch('/api/collections', {headers:{...getAuthHeader()}});
    if(!r.ok) return;
    const tree = await r.json();
    sel.innerHTML = '<option value="">— Aucune —</option>';
    function w(nodes,d){ for(const n of nodes){ if(n.type==='folder'){ sel.innerHTML+=`<option value="${n.id}">${'  '.repeat(d)}📁 ${esc(n.name)}</option>`; if(n.children) w(n.children,d+1); } } }
    w(tree,0);
    if(selectedId) sel.value = selectedId;
  } catch {}
}

function loadTeams(selectedId = '') {
  const sel = $('#bt-modal-team'); if(!sel) return;
  fetch('/api/teams',{headers:{...getAuthHeader()}}).then(r=>r.json()).then(teams=>{
    sel.innerHTML = '<option value="">Personnel</option>';
    teams.forEach(t=>{ sel.innerHTML += `<option value="${t.team_id}">${esc(t.name)}</option>`; });
    if(selectedId) sel.value = selectedId;
  }).catch(()=>{});
}

async function createProfile() {
  const name = $('#bt-modal-name').value.trim(), url = $('#bt-modal-url').value.trim();
  if(!name) return;
  let spec_content = null;
  const file = $('#bt-modal-openapi-file').files[0];
  if(file) spec_content = await new Promise(r=>{ const fr=new FileReader(); fr.onload=()=>r(fr.result); fr.readAsText(file); });
  const payload = {
    name, target_url: url, description: $('#bt-modal-desc').value.trim(),
    master_prompt: $('#bt-modal-master-prompt').value.trim(),
    documentation: $('#bt-modal-documentation').value.trim(),
    openapi_spec_url: $('#bt-modal-openapi-url').value.trim(),
    openapi_spec_content: spec_content,
    collection_id: $('#bt-modal-collection')?.value||'',
    team_ids: $('#bt-modal-team')?.value||'',
  };
  const isEdit = !!editingProfileId;
  const url_ep = isEdit ? API.profile(editingProfileId) : API.profiles;
  const method = isEdit ? 'PUT' : 'POST';
  const res = await fetch(url_ep, { method, headers:{'Content-Type':'application/json',...getAuthHeader()}, body: JSON.stringify(payload) });
  if(res.ok) {
    $('#bt-modal').classList.add('hidden');
    editingProfileId = null;
    loadProfiles();
  }
}

// ── OpenAPI Drop Zone ──
function setupOpenAPIDrop() {
  const zone = $('#bt-openapi-drop-zone');
  const input = $('#bt-modal-openapi-file');
  if(!zone||!input) return;
  const show = (name) => {
    $('#bt-openapi-drop-content').classList.add('hidden');
    $('#bt-openapi-file-selected').classList.remove('hidden');
    $('#bt-openapi-file-name').textContent = name;
  };
  input.addEventListener('change', () => { if(input.files[0]) show(input.files[0].name); });
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.style.borderColor='rgba(37,99,235,.4)'; zone.style.background='rgba(37,99,235,.05)'; });
  zone.addEventListener('dragleave', () => { zone.style.borderColor='rgba(255,255,255,.1)'; zone.style.background='transparent'; });
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.style.borderColor='rgba(255,255,255,.1)'; zone.style.background='transparent';
    if(e.dataTransfer.files.length>0) { input.files = e.dataTransfer.files; show(e.dataTransfer.files[0].name); }
  });
}

// ── Analysis ──
async function startAnalysis() {
  if(!state.activePid) return;
  updateStatusBadge('running');
  dom.liveProgress.classList.remove('hidden');
  dom.livePct.textContent = '0%';
  dom.liveBar.style.width = '0%';
  dom.liveMsg.textContent = 'Demarrage de l\'analyse...';
  const btnRun = $('#btn-run-analysis'); if(btnRun) btnRun.classList.add('hidden');
  const btnStop = $('#btn-stop-analysis'); if(btnStop) btnStop.classList.remove('hidden');
  const res = await fetch(API.analyze(state.activePid), { method:'POST', headers:{...getAuthHeader()} });
  if(!res.ok) { alert('Failed to start analysis'); return; }
  const data = await res.json();
  if(data.pro_model) { dom.proModelBadge.classList.remove('hidden'); dom.proModelBadge.textContent = data.pro_model; }
  connectSSE(state.activePid);
}

async function stopAnalysis() {
  if(!state.activePid) return;
  await fetch(`${API.profile(state.activePid)}/stop`, { method:'POST', headers:{...getAuthHeader()} });
  updateStatusBadge('stopped');
  const btnRun = $('#btn-run-analysis'); if(btnRun) btnRun.classList.remove('hidden');
  const btnStop = $('#btn-stop-analysis'); if(btnStop) btnStop.classList.add('hidden');
  disconnectSSE();
}

function connectSSE(pid) {
  disconnectSSE();
  dom.liveProgress.classList.remove('hidden');
  dom.livePct.textContent = '0%';
  dom.liveBar.style.width = '0%';
  dom.liveMsg.textContent = 'Analyse en cours...';
  // Adaptive polling: speed up on activity, slow down when idle
  let interval = 3000;
  let lastPct = -1;
  let sameCount = 0;

  const schedule = () => {
    if (!state._pollTimer) return;
    state._pollTimer = setTimeout(poll, interval);
  };

  const poll = async () => {
    const r = await fetch(API.profileStatus(pid), { headers: {...getAuthHeader()} });
    if (!r.ok) { disconnectSSE(); return; }
    const p = await r.json();
    updateStatusBadge(p.status);
    const pct = p.scan_progress || 0;
    dom.livePct.textContent = pct + '%';
    dom.liveBar.style.width = pct + '%';
    dom.liveMsg.textContent = p.progress_msg || 'Analyse en cours...';
    if (p.status !== 'running') {
      disconnectSSE();
      selectProfile(pid);
      return;
    }
    if (pct !== lastPct) {
      interval = Math.max(2000, interval / 1.5);
      sameCount = 0;
    } else {
      sameCount++;
      if (sameCount >= 2) {
        interval = Math.min(30000, interval * 2);
        sameCount = 0;
      }
    }
    lastPct = pct;
    schedule();
  };

  state._pollTimer = setTimeout(poll, 500);
}

function disconnectSSE() {
  if (state._pollTimer) { clearTimeout(state._pollTimer); state._pollTimer = null; }
  dom.liveProgress.classList.add('hidden');
}

function addProgressMsg(msg) {
  const logEl = $('#bt-progress-log');
  const msgsEl = $('#bt-progress-msgs');
  if(!logEl || !msgsEl) return;
  logEl.classList.remove('hidden');

  state._progressMsgs.push(msg);
  if(state._progressMsgs.length > 12) state._progressMsgs.shift();

  msgsEl.innerHTML = state._progressMsgs.map((m, i) => {
    const isLatest = i === state._progressMsgs.length - 1;
    const opacity = 0.3 + (i / state._progressMsgs.length) * 0.7;
    return `<div class="transition-all duration-500" style="opacity:${opacity.toFixed(2)}">
      <span class="text-blue-400/60 mr-2">▸</span><span class="${isLatest ? 'text-blue-300' : 'text-gray-500'}">${esc(m)}</span>
    </div>`;
  }).join('');

  // Auto-scroll to bottom
  const container = logEl;
  container.scrollTop = container.scrollHeight;
}

// ── Report ──
function renderReport(report) {
  dom.reportEmpty.classList.add('hidden');
  const content = $('#bt-report-content');
  const rendered = $('#bt-report-rendered');
  if (content) content.classList.remove('hidden');
  const md = report.report_markdown || '';

  // Add anchor IDs to markdown headings
  const anchored = md.replace(/^(#{1,3})\s+(.+)$/gm, (m, hashes, title) => {
    const id = title.toLowerCase().replace(/[^\w]+/g, '-').replace(/^-|-$/g, '');
    return `${hashes} <a id="${id}" class="report-anchor"></a>${title}`;
  });

  if (typeof marked !== 'undefined' && rendered) {
    rendered.innerHTML = marked.parse(anchored);
    // Render mermaid diagrams if present
    try {
      const mermaidEls = rendered.querySelectorAll('pre code.language-mermaid');
      if (mermaidEls.length > 0 && typeof mermaid !== 'undefined') {
        mermaidEls.forEach(el => {
          const pre = el.parentElement;
          // Decode HTML entities that marked.js may have escaped in code blocks
          let code = el.textContent || '';
          code = code.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
          const div = document.createElement('div');
          div.className = 'mermaid bg-base-900/50 rounded-lg p-4 my-4';
          div.textContent = code;
          pre.replaceWith(div);
        });
        mermaid.run({ querySelector: '.mermaid' }).catch(() => {
          // Mermaid syntax error — keep code block visible as text
          console.warn('Mermaid render failed, showing code blocks instead');
        });
      }
    } catch(e) { console.log('mermaid render skipped', e); }
  } else if (rendered) {
    rendered.innerHTML = `<pre class="text-xs text-gray-300 font-mono whitespace-pre-wrap">${esc(md)}</pre>`;
  }

  // Build table of contents
  const toc = $('#bt-toc');
  const tocLinks = $('#bt-toc-links');
  if (toc && tocLinks && rendered) {
    const headings = rendered.querySelectorAll('h2');
    if (headings.length > 1) {
      let html = '';
      headings.forEach(h => {
        const a = h.querySelector('a.report-anchor');
        if (!a) return;
        html += `<a href="#${a.id}" data-toc="${a.id}" onclick="document.getElementById('${a.id}').scrollIntoView({behavior:'smooth'});return false">${esc(h.textContent.trim())}</a>`;
      });
      tocLinks.innerHTML = html;
      toc.classList.remove('hidden');
    } else {
      toc.classList.add('hidden');
    }
  }

  // Add download button
  if(report.report_id && !$('#btn-download-report')) {
    const btn = document.createElement('button');
    btn.id = 'btn-download-report';
    btn.className = 'h-8 px-3 rounded-lg bg-blue-500/15 hover:bg-blue-500/25 border border-blue-500/20 hover:border-blue-500/40 text-xs text-blue-400 font-medium transition-all flex items-center gap-1.5 mt-4';
    btn.innerHTML = `<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>Telecharger le rapport (.md)`;
    btn.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = API.reportDownload(report.report_id);
      a.download = `ssdlc-report-${report.report_id.substring(0,8)}.md`;
      a.click();
    });
    rendered.appendChild(btn);
  }
}

// ── Load marked lib ──
(function loadMarked() {
  const s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/marked/marked.min.js';
  document.head.appendChild(s);
})();

init();
