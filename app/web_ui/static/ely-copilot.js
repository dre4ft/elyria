/* ═══════════════════════════════════════════════════════════════
   Elyria — ely-copilot.js
   Shared AI Copilot side panel. Injects into every page.
   Communicates with /api/ely/chat (Ely backend).
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  if (window.__elyCopilotInit) return;
  window.__elyCopilotInit = true;

  // Load marked if not already present (block until loaded)
  var _markedReady = typeof marked !== 'undefined';
  if (!_markedReady) {
    var ms = document.createElement('script');
    ms.src = 'https://cdn.jsdelivr.net/npm/marked/marked.min.js';
    ms.onload = function () { _markedReady = true; };
    document.head.appendChild(ms);
  }

  function _renderMarkdown(text) {
    if (typeof marked !== 'undefined' && marked.parse) {
      try { return marked.parse(text); } catch(e) {}
    }
    return _esc(text);
  }

  // ── Persistent state (sessionStorage: survives page nav, dies on tab close) ──
  var _historyKey = 'elyria-ely-history';
  var _openKey = 'elyria-ely-open';
  var _pageKey = 'elyria-ely-lastpage';
  var _slotKey = 'elyria-ely-slot';

  function _loadHistory() {
    try { return JSON.parse(sessionStorage.getItem(_historyKey) || '[]'); } catch(e) { return []; }
  }
  function _saveHistory(msgs) {
    try { sessionStorage.setItem(_historyKey, JSON.stringify(msgs.slice(-30))); } catch(e) {}
  }
  function _isOpen() {
    return sessionStorage.getItem(_openKey) === '1';
  }
  function _setOpen(v) {
    try { sessionStorage.setItem(_openKey, v ? '1' : '0'); } catch(e) {}
  }
  function _lastPage() {
    return sessionStorage.getItem(_pageKey) || '';
  }
  function _setLastPage(p) {
    try { sessionStorage.setItem(_pageKey, p); } catch(e) {}
  }
  function _loadSlot() {
    return sessionStorage.getItem(_slotKey) || 'pro';
  }
  function _saveSlot(s) {
    try { sessionStorage.setItem(_slotKey, s); } catch(e) {}
  }

  var state = {
    slot: _loadSlot(),
    messages: _loadHistory(),
    page: _detectPage(),
    _context: {},
    _diaryView: sessionStorage.getItem('elyria-ely-diaryview') === '1',
    _diaryEntries: [],
    _diaryTotal: 0,
    _diaryOffset: 0,
    _diarySearchQuery: '',
    _diaryTagFilter: '',
  };

  function _detectPage() {
    var p = window.location.pathname.replace(/\/$/, '');
    if (p === '/app' || p === '') return 'app';
    if (p === '/workflow') return 'workflow';
    if (p === '/pentest') return 'pentest';
    if (p === '/greyteam') return 'greyteam';
    if (p === '/blueteam') return 'blueteam';
    if (p === '/hub') return 'hub';
    if (p === '/doc') return 'doc';
    return 'app';
  }

  function _esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

  // ── Global bridge: called by app.js when request is sent or history loaded ──
  window.updateChatContext = function (data) {
    if (!data) {
      // Auto-detect from DOM (app page)
      var m = document.getElementById('req-method');
      var u = document.getElementById('req-url');
      var s = document.getElementById('resp-status');
      var b = document.getElementById('resp-body-content');
      data = {
        method: m ? m.value : '',
        url: u ? u.value : '',
        status_code: s ? parseInt(s.textContent) || 0 : 0,
        response_preview: b ? (b.textContent || '').substring(0, 500) : '',
      };
    }
    state._context = data;
  };

  var PANEL_HTML = ''
    + '<aside id="ely-copilot-panel" class="w-[480px] min-w-[380px] bg-base-800 border-l border-white/5 flex flex-col shrink-0 hidden" style="position:relative">'
    + '<div id="ely-resize-left" class="absolute left-0 top-0 bottom-0 w-[5px] cursor-col-resize hover:bg-primary/30 transition-colors z-10" style="margin-left:-2px"></div>'
    // Header
    + '<div class="h-12 px-4 border-b border-white/5 flex items-center justify-between shrink-0">'
    + '<div class="flex items-center gap-3">'
    + '<img src="/static/icons/new_logo_blanc.png" class="w-7 h-7 shrink-0 mt-0.5 ely-logo" alt="" />'
    + '<span class="text-xs font-semibold text-white">ELY Copilot</span>'
    // Model toggle
    + '<div class="flex items-center rounded-lg bg-base-700 border border-white/5 overflow-hidden">'
    + '<button id="ely-copilot-flash" class="h-6 px-2.5 text-[10px] font-semibold transition-all text-gray-500 hover:text-gray-300">Flash</button>'
    + '<button id="ely-copilot-pro" class="h-6 px-2.5 text-[10px] font-semibold transition-all bg-purple-500/15 text-purple-400">Pro</button>'
    + '</div>'
    + '</div>'
    + '<div class="flex items-center gap-2">'
    + '<button id="ely-copilot-diary" class="h-7 px-2.5 rounded-lg bg-base-700 hover:bg-cyan-500/10 border border-white/5 hover:border-cyan-500/30 text-[10px] font-medium text-gray-500 hover:text-cyan-400 transition-all flex items-center gap-1" title="Ely Diary">'
    + '<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
    + 'Diary'
    + '</button>'
    + '<button id="ely-copilot-clear" class="w-6 h-6 rounded-md hover:bg-white/5 flex items-center justify-center text-gray-500 hover:text-gray-300 transition-colors" title="Nouvelle conversation">'
    + '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>'
    + '</button>'
    + '<button id="ely-copilot-close" class="w-6 h-6 rounded-md hover:bg-white/5 flex items-center justify-center text-gray-500 hover:text-gray-300 transition-colors">'
    + '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>'
    + '</button>'
    + '</div>'
    + '</div>'
    // Messages
    + '<div id="ely-copilot-messages" class="flex-1 overflow-y-auto p-3 space-y-4 scrollbar-thin">'
    + '<div class="flex gap-3">'
    + '<img src="/static/icons/new_logo_blanc.png" class="w-7 h-7 shrink-0 mt-0.5 ely-logo" alt="" />'
    + '<div class="bg-base-700/50 rounded-xl rounded-tl-md px-4 py-3 text-xs text-gray-300 leading-relaxed" style="max-width:90%">Bonjour ! Je suis Ely, votre assistant IA contextuel. Je connais la page sur laquelle vous etes et je peux vous aider a utiliser Elyria. Tapez <b>/</b> pour voir les commandes disponibles.</div>'
    + '</div>'
    + '</div>'
    // Input
    + '<div class="px-4 py-3 border-t border-white/5 shrink-0">'
    + '<div class="relative flex-1">'
    + '<textarea id="ely-copilot-input" rows="1" placeholder="Posez une question ou tapez / pour les commandes…" class="w-full px-3.5 py-2.5 pr-10 rounded-xl bg-base-900/60 border border-white/8 text-xs text-gray-300 placeholder-gray-600 resize-none focus:outline-none focus:border-primary/40 transition-all scrollbar-thin"></textarea>'
    + '<button id="ely-copilot-send" class="absolute right-1.5 top-1.5 w-7 h-7 rounded-lg bg-primary hover:bg-primary-light text-white flex items-center justify-center transition-all active:scale-90">'
    + '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>'
    + '</button>'
    + '</div>'
    + '</div>'
        // Diary view (hidden by default, replaces messages + input when active)
    + '<div id="ely-copilot-diary-view" class="hidden flex-1 flex flex-col overflow-hidden">'
    + '<div class="px-3 py-2 border-b border-white/5 shrink-0">'
    + '<div class="relative">'
    + '<svg class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/></svg>'
    + '<input id="diary-search" type="text" placeholder="Rechercher dans le diary..." class="w-full h-7 pl-7 pr-3 rounded-md bg-base-900/60 border border-white/5 text-[11px] text-gray-300 placeholder-gray-600 focus:outline-none focus:border-cyan-500/40 transition-all">'
    + '</div>'
    + '<div class="flex gap-1 mt-1.5 flex-wrap">'
    + '<button data-dtag="" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-semibold bg-cyan-500/15 text-cyan-400 border border-cyan-500/20 transition-all">Tous</button>'
    + '<button data-dtag="requêtes" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-medium text-gray-500 hover:text-gray-300 border border-transparent hover:border-white/10 transition-all">Requetes</button>'
    + '<button data-dtag="scan" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-medium text-gray-500 hover:text-gray-300 border border-transparent hover:border-white/10 transition-all">Scans</button>'
    + '<button data-dtag="osint" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-medium text-gray-500 hover:text-gray-300 border border-transparent hover:border-white/10 transition-all">OSINT</button>'
    + '<button data-dtag="audit" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-medium text-gray-500 hover:text-gray-300 border border-transparent hover:border-white/10 transition-all">Audit</button>'
    + '<button data-dtag="workflow" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-medium text-gray-500 hover:text-gray-300 border border-transparent hover:border-white/10 transition-all">Workflows</button>'
    + '<button data-dtag="notes" class="diary-theme-filter h-5 px-2 rounded text-[9px] font-medium text-gray-500 hover:text-gray-300 border border-transparent hover:border-white/10 transition-all">Notes</button>'
    + '</div>'
    + '</div>'
    + '<div id="diary-entries-list" class="flex-1 overflow-y-auto p-3 scrollbar-thin">'
    + '<div id="diary-empty-state" class="flex flex-col items-center justify-center h-full text-center px-6">'
    + '<div class="w-12 h-12 rounded-2xl bg-base-700/50 flex items-center justify-center mb-3">'
    + '<svg class="w-6 h-6 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
    + '</div>'
    + '<p class="text-xs text-gray-600">Aucune entree dans le diary.<br/>Les entrees seront creees automatiquement.</p>'
    + '</div>'
    + '<div id="diary-entries-scroll" class="space-y-2"></div>'
    + '</div>'
    + '<div class="px-3 py-2 border-t border-white/5 shrink-0 flex gap-2">'
    + '<button id="diary-add-entry" class="flex-1 h-7 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 hover:border-cyan-500/40 text-[10px] font-medium text-cyan-400 transition-all flex items-center justify-center gap-1">'
    + '<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>'
    + 'Nouvelle entree'
    + '</button>'
    + '<button id="diary-refresh" class="h-7 w-7 rounded-lg bg-base-700 hover:bg-white/5 border border-white/5 flex items-center justify-center text-gray-500 hover:text-gray-300 transition-all" title="Actualiser">'
    + '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182"/></svg>'
    + '</button>'
    + '</div>'
    + '</div>'
    + '</aside>';

  // ── Slash commands ──
  var SLASH_COMMANDS = [
    { cmd: '/explain', desc: 'Analyser une reponse HTTP' },
    { cmd: '/scan',    desc: 'Lancer un scan de securite' },
    { cmd: '/osint',   desc: 'Lancer un scan OSINT' },
    { cmd: '/analyze', desc: 'Analyser une spec (Blue Team)' },
    { cmd: '/create',  desc: 'Creer une requete, collection ou workflow' },
    { cmd: '/help',    desc: 'Aide sur Elyria' },
  ];
  var _slashIdx = -1;

  function _renderSlashMenu(filter) {
    var menu = document.getElementById('ely-copilot-slash');
    if (!menu) return;
    var filtered = SLASH_COMMANDS;
    if (filter) filtered = SLASH_COMMANDS.filter(function (c) { return c.cmd.indexOf(filter) === 0; });
    menu.innerHTML = filtered.map(function (c, i) {
      return '<div class="slash-item px-3 py-2 flex items-center gap-2 cursor-pointer text-xs ' + (i === _slashIdx ? 'bg-primary/15 text-primary-light' : 'text-gray-400 hover:bg-white/5 hover:text-gray-200') + '" data-idx="' + i + '"><span class="font-mono font-bold text-primary-light w-14">' + _esc(c.cmd) + '</span><span class="text-gray-500">' + _esc(c.desc) + '</span></div>';
    }).join('');
    if (filtered.length === 0) { menu.classList.add('hidden'); _slashIdx = -1; }
    else { menu.classList.remove('hidden'); }
  }

  // ── Build & inject ──
  function _init() {
    if (document.getElementById('ely-copilot-panel')) return;

    // Inject markdown styles for messages
    if (!document.getElementById('ely-copilot-css')) {
      var style = document.createElement('style');
      style.id = 'ely-copilot-css';
      style.textContent = ''
        + '.ely-msg-body p{margin-bottom:.5em;}'
        + '.ely-msg-body p:last-child{margin-bottom:0;}'
        + '.ely-msg-body code{background:rgba(124,58,237,.15);color:#c4b5fd;padding:1px 4px;border-radius:3px;font-family:"JetBrains Mono",monospace;font-size:11px;}'
        + '.ely-msg-body pre{background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:8px 10px;margin:.5em 0;overflow-x:auto;font-size:11px;}'
        + '.ely-msg-body pre code{background:none;padding:0;color:#d1d5db;}'
        + '.ely-msg-body ul,.ely-msg-body ol{padding-left:1.2em;margin-bottom:.5em;}'
        + '.ely-msg-body li{margin-bottom:.2em;}'
        + '.ely-msg-body strong{color:#e5e7eb;font-weight:600;}'
        + '.ely-msg-body a{color:#a78bfa;text-decoration:underline;}'
        + '.ely-msg-body blockquote{border-left:2px solid #7c3aed;padding-left:.6em;margin:.5em 0;color:#9ca3af;}'
        + '.ely-msg-body h1,.ely-msg-body h2,.ely-msg-body h3{color:#e5e7eb;font-weight:600;margin:.6em 0 .3em;}'
        + '.ely-msg-body h1{font-size:13px;}.ely-msg-body h2{font-size:12px;}.ely-msg-body h3{font-size:11px;}'
        + '.ely-msg-body table{width:100%;border-collapse:collapse;margin:.5em 0;font-size:10px;}'
        + '.ely-msg-body th,.ely-msg-body td{padding:3px 6px;border:1px solid rgba(255,255,255,.08);text-align:left;}'
        + '.ely-msg-body th{background:rgba(124,58,237,.1);color:#c4b5fd;}'
        + '.ely-msg-body hr{border:none;border-top:1px solid rgba(255,255,255,.08);margin:.8em 0;}'
        + '.ely-tools-used{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.06);}'
        + '.ely-tool-badge{font-size:10px;padding:2px 7px;border-radius:5px;font-family:"JetBrains Mono",monospace;}'
        + '.ely-tool-ok{background:rgba(34,197,94,.1);color:#4ade80;border:1px solid rgba(34,197,94,.15);}'
        + '.ely-tool-err{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.15);}';
        + '.diary-entry .line-clamp-2{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}'
        + '[data-theme="light"] .ely-logo{filter:invert(1);}'
        + '[data-theme="light"] .ely-msg-body strong{color:#1e293b;}'
        + '[data-theme="light"] .ely-msg-body h1,[data-theme="light"] .ely-msg-body h2,[data-theme="light"] .ely-msg-body h3{color:#1e293b;}'
        + '[data-theme="light"] .ely-msg-body p{color:#334155;}'
        + '[data-theme="light"] .ely-msg-body li{color:#334155;}'
        + '[data-theme="light"] .ely-msg-body code{background:rgba(124,58,237,.1);color:#5b21b6;}'
        + '[data-theme="light"] .ely-msg-body pre{background:rgba(0,0,0,.05);border-color:rgba(0,0,0,.1);}'
        + '[data-theme="light"] .ely-msg-body pre code{color:#1e293b;}'
        + '[data-theme="light"] .ely-msg-body blockquote{color:#475569;border-left-color:#7c3aed;}'
        + '[data-theme="light"] .ely-msg-body a{color:#6d28d9;}'
        + '[data-theme="light"] .ely-msg-body th{background:rgba(124,58,237,.08);color:#5b21b6;}'
        + '[data-theme="light"] .ely-msg-body td{color:#334155;}'
        + '.ely-eye{fill:#06b6d4;}'
        + '[data-theme="dark"] .ely-eye{fill:#7c3aed;}';
      document.head.appendChild(style);
    }

    var container = document.createElement('div');
    container.innerHTML = PANEL_HTML
      // Slash menu (outside the aside for z-index)
      + '<div id="ely-copilot-slash" class="hidden fixed z-[10000] w-80 max-h-48 overflow-y-auto rounded-xl bg-base-700 border border-white/10 shadow-2xl py-1"></div>';
    while (container.firstChild) {
      var child = container.firstChild;
      if (child.id === 'ely-copilot-panel') {
        // Insert into the main flex layout so it pushes content instead of overlaying
        var layout = document.querySelector('[class*="flex h-\\[calc"]');
        if (layout) { layout.appendChild(child); }
        else { document.body.appendChild(child); }
      } else {
        document.body.appendChild(child);
      }
    }

    _bindEvents();

    // ── Auto-open if was open + restore messages + restore width ──
    var panel = document.getElementById('ely-copilot-panel');
    if (_isOpen() && panel) {
      panel.classList.remove('hidden');
      var input = document.getElementById('ely-copilot-input');
      if (input) setTimeout(function () { input.focus(); }, 100);
    }
    try {
      var savedW = sessionStorage.getItem('elyria-ely-width');
      if (savedW && panel) panel.style.width = savedW;
    } catch(e) {}
    _restoreMessages();

    // ── Page change detection: notify Ely ──
    var prevPage = _lastPage();
    var currPage = state.page;
    if (prevPage && prevPage !== currPage && state.messages.length > 0) {
      var note = '[System] L\'utilisateur a change de page : ' + prevPage + ' → ' + currPage + '. Adapte ton contexte.';
      state.messages.push({ role: 'system', content: note });
      _saveHistory(state.messages);
    }
    _setLastPage(currPage);
  }

  function _restoreMessages() {
    var container = document.getElementById('ely-copilot-messages');
    if (!container) return;
    container.innerHTML = '';
    var msgs = state.messages;
    if (!msgs.length) {
      // Show default greeting
      container.innerHTML = '<div class="flex gap-3">'
        + '<img src="/static/icons/new_logo_blanc.png" class="w-7 h-7 shrink-0 mt-0.5 ely-logo" alt="" />'
        + '<div class="bg-base-700/50 rounded-xl rounded-tl-md px-4 py-3 text-xs text-gray-300 leading-relaxed" style="max-width:90%">Bonjour ! Je suis Ely, votre assistant IA contextuel. Tapez <b>/</b> pour voir les commandes disponibles.</div>'
        + '</div>';
      return;
    }
    for (var i = 0; i < msgs.length; i++) {
      var m = msgs[i];
      if (m.role === 'system' || m.role === 'tool') continue;  // skip system messages in display
      _addMessage(m.role === 'user' ? 'user' : 'ely', m.content);
    }
    container.scrollTop = container.scrollHeight;
  }

  function _bindEvents() {
    var panel = document.getElementById('ely-copilot-panel');
    var messages = document.getElementById('ely-copilot-messages');
    var input = document.getElementById('ely-copilot-input');
    var send = document.getElementById('ely-copilot-send');
    var close = document.getElementById('ely-copilot-close');
    var clear = document.getElementById('ely-copilot-clear');
    var flash = document.getElementById('ely-copilot-flash');
    var pro = document.getElementById('ely-copilot-pro');
    var slashMenu = document.getElementById('ely-copilot-slash');

    // Toggle from header button
    var toggleBtn = document.getElementById('btn-toggle-copilot');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', function () {
        panel.classList.toggle('hidden');
        var open = !panel.classList.contains('hidden');
        _setOpen(open);
        if (open) { input.focus(); }
      });
    }

    close.addEventListener('click', function () { panel.classList.add('hidden'); _setOpen(false); });
    clear.addEventListener('click', function () {
      state.messages = [];
      messages.innerHTML = '';
      _saveHistory([]);
    });

    flash.addEventListener('click', function () {
      state.slot = 'flash'; _saveSlot('flash');
      flash.className = 'h-6 px-2.5 text-[10px] font-semibold transition-all bg-amber-500/15 text-amber-400';
      pro.className = 'h-6 px-2.5 text-[10px] font-semibold transition-all text-gray-500 hover:text-gray-300';
    });
    pro.addEventListener('click', function () {
      state.slot = 'pro'; _saveSlot('pro');
      pro.className = 'h-6 px-2.5 text-[10px] font-semibold transition-all bg-purple-500/15 text-purple-400';
      flash.className = 'h-6 px-2.5 text-[10px] font-semibold transition-all text-gray-500 hover:text-gray-300';
    });

    // ── Diary toggle ──
    var diaryBtn = document.getElementById('ely-copilot-diary');
    var diaryView = document.getElementById('ely-copilot-diary-view');
    var inputWrapper = null;
    if (input && input.closest) inputWrapper = input.closest('.px-4.py-3');

    if (diaryBtn) {
      if (state._diaryView) {
        setTimeout(function () {
          messages.classList.add('hidden');
          if (inputWrapper) inputWrapper.classList.add('hidden');
          diaryView.classList.remove('hidden');
          diaryView.classList.add('flex');
          diaryBtn.className = 'h-7 px-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-[10px] font-medium text-cyan-400 transition-all flex items-center gap-1';
          _loadDiaryEntries();
        }, 50);
      }
      diaryBtn.addEventListener('click', function () {
        state._diaryView = !state._diaryView;
        sessionStorage.setItem('elyria-ely-diaryview', state._diaryView ? '1' : '0');
        if (state._diaryView) {
          messages.classList.add('hidden');
          if (inputWrapper) inputWrapper.classList.add('hidden');
          diaryView.classList.remove('hidden');
          diaryView.classList.add('flex');
          diaryBtn.className = 'h-7 px-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-[10px] font-medium text-cyan-400 transition-all flex items-center gap-1';
          _loadDiaryEntries();
        } else {
          diaryView.classList.add('hidden');
          diaryView.classList.remove('flex');
          messages.classList.remove('hidden');
          if (inputWrapper) inputWrapper.classList.remove('hidden');
          diaryBtn.className = 'h-7 px-2.5 rounded-lg bg-base-700 hover:bg-cyan-500/10 border border-white/5 hover:border-cyan-500/30 text-[10px] font-medium text-gray-500 hover:text-cyan-400 transition-all flex items-center gap-1';
        }
      });
    }

    // ── Diary theme filter buttons ──
    var diaryFilterBtns = document.querySelectorAll('.diary-theme-filter');
    var DIARY_FILTER_GRAY = 'h-5 px-2 rounded text-[9px] font-medium text-gray-500 border border-transparent transition-all';
    var DIARY_FILTER_CYAN = 'h-5 px-2 rounded text-[9px] font-semibold bg-cyan-500/15 text-cyan-400 border border-cyan-500/20 transition-all';
    diaryFilterBtns.forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        var clicked = e.currentTarget;
        state._diaryTagFilter = clicked.dataset.dtag;
        diaryFilterBtns.forEach(function (b) { b.className = DIARY_FILTER_GRAY; });
        clicked.className = DIARY_FILTER_CYAN;
        _loadDiaryEntries();
      });
    });

    // ── Diary search ──
    var diarySearch = document.getElementById('diary-search');
    if (diarySearch) {
      diarySearch.addEventListener('input', function () {
        state._diarySearchQuery = this.value;
        _loadDiaryEntries();
      });
    }

    // ── Diary add/refresh ──
    var diaryAdd = document.getElementById('diary-add-entry');
    if (diaryAdd) diaryAdd.addEventListener('click', function () { _createDiarySnapshot(); });
    var diaryRefresh = document.getElementById('diary-refresh');
    if (diaryRefresh) diaryRefresh.addEventListener('click', function () { _loadDiaryEntries(true); });

    send.addEventListener('click', _send);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (_slashIdx >= 0 && !slashMenu.classList.contains('hidden')) {
          _selectSlash(_slashIdx); return;
        }
        _send();
      } else if (e.key === 'ArrowDown') {
        if (!slashMenu.classList.contains('hidden')) { e.preventDefault(); _slashIdx = (_slashIdx + 1) % SLASH_COMMANDS.length; _renderSlashMenu(input.value.slice(1)); }
      } else if (e.key === 'ArrowUp') {
        if (!slashMenu.classList.contains('hidden')) { e.preventDefault(); _slashIdx = _slashIdx <= 0 ? SLASH_COMMANDS.length - 1 : _slashIdx - 1; _renderSlashMenu(input.value.slice(1)); }
      }
    });

    input.addEventListener('input', function () {
      var val = input.value;
      if (val.startsWith('/') && !val.includes(' ')) {
        _renderSlashMenu(val.slice(1));
        _positionSlashMenu(input);
      } else {
        slashMenu.classList.add('hidden');
        _slashIdx = -1;
      }
    });

    // Close slash menu on click outside
    document.addEventListener('click', function (e) {
      if (!slashMenu.contains(e.target) && e.target !== input) {
        slashMenu.classList.add('hidden'); _slashIdx = -1;
      }
    });

    slashMenu.addEventListener('click', function (e) {
      var item = e.target.closest('.slash-item');
      if (item) { _selectSlash(parseInt(item.dataset.idx)); }
    });

    // ── Left-edge resize handle ──
    var resizeLeft = document.getElementById('ely-resize-left');
    var resizing = false, rStartX, rStartW;
    resizeLeft.addEventListener('pointerdown', function (e) {
      resizing = true; rStartX = e.clientX; rStartW = panel.offsetWidth;
      e.preventDefault(); e.stopPropagation();
      panel.setPointerCapture(e.pointerId);
    });
    panel.addEventListener('pointermove', function (e) {
      if (!resizing) return;
      var w = Math.max(320, Math.min(900, rStartW - (e.clientX - rStartX)));
      panel.style.width = w + 'px';
    });
    panel.addEventListener('pointerup', function () {
      if (resizing) {
        resizing = false;
        try { sessionStorage.setItem('elyria-ely-width', panel.style.width); } catch(e) {}
      }
    });
  }

  function _positionSlashMenu(input) {
    var menu = document.getElementById('ely-copilot-slash');
    if (!menu) return;
    var r = input.getBoundingClientRect();
    menu.style.left = r.left + 'px';
    menu.style.top = (r.top - menu.offsetHeight - 4) + 'px';
    menu.style.width = Math.max(320, r.width) + 'px';
  }

  function _selectSlash(idx) {
    var cmd = SLASH_COMMANDS[idx];
    if (!cmd) return;
    var input = document.getElementById('ely-copilot-input');
    input.value = cmd.cmd + ' ';
    document.getElementById('ely-copilot-slash').classList.add('hidden');
    _slashIdx = -1;
    input.focus();
  }

  async function _send() {
    var input = document.getElementById('ely-copilot-input');
    var messages = document.getElementById('ely-copilot-messages');
    var sendBtn = document.getElementById('ely-copilot-send');
    var text = input.value.trim();
    if (!text) return;

    input.value = '';
    sendBtn.disabled = true;
    _addMessage('user', text);
    state.messages.push({ role: 'user', content: text });
    _saveHistory(state.messages);

    var loadingEl = _addMessage('ely', '<span class="text-[11px] text-gray-500 italic">Je reflechis...</span>');

    try {
      var token = (typeof getToken === 'function') ? getToken() : (sessionStorage.getItem('elyria_token') || '');
      var ctx = Object.assign({ url: window.location.href }, state._context || {});
      if (state.page === 'app') {
        var m = document.querySelector('.method-badge'); if (m) ctx.method = ctx.method || m.textContent.trim();
      }

      var resp = await fetch('/api/ely/chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ page: state.page, message: text, context: ctx, history: state.messages, slot: state.slot }),
      });

      if (!resp.ok) { loadingEl.remove(); _addMessage('ely', 'Erreur ' + resp.status); sendBtn.disabled = false; return; }

      var data = await resp.json();
      loadingEl.remove();

      var toolsHtml = '';
      if (data.actions && data.actions.length) {
        toolsHtml = '<div class="ely-tools-used">';
        for (var a = 0; a < data.actions.length; a++) {
          var act = data.actions[a];
          var ok = act.result && !act.result.error;
          toolsHtml += '<span class="ely-tool-badge ' + (ok ? 'ely-tool-ok' : 'ely-tool-err') + '">'
            + (ok ? '✓' : '✗') + ' ' + _esc(act.name.replace('ely_', '').replace(/_/g, ' '))
            + '</span>';
        }
        toolsHtml += '</div>';
      }
      if (data.reply) {
        _addMessage('ely', data.reply + toolsHtml);
        state.messages.push({ role: 'assistant', content: data.reply });
      } else if (toolsHtml) {
        _addMessage('ely', toolsHtml);
      }
      _saveHistory(state.messages);
    } catch (e) {
      loadingEl.remove();
      _addMessage('ely', 'Erreur : ' + _esc(e.message || 'connexion'));
    }
    sendBtn.disabled = false;
  }

  function _addMessage(role, content) {
    var container = document.getElementById('ely-copilot-messages');
    if (!container) return;
    var div = document.createElement('div');
    div.className = 'flex gap-3' + (role === 'user' ? ' justify-end' : '');
    if (role === 'user') {
      div.innerHTML = '<div class="bg-primary/15 rounded-xl rounded-tr-md px-4 py-2.5 text-xs text-gray-300 leading-relaxed" style="max-width:85%">' + _esc(content) + '</div>';
    } else {
      var isHtml = content.indexOf('<') === 0;
      var body = isHtml ? content : _renderMarkdown(content);
      div.innerHTML = '<img src="/static/icons/new_logo_blanc.png" class="w-7 h-7 shrink-0 mt-0.5 ely-logo" alt="" />'
        + '<div class="ely-msg-body bg-base-700/50 rounded-xl rounded-tl-md px-4 py-3 text-xs text-gray-300 leading-relaxed" style="max-width:90%">' + body + '</div>';
    }
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return div;
  }

  // ═══════════════════════════════════════════════════════════════
  // Diary helpers
  // ═══════════════════════════════════════════════════════════════

  var _lastDiaryFilter = '';
  var _lastDiarySearch = '';

  function _loadDiaryEntries(forceRefresh) {
    var filterChanged = state._diaryTagFilter !== _lastDiaryFilter;
    var searchChanged = state._diarySearchQuery !== _lastDiarySearch;
    if (!forceRefresh && !filterChanged && !searchChanged && state._diaryEntries.length > 0) return;
    _lastDiaryFilter = state._diaryTagFilter;
    _lastDiarySearch = state._diarySearchQuery;

    var token = (typeof getToken === 'function') ? getToken() : (sessionStorage.getItem('elyria_token') || '');
    var url;
    if (state._diarySearchQuery) {
      url = '/api/ely/diary/search?q=' + encodeURIComponent(state._diarySearchQuery) + '&limit=50';
    } else {
      url = '/api/ely/diary?limit=100&offset=' + state._diaryOffset;
      if (state._diaryTagFilter) url += '&tag=' + encodeURIComponent(state._diaryTagFilter);
    }
    fetch(url, { headers: { 'Authorization': 'Bearer ' + token } })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      state._diaryEntries = data.items || [];
      state._diaryTotal = data.total || 0;
      _renderDiaryEntries();
    })
    .catch(function () {});
  }

  function _renderDiaryEntries() {
    var scroll = document.getElementById('diary-entries-scroll');
    var empty = document.getElementById('diary-empty-state');
    if (!scroll) return;
    scroll.innerHTML = '';
    if (state._diaryEntries.length === 0) {
      if (empty) empty.classList.remove('hidden');
      return;
    }
    if (empty) empty.classList.add('hidden');

    var token = (typeof getToken === 'function') ? getToken() : (sessionStorage.getItem('elyria_token') || '');

    state._diaryEntries.forEach(function (entry) {
      var date = (entry.created_at || '').substring(0, 19).replace('T', ' ');
      var preview = (entry.content || '').replace(/[#*`\n]/g, ' ').substring(0, 150);
      var tags = [];
      try { tags = JSON.parse(entry.tags || '[]'); } catch (e) {}
      var tagHtml = tags.map(function (t) {
        return '<span class="px-1.5 py-0.5 rounded-full bg-cyan-500/10 text-[8px] text-cyan-400 font-medium">' + _esc(t) + '</span>';
      }).join('');

      var entryEl = document.createElement('div');
      entryEl.className = 'diary-entry rounded-lg bg-base-700/30 border border-white/5 hover:border-cyan-500/20 transition-all overflow-hidden cursor-pointer';
      entryEl.dataset.did = entry.diary_id;
      entryEl.dataset.content = entry.content || '';
      entryEl.innerHTML = '<div class="p-3">'
        + '<div class="flex items-start justify-between gap-2">'
        + '<div class="min-w-0 flex-1">'
        + '<div class="text-xs font-semibold text-gray-200 truncate">' + _esc(entry.title || 'Sans titre') + '</div>'
        + '<div class="text-[10px] text-gray-500 mt-0.5">' + _esc(date) + ' \u00b7 ' + _esc(entry.page || '') + '</div>'
        + '</div>'
        + '<div class="flex gap-1 shrink-0 flex-wrap justify-end">' + tagHtml + '</div>'
        + '</div>'
        + '<div class="mt-2 text-[11px] text-gray-400 line-clamp-2 leading-relaxed">' + _esc(preview) + '</div>'
        + '</div>'
        + '<div class="diary-entry-expanded hidden p-3 pt-0 border-t border-white/5">'
        + '<div class="ely-msg-body text-xs text-gray-300 leading-relaxed">' + _renderMarkdown(entry.content || '') + '</div>'
        + '<div class="flex gap-2 mt-3 pt-2 border-t border-white/5">'
        + '<button class="diary-copy-btn h-6 px-2 rounded bg-base-700 hover:bg-white/5 text-[9px] text-gray-500 hover:text-gray-300 transition-all">Copier</button>'
        + '<button class="diary-del-btn h-6 px-2 rounded bg-red-500/10 hover:bg-red-500/20 text-[9px] text-red-400 transition-all">Supprimer</button>'
        + '</div>'
        + '</div>';

      entryEl.addEventListener('click', function (e) {
        if (e.target.closest('.diary-del-btn') || e.target.closest('.diary-copy-btn')) return;
        this.querySelector('.diary-entry-expanded').classList.toggle('hidden');
      });

      entryEl.querySelector('.diary-del-btn').addEventListener('click', function (e) {
        e.stopPropagation();
        if (!confirm('Supprimer cette entree du diary ?')) return;
        var did = entryEl.dataset.did;
        fetch('/api/ely/diary/' + encodeURIComponent(did), {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + token }
        }).then(function (r) {
          if (r.ok) {
            entryEl.remove();
            state._diaryEntries = state._diaryEntries.filter(function (e) { return e.diary_id !== did; });
            state._diaryTotal--;
            if (state._diaryEntries.length === 0) _renderDiaryEntries();
          }
        });
      });

      entryEl.querySelector('.diary-copy-btn').addEventListener('click', function (e) {
        e.stopPropagation();
        navigator.clipboard.writeText(entryEl.dataset.content || '').catch(function () {});
      });

      scroll.appendChild(entryEl);
    });
  }

  function _createDiarySnapshot() {
    var token = (typeof getToken === 'function') ? getToken() : (sessionStorage.getItem('elyria_token') || '');
    var ctx = Object.assign({ url: window.location.href }, state._context || {});
    fetch('/api/ely/diary/snapshot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({
        page: state.page,
        url: ctx.url,
        method: ctx.method || '',
        status_code: ctx.status_code || 0,
        response_preview: ctx.response_preview || '',
      }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.diary_id) {
        state._diaryEntries.unshift({
          diary_id: data.diary_id,
          title: data.title,
          content: 'Prise de snapshot automatique.',
          created_at: new Date().toISOString(),
          page: state.page,
          tags: '["auto-snapshot"]',
        });
        state._diaryTotal++;
        _renderDiaryEntries();
      }
    })
    .catch(function () {});
  }

  // ── Init ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    _init();
  }
})();
