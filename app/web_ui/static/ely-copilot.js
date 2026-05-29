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

  var state = { slot: _loadSlot(), messages: _loadHistory(), page: _detectPage(), _context: {} };

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
    + '<div class="w-6 h-6 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center">'
    + '<svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>'
    + '</div>'
    + '<span class="text-xs font-semibold text-white">ELY Copilot</span>'
    // Model toggle
    + '<div class="flex items-center rounded-lg bg-base-700 border border-white/5 overflow-hidden">'
    + '<button id="ely-copilot-flash" class="h-6 px-2.5 text-[10px] font-semibold transition-all text-gray-500 hover:text-gray-300">Flash</button>'
    + '<button id="ely-copilot-pro" class="h-6 px-2.5 text-[10px] font-semibold transition-all bg-purple-500/15 text-purple-400">Pro</button>'
    + '</div>'
    + '</div>'
    + '<div class="flex items-center gap-2">'
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
    + '<div class="w-7 h-7 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">'
    + '<svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>'
    + '</div>'
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
        + '<div class="w-7 h-7 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">'
        + '<svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>'
        + '</div>'
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
      div.innerHTML = '<div class="w-7 h-7 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">'
        + '<svg class="w-3.5 h-3.5 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"/></svg>'
        + '</div>'
        + '<div class="ely-msg-body bg-base-700/50 rounded-xl rounded-tl-md px-4 py-3 text-xs text-gray-300 leading-relaxed" style="max-width:90%">' + body + '</div>';
    }
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return div;
  }

  // ── Init ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    _init();
  }
})();
