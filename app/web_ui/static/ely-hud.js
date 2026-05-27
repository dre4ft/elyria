/* ═══════════════════════════════════════════════════════════════
   Elyria — ely-hud.js
   Ely AI agent HUD — sticky to corners, draggable between corners,
   semi-transparent overlay with expand/collapse.

   Injects into any page automatically. Load after auth.js.
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  if (window.__elyHudInit) return;
  window.__elyHudInit = true;

  // ── State ──
  var state = {
    open: false,
    messages: [],
    opacity: 80,
    page: _detectPage(),
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

  // ── Load persisted state ──
  try {
    var saved = JSON.parse(localStorage.getItem('elyria-ely-state') || '{}');
    if (saved.opacity) state.opacity = saved.opacity;
  } catch (e) {}

  function _save() {
    try {
      localStorage.setItem('elyria-ely-state', JSON.stringify({ opacity: state.opacity }));
    } catch (e) {}
  }

  // ── DOM construction ──
  function _build() {
    var hud = document.createElement('div');
    hud.id = 'ely-hud';
    hud.innerHTML = ''
      // Collapsed bubble
      + '<div id="ely-bubble" class="ely-bubble" title="Ely — Assistant IA">'
      + '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
      + '<circle cx="12" cy="12" r="10"/>'
      + '<path d="M8 9.5h8M8 13h5.5"/>'
      + '</svg>'
      + '</div>'

      // Expanded panel
      + '<div id="ely-panel" class="ely-panel" style="display:none">'
      + '<div id="ely-drag-handle" class="ely-header">'
      + '<span class="ely-header-title">Ely</span>'
      + '<div class="ely-header-actions">'
      + '<input id="ely-opacity" type="range" min="20" max="100" value="' + state.opacity + '" class="ely-opacity-slider" title="Opacite" />'
      + '<button id="ely-reset" class="ely-header-btn" title="Reinitialiser la position">&circlearrowright;</button>'
      + '<button id="ely-minimize" class="ely-header-btn" title="Minimiser">&minus;</button>'
      + '</div>'
      + '</div>'
      + '<div id="ely-messages" class="ely-messages"></div>'
      + '<div class="ely-input-row">'
      + '<input id="ely-input" type="text" class="ely-input" placeholder="Que veux-tu faire ?" autocomplete="off" />'
      + '<button id="ely-send" class="ely-send-btn" title="Envoyer">'
      + '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>'
      + '</button>'
      + '</div>'
      + '</div>'
      + '<div id="ely-resize-handle" class="ely-resize-handle" style="display:none"></div>';

    var style = document.createElement('style');
    style.id = 'ely-hud-css';
    style.textContent = _css();
    document.head.appendChild(style);
    document.body.appendChild(hud);

    _applyOpacity();
    _bindEvents();
  }

  function _css() {
    return ''
      // ── Positioning ──
      + '#ely-hud{position:fixed;z-index:9999;font-family:Inter,sans-serif;display:flex;flex-direction:column;align-items:flex-end;gap:6px;bottom:16px;right:16px;}'

      // ── Bubble ──
      + '.ely-bubble{width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 4px 16px rgba(124,58,237,.35);transition:transform .2s,box-shadow .2s;flex-shrink:0;}'
      + '.ely-bubble:hover{transform:scale(1.08);box-shadow:0 6px 24px rgba(124,58,237,.5);}'

      // ── Panel ──
      + '.ely-panel{width:360px;max-height:480px;background:var(--panel-bg,rgba(15,22,41,.95));backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.08);border-radius:14px;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4);}'

      // ── Header ──
      + '.ely-header{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.06);cursor:grab;user-select:none;}'
      + '.ely-header:active{cursor:grabbing;}'
      + '.ely-header-title{font-size:12px;font-weight:600;color:#c4b5fd;}'
      + '.ely-header-actions{display:flex;align-items:center;gap:6px;}'
      + '.ely-opacity-slider{width:50px;height:4px;-webkit-appearance:none;appearance:none;background:rgba(255,255,255,.15);border-radius:2px;outline:none;cursor:pointer;}'
      + '.ely-opacity-slider::-webkit-slider-thumb{-webkit-appearance:none;width:12px;height:12px;border-radius:50%;background:#a78bfa;cursor:pointer;}'
      + '.ely-header-btn{width:22px;height:22px;border-radius:5px;border:none;background:none;color:#6b7280;font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;}'
      + '.ely-header-btn:hover{background:rgba(255,255,255,.06);color:#d1d5db;}'

      // ── Messages ──
      + '.ely-messages{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;max-height:340px;font-size:12px;}'
      + '.ely-messages::-webkit-scrollbar{width:3px;}'
      + '.ely-messages::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:3px;}'
      + '.ely-msg{max-width:90%;padding:8px 12px;border-radius:10px;line-height:1.5;animation:elyFadeIn .2s ease-out;}'
      + '@keyframes elyFadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}'
      + '.ely-msg-user{align-self:flex-end;background:rgba(124,58,237,.15);color:#d1d5db;border-bottom-right-radius:4px;}'
      + '.ely-msg-ely{align-self:flex-start;background:rgba(255,255,255,.05);color:#e5e7eb;border-bottom-left-radius:4px;}'
      + '.ely-msg-action{font-size:10px;color:#a78bfa;padding:2px 0;}'
      + '.ely-msg-thinking{color:#6b7280;font-style:italic;font-size:11px;}'

      // ── Input ──
      + '.ely-input-row{display:flex;align-items:center;gap:6px;padding:8px 12px;border-top:1px solid rgba(255,255,255,.06);}'
      + '.ely-input{flex:1;height:32px;padding:0 10px;border-radius:8px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.04);color:#e5e7eb;font-size:12px;outline:none;transition:border-color .15s;}'
      + '.ely-input:focus{border-color:rgba(124,58,237,.4);}'
      + '.ely-input::placeholder{color:#4b5563;}'
      + '.ely-send-btn{width:32px;height:32px;border-radius:8px;border:none;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:opacity .15s;flex-shrink:0;}'
      + '.ely-send-btn:disabled{opacity:.4;cursor:not-allowed;}'

      // ── Resize handle (sibling of panel, positioned at its bottom-right) ──
      + '.ely-resize-handle{width:16px;height:16px;cursor:nwse-resize;align-self:flex-end;margin-top:-16px;position:relative;z-index:10;}'
      + '.ely-resize-handle::after{content:"";position:absolute;bottom:2px;right:2px;width:10px;height:10px;border-right:2px solid rgba(255,255,255,.25);border-bottom:2px solid rgba(255,255,255,.25);border-radius:0 0 3px 0;}'
      + '.ely-resize-handle:hover::after{border-color:rgba(255,255,255,.5);}'

      // ── Light theme ──
      + '[data-theme="light"] .ely-panel{--panel-bg:rgba(255,255,255,.92);}'
      + '[data-theme="light"] .ely-input{background:rgba(0,0,0,.03);color:#1e293b;border-color:rgba(0,0,0,.08);}'
      + '[data-theme="light"] .ely-msg-ely{background:rgba(0,0,0,.04);color:#1e293b;}'
      + '[data-theme="light"] .ely-msg-user{color:#1e293b;}'
      + '[data-theme="light"] .ely-header-title{color:#6d28d9;}'
      + '[data-theme="light"] .ely-bubble{box-shadow:0 4px 16px rgba(124,58,237,.25);}';
  }

  function _applyOpacity() {
    var panel = document.getElementById('ely-panel');
    if (panel) {
      var alpha = state.opacity / 100;
      panel.style.setProperty('--panel-bg', 'rgba(15,22,41,' + (alpha * 0.95).toFixed(2) + ')');
    }
  }

  // ── Reset to default ──
  function _resetPosition() {
    var hud = document.getElementById('ely-hud');
    if (!hud) return;
    hud.style.top = '';
    hud.style.left = '';
    hud.style.right = '16px';
    hud.style.bottom = '16px';
    var panel = document.getElementById('ely-panel');
    if (panel) {
      panel.style.width = '360px';
      panel.style.height = '';
      panel.style.maxHeight = '';
      document.getElementById('ely-messages').style.maxHeight = '340px';
    }
  }

  // ── Events ──
  function _bindEvents() {
    var bubble = document.getElementById('ely-bubble');
    var panel = document.getElementById('ely-panel');
    var input = document.getElementById('ely-input');
    var send = document.getElementById('ely-send');
    var minimize = document.getElementById('ely-minimize');
    var reset = document.getElementById('ely-reset');
    var opacity = document.getElementById('ely-opacity');
    var dragHandle = document.getElementById('ely-drag-handle');
    var resizeHandle = document.getElementById('ely-resize-handle');
    var hud = document.getElementById('ely-hud');

    bubble.addEventListener('click', function () {
      state.open = true;
      bubble.style.display = 'none';
      panel.style.display = 'flex';
      resizeHandle.style.display = 'block';
      input.focus();
    });

    minimize.addEventListener('click', function () {
      state.open = false;
      panel.style.display = 'none';
      resizeHandle.style.display = 'none';
      bubble.style.display = 'flex';
      // Snap to nearest corner
      var r = hud.getBoundingClientRect();
      var cx = r.left + r.width / 2;
      var cy = r.top + r.height / 2;
      var midX = window.innerWidth / 2;
      var midY = window.innerHeight / 2;
      hud.style.left = '';
      hud.style.top = '';
      hud.style.right = (cx > midX) ? '16px' : 'auto';
      hud.style.left = (cx <= midX) ? '16px' : 'auto';
      hud.style.bottom = (cy > midY) ? '16px' : 'auto';
      hud.style.top = (cy <= midY) ? '16px' : 'auto';
    });

    reset.addEventListener('click', _resetPosition);

    opacity.addEventListener('input', function () {
      state.opacity = parseInt(this.value);
      _applyOpacity();
      _save();
    });

    send.addEventListener('click', _sendMessage);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        _sendMessage();
      }
    });

    // ── Free drag (header) ──
    var dragging = false, dragX, dragY, startLeft, startTop;

    dragHandle.addEventListener('pointerdown', function (e) {
      if (e.target.tagName === 'BUTTON' || e.target.tagName === 'INPUT') return;
      dragging = true;
      dragX = e.clientX;
      dragY = e.clientY;
      var r = hud.getBoundingClientRect();
      startLeft = r.left;
      startTop = r.top;
      // Detach from CSS corners
      hud.style.right = 'auto';
      hud.style.bottom = 'auto';
      hud.style.left = startLeft + 'px';
      hud.style.top = startTop + 'px';
      hud.setPointerCapture(e.pointerId);
    });

    hud.addEventListener('pointermove', function (e) {
      if (!dragging) return;
      var newLeft = startLeft + e.clientX - dragX;
      var newTop = startTop + e.clientY - dragY;
      // Clamp to screen bounds
      var r = hud.getBoundingClientRect();
      newLeft = Math.max(0, Math.min(window.innerWidth - r.width, newLeft));
      newTop = Math.max(0, Math.min(window.innerHeight - r.height, newTop));
      hud.style.left = newLeft + 'px';
      hud.style.top = newTop + 'px';
    });

    hud.addEventListener('pointerup', function () { dragging = false; });

    // ── Resize (bottom-right handle) ──
    var resizing = false, rStartW, rStartH, rStartX, rStartY;

    resizeHandle.addEventListener('pointerdown', function (e) {
      resizing = true;
      rStartX = e.clientX;
      rStartY = e.clientY;
      rStartW = panel.offsetWidth;
      rStartH = panel.offsetHeight;
      e.stopPropagation();
      hud.setPointerCapture(e.pointerId);
    });

    hud.addEventListener('pointermove', function (e) {
      if (!resizing) return;
      var w = Math.max(300, Math.min(700, rStartW + e.clientX - rStartX));
      var h = Math.max(300, Math.min(800, rStartH + e.clientY - rStartY));
      panel.style.width = w + 'px';
      panel.style.height = h + 'px';
      panel.style.maxHeight = 'none';
      document.getElementById('ely-messages').style.maxHeight = (h - 100) + 'px';
    });

    hud.addEventListener('pointerup', function () { resizing = false; });
  }

  // ── Chat logic ──
  async function _sendMessage() {
    var input = document.getElementById('ely-input');
    var sendBtn = document.getElementById('ely-send');
    var text = input.value.trim();
    if (!text) return;

    input.value = '';
    sendBtn.disabled = true;

    _addMessage('user', text);
    state.messages.push({ role: 'user', content: text });

    var thinkingEl = _addMessage('ely', '<span class="ely-msg-thinking">Je reflechis...</span>');

    try {
      var token = (typeof getToken === 'function') ? getToken() : '';
      if (!token) token = sessionStorage.getItem('elyria_token') || '';

      var response = await fetch('/api/ely/chat', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token,
        },
        body: JSON.stringify({
          page: state.page,
          message: text,
          context: _collectContext(),
          history: state.messages.slice(0, -1),
        }),
      });

      if (!response.ok) {
        var err = { detail: 'Erreur ' + response.status };
        try { err = await response.json(); } catch (e) {}
        throw new Error(err.detail || 'Erreur ' + response.status);
      }

      var data = await response.json();
      thinkingEl.remove();

      if (data.reply) {
        _addMessage('ely', data.reply);
        state.messages.push({ role: 'assistant', content: data.reply });
      }
      if (data.actions && data.actions.length) {
        for (var a = 0; a < data.actions.length; a++) {
          var act = data.actions[a];
          var status = act.result && act.result.status ? (' → ' + act.result.status) : '';
          var err = act.result && act.result.error ? (' — ' + act.result.error) : '';
          _addMessage('ely', '<div class="ely-msg-action">✓ ' + _esc(act.name) + status + err + '</div>');
        }
      }
    } catch (e) {
      thinkingEl.remove();
      _addMessage('ely', 'Desole, impossible de contacter Ely. ' + _esc(e.message || ''));
    }

    sendBtn.disabled = false;
  }

  function _addMessage(role, content) {
    var container = document.getElementById('ely-messages');
    var el = document.createElement('div');
    el.className = 'ely-msg ely-msg-' + role;
    if (typeof content === 'string' && content.indexOf('<') === 0) {
      el.innerHTML = content;
    } else {
      el.textContent = content;
    }
    container.appendChild(el);
    _scrollDown();
    return el;
  }

  function _scrollDown() {
    var container = document.getElementById('ely-messages');
    if (container) container.scrollTop = container.scrollHeight;
  }

  function _esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  function _collectContext() {
    var ctx = { url: window.location.href };
    if (state.page === 'app') {
      var methodEl = document.querySelector('.method-badge');
      var urlEl = document.querySelector('input[placeholder*="URL"]') || document.querySelector('input[placeholder*="url"]');
      if (methodEl) ctx.method = methodEl.textContent.trim();
      if (urlEl) ctx.url_input = urlEl.value;
    }
    if (state.page === 'workflow') {
      var wfName = document.getElementById('wf-name');
      if (wfName) ctx.workflow_name = wfName.value;
    }
    return ctx;
  }

  // ── Init ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _build);
  } else {
    _build();
  }
})();
