/* ═══════════════════════════════════════════════════════════════
   Elyria — elyria-ui.js
   Shared UI component library (vanilla JS, zero dependencies).

   Provides:
     - renderHeader()     — top navigation bar HTML
     - buildSidebar()     — sidebar skeleton HTML
     - buildPageShell()   — full page layout (header + sidebar + main)
     - buildModal()       — modal dialog HTML
     - $, $$, esc()       — DOM helpers
     - TAILWIND_THEME     — shared color palette

   Dependencies: auth.js (must be loaded first).
   The header HTML uses #header-username and #btn-logout, which
   auth.js's initHeaderUser() wires up automatically.
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── Theme ──

  // Tailwind config uses hardcoded dark values so opacity modifiers work correctly.
  // Light theme is applied via CSS overrides injected by injectTheme().
  var TAILWIND_THEME = {
    base:    { 900: '#0a0f1c', 800: '#0f1629', 700: '#141c35', 600: '#1a2340', 500: '#212b4a' },
    primary: { DEFAULT: '#7c3aed', light: '#a78bfa', dark: '#6d28d9', 50: 'rgba(124,58,237,0.08)', 100: 'rgba(124,58,237,0.15)' },
    accent:  { DEFAULT: '#06b6d4', light: '#22d3ee', dark: '#0891b2', 50: 'rgba(6,182,212,0.08)', 100: 'rgba(6,182,212,0.15)' },
    critical:{ DEFAULT: '#ef4444', light: '#f87171' },
    high:    { DEFAULT: '#f97316', light: '#fb923c' },
    medium:  { DEFAULT: '#e2a03f', light: '#f0bc54' },
    low:     { DEFAULT: '#22c55e', light: '#4ade80' },
    info:    { DEFAULT: '#6b7280', light: '#9ca3af' },
  };

  // ── Theme injection ──

  function injectTheme() {
    if (document.getElementById('elyria-theme-css')) return;

    var css = ''
      // ── Dark theme: explicit rules (fallback when Tailwind CDN is slow/blocked) ──
      + '[data-theme="dark"] .bg-base-900{background-color:#0a0f1c;}'
      + '[data-theme="dark"] .bg-base-800{background-color:#0f1629;}'
      + '[data-theme="dark"] .bg-base-700{background-color:#141c35;}'
      + '[data-theme="dark"] .bg-base-600{background-color:#1a2340;}'
      + '[data-theme="dark"] .bg-base-500{background-color:#212b4a;}'
      + '[data-theme="dark"] .text-gray-200{color:#e5e7eb;}'
      + '[data-theme="dark"] .text-gray-300{color:#d1d5db;}'
      + '[data-theme="dark"] .text-gray-400{color:#9ca3af;}'
      + '[data-theme="dark"] .text-gray-500{color:#6b7280;}'
      + '[data-theme="dark"] .text-gray-600{color:#4b5563;}'
      + '[data-theme="dark"] .text-slate-400{color:#94a3b8;}'
      + '[data-theme="dark"] .text-slate-500{color:#64748b;}'
      + '[data-theme="dark"] .text-white{color:#ffffff;}'
      + '[data-theme="dark"] .border-white\\/5{border-color:rgba(255,255,255,0.05);}'
      + '[data-theme="dark"] .border-white\\/10{border-color:rgba(255,255,255,0.10);}'
      + '[data-theme="dark"] .border-white\\/20{border-color:rgba(255,255,255,0.15);}'
      + '[data-theme="dark"] .bg-white\\/5{background-color:rgba(255,255,255,0.05);}'
      + '[data-theme="dark"] .bg-white\\/10{background-color:rgba(255,255,255,0.10);}'
      + '[data-theme="dark"] .hover\\:bg-white\\/5:hover{background-color:rgba(255,255,255,0.05);}'
      + '[data-theme="dark"] .hover\\:bg-white\\/10:hover{background-color:rgba(255,255,255,0.10);}'

      // ── Light theme: core bg/text overrides ──
      + '[data-theme="light"] .bg-base-900{background-color:#f1f5f9;}'
      + '[data-theme="light"] .bg-base-800{background-color:#ffffff;}'
      + '[data-theme="light"] .bg-base-700{background-color:#f8fafc;}'
      + '[data-theme="light"] .bg-base-600{background-color:#e2e8f0;}'
      + '[data-theme="light"] .bg-base-500{background-color:#cbd5e1;}'
      + '[data-theme="light"] .text-gray-200,[data-theme="light"] .text-gray-300{color:#1e293b;}'
      + '[data-theme="light"] .text-gray-400{color:#334155;}'
      + '[data-theme="light"] .text-gray-500,[data-theme="light"] .text-gray-600{color:#475569;}'
      + '[data-theme="light"] .text-slate-400{color:#475569;}'
      + '[data-theme="light"] .text-slate-500{color:#64748b;}'

      // ── Light theme: border overrides ──
      + '[data-theme="light"] .border-white\\/5{border-color:rgba(0,0,0,0.06);}'
      + '[data-theme="light"] .border-white\\/10{border-color:rgba(0,0,0,0.10);}'
      + '[data-theme="light"] .border-white\\/15{border-color:rgba(0,0,0,0.12);}'
      + '[data-theme="light"] .border-white\\/20{border-color:rgba(0,0,0,0.15);}'
      + '[data-theme="light"] .border-white\\/25{border-color:rgba(0,0,0,0.18);}'
      + '[data-theme="light"] .border-white\\/30{border-color:rgba(0,0,0,0.20);}'
      + '[data-theme="light"] .border-white\\/40{border-color:rgba(0,0,0,0.25);}'

      // ── Light theme: transparent-bg overrides ──
      + '[data-theme="light"] .bg-white\\/5{background-color:rgba(0,0,0,0.03);}'
      + '[data-theme="light"] .bg-white\\/10{background-color:rgba(0,0,0,0.05);}'
      + '[data-theme="light"] .hover\\:bg-white\\/5:hover{background-color:rgba(0,0,0,0.03);}'
      + '[data-theme="light"] .hover\\:bg-white\\/10:hover{background-color:rgba(0,0,0,0.05);}'
      + '[data-theme="light"] .bg-gray-500\\/8{background-color:rgba(0,0,0,0.04);}'
      + '[data-theme="light"] .bg-gray-500\\/10{background-color:rgba(0,0,0,0.05);}'
      + '[data-theme="light"] .bg-gray-500\\/20{background-color:rgba(0,0,0,0.10);}'
      + '[data-theme="light"] .bg-black\\/60{background-color:rgba(0,0,0,0.3);}'
      + '[data-theme="light"] .bg-base-700\\/40{background-color:rgba(0,0,0,0.04);}'
      + '[data-theme="light"] .bg-base-900\\/60{background-color:rgba(0,0,0,0.05);}'
      + '[data-theme="light"] .bg-base-900\\/90{background-color:rgba(0,0,0,0.5);}'

      // ── Light theme: primary/accent overrides (slightly darker for contrast on white) ──
      + '[data-theme="light"] .bg-primary\\/80{background-color:#6d28d9;}'
      + '[data-theme="light"] .bg-primary\\/15,[data-theme="light"] .hover\\:bg-primary\\/15:hover{background-color:rgba(124,58,237,0.08);}'
      + '[data-theme="light"] .text-primary-light{color:#7c3aed;}'
      + '[data-theme="light"] .hover\\:text-primary-light:hover{color:#7c3aed;}'
      + '[data-theme="light"] .border-primary\\/30{border-color:rgba(124,58,237,0.20);}'
      + '[data-theme="light"] .border-primary\\/40{border-color:rgba(124,58,237,0.25);}'
      + '[data-theme="light"] .hover\\:border-primary\\/30:hover{border-color:rgba(124,58,237,0.20);}'
      + '[data-theme="light"] .hover\\:border-primary\\/40:hover{border-color:rgba(124,58,237,0.25);}'
      + '[data-theme="light"] .hover\\:bg-accent\\/15:hover{background-color:rgba(6,182,212,0.08);}'
      + '[data-theme="light"] .hover\\:border-accent\\/40:hover{border-color:rgba(6,182,212,0.25);}'
      + '[data-theme="light"] .text-accent-light{color:#0891b2;}'
      + '[data-theme="light"] .hover\\:text-accent-light:hover{color:#0891b2;}'

      // ── Force dark form elements (override browser defaults) ──
      + '[data-theme="dark"] input:not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"]),'
      + '[data-theme="dark"] select,[data-theme="dark"] textarea{background-color:#141c35;color:#d1d5db;}'

      // ── Theme toggle switch styles ──
      + '.elyria-theme-toggle{position:relative;display:inline-flex;align-items:center;cursor:pointer;}'
      + '.elyria-theme-toggle *{pointer-events:none;}'
      + '.elyria-theme-toggle-track{width:38px;height:22px;border-radius:999px;background:#374151;transition:all .3s ease;display:flex;align-items:center;padding:2px;box-shadow:inset 0 1px 3px rgba(0,0,0,.2);}'
      + '[data-theme="light"] .elyria-theme-toggle-track{background:#cbd5e1;}'
      + '.elyria-theme-toggle-thumb{width:18px;height:18px;border-radius:50%;background:#fff;transform:translateX(0);transition:transform .3s cubic-bezier(.4,0,.2,1);display:flex;align-items:center;justify-content:center;font-size:10px;line-height:1;box-shadow:0 1px 4px rgba(0,0,0,.25);}'
      + '[data-theme="light"] .elyria-theme-toggle-thumb{transform:translateX(16px);}'
      + '.elyria-theme-toggle:hover .elyria-theme-toggle-track{box-shadow:inset 0 1px 3px rgba(0,0,0,.3),0 0 0 2px rgba(124,58,237,.3);}'
      + '.ely-eye{fill:#06b6d4;}'
      + '[data-theme="dark"] .ely-eye{fill:#7c3aed;}';

    var style = document.createElement('style');
    style.id = 'elyria-theme-css';
    style.textContent = css;
    document.head.appendChild(style);
  }

  // ── Theme control ──

  function getTheme() {
    return document.documentElement.getAttribute('data-theme') || 'dark';
  }

  function setTheme(theme) {
    theme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    try { document.body.setAttribute('data-theme', theme); } catch(e) {}
    try { localStorage.setItem('elyria-theme', theme); } catch(e) {}
  }

  function toggleTheme() {
    try {
      var next = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(next);
    } catch(e) { console.error('toggleTheme error:', e); }
  }

  function initTheme() {
    var saved;
    try { saved = localStorage.getItem('elyria-theme'); } catch(e) {}
    setTheme(saved || 'dark');
  }

  // Bind theme toggle via event delegation on document
  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.elyria-theme-toggle');
    if (btn) {
      e.stopPropagation();
      toggleTheme();
    }
  });

  // Inject theme CSS immediately (before Tailwind CDN scans the DOM)
  injectTheme();

  // Apply saved theme preference after DOM is interactive
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
  } else {
    initTheme();
  }

  // ── Nav items definition ──

  var NAV_ITEMS = [
    { id: 'app',      label: 'Client API', path: '/app',      color: 'cyan' },
    { id: 'workflow', label: 'Workflows',  path: '/workflow', color: 'green' },
    { id: 'pentest',  label: 'Red Team',   path: '/pentest',  color: 'red' },
    { id: 'greyteam', label: 'Grey Team',  path: '/greyteam', color: 'gray' },
    { id: 'blueteam',   label: 'Blue Team',   path: '/blueteam',   color: 'blue' },
    { id: 'purpleteam', label: 'Purple Team', path: '/purpleteam', color: 'purple' },
  ];

  // ── DOM helpers ──

  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return document.querySelectorAll(sel); }
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // ── SVG icons ──

  var ICONS = {
    logout: '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>',
    globe: '<svg class="w-16 h-16 mb-4 opacity-20" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1"><path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>',
    shield: '<svg class="w-12 h-12 mb-3 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>',
  };

  // ── Page builder ──

  var SIDEBAR_OPEN = {};  // sidebar-id → true/false

  function toggleSidebar(sidebarId) {
    var el = document.getElementById(sidebarId || 'sidebar-left');
    if (!el) return;
    var open = SIDEBAR_OPEN[sidebarId] !== false;
    if (open) {
      el.style.width = '0';
      el.style.minWidth = '0';
      el.style.overflow = 'hidden';
      el.style.padding = '0';
      el.style.border = 'none';
      SIDEBAR_OPEN[sidebarId] = false;
    } else {
      el.style.width = '';
      el.style.minWidth = '';
      el.style.overflow = '';
      el.style.padding = '';
      el.style.border = '';
      SIDEBAR_OPEN[sidebarId] = true;
    }
    try { localStorage.setItem('elyria-sb-' + sidebarId, SIDEBAR_OPEN[sidebarId] ? '1' : '0'); } catch(e) {}
  }

  function togglePanel(panelId) {
    var panel = document.getElementById('panel-' + panelId);
    var btn = document.getElementById('btn-panel-' + panelId);
    if (!panel) return;

    var open = !panel.classList.contains('hidden');
    if (open) {
      panel.classList.add('hidden');
      if (btn) btn.classList.remove('bg-white/10', 'text-gray-200');
    } else {
      panel.classList.remove('hidden');
      if (btn) btn.classList.add('bg-white/10', 'text-gray-200');
    }
  }

  /**
   * Build a complete Elyria page.
   *
   * Header structure (fixed):
   *   LEFT  : logo | nav (all pages except current)
   *   CENTER: [burger] [controls] [panel buttons]
   *   RIGHT : theme toggle | Hub | username | logout
   *
   * @param {Object} opts
   *   .active   — current page id ('app','workflow','pentest','blueteam','greyteam','doc')
   *   .controls — raw HTML injected in header center (page-specific actions)
   *   .burger   — truthy to show burger menu that toggles the left sidebar (id 'sidebar-left')
   *   .panels   — array of {id, label, width?, html} for right-side panels toggled by center buttons
   *   .sidebar  — {width?, html} left sidebar (width defaults to 'w-56')
   *   .main     — {html} main content area
   *   .hubButton  — show Hub button (default true)
   *   .logoutBtn  — show logout button (default true)
   * @returns {string} HTML
   */
  function buildPage(opts) {
    opts = opts || {};
    var active = opts.active || '';
    var controls = opts.controls || '';
    var burger = !!opts.burger;
    var panels = opts.panels || [];
    var sidebar = opts.sidebar || {};
    var main = opts.main || {};
    var hubBtn = opts.hubButton !== false;
    var logoutBtn = opts.logoutBtn !== false;

    // ── Header: LEFT (logo + nav) ──

    var navHTML = NAV_ITEMS.filter(function(item) {
      return item.id !== active;
    }).map(function(item) {
      return '<button onclick="navigateTo(\'' + item.path + '\')" class="h-7 px-2.5 rounded-md text-[11px] text-gray-500 hover:text-' + item.color + '-400 hover:bg-' + item.color + '-500/5 transition-all">' + esc(item.label) + '</button>';
    }).join('');

    // ── Header: CENTER (burger + controls + panel buttons) ──

    var centerHTML = '';

    if (burger) {
      centerHTML += '<button onclick="ElyriaUI.toggleSidebar(\'sidebar-left\')" class="h-8 w-8 rounded-lg bg-base-700 hover:bg-white/5 border border-white/5 text-gray-500 hover:text-gray-300 transition-all flex items-center justify-center flex-shrink-0" title="Toggle sidebar">'
        + '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5"/></svg>'
        + '</button>';
    }

    if (controls) {
      centerHTML += controls;
    }

    for (var i = 0; i < panels.length; i++) {
      var p = panels[i];
      var pLabel = p.label || p.id;
      var pId = p.id || ('panel' + i);
      centerHTML += '<button id="btn-panel-' + pId + '" onclick="ElyriaUI.togglePanel(\'' + pId + '\')" class="h-8 px-3 rounded-lg bg-base-700 hover:bg-white/5 border border-white/5 text-xs text-gray-500 hover:text-gray-300 transition-all flex items-center gap-1.5">' + esc(pLabel) + '</button>';
    }

    // ── Header: RIGHT (theme + hub + user + logout) ──

    var rightHTML = '<button class="elyria-theme-toggle h-8 w-12 rounded-full hover:bg-white/5 border border-transparent hover:border-white/5 flex items-center justify-center transition-all flex-shrink-0" title="Basculer le theme clair/sombre">'
      + '<span class="elyria-theme-toggle-track"><span class="elyria-theme-toggle-thumb"></span></span>'
      + '</button>';

    if (hubBtn) {
      rightHTML += '<button onclick="navigateTo(\'/hub\')" class="h-8 px-3 rounded-lg bg-base-700 hover:bg-primary/15 border border-white/5 hover:border-primary/30 text-xs font-medium text-gray-400 hover:text-primary-light transition-all">Hub</button>';
    }
    if (active !== 'doc') {
      rightHTML += '<button onclick="navigateTo(\'/doc\')" class="h-8 px-3 rounded-lg bg-base-700 hover:bg-purple-500/10 border border-white/5 hover:border-purple-500/30 text-xs font-medium text-gray-400 hover:text-purple-400 transition-all">Docs</button>';
    }
    rightHTML += '<button id="btn-toggle-copilot" class="h-8 px-3 rounded-lg bg-base-700 hover:bg-primary/20 border border-white/5 hover:border-primary/40 text-xs font-medium text-gray-400 hover:text-primary-light transition-all flex items-center gap-1.5" title="Ely Copilot">'
      + '<svg class="w-3.5 h-3.5" viewBox="0 0 400 400" fill="currentColor"><ellipse stroke="currentColor" stroke-width="18" ry="72" rx="48" cy="195" cx="200"/><ellipse stroke="currentColor" stroke-width="16" ry="29" rx="36" cy="125" cx="200"/><circle class="ely-eye" r="10" cy="122" cx="175"/><circle class="ely-eye" r="10" cy="122" cx="225"/><path stroke="currentColor" stroke-linecap="round" stroke-width="16" fill="none" d="M150 165 L85 70 L65 95"/><path stroke="currentColor" stroke-linecap="round" stroke-width="16" fill="none" d="M145 185 L75 130 L55 165"/><path stroke="currentColor" stroke-linecap="round" stroke-width="15" fill="none" d="M145 220 L80 235 L65 280"/><path stroke="currentColor" stroke-linecap="round" stroke-width="15" fill="none" d="M155 245 L95 285 L105 335"/><path stroke="currentColor" stroke-linecap="round" stroke-width="16" fill="none" d="M250 165 L315 70 L335 95"/><path stroke="currentColor" stroke-linecap="round" stroke-width="16" fill="none" d="M255 185 L325 130 L345 165"/><path stroke="currentColor" stroke-linecap="round" stroke-width="15" fill="none" d="M255 220 L320 235 L335 280"/><path stroke="currentColor" stroke-linecap="round" stroke-width="15" fill="none" d="M245 245 L305 285 L295 335"/></svg>'
      + 'ELY</button>';
    rightHTML += '<span id="header-username" class="text-[10px] text-gray-500 font-medium hidden"></span>';
    if (logoutBtn) {
      rightHTML += '<button id="btn-logout" class="h-8 px-3 rounded-lg bg-base-700 hover:bg-red-500/10 border border-white/5 hover:border-red-500/30 text-gray-500 hover:text-red-400 text-xs font-medium transition-all flex items-center gap-1.5" title="Logout">' + ICONS.logout + '</button>';
    }

    // ── Header assembly ──

    var headerHTML = '<header class="h-12 bg-base-800 border-b border-white/5 flex items-center justify-between px-5 shrink-0 z-50 relative">'
      + '<div class="flex items-center gap-2">'
      + '<a href="/app" class="flex items-center gap-2 no-underline flex-shrink-0">'
      + '<img src="/static/icons/icon.svg" class="w-7 h-7" alt="" />'
      + '<span class="text-sm font-medium tracking-widest text-slate-400">elyria</span>'
      + '</a>'
      + '<div class="w-px h-5 bg-white/10"></div>'
      + '<nav class="flex items-center gap-1">' + navHTML + '</nav>'
      + '</div>'
      + '<div class="flex items-center gap-1.5">' + centerHTML + '</div>'
      + '<div class="flex items-center gap-2">' + rightHTML + '</div>'
      + '</header>';

    // ── Sidebar ──

    var sidebarWidth = sidebar.width || 'w-56';
    var sidebarHTML = sidebar.html ? ('<aside id="sidebar-left" class="' + sidebarWidth + ' bg-base-800 border-r border-white/5 flex flex-col shrink-0 overflow-hidden transition-all duration-300">' + sidebar.html + '</aside>') : '';

    // ── Right panels ──

    var panelsHTML = '';
    for (var i = 0; i < panels.length; i++) {
      var p = panels[i];
      var pId = p.id || ('panel' + i);
      var pWidth = p.width || 'w-80';
      panelsHTML += '<aside id="panel-' + pId + '" class="hidden ' + pWidth + ' bg-base-800 border-l border-white/5 flex flex-col shrink-0 overflow-y-auto">' + (p.html || '') + '</aside>';
    }

    // ── Full layout ──

    return headerHTML
      + '<div class="flex h-[calc(100%-3rem)]">'
      + sidebarHTML
      + '<main class="flex-1 flex flex-col overflow-hidden">' + (main.html || '') + '</main>'
      + panelsHTML
      + '</div>';
  }

  // ── Backward-compatible renderHeader (delegates to buildPage internal logic) ──

  function renderHeader(opts) {
    // Simple wrapper: build a standalone header without page layout
    opts = opts || {};
    var html = buildPage({
      active: opts.active || '',
      controls: opts.centerHTML || '',
      burger: false,
      panels: [],
      sidebar: {},
      main: { html: '' },
      hubButton: opts.hubButton,
      logoutBtn: opts.logoutBtn,
    });
    // Extract just the header part
    var headerEnd = html.indexOf('</header>');
    if (headerEnd > -1) return html.substring(0, headerEnd + 9);
    return html;
  }

  function injectHeader(targetId, opts) {
    var el = document.getElementById(targetId);
    if (!el) return;
    el.outerHTML = renderHeader(opts);
  }

  // ── buildModal ──

  /**
   * Build a modal dialog skeleton.
   *
   * @param {Object} opts
   *   .id        — modal root id
   *   .title     — modal title
   *   .width     — CSS width class (default 'max-w-lg')
   *   .bodyHTML  — body content
   *   .footerHTML — footer content (buttons)
   * @returns {string} HTML
   */
  function buildModal(opts) {
    opts = opts || {};
    var id = opts.id || 'modal';
    var title = opts.title || '';
    var width = opts.width || 'max-w-lg';
    var bodyHTML = opts.bodyHTML || '';
    var footerHTML = opts.footerHTML || '';

    return '<div id="' + id + '" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">'
      + '<div class="bg-base-800 border border-white/10 rounded-xl ' + width + ' w-full mx-4 max-h-[80vh] overflow-y-auto shadow-2xl">'
      + '<div class="p-4 border-b border-white/5 flex items-center justify-between">'
      + '<h3 class="text-sm font-semibold text-gray-200">' + esc(title) + '</h3>'
      + '<button onclick="ElyriaUI.closeModal(\'' + id + '\')" class="w-6 h-6 rounded-md hover:bg-white/5 flex items-center justify-center text-gray-500 hover:text-gray-300 transition-colors">&times;</button>'
      + '</div>'
      + '<div class="p-4 space-y-3">' + bodyHTML + '</div>'
      + (footerHTML ? '<div class="p-3 border-t border-white/5 flex justify-end gap-2">' + footerHTML + '</div>' : '')
      + '</div>'
      + '</div>';
  }

  function openModal(id) {
    var el = document.getElementById(id);
    if (el) el.classList.remove('hidden');
  }

  function closeModal(id) {
    var el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  }

  // ── buildEmptyState ──

  /**
   * Build an empty-state placeholder.
   * @param {Object} opts
   *   .icon       — SVG icon string
   *   .title      — main text
   *   .subtitle   — secondary text
   *   .actionHTML — optional CTA button HTML
   */
  function buildEmptyState(opts) {
    opts = opts || {};
    var icon = opts.icon || ICONS.shield;
    var title = opts.title || '';
    var subtitle = opts.subtitle || '';
    var actionHTML = opts.actionHTML || '';

    return '<div class="flex flex-col items-center justify-center h-full text-gray-600">'
      + icon
      + (title ? '<p class="text-sm font-medium mb-1">' + esc(title) + '</p>' : '')
      + (subtitle ? '<p class="text-xs">' + esc(subtitle) + '</p>' : '')
      + (actionHTML || '')
      + '</div>';
  }

  // ── buildToast (simple notification banner) ──

  function showToast(message, type) {
    type = type || 'info';
    var colors = { info: 'bg-accent/90', error: 'bg-critical/90', success: 'bg-low/90' };
    var toast = document.createElement('div');
    toast.className = 'fixed bottom-4 right-4 z-[100] px-4 py-2 rounded-lg text-xs text-white font-medium shadow-lg transition-all ' + (colors[type] || colors.info);
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(function () {
      toast.style.opacity = '0';
      setTimeout(function () { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 300);
    }, 3000);
  }

  // ── tailwindConfig ──

  /**
   * Build the tailwind.config object for Tailwind CDN.
   * Merges page-specific color overrides into the shared theme.
   *
   * Usage in <head>:
   *   <script src="static/elyria-ui.js"></script>
   *   <script>tailwind.config = ElyriaUI.tailwindConfig({primary: {DEFAULT: '#6b7280', ...}});</script>
   *   <script src="https://cdn.tailwindcss.com"></script>
   *
   * @param {Object} overrides — optional per-page color overrides
   * @returns {Object} tailwind.config
   */
  function tailwindConfig(overrides) {
    var colors = JSON.parse(JSON.stringify(TAILWIND_THEME));
    if (overrides) {
      Object.keys(overrides).forEach(function (k) {
        colors[k] = overrides[k];
      });
    }
    return { theme: { extend: { colors: colors } } };
  }

  // ── Exports ──

  // ═══════════════════════════════════════════════════════════════
  // JSON Editor — rich JSON editing component
  // ═══════════════════════════════════════════════════════════════

  var _jsonEditorStylesInjected = false;

  function _injectJsonEditorStyles() {
    if (_jsonEditorStylesInjected) return;
    _jsonEditorStylesInjected = true;
    var style = document.createElement('style');
    style.id = 'ely-json-editor-styles';
    style.textContent = ''
      + '.json-editor-wrap{position:relative;border:1px solid rgba(255,255,255,.06);border-radius:8px;overflow:hidden;background:#0a0f1c;min-height:80px;display:flex;flex-direction:column;}'
      + '.json-editor-wrap:focus-within{border-color:rgba(124,58,237,.4);box-shadow:0 0 0 2px rgba(124,58,237,.1);}'
      + '.json-editor-wrap.has-error{border-color:rgba(239,68,68,.4);box-shadow:0 0 0 2px rgba(239,68,68,.1);}'
      + '.json-editor-wrap.has-error:focus-within{border-color:rgba(239,68,68,.5);}'
      + '.json-editor-tb{display:flex;align-items:center;justify-content:space-between;padding:4px 8px;background:rgba(255,255,255,.02);border-bottom:1px solid rgba(255,255,255,.04);flex-shrink:0;min-height:28px;}'
      + '.json-editor-tb-left{display:flex;align-items:center;gap:4px;}'
      + '.json-editor-msg{font-size:9px;font-family:"JetBrains Mono",monospace;color:#f87171;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}'
      + '.json-editor-msg.ok{color:#4ade80;}'
      + '.json-editor-btn{height:20px;padding:0 6px;border-radius:4px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.03);color:#9ca3af;font-size:9px;font-weight:600;cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:2px;font-family:"JetBrains Mono",monospace;}'
      + '.json-editor-btn:hover{background:rgba(255,255,255,.08);color:#e5e7eb;border-color:rgba(255,255,255,.12);}'
      + '.json-editor-btn.fmt:hover{background:rgba(124,58,237,.15);border-color:rgba(124,58,237,.3);color:#a78bfa;}'
      + '.json-editor-btn.minify{font-size:8px;}'
      + '.json-editor-body{display:flex;flex:1;min-height:60px;position:relative;}'
      + '.json-editor-gutter{width:36px;flex-shrink:0;background:rgba(255,255,255,.015);border-right:1px solid rgba(255,255,255,.04);padding:8px 0;overflow:hidden;user-select:none;}'
      + '.json-editor-gutter div{height:18px;line-height:18px;font-size:9px;font-family:"JetBrains Mono",monospace;color:rgba(255,255,255,.15);text-align:right;padding-right:6px;}'
      + '.json-editor-area{flex:1;position:relative;overflow:hidden;}'
      + '.json-editor-highlight{position:absolute;top:0;left:0;right:0;bottom:0;padding:8px 10px;font-family:"JetBrains Mono",monospace;font-size:11px;line-height:18px;tab-size:2;white-space:pre-wrap;word-wrap:break-word;overflow:auto;pointer-events:none;color:transparent;}'
      + '.json-editor-highlight code{font-family:inherit;font-size:inherit;}'
      + '.json-editor-textarea{display:block;width:100%;height:100%;padding:8px 10px;font-family:"JetBrains Mono",monospace;font-size:11px;line-height:18px;tab-size:2;color:transparent;caret-color:#e5e7eb;background:transparent;border:none;outline:none;resize:none;overflow:auto;position:relative;z-index:2;}'
      + '.json-editor-textarea::selection{background:rgba(124,58,237,.35);}'
      + '.json-key{color:#93c5fd;}'
      + '.json-string{color:#86efac;}'
      + '.json-number{color:#fde68a;}'
      + '.json-bool{color:#c084fc;}'
      + '.json-null{color:#94a3b8;}'
      + '.json-punct{color:#e5e7eb;}'
      + '.json-err-underline{text-decoration:wavy underline #ef4444;text-underline-offset:3px;}';
    document.head.appendChild(style);
  }

  function _highlightJson(text) {
    // Robust tokenizer that walks the JSON string
    var out = '';
    var i = 0;
    var len = text.length;
    while (i < len) {
      var ch = text[i];
      // String
      if (ch === '"') {
        var start = i;
        i++;
        while (i < len) {
          if (text[i] === '\\') { i += 2; continue; }
          if (text[i] === '"') { i++; break; }
          i++;
        }
        var str = text.substring(start, i);
        // Check if followed by :
        var after = text.substring(i).trimStart();
        if (after.startsWith(':')) {
          out += '<span class="json-key">' + esc(str) + '</span>';
        } else {
          out += '<span class="json-string">' + esc(str) + '</span>';
        }
        continue;
      }
      // Number
      if ((ch === '-' && i+1 < len && text[i+1] >= '0' && text[i+1] <= '9') || (ch >= '0' && ch <= '9')) {
        var numStart = i;
        if (ch === '-') i++;
        while (i < len && ((text[i] >= '0' && text[i] <= '9') || text[i] === '.' || text[i] === 'e' || text[i] === 'E' || text[i] === '+' || text[i] === '-')) {
          if ((text[i] === '+' || text[i] === '-') && numStart !== i-1 && text[i-1] !== 'e' && text[i-1] !== 'E') break;
          i++;
        }
        out += '<span class="json-number">' + esc(text.substring(numStart, i)) + '</span>';
        continue;
      }
      // true / false / null
      if (text.substring(i, i+4) === 'true') { out += '<span class="json-bool">true</span>'; i += 4; continue; }
      if (text.substring(i, i+5) === 'false') { out += '<span class="json-bool">false</span>'; i += 5; continue; }
      if (text.substring(i, i+4) === 'null') { out += '<span class="json-null">null</span>'; i += 4; continue; }
      // Punctuation
      if ('{}[]:,'.indexOf(ch) !== -1) {
        out += '<span class="json-punct">' + esc(ch) + '</span>';
        i++;
        continue;
      }
      out += esc(ch);
      i++;
    }
    return out;
  }

  function _updateLineNumbers(container) {
    var textarea = container.querySelector('.json-editor-textarea');
    var gutter = container.querySelector('.json-editor-gutter');
    if (!textarea || !gutter) return;
    var lines = (textarea.value || '').split('\n');
    var currentCount = gutter.children.length;
    if (lines.length === currentCount) return; // no change
    var html = '';
    for (var l = 0; l < lines.length; l++) {
      html += '<div>' + (l + 1) + '</div>';
    }
    gutter.innerHTML = html;
  }

  function _syncScroll(container) {
    var textarea = container.querySelector('.json-editor-textarea');
    var highlight = container.querySelector('.json-editor-highlight');
    var gutter = container.querySelector('.json-editor-gutter');
    if (textarea && highlight) highlight.scrollTop = textarea.scrollTop;
    if (textarea && gutter) gutter.scrollTop = textarea.scrollTop;
  }

  function _updateHighlight(container) {
    var textarea = container.querySelector('.json-editor-textarea');
    var highlight = container.querySelector('.json-editor-highlight code');
    if (!textarea || !highlight) return;
    var raw = textarea.value || '';
    highlight.innerHTML = _highlightJson(raw) + '\n';
    _updateLineNumbers(container);
    _validateAndShow(container, raw);
  }

  function _validateAndShow(container, raw) {
    var msgEl = container.querySelector('.json-editor-msg');
    if (!msgEl) return;
    if (!raw.trim()) {
      msgEl.textContent = '';
      msgEl.className = 'json-editor-msg';
      container.classList.remove('has-error');
      return;
    }
    try {
      JSON.parse(raw);
      msgEl.textContent = 'JSON valide';
      msgEl.className = 'json-editor-msg ok';
      container.classList.remove('has-error');
    } catch(e) {
      msgEl.textContent = e.message;
      msgEl.className = 'json-editor-msg';
      container.classList.add('has-error');
    }
  }

  function _formatJson(container) {
    var textarea = container.querySelector('.json-editor-textarea');
    if (!textarea) return;
    var raw = textarea.value.trim();
    if (!raw) return;
    try {
      var parsed = JSON.parse(raw);
      textarea.value = JSON.stringify(parsed, null, 2);
    } catch(e) {
      // Can't format invalid JSON
    }
    _updateHighlight(container);
    _syncScroll(container);
  }

  function _minifyJson(container) {
    var textarea = container.querySelector('.json-editor-textarea');
    if (!textarea) return;
    var raw = textarea.value.trim();
    if (!raw) return;
    try {
      var parsed = JSON.parse(raw);
      textarea.value = JSON.stringify(parsed);
    } catch(e) {
      // Can't minify invalid JSON
    }
    _updateHighlight(container);
    _syncScroll(container);
  }

  function _handleTab(textarea, e) {
    e.preventDefault();
    var start = textarea.selectionStart;
    var end = textarea.selectionEnd;
    textarea.value = textarea.value.substring(0, start) + '  ' + textarea.value.substring(end);
    textarea.selectionStart = textarea.selectionEnd = start + 2;
    textarea.dispatchEvent(new Event('input', {bubbles: true}));
  }

  function _handleAutoPair(textarea, e) {
    var pairs = {'{': '}', '[': ']', '"': '"'};
    var ch = e.key;
    if (!pairs[ch]) return;
    var start = textarea.selectionStart;
    var end = textarea.selectionEnd;
    var val = textarea.value;
    // If there's a selection, wrap it
    if (start !== end) {
      e.preventDefault();
      textarea.value = val.substring(0, start) + ch + val.substring(start, end) + pairs[ch] + val.substring(end);
      textarea.selectionStart = start + 1;
      textarea.selectionEnd = end + 1;
      textarea.dispatchEvent(new Event('input', {bubbles: true}));
      return;
    }
    // Smart: don't double-close if next char is the closing pair
    if (ch === '"' && val[start] === '"') {
      e.preventDefault();
      textarea.selectionStart = textarea.selectionEnd = start + 1;
      return;
    }
    if ((ch === '}' || ch === ']') && val[start] === ch) {
      e.preventDefault();
      textarea.selectionStart = textarea.selectionEnd = start + 1;
      return;
    }
    // Auto-insert closing pair
    e.preventDefault();
    textarea.value = val.substring(0, start) + ch + pairs[ch] + val.substring(end);
    textarea.selectionStart = textarea.selectionEnd = start + 1;
    textarea.dispatchEvent(new Event('input', {bubbles: true}));
  }

  var _debounceTimers = {};

  function createJsonEditor(textarea, options) {
    if (!textarea || textarea._jsonEditorWrapped) return textarea;
    textarea._jsonEditorWrapped = true;
    options = options || {};
    var minHeight = options.minHeight || 80;

    _injectJsonEditorStyles();

    var wrap = document.createElement('div');
    wrap.className = 'json-editor-wrap';
    wrap.style.minHeight = minHeight + 'px';

    // Toolbar
    var tb = document.createElement('div');
    tb.className = 'json-editor-tb';
    tb.innerHTML = ''
      + '<div class="json-editor-tb-left">'
      + '<span class="json-editor-msg"></span>'
      + '</div>'
      + '<div style="display:flex;align-items:center;gap:3px;">'
      + '<button class="json-editor-btn fmt" title="Formater (Ctrl+Shift+F)">{ }</button>'
      + '<button class="json-editor-btn minify" title="Minifier">↔</button>'
      + '</div>';

    // Body
    var body = document.createElement('div');
    body.className = 'json-editor-body';

    var gutter = document.createElement('div');
    gutter.className = 'json-editor-gutter';
    gutter.innerHTML = '<div>1</div>';

    var area = document.createElement('div');
    area.className = 'json-editor-area';

    var highlight = document.createElement('div');
    highlight.className = 'json-editor-highlight';
    var code = document.createElement('code');
    highlight.appendChild(code);

    // Clone textarea
    var newTextarea = textarea.cloneNode(true);
    newTextarea.removeAttribute('id');
    newTextarea.className = (textarea.className || '') + ' json-editor-textarea';
    newTextarea.spellcheck = false;
    newTextarea.style.cssText = '';

    area.appendChild(highlight);
    area.appendChild(newTextarea);
    body.appendChild(gutter);
    body.appendChild(area);
    wrap.appendChild(tb);
    wrap.appendChild(body);

    textarea.replaceWith(wrap);
    // Keep hidden textarea in DOM for backward compat (e.g. dom.reqBody.value = ...)
    textarea.style.display = 'none';
    textarea._jsonEditorProxy = newTextarea;
    wrap.appendChild(textarea);

    // Bidirectional sync: hidden textarea acts as transparent proxy
    var _desc = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
    Object.defineProperty(textarea, 'value', {
      get: function() { return newTextarea.value; },
      set: function(v) {
        _desc.set.call(newTextarea, v);
        _updateHighlight(wrap);
        _updateLineNumbers(wrap);
      },
      enumerable: true, configurable: true
    });

    // Also sync on direct input (for event listeners on the original element)
    newTextarea.addEventListener('input', function() {
      _desc.set.call(textarea, newTextarea.value);
    });

    // Event handlers
    newTextarea.addEventListener('input', function() {
      clearTimeout(_debounceTimers[wrap._jsonId]);
      _debounceTimers[wrap._jsonId] = setTimeout(function() {
        _updateHighlight(wrap);
      }, 150);
      _updateLineNumbers(wrap);
    });

    newTextarea.addEventListener('scroll', function() {
      _syncScroll(wrap);
    });

    newTextarea.addEventListener('keydown', function(e) {
      if (e.key === 'Tab') { _handleTab(newTextarea, e); return; }
      if (e.key === 'Enter') {
        // Auto-indent next line
        setTimeout(function() {
          var v = newTextarea.value;
          var pos = newTextarea.selectionStart;
          var lineStart = v.lastIndexOf('\n', pos - 2) + 1;
          var prevLine = v.substring(lineStart, pos - 1);
          var indent = prevLine.match(/^(\s*)/);
          if (indent && indent[1]) {
            var before = v.substring(0, pos);
            var after = v.substring(pos);
            newTextarea.value = before + indent[1] + after;
            newTextarea.selectionStart = newTextarea.selectionEnd = pos + indent[1].length;
          }
        }, 0);
      }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
        e.preventDefault();
        _formatJson(wrap);
        return;
      }
      if ('{}[]"'.indexOf(e.key) !== -1) { _handleAutoPair(newTextarea, e); }
    });

    newTextarea.addEventListener('blur', function() {
      _validateAndShow(wrap, newTextarea.value || '');
    });

    // Toolbar buttons
    wrap._jsonId = Math.random().toString(36).substring(2);
    var fmtBtn = tb.querySelector('.json-editor-btn.fmt');
    var minifyBtn = tb.querySelector('.json-editor-btn.minify');
    fmtBtn.addEventListener('click', function() { _formatJson(wrap); });
    minifyBtn.addEventListener('click', function() { _minifyJson(wrap); });

    // Initial render
    _updateHighlight(wrap);
    _updateLineNumbers(wrap);

    // Expose API
    wrap._jsonEditor = {
      format: function() { _formatJson(wrap); },
      minify: function() { _minifyJson(wrap); },
      validate: function() {
        try { JSON.parse(newTextarea.value || '{}'); return true; }
        catch(e) { return false; }
      },
      getValue: function() { return newTextarea.value; },
      setValue: function(v) {
        newTextarea.value = v || '';
        textarea.value = newTextarea.value;
        _updateHighlight(wrap);
        _updateLineNumbers(wrap);
      },
      focus: function() { newTextarea.focus(); },
      getTextarea: function() { return newTextarea; },
    };

    return wrap;
  }

  window.ElyriaUI = {
    // Theme
    TAILWIND_THEME: TAILWIND_THEME,
    tailwindConfig: tailwindConfig,
    toggleTheme: toggleTheme,
    getTheme: getTheme,
    setTheme: setTheme,
    initTheme: initTheme,

    // Page builder (primary API)
    buildPage: buildPage,
    toggleSidebar: toggleSidebar,
    togglePanel: togglePanel,

    // Header (backward-compatible)
    renderHeader: renderHeader,
    injectHeader: injectHeader,

    // Components
    buildEmptyState: buildEmptyState,
    buildModal: buildModal,
    openModal: openModal,
    closeModal: closeModal,
    createJsonEditor: createJsonEditor,

    // Toast
    showToast: showToast,

    // Helpers
    $: $,
    $$: $$,
    esc: esc,

    // Icons
    ICONS: ICONS,
  };
})();

// ── Ely Copilot loader ──
(function () {
  if (window.__elyCopilotLoaded) return;
  window.__elyCopilotLoaded = true;
  var s = document.createElement('script');
  s.src = 'static/ely-copilot.js';
  document.head.appendChild(s);
})();
