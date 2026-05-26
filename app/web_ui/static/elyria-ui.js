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
      + '.elyria-theme-toggle:hover .elyria-theme-toggle-track{box-shadow:inset 0 1px 3px rgba(0,0,0,.3),0 0 0 2px rgba(124,58,237,.3);}';

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
    { id: 'blueteam', label: 'Blue Team',  path: '/blueteam', color: 'blue' },
    { id: 'doc',      label: 'Docs',       path: '/doc',      color: 'purple' },
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
