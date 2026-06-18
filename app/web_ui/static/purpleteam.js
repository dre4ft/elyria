// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Elyria
// Purple Team — IAST code security analysis page

(function () {
  'use strict';

  var state = {
    profiles: [],
    activePid: null,
    activeProfile: null,
    activeScanId: null,
    scans: [],
    findings: [],
    _pollTimer: null,
    teamFilter: '',
    _viewMode: 'findings', // 'findings' | 'report'
  };

  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  };

  var dom = {
    profileList: $('#pt-profile-list'),
    btnNewProfile: $('#btn-new-profile'),
    btnCreateFirst: $('#btn-create-first'),
    btnRunScan: $('#btn-run-scan'),
    btnStopScan: $('#btn-stop-scan'),
    btnSendBlueteam: $('#btn-send-blueteam'),
    btnEditProfile: $('#btn-edit-profile'),
    btnDeleteProfile: $('#btn-delete-profile'),
    btnDownloadReport: $('#btn-download-report'),
    btnViewReport: $('#btn-view-report'),
    empty: $('#pt-empty'),
    content: $('#pt-content'),
    cards: $('#pt-cards'),
    profileName: $('#pt-profile-name'),
    profileTarget: $('#pt-profile-target'),
    statusBadge: $('#pt-status-badge'),
    modelBadge: $('#pt-model-badge'),
    progressContainer: $('#pt-progress-container'),
    progressBar: $('#pt-progress-bar'),
    progressPct: $('#pt-progress-pct'),
    progressMsg: $('#pt-progress-msg'),
    liveProgress: $('#pt-live-progress'),
    liveMsg: $('#pt-live-msg'),
    livePct: $('#pt-live-pct'),
    liveBar: $('#pt-live-bar'),
    findingsEmpty: $('#pt-findings-empty'),
    findingsList: $('#pt-findings-list'),
    reportContent: $('#pt-report-content'),
    reportRendered: $('#pt-report-rendered'),
    toc: $('#pt-toc'),
    tocLinks: $('#pt-toc-links'),
    detailPanel: $('#pt-detail-panel'),
    detailContent: $('#pt-detail-content'),
  };

  // ── Init ──
  function init() {
    if (window.__ptInit) return;
    window.__ptInit = true;
    initAuth();
    initHeaderUser();

    dom.btnNewProfile.addEventListener('click', function () { openProfileModal(); });
    if (dom.btnCreateFirst) dom.btnCreateFirst.addEventListener('click', function () { openProfileModal(); });
    if ($('#btn-pt-modal-save')) $('#btn-pt-modal-save').addEventListener('click', function () { saveProfile(); });
    dom.btnRunScan.addEventListener('click', function () { if (state.activePid) runScan(); });
    dom.btnStopScan.addEventListener('click', function () { if (state.activePid) stopScan(); });
    dom.btnEditProfile.addEventListener('click', function () {
      var p = state.profiles.find(function (x) { return x.profile_id === state.activePid; });
      if (p) openProfileModal(p);
    });
    dom.btnDeleteProfile.addEventListener('click', function () {
      if (!state.activePid) return;
      if (!confirm('Supprimer ce profil et tous ses scans ?')) return;
      deleteProfile(state.activePid);
    });
    dom.btnSendBlueteam.addEventListener('click', function () { sendToBlueTeam(); });
    dom.btnDownloadReport.addEventListener('click', function () { downloadReport(); });
    dom.btnViewReport.addEventListener('click', function () { viewReport(); });

    var btnToggle = $('#btn-toggle-sidebar');
    if (btnToggle) btnToggle.addEventListener('click', toggleSidebar);

    // Resizable sidebar (valise)
    _initResizeHandle();

    document.getElementById('filter-part').onchange = renderFindings;
    document.getElementById('filter-severity').onchange = renderFindings;
    document.getElementById('filter-cwe').addEventListener('input', function () {
      _filterDebounce = setTimeout(renderFindings, 300);
    });
    document.getElementById('filter-file').addEventListener('input', function () {
      _filterDebounce = setTimeout(renderFindings, 300);
    });

    setupUploadZone();
    setupRepoSourceToggle();

    var teamFilter = $('#pt-team-filter');
    if (teamFilter) {
      loadTeamsForFilter();
      teamFilter.addEventListener('change', function () {
        state.teamFilter = teamFilter.value;
        loadProfiles();
      });
    }

    loadProfiles();
  }

  // ── API helpers ──
  function api(method, path, body) {
    var opts = { method: method, headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('elyria_token') || '') } };
    if (body) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || 'Request failed'); });
      return r.json();
    });
  }

  // ── Sidebar ──
  function _initResizeHandle() {
    var sidebar = document.getElementById('pt-sidebar');
    var handle = document.getElementById('pt-resize-handle');
    if (!sidebar || !handle) return;

    var startX, startWidth;
    var MIN_W = 180;
    var MAX_W = 600;

    function onDown(e) {
      e.preventDefault();
      startX = e.clientX;
      startWidth = sidebar.offsetWidth;
      handle.classList.add('!bg-purple-500/40');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp);
    }

    function onMove(e) {
      var dx = e.clientX - startX;
      var w = Math.max(MIN_W, Math.min(MAX_W, startWidth + dx));
      sidebar.style.width = w + 'px';
    }

    function onUp() {
      handle.classList.remove('!bg-purple-500/40');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
    }

    handle.addEventListener('pointerdown', onDown);

    // Detail panel resize
    var detailPanel = document.getElementById('pt-detail-panel');
    var detailHandle = document.getElementById('pt-detail-resize-handle');
    if (detailPanel && detailHandle) {
      var dStartX, dStartWidth;

      function dOnDown(e) {
        e.preventDefault();
        dStartX = e.clientX;
        dStartWidth = detailPanel.offsetWidth;
        detailHandle.classList.add('!bg-purple-500/40');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        document.addEventListener('pointermove', dOnMove);
        document.addEventListener('pointerup', dOnUp);
      }

      function dOnMove(e) {
        var dx = dStartX - e.clientX;
        var w = Math.max(220, Math.min(700, dStartWidth + dx));
        detailPanel.style.width = w + 'px';
      }

      function dOnUp() {
        detailHandle.classList.remove('!bg-purple-500/40');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        document.removeEventListener('pointermove', dOnMove);
        document.removeEventListener('pointerup', dOnUp);
      }

      detailHandle.addEventListener('pointerdown', dOnDown);
    }
  }

  function toggleSidebar() {
    var sidebar = document.getElementById('pt-sidebar');
    if (!sidebar) return;
    var collapsed = sidebar.dataset.collapsed === 'true';
    sidebar.dataset.collapsed = collapsed ? 'false' : 'true';
  }

  function loadTeamsForFilter() {
    var sel = $('#pt-team-filter'); if (!sel) return;
    fetch('/api/teams', { headers: { Authorization: 'Bearer ' + (localStorage.getItem('elyria_token') || '') } })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (teams) {
        var opts = sel.innerHTML;
        teams.forEach(function (t) { opts += '<option value="' + t.team_id + '">' + esc(t.name) + '</option>'; });
        sel.innerHTML = opts;
      }).catch(function () {});
  }

  // ── Profiles ──
  function loadProfiles() {
    var url = '/api/purpleteam/profiles';
    if (state.teamFilter) url += '?team_id=' + encodeURIComponent(state.teamFilter);
    api('GET', url).then(function (data) {
      state.profiles = data || [];
      renderProfileList();
    }).catch(function () {});
  }

  function renderProfileList() {
    dom.profileList.innerHTML = '';
    state.profiles.forEach(function (p) {
      var el = document.createElement('div');
      var statusColors = { pending: 'bg-gray-500', running: 'bg-yellow-400 animate-pulse', completed: 'bg-green-400', stopped: 'bg-orange-400', failed: 'bg-red-400' };
      var dot = statusColors[p.status] || 'bg-gray-500';
      var total = p.total_findings || 0;
      el.className = 'profile-item' + (p.profile_id === state.activePid ? ' active' : '');
      el.innerHTML = '<span class="flex items-center gap-2 min-w-0 flex-1"><span class="w-2 h-2 rounded-full flex-shrink-0 ' + dot + '"></span><span class="text-xs text-gray-300 truncate">' + esc(p.name) + '</span></span>' +
        '<span class="text-[9px] text-gray-600 font-mono flex-shrink-0">' + (total > 0 ? total + ' findings' : '—') + '</span>';
      el.style.cssText = 'display:flex;align-items:center;gap:.5rem;padding:.5rem .625rem;border-radius:.5rem;cursor:pointer;transition:all .15s;border:1px solid transparent;';
      el.addEventListener('click', function () { selectProfile(p.profile_id); });
      dom.profileList.appendChild(el);
    });
  }

  function selectProfile(pid) {
    state.activePid = pid;
    state._viewMode = 'findings';
    renderProfileList();
    api('GET', '/api/purpleteam/profiles/' + pid).then(function (p) {
      state.activeProfile = p;
      state.scans = p.scans || [];
      showDashboard(p);
      if (p.scans && p.scans.length) {
        selectScan(p.scans[0].scan_id);
      }
    }).catch(function () {});
  }

  window._selectProfile = selectProfile;

  function deleteProfile(pid) {
    api('DELETE', '/api/purpleteam/profiles/' + pid).then(function () {
      if (state.activePid === pid) {
        state.activePid = null;
        state.activeProfile = null;
        dom.content.classList.add('hidden');
        dom.empty.classList.remove('hidden');
      }
      loadProfiles();
    }).catch(function (e) { alert('Delete failed: ' + e.message); });
  }

  // ── Dashboard ──
  function showDashboard(p) {
    dom.empty.classList.add('hidden');
    dom.content.classList.remove('hidden');
    dom.cards.classList.remove('hidden');
    dom.profileName.textContent = p.name;
    dom.profileTarget.textContent = (p.repo_source || '') + ' / ' + (p.repo_branch || 'main') + (p.target_endpoint ? ' → ' + p.target_endpoint : '');
    updateStatusBadge(p.status);
    if (p.status === 'running') {
      dom.btnRunScan.classList.add('hidden');
      dom.btnStopScan.classList.remove('hidden');
      dom.liveProgress.classList.remove('hidden');
      var pct = p.scan_progress || 0;
      dom.livePct.textContent = pct + '%';
      dom.liveBar.style.width = pct + '%';
      dom.liveMsg.textContent = p.progress_msg || 'Scan en cours...';
    } else {
      dom.liveProgress.classList.add('hidden');
      dom.btnRunScan.classList.remove('hidden');
      dom.btnStopScan.classList.add('hidden');
    }
  }

  function updateStatusBadge(status) {
    var b = dom.statusBadge;
    b.classList.remove('hidden');
    var map = {
      pending: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
      running: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
      completed: 'bg-green-500/10 text-green-400 border-green-500/20',
      stopped: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
      failed: 'bg-red-500/10 text-red-400 border-red-500/20',
    };
    b.className = 'px-2 py-0.5 rounded-full text-[9px] font-bold border ' + (map[status] || map.pending);
    b.textContent = status.toUpperCase();
  }

  // ── Scan ──
  function runScan() {
    if (!state.activePid) return;
    var btn = dom.btnRunScan;
    btn.disabled = true;
    btn.textContent = 'Starting...';
    api('POST', '/api/purpleteam/profiles/' + state.activePid + '/scan').then(function (data) {
      state.activeScanId = data.scan_id;
      updateStatusBadge('running');
      dom.liveProgress.classList.remove('hidden');
      dom.btnRunScan.classList.add('hidden');
      dom.btnStopScan.classList.remove('hidden');
      dom.livePct.textContent = '0%';
      dom.liveBar.style.width = '0%';
      dom.liveMsg.textContent = 'Demarrage du scan...';
      startPolling(data.scan_id);
    }).catch(function (e) {
      alert('Scan failed: ' + e.message);
      btn.disabled = false;
      resetRunButton();
    });
  }

  function stopScan() {
    if (!state.activePid) return;
    api('POST', '/api/purpleteam/profiles/' + state.activePid + '/stop').then(function () {
      stopPolling();
      dom.liveProgress.classList.add('hidden');
      dom.btnRunScan.classList.remove('hidden');
      dom.btnStopScan.classList.add('hidden');
      updateStatusBadge('stopped');
      resetRunButton();
    }).catch(function () {});
  }

  function resetRunButton() {
    dom.btnRunScan.disabled = false;
    dom.btnRunScan.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"/></svg>Lancer le scan';
  }

  // ── Adaptive polling ──
  var _lastPct = -1;
  var _pollInterval = 2000;
  var _sameCount = 0;
  var _pollCount = 0;
  var MAX_POLLS = 120;
  var _scanDone = false;

  function startPolling(scanId) {
    _lastPct = -1;
    _pollInterval = 2000;
    _sameCount = 0;
    _pollCount = 0;
    _scanDone = false;
    schedulePoll();
  }

  function schedulePoll() {
    if (state._pollTimer) clearTimeout(state._pollTimer);
    state._pollTimer = setTimeout(poll, _pollInterval);
  }

  function stopPolling() {
    if (state._pollTimer) { clearTimeout(state._pollTimer); state._pollTimer = null; }
    setTimeout(function () { _scanDone = false; }, 500);
  }

  function poll() {
    _pollCount++;
    if (_pollCount > MAX_POLLS) {
      stopPolling();
      dom.liveProgress.classList.add('hidden');
      return;
    }
    api('GET', '/api/purpleteam/scans/' + state.activeScanId).then(function (s) {
      var pct = s.scan_progress || 0;
      dom.livePct.textContent = pct + '%';
      dom.liveBar.style.width = pct + '%';
      if (s.progress_msg) {
        dom.liveMsg.textContent = s.progress_msg;
      }

      if (s.status === 'completed') {
        _onScanDone(s);
        return;
      }
      if (s.status === 'failed') {
        _onScanFailed(s);
        return;
      }

      if (pct !== _lastPct) {
        _pollInterval = Math.max(2000, _pollInterval / 1.5);
        _sameCount = 0;
        selectScanSilent(state.activeScanId);
      } else {
        _sameCount++;
        if (_sameCount >= 3) {
          _pollInterval = Math.min(30000, _pollInterval * 2);
          _sameCount = 0;
        }
      }
      _lastPct = pct;
      schedulePoll();
    }).catch(function () { schedulePoll(); });
  }

  function _onScanDone(s) {
    if (_scanDone) return;
    _scanDone = true;
    stopPolling();
    dom.livePct.textContent = '100%';
    dom.liveBar.style.width = '100%';
    dom.liveMsg.textContent = 'Complete';
    dom.liveProgress.classList.add('hidden');
    dom.btnRunScan.classList.remove('hidden');
    dom.btnStopScan.classList.add('hidden');
    resetRunButton();
    updateStatusBadge('completed');
    if (s.models && s.models.pro) {
      dom.modelBadge.classList.remove('hidden');
      dom.modelBadge.textContent = s.models.pro;
    }
    dom.btnSendBlueteam.classList.remove('hidden');
    selectScan(state.activeScanId);
    loadProfiles();
  }

  function _onScanFailed(s) {
    if (_scanDone) return;
    _scanDone = true;
    stopPolling();
    dom.liveMsg.textContent = 'Failed: ' + (s.progress_msg || 'Unknown error');
    dom.liveProgress.classList.add('hidden');
    dom.btnRunScan.classList.remove('hidden');
    dom.btnStopScan.classList.add('hidden');
    resetRunButton();
    updateStatusBadge('failed');
  }

  function selectScanSilent(scanId) {
    api('GET', '/api/purpleteam/scans/' + scanId).then(function (s) {
      state.findings = s.findings || [];
      updateCards(s);
      renderFindings();
      _syncSidebarCount(s.findings.length);
    }).catch(function () {});
  }

  function selectScan(scanId) {
    state.activeScanId = scanId;
    _resetFilters();
    api('GET', '/api/purpleteam/scans/' + scanId).then(function (s) {
      state.findings = s.findings || [];
      updateCards(s);
      renderFindings();
      _syncSidebarCount(s.findings.length);
    }).catch(function () {});
  }

  function _resetFilters() {
    var cwe = document.getElementById('filter-cwe');
    var file = document.getElementById('filter-file');
    if (cwe) cwe.value = '';
    if (file) file.value = '';
  }

  function _syncSidebarCount(total) {
    if (!state.activePid) return;
    state.profiles.forEach(function (p) {
      if (p.profile_id === state.activePid) {
        p.total_findings = total;
      }
    });
    renderProfileList();
  }

  function updateCards(s) {
    var counts = s.finding_counts || {};
    var byPart = { cves: 0, cwes: 0, practices: 0 };
    (s.findings || []).forEach(function (f) {
      var part = f.finding_part || 'practices';
      byPart[part] = (byPart[part] || 0) + 1;
    });
    document.getElementById('card-cves').querySelector('.text-2xl').textContent = byPart.cves;
    document.getElementById('card-cwes').querySelector('.text-2xl').textContent = byPart.cwes;
    document.getElementById('card-practices').querySelector('.text-2xl').textContent = byPart.practices;
    document.getElementById('card-critical').querySelector('.text-2xl').textContent = counts.critical || 0;
    document.getElementById('card-high').querySelector('.text-2xl').textContent = counts.high || 0;
  }

  // ── Findings ──
  var _filterDebounce = null;

  function renderFindings() {
    // Switch to findings view
    state._viewMode = 'findings';
    dom.reportContent.classList.add('hidden');
    dom.toc.classList.add('hidden');
    dom.findingsList.classList.remove('hidden');
    updateViewReportButton();

    var partFilter = document.getElementById('filter-part').value;
    var sevFilter = document.getElementById('filter-severity').value;
    var cweFilter = (document.getElementById('filter-cwe').value || '').toLowerCase().trim();
    var fileFilter = (document.getElementById('filter-file').value || '').toLowerCase().trim();
    var filtered = state.findings.filter(function (f) {
      if (partFilter === 'ai') {
        if (f.category !== 'ai_discovered') return false;
      } else if (partFilter !== 'all' && f.finding_part !== partFilter) {
        return false;
      }
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
      if (cweFilter && (!f.cwe_id && !f.cve_id)) return false;
      if (cweFilter && f.cwe_id && f.cwe_id.toLowerCase().indexOf(cweFilter) === -1 && (!f.cve_id || f.cve_id.toLowerCase().indexOf(cweFilter) === -1)) return false;
      if (fileFilter && (!f.file_path || f.file_path.toLowerCase().indexOf(fileFilter) === -1)) return false;
      return true;
    });

    if (!filtered.length) {
      dom.findingsEmpty.classList.remove('hidden');
      dom.findingsList.classList.add('hidden');
      return;
    }
    dom.findingsEmpty.classList.add('hidden');
    dom.findingsList.classList.remove('hidden');

    var sevColors = { critical: 'text-red-400 bg-red-500/10 border-red-500/20', high: 'text-orange-400 bg-orange-500/10 border-orange-500/20', medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20', low: 'text-blue-400 bg-blue-500/10 border-blue-500/20', info: 'text-gray-400 bg-gray-500/10 border-gray-500/20' };
    var partLabels = { cves: 'CVE', cwes: 'CWE', practices: 'PRAC' };

    dom.findingsList.innerHTML = filtered.map(function (f) {
      var part = f.finding_part || 'practices';
      var partLabel = partLabels[part] || 'PRAC';
      var isAI = f.category === 'ai_discovered';
      var aiBadge = isAI ? '<span class="px-1 py-0 rounded text-[8px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">AI</span>' : '';
      return '<div class="finding-row px-5 py-2.5 flex items-center gap-3 text-[12px] cursor-pointer" onclick="window._showDetail(\'' + esc(f.finding_id).replace(/\\/g, '\\\\') + '\')">' +
        '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ' + (sevColors[f.severity] || sevColors.info) + '">' + esc(f.severity) + '</span>' +
        '<span class="text-[9px] text-gray-600 font-mono w-8">' + partLabel + '</span>' +
        aiBadge +
        '<span class="flex-1 text-gray-300 truncate">' + esc(f.title) + '</span>' +
        '<span class="text-[10px] text-gray-600 font-mono">' + esc(f.file_path || '-') + '</span>' +
        '</div>';
    }).join('');
  }

  window._showDetail = function (fid) {
    var f = state.findings.find(function (x) { return x.finding_id === fid; });
    if (!f) return;
    dom.detailPanel.classList.remove('hidden');
    var dh = $('#pt-detail-resize-handle'); if (dh) dh.classList.remove('hidden');
    dom.detailContent.innerHTML =
      '<div><span class="text-[10px] text-gray-500">Severity</span><div class="text-sm font-semibold mt-0.5">' + esc(f.severity).toUpperCase() + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Title</span><div class="text-sm mt-0.5">' + esc(f.title) + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Category</span><div class="text-sm mt-0.5">' + esc(f.category) + '</div></div>' +
      (f.cve_id ? '<div><span class="text-[10px] text-gray-500">CVE</span><div class="text-sm mt-0.5 font-mono text-purple-300">' + esc(f.cve_id) + '</div></div>' : '') +
      (f.cwe_id ? '<div><span class="text-[10px] text-gray-500">CWE</span><div class="text-sm mt-0.5 font-mono text-purple-300">' + esc(f.cwe_id) + '</div></div>' : '') +
      '<div><span class="text-[10px] text-gray-500">Location</span><div class="text-sm mt-0.5 font-mono">' + esc(f.file_path || '-') + (f.line_number ? ':' + f.line_number : '') + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">CVSS</span><div class="text-sm mt-0.5 font-mono">' + (f.cvss_score || '0.0') + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Description</span><div class="text-sm mt-0.5 text-gray-400">' + esc(f.description || '-') + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Remediation</span><div class="text-sm mt-0.5 text-green-400">' + esc(f.remediation || '-') + '</div></div>';
  };

  window.closeDetail = function () {
    dom.detailPanel.classList.add('hidden');
    var dh = $('#pt-detail-resize-handle'); if (dh) dh.classList.add('hidden');
  };

  // ── Report ──
  function viewReport() {
    if (!state.activeScanId) return;
    if (state._viewMode === 'report') {
      // Toggle back to findings
      state._viewMode = 'findings';
      dom.reportContent.classList.add('hidden');
      dom.toc.classList.add('hidden');
      dom.findingsList.classList.remove('hidden');
      updateViewReportButton();
      return;
    }
    api('GET', '/api/purpleteam/scans/' + state.activeScanId + '/report').then(function (data) {
      state._viewMode = 'report';
      dom.findingsList.classList.add('hidden');
      dom.findingsEmpty.classList.add('hidden');
      dom.reportContent.classList.remove('hidden');
      renderReportContent(data.report_markdown);
      updateViewReportButton();
    }).catch(function (e) { alert('Failed to load report: ' + e.message); });
  }

  function updateViewReportButton() {
    var btn = dom.btnViewReport;
    if (state._viewMode === 'report') {
      btn.innerHTML = '<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>View Findings';
    } else {
      btn.innerHTML = '<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>View Report';
    }
  }

  function renderReportContent(md) {
    var anchored = (md || '').replace(/^(#{1,3})\s+(.+)$/gm, function (m, hashes, title) {
      var id = title.toLowerCase().replace(/[^\w]+/g, '-').replace(/^-|-$/g, '');
      return hashes + ' <a id="' + id + '" class="report-anchor"></a>' + title;
    });

    if (typeof marked !== 'undefined' && dom.reportRendered) {
      dom.reportRendered.innerHTML = marked.parse(anchored);
      // Render mermaid diagrams
      try {
        var mermaidEls = dom.reportRendered.querySelectorAll('pre code.language-mermaid');
        if (mermaidEls.length > 0 && typeof mermaid !== 'undefined') {
          mermaidEls.forEach(function (el) {
            var pre = el.parentElement;
            var code = (el.textContent || '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
            var div = document.createElement('div');
            div.className = 'mermaid bg-base-900/50 rounded-lg p-4 my-4';
            div.textContent = code;
            pre.replaceWith(div);
          });
          mermaid.run({ querySelector: '.mermaid' }).catch(function () {
            console.warn('Mermaid render failed, showing code blocks instead');
          });
        }
      } catch (e) { console.log('mermaid render skipped', e); }
    } else if (dom.reportRendered) {
      dom.reportRendered.innerHTML = '<pre class="text-xs text-gray-300 font-mono whitespace-pre-wrap">' + esc(md) + '</pre>';
    }

    // Build table of contents
    if (dom.toc && dom.tocLinks && dom.reportRendered) {
      var headings = dom.reportRendered.querySelectorAll('h2');
      if (headings.length > 1) {
        var html = '';
        headings.forEach(function (h) {
          var a = h.querySelector('a.report-anchor');
          if (!a) return;
          html += '<a href="#' + a.id + '" data-toc="' + a.id + '" onclick="document.getElementById(\'' + a.id + '\').scrollIntoView({behavior:\'smooth\'});return false">' + esc(h.textContent.trim()) + '</a>';
        });
        dom.tocLinks.innerHTML = html;
        dom.toc.classList.remove('hidden');
      } else {
        dom.toc.classList.add('hidden');
      }
    }
  }

  function downloadReport() {
    if (!state.activeScanId) return;
    var token = localStorage.getItem('elyria_token') || '';
    var a = document.createElement('a');
    a.href = '/api/purpleteam/scans/' + state.activeScanId + '/report/download?token=' + encodeURIComponent(token);
    a.download = 'purpleteam-report-' + state.activeScanId.slice(0, 8) + '.md';
    a.click();
  }

  // ── Send to Blue Team ──
  function sendToBlueTeam() {
    if (!state.activeScanId) return;
    if (!confirm('Send this Purple Team report to Blue Team for remediation analysis?')) return;
    var btn = dom.btnSendBlueteam;
    btn.disabled = true;
    btn.textContent = 'Sending...';
    api('POST', '/api/purpleteam/scans/' + state.activeScanId + '/send-to-blueteam').then(function (data) {
      alert('Blue Team remediation analysis started!\nProfile: ' + data.blueteam_profile_id);
      btn.disabled = false;
      btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>Send to Blue Team';
    }).catch(function (e) {
      alert('Failed: ' + e.message);
      btn.disabled = false;
      btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>Send to Blue Team';
    });
  }

  // ── Upload Zone ──
  var _selectedUploadFile = null;

  function setupUploadZone() {
    var zone = $('#pt-upload-zone');
    var input = $('#pt-upload-file');
    if (!zone || !input) return;

    var showFile = function (file) {
      _selectedUploadFile = file;
      $('#pt-upload-drop-content').classList.add('hidden');
      $('#pt-upload-file-selected').classList.remove('hidden');
      $('#pt-upload-file-name').textContent = file.name;
    };

    input.addEventListener('change', function () {
      if (input.files[0]) showFile(input.files[0]);
    });

    zone.addEventListener('dragover', function (e) {
      e.preventDefault();
      zone.style.borderColor = 'rgba(168,85,247,.4)';
      zone.style.background = 'rgba(168,85,247,.05)';
    });
    zone.addEventListener('dragleave', function () {
      zone.style.borderColor = 'rgba(255,255,255,.1)';
      zone.style.background = 'transparent';
    });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.style.borderColor = 'rgba(255,255,255,.1)';
      zone.style.background = 'transparent';
      if (e.dataTransfer.files.length > 0) {
        var dt = new DataTransfer();
        dt.items.add(e.dataTransfer.files[0]);
        input.files = dt.files;
        showFile(e.dataTransfer.files[0]);
      }
    });
  }

  function setupRepoSourceToggle() {
    var sel = $('#pt-modal-repo-source');
    if (!sel) return;
    sel.addEventListener('change', function () {
      var isLocal = sel.value === 'local';
      var urlInput = $('#pt-modal-repo-url');
      var uploadZone = $('#pt-upload-zone');
      if (isLocal) {
        if (urlInput) urlInput.placeholder = '/path/to/local/repo';
        if (uploadZone) uploadZone.classList.remove('hidden');
      } else {
        if (urlInput) urlInput.placeholder = 'https://github.com/user/repo.git';
        if (uploadZone) uploadZone.classList.add('hidden');
      }
    });
  }

  function resetUploadZone() {
    _selectedUploadFile = null;
    var input = $('#pt-upload-file');
    if (input) input.value = '';
    var drop = $('#pt-upload-drop-content');
    var sel = $('#pt-upload-file-selected');
    if (drop) drop.classList.remove('hidden');
    if (sel) sel.classList.add('hidden');
  }

  // ── Modal ──
  function openProfileModal(profile) {
    var editId = profile ? profile.profile_id : null;
    var modal = $('#pt-modal');
    modal.classList.remove('hidden');
    modal.classList.add('flex');
    $('#pt-modal-title').textContent = editId ? 'Edit Repository' : 'Add Repository for IAST';
    resetUploadZone();

    if (profile) {
      $('#pt-modal-name').value = profile.name || '';
      $('#pt-modal-repo-source').value = profile.repo_source || 'github';
      $('#pt-modal-branch').value = profile.repo_branch || 'main';
      $('#pt-modal-repo-url').value = profile.repo_url || '';
      $('#pt-modal-auth-type').value = profile.repo_auth_type || '';
      $('#pt-modal-auth-key').value = profile.repo_auth_key || '';
      $('#pt-modal-endpoint').value = profile.target_endpoint || '';
      $('#pt-modal-spec-url').value = profile.openapi_spec_url || '';
      $('#pt-modal-scan-depth').value = profile.scan_depth || 'full';
      $('#pt-modal-desc').value = profile.description || '';
      modal.dataset.editId = editId;
    } else {
      ['pt-modal-name', 'pt-modal-branch', 'pt-modal-repo-url', 'pt-modal-auth-key', 'pt-modal-endpoint', 'pt-modal-spec-url', 'pt-modal-desc'].forEach(function (id) { var el = $('#' + id); if (el) el.value = ''; });
      var repoSource = $('#pt-modal-repo-source'); if (repoSource) repoSource.value = 'github';
      var authType = $('#pt-modal-auth-type'); if (authType) authType.value = '';
      var scanDepth = $('#pt-modal-scan-depth'); if (scanDepth) scanDepth.value = 'full';
      delete modal.dataset.editId;
    }
    // Sync upload zone visibility
    var sel = $('#pt-modal-repo-source');
    var uploadZone = $('#pt-upload-zone');
    if (sel && uploadZone) {
      uploadZone.classList.toggle('hidden', sel.value !== 'local');
    }
    loadTeamsForModal(profile ? profile.team_ids : '');
  }

  window.openModal = openProfileModal;

  function loadTeamsForModal(selectedId) {
    var sel = $('#pt-modal-team'); if (!sel) return;
    fetch('/api/teams', { headers: { Authorization: 'Bearer ' + (localStorage.getItem('elyria_token') || '') } })
      .then(function (r) { return r.json(); })
      .then(function (teams) {
        var opts = '<option value="">Personnel</option>';
        teams.forEach(function (t) { opts += '<option value="' + t.team_id + '">' + esc(t.name) + '</option>'; });
        sel.innerHTML = opts;
        if (selectedId) sel.value = selectedId;
      }).catch(function () {});
  }

  function saveProfile() {
    var editId = $('#pt-modal').dataset.editId;
    var repoSource = $('#pt-modal-repo-source').value;
    var body = {
      name: $('#pt-modal-name').value.trim(),
      repo_source: repoSource,
      repo_branch: $('#pt-modal-branch').value.trim() || 'main',
      repo_url: $('#pt-modal-repo-url').value.trim(),
      repo_auth_type: $('#pt-modal-auth-type').value,
      repo_auth_key: $('#pt-modal-auth-key').value.trim(),
      target_endpoint: $('#pt-modal-endpoint').value.trim(),
      openapi_spec_url: $('#pt-modal-spec-url').value.trim(),
      scan_depth: $('#pt-modal-scan-depth').value,
      description: $('#pt-modal-desc').value.trim(),
      team_ids: $('#pt-modal-team') ? $('#pt-modal-team').value : '',
    };
    if (!body.name) { alert('Name is required'); return; }

    var method = editId ? 'PUT' : 'POST';
    var path = editId ? '/api/purpleteam/profiles/' + editId : '/api/purpleteam/profiles';

    var doSave = function () {
      api(method, path, body).then(function () {
        $('#pt-modal').classList.add('hidden');
        loadProfiles();
        if (editId) { selectProfile(editId); }
      }).catch(function (e) { alert('Save failed: ' + e.message); });
    };

    if (repoSource === 'local' && _selectedUploadFile) {
      var fd = new FormData();
      fd.append('file', _selectedUploadFile);
      fetch('/api/purpleteam/repos/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + (localStorage.getItem('elyria_token') || '') },
        body: fd,
      }).then(function (r) {
        if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || 'Upload failed'); });
        return r.json();
      }).then(function (data) {
        body.repo_url = data.repo_path;
        body.repo_source = 'local';
        doSave();
      }).catch(function (e) { alert('Upload failed: ' + e.message); });
    } else {
      doSave();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
