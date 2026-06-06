// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Elyria
// Purple Team — IAST code security analysis page

(function () {
  'use strict';

  var state = {
    profiles: [],
    activeProfileId: null,
    activeProfile: null,
    activeScanId: null,
    scans: [],
    findings: [],
    source: null,
    _pollTimer: null,
  };

  // ── Init ──
  function init() {
    document.getElementById('btn-new-profile').onclick = openModal;
    document.getElementById('btn-modal-cancel').onclick = closeModal;
    document.getElementById('btn-modal-save').onclick = saveProfile;
    document.getElementById('btn-run-scan').onclick = runScan;
    document.getElementById('btn-edit-profile').onclick = editActiveProfile;
    document.getElementById('btn-delete-profile').onclick = deleteActiveProfile;
    document.getElementById('btn-send-blueteam').onclick = sendToBlueTeam;
    document.getElementById('btn-download-report').onclick = downloadReport;
    document.getElementById('btn-view-report').onclick = viewReport;
    document.getElementById('filter-part').onchange = renderFindings;
    document.getElementById('filter-severity').onchange = renderFindings;
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

  // ── Profiles ──
  function loadProfiles() {
    api('GET', '/api/purpleteam/profiles').then(function (data) {
      state.profiles = data || [];
      renderProfileList();
    }).catch(function () {});
  }

  function renderProfileList() {
    var el = document.getElementById('profile-list');
    if (!state.profiles.length) {
      el.innerHTML = '<div class="text-[11px] text-gray-600 text-center mt-6">No repositories</div>';
      return;
    }
    el.innerHTML = state.profiles.map(function (p) {
      var active = p.profile_id === state.activeProfileId ? 'bg-purple-500/10 border-purple-500/20' : 'hover:bg-white/5 border-transparent';
      var total = p.total_findings || 0;
      return '<div class="px-2.5 py-2 rounded-lg cursor-pointer border ' + active + ' text-[12px] transition-all" onclick="window._selectProfile(\'' + p.profile_id + '\')">' +
        '<div class="text-gray-300 truncate font-medium">' + esc(p.name) + '</div>' +
        '<div class="text-[10px] text-gray-500 mt-0.5 font-mono">' + esc(p.repo_source) + ' &middot; ' + esc(p.scan_depth || 'full') + (total > 0 ? ' &middot; ' + total + ' findings' : '') + '</div>' +
        '</div>';
    }).join('');
  }

  window._selectProfile = function (pid) {
    state.activeProfileId = pid;
    state.activeScanId = null;
    api('GET', '/api/purpleteam/profiles/' + pid).then(function (p) {
      state.activeProfile = p;
      state.scans = p.scans || [];
      showDashboard(p);
      renderProfileList();
      if (p.scans && p.scans.length) {
        selectScan(p.scans[0].scan_id);
      }
    }).catch(function () {});
  };

  // ── Dashboard ──
  function showDashboard(p) {
    document.getElementById('main-placeholder').classList.add('hidden');
    var dash = document.getElementById('main-dashboard');
    dash.classList.remove('hidden');
    document.getElementById('dashboard-cards').classList.remove('hidden');
    document.getElementById('dash-name').textContent = p.name;
    document.getElementById('dash-meta').innerHTML = '<span>' + esc(p.repo_source + ' / ' + (p.repo_branch || 'main')) + '</span>' +
      (p.target_endpoint ? '<span>Target: ' + esc(p.target_endpoint) + '</span>' : '') +
      '<span>Depth: ' + esc(p.scan_depth || 'full') + '</span>';
  }

  // ── Scan ──
  function runScan() {
    if (!state.activeProfileId) return;
    var btn = document.getElementById('btn-run-scan');
    btn.disabled = true;
    btn.textContent = 'Starting...';
    api('POST', '/api/purpleteam/profiles/' + state.activeProfileId + '/scan').then(function (data) {
      state.activeScanId = data.scan_id;
      document.getElementById('scan-progress-container').classList.remove('hidden');
      document.getElementById('scan-progress-label').classList.add('scanning-pulse');
      startPolling(data.scan_id);
    }).catch(function (e) {
      alert('Scan failed: ' + e.message);
      btn.disabled = false;
      btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>Run IAST Scan';
    });
  }

  // ── Adaptive polling ──
  var _lastPct = -1;
  var _pollInterval = 2000;
  var _sameCount = 0;
  var _pollCount = 0;
  var MAX_POLLS = 120;
  var _scanDone = false;

  function schedulePoll() {
    if (state._pollTimer) clearTimeout(state._pollTimer);
    state._pollTimer = setTimeout(poll, _pollInterval);
  }

  function poll() {
    _pollCount++;
    if (_pollCount > MAX_POLLS) {
      stopPolling();
      document.getElementById('scan-progress-container').classList.add('hidden');
      return;
    }
    api('GET', '/api/purpleteam/scans/' + state.activeScanId).then(function (s) {
      var pct = s.scan_progress || 0;
      document.getElementById('scan-progress-bar').style.width = pct + '%';
      document.getElementById('scan-progress-pct').textContent = pct + '%';
      if (s.progress_msg) {
        document.getElementById('scan-progress-label').textContent = s.progress_msg;
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

  function startPolling(scanId) {
    _lastPct = -1;
    _pollInterval = 2000;
    _sameCount = 0;
    _pollCount = 0;
    _scanDone = false;
    schedulePoll();
  }

  function stopPolling() {
    if (state._pollTimer) { clearTimeout(state._pollTimer); state._pollTimer = null; }
    setTimeout(function () { _scanDone = false; }, 500);
  }

  function _onScanDone(s) {
    if (_scanDone) return;
    _scanDone = true;
    stopPolling();
    document.getElementById('scan-progress-bar').style.width = '100%';
    document.getElementById('scan-progress-pct').textContent = '100%';
    document.getElementById('scan-progress-label').textContent = 'Complete';
    document.getElementById('scan-progress-label').classList.remove('scanning-pulse');
    document.getElementById('btn-run-scan').disabled = false;
    document.getElementById('btn-run-scan').innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>Run IAST Scan';
    document.getElementById('btn-send-blueteam').classList.remove('hidden');
    selectScan(state.activeScanId);
    loadProfiles();
  }

  function _onScanFailed(s) {
    if (_scanDone) return;
    _scanDone = true;
    stopPolling();
    document.getElementById('scan-progress-label').textContent = 'Failed: ' + (s.progress_msg || 'Unknown error');
    document.getElementById('scan-progress-label').classList.remove('scanning-pulse');
    document.getElementById('btn-run-scan').disabled = false;
    document.getElementById('btn-run-scan').innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>Run IAST Scan';
  }

  function selectScanSilent(scanId) {
    api('GET', '/api/purpleteam/scans/' + scanId).then(function (s) {
      state.findings = s.findings || [];
      updateCards(s);
      renderFindings();
    }).catch(function () {});
  }

  function selectScan(scanId) {
    state.activeScanId = scanId;
    api('GET', '/api/purpleteam/scans/' + scanId).then(function (s) {
      state.findings = s.findings || [];
      updateCards(s);
      renderFindings();
    }).catch(function () {});
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
  function renderFindings() {
    var partFilter = document.getElementById('filter-part').value;
    var sevFilter = document.getElementById('filter-severity').value;
    var filtered = state.findings.filter(function (f) {
      if (partFilter !== 'all' && f.finding_part !== partFilter) return false;
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
      return true;
    });

    if (!filtered.length) {
      document.getElementById('findings-empty').classList.remove('hidden');
      document.getElementById('findings-list').classList.add('hidden');
      return;
    }
    document.getElementById('findings-empty').classList.add('hidden');
    document.getElementById('findings-list').classList.remove('hidden');

    var sevColors = { critical: 'text-red-400 bg-red-500/10 border-red-500/20', high: 'text-orange-400 bg-orange-500/10 border-orange-500/20', medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20', low: 'text-blue-400 bg-blue-500/10 border-blue-500/20', info: 'text-gray-400 bg-gray-500/10 border-gray-500/20' };
    var partLabels = { cves: 'CVE', cwes: 'CWE', practices: 'PRAC' };

    document.getElementById('findings-list').innerHTML = filtered.map(function (f, i) {
      var part = f.finding_part || 'practices';
      var partLabel = partLabels[part] || 'PRAC';
      return '<div class="finding-row px-5 py-2.5 flex items-center gap-3 text-[12px] cursor-pointer" onclick="window._showDetail(\'' + f.finding_id + '\')">' +
        '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ' + (sevColors[f.severity] || sevColors.info) + '">' + esc(f.severity) + '</span>' +
        '<span class="text-[9px] text-gray-600 font-mono w-8">' + partLabel + '</span>' +
        '<span class="flex-1 text-gray-300 truncate">' + esc(f.title) + '</span>' +
        '<span class="text-[10px] text-gray-600 font-mono">' + esc(f.file_path || '-') + '</span>' +
        '</div>';
    }).join('');
  }

  window._showDetail = function (fid) {
    var f = state.findings.find(function (x) { return x.finding_id === fid; });
    if (!f) return;
    var panel = document.getElementById('detail-panel');
    panel.classList.remove('hidden');
    document.getElementById('detail-content').innerHTML =
      '<div><span class="text-[10px] text-gray-500">Severity</span><div class="text-sm font-semibold mt-0.5">' + esc(f.severity).toUpperCase() + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Title</span><div class="text-sm mt-0.5">' + esc(f.title) + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Category</span><div class="text-sm mt-0.5">' + esc(f.category) + '</div></div>' +
      (f.cve_id ? '<div><span class="text-[10px] text-gray-500">CVE</span><div class="text-sm mt-0.5 font-mono text-purple-300">' + esc(f.cve_id) + '</div></div>' : '') +
      (f.cwe_id ? '<div><span class="text-[10px] text-gray-500">CWE</span><div class="text-sm mt-0.5 font-mono text-purple-300">' + esc(f.cwe_id) + '</div></div>' : '') +
      '<div><span class="text-[10px] text-gray-500">Location</span><div class="text-sm mt-0.5 font-mono">' + esc(f.file_path || '-') + (f.line_number ? ':' + f.line_number : '') + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">CVSS</span><div class="text-sm mt-0.5 font-mono">' + (f.cvss_score || '0.0') + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Description</span><div class="text-sm mt-0.5 text-gray-400">' + esc(f.description || '-') + '</div></div>' +
      '<div><span class="text-[10px] text-gray-500">Remediation</span><div class="text-sm mt-0.5 text-green-400">' + esc(f.remediation || '-') + '</div></div>' +
      (f.ai_analysis ? '<div><span class="text-[10px] text-gray-500">AI Analysis</span><div class="text-sm mt-0.5 text-gray-400">' + esc(f.ai_analysis) + '</div></div>' : '');
  };

  window.closeDetail = function () {
    document.getElementById('detail-panel').classList.add('hidden');
  };

  // ── Report ──
  function viewReport() {
    if (!state.activeScanId) return;
    api('GET', '/api/purpleteam/scans/' + state.activeScanId + '/report').then(function (data) {
      document.getElementById('report-content').textContent = data.report_markdown;
      document.getElementById('modal-report').classList.remove('hidden');
    }).catch(function (e) { alert('Failed to load report: ' + e.message); });
  }

  window.closeReport = function () {
    document.getElementById('modal-report').classList.add('hidden');
  };

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
    var btn = document.getElementById('btn-send-blueteam');
    btn.disabled = true;
    btn.textContent = 'Sending...';
    api('POST', '/api/purpleteam/scans/' + state.activeScanId + '/send-to-blueteam').then(function (data) {
      alert('Blue Team remediation analysis started!\nProfile: ' + data.blueteam_profile_id);
      btn.disabled = false;
      btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>Sent to Blue Team';
    }).catch(function (e) { alert('Failed: ' + e.message); btn.disabled = false; btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>Send to Blue Team'; });
  }

  // ── Modal ──
  window.openModal = function (edit) {
    document.getElementById('modal-title').textContent = edit ? 'Edit Repository' : 'Add Repository for IAST';
    if (edit && state.activeProfile) {
      var p = state.activeProfile;
      document.getElementById('modal-name').value = p.name || '';
      document.getElementById('modal-repo-source').value = p.repo_source || 'github';
      document.getElementById('modal-branch').value = p.repo_branch || 'main';
      document.getElementById('modal-repo-url').value = p.repo_url || '';
      document.getElementById('modal-auth-type').value = p.repo_auth_type || '';
      document.getElementById('modal-auth-key').value = p.repo_auth_key || '';
      document.getElementById('modal-endpoint').value = p.target_endpoint || '';
      document.getElementById('modal-spec-url').value = p.openapi_spec_url || '';
      document.getElementById('modal-scan-depth').value = p.scan_depth || 'full';
      document.getElementById('modal-desc').value = p.description || '';
      document.getElementById('modal-profile').dataset.editId = p.profile_id;
    } else {
      document.getElementById('modal-name').value = '';
      document.getElementById('modal-repo-source').value = 'github';
      document.getElementById('modal-branch').value = 'main';
      document.getElementById('modal-repo-url').value = '';
      document.getElementById('modal-auth-type').value = '';
      document.getElementById('modal-auth-key').value = '';
      document.getElementById('modal-endpoint').value = '';
      document.getElementById('modal-spec-url').value = '';
      document.getElementById('modal-scan-depth').value = 'full';
      document.getElementById('modal-desc').value = '';
      delete document.getElementById('modal-profile').dataset.editId;
    }
    document.getElementById('modal-profile').classList.remove('hidden');
  };

  function closeModal() {
    document.getElementById('modal-profile').classList.add('hidden');
  }

  function saveProfile() {
    var editId = document.getElementById('modal-profile').dataset.editId;
    var body = {
      name: document.getElementById('modal-name').value.trim(),
      repo_source: document.getElementById('modal-repo-source').value,
      repo_branch: document.getElementById('modal-branch').value.trim() || 'main',
      repo_url: document.getElementById('modal-repo-url').value.trim(),
      repo_auth_type: document.getElementById('modal-auth-type').value,
      repo_auth_key: document.getElementById('modal-auth-key').value.trim(),
      target_endpoint: document.getElementById('modal-endpoint').value.trim(),
      openapi_spec_url: document.getElementById('modal-spec-url').value.trim(),
      scan_depth: document.getElementById('modal-scan-depth').value,
      description: document.getElementById('modal-desc').value.trim(),
    };
    if (!body.name) { alert('Name is required'); return; }

    var method = editId ? 'PUT' : 'POST';
    var path = editId ? '/api/purpleteam/profiles/' + editId : '/api/purpleteam/profiles';

    api(method, path, body).then(function () {
      closeModal();
      loadProfiles();
      if (editId) { window._selectProfile(editId); }
    }).catch(function (e) { alert('Save failed: ' + e.message); });
  }

  function editActiveProfile() {
    if (!state.activeProfileId) return;
    window.openModal(true);
  }

  function deleteActiveProfile() {
    if (!state.activeProfileId) return;
    if (!confirm('Delete this profile and all its scans?')) return;
    api('DELETE', '/api/purpleteam/profiles/' + state.activeProfileId).then(function () {
      state.activeProfileId = null;
      state.activeProfile = null;
      document.getElementById('main-dashboard').classList.add('hidden');
      document.getElementById('main-placeholder').classList.remove('hidden');
      loadProfiles();
    }).catch(function (e) { alert('Delete failed: ' + e.message); });
  }

  // ── Utils ──
  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
