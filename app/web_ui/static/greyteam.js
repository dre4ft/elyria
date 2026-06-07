/* Grey Team — OSINT Signals Intelligence Dashboard */

(function () {
  'use strict';

  var A = {
    profiles:    '/api/greyteam/profiles',
    profile:     function (id) { return '/api/greyteam/profiles/' + id; },
    reports:     function (pid) { return '/api/greyteam/reports?profile_id=' + pid; },
    createReport:'/api/greyteam/reports',
    report:      function (rid) { return '/api/greyteam/reports/' + rid; },
    findings:    function (rid) { return '/api/greyteam/reports/' + rid + '/findings'; },
    stop:        function (rid) { return '/api/greyteam/reports/' + rid + '/stop'; },
  };

  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  };

  var SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 };

  var S = {
    profiles: [],
    activePid: null,
    activeRid: null,
    reports: [],
    findings: [],
    editingPid: null,
  };

  var D = {
    empty: $('#gt-empty'),
    content: $('#gt-content'),
    profileList: $('#gt-profile-list'),
    kpiRow: $('#gt-kpi-row'),
    indicators: $('#gt-indicators'),
    statsBar: $('#gt-stats-bar'),
    findingsEmpty: $('#gt-findings-empty'),
    findingsList: $('#gt-findings-list'),
    detailPanel: $('#gt-detail-panel'),
    detailContent: $('#gt-detail-content'),
    progressContainer: $('#gt-progress-container'),
    progressBar: $('#gt-progress-bar'),
    progressPct: $('#gt-progress-pct'),
    progressMsg: $('#gt-progress-msg'),
    liveProgress: $('#gt-live-progress'),
    liveMsg: $('#gt-live-msg'),
    livePct: $('#gt-live-pct'),
    liveBar: $('#gt-live-bar'),
    riskArc: $('#gt-risk-arc'),
    riskValue: $('#gt-risk-value'),
    riskLabel: $('#gt-risk-label'),
    threatBadge: $('#gt-threat-badge'),
    domain: $('#gt-domain'),
    meta: $('#gt-meta'),
    statusBadge: $('#gt-status-badge'),
  };

  // ── Auth ──
  function authHeaders() {
    var t = localStorage.getItem('elyria_token');
    return t ? { 'Authorization': 'Bearer ' + t } : {};
  }

  function api(method, path, body) {
    var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
    var ah = authHeaders();
    for (var k in ah) opts.headers[k] = ah[k];
    if (body) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function (r) {
      if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || 'Request failed'); });
      return r.json();
    });
  }

  // ── Init ──
  function init() {
    if (window.__gtInit) return;
    window.__gtInit = true;

    $('#btn-new-profile').addEventListener('click', function () { openModal(); });
    if ($('#btn-create-first')) $('#btn-create-first').addEventListener('click', function () { openModal(); });
    if ($('#btn-gt-modal-save')) $('#btn-gt-modal-save').addEventListener('click', saveProfile);
    $('#btn-run-scan').addEventListener('click', function () { if (S.activePid) runScan(); });
    $('#btn-stop-scan').addEventListener('click', function () { if (S.activePid) stopScan(); });
    $('#btn-edit-profile').addEventListener('click', function () {
      var p = S.profiles.find(function (x) { return x.profile_id === S.activePid; });
      if (p) openModal(p);
    });
    $('#btn-delete-profile').addEventListener('click', function () {
      if (!S.activePid) return;
      if (!confirm('Delete this target and all its intelligence reports?')) return;
      deleteProfile(S.activePid);
    });

    $('#filter-severity').addEventListener('change', function () { renderFindings(); });
    $('#filter-source').addEventListener('change', function () { renderFindings(); });
    $('#filter-type').addEventListener('change', function () { renderFindings(); });

    loadProfiles();
  }

  // ── Profiles ──
  function loadProfiles() {
    api('GET', A.profiles).then(function (data) {
      S.profiles = data || [];
      renderProfileList();
    }).catch(function () {});
  }

  function renderProfileList() {
    if (!D.profileList) return;
    D.profileList.innerHTML = '';
    S.profiles.forEach(function (p) {
      var el = document.createElement('div');
      var statusColors = { pending:'bg-gray-600', running:'bg-amber-400 animate-pulse', completed:'bg-emerald-400', stopped:'bg-amber-400', failed:'bg-red-400' };
      var dot = statusColors[p.status] || 'bg-gray-600';
      var total = p.total_findings || 0;
      el.className = 'profile-item' + (p.profile_id === S.activePid ? ' active' : '');
      el.innerHTML = '<span class="flex items-center gap-2 min-w-0 flex-1"><span class="w-2 h-2 rounded-full flex-shrink-0 ' + dot + '"></span><span class="text-xs text-gray-300 truncate">' + esc(p.name) + '</span></span>' +
        '<span class="text-[9px] text-gray-600 font-mono flex-shrink-0">' + (total > 0 ? total + ' sig' : '—') + '</span>';
      el.style.cssText = 'display:flex;align-items:center;gap:.5rem;padding:.5rem .625rem;border-radius:.5rem;cursor:pointer;transition:all .15s;border:1px solid transparent;';
      el.addEventListener('click', function () { selectProfile(p.profile_id); });
      D.profileList.appendChild(el);
    });
  }

  function selectProfile(pid) {
    S.activePid = pid;
    S.activeRid = null;
    S.findings = [];
    renderProfileList();
    hideDetail();

    api('GET', A.profile(pid)).then(function (p) {
      S.reports = p.reports || [];
      showDashboard(p);
      if (S.reports.length > 0) {
        selectReport(S.reports[0].report_id);
      } else {
        showEmptyFindings();
      }
    }).catch(function () {});
  }

  window._selectProfile = selectProfile;

  function deleteProfile(pid) {
    api('DELETE', A.profile(pid)).then(function () {
      if (S.activePid === pid) {
        S.activePid = null; S.activeRid = null; S.findings = [];
        D.content.classList.add('hidden');
        D.empty.classList.remove('hidden');
      }
      loadProfiles();
    }).catch(function (e) { alert('Delete failed: ' + e.message); });
  }

  // ── Dashboard ──
  function showDashboard(p) {
    D.empty.classList.add('hidden');
    D.content.classList.remove('hidden');
    D.kpiRow.classList.remove('hidden');
    D.indicators.classList.remove('hidden');
    D.statsBar.classList.remove('hidden');

    var domain = p.target_domain || p.target_path || '';
    D.domain.textContent = domain || 'NO TARGET CONFIGURED';
    D.meta.textContent = (domain ? 'TARGET: ' + domain : '') + (p.description ? '  //  ' + p.description : '');

    updateStatusBadge(p.status);
    if (p.status === 'running') {
      $('#btn-run-scan').classList.add('hidden');
      $('#btn-stop-scan').classList.remove('hidden');
      D.liveProgress.classList.remove('hidden');
      var pct = p.scan_progress || 0;
      D.livePct.textContent = pct + '%';
      D.liveBar.style.width = pct + '%';
      D.liveMsg.textContent = 'COLLECTION IN PROGRESS...';
    } else {
      D.liveProgress.classList.add('hidden');
      $('#btn-run-scan').classList.remove('hidden');
      $('#btn-stop-scan').classList.add('hidden');
    }

    resetAllIndicators();
  }

  function updateStatusBadge(status) {
    var b = D.statusBadge;
    b.classList.remove('hidden');
    var map = {
      pending: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
      running: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      stopped: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      failed: 'bg-red-500/10 text-red-400 border-red-500/20',
    };
    b.className = 'px-2 py-0.5 rounded-full text-[9px] font-bold border ' + (map[status] || map.pending);
    b.textContent = status.toUpperCase();
  }

  // ── Scan ──
  function runScan() {
    if (!S.activePid) return;
    var btn = $('#btn-run-scan');
    btn.disabled = true; btn.textContent = 'INITIALIZING...';
    D.liveProgress.classList.remove('hidden');
    D.liveBar.style.width = '0%';
    D.livePct.textContent = '0%';
    D.liveMsg.textContent = 'SIGNALS COLLECTION IN PROGRESS...';
    $('#btn-run-scan').classList.add('hidden');
    $('#btn-stop-scan').classList.remove('hidden');
    updateStatusBadge('running');
    resetAllIndicators();

    api('POST', A.createReport, { profile_id: S.activePid }).then(function (data) {
      S.activeRid = data.report_id;
      startPolling(data.report_id);
    }).catch(function (e) {
      alert('Scan failed: ' + e.message);
      btn.disabled = false;
      resetRunButton();
    });
  }

  function stopScan() {
    if (!S.activeRid) return;
    api('POST', A.stop(S.activeRid)).then(function () {
      stopPolling();
      D.liveProgress.classList.add('hidden');
      $('#btn-run-scan').classList.remove('hidden');
      $('#btn-stop-scan').classList.add('hidden');
      resetRunButton();
    }).catch(function () {});
  }

  function resetRunButton() {
    var btn = $('#btn-run-scan');
    btn.disabled = false;
    btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"/></svg>COLLECT';
  }

  // ── Polling ──
  var _pollTimer = null, _pollInterval = 2000, _lastPct = -1, _sameCount = 0, _pollCount = 0, _scanDone = false;

  function startPolling(rid) {
    stopPolling();
    _pollInterval = 2000; _lastPct = -1; _sameCount = 0; _pollCount = 0; _scanDone = false;
    _pollTimer = setTimeout(function () { poll(rid); }, 500);
  }

  function stopPolling() {
    if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    setTimeout(function () { _scanDone = false; }, 500);
  }

  function poll(rid) {
    _pollCount++;
    if (_pollCount > 180) { stopPolling(); D.liveProgress.classList.add('hidden'); return; }
    api('GET', A.report(rid)).then(function (r) {
      var pct = r.scan_progress || 0;
      D.livePct.textContent = pct + '%';
      D.liveBar.style.width = pct + '%';
      if (r.progress_msg) D.liveMsg.textContent = r.progress_msg;

      if (r.status === 'completed') { _onScanDone(r); return; }
      if (r.status === 'failed') { _onScanFailed(r); return; }

      if (pct !== _lastPct) {
        _pollInterval = Math.max(2000, _pollInterval / 1.5); _sameCount = 0;
        loadFindingsSilent(rid);
      } else {
        _sameCount++;
        if (_sameCount >= 3) { _pollInterval = Math.min(30000, _pollInterval * 2); _sameCount = 0; }
      }
      _lastPct = pct;
      _pollTimer = setTimeout(function () { poll(rid); }, _pollInterval);
    }).catch(function () {
      _pollInterval = Math.min(30000, _pollInterval * 2);
      _pollTimer = setTimeout(function () { poll(rid); }, _pollInterval);
    });
  }

  function _onScanDone(r) {
    if (_scanDone) return; _scanDone = true; stopPolling();
    D.livePct.textContent = '100%'; D.liveBar.style.width = '100%';
    D.liveMsg.textContent = 'COLLECTION COMPLETE';
    D.liveProgress.classList.add('hidden');
    $('#btn-run-scan').classList.remove('hidden'); $('#btn-stop-scan').classList.add('hidden');
    resetRunButton(); updateStatusBadge('completed');
    selectReport(S.activeRid); loadProfiles();
  }

  function _onScanFailed(r) {
    if (_scanDone) return; _scanDone = true; stopPolling();
    D.liveMsg.textContent = 'COLLECTION FAILED';
    D.liveProgress.classList.add('hidden');
    $('#btn-run-scan').classList.remove('hidden'); $('#btn-stop-scan').classList.add('hidden');
    resetRunButton(); updateStatusBadge('failed');
  }

  // ── Reports & Findings ──
  function selectReport(rid) { S.activeRid = rid; loadFindings(rid); }

  function loadFindings(rid) {
    api('GET', A.findings(rid)).then(function (data) {
      S.findings = data.findings || [];
      updateStats(data.counts || {});
      renderFindings();
      extractIntelFromFindings(S.findings);
    }).catch(function () {});
  }

  function loadFindingsSilent(rid) {
    api('GET', A.findings(rid)).then(function (data) {
      S.findings = data.findings || [];
      updateStats(data.counts || {});
      renderFindings();
      extractIntelFromFindings(S.findings);
    }).catch(function () {});
  }

  function showEmptyFindings() {
    D.findingsEmpty.classList.remove('hidden'); D.findingsList.classList.add('hidden');
    D.statsBar.classList.add('hidden');
  }

  // ── Stats bar ──
  function updateStats(counts) {
    var c = counts || {};
    if (!Object.keys(c).length && S.findings.length) {
      S.findings.forEach(function (f) { c[f.severity] = (c[f.severity] || 0) + 1; });
    }
    $('#stat-critical').textContent = c.critical || 0;
    $('#stat-high').textContent = c.high || 0;
    $('#stat-medium').textContent = c.medium || 0;
    $('#stat-low').textContent = c.low || 0;
    $('#stat-info').textContent = c.info || 0;

    var det = 0, ai = 0;
    S.findings.forEach(function (f) {
      if (!f.ai_description) det++; else ai++;
    });
    $('#stat-det').textContent = det;
    $('#stat-ai').textContent = ai;

    if (S.findings.length > 0) {
      D.findingsEmpty.classList.add('hidden'); D.findingsList.classList.remove('hidden');
      D.statsBar.classList.remove('hidden');
    }
  }

  // ── Findings rendering ──
  function renderFindings() {
    if (!D.findingsList) return;
    var sev = ($('#filter-severity') || {}).value || 'all';
    var src = ($('#filter-source') || {}).value || 'all';
    var type = ($('#filter-type') || {}).value || 'all';

    var filtered = S.findings;
    if (sev !== 'all') filtered = filtered.filter(function (f) { return f.severity === sev; });
    if (src !== 'all') filtered = filtered.filter(function (f) {
      if (src === 'ai') return !!f.ai_description;
      if (src === 'deterministic') return !f.ai_description;
      return true;
    });
    if (type !== 'all') filtered = filtered.filter(function (f) { return f.finding_type === type; });

    if (!filtered.length) {
      D.findingsList.innerHTML = '<div class="text-gray-600 text-xs text-center py-12 font-[\'JetBrains_Mono\']">NO SIGNALS MATCH FILTER</div>';
      return;
    }

    filtered.sort(function (a, b) { return (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4); });

    var sevBorders = { critical:'border-l-red-500', high:'border-l-orange-500', medium:'border-l-yellow-500', low:'border-l-green-500', info:'border-l-gray-600' };
    var sevBadges = {
      critical:'text-red-400 bg-red-500/10 border-red-500/20',
      high:'text-orange-400 bg-orange-500/10 border-orange-500/20',
      medium:'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
      low:'text-green-400 bg-green-500/10 border-green-500/20',
      info:'text-gray-400 bg-gray-500/10 border-gray-500/20'
    };

    D.findingsList.innerHTML = filtered.map(function (f) {
      var sevBorder = sevBorders[f.severity] || 'border-l-gray-600';
      var sevBadge = sevBadges[f.severity] || sevBadges.info;
      var ft = f.finding_type || 'osint';
      return '<div onclick="window.gtShowDetail(\'' + f.finding_id + '\')" class="finding-row cursor-pointer px-5 py-2.5 border-l-2 ' + sevBorder + ' transition-all">' +
        '<div class="flex items-start justify-between gap-3">' +
          '<div class="flex-1 min-w-0">' +
            '<div class="flex items-center gap-2">' +
              '<span class="text-xs font-medium text-gray-200 truncate">' + esc(f.title) + '</span>' +
              '<span class="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ' + sevBadge + '">' + esc(f.severity) + '</span>' +
              '<span class="shrink-0 px-1 py-0.5 rounded text-[8px] font-mono text-gray-500 bg-[#0d1117] uppercase border border-white/5">' + esc(ft) + '</span>' +
            '</div>' +
            (f.ai_description ? '<div class="text-[10px] text-amber-300/70 mt-0.5 italic line-clamp-2 font-[\'JetBrains_Mono\']">' + esc(f.ai_description) + '</div>' : '') +
            '<div class="text-[10px] text-gray-500 mt-0.5 truncate">' + esc((f.description || '').substring(0, 180)) + '</div>' +
            '<div class="flex items-center gap-2 mt-1">' +
              '<span class="text-[9px] text-gray-600 font-mono">' + esc(f.category || '') + '</span>' +
              (f.evidence && f.evidence !== 'Connection failed' ? '<span class="text-[9px] text-gray-500 font-mono truncate max-w-[220px]">' + esc(String(f.evidence).substring(0, 60)) + '</span>' : '') +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  window.gtShowDetail = function (fid) {
    var f = S.findings.find(function (x) { return x.finding_id === fid; });
    if (!f) return;
    D.detailPanel.classList.remove('hidden');
    D.detailContent.innerHTML =
      '<div class="flex items-center gap-2">' +
        '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ' + (f.severity==='critical'?'text-red-400 bg-red-500/10 border-red-500/20':f.severity==='high'?'text-orange-400 bg-orange-500/10 border-orange-500/20':f.severity==='low'?'text-green-400 bg-green-500/10 border-green-500/20':f.severity==='info'?'text-gray-400 bg-gray-500/10 border-gray-500/20':'text-yellow-400 bg-yellow-500/10 border-yellow-500/20') + '">' + esc(f.severity) + '</span>' +
        '<span class="text-[10px] text-gray-600 font-mono uppercase tracking-wider">' + esc(f.finding_type || 'osint') + '</span>' +
      '</div>' +
      '<h3 class="text-sm font-semibold text-gray-200 leading-snug">' + esc(f.title) + '</h3>' +
      (f.ai_description ? '<div class="text-[11px] text-amber-300/80 italic leading-relaxed p-3 bg-amber-500/5 rounded-lg border border-amber-500/10 font-[\'JetBrains_Mono\']">' + esc(f.ai_description) + '</div>' : '') +
      '<div class="space-y-3 pt-1">' +
        '<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wider mb-0.5">Description</div><div class="text-[11px] text-gray-400 leading-relaxed">' + esc(f.description || '—') + '</div></div>' +
        '<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wider mb-0.5">Category</div><div class="text-[11px] text-gray-400 font-mono">' + esc(f.category || '—') + '</div></div>' +
        (f.cwe_id ? '<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wider mb-0.5">CWE</div><div class="text-[11px] text-gray-400 font-mono">' + esc(f.cwe_id) + '</div></div>' : '') +
        (f.evidence ? '<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wider mb-1">Evidence</div><pre class="p-3 rounded-lg bg-[#0a0e14] border border-white/5 text-[10px] text-gray-400 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed">' + esc(String(f.evidence)) + '</pre></div>' : '') +
        (f.remediation ? '<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wider mb-0.5">Remediation</div><div class="text-[11px] text-emerald-400/70 leading-relaxed">' + esc(f.remediation) + '</div></div>' : '') +
      '</div>';
  };

  window.gtCloseDetail = function () { D.detailPanel.classList.add('hidden'); };
  function hideDetail() { D.detailPanel.classList.add('hidden'); }

  // ── KPI / Intel Extraction ──
  function resetAllIndicators() {
    ['a','mx','spf','dmarc'].forEach(function (k) { $('#ind-dns-' + k).textContent = '--'; $('#ind-dns-' + k).className = 'text-gray-400'; });
    setDot('dns', 'unknown');
    ['issuer','expiry','sans','oldtls'].forEach(function (k) { $('#ind-ssl-' + k).textContent = '--'; $('#ind-ssl-' + k).className = 'text-gray-400'; });
    setDot('ssl', 'unknown');
    ['hsts','csp','xfo','server'].forEach(function (k) { $('#ind-http-' + k).textContent = '--'; $('#ind-http-' + k).className = 'text-gray-400'; });
    setDot('http', 'unknown');
    $('#ind-subs-count').textContent = '--'; $('#ind-subs-list').innerHTML = ''; setDot('subs', 'unknown');
    $('#ind-emails-count').textContent = '--'; $('#ind-emails-list').innerHTML = ''; setDot('emails', 'unknown');
    $('#ind-tech-body').innerHTML = '<div class="text-gray-600">No components detected</div>'; setDot('tech', 'unknown');
    D.riskValue.textContent = '--'; D.riskLabel.textContent = 'NO DATA';
    D.riskArc.setAttribute('stroke', '#6b7280'); D.riskArc.setAttribute('stroke-dashoffset', '201');
    D.threatBadge.classList.add('hidden');
    $('#kpi-critical').textContent = '0'; $('#kpi-high').textContent = '0'; $('#kpi-total').textContent = '0';
  }

  function setDot(name, status) {
    var el = $('#ind-' + name + '-dot');
    if (!el) return;
    var map = { ok:'bg-emerald-500', warn:'bg-amber-500', bad:'bg-red-500', unknown:'bg-gray-600' };
    el.className = 'w-2 h-2 rounded-full ' + (map[status] || 'bg-gray-600');
    if (status === 'bad') el.style.boxShadow = '0 0 6px rgba(239,68,68,0.4)';
    else el.style.boxShadow = 'none';
  }

  function extractIntelFromFindings(findings) {
    if (!findings || !findings.length) return;

    var byType = {};
    findings.forEach(function (f) { var t = f.finding_type || 'osint'; byType[t] = byType[t] || []; byType[t].push(f); });

    // ── DNS Intel ──
    var dns = byType['dns'] || [];
    dns.forEach(function (f) {
      var t = f.title || '', ev = f.evidence || '';
      if (t.toLowerCase().includes('a record')) { var m = ev.match(/A:\s*(.+)/i); $('#ind-dns-a').textContent = m ? m[1].split(',')[0].trim() : '✓'; }
      if (t.toLowerCase().includes('mx')) $('#ind-dns-mx').textContent = '✓';
      if (t.includes('SPF record present')) { $('#ind-dns-spf').textContent = '✓ Present'; $('#ind-dns-spf').className = 'text-emerald-400'; }
      if (t.includes('Missing SPF')) { $('#ind-dns-spf').textContent = '✗ Missing'; $('#ind-dns-spf').className = 'text-red-400'; }
      if (t.includes('DMARC record present')) { var pol = t.includes('p=reject') ? '✓ Reject' : '✓ Monitor'; $('#ind-dns-dmarc').textContent = pol; $('#ind-dns-dmarc').className = t.includes('p=reject') ? 'text-emerald-400' : 'text-amber-400'; }
      if (t.includes('Missing DMARC')) { $('#ind-dns-dmarc').textContent = '✗ Missing'; $('#ind-dns-dmarc').className = 'text-red-400'; }
    });
    var dnsIssues = dns.filter(function (f) { return f.severity !== 'info'; }).length;
    var spfOk = dns.some(function (f) { return (f.title||'').includes('SPF record present'); });
    var dmarcOk = dns.some(function (f) { return (f.title||'').includes('DMARC record present'); });
    if (dnsIssues > 0) setDot('dns', 'bad'); else if (!spfOk || !dmarcOk) setDot('dns', 'warn'); else if (dns.length > 0) setDot('dns', 'ok');

    // ── SSL Intel ──
    var ssl = byType['ssl'] || [];
    ssl.forEach(function (f) {
      var t = f.title || '', ev = f.evidence || '';
      if (t.includes('issued by')) { var parts = ev.split(':'); var issuer = parts.slice(1).join(':').trim().substring(0, 28); $('#ind-ssl-issuer').textContent = issuer || '✓'; }
      if (t.includes('expires in')) { var dm = t.match(/(\d+)\s*days/); var days = dm ? parseInt(dm[1]) : null; $('#ind-ssl-expiry').textContent = days !== null ? days + 'd' : '✓'; if (days !== null && days < 30) $('#ind-ssl-expiry').className = 'text-red-400'; else if (days !== null && days < 90) $('#ind-ssl-expiry').className = 'text-amber-400'; else $('#ind-ssl-expiry').className = 'text-emerald-400'; }
      if (t.includes('SANs')) { var sm = t.match(/(\d+)\s*subdomain/); $('#ind-ssl-sans').textContent = sm ? sm[1] : '✓'; }
      if (t.includes('TLS version negotiated')) { var vm = t.match(/TLS version negotiated:\s*(.+)/); var v = vm ? vm[1].trim() : ''; $('#ind-ssl-oldtls').textContent = v || '--'; $('#ind-ssl-oldtls').className = v && (v.includes('1.0') || v.includes('1.1')) ? 'text-red-400' : 'text-emerald-400'; }
      if (t.includes('SSL connection failed')) { $('#ind-ssl-issuer').textContent = '✗ Failed'; $('#ind-ssl-issuer').className = 'text-red-400'; }
    });
    if (!$('#ind-ssl-oldtls').textContent || $('#ind-ssl-oldtls').textContent === '--') { $('#ind-ssl-oldtls').textContent = '✗ Unknown'; }
    var sslIssues = ssl.filter(function (f) { return f.severity !== 'info'; }).length;
    var hasOldTls = ssl.some(function (f) { return (f.title||'').includes('TLS version negotiated') && ((f.title||'').includes('TLSv1.0') || (f.title||'').includes('TLSv1.1')); });
    var nearExpiry = ssl.some(function (f) { return (f.title||'').includes('expires in') && (f.severity === 'critical' || f.severity === 'high'); });
    if (nearExpiry || hasOldTls) setDot('ssl', 'bad'); else if (sslIssues > 0) setDot('ssl', 'warn'); else if (ssl.length > 0) setDot('ssl', 'ok');

    // ── HTTP Intel ──
    var http = byType['http'] || [];
    var hasHttp = http.length > 0;
    var hasHsts = hasHttp && !http.some(function (f) { return (f.title||'').includes('Missing') && (f.title||'').includes('HSTS'); });
    var hasCsp = hasHttp && !http.some(function (f) { return (f.title||'').includes('Missing') && (f.title||'').includes('CSP'); });
    var hasXfo = hasHttp && !http.some(function (f) { return (f.title||'').includes('Missing') && (f.title||'').includes('X-Frame'); });
    if (hasHttp) {
      $('#ind-http-hsts').textContent = hasHsts ? '✓' : '✗'; $('#ind-http-hsts').className = hasHsts ? 'text-emerald-400' : 'text-red-400';
      $('#ind-http-csp').textContent = hasCsp ? '✓' : '✗'; $('#ind-http-csp').className = hasCsp ? 'text-emerald-400' : 'text-red-400';
      $('#ind-http-xfo').textContent = hasXfo ? '✓' : '✗'; $('#ind-http-xfo').className = hasXfo ? 'text-emerald-400' : 'text-red-400';
    }
    var serverFinding = http.find(function (f) { return (f.title||'').includes('Server header'); });
    if (serverFinding) { $('#ind-http-server').textContent = (serverFinding.evidence || '').replace('Server:', '').trim().substring(0, 22); $('#ind-http-server').className = 'text-amber-400'; }
    var httpIssues = http.filter(function (f) { return f.severity !== 'info'; }).length;
    if (httpIssues > 2) setDot('http', 'bad'); else if (httpIssues > 0 || !hasHsts || !hasCsp) setDot('http', 'warn'); else if (http.length > 0) setDot('http', 'ok');

    // ── Attack Surface (Subdomains) ──
    var ct = byType['ct'] || [];
    var subCount = 0, subList = [];
    ct.forEach(function (f) {
      var tm = (f.title||'').match(/(\d+)\s*subdomains/); if (tm) subCount = Math.max(subCount, parseInt(tm[1]));
      try { var ev = JSON.parse(f.evidence || '{}'); if (ev.subdomains && Array.isArray(ev.subdomains)) subList = ev.subdomains.slice(0, 5); } catch (e) {}
    });
    if (subCount === 0) {
      ssl.forEach(function (f) {
        if ((f.title||'').includes('SANs')) { var m = (f.title||'').match(/(\d+)\s*subdomain/); if (m) subCount = Math.max(subCount, parseInt(m[1])); var ev = f.evidence || ''; if (ev && !ev.startsWith('{')) { var sans = ev.split('\n').filter(function (s) { return s.trim(); }).slice(0, 5); if (sans.length) subList = sans; } }
      });
    }
    $('#ind-subs-count').textContent = subCount || '--';
    $('#ind-subs-list').innerHTML = subList.length ? subList.map(function (s) { return '<div class="truncate">' + esc(String(s).trim()) + '</div>'; }).join('') : (subCount > 0 ? '<div class="text-gray-600">' + subCount + ' discovered</div>' : '');
    if (subCount > 10) setDot('subs', 'bad'); else if (subCount > 3) setDot('subs', 'warn'); else if (subCount > 0) setDot('subs', 'ok');

    // ── Personnel Intel (Emails) ──
    var email = byType['email'] || [];
    var emailCount = 0, emailList = [];
    email.forEach(function (f) {
      var ev = (f.evidence || '').trim();
      if (!ev || ev === 'No data' || ev.includes('Connection failed')) return;
      var items = ev.split(',').map(function (e) { return e.trim(); }).filter(function (e) { return e.includes('@') && e.length < 80; });
      if (items.length) { emailCount += items.length; items.forEach(function (i) { if (emailList.length < 4) emailList.push(i); }); }
      else if (ev.includes('@') && ev.length < 80) { emailCount++; if (emailList.length < 4) emailList.push(ev); }
    });
    // Also check whois for emails
    var whois = byType['whois'] || [];
    whois.forEach(function (f) {
      var ev = (f.evidence || '').trim();
      var em = ev.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g);
      if (em) { emailCount += em.length; em.forEach(function (e) { if (emailList.length < 4 && !emailList.includes(e)) emailList.push(e); }); }
    });
    $('#ind-emails-count').textContent = emailCount || '--';
    $('#ind-emails-list').innerHTML = emailList.length ? emailList.map(function (e) { return '<div class="truncate">' + esc(e) + '</div>'; }).join('') : '';
    if (emailCount > 5) setDot('emails', 'warn'); else if (emailCount > 0) setDot('emails', 'ok');

    // ── Tech Stack ──
    var tech = byType['tech'] || [];
    var techItems = [], techSeen = {};
    tech.forEach(function (f) {
      if ((f.title||'').includes('components detected')) {
        try { var ev = JSON.parse(f.evidence || '[]'); if (Array.isArray(ev)) ev.forEach(function (t) { var s = String(t).trim(); if (s && !techSeen[s]) { techSeen[s] = true; techItems.push(s); } }); }
        catch (e) { var lines = (f.evidence || '').split('\n').filter(function (l) { return l.trim(); }); lines.forEach(function (l) { var s = l.trim(); if (s && !techSeen[s]) { techSeen[s] = true; techItems.push(s); } }); }
      }
    });
    $('#ind-tech-body').innerHTML = techItems.length ? techItems.slice(0, 6).map(function (t) { var d = String(t).length > 32 ? String(t).substring(0, 29) + '...' : String(t); return '<div class="truncate" title="' + esc(String(t)) + '">' + esc(d) + '</div>'; }).join('') : '<div class="text-gray-600">No components detected</div>';
    if (techItems.length > 0) setDot('tech', 'ok');

    // ── Threat Index Calculation ──
    var critical = findings.filter(function (f) { return f.severity === 'critical'; }).length;
    var high = findings.filter(function (f) { return f.severity === 'high'; }).length;
    var medium = findings.filter(function (f) { return f.severity === 'medium'; }).length;
    var low = findings.filter(function (f) { return f.severity === 'low'; }).length;

    var score = 0;
    score += critical * 25;
    score += high * 15;
    score += medium * 5;
    score += low * 2;
    // Bonus: exposed subdomains and emails increase threat
    if (subCount > 10) score += 10;
    else if (subCount > 5) score += 5;
    if (emailCount > 5) score += 5;
    score = Math.min(100, score);

    var riskLabel, riskColor;
    if (findings.length === 0) { riskLabel = 'NO DATA'; riskColor = '#6b7280'; }
    else if (score === 0) { riskLabel = 'CLEAN'; riskColor = '#22c55e'; }
    else if (score < 15) { riskLabel = 'LOW'; riskColor = '#22c55e'; }
    else if (score < 35) { riskLabel = 'ELEVATED'; riskColor = '#eab308'; }
    else if (score < 65) { riskLabel = 'HIGH'; riskColor = '#f97316'; }
    else { riskLabel = 'CRITICAL'; riskColor = '#ef4444'; }

    D.riskValue.textContent = score;
    D.riskLabel.textContent = riskLabel;
    D.riskArc.setAttribute('stroke', riskColor);
    D.riskArc.setAttribute('stroke-dashoffset', 201 - (score / 100) * 201);

    D.threatBadge.classList.remove('hidden');
    D.threatBadge.textContent = riskLabel;
    var badgeMap = { 'CRITICAL':'bg-red-500/10 text-red-400 border-red-500/20', 'HIGH':'bg-orange-500/10 text-orange-400 border-orange-500/20', 'ELEVATED':'bg-yellow-500/10 text-yellow-400 border-yellow-500/20', 'LOW':'bg-emerald-500/10 text-emerald-400 border-emerald-500/20', 'CLEAN':'bg-emerald-500/10 text-emerald-400 border-emerald-500/20', 'NO DATA':'bg-gray-500/10 text-gray-400 border-gray-500/20' };
    D.threatBadge.className = 'px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border intel-badge ' + (badgeMap[riskLabel] || badgeMap['NO DATA']);

    $('#kpi-critical').textContent = critical;
    $('#kpi-high').textContent = high;
    $('#kpi-total').textContent = findings.length;
  }

  // ── Modal ──
  function openModal(profile) {
    S.editingPid = profile ? profile.profile_id : null;
    var modal = $('#gt-modal');
    modal.classList.remove('hidden'); modal.classList.add('flex');
    $('#gt-modal-title').textContent = profile ? 'EDIT TARGET PARAMETERS' : 'TARGET ACQUISITION';
    if (profile) {
      $('#gt-modal-name').value = profile.name || '';
      $('#gt-modal-domain').value = profile.target_domain || '';
      $('#gt-modal-desc').value = profile.description || '';
      $('#gt-modal-rounds').value = profile.analysis_rounds || 5;
      var cats = typeof profile.categories === 'string' ? JSON.parse(profile.categories || '[]') : (profile.categories || []);
      document.querySelectorAll('.gt-cat-check').forEach(function (cb) { cb.checked = cats.length === 0 || cats.includes(cb.value); });
    } else {
      ['gt-modal-name','gt-modal-domain','gt-modal-desc'].forEach(function (id) { var el = $('#' + id); if (el) el.value = ''; });
      $('#gt-modal-rounds').value = 5;
      document.querySelectorAll('.gt-cat-check').forEach(function (cb) { cb.checked = true; });
    }
  }

  window.openModal = openModal;

  function saveProfile() {
    var name = $('#gt-modal-name').value.trim();
    var domain = $('#gt-modal-domain').value.trim();
    if (!name) { alert('Operation name is required'); return; }
    if (!domain && !S.editingPid) { alert('Target domain is required'); return; }
    var body = {
      name: name,
      description: $('#gt-modal-desc').value.trim(),
      target_domain: domain,
      categories: [].map.call(document.querySelectorAll('.gt-cat-check:checked'), function (c) { return c.value; }),
      analysis_rounds: parseInt($('#gt-modal-rounds').value) || 5,
    };
    var url = S.editingPid ? A.profile(S.editingPid) : A.profiles;
    var method = S.editingPid ? 'PUT' : 'POST';
    api(method, url, body).then(function () {
      $('#gt-modal').classList.add('hidden');
      loadProfiles();
      if (S.editingPid) selectProfile(S.editingPid);
    }).catch(function (e) { alert('Save failed: ' + e.message); });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
