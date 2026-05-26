/* Grey Team — Passive OSINT Dashboard */

const A = {
  profiles:    () => `/api/greyteam/profiles`,
  profile:     (id) => `/api/greyteam/profiles/${id}`,
  reports:     (pid) => `/api/greyteam/reports?profile_id=${pid}`,
  createReport: '/api/greyteam/reports',
  report:      (rid) => `/api/greyteam/reports/${rid}`,
  findings:    (rid) => `/api/greyteam/reports/${rid}/findings`,
  events:      (rid) => `/api/greyteam/events/${rid}`,
  stop:        (rid) => `/api/greyteam/reports/${rid}/stop`,
};

const $ = s => document.querySelector(s);
const esc = s => { const d = document.createElement('div'); d.textContent = s||''; return d.innerHTML; };

const SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 };
const STATUS_CLASS = { ok:'bg-low', warn:'bg-medium', bad:'bg-critical', unknown:'bg-info' };

let S = {
  profiles: [],
  activePid: null,
  activeRid: null,
  reports: [],
  findings: [],
  editingPid: null,
};

// ── DOM refs ──
const D = {
  placeholder: $('#main-placeholder'),
  dashboard: $('#main-dashboard'),
  profileList: $('#profile-list'),
  statsBar: $('#stats-bar'),
  findingsEmpty: $('#findings-empty'),
  findingsList: $('#findings-list'),
  detailPanel: $('#detail-panel'),
  detailContent: $('#detail-content'),
  scanProg: $('#scan-progress-container'),
  scanBar: $('#scan-progress-bar'),
  scanPct: $('#scan-progress-pct'),
  scanLabel: $('#scan-progress-label'),
  dashCards: $('#dashboard-cards'),
  dashIndicators: $('#dashboard-indicators'),
};

// ── Init ──
function init() {
  if (window.__greyteamInit) return;
  window.__greyteamInit = true;
  initAuth();
  initHeaderUser();
  setupButtons();
  setupModal();
  setupFilters();
  loadProfiles();
}

// ── Profile list ──
async function loadProfiles() {
  try {
    const r = await fetch(A.profiles(), { headers: _authHeaders() });
    S.profiles = await r.json();
    renderProfiles();
  } catch (e) {
    console.error('Failed to load profiles', e);
  }
}

function renderProfiles() {
  if (!D.profileList) return;
  if (!S.profiles.length) {
    D.profileList.innerHTML = '<div class="text-[11px] text-gray-600 px-2 py-3 text-center">No domains yet</div>';
    return;
  }
  D.profileList.innerHTML = S.profiles.map(p => {
    const active = S.activePid === p.profile_id ? 'bg-primary/10 border-primary/20 text-primary-light' : 'text-gray-400 hover:bg-white/5 border-transparent';
    const domain = esc(p.target_domain || p.target_path || 'No domain');
    return `<button onclick="selectProfile('${p.profile_id}')" class="w-full text-left px-2.5 py-1.5 rounded-md border text-[11px] transition-all ${active}">
      <div class="truncate font-medium">${esc(p.name)}</div>
      <div class="text-[10px] text-gray-600 truncate mt-0.5 font-mono">${domain}</div>
    </button>`;
  }).join('');
}

async function selectProfile(pid) {
  S.activePid = pid;
  S.activeRid = null;
  S.findings = [];
  renderProfiles();
  hideDetail();

  try {
    const r = await fetch(A.profile(pid), { headers: _authHeaders() });
    const p = await r.json();
    S.reports = p.reports || [];
    renderDashboard(p);
    if (S.reports.length > 0) {
      selectReport(S.reports[0].report_id);
    } else {
      showEmptyFindings();
    }
  } catch (e) {
    console.error('Failed to load profile', e);
  }
}

// ── Dashboard ──
function renderDashboard(p) {
  D.placeholder.classList.add('hidden');
  D.dashboard.classList.remove('hidden');
  D.dashCards.classList.remove('hidden');
  D.dashIndicators.classList.remove('hidden');
  D.statsBar.classList.remove('hidden');

  // Domain header
  const domain = p.target_domain || p.target_path || '';
  $('#dash-domain').textContent = domain || 'No domain configured';
  $('#dash-meta').innerHTML = domain ? `<span>Target: ${esc(domain)}</span>` : '';

  if (p.description) {
    $('#dash-meta').innerHTML += `<span class="text-gray-600">· ${esc(p.description)}</span>`;
  }

  // Buttons are wired inline in the HTML (onclick="runScan()" etc)
  // They read S.activePid dynamically to know the current profile

  // Reset indicators
  resetIndicators();

  // Load latest report findings
  if (S.reports.length > 0) {
    const latest = S.reports[0];
    loadFindings(latest.report_id);
  }
}

function resetIndicators() {
  // DNS
  ['a','mx','spf','dmarc'].forEach(k => $('#ind-dns-'+k).textContent = '--');
  setIndicatorStatus('dns', 'unknown');
  // SSL
  ['issuer','expiry','sans','oldtls'].forEach(k => $('#ind-ssl-'+k).textContent = '--');
  setIndicatorStatus('ssl', 'unknown');
  // HTTP
  ['hsts','csp','xfo','server'].forEach(k => $('#ind-http-'+k).textContent = '--');
  setIndicatorStatus('http', 'unknown');
  // Subs
  $('#ind-subs-count').textContent = '--';
  $('#ind-subs-list').innerHTML = '';
  setIndicatorStatus('subs', 'unknown');
  // Emails
  $('#ind-emails-count').textContent = '--';
  $('#ind-emails-list').innerHTML = '';
  setIndicatorStatus('emails', 'unknown');
  // Tech
  $('#ind-tech-body').innerHTML = '';
  setIndicatorStatus('tech', 'unknown');

  // Risk gauge
  $('#risk-gauge-value').textContent = '--';
  $('#risk-gauge-label').textContent = 'No data';
  $('#risk-gauge-arc').setAttribute('stroke', '#e2a03f');
  $('#risk-gauge-arc').setAttribute('stroke-dashoffset', '201');
  $('#dash-risk-badge').classList.add('hidden');

  // Summary cards
  $('#card-critical .text-2xl').textContent = '0';
  $('#card-high .text-2xl').textContent = '0';
  $('#card-total .text-2xl').textContent = '0';
}

function setIndicatorStatus(name, status) {
  const el = $(`#ind-${name}-status`);
  if (el) {
    el.className = `w-2 h-2 rounded-full ${STATUS_CLASS[status] || 'bg-info'}`;
  }
}

function updateDashboardFromFindings(findings) {
  if (!findings || !findings.length) return;

  // Per-type extraction
  const byType = {};
  for (const f of findings) {
    const t = f.finding_type || 'osint';
    byType[t] = byType[t] || [];
    byType[t].push(f);
  }

  // ── DNS indicator ──
  const dns = byType['dns'] || [];
  for (const f of dns) {
    const t = f.title || '';
    const ev = f.evidence || '';
    if (t.includes('A record')) {
      $('#ind-dns-a').textContent = ev.split(':')[1]?.trim() || '✓';
    }
    if (t.includes('MX')) {
      const match = ev.match(/mx/i) ? '✓' : (ev.length > 2 ? ev.substring(0,40) : '--');
      $('#ind-dns-mx').textContent = '✓';
    }
    if (t.includes('SPF record present')) {
      $('#ind-dns-spf').textContent = '✓';
      $('#ind-dns-spf').className = 'text-[10px] indicator-good';
    }
    if (t.includes('Missing SPF')) {
      $('#ind-dns-spf').textContent = '✗ Missing';
      $('#ind-dns-spf').className = 'text-[10px] indicator-bad';
    }
    if (t.includes('DMARC record present')) {
      $('#ind-dns-dmarc').textContent = t.includes('p=reject') ? '✓ Reject' : '✓ Monitor';
      $('#ind-dns-dmarc').className = t.includes('p=reject') ? 'text-[10px] indicator-good' : 'text-[10px] indicator-warn';
    }
    if (t.includes('Missing DMARC')) {
      $('#ind-dns-dmarc').textContent = '✗ Missing';
      $('#ind-dns-dmarc').className = 'text-[10px] indicator-bad';
    }
  }

  const dnsIssues = dns.filter(f => f.severity !== 'info').length;
  const spfOk = dns.some(f => f.title.includes('SPF record present'));
  const dmarcOk = dns.some(f => f.title.includes('DMARC record present') && (f.title.includes('p=reject') || f.title.includes('p=quarantine')));
  if (dnsIssues > 0) setIndicatorStatus('dns', 'bad');
  else if (!spfOk || !dmarcOk) setIndicatorStatus('dns', 'warn');
  else setIndicatorStatus('dns', 'ok');

  // ── SSL indicator ──
  const ssl = byType['ssl'] || [];
  for (const f of ssl) {
    const t = f.title || '';
    if (t.includes('issued by')) {
      $('#ind-ssl-issuer').textContent = f.evidence?.split(':')[1]?.trim()?.substring(0,30) || '✓';
    }
    if (t.includes('expires in')) {
      const days = t.match(/(\d+)\s*days/);
      $('#ind-ssl-expiry').textContent = days ? `${days[1]}d` : '✓';
      if (days && parseInt(days[1]) < 30) {
        $('#ind-ssl-expiry').className = 'text-[10px] indicator-bad';
      } else if (days && parseInt(days[1]) < 90) {
        $('#ind-ssl-expiry').className = 'text-[10px] indicator-warn';
      }
    }
    if (t.includes('SANs')) {
      const m = t.match(/(\d+)\s*subdomains/);
      $('#ind-ssl-sans').textContent = m ? m[1] : '✓';
    }
    if (t.includes('TLS 1.0 enabled') || t.includes('TLS 1.1 enabled')) {
      $('#ind-ssl-oldtls').textContent = '✗ Enabled';
      $('#ind-ssl-oldtls').className = 'text-[10px] indicator-bad';
    }
    if (t.includes('TLS 1.0/1.1 disabled')) {
      $('#ind-ssl-oldtls').textContent = '✓ Disabled';
      $('#ind-ssl-oldtls').className = 'text-[10px] indicator-good';
    }
  }
  if (!$('#ind-ssl-oldtls').textContent || $('#ind-ssl-oldtls').textContent === '--') {
    $('#ind-ssl-oldtls').textContent = '✗ Unknown';
  }

  const sslIssues = ssl.filter(f => f.severity !== 'info').length;
  const hasOldTls = ssl.some(f => (f.title||'').includes('TLS 1.0 enabled') || (f.title||'').includes('TLS 1.1 enabled'));
  const nearExpiry = ssl.some(f => (f.title||'').includes('expires in') && (f.severity === 'critical' || f.severity === 'high'));
  if (nearExpiry || hasOldTls) setIndicatorStatus('ssl', 'bad');
  else if (sslIssues > 0) setIndicatorStatus('ssl', 'warn');
  else if (ssl.length > 0) setIndicatorStatus('ssl', 'ok');
  else setIndicatorStatus('ssl', 'unknown');

  // ── HTTP indicator ──
  const http = byType['http'] || [];
  const hasHttpData = http.length > 0;
  const hasHsts = hasHttpData && !http.some(f => (f.title||'').includes('Missing') && (f.title||'').includes('HSTS'));
  const hasCsp = hasHttpData && !http.some(f => (f.title||'').includes('Missing') && (f.title||'').includes('CSP'));
  const hasXfo = hasHttpData && !http.some(f => (f.title||'').includes('Missing') && (f.title||'').includes('X-Frame'));

  if (!hasHttpData) {
    $('#ind-http-hsts').textContent = '--';
    $('#ind-http-hsts').className = 'text-[10px]';
    $('#ind-http-csp').textContent = '--';
    $('#ind-http-csp').className = 'text-[10px]';
    $('#ind-http-xfo').textContent = '--';
    $('#ind-http-xfo').className = 'text-[10px]';
  } else {
    $('#ind-http-hsts').textContent = hasHsts ? '✓' : '✗';
    $('#ind-http-hsts').className = hasHsts ? 'text-[10px] indicator-good' : 'text-[10px] indicator-bad';
    $('#ind-http-csp').textContent = hasCsp ? '✓' : '✗';
    $('#ind-http-csp').className = hasCsp ? 'text-[10px] indicator-good' : 'text-[10px] indicator-bad';
    $('#ind-http-xfo').textContent = hasXfo ? '✓' : '✗';
    $('#ind-http-xfo').className = hasXfo ? 'text-[10px] indicator-good' : 'text-[10px] indicator-bad';
  }

  // Server header
  const serverFinding = http.find(f => (f.title||'').includes('Server header'));
  if (serverFinding) {
    const sv = serverFinding.evidence || '';
    $('#ind-http-server').textContent = sv.replace('Server:','').trim().substring(0,25);
    $('#ind-http-server').className = 'text-[10px] indicator-warn';
  }

  const httpIssues = http.filter(f => f.severity !== 'info').length;
  if (httpIssues > 2) setIndicatorStatus('http', 'bad');
  else if (httpIssues > 0 || !hasHsts || !hasCsp) setIndicatorStatus('http', 'warn');
  else if (http.length > 0) setIndicatorStatus('http', 'ok');
  else setIndicatorStatus('http', 'unknown');

  // ── Subdomains (CT + SSL SANs + DNS) ──
  const ct = byType['ct'] || [];
  let subCount = 0;
  let subList = [];
  for (const f of ct) {
    const t = f.title || '';
    const m = t.match(/(\d+)\s*subdomains/);
    if (m) subCount = parseInt(m[1]);
    try {
      const ev = JSON.parse(f.evidence || '{}');
      if (ev.subdomains && Array.isArray(ev.subdomains)) {
        subList = ev.subdomains.slice(0, 5);
      }
    } catch(e) {}
  }
  // Fallback: extract SANs from SSL
  if (subCount === 0) {
    const ssl = byType['ssl'] || [];
    for (const f of ssl) {
      if ((f.title||'').includes('SANs')) {
        const m = (f.title||'').match(/(\d+)\s*subdomains/);
        if (m) subCount = parseInt(m[1]);
        // Parse SAN names from evidence (newline-separated)
        const ev = f.evidence || '';
        if (ev && !ev.startsWith('{')) {
          const sans = ev.split('\n').filter(s => s.trim() && !s.includes('DNS:')).slice(0, 5);
          if (sans.length > 0) subList = sans;
        }
        break;
      }
    }
  }
  // Fallback: count DNS A/AAAA records as subdomain indicator
  if (subCount === 0) {
    const dns = byType['dns'] || [];
    for (const f of dns) {
      if ((f.title||'').includes('A records')) {
        const m = (f.evidence||'').match(/A:\s*(.+)/);
        if (m) {
          const ips = m[1].split(',').map(s => s.trim()).filter(Boolean);
          if (ips.length > 0 && subCount === 0) subCount = Math.max(subCount, ips.length);
        }
      }
    }
  }

  $('#ind-subs-count').textContent = subCount || '--';
  $('#ind-subs-list').innerHTML = subList.length > 0
    ? subList.map(s => `<div class="truncate">${esc(String(s).trim())}</div>`).join('')
    : (subCount > 0 ? `<div class="text-gray-600">${subCount} subdomain(s) found</div>` : '');

  if (subCount > 10) setIndicatorStatus('subs', 'bad');
  else if (subCount > 3) setIndicatorStatus('subs', 'warn');
  else if (subCount > 0) setIndicatorStatus('subs', 'ok');
  else setIndicatorStatus('subs', 'unknown');

  // ── Emails (from email module + WHOIS) ──
  const email = byType['email'] || [];
  let emailCount = 0;
  let emailList = [];

  for (const f of email) {
    const ev = (f.evidence || '').trim();
    if (!ev || ev === 'No data' || ev.includes('Connection failed')) continue;
    // Comma-separated list
    const items = ev.split(',').map(e => e.trim()).filter(e => e.includes('@') && e.length < 80);
    if (items.length > 0) {
      emailCount += items.length;
      for (const item of items) {
        if (emailList.length < 4) emailList.push(item);
      }
    } else if (ev.includes('@') && ev.length < 80) {
      // Single email
      emailCount++;
      if (emailList.length < 4) emailList.push(ev);
    }
  }

  $('#ind-emails-count').textContent = emailCount || '--';
  $('#ind-emails-list').innerHTML = emailList.length > 0
    ? emailList.map(e => `<div class="truncate">${esc(e)}</div>`).join('')
    : '';

  if (emailCount > 5) setIndicatorStatus('emails', 'warn');
  else if (emailCount > 0) setIndicatorStatus('emails', 'ok');
  else setIndicatorStatus('emails', 'unknown');

  // ── Tech Stack (fingerprint + response headers) ──
  const tech = byType['tech'] || [];
  let techItems = [];
  let techSeen = new Set();

  for (const f of tech) {
    if ((f.title||'').includes('components detected')) {
      try {
        const ev = JSON.parse(f.evidence || '[]');
        if (Array.isArray(ev)) {
          ev.forEach(t => {
            const s = String(t).trim();
            if (s && !techSeen.has(s)) {
              techSeen.add(s);
              techItems.push(s);
            }
          });
        }
      } catch(e) {
        // Evidence might be plain text, try line-by-line
        const lines = (f.evidence || '').split('\n').filter(l => l.trim());
        lines.forEach(l => {
          const s = l.trim();
          if (s && !techSeen.has(s)) {
            techSeen.add(s);
            techItems.push(s);
          }
        });
      }
    }
  }

  $('#ind-tech-body').innerHTML = techItems.length > 0
    ? techItems.slice(0, 5).map(t => {
        // Truncate long entries
        const display = String(t).length > 35 ? String(t).substring(0, 32) + '...' : String(t);
        return `<div class="truncate" title="${esc(String(t))}">${esc(display)}</div>`;
      }).join('')
    : '<div class="text-gray-600">No components detected</div>';

  if (techItems.length > 0) setIndicatorStatus('tech', 'ok');
  else setIndicatorStatus('tech', 'unknown');

  // ── Risk Score ──
  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;
  const info = findings.filter(f => f.severity === 'info').length;

  let score = 0;
  score += critical * 25;
  score += high * 15;
  score += medium * 5;
  score += low * 2;
  score = Math.min(100, score);

  let riskLabel, riskColor;
  if (findings.length === 0) {
    riskLabel = 'No data';
    riskColor = '#6b7280';
  } else if (score === 0) {
    riskLabel = 'Info';
    riskColor = '#6b7280';
  } else if (score < 15) {
    riskLabel = 'Low';
    riskColor = '#22c55e';
  } else if (score < 35) {
    riskLabel = 'Medium';
    riskColor = '#e2a03f';
  } else if (score < 65) {
    riskLabel = 'High';
    riskColor = '#f97316';
  } else {
    riskLabel = 'Critical';
    riskColor = '#ef4444';
  }

  $('#risk-gauge-value').textContent = score;
  $('#risk-gauge-label').textContent = riskLabel;
  $('#risk-gauge-arc').setAttribute('stroke', riskColor);
  const circumference = 201;
  const offset = circumference - (score / 100) * circumference;
  $('#risk-gauge-arc').setAttribute('stroke-dashoffset', offset);

  // Risk badge
  const badge = $('#dash-risk-badge');
  badge.classList.remove('hidden');
  badge.textContent = riskLabel;
  badge.className = 'px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide';
  if (riskLabel === 'Critical') {
    badge.classList.add('bg-critical/15', 'text-critical-light', 'border', 'border-critical/20');
  } else if (riskLabel === 'High') {
    badge.classList.add('bg-high/15', 'text-high-light', 'border', 'border-high/20');
  } else if (riskLabel === 'Medium') {
    badge.classList.add('bg-medium/15', 'text-medium-light', 'border', 'border-medium/20');
  } else if (riskLabel === 'Low') {
    badge.classList.add('bg-low/15', 'text-low-light', 'border', 'border-low/20');
  } else {
    badge.classList.add('bg-info/15', 'text-info-light', 'border', 'border-info/20');
  }

  // Summary cards
  $('#card-critical .text-2xl').textContent = critical;
  $('#card-high .text-2xl').textContent = high;
  $('#card-total .text-2xl').textContent = findings.length;
}

// ── Reports & Findings ──
function selectReport(rid) {
  S.activeRid = rid;
  loadFindings(rid);
}

async function loadFindings(rid) {
  try {
    const r = await fetch(A.findings(rid), { headers: _authHeaders() });
    const data = await r.json();
    S.findings = data.findings || [];
    updateStats(data.counts || {});
    renderFindings(S.findings);
    updateDashboardFromFindings(S.findings);
  } catch (e) {
    console.error('Failed to load findings', e);
  }
}

function showEmptyFindings() {
  D.findingsEmpty.classList.remove('hidden');
  D.findingsList.classList.add('hidden');
  D.statsBar.classList.add('hidden');
}

// ── Scan + Hybrid Polling (adaptive: /1.5 when active, *2 when idle, 2s–30s) ──

let _pollTimer = null;
let _pollInterval = 2000;
let _pollLastPct = -1;
let _pollSameCount = 0;

async function runScan() {
  if (!S.activePid) return;

  D.scanProg.classList.remove('hidden');
  D.scanBar.style.width = '0%';
  D.scanPct.textContent = '0%';
  D.scanLabel.textContent = 'Starting OSINT collection...';
  D.scanLabel.classList.add('scanning-pulse');
  D.statsBar.classList.remove('hidden');
  D.dashCards.classList.remove('hidden');
  D.dashIndicators.classList.remove('hidden');
  resetIndicators();

  try {
    const r = await fetch(A.createReport, {
      method: 'POST',
      headers: { ..._authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: S.activePid }),
    });
    const { report_id } = await r.json();
    S.activeRid = report_id;
    startPolling(report_id);
  } catch (e) {
    console.error('Failed to start scan', e);
    D.scanProg.classList.add('hidden');
  }
}

function startPolling(rid) {
  stopPolling();
  _pollInterval = 2000;
  _pollLastPct = -1;
  _pollSameCount = 0;

  // Fire first poll after 500ms (blueteam pattern)
  _pollTimer = setTimeout(() => poll(rid), 500);
}

function stopPolling() {
  if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
}

async function poll(rid) {
  try {
    const r = await fetch(A.report(rid), { headers: _authHeaders() });
    if (!r.ok) { stopPolling(); return; }
    const report = await r.json();

    const pct = report.scan_progress || 0;
    const status = report.status;

    // Update progress UI
    D.scanProg.classList.remove('hidden');
    D.scanBar.style.width = `${pct}%`;
    D.scanPct.textContent = `${pct}%`;

    if (pct >= 100) {
      D.scanLabel.textContent = status === 'completed' ? 'OSINT scan complete' : status === 'failed' ? 'Scan failed' : 'Done';
      D.scanLabel.classList.remove('scanning-pulse');
    }

    // Adaptive interval
    if (pct !== _pollLastPct) {
      _pollInterval = Math.max(2000, _pollInterval / 1.5);
      _pollSameCount = 0;
      // Reload findings when progress changes
      loadFindings(rid);
    } else {
      _pollSameCount++;
      if (_pollSameCount >= 2) {
        _pollInterval = Math.min(30000, _pollInterval * 2);
        _pollSameCount = 0;
      }
    }
    _pollLastPct = pct;

    // Stop condition
    if (status !== 'running') {
      D.scanLabel.classList.remove('scanning-pulse');
      D.scanLabel.textContent = status === 'completed' ? 'OSINT scan complete' : 'Scan failed';
      setTimeout(() => D.scanProg.classList.add('hidden'), 3000);
      loadFindings(rid);
      stopPolling();
      return;
    }

    // Schedule next poll
    _pollTimer = setTimeout(() => poll(rid), _pollInterval);
  } catch (e) {
    console.error('Poll failed:', e);
    _pollInterval = Math.min(30000, _pollInterval * 2);
    _pollTimer = setTimeout(() => poll(rid), _pollInterval);
  }
}

// ── Render findings ──
function updateStats(counts) {
  if (!counts) {
    counts = {};
    for (const f of S.findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
  }
  const c = counts || {};
  $('#stat-critical').textContent = c.critical || 0;
  $('#stat-high').textContent = c.high || 0;
  $('#stat-medium').textContent = c.medium || 0;
  $('#stat-low').textContent = c.low || 0;
  $('#stat-info').textContent = c.info || 0;

  let det = 0, ai = 0;
  for (const f of S.findings) {
    if (f.source === 'deterministic') det++;
    else if (f.ai_description) ai++;
  }
  $('#stat-det').textContent = det;
  $('#stat-ai').textContent = ai;

  if (S.findings.length > 0) {
    D.findingsEmpty.classList.add('hidden');
    D.findingsList.classList.remove('hidden');
    D.statsBar.classList.remove('hidden');
  }
}

function renderFindings(findings) {
  if (!D.findingsList) return;
  const sev = $('#filter-severity')?.value || 'all';
  const src = $('#filter-source')?.value || 'all';
  const type = $('#filter-type')?.value || 'all';

  let filtered = findings || S.findings;
  if (sev !== 'all') filtered = filtered.filter(f => f.severity === sev);
  if (src !== 'all') filtered = filtered.filter(f => {
    if (src === 'ai') return !!f.ai_description;
    if (src === 'deterministic') return !f.ai_description;
    return true;
  });
  if (type !== 'all') filtered = filtered.filter(f => f.finding_type === type);

  if (!filtered.length) {
    D.findingsList.innerHTML = '<div class="text-gray-600 text-xs text-center py-8">No findings match the filter</div>';
    return;
  }

  filtered.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

  const SEV_COLORS = {
    critical: 'border-l-critical bg-critical/5',
    high:     'border-l-high bg-high/5',
    medium:   'border-l-medium bg-medium/5',
    low:      'border-l-low bg-low/5',
    info:     'border-l-info bg-info/5',
  };

  D.findingsList.innerHTML = filtered.map(f => {
    const sevClass = SEV_COLORS[f.severity] || 'border-l-medium';
    const ft = f.finding_type || f.category || 'osint';
    return `<div onclick="showDetail('${f.finding_id}')" class="finding-row cursor-pointer px-5 py-2.5 border-l-2 ${sevClass} transition-all">
      <div class="flex items-start justify-between gap-3">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            <span class="text-xs font-medium text-gray-200 truncate">${esc(f.title)}</span>
            <span class="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold uppercase ${f.severity==='critical'?'text-critical bg-critical/10':f.severity==='high'?'text-high bg-high/10':f.severity==='low'?'text-low bg-low/10':f.severity==='info'?'text-info bg-info/10':'text-medium bg-medium/10'}">${f.severity}</span>
            <span class="shrink-0 px-1 py-0.5 rounded text-[8px] font-mono text-gray-500 bg-base-700 uppercase">${esc(ft)}</span>
          </div>
          ${f.ai_description ? `<div class="text-[10px] text-amber-300/70 mt-0.5 italic line-clamp-2">${esc(f.ai_description)}</div>` : ''}
          <div class="text-[10px] text-gray-500 mt-0.5 truncate">${esc((f.description || '').substring(0, 150))}</div>
          <div class="flex items-center gap-2 mt-1">
            <span class="text-[9px] text-gray-600 font-mono">${esc(f.category || '')}</span>
            ${f.cwe_id ? `<span class="text-[9px] text-gray-700 font-mono">${esc(f.cwe_id)}</span>` : ''}
            ${f.evidence && f.evidence !== 'Connection failed' ? `<span class="text-[9px] text-primary/50 font-mono truncate max-w-[200px]">${esc(f.evidence.substring(0, 60))}</span>` : ''}
          </div>
        </div>
      </div>
    </div>`;
  }).join('');
}

// ── Finding detail ──
function showDetail(fid) {
  const f = S.findings.find(x => x.finding_id === fid);
  if (!f) return;

  D.detailPanel.classList.remove('hidden');
  D.detailContent.innerHTML = `
    <div>
      <span class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${f.severity==='critical'?'text-critical bg-critical/10 border border-critical/20':f.severity==='high'?'text-high bg-high/10 border border-high/20':f.severity==='low'?'text-low bg-low/10 border border-low/20':f.severity==='info'?'text-info bg-info/10 border border-info/20':'text-medium bg-medium/10 border border-medium/20'}">${f.severity}</span>
      <span class="ml-1.5 text-[10px] text-gray-600 font-mono uppercase">${esc(f.finding_type || 'osint')}</span>
    </div>
    <h3 class="text-sm font-semibold text-gray-200">${esc(f.title)}</h3>
    ${f.ai_description ? `<div class="text-[11px] text-amber-300/80 italic leading-relaxed p-2 bg-amber-500/5 rounded-lg border border-amber-500/10">${esc(f.ai_description)}</div>` : ''}
    <div class="space-y-2">
      <div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wide">Description</div><div class="text-[11px] text-gray-400 mt-0.5">${esc(f.description)}</div></div>
      <div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wide">Category</div><div class="text-[11px] text-gray-400 mt-0.5">${esc(f.category)}</div></div>
      ${f.cwe_id ? `<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wide">CWE</div><div class="text-[11px] text-gray-400 mt-0.5 font-mono">${esc(f.cwe_id)}</div></div>` : ''}
      ${f.evidence ? `<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wide">Evidence</div><pre class="mt-1 p-2 rounded-md bg-base-900 border border-white/5 text-[10px] text-gray-400 font-mono whitespace-pre-wrap max-h-40 overflow-y-auto">${esc(f.evidence)}</pre></div>` : ''}
      ${f.remediation ? `<div><div class="text-[10px] text-gray-600 font-semibold uppercase tracking-wide">Remediation</div><div class="text-[11px] text-green-400/70 mt-0.5">${esc(f.remediation)}</div></div>` : ''}
    </div>`;
}

function hideDetail() {
  D.detailPanel.classList.add('hidden');
}

// ── Modal ──
function setupModal() {
  $('#btn-new-profile')?.addEventListener('click', () => openModal());
  $('#btn-modal-cancel')?.addEventListener('click', closeModal);
  $('#btn-modal-save')?.addEventListener('click', saveProfile);
  $('#btn-close-detail')?.addEventListener('click', hideDetail);
}

function openModal(profile) {
  S.editingPid = profile?.profile_id || null;
  $('#modal-title').textContent = profile ? 'Edit OSINT Profile' : 'Add Domain for OSINT';
  $('#modal-name').value = profile?.name || '';
  $('#modal-desc').value = profile?.description || '';
  $('#modal-domain').value = profile?.target_domain || '';
  $('#modal-analysis').value = profile?.analysis_rounds || 5;
  const cats = typeof profile?.categories === 'string' ? JSON.parse(profile.categories || '[]') : (profile?.categories || []);
  document.querySelectorAll('.cat-check').forEach(cb => {
    cb.checked = cats.length === 0 || cats.includes(cb.value);
  });
  $('#modal-profile').classList.remove('hidden');
}

function closeModal() {
  $('#modal-profile').classList.add('hidden');
  S.editingPid = null;
}

async function saveProfile() {
  const name = $('#modal-name').value.trim();
  const domain = $('#modal-domain').value.trim();
  if (!name) { alert('Name is required'); return; }
  if (!domain && !S.editingPid) { alert('Target domain is required'); return; }
  const body = {
    name,
    description: $('#modal-desc').value.trim(),
    target_domain: domain,
    categories: [...document.querySelectorAll('.cat-check:checked')].map(c => c.value),
    analysis_rounds: parseInt($('#modal-analysis').value) || 5,
  };

  try {
    const url = S.editingPid ? A.profile(S.editingPid) : A.profiles();
    const method = S.editingPid ? 'PUT' : 'POST';
    await fetch(url, { method, headers: { ..._authHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    closeModal();
    loadProfiles();
    if (S.editingPid) selectProfile(S.editingPid);
  } catch (e) {
    console.error('Failed to save profile', e);
  }
}

function editActiveProfile() {
  if (S.activePid) editProfile(S.activePid);
}

function deleteActiveProfile() {
  if (S.activePid) deleteProfile(S.activePid);
}

async function editProfile(pid) {
  try {
    const r = await fetch(A.profile(pid), { headers: _authHeaders() });
    const p = await r.json();
    openModal(p);
  } catch (e) { console.error(e); }
}

async function deleteProfile(pid) {
  if (!confirm('Delete this domain profile and all its reports?')) return;
  try {
    await fetch(A.profile(pid), { method: 'DELETE', headers: _authHeaders() });
    S.activePid = null;
    S.activeRid = null;
    S.findings = [];
    loadProfiles();
    D.placeholder.classList.remove('hidden');
    D.dashboard.classList.add('hidden');
    D.dashCards.classList.add('hidden');
    D.dashIndicators.classList.add('hidden');
    hideDetail();
  } catch (e) { console.error(e); }
}

// ── Filters ──
function setupFilters() {
  $('#filter-severity')?.addEventListener('change', () => renderFindings(S.findings));
  $('#filter-source')?.addEventListener('change', () => renderFindings(S.findings));
  $('#filter-type')?.addEventListener('change', () => renderFindings(S.findings));
}

// ── Buttons ──
function setupButtons() {
  $('#btn-logout')?.addEventListener('click', logout);
}

// ── Auth helpers ──
function _authHeaders() {
  const t = localStorage.getItem('elyria_token');
  return t ? { 'Authorization': `Bearer ${t}` } : {};
}

document.addEventListener('DOMContentLoaded', init);
init();
