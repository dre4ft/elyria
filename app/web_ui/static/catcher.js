/* Catcher — Burp-like proxy interceptor */

const Catcher = {
  _interceptOn: false,
  _pollTimer: null,
  _lastPendingIds: '',
  _pending: [],
  _history: [],

  init() {
    const btnToggle = document.getElementById('btn-toggle-catcher');
    const btnClose = document.getElementById('btn-catcher-close');
    if (btnToggle) btnToggle.addEventListener('click', () => this.togglePanel());
    if (btnClose) btnClose.addEventListener('click', () => this.togglePanel(false));

    const btnIntercept = document.getElementById('btn-catcher-toggle');
    if (btnIntercept) btnIntercept.addEventListener('click', () => this.toggleIntercept());

    const btnDropAll = document.getElementById('btn-catcher-drop-all');
    if (btnDropAll) btnDropAll.addEventListener('click', () => this.dropAll());

    const btnClear = document.getElementById('btn-catcher-clear-history');
    if (btnClear) btnClear.addEventListener('click', () => this.clearHistory());

    // Fetch initial status
    this._fetchStatus();
  },

  togglePanel(show) {
    const panel = document.getElementById('catcher-panel');
    if (!panel) return;
    const open = typeof show === 'boolean' ? show : panel.classList.contains('hidden');
    panel.classList.toggle('hidden', !open);
    panel.classList.toggle('flex', open);
    if (open) { this._startPolling(); this._fetchStatus(); }
    else this._stopPolling();
  },

  async toggleIntercept() {
    const res = await fetch('/api/catcher/toggle', { method: 'POST', headers: { ...getAuthHeader() } });
    if (!res.ok) return;
    const data = await res.json();
    this._interceptOn = data.intercept_enabled;
    this._proxyPort = data.proxy_port;
    this._updateInterceptBtn();
    // Reset pending rendering to force refresh on toggle
    this._lastPendingIds = '';
    this._lastPendingIds = '';
    this._pollTick();
  },

  _updateInterceptBtn() {
    const btn = document.getElementById('btn-catcher-toggle');
    const addr = document.getElementById('catcher-proxy-addr');
    if (!btn) return;
    if (this._interceptOn) {
      btn.className = 'h-7 px-2.5 rounded-md text-[10px] font-semibold transition-all bg-pink-500/15 text-pink-400 border border-pink-500/20 hover:bg-pink-500/25';
      btn.textContent = 'Intercept ON';
      if (addr) { addr.textContent = 'Proxy: localhost:' + (this._proxyPort || 6767); addr.classList.remove('hidden'); }
    } else {
      btn.className = 'h-7 px-2.5 rounded-md text-[10px] font-semibold transition-all bg-base-700 text-gray-500 border border-white/5 hover:bg-white/5';
      btn.textContent = 'Intercept OFF';
      if (addr) addr.classList.add('hidden');
    }
  },

  async _fetchStatus() {
    try {
      const res = await fetch('/api/catcher/status', { headers: { ...getAuthHeader() } });
      if (!res.ok) return;
      const data = await res.json();
      const wasOn = this._interceptOn;
      this._interceptOn = data.intercept_enabled;
      this._proxyPort = data.proxy_port;
      this._updateInterceptBtn();
      // Restart polling if intercept was off but server says it's on
      if (!wasOn && this._interceptOn) {
        this._lastPendingIds = '';
        this._pollTick();
      }
    } catch {}
  },

  // ── Variable polling ──
  _pollFast: 500,      // intercept ON + pending requests
  _pollNormal: 1500,   // intercept ON, idle start
  _pollIdleStep: 1500, // increment per idle tick
  _pollMax: 10000,     // cap when idle
  _idleCount: 0,

  _startPolling() {
    this._stopPolling();
    this._pollTick();
  },

  _stopPolling() {
    if (this._pollTimer) { clearTimeout(this._pollTimer); this._pollTimer = null; }
  },

  _scheduleNextPoll() {
    if (!this._interceptOn) return;
    if (this._pollTimer) clearTimeout(this._pollTimer);
    const hasPending = this._pending && this._pending.length > 0;
    const delay = hasPending ? this._pollFast
      : Math.min(this._pollNormal + this._idleCount * this._pollIdleStep, this._pollMax);
    this._pollTimer = setTimeout(() => this._pollTick(), delay);
  },

  async _pollTick() {
    try {
      if (this._interceptOn) {
        const [pendingRes, historyRes] = await Promise.all([
          fetch('/api/catcher/pending', { headers: { ...getAuthHeader() } }),
          fetch('/api/catcher/history?limit=100', { headers: { ...getAuthHeader() } }),
        ]);
        if (pendingRes.ok) {
          this._pending = await pendingRes.json();
          this._renderPending();
          this._idleCount = this._pending.length > 0 ? 0 : this._idleCount + 1;
        }
        if (historyRes.ok) { this._history = await historyRes.json(); this._renderHistory(); }
      } else {
        const historyRes = await fetch('/api/catcher/history?limit=100', { headers: { ...getAuthHeader() } });
        if (historyRes.ok) { this._history = await historyRes.json(); this._renderHistory(); }
        this._pending = []; this._renderPending();
      }
    } catch (e) {
      console.error('[catcher] poll error:', e);
    }
    this._scheduleNextPoll();
  },

  // ── Pending queue ──
  _renderPending() {
    const list = document.getElementById('catcher-pending-list');
    // Wire JSON editors after render
    setTimeout(() => this._setupCatcherJsonEditors(), 50);
    const empty = document.getElementById('catcher-pending-empty');
    const badge = document.getElementById('catcher-pending-badge');
    if (!list) return;

    const pending = this._pending || [];
    if (badge) {
      badge.textContent = pending.length;
      badge.classList.toggle('hidden', pending.length === 0);
    }

    // Skip re-render if queue hasn't changed (avoids overwriting user edits)
    const newIds = pending.map(r => r.id).join(',');
    if (newIds === this._lastPendingIds && pending.length > 0) return;
    this._lastPendingIds = newIds;

    if (pending.length === 0) {
      list.innerHTML = '';
      if (empty) empty.style.display = '';
      this._lastPendingIds = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    // First request: expanded. Others: compact summary.
    list.innerHTML = pending.map((r, i) => {
      const isFirst = i === 0;
      const methodColor = {GET:'text-green-400',POST:'text-blue-400',PUT:'text-orange-400',DELETE:'text-red-400',PATCH:'text-purple-400'}[r.method]||'text-gray-400';
      const headersStr = typeof r.headers === 'string' ? r.headers : JSON.stringify(r.headers||{}, null, 2);
      const bodyStr = r.body || '';
      const rid = 'pending-' + r.id;

      if (isFirst) {
        return `<div class="catcher-pending-item border-b border-pink-500/10 bg-pink-500/[0.02]">
          <div class="flex items-center justify-between px-3 pt-3 pb-1">
            <span class="text-[10px] uppercase tracking-widest text-pink-400 font-semibold">Requete en cours d'analyse</span>
            <div class="flex items-center gap-1.5">
              <button class="h-6 px-3 rounded text-[10px] font-semibold bg-green-500/15 text-green-400 border border-green-500/20 hover:bg-green-500/25 transition-all" onclick="Catcher.forward('${r.id}')">Forward</button>
              <button class="h-6 px-3 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/10 hover:bg-red-500/20 transition-all" onclick="Catcher.drop('${r.id}')">Drop</button>
              <button class="h-6 px-2.5 rounded text-[10px] text-gray-500 hover:text-gray-300 border border-transparent hover:bg-white/5 transition-all" onclick="Catcher.loadInBuilder('${r.id}')">Load</button>
            </div>
          </div>
          <div class="px-3 pb-3 space-y-2">
            <div class="flex items-center gap-2">
              <select id="${rid}-method" class="h-7 px-2 rounded bg-base-700 border border-white/8 text-[11px] font-bold ${methodColor} focus:outline-none focus:border-pink-500/40" onchange="Catcher._editField('${r.id}','method',this.value)">
                ${['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(m => `<option value="${m}" ${r.method===m?'selected':''}>${m}</option>`).join('')}
              </select>
              <input id="${rid}-url" class="flex-1 h-7 px-2 rounded bg-base-700 border border-white/8 text-[11px] font-mono text-gray-200 focus:outline-none focus:border-pink-500/40" value="${this._escAttr(r.url||'')}" onchange="Catcher._editField('${r.id}','url',this.value)" />
            </div>
            <div>
              <div class="text-[9px] uppercase text-gray-500 font-semibold mb-1">Headers</div>
              <div class="json-editor">
                <div class="json-editor-toolbar">
                  <span class="json-editor-status catcher-json-status" data-json-status="${rid}-headers"></span>
                  <button class="json-editor-fmt" data-json-fmt="${rid}-headers" title="Formatter (Ctrl+Shift+F)">{ }</button>
                </div>
                <textarea id="${rid}-headers" class="json-editor-textarea w-full h-24 p-2 rounded text-[10px] text-gray-300 resize-none focus:outline-none focus:border-pink-500/40" onchange="Catcher._editField('${r.id}','headers',this.value)" oninput="Catcher._validateJsonField('${rid}-headers')" spellcheck="false">${this._esc(headersStr)}</textarea>
              </div>
            </div>
            <div>
              <div class="text-[9px] uppercase text-gray-500 font-semibold mb-1">Body</div>
              <div class="json-editor">
                <div class="json-editor-toolbar">
                  <span class="json-editor-status catcher-json-status" data-json-status="${rid}-body"></span>
                  <button class="json-editor-fmt" data-json-fmt="${rid}-body" title="Formatter (Ctrl+Shift+F)">{ }</button>
                </div>
                <textarea id="${rid}-body" class="json-editor-textarea w-full h-32 p-2 rounded text-[10px] text-gray-300 resize-none focus:outline-none focus:border-pink-500/40" onchange="Catcher._editField('${r.id}','body',this.value)" oninput="Catcher._validateJsonField('${rid}-body')" spellcheck="false">${this._esc(bodyStr)}</textarea>
              </div>
            </div>
          </div>
        </div>`;
      }

      // Compact row for subsequent requests
      const urlShort = (r.url || '').replace(/^https?:\/\/[^/]+/, '') || '/';
      return `<div class="catcher-pending-item border-b border-white/5 px-3 py-2 flex items-center gap-2">
        <span class="${methodColor} text-[11px] font-bold font-mono w-12 flex-shrink-0">${this._esc(r.method)}</span>
        <span class="text-[11px] text-gray-400 font-mono truncate flex-1" title="${this._esc(r.url)}">${this._esc(urlShort)}</span>
        <button class="h-6 px-2 rounded text-[10px] font-semibold bg-green-500/15 text-green-400 border border-green-500/20 hover:bg-green-500/25 transition-all flex-shrink-0" onclick="Catcher.forward('${r.id}')">Forward</button>
        <button class="h-6 px-2 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/10 hover:bg-red-500/20 transition-all flex-shrink-0" onclick="Catcher.drop('${r.id}')">Drop</button>
      </div>`;
    }).join('');
  },

  async forward(id) {
    const res = await fetch(`/api/catcher/pending/${id}/forward`, { method: 'POST', headers: { ...getAuthHeader() } });
    if (res.ok) this._pollTick();
  },

  async drop(id) {
    const res = await fetch(`/api/catcher/pending/${id}/drop`, { method: 'POST', headers: { ...getAuthHeader() } });
    if (res.ok) this._pollTick();
  },

  async dropAll() {
    await fetch('/api/catcher/pending/drop-all', { method: 'POST', headers: { ...getAuthHeader() } });
    this._pollTick();
  },

  async clearHistory() {
    if (!confirm('Effacer tout l\'historique du Catcher ?')) return;
    await fetch('/api/catcher/history', { method: 'DELETE', headers: { ...getAuthHeader() } });
    this._pollTick();
  },

  loadInBuilder(id) {
    const entry = (this._pending || []).find(r => r.id === id) || (this._history || []).find(r => r.id === id);
    if (!entry) return;
    // Set request builder fields
    const methodEl = document.getElementById('req-method');
    const urlEl = document.getElementById('req-url');
    const bodyEl = document.getElementById('req-body');
    if (methodEl) methodEl.value = entry.method || 'GET';
    if (urlEl) urlEl.value = entry.url || '';
    if (bodyEl) bodyEl.value = entry.body || '';

    // Clear existing headers and load from entry
    if (typeof clearHeaders === 'function') clearHeaders();
    let headers = entry.headers || {};
    if (typeof headers === 'string') { try { headers = JSON.parse(headers); } catch {} }
    if (typeof addHeaderRow === 'function') {
      const entries = Object.entries(headers);
      if (entries.length === 0) addHeaderRow('', '', true);
      else entries.forEach(([k, v]) => addHeaderRow(k, v, true));
    }
    if (typeof syncContentTypeHeader === 'function') syncContentTypeHeader();

    // Switch to structured tab
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');
    tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === 'structured'));
    tabPanels.forEach(p => { p.classList.toggle('hidden', p.id !== 'tab-structured'); p.classList.toggle('active', p.id === 'tab-structured'); });
  },

  // ── History ──
  _renderHistory() {
    const list = document.getElementById('catcher-history-list');
    const empty = document.getElementById('catcher-history-empty');
    const count = document.getElementById('catcher-history-count');
    if (!list) return;

    const history = this._history || [];
    if (count) count.textContent = history.length + ' requetes';

    if (history.length === 0) {
      list.classList.add('hidden');
      if (empty) empty.style.display = '';
      return;
    }
    list.classList.remove('hidden');
    if (empty) empty.style.display = 'none';

    list.innerHTML = history.map(r => {
      const methodColor = {GET:'text-green-400',POST:'text-blue-400',PUT:'text-orange-400',DELETE:'text-red-400',PATCH:'text-purple-400'}[r.method]||'text-gray-400';
      const sc = r.status_code || 0;
      const scColor = sc >= 500 ? 'text-red-400' : sc >= 400 ? 'text-orange-400' : sc >= 200 ? 'text-green-400' : 'text-gray-500';
      const urlShort = (r.url || '').replace(/^https?:\/\/[^/]+/, '') || '/';
      return `<div class="catcher-history-item rounded-lg hover:bg-white/[0.02] border border-transparent hover:border-white/5 p-2 mb-0.5 transition-all">
        <div class="flex items-center gap-2.5 text-[11px] cursor-pointer" onclick="Catcher._toggleHistoryDetail(this.parentElement, '${r.id}')">
          <span class="${methodColor} font-bold font-mono w-10 flex-shrink-0">${this._esc(r.method)}</span>
          <span class="${scColor} font-bold font-mono w-7 flex-shrink-0">${sc || '—'}</span>
          <span class="text-gray-400 font-mono truncate flex-1 text-[10px]" title="${this._esc(r.url)}">${this._esc(urlShort)}</span>
          <button class="w-5 h-5 rounded hover:bg-pink-500/10 flex items-center justify-center text-gray-600 hover:text-pink-400 transition-colors flex-shrink-0" onclick="event.stopPropagation();Catcher.loadInBuilder('${r.id}')" title="Charger dans le builder">
            <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>
          </button>
        </div>
        <div class="hidden catcher-history-detail mt-2 pl-12 pr-2 pb-2 text-[10px] font-mono">
          <div class="text-gray-500 mb-1">Response body:</div>
          <pre class="text-gray-400 max-h-20 overflow-y-auto bg-base-900/40 p-1.5 rounded">${this._esc((r.response_body||'').substring(0, 500))}</pre>
        </div>
      </div>`;
    }).join('');
  },

  _toggleHistoryDetail(el, id) {
    const detail = el.querySelector('.catcher-history-detail');
    if (!detail) return;
    detail.classList.toggle('hidden');
  },

  _esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  },

  _escAttr(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },

  async _editField(id, field, value) {
    try {
      await fetch(`/api/catcher/pending/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
        body: JSON.stringify({ [field]: field === 'headers' ? value : value }),
      });
    } catch {}
  },

  // ── JSON editor helpers for catcher textareas ──

  _catcherAutoPairKeys: { '{': '}', '[': ']', '(': ')', '"': '"', "'": "'" },

  _setupCatcherJsonEditors() {
    document.querySelectorAll('.json-editor-fmt[data-json-fmt]').forEach(btn => {
      if (btn._catcherWired) return;
      btn._catcherWired = true;
      btn.addEventListener('click', () => {
        const targetId = btn.dataset.jsonFmt;
        const textarea = document.getElementById(targetId);
        if (!textarea) return;
        try {
          const parsed = JSON.parse(textarea.value);
          textarea.value = JSON.stringify(parsed, null, 2);
          textarea.dispatchEvent(new Event('change', { bubbles: true }));
          this._updateCatcherJsonStatus(targetId, 'ok');
        } catch {
          this._updateCatcherJsonStatus(targetId, 'err');
        }
      });
    });

    // Auto-pair brackets & quotes on catcher JSON textareas
    document.querySelectorAll('.json-editor-textarea').forEach(textarea => {
      if (textarea._catcherAutoWired) return;
      textarea._catcherAutoWired = true;
      textarea.addEventListener('keydown', (e) => {
        const pair = this._catcherAutoPairKeys[e.key];
        if (!pair) return;
        e.preventDefault();
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const val = textarea.value;
        const hasSelection = start !== end;

        if (hasSelection) {
          const wrapped = e.key + val.substring(start, end) + pair;
          textarea.setRangeText(wrapped, start, end, 'select');
          textarea.selectionStart = start + 1;
          textarea.selectionEnd = start + wrapped.length - 1;
        } else if (e.key === pair) {
          if (val.charAt(start) === pair) {
            textarea.selectionStart = textarea.selectionEnd = start + 1;
            return;
          }
          textarea.setRangeText(e.key + pair, start, start, 'end');
          textarea.selectionStart = textarea.selectionEnd = start + 1;
        } else {
          textarea.setRangeText(e.key + pair, start, start, 'end');
          textarea.selectionStart = textarea.selectionEnd = start + 1;
        }
        textarea.dispatchEvent(new Event('input', { bubbles: true }));
      });
    });
  },

  _validateJsonField(textareaId) {
    const textarea = document.getElementById(textareaId);
    if (!textarea) return;
    const val = textarea.value.trim();
    if (!val) { this._updateCatcherJsonStatus(textareaId, 'empty'); return; }
    try { JSON.parse(val); this._updateCatcherJsonStatus(textareaId, 'ok'); } catch { this._updateCatcherJsonStatus(textareaId, 'err'); }
  },

  _updateCatcherJsonStatus(targetId, state) {
    const status = document.querySelector(`[data-json-status="${targetId}"]`);
    if (!status) return;
    status.className = 'json-editor-status catcher-json-status';
    if (state === 'ok') { status.textContent = '✓'; status.classList.add('ok'); }
    else if (state === 'err') { status.textContent = '✗'; status.classList.add('err'); }
    else { status.textContent = ''; }
  },
};

// Init when DOM ready
document.addEventListener('DOMContentLoaded', () => Catcher.init());
