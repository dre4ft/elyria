// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Elyria
// GED — Gestion Electronique de Documents

(function () {
  'use strict';

  var API = '/api/ged';
  var selectedFile = null;
  var activeDocId = null;

  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  };

  function init() {
    $('#btn-ged-upload').addEventListener('click', openGedModal);
    $('#btn-ged-save').addEventListener('click', uploadDocument);
    $('#ged-filter-type').addEventListener('change', loadDocuments);
    $('#ged-search').addEventListener('input', function () {
      clearTimeout(this._timer);
      this._timer = setTimeout(loadDocuments, 300);
    });
    setupDropZone();
    loadDocuments();
  }

  function setupDropZone() {
    var zone = $('#ged-drop-zone');
    var input = $('#ged-file-input');
    if (!zone || !input) return;
    zone.addEventListener('click', function () { input.click(); });
    input.addEventListener('change', function () {
      if (input.files && input.files[0]) setFile(input.files[0]);
    });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('border-violet-500/50'); });
    zone.addEventListener('dragleave', function () { zone.classList.remove('border-violet-500/50'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('border-violet-500/50');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
    });
  }

  function setFile(file) {
    selectedFile = file;
    $('#ged-drop-content').classList.add('hidden');
    $('#ged-file-selected').classList.remove('hidden');
    $('#ged-file-name').textContent = file.name;
    $('#ged-file-size').textContent = formatSize(file.size);
    if (!$('#ged-name').value) $('#ged-name').value = file.name.replace(/\.[^.]+$/, '');
    $('#btn-ged-save').disabled = false;
    var ext = file.name.split('.').pop().toLowerCase();
    var typeMap = { json: 'openapi', yaml: 'openapi', yml: 'openapi', md: 'markdown' };
    if (typeMap[ext]) $('#ged-type').value = typeMap[ext];
    $('#ged-msg').classList.add('hidden');
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function openGedModal() {
    $('#ged-modal').classList.remove('hidden');
    $('#ged-modal').classList.add('flex');
    selectedFile = null;
    $('#ged-file-input').value = '';
    $('#ged-drop-content').classList.remove('hidden');
    $('#ged-file-selected').classList.add('hidden');
    $('#ged-name').value = '';
    $('#ged-snippet').value = '';
    $('#ged-type').value = 'openapi';
    $('#ged-msg').classList.add('hidden');
    $('#btn-ged-save').disabled = true;
  }

  window.closeGedModal = function () {
    $('#ged-modal').classList.add('hidden');
    $('#ged-modal').classList.remove('flex');
  };

  async function uploadDocument() {
    if (!selectedFile) return;
    var btn = $('#btn-ged-save');
    btn.disabled = true;
    btn.innerHTML = '<svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-opacity=".25"/><path stroke-linecap="round" d="M12 2a10 10 0 019.95 8.9" opacity=".8"/></svg> Envoi...';
    try {
      var fd = new FormData();
      fd.append('file', selectedFile);
      fd.append('name', $('#ged-name').value.trim());
      fd.append('snippet', $('#ged-snippet').value.trim());
      fd.append('file_type', $('#ged-type').value);
      var res = await fetch(API + '/upload', { method: 'POST', headers: getAuthHeader(), body: fd });
      if (res.ok) {
        showMsg('Document enregistre', 'success');
        closeGedModal();
        loadDocuments();
      } else {
        var err = await res.json().catch(function () { return {}; });
        showMsg(err.detail || 'Erreur lors de l\'upload', 'error');
      }
    } catch (e) {
      showMsg('Erreur reseau: ' + e.message, 'error');
    }
    btn.disabled = false;
    btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg> Enregistrer';
  }

  function showMsg(msg, type) {
    var el = $('#ged-msg');
    el.classList.remove('hidden');
    el.className = 'mt-3 px-3 py-2 rounded-lg text-xs ' + (type === 'error' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20');
    el.textContent = msg;
  }

  async function loadDocuments() {
    var list = $('#ged-list');
    var empty = $('#ged-empty');
    var type = $('#ged-filter-type').value;
    var search = $('#ged-search').value.trim();
    var qs = '?limit=200';
    if (type) qs += '&file_type=' + type;
    if (search) qs += '&search=' + encodeURIComponent(search);
    try {
      var res = await fetch(API + qs, { headers: getAuthHeader() });
      if (!res.ok) return;
      var docs = await res.json();
      list.querySelectorAll('.ged-item').forEach(function (el) { el.remove(); });
      if (!docs.length) {
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      var typeClasses = {
        openapi: 'ged-type-openapi', arazzo: 'ged-type-arazzo', markdown: 'ged-type-markdown',
        other: 'ged-type-other'
      };
      docs.forEach(function (d) {
        var row = document.createElement('div');
        row.className = 'ged-item px-3 py-2.5 flex items-start gap-2.5';
        row.dataset.docId = d.doc_id;
        if (d.doc_id === activeDocId) row.classList.add('active');
        row.innerHTML =
          '<span class="ged-type-badge ' + (typeClasses[d.file_type] || 'ged-type-other') + ' mt-0.5 shrink-0">' + esc(d.file_type) + '</span>' +
          '<div class="flex-1 min-w-0">' +
            '<div class="text-[11px] font-medium text-gray-200 truncate">' + esc(d.name) + '</div>' +
            (d.snippet ? '<div class="text-[9px] text-gray-500 truncate mt-0.5">' + esc(d.snippet) + '</div>' : '') +
            '<div class="text-[8px] text-gray-600 mt-0.5">' + (d.created_at || '').substring(0, 10) + '</div>' +
          '</div>';
        row.addEventListener('click', function () { viewDocument(d); });
        list.appendChild(row);
      });
    } catch (e) {
      console.error('[ged] load error:', e);
    }
  }

  async function viewDocument(doc) {
    activeDocId = doc.doc_id;
    // Highlight active row
    document.querySelectorAll('.ged-item').forEach(function (el) { el.classList.remove('active'); });
    var activeRow = document.querySelector('.ged-item[data-doc-id]');
    var rows = document.querySelectorAll('.ged-item');
    // Find and highlight
    rows.forEach(function (r) { r.classList.remove('active'); });
    // We need to set data-doc-id on rows. Let's just re-render.
    loadDocuments();

    // Show viewer
    $('#ged-viewer-empty').classList.add('hidden');
    $('#ged-viewer').classList.remove('hidden');
    var typeBadge = $('#ged-viewer-type');
    typeBadge.textContent = doc.file_type;
    typeBadge.className = 'ged-type-badge ' + ({
      openapi: 'ged-type-openapi', arazzo: 'ged-type-arazzo',
      markdown: 'ged-type-markdown', other: 'ged-type-other'
    }[doc.file_type] || 'ged-type-other');
    $('#ged-viewer-name').textContent = doc.name;
    var snippetEl = $('#ged-viewer-snippet');
    if (doc.snippet) { snippetEl.textContent = doc.snippet; snippetEl.classList.remove('hidden'); }
    else { snippetEl.classList.add('hidden'); }
    $('#ged-viewer-download').href = API + '/' + doc.doc_id + '/download';

    var content = $('#ged-viewer-content');
    content.innerHTML = '<div class="flex items-center justify-center h-48"><svg class="w-5 h-5 animate-spin text-gray-600" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-opacity=".25"/><path stroke-linecap="round" d="M12 2a10 10 0 019.95 8.9" opacity=".8"/></svg></div>';

    try {
      var res = await fetch(API + '/' + doc.doc_id + '/download', { headers: getAuthHeader() });
      if (!res.ok) { content.innerHTML = '<p class="text-red-400 text-sm p-8">Erreur de chargement</p>'; return; }
      var text = await res.text();

      if (doc.file_type === 'markdown') {
        var html = typeof marked !== 'undefined' ? marked.parse(text) : '<pre>' + esc(text) + '</pre>';
        content.innerHTML = html;
      } else if (doc.file_type === 'openapi' || doc.file_type === 'arazzo') {
        var formatted = text;
        try {
          var parsed = JSON.parse(text);
          formatted = JSON.stringify(parsed, null, 2);
        } catch (e) {
          // YAML or plain text — display as-is
        }
        content.innerHTML = '<pre>' + esc(formatted) + '</pre>';
      } else {
        content.innerHTML = '<pre>' + esc(text) + '</pre>';
      }
    } catch (e) {
      content.innerHTML = '<p class="text-red-400 text-sm p-8">Erreur: ' + esc(e.message) + '</p>';
    }
  }

  window.closeGedViewer = function () {
    activeDocId = null;
    $('#ged-viewer-empty').classList.remove('hidden');
    $('#ged-viewer').classList.add('hidden');
    loadDocuments();
  };

  window.deleteGedDoc = async function (docId) {
    if (!confirm('Supprimer ce document ?')) return;
    try {
      await fetch(API + '/' + docId, { method: 'DELETE', headers: getAuthHeader() });
      if (activeDocId === docId) closeGedViewer();
      loadDocuments();
    } catch (e) {
      console.error('[ged] delete error:', e);
    }
  };

  // GED picker modal for other pages
  window.openGedPicker = function (onSelect) {
    var modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-base-900/80 backdrop-blur-sm z-[200] flex items-center justify-center';
    modal.innerHTML =
      '<div class="bg-base-800 border border-white/5 rounded-xl p-6 w-[500px] max-h-[70vh] flex flex-col shadow-2xl">' +
        '<div class="flex items-center justify-between mb-4 shrink-0">' +
          '<h3 class="text-sm font-semibold text-white">Selectionner un document</h3>' +
          '<button class="w-6 h-6 rounded-md hover:bg-white/5 flex items-center justify-center text-gray-500 hover:text-gray-300" onclick="this.closest(\'.fixed\').remove()">' +
            '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>' +
          '</button>' +
        '</div>' +
        '<div id="ged-picker-list" class="flex-1 overflow-y-auto space-y-1 scrollbar-thin"></div>' +
      '</div>';
    document.body.appendChild(modal);
    fetch(API + '?limit=200', { headers: getAuthHeader() })
      .then(function (r) { return r.json(); })
      .then(function (docs) {
        var list = modal.querySelector('#ged-picker-list');
        if (!docs.length) { list.innerHTML = '<p class="text-xs text-gray-600 text-center py-8">Aucun document dans la GED</p>'; return; }
        docs.forEach(function (d) {
          var row = document.createElement('div');
          row.className = 'px-3 py-2 rounded-lg hover:bg-white/5 cursor-pointer flex items-center gap-3 text-xs transition-all';
          row.innerHTML =
            '<span class="text-[10px] text-violet-400 font-mono uppercase w-16 shrink-0">' + esc(d.file_type) + '</span>' +
            '<span class="flex-1 text-gray-300 truncate">' + esc(d.name) + '</span>' +
            (d.snippet ? '<span class="text-[10px] text-gray-500 truncate max-w-[180px] shrink-0">' + esc(d.snippet) + '</span>' : '');
          row.addEventListener('click', function () { onSelect(d); modal.remove(); });
          list.appendChild(row);
        });
      });
    modal.addEventListener('click', function (e) { if (e.target === modal) modal.remove(); });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
