// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Elyria
// GED — Gestion Electronique de Documents + Ely Skills

(function () {
  'use strict';

  var API = '/api/ged';
  var selectedFile = null;
  var activeDocId = null;
  var skillsActive = false;

  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  };

  // ═══════════════════════════════════════════
  // Init
  // ═══════════════════════════════════════════

  function init() {
    $('#btn-ged-upload').addEventListener('click', handleUploadClick);
    $('#btn-ged-save').addEventListener('click', uploadDocument);
    $('#ged-filter-type').addEventListener('change', reloadList);
    $('#ged-search').addEventListener('input', function () {
      clearTimeout(this._timer);
      this._timer = setTimeout(reloadList, 300);
    });
    setupDropZone();
    loadTypes();
    reloadList();
  }

  function reloadList() {
    if (skillsActive) { skillsLoad(); return; }
    loadDocuments();
  }

  // ═══════════════════════════════════════════
  // Document upload / list / view
  // ═══════════════════════════════════════════

  async function loadTypes() {
    try {
      var res = await fetch(API + '/types', { headers: getAuthHeader() });
      if (!res.ok) return;
      var types = await res.json();
      var labels = { openapi: 'OpenAPI', arazzo: 'Arazzo', markdown: 'Markdown', other: 'Autre' };
      ['ged-filter-type', 'ged-type'].forEach(function (selId) {
        var sel = $('#' + selId);
        if (!sel) return;
        var current = sel.value;
        sel.innerHTML = '<option value="">— Tous —</option>';
        types.forEach(function (t) {
          sel.innerHTML += '<option value="' + esc(t) + '"' + (t === current ? ' selected' : '') + '>' + (labels[t] || t) + '</option>';
        });
      });
    } catch (e) {
      console.error('[ged] loadTypes error:', e);
    }
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

  function handleUploadClick() {
    if (skillsActive) { showSkillEditor(); return; }
    openGedModal();
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
      var content = await new Promise(function (resolve, reject) {
        var reader = new FileReader();
        reader.onload = function () { resolve(reader.result); };
        reader.onerror = function () { reject(new Error('Lecture echouee')); };
        reader.readAsText(selectedFile);
      });
      var h = getAuthHeader();
      h['Content-Type'] = 'application/json';
      var res = await fetch(API + '/upload', {
        method: 'POST',
        headers: h,
        body: JSON.stringify({
          name: $('#ged-name').value.trim(),
          snippet: $('#ged-snippet').value.trim(),
          file_type: $('#ged-type').value,
          content: content
        })
      });
      if (res.ok) {
        showMsg('Document enregistre', 'success');
        closeGedModal();
        loadDocuments();
      } else {
        var err = await res.json().catch(function () { return {}; });
        showMsg(err.detail || "Erreur lors de l'upload", 'error');
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
          '</div>' +
          '<button class="ged-delete-btn shrink-0 w-5 h-5 rounded hover:bg-red-500/10 flex items-center justify-center text-gray-600 hover:text-red-400 transition-colors ml-1" title="Supprimer">' +
            '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>' +
          '</button>';
        row.addEventListener('click', function () { viewDocument(d); });
        row.querySelector('.ged-delete-btn').addEventListener('click', function (e) {
          e.stopPropagation();
          deleteGedDoc(d.doc_id);
        });
        list.appendChild(row);
      });
    } catch (e) {
      console.error('[ged] load error:', e);
    }
  }

  async function viewDocument(doc) {
    activeDocId = doc.doc_id;
    document.querySelectorAll('.ged-item').forEach(function (r) { r.classList.remove('active'); });
    var activeRow = document.querySelector('.ged-item[data-doc-id="' + doc.doc_id + '"]');
    if (activeRow) activeRow.classList.add('active');

    $('#ged-viewer-empty').classList.add('hidden');
    $('#ged-viewer').classList.remove('hidden');
    $('#ged-viewer-download').href = API + '/' + doc.doc_id + '/download';
    $('#ged-viewer-download').classList.remove('hidden');

    var content = $('#ged-viewer-content');
    content.innerHTML = '<div class="flex items-center justify-center h-48"><svg class="w-5 h-5 animate-spin text-gray-600" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-opacity=".25"/><path stroke-linecap="round" d="M12 2a10 10 0 019.95 8.9" opacity=".8"/></svg></div>';

    try {
      var res = await fetch(API + '/' + doc.doc_id, { headers: getAuthHeader() });
      if (!res.ok) { content.innerHTML = '<p class="text-red-400 text-sm p-8">Erreur de chargement</p>'; return; }
      var data = await res.json();
      var text = data.content || '';

      var fileType = data.file_type || doc.file_type;
      var typeBadge = $('#ged-viewer-type');
      typeBadge.textContent = fileType;
      typeBadge.className = 'ged-type-badge ' + ({
        openapi: 'ged-type-openapi', arazzo: 'ged-type-arazzo',
        markdown: 'ged-type-markdown', other: 'ged-type-other'
      }[fileType] || 'ged-type-other');
      $('#ged-viewer-name').textContent = data.filename || doc.name;
      $('#ged-viewer-snippet').classList.add('hidden');

      if (fileType === 'markdown') {
        var html = typeof marked !== 'undefined' ? marked.parse(text) : '<pre>' + esc(text) + '</pre>';
        content.innerHTML = html;
      } else if (fileType === 'openapi' || fileType === 'arazzo') {
        var formatted = text;
        try {
          var parsed = JSON.parse(text);
          formatted = JSON.stringify(parsed, null, 2);
        } catch (e) { /* YAML — display as-is */ }
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
    reloadList();
  };

  window.deleteGedDoc = async function (docId) {
    if (!confirm('Supprimer ce document ?')) return;
    try {
      await fetch(API + '/' + docId, { method: 'DELETE', headers: getAuthHeader() });
      if (activeDocId === docId) closeGedViewer();
      reloadList();
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

  // ═══════════════════════════════════════════
  // Skills mode
  // ═══════════════════════════════════════════

  function skillsLoad() {
    var list = $('#ged-list'), empty = $('#ged-empty');
    fetch('/api/ged?file_type=skill&limit=200', { headers: getAuthHeader() })
      .then(function (r) { return r.json(); })
      .then(function (docs) {
        list.querySelectorAll('.ged-item').forEach(function (el) { el.remove(); });
        if (!docs.length) { empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');
        docs.forEach(function (d) {
          var row = document.createElement('div');
          row.className = 'ged-item px-3 py-2.5 flex items-start gap-2.5';
          row.dataset.docId = d.doc_id;
          row.innerHTML =
            '<span class="ged-type-badge ged-type-markdown mt-0.5 shrink-0">skill</span>' +
            '<div class="flex-1 min-w-0"><div class="text-[11px] font-medium text-gray-200 truncate">' + esc(d.name) + '</div>' +
            (d.snippet ? '<div class="text-[9px] text-gray-500 truncate mt-0.5">' + esc(d.snippet) + '</div>' : '') + '</div>' +
            '<button class="sk-edit-btn shrink-0 w-5 h-5 rounded hover:bg-violet-500/10 flex items-center justify-center text-gray-600 hover:text-violet-400 transition-colors ml-1"><svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z"/></svg></button>' +
            '<button class="sk-del-btn shrink-0 w-5 h-5 rounded hover:bg-red-500/10 flex items-center justify-center text-gray-600 hover:text-red-400 transition-colors ml-1"><svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg></button>';
          row.querySelector('.sk-edit-btn').addEventListener('click', function (e) {
            e.stopPropagation();
            fetch('/api/ged/' + d.doc_id, { headers: getAuthHeader() }).then(function (r) { return r.json(); }).then(function (data) {
              showSkillEditor({ skill_id: d.doc_id, name: d.name, description: d.snippet || '', content: data.content });
            });
          });
          row.querySelector('.sk-del-btn').addEventListener('click', function (e) {
            e.stopPropagation();
            if (confirm('Supprimer ce skill ?')) {
              fetch('/api/skills/' + d.doc_id, { method: 'DELETE', headers: getAuthHeader() }).then(function () { skillsLoad(); });
            }
          });
          row.addEventListener('click', function () {
            activeDocId = d.doc_id;
            document.querySelectorAll('.ged-item').forEach(function (r) { r.classList.remove('active'); });
            row.classList.add('active');
            $('#ged-viewer-empty').classList.add('hidden');
            $('#ged-viewer').classList.remove('hidden');
            $('#ged-viewer-type').textContent = 'skill';
            $('#ged-viewer-type').className = 'ged-type-badge ged-type-markdown';
            $('#ged-viewer-name').textContent = d.name;
            $('#ged-viewer-snippet').classList.add('hidden');
            $('#ged-viewer-download').classList.add('hidden');
            fetch('/api/ged/' + d.doc_id, { headers: getAuthHeader() }).then(function (r) { return r.json(); }).then(function (data) {
              var skillContent = data.content || '';
              $('#ged-viewer-content').innerHTML =
                '<div class="mb-4 flex justify-between"><div><h1 class="text-lg font-bold text-white">' + esc(data.filename) + '</h1>' +
                '<p class="text-xs text-gray-500 mt-1">' + esc(d.snippet || '') + '</p></div>' +
                '<div class="flex gap-2"><button id="btn-skill-view-edit" class="h-8 px-3 rounded-lg bg-violet-500/10 hover:bg-violet-500/20 border border-violet-500/20 text-xs font-medium text-violet-400 hover:text-violet-300 transition-all flex items-center gap-1.5"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z"/></svg>Editer</button>' +
                '<button id="btn-skill-view-delete" class="h-8 px-3 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-xs font-medium text-red-400 hover:text-red-300 transition-all flex items-center gap-1.5"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>Supprimer</button></div></div>' +
                '<div id="skill-content-rendered" class="ged-markdown"></div>';
              document.getElementById('btn-skill-view-edit').addEventListener('click', function () {
                showSkillEditor({ skill_id: d.doc_id, name: d.name, description: d.snippet || '', content: skillContent });
              });
              document.getElementById('btn-skill-view-delete').addEventListener('click', function () {
                if (confirm('Supprimer ce skill ?')) {
                  fetch('/api/skills/' + d.doc_id, { method: 'DELETE', headers: getAuthHeader() }).then(function () {
                    document.getElementById('ged-viewer').classList.add('hidden');
                    document.getElementById('ged-viewer-empty').classList.remove('hidden');
                    skillsLoad();
                  });
                }
              });
              var rendered = document.getElementById('skill-content-rendered');
              if (rendered) {
                rendered.innerHTML = typeof marked !== 'undefined' ? marked.parse(skillContent) : '<pre>' + esc(skillContent) + '</pre>';
              }
            });
          });
          list.appendChild(row);
        });
      });
  }

  window.toggleSkillsFilter = function () {
    skillsActive = !skillsActive;
    var b = document.getElementById('btn-ged-skills');
    var f = document.getElementById('ged-filter-type');
    var l = document.getElementById('ged-sidebar-label');
    var u = document.getElementById('btn-ged-upload');
    if (skillsActive) {
      if (b) b.classList.add('bg-violet-500/20', 'border-violet-500/30');
      if (f) f.style.display = 'none';
      if (l) l.textContent = 'Skills';
      if (u) u.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>';
      if (u) u.title = 'Ajouter un skill';
      skillsLoad();
    } else {
      if (b) b.classList.remove('bg-violet-500/20', 'border-violet-500/30');
      if (f) f.style.display = '';
      if (l) l.textContent = 'Documents';
      if (u) u.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>';
      if (u) u.title = 'Ajouter un document';
      loadDocuments();
    }
  };

  function showSkillEditor(skill) {
    var m = document.getElementById('skill-modal');
    if (!m) return;
    document.getElementById('skill-modal-title').textContent = skill ? 'Editer ' + skill.name : 'Nouveau Skill';
    m.classList.remove('hidden'); m.classList.add('flex');
    document.getElementById('sk-editor-id').value = skill ? skill.skill_id : '';
    document.getElementById('sk-editor-name').value = skill ? skill.name : '';
    document.getElementById('sk-editor-desc').value = skill ? (skill.description || '') : '';
    document.getElementById('sk-editor-content').value = skill ? skill.content : '';
    var d = document.getElementById('btn-skill-delete');
    if (d) { d.classList.toggle('hidden', !skill); if (skill) d.setAttribute('data-sid', skill.skill_id); }
  }

  window._showSkillEditor = showSkillEditor;

  window.closeSkillModal = function () {
    var m = document.getElementById('skill-modal');
    if (m) { m.classList.add('hidden'); m.classList.remove('flex'); }
  };

  window.saveSkill = function () {
    var sid = document.getElementById('sk-editor-id').value.trim().toLowerCase().replace(/\s+/g, '-');
    var name = document.getElementById('sk-editor-name').value.trim() || sid;
    var desc = document.getElementById('sk-editor-desc').value.trim();
    var content = document.getElementById('sk-editor-content').value.trim();
    if (!sid || !content) { alert('Skill ID et contenu requis'); return; }
    fetch('/api/skills', { method: 'POST', headers: { 'Content-Type': 'application/json', ...getAuthHeader() }, body: JSON.stringify({ skill_id: sid, name: name, description: desc, content: content }) })
      .then(function (r) { if (r.ok) { closeSkillModal(); skillsLoad(); } });
  };

  window.deleteSkillFromEditor = function () {
    var d = document.getElementById('btn-skill-delete'), sid = d ? d.getAttribute('data-sid') : '';
    if (!sid || !confirm('Supprimer ?')) return;
    fetch('/api/skills/' + sid, { method: 'DELETE', headers: getAuthHeader() }).then(function (r) { if (r.ok) { closeSkillModal(); skillsLoad(); } });
  };

  // ═══════════════════════════════════════════
  // Boot
  // ═══════════════════════════════════════════

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
