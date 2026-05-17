/* ═══════════════════════════════════════════════════════════════
   Elyria — auth.js
   Token stocké en sessionStorage.
   La navigation utilise window.location.href (reload complet).
   initAuth() vérifie le token au chargement de chaque page.
   Toutes les requêtes API passent par l'intercepteur fetch qui
   ajoute automatiquement le header Authorization: Bearer.
   ═══════════════════════════════════════════════════════════════ */

var SESSION_KEY = 'elyria_token';
var REFRESH_KEY = 'elyria_refresh_token';
var _token = null;
var _refreshToken = null;
var _user = null;
var _refreshing = false;  // prevent concurrent refresh attempts
var _refreshCount = 0;
var AUTH_API = {
  login: '/api/user/login',
  register: '/api/user/create',
  logout: '/api/user/logout',
  refresh: '/api/user/refresh',
};

function initAuth() {
  var isLoginPage = window.location.pathname.endsWith('/login') || window.location.pathname.endsWith('/login.html');

  _token = sessionStorage.getItem(SESSION_KEY);
  _refreshToken = sessionStorage.getItem(REFRESH_KEY);

  if (_token) {
    _user = parseUserFromToken(_token);
  }

  if (!_token && !isLoginPage) {
    window.location.href = '/login';
    return;
  }

  if (_token && isLoginPage) {
    window.location.href = '/app';
    return;
  }

  setupFetchInterceptor();
}

function setupFetchInterceptor() {
  if (window.__fetchIntercepted) return;
  window.__fetchIntercepted = true;

  var originalFetch = window.fetch;
  var isLoginPage = window.location.pathname.endsWith('/login') || window.location.pathname.endsWith('/login.html');

  window.fetch = function (url, options) {
    // Build request — add auth header for same-origin requests
    if (_token) {
      var isSameOrigin = false;
      try {
        var resolved = new URL(url, window.location.origin);
        isSameOrigin = resolved.origin === window.location.origin;
      } catch (_e) {
        isSameOrigin = true;
      }
      if (isSameOrigin) {
        options = options || {};
        options.headers = Object.assign({}, options.headers, {
          Authorization: 'Bearer ' + _token
        });
      }
    }

    return originalFetch(url, options).then(function (response) {
      // 401 catcher — try silent refresh first, then logout
      if (response.status === 401 && !isLoginPage && _refreshToken && !_refreshing) {
        return trySilentRefresh().then(function (refreshed) {
          if (refreshed) {
            // Retry original request with new token
            options = options || {};
            options.headers = Object.assign({}, options.headers, {
              Authorization: 'Bearer ' + _token
            });
            return originalFetch(url, options);
          }
          // Refresh failed — force logout
          _token = null;
          _refreshToken = null;
          _user = null;
          sessionStorage.removeItem(SESSION_KEY);
          sessionStorage.removeItem(REFRESH_KEY);
          window.location.href = '/login';
          return response;
        });
      }
      if (response.status === 401 && !isLoginPage && !_refreshToken) {
        _token = null;
        _user = null;
        sessionStorage.removeItem(SESSION_KEY);
        window.location.href = '/login';
      }
      return response;
    });
  };
}

function trySilentRefresh() {
  _refreshing = true;
  return fetch(AUTH_API.refresh, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: _refreshToken }),
  }).then(function (r) {
    _refreshing = false;
    if (!r.ok) return false;
    return r.json().then(function (data) {
      _token = data.token;
      _refreshToken = data.refresh_token;
      _user = parseUserFromToken(_token);
      sessionStorage.setItem(SESSION_KEY, _token);
      sessionStorage.setItem(REFRESH_KEY, _refreshToken);
      _refreshCount++;
      return true;
    });
  }).catch(function () {
    _refreshing = false;
    return false;
  });
}

function parseUserFromToken(token) {
  try {
    var parts = token.split('.');
    if (parts.length !== 3) return null;
    var payload = JSON.parse(atob(parts[1]));
    return {
      userId: payload.sub,
      username: payload.username || payload.sub,
      keyId: payload.kid,
    };
  } catch (_e) {
    return null;
  }
}

function getToken() { return _token; }
function getUser() { return _user; }

function initHeaderUser() {
  var user = _user;
  var el = document.getElementById('header-username');
  var logoutBtn = document.getElementById('btn-logout');
  if (user && el) {
    el.textContent = user.username || user.userId || '';
    el.classList.remove('hidden');
  }
  if (logoutBtn) logoutBtn.addEventListener('click', logout);
}

function getAuthHeader() {
  if (!_token) return {};
  return { Authorization: 'Bearer ' + _token };
}

function isAuthenticated() { return !!_token; }

function navigateTo(path) {
  window.location.href = path;
}

async function logout() {
  if (_token) {
    try { await fetch(AUTH_API.logout); } catch (_e) {}
  }
  _token = null;
  _refreshToken = null;
  _user = null;
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(REFRESH_KEY);
  window.location.href = '/login';
}

async function loginUser(username, digest) {
  var res = await fetch(AUTH_API.login, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, digest: digest }),
  });
  if (!res.ok) {
    var data = await res.json().catch(function() { return {}; });
    return { success: false, error: data.detail || 'Identifiants invalides' };
  }
  var data = await res.json();
  _token = data.token;
  _refreshToken = data.refresh_token || '';
  _user = { userId: data.user_id, username: data.username };
  sessionStorage.setItem(SESSION_KEY, _token);
  if (_refreshToken) sessionStorage.setItem(REFRESH_KEY, _refreshToken);
  return { success: true, token: data.token, refresh_token: _refreshToken, user: _user };
}

async function registerUser(username, digest) {
  var res = await fetch(AUTH_API.register, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, digest: digest }),
  });
  if (!res.ok) {
    var data = await res.json().catch(function() { return {}; });
    return { success: false, error: data.detail || "Échec de l'inscription" };
  }
  return { success: true };
}

// ── OIDC / SSO ──

function initOidc() {
  // Handle OIDC callback: /app#token=xxx&refresh_token=yyy → store tokens
  var hash = window.location.hash;
  if (hash && (hash.startsWith('#token=') || hash.indexOf('token=') > -1)) {
    // Parse URL-encoded hash params
    var raw = hash.substring(1); // remove #
    var params = {};
    raw.split('&').forEach(function(p) {
      var parts = p.split('=');
      if (parts.length === 2) params[parts[0]] = decodeURIComponent(parts[1]);
    });
    if (params.token) {
      _token = params.token;
      _refreshToken = params.refresh_token || '';
      _user = parseUserFromToken(_token);
      sessionStorage.setItem(SESSION_KEY, _token);
      if (_refreshToken) sessionStorage.setItem(REFRESH_KEY, _refreshToken);
    }
    window.location.hash = '';
    window.location.reload();
    return;
  }

  // Fetch OIDC config and show SSO button if enabled
  fetch('/api/user/oidc/config')
    .then(function (r) { return r.json(); })
    .then(function (cfg) {
      if (cfg.enabled) {
        var section = document.getElementById('oidc-section');
        var label = document.getElementById('oidc-btn-label');
        var btn = document.getElementById('btn-oidc-login');
        if (section) section.classList.remove('hidden');
        if (label) label.textContent = cfg.button_label || 'Connexion SSO';
        if (btn) {
          btn.addEventListener('click', function () {
            window.location.href = '/api/user/oidc/login';
          });
        }
      }
    })
    .catch(function () { /* OIDC not available, hide button */ });
}

// initOidc handles both: SSO button on /login, and #token=xxx on /app callback
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initOidc);
} else {
  initOidc();
}

initAuth();
