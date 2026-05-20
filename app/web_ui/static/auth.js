/* ═══════════════════════════════════════════════════════════════
   Elyria — auth.js
   Token stocke en sessionStorage.
   Navigation via window.location.href (reload complet).
   initAuth() verifie le token au chargement de chaque page.
   Toutes les requetes API passent par l'intercepteur fetch qui
   ajoute automatiquement le header Authorization: Bearer.
   ═══════════════════════════════════════════════════════════════ */

var SESSION_KEY = 'elyria_token';
var REFRESH_KEY = 'elyria_refresh_token';
var _token = null;
var _refreshToken = null;
var _user = null;
var _refreshing = false;
var _refreshCount = 0;
var AUTH_API = {
  login: '/api/user/login',
  register: '/api/user/create',
  logout: '/api/user/logout',
  refresh: '/api/user/refresh',
  verifyEmail: '/api/user/verify-email',
  resendCode: '/api/user/resend-code',
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
      if (response.status === 401 && !isLoginPage && _refreshToken && !_refreshing) {
        return trySilentRefresh().then(function (refreshed) {
          if (refreshed) {
            options = options || {};
            options.headers = Object.assign({}, options.headers, {
              Authorization: 'Bearer ' + _token
            });
            return originalFetch(url, options);
          }
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
      email: payload.email || payload.sub,
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
    el.textContent = user.email || user.userId || '';
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

// ═══════════════════════════════════════════
// Auth API (email-based, no client digest)
// ═══════════════════════════════════════════

async function loginUser(email, password) {
  var res = await fetch(AUTH_API.login, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: password }),
  });
  var data = await res.json().catch(function() { return {}; });
  if (!res.ok) {
    return { success: false, error: data.detail || 'Email ou mot de passe invalide.' };
  }
  _token = data.token;
  _refreshToken = data.refresh_token || '';
  _user = { userId: data.user_id, email: data.email };
  sessionStorage.setItem(SESSION_KEY, _token);
  if (_refreshToken) sessionStorage.setItem(REFRESH_KEY, _refreshToken);
  return {
    success: true,
    token: data.token,
    refresh_token: _refreshToken,
    user: _user,
    recovery_words: data.recovery_words || '',
  };
}

async function registerUser(email, password, confirmPassword) {
  var res = await fetch(AUTH_API.register, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: password, confirm_password: confirmPassword }),
  });
  var data = await res.json().catch(function() { return {}; });
  if (!res.ok) {
    return { success: false, error: data.detail || "Echec de l'inscription." };
  }
  return {
    success: true,
    userId: data.user_id,
    email: data.email,
    verification_token: data.verification_token,
    recovery_words: data.recovery_words || '',
  };
}

async function verifyEmailCode(token, code) {
  var res = await fetch(AUTH_API.verifyEmail, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token, code: code }),
  });
  var data = await res.json().catch(function() { return {}; });
  if (!res.ok) {
    return { success: false, error: data.detail || 'Code invalide.' };
  }
  return { success: true };
}

async function resendCode(token) {
  var headers = { 'Content-Type': 'application/json' };
  if (_token) headers['Authorization'] = 'Bearer ' + _token;
  var res = await fetch(AUTH_API.resendCode, {
    method: 'POST',
    headers: headers,
    body: JSON.stringify({ token: token }),
  });
  var data = await res.json().catch(function() { return {}; });
  if (!res.ok) {
    return { success: false, error: data.detail || 'Erreur.' };
  }
  return { success: true };
}

// ═══════════════════════════════════════════
// OIDC / SSO
// ═══════════════════════════════════════════

function initOidc() {
  var hash = window.location.hash;
  if (hash && (hash.startsWith('#token=') || hash.indexOf('token=') > -1)) {
    var raw = hash.substring(1);
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
    .catch(function () { /* OIDC not available */ });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initOidc);
} else {
  initOidc();
}

initAuth();
