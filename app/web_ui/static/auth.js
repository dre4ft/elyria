/* ═══════════════════════════════════════════════════════════════
   Elyria — auth.js
   Token stocké en sessionStorage.
   La navigation utilise window.location.href (reload complet).
   initAuth() vérifie le token au chargement de chaque page.
   Toutes les requêtes API passent par l'intercepteur fetch qui
   ajoute automatiquement le header Authorization: Bearer.
   ═══════════════════════════════════════════════════════════════ */

var SESSION_KEY = 'elyria_token';
var _token = null;
var _user = null;
var AUTH_API = {
  login: '/api/user/login',
  register: '/api/user/create',
  logout: '/api/user/logout',
};

function initAuth() {
  var isLoginPage = window.location.pathname.endsWith('/login') || window.location.pathname.endsWith('/login.html');

  _token = sessionStorage.getItem(SESSION_KEY);

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

  window.fetch = function (url, options) {
    if (!_token) return originalFetch(url, options);

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

    return originalFetch(url, options);
  };
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
  _user = null;
  sessionStorage.removeItem(SESSION_KEY);
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
  _user = { userId: data.user_id, username: data.username };
  sessionStorage.setItem(SESSION_KEY, _token);
  return { success: true, token: data.token, user: _user };
}

async function registerUser(username, digest, teams) {
  teams = teams || [];
  var res = await fetch(AUTH_API.register, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, digest: digest, teams: teams }),
  });
  if (!res.ok) {
    var data = await res.json().catch(function() { return {}; });
    return { success: false, error: data.detail || "Échec de l'inscription" };
  }
  return { success: true };
}

initAuth();
