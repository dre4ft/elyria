/* ═══════════════════════════════════════════════════════════════
   Elyria — auth.js
   Gestion du token d'authentification (variable JS uniquement).
   Transport entre pages via hash d'URL (#token=xxx) — le hash
   n'est jamais envoyé au serveur.
   ═══════════════════════════════════════════════════════════════ */

let _token = null;
let _user = null;

const AUTH_API = {
  login: '/api/user/login',
  register: '/api/user/create',
  logout: '/api/user/logout',
};

/**
 * Initialise l'auth au chargement de la page.
 * Vérifie la présence d'un token dans le hash et le consomme.
 * Redirige vers /login si pas de token et qu'on n'est pas déjà sur login.
 */
function initAuth() {
  const hash = window.location.hash;
  const tokenMatch = hash.match(/[#&]token=([^&]+)/);
  if (tokenMatch) {
    _token = decodeURIComponent(tokenMatch[1]);
    // Extraire les infos utilisateur du hash si présentes
    const uidMatch = hash.match(/[#&]uid=([^&]+)/);
    const unameMatch = hash.match(/[#&]uname=([^&]+)/);
    if (uidMatch) {
      _user = {
        userId: decodeURIComponent(uidMatch[1]),
        username: unameMatch ? decodeURIComponent(unameMatch[1]) : decodeURIComponent(uidMatch[1]),
      };
    } else {
      _user = parseUserFromToken(_token);
    }
    // Nettoyer le hash de l'URL sans recharger
    history.replaceState(null, '', window.location.pathname + window.location.search);
  }

  // Rediriger vers login si pas authentifié (sauf sur la page login)
  if (!_token && !window.location.pathname.endsWith('/login') && !window.location.pathname.endsWith('/login.html')) {
    window.location.href = '/login';
    return;
  }

  // Intercepter les liens internes pour transporter le token
  interceptLinks();
}

/**
 * Parse le payload JWT pour extraire les infos utilisateur (sans vérifier la signature).
 */
function parseUserFromToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    return {
      userId: payload.sub,
      username: payload.username || payload.sub,
      keyId: payload.kid,
    };
  } catch {
    return null;
  }
}

/**
 * Retourne le token actuel.
 */
function getToken() {
  return _token;
}

/**
 * Retourne les infos utilisateur décodées du token.
 */
function getUser() {
  return _user;
}

/**
 * Retourne le header Authorization pour les appels fetch.
 */
function getAuthHeader() {
  if (!_token) return {};
  return { 'Authorization': `Bearer ${_token}` };
}

/**
 * Vérifie si l'utilisateur est authentifié.
 */
function isAuthenticated() {
  return !!_token;
}

/**
 * Ajoute le token au hash d'une URL pour naviguer entre pages.
 */
function urlWithToken(url) {
  if (!_token) return url;
  let hash = `#token=${encodeURIComponent(_token)}`;
  if (_user) {
    hash += `&uid=${encodeURIComponent(_user.userId)}&uname=${encodeURIComponent(_user.username || _user.userId)}`;
  }
  const base = url.split('#')[0];
  return base + hash;
}

/**
 * Navigue vers une URL en transportant le token.
 */
function navigateWithToken(url) {
  window.location.href = urlWithToken(url);
}

/**
 * Déconnexion : appelle l'API logout puis redirige vers login.
 */
async function logout() {
  if (_token) {
    try {
      await fetch(AUTH_API.logout, {
        headers: getAuthHeader(),
      });
    } catch {}
  }
  _token = null;
  _user = null;
  window.location.href = '/login';
}

/**
 * Intercepte les clics sur les liens internes pour y ajouter le hash token.
 */
function interceptLinks() {
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href');
    if (!href || href.startsWith('http') || href.startsWith('//') || href.startsWith('#')) return;
    // Ne pas modifier les liens vers login
    if (href.startsWith('/login') || href.startsWith('login')) return;
    if (!_token) return;

    e.preventDefault();
    navigateWithToken(href);
  });
}

/**
 * Tente de se connecter via l'API.
 * Retourne { success, token?, user?, error? }
 */
async function loginUser(username, digest) {
  const res = await fetch(AUTH_API.login, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, digest }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    return { success: false, error: data.detail || 'Identifiants invalides' };
  }
  const data = await res.json();
  _token = data.token;
  _user = { userId: data.user_id, username: data.username };
  return { success: true, token: data.token, user: _user };
}

/**
 * Crée un compte utilisateur.
 * Retourne { success, error? }
 */
async function registerUser(username, digest, teams = []) {
  const res = await fetch(AUTH_API.register, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, digest, teams }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    return { success: false, error: data.detail || "Échec de l'inscription" };
  }
  return { success: true };
}
