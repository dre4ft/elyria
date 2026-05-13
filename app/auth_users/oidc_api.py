"""
OIDC / SSO Connector — modular, provider-agnostic.
Supports any standard OIDC provider (Google, Azure AD, Keycloak, Authentik…).

Configuration via app_config (DB or admin API):
  oidc.enabled           — "1" to enable
  oidc.provider_name     — slug for provider (used in DB, e.g. "google", "azure")
  oidc.issuer            — OIDC discovery URL (https://accounts.google.com)
  oidc.client_id         — client ID
  oidc.client_secret     — client secret
  oidc.scope             — default "openid profile email"
  oidc.button_label      — label on login page, e.g. "Google", "Microsoft"
"""

import json
import secrets
import time
import uuid

import jwt
from authlib.integrations.requests_client import OAuth2Session
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, JSONResponse
from database.app_config import get as cfg, get_int
from database import user_mgmt

app = APIRouter(prefix="/api/user/oidc")

# ── Session store (in-memory) — maps state → nonce ──
_sessions: dict[str, dict] = {}


def _oidc_config() -> dict | None:
    """Load OIDC configuration. Returns None if not enabled."""
    if not get_int("oidc.enabled"):
        return None
    issuer = cfg("oidc.issuer")
    client_id = cfg("oidc.client_id")
    if not issuer or not client_id:
        return None
    return {
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": cfg("oidc.client_secret"),
        "scope": cfg("oidc.scope", "openid profile email"),
        "provider_name": cfg("oidc.provider_name", "oidc"),
        "button_label": cfg("oidc.button_label", "Connexion SSO"),
    }


def _discover(issuer: str) -> dict:
    """Discover OIDC provider metadata. Results are cached in memory."""
    if not hasattr(_discover, "_cache"):
        _discover._cache = {}
    if issuer in _discover._cache:
        return _discover._cache[issuer]
    import requests
    well_known = issuer.rstrip("/") + "/.well-known/openid-configuration"
    resp = requests.get(well_known, timeout=10)
    resp.raise_for_status()
    meta = resp.json()
    _discover._cache[issuer] = meta
    return meta


def _build_jwt(user: dict, expires_in: int = 3600) -> str:
    """Create an Elyria HS512 session JWT from a user dict."""
    key_id = str(uuid.uuid4())
    secret_key = secrets.token_bytes(64).hex()
    user_mgmt.add_key(key_id, secret_key, user.get("user_id"))
    payload = {
        "kid": key_id,
        "sub": user["user_id"],
        "username": user.get("username", ""),
        "iat": int(time.time()),
        "exp": time.time() + expires_in,
    }
    return jwt.encode(payload, secret_key, algorithm="HS512")


# ═══════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════

@app.get("/config")
def get_oidc_config():
    """Return OIDC configuration for the frontend (safe, no secrets)."""
    oidc = _oidc_config()
    if not oidc:
        return JSONResponse({"enabled": False})
    return {
        "enabled": True,
        "provider_name": oidc["provider_name"],
        "button_label": oidc["button_label"],
    }


def _redirect_uri(request: Request) -> str:
    """Build the OIDC callback URL from the request."""
    scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    host = request.headers.get("X-Forwarded-Host", request.headers.get("Host", request.base_url.netloc))
    return f"{scheme}://{host}/api/user/oidc/callback"


@app.get("/login")
def oidc_login(request: Request):
    """Initiate OIDC login — redirect to provider."""
    oidc = _oidc_config()
    if not oidc:
        return JSONResponse({"error": "OIDC not configured"}, status_code=400)

    meta = _discover(oidc["issuer"])
    redirect_uri = _redirect_uri(request)

    session = OAuth2Session(
        oidc["client_id"],
        oidc["client_secret"],
        scope=oidc["scope"],
        redirect_uri=redirect_uri,
    )
    authorization_url, state = session.create_authorization_url(
        meta["authorization_endpoint"]
    )
    _sessions[state] = {"nonce": secrets.token_hex(16), "created": time.time()}
    return RedirectResponse(authorization_url)


@app.get("/callback", name="oidc_callback")
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """OIDC callback — exchange code, validate id_token, issue Elyria JWT."""
    if error:
        return RedirectResponse(f"/login?error={error}")

    oidc = _oidc_config()
    if not oidc or not code or not state:
        return RedirectResponse("/login?error=invalid_request")

    session_data = _sessions.pop(state, None)
    if not session_data:
        return RedirectResponse("/login?error=invalid_state")

    try:
        meta = _discover(oidc["issuer"])
        redirect_uri = _redirect_uri(request)

        session = OAuth2Session(
            oidc["client_id"],
            oidc["client_secret"],
            scope=oidc["scope"],
            redirect_uri=redirect_uri,
        )
        token = session.fetch_token(
            meta["token_endpoint"],
            authorization_response=str(request.url),
            code=code,
        )

        # Validate id_token — fetch JWKS from provider
        import requests as http_requests
        jwks_uri = meta.get("jwks_uri")
        if jwks_uri:
            jwks_client = jwt.PyJWKClient(jwks_uri, cache_keys=True)
            signing_key = jwks_client.get_signing_key_from_jwt(token.get("id_token", ""))
        else:
            signing_key = oidc["client_secret"]

        claims = jwt.decode(
            token.get("id_token", ""),
            key=signing_key.key if jwks_uri else signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            issuer=oidc["issuer"],
            audience=oidc["client_id"],
            options={"verify_exp": True},
        )

        sub = claims.get("sub", "")
        email = claims.get("email", "")
        preferred_username = claims.get("preferred_username", claims.get("nickname", ""))
        username = preferred_username or email.split("@")[0] or sub

        # Find or create local user
        user_id = str(uuid.uuid4())
        user = user_mgmt.find_or_create_oidc_user(
            user_id=user_id,
            username=username,
            sub=sub,
            provider=oidc["provider_name"],
            id_token=token.get("id_token", ""),
            access_token=token.get("access_token", ""),
            refresh_token=token.get("refresh_token", ""),
            expires_at=time.time() + token.get("expires_in", 3600),
        )

        if not user:
            return RedirectResponse("/login?error=user_creation_failed")

        # Issue session JWT
        jwt_token = _build_jwt(user)

        # Redirect to the app with token in URL hash (handled by auth.js)
        return RedirectResponse(f"/app#token={jwt_token}")

    except jwt.ExpiredSignatureError:
        return RedirectResponse("/login?error=token_expired")
    except jwt.InvalidTokenError as e:
        return RedirectResponse(f"/login?error=invalid_token")
    except Exception as e:
        print(f"[oidc] callback error: {e}")
        return RedirectResponse("/login?error=server_error")


@app.get("/providers")
def list_providers():
    """List configured OIDC providers (for admin UI)."""
    oidc = _oidc_config()
    if not oidc:
        return []
    return [{
        "provider_name": oidc["provider_name"],
        "issuer": oidc["issuer"],
        "client_id": oidc["client_id"][:12] + "…" if len(oidc["client_id"]) > 12 else oidc["client_id"],
        "scope": oidc["scope"],
        "button_label": oidc["button_label"],
        "enabled": True,
    }]


# Cleanup stale sessions periodically (called by the callback on every login)
def _cleanup_sessions():
    now = time.time()
    stale = [s for s, d in _sessions.items() if now - d.get("created", 0) > 600]
    for s in stale:
        del _sessions[s]
