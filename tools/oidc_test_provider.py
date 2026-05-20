# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

#!/usr/bin/env python3
"""
Micro OIDC Test Provider — for local SSO testing.
Starts a standalone OIDC provider on http://localhost:9001.

Usage:
    pip install pyjwt>=2.8 cryptography
    python tools/oidc_test_provider.py

Then configure Elyria OIDC:
    oidc.enabled = 1
    oidc.provider_name = test
    oidc.issuer = http://localhost:9001
    oidc.client_id = elyria-test
    oidc.client_secret = test-secret
    oidc.scope = openid profile email
    oidc.button_label = Test SSO

Test users: alice / password123
"""

import json
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, parse_qs, urlparse
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

PORT = 9001
ISSUER = f"http://localhost:{PORT}"
CLIENT_ID = "elyria-test"
CLIENT_SECRET = "test-secret"

# ── Generate RSA key pair for signing tokens ──
_key = rsa.generate_private_key(65537, 2048, default_backend())
_private_pem = _key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
_public_pem = _key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

_jwk_kid = str(uuid.uuid4())

# Extract JWK components from the public key
_pub_numbers = _key.public_key().public_numbers()
import base64


def _int_to_b64(n: int) -> str:
    """Convert int to base64url without padding."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode()


_jwk_n = _int_to_b64(_pub_numbers.n)
_jwk_e = _int_to_b64(_pub_numbers.e)


# ── In-memory state ──
_codes: dict[str, dict] = {}  # state → { code, client_id, redirect_uri, nonce, sub }
_users = {
    "alice": {"sub": "alice-oidc-sub", "name": "Alice Martin", "email": "alice@example.com", "password": "password123"},
}


def _well_known() -> dict:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
    }


def _jwks() -> dict:
    return {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": _jwk_kid,
                "n": _jwk_n,
                "e": _jwk_e,
            }
        ]
    }


def _id_token(sub: str, name: str, email: str, nonce: str, client_id: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "sub": sub,
            "aud": client_id,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "name": name,
            "email": email,
            "email_verified": True,
        },
        _private_pem,
        algorithm="RS256",
        headers={"kid": _jwk_kid},
    )


# ── HTML templates ──
LOGIN_HTML = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test OIDC Provider — Login</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:#0f1629;color:#d1d5db;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#141c35;border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:32px;width:380px;box-shadow:0 20px 60px rgba(0,0,0,.3)}}
h1{{font-size:18px;color:white;margin-bottom:4px}}
.sub{{font-size:12px;color:#6b7280;margin-bottom:24px}}
label{{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#6b7280;margin-bottom:6px}}
input{{width:100%;height:40px;padding:0 12px;border-radius:10px;background:rgba(15,22,41,.6);border:1px solid rgba(255,255,255,.06);color:#d1d5db;font-size:14px;margin-bottom:16px;outline:none}}
input:focus{{border-color:rgba(124,58,237,.4)}}
button{{width:100%;height:44px;border-radius:12px;background:linear-gradient(135deg,#7c3aed,#8b5cf6);color:white;font-weight:600;font-size:14px;border:none;cursor:pointer;transition:all .15s}}
button:hover{{background:linear-gradient(135deg,#8b5cf6,#a78bfa)}}
.error{{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#f87171;padding:10px 14px;border-radius:8px;font-size:12px;margin-bottom:16px}}
.info{{font-size:11px;color:#6b7280;margin-top:12px;text-align:center}}
</style>
</head>
<body>
<div class="card">
<h1>Test OIDC Provider</h1>
<p class="sub">Micro serveur de test — utilisateur: <b>alice</b> / <b>password123</b></p>
{error}
<form method="POST" id="f">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<label>Username</label>
<input name="username" value="alice" autocomplete="username">
<label>Password</label>
<input name="password" type="password" value="password123" autocomplete="current-password">
<button type="submit">Se connecter</button>
</form>
<p class="info">Cette page simule un fournisseur OIDC (Google, Keycloak…)</p>
</div>
</body>
</html>"""

ERROR_HTML = """<!DOCTYPE html><html><head><title>Error</title></head>
<body style="font-family:sans-serif;background:#0f1629;color:#f87171;display:flex;align-items:center;justify-content:center;height:100vh">
<div><h1>Erreur</h1><p>{msg}</p><a href="javascript:history.back()" style="color:#8b5cf6">Retour</a></div>
</body></html>"""


class OIDCHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[oidc-test] {args[0]}")

    def _json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, url: str):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # ── Discovery ──
        if path == "/.well-known/openid-configuration":
            return self._json(_well_known())

        # ── JWKS ──
        if path == "/jwks":
            return self._json(_jwks())

        # ── Authorization endpoint ──
        if path == "/authorize":
            state = qs.get("state", [""])[0]
            redirect_uri = qs.get("redirect_uri", [""])[0]
            if not state or not redirect_uri:
                return self._html(ERROR_HTML.format(msg="state ou redirect_uri manquant"), 400)
            html = LOGIN_HTML.format(
                error="",
                state=state,
                redirect_uri=redirect_uri,
            )
            return self._html(html)

        # ── Unknown ──
        return self._html(ERROR_HTML.format(msg=f"Route inconnue: {path}"), 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ── Authorization (login form submit) ──
        if path == "/authorize":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            form = parse_qs(body)
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            state = form.get("state", [""])[0]
            redirect_uri = form.get("redirect_uri", [""])[0]

            user = _users.get(username)
            if not user or user["password"] != password:
                html = LOGIN_HTML.format(
                    error='<div class="error">Identifiants invalides</div>',
                    state=state,
                    redirect_uri=redirect_uri,
                )
                return self._html(html, 401)

            code = str(uuid.uuid4())
            _codes[code] = {
                "client_id": CLIENT_ID,
                "redirect_uri": redirect_uri,
                "sub": user["sub"],
                "name": user["name"],
                "email": user["email"],
                "nonce": str(uuid.uuid4()),
            }
            redirect_url = f"{redirect_uri}?code={code}&state={state}"
            return self._redirect(redirect_url)

        # ── Token endpoint ──
        if path == "/token":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            form = parse_qs(body)
            code = form.get("code", [""])[0]
            grant_type = form.get("grant_type", ["authorization_code"])[0]

            if grant_type != "authorization_code" or not code:
                return self._json({"error": "invalid_grant"}, 400)

            session = _codes.pop(code, None)
            if not session:
                return self._json({"error": "invalid_grant"}, 400)

            id_token = _id_token(
                sub=session["sub"],
                name=session["name"],
                email=session["email"],
                nonce=session["nonce"],
                client_id=session["client_id"],
            )

            return self._json({
                "access_token": str(uuid.uuid4()),
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 3600,
            })

        # ── Unknown ──
        return self._html(ERROR_HTML.format(msg=f"Route inconnue: {path}"), 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════╗
║        OIDC Test Provider — Ready                    ║
╠══════════════════════════════════════════════════════╣
║  Issuer:   http://localhost:{PORT}                     ║
║  Client:   {CLIENT_ID}                              ║
║  Secret:   {CLIENT_SECRET}                     ║
║  User:     alice / password123                     ║
╠══════════════════════════════════════════════════════╣
║  Discovery: /.well-known/openid-configuration       ║
║  JWKS:      /jwks                                   ║
║  Login:     /authorize                              ║
║  Token:     /token                                  ║
╚══════════════════════════════════════════════════════╝
    """.strip())

    server = HTTPServer(("127.0.0.1", PORT), OIDCHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print("\n[oidc-test] Stopped")
