# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
BYOK — Bring Your Own Key.

Architecture:
  user_key  = HKDF(client_digest, user_salt, "elyria-user-key", 32 bytes)
               Derived server-side at login from the SHA-512 digest the client already sends.
               Never stored in plaintext.

  Server wrap key = ELYRIA_SERVER_WRAP_KEY env var (64 bytes hex) or ephemeral.
               Used only to wrap user_key at rest so password reset can re-wrap team keys.

  Personal data:       payload = AES-256-GCM(data, user_key)
  Team data:           payload = AES-256-GCM(data, team_key)
  Team key for member: teams.encrypted_team_key = AES-256-GCM(team_key, member's user_key)

Without the user's password, data is irrecoverable.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ═══════════════════════════════════════════════════════════════
# HKDF helper (stdlib only — no cryptography dep needed for this)
# ═══════════════════════════════════════════════════════════════

def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    i = 1
    while len(out) < length:
        out += hmac.new(prk, out[-32:] + info + bytes([i]), hashlib.sha256).digest()
        i += 1
    return out[:length]


# ═══════════════════════════════════════════════════════════════
# Server wrap key (for password reset recovery only)
# ═══════════════════════════════════════════════════════════════

_server_wrap_key: bytes | None = None


def _load_server_wrap_key() -> bytes:
    raw = os.getenv("ELYRIA_SERVER_WRAP_KEY", "")
    if raw:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    key = secrets.token_bytes(32)
    print("[crypto] ⚠ ELYRIA_SERVER_WRAP_KEY not set — ephemeral server key. "
          "Wrapped user keys will be lost on restart (users can still re-derive from password).")
    return key


def get_server_wrap_key() -> bytes:
    global _server_wrap_key
    if _server_wrap_key is None:
        _server_wrap_key = _load_server_wrap_key()
    return _server_wrap_key


# ═══════════════════════════════════════════════════════════════
# User key — derived from login digest + user salt
# ═══════════════════════════════════════════════════════════════

def derive_user_key(client_digest: str, user_salt: str) -> bytes:
    """
    Derive a 32-byte AES-256 key from the login credentials.
    client_digest = SHA-512(password) from the browser (hex string)
    user_salt     = per-user salt from the users table (hex string)
    """
    ikm = client_digest.encode()
    salt = user_salt.encode()
    return _hkdf_sha256(ikm, salt, b"elyria-user-key", 32)


def wrap_user_key(user_key: bytes) -> str:
    """Encrypt user_key with server wrap key for at-rest storage."""
    nonce = secrets.token_bytes(12)
    aes = AESGCM(get_server_wrap_key())
    ct = aes.encrypt(nonce, user_key, None)
    return base64.b64encode(nonce + ct).decode()


def unwrap_user_key(wrapped: str) -> bytes | None:
    """Decrypt user_key from at-rest storage. Returns None on failure."""
    if not wrapped:
        return None
    try:
        raw = base64.b64decode(wrapped)
        nonce, ct = raw[:12], raw[12:]
        aes = AESGCM(get_server_wrap_key())
        return aes.decrypt(nonce, ct, None)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# Team keys — wrapped per member
# ═══════════════════════════════════════════════════════════════

def generate_team_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def wrap_team_key_for_member(team_key: bytes, member_user_key: bytes) -> str:
    """Encrypt team_key with a specific member's user_key."""
    nonce = secrets.token_bytes(12)
    aes = AESGCM(member_user_key)
    ct = aes.encrypt(nonce, team_key, None)
    return base64.b64encode(nonce + ct).decode()


def unwrap_team_key_for_member(encrypted: str, member_user_key: bytes) -> bytes:
    """Decrypt team_key using a member's user_key."""
    raw = base64.b64decode(encrypted)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(member_user_key)
    return aes.decrypt(nonce, ct, None)


# ═══════════════════════════════════════════════════════════════
# Payload encryption
# ═══════════════════════════════════════════════════════════════

def encrypt_payload(data: dict, key: bytes) -> str:
    """AES-256-GCM encrypt a JSON dict. Returns base64 (nonce + ct)."""
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(data, ensure_ascii=False).encode()
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_payload(encrypted: str, key: bytes) -> dict:
    """AES-256-GCM decrypt a payload back to a dict."""
    raw = base64.b64decode(encrypted)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(key)
    return json.loads(aes.decrypt(nonce, ct, None))
