"""
Cryptographic compartmentalization for team data.

Architecture:
  Master key = HKDF-SHA256(ELYRIA_MASTER_SEED, salt, length=32)
  Per team: team_key (AES-256), encrypted with master key via AES-GCM
  Per row: payload = AES-256-GCM(json(data), team_key), nonce prepended

Without ELYRIA_MASTER_SEED, all encrypted data is irrecoverable.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Master key ──────────────────────────────────────────────────────────

def _derive_master_key(seed: bytes) -> bytes:
    """HKDF-SHA256: derive a 32-byte master key from the seed."""
    # HKDF using hashlib + hmac (stdlib only, no cryptography dependency for this)
    # extract
    prk = hmac.new(b"elyria-master-salt", seed, hashlib.sha256).digest()
    # expand
    return hmac.new(prk, b"elyria-master-expand", hashlib.sha256).digest()


def _load_master_seed() -> bytes:
    """Load master seed from env or generate one if not set."""
    raw = os.getenv("ELYRIA_MASTER_SEED", "")
    if raw:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    # Dev mode: generate a random seed — data WILL be lost on restart
    seed = secrets.token_bytes(64)
    print("[crypto] ⚠ ELYRIA_MASTER_SEED not set — generated ephemeral seed. "
          "Encrypted data will be lost on restart.")
    return seed


_master_key: Optional[bytes] = None


def get_master_key() -> bytes:
    """Return the master key (lazy init, cached in memory)."""
    global _master_key
    if _master_key is None:
        _master_key = _derive_master_key(_load_master_seed())
    return _master_key


# ── Team keys ───────────────────────────────────────────────────────────

def generate_team_key() -> bytes:
    """Generate a fresh 32-byte AES-256 key for a new team."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_team_key(team_key: bytes) -> str:
    """Encrypt a team key with the master key. Returns base64-encoded ciphertext (nonce prepended)."""
    nonce = secrets.token_bytes(12)
    aes = AESGCM(get_master_key())
    ct = aes.encrypt(nonce, team_key, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_team_key(encrypted: str) -> bytes:
    """Decrypt a team key using the master key."""
    raw = base64.b64decode(encrypted)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(get_master_key())
    return aes.decrypt(nonce, ct, None)


# ── Payload encryption ──────────────────────────────────────────────────

def encrypt_payload(data: dict, team_key: bytes) -> str:
    """Encrypt a JSON-serializable dict with the team key. Returns base64 (nonce + ciphertext)."""
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(data, ensure_ascii=False).encode()
    aes = AESGCM(team_key)
    ct = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_payload(encrypted: str, team_key: bytes) -> dict:
    """Decrypt a payload with the team key. Returns the original dict."""
    raw = base64.b64decode(encrypted)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(team_key)
    plaintext = aes.decrypt(nonce, ct, None)
    return json.loads(plaintext)


# ── Wrappers for DB integration ─────────────────────────────────────────

def encrypt_row(cleartext_columns: dict, team_key: bytes) -> str:
    """Encrypt a dict of sensitive columns into a single payload string."""
    return encrypt_payload(cleartext_columns, team_key)


def decrypt_row(payload: str, team_key: bytes) -> dict:
    """Decrypt a payload string back into a dict of columns."""
    return decrypt_payload(payload, team_key)


def get_team_key(encrypted_team_key: str) -> bytes:
    """Decrypt and return a team key (caller must hold master key)."""
    return decrypt_team_key(encrypted_team_key)
