"""
Crypto store — transparent encryption layer for DB rows.

Usage:
  # Write
  encrypted = crypto_seal(payload_dict, team_id)
  db.execute("INSERT ... payload_encrypted=?", (encrypted,))

  # Read
  payload_dict = crypto_open(encrypted, team_id)
"""

from database.crypto import (
    encrypt_payload, decrypt_payload,
    get_team_key, encrypt_team_key,
    get_master_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from database.app_config import get as cfg
from database.connection import get_connection
import secrets
import base64

# Cache team keys in memory (valid for process lifetime, cleared on restart)
_team_key_cache: dict[str, bytes] = {}


def _fetch_team_key(team_id: str) -> bytes:
    """Fetch and decrypt a team's key from the DB, with memory cache."""
    if team_id in _team_key_cache:
        return _team_key_cache[team_id]
    conn = get_connection()
    row = conn.execute(
        "SELECT encrypted_team_key FROM teams WHERE team_id=?", (team_id,)
    ).fetchone()
    conn.close()
    if not row or not row["encrypted_team_key"]:
        raise ValueError(f"No encryption key found for team {team_id}")
    key = get_team_key(row["encrypted_team_key"])
    _team_key_cache[team_id] = key
    return key


def crypto_seal(data: dict, team_id: str = "") -> str:
    """Encrypt a data dict. If team_id is set, use team key; else personal key."""
    if not data:
        return ""
    key = _fetch_team_key(team_id) if team_id else get_master_key()
    return encrypt_payload(data, key)


def crypto_open(encrypted: str, team_id: str = "") -> dict:
    """Decrypt a payload back to a dict."""
    if not encrypted:
        return {}
    key = _fetch_team_key(team_id) if team_id else get_master_key()
    return decrypt_payload(encrypted, key)


def clear_key_cache():
    """Clear cached team keys (call after key rotation)."""
    _team_key_cache.clear()
