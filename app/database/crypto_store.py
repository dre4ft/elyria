"""
Crypto store — transparent encryption for DB rows using per-user keys.

Session lifecycle:
  1. Login → derive user_key from digest + salt → store in request.state.user_key
  2. Access team data → unwrap team key with user_key → cache (TTL 3600s)
  3. Logout → clear caches

Personal data: encrypted with user_key directly.
Team data: encrypted with team_key, team key wrapped per member.
"""

import time
from database.crypto import (
    encrypt_payload, decrypt_payload,
    wrap_team_key_for_member, unwrap_team_key_for_member,
    generate_team_key, derive_user_key, wrap_user_key, unwrap_user_key,
)
from database.connection import get_connection

_CACHE_TTL = 3600  # 1 hour

# In-memory cache: user_id → (user_key, timestamp)
_user_key_cache: dict[str, tuple[bytes, float]] = {}
# In-memory cache: (user_id, team_id) → (team_key, timestamp)
_team_key_cache: dict[tuple[str, str], tuple[bytes, float]] = {}


def _cache_prune():
    """Remove expired entries from both caches."""
    now = time.time()
    for cache in (_user_key_cache, _team_key_cache):
        stale = [k for k, v in cache.items() if now - v[1] > _CACHE_TTL]
        for k in stale:
            del cache[k]


# ═══════════════════════════════════════════════════════════════
# User key lifecycle
# ═══════════════════════════════════════════════════════════════

def set_user_key(user_id: str, user_key: bytes):
    """Store user key in memory for the session."""
    _cache_prune()
    _user_key_cache[user_id] = (user_key, time.time())


def get_user_key(user_id: str) -> bytes | None:
    """Get user key from session memory."""
    entry = _user_key_cache.get(user_id)
    if entry and time.time() - entry[1] < _CACHE_TTL:
        return entry[0]
    elif entry:
        del _user_key_cache[user_id]
    return None


def clear_user_key(user_id: str):
    """Remove user key from memory (on logout)."""
    _user_key_cache.pop(user_id, None)
    to_remove = [k for k in _team_key_cache if k[0] == user_id]
    for k in to_remove:
        del _team_key_cache[k]


def derive_and_store_user_key(user_id: str, client_digest: str, user_salt: str) -> bytes:
    """Derive user key from login digest, store in memory, return it."""
    key = derive_user_key(client_digest, user_salt)
    _cache_prune()
    _user_key_cache[user_id] = (key, time.time())
    return key


def wrap_and_persist_user_key(user_id: str, user_key: bytes):
    """Store wrapped user key in DB for password reset recovery."""
    wrapped = wrap_user_key(user_key)
    conn = get_connection()
    conn.execute("UPDATE users SET wrapped_user_key = ? WHERE user_id = ?",
                 (wrapped, user_id))
    conn.commit()
    conn.close()


def load_user_key(user_id: str) -> bytes | None:
    """
    Try to recover user key from memory → DB wrapped key.
    Returns None if the server wrap key is unavailable (ephemeral mode).
    """
    entry = _user_key_cache.get(user_id)
    if entry and time.time() - entry[1] < _CACHE_TTL:
        return entry[0]
    # Try DB recovery
    conn = get_connection()
    row = conn.execute("SELECT wrapped_user_key FROM users WHERE user_id = ?",
                       (user_id,)).fetchone()
    conn.close()
    if row and row["wrapped_user_key"]:
        key = unwrap_user_key(row["wrapped_user_key"])
        if key:
            _user_key_cache[user_id] = (key, time.time())
            return key
    return None


# ═══════════════════════════════════════════════════════════════
# Team key management
# ═══════════════════════════════════════════════════════════════

def create_team_with_key(team_id: str, creator_user_id: str) -> str:
    """Generate a team key, wrap it for the creator, store it."""
    team_key = generate_team_key()
    creator_key = get_user_key(creator_user_id)
    if not creator_key:
        raise RuntimeError("User key not available — user must be logged in")
    wrapped = wrap_team_key_for_member(team_key, creator_key)
    _cache_prune()
    _team_key_cache[(creator_user_id, team_id)] = (team_key, time.time())
    conn = get_connection()
    conn.execute(
        "UPDATE team_users SET encrypted_team_key = ? WHERE team_id = ? AND user_id = ?",
        (wrapped, team_id, creator_user_id),
    )
    conn.commit()
    conn.close()
    return wrapped


def add_member_team_key(team_id: str, new_user_id: str, added_by_user_id: str):
    """Wrap the team key for a new member."""
    team_key = get_team_key(added_by_user_id, team_id)
    if not team_key:
        raise RuntimeError("Caller does not have access to team key")
    new_key = get_user_key(new_user_id)
    if not new_key:
        raise RuntimeError("New member's user key not available")
    wrapped = wrap_team_key_for_member(team_key, new_key)
    conn = get_connection()
    conn.execute(
        "UPDATE team_users SET encrypted_team_key = ? WHERE team_id = ? AND user_id = ?",
        (wrapped, team_id, new_user_id),
    )
    conn.commit()
    conn.close()


def get_team_key(user_id: str, team_id: str) -> bytes | None:
    """Get the team key for a user (from cache or DB)."""
    cache_key = (user_id, team_id)
    entry = _team_key_cache.get(cache_key)
    if entry and time.time() - entry[1] < _CACHE_TTL:
        return entry[0]
    user_key = get_user_key(user_id)
    if not user_key:
        return None
    conn = get_connection()
    row = conn.execute(
        "SELECT encrypted_team_key FROM team_users WHERE team_id = ? AND user_id = ?",
        (team_id, user_id),
    ).fetchone()
    conn.close()
    if row and row["encrypted_team_key"]:
        try:
            team_key = unwrap_team_key_for_member(row["encrypted_team_key"], user_key)
            _team_key_cache[cache_key] = (team_key, time.time())
            return team_key
        except Exception:
            return None
    return None


# ═══════════════════════════════════════════════════════════════
# Payload seal / open
# ═══════════════════════════════════════════════════════════════

def _resolve_key(user_id: str, team_id: str = "") -> bytes | None:
    """Get encryption key for user/team. Falls back to DB recovery if not in memory."""
    if team_id:
        key = get_team_key(user_id, team_id)
        if key:
            return key
        # Try DB recovery: load user key, then team key
        uk = get_user_key(user_id) or load_user_key(user_id)
        if uk:
            set_user_key(user_id, uk)
            return get_team_key(user_id, team_id)
        return None
    else:
        key = get_user_key(user_id)
        if key:
            return key
        # Try DB recovery
        key = load_user_key(user_id)
        if key:
            set_user_key(user_id, key)
        return key


def crypto_seal(data: dict, user_id: str, team_id: str = "") -> str:
    """Encrypt data. Falls back to DB recovery if user key not in memory."""
    if not data:
        return ""
    key = _resolve_key(user_id, team_id)
    if not key:
        raise RuntimeError(f"Encryption key not available for user {user_id}")
    return encrypt_payload(data, key)


def crypto_open(encrypted: str, user_id: str, team_id: str = "") -> dict:
    """Decrypt a payload. Falls back to DB recovery. Returns {} on failure."""
    if not encrypted:
        return {}
    key = _resolve_key(user_id, team_id)
    if not key:
        return {}
    try:
        return decrypt_payload(encrypted, key)
    except Exception:
        return {}


# ═══════════════════════════════════════════════════════════════
# Team key rotation — re-encrypt all data when a member leaves
# ═══════════════════════════════════════════════════════════════

def rotate_team_key(team_id: str, performed_by: str) -> int:
    """
    Generate a new team key, re-encrypt all payloads, re-wrap for remaining members.
    The user performing the rotation must have the current team key.
    Returns the number of rows re-encrypted.
    """
    old_key = get_team_key(performed_by, team_id)
    if not old_key:
        raise RuntimeError("Cannot rotate: caller doesn't have team key access")

    new_key = generate_team_key()
    conn = get_connection()
    count = 0

    # 1. Re-encrypt saved_requests payloads
    rows = conn.execute(
        "SELECT id, payload_encrypted FROM saved_requests WHERE team_id = ? AND payload_encrypted != ''",
        (team_id,),
    ).fetchall()
    for row in rows:
        try:
            data = decrypt_payload(row["payload_encrypted"], old_key)
            new_payload = encrypt_payload(data, new_key)
            conn.execute("UPDATE saved_requests SET payload_encrypted = ? WHERE id = ?",
                         (new_payload, row["id"]))
            count += 1
        except Exception:
            pass

    # 2. Re-encrypt workflow_graphs payloads
    wf_rows = conn.execute(
        "SELECT id, payload_encrypted FROM workflow_graphs WHERE team_id = ? AND payload_encrypted != ''",
        (team_id,),
    ).fetchall()
    for row in wf_rows:
        try:
            data = decrypt_payload(row["payload_encrypted"], old_key)
            new_payload = encrypt_payload(data, new_key)
            conn.execute("UPDATE workflow_graphs SET payload_encrypted = ? WHERE id = ?",
                         (new_payload, row["id"]))
            count += 1
        except Exception:
            pass

    # 3. Re-wrap team key for all remaining members
    now = time.time()
    members = conn.execute(
        "SELECT user_id FROM team_users WHERE team_id = ?",
        (team_id,),
    ).fetchall()
    for m in members:
        member_key = get_user_key(m["user_id"])
        if not member_key:
            member_key = load_user_key(m["user_id"])
        if member_key:
            wrapped = wrap_team_key_for_member(new_key, member_key)
            conn.execute(
                "UPDATE team_users SET encrypted_team_key = ? WHERE team_id = ? AND user_id = ?",
                (wrapped, team_id, m["user_id"]),
            )
            _team_key_cache[(m["user_id"], team_id)] = (new_key, now)

    conn.commit()
    conn.close()
    return count

