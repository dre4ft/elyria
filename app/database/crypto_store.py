# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Crypto store — key lifecycle manager.

Architecture:
  master_key       = random(32) — never derived, never stored plaintext
  auth_verifier    = Argon2id[:32] — stored DB, login check only
  pw_key           = Argon2id[32:] — memory, unwraps master_key_blob_pw
  rec_key          = Argon2id(recovery_words) — recovery path
  master_key_blob_* = AES-GCM(key, master_key) — stored DB, opaque

  Collection:  DEK = random(32), wrapped by master_key or TVK
  Team:        TVK = random(32), wrapped per member by their master_key

At-rest guarantees:
  - DB dump → auth_verifier cannot reach pw_key (one-way split)
  - DB dump → master_key_blob_* is AES-GCM without password or recovery
  - Employee rogue → DB alone can't decrypt anything
  - Password change → re-wrap master_key, O(1), no data re-encryption
"""

import time
from database.crypto import (
    generate_key,
    derive_auth_and_key,
    verify_auth,
    derive_rec_key,
    wrap_master_key,
    unwrap_master_key,
    DEKManager,
    aes_encrypt_json,
    aes_decrypt_json,
    aes_encrypt_string,
    aes_decrypt_string,
)
from database.connection import get_connection

_USER_CACHE_TTL = 3600  # 1 hour session
_TEAM_CACHE_TTL = 3600

# In-memory cache: user_id → master_key (cleared on logout, expires after TTL)
_master_key_cache: dict[str, tuple[bytes, float]] = {}
# In-memory cache: (user_id, team_id) → TVK
_tvk_cache: dict[tuple[str, str], tuple[bytes, float]] = {}
# In-memory cache: (user_id, collection_id) → DEK (expires with session)
# Scoped by user_id to prevent cross-user BOLA/IDOR attacks via cache
_dek_cache: dict[tuple[str, str], tuple[bytes, float]] = {}

# Pending recovery words for first login (user_id → words)
_pending_recovery: dict[str, str] = {}


def _prune(cache: dict, ttl: float):
    now = time.time()
    stale = [k for k, v in cache.items() if now - v[1] > ttl]
    for k in stale:
        del cache[k]


# ═══════════════════════════════════════════════════════════════
# Master Key — Registration
# ═══════════════════════════════════════════════════════════════

def register_master_key(user_id: str, password: str,
                        salt_pw: str, salt_auth: str, salt_rec: str) -> tuple[str, str, str]:
    """
    Create a new user's crypto material.

    Returns (auth_verifier, master_key_blob_pw, master_key_blob_rec).

    master_key = random 32B — never derived, never stored plaintext.
    auth_verifier = Argon2id(password, salt_auth)[:32] — login only.
    pw_key = Argon2id(password, salt_pw)[32:] — memory, unwraps master_key.
    master_key_blob_pw = AES-GCM(pw_key, master_key) — stored DB.
    """
    master_key = generate_key()
    auth_verifier, pw_key = derive_auth_and_key(password, salt_pw)

    mp_blob_pw = wrap_master_key(master_key, pw_key)

    # Recovery path
    from database.crypto import generate_recovery_words as gen_rec
    recovery_words = gen_rec()
    rec_key = derive_rec_key(recovery_words, salt_rec)
    mp_blob_rec = wrap_master_key(master_key, rec_key)

    # Encrypt recovery words with pw_key for first-login handoff
    pending_rec = aes_encrypt_string(pw_key, recovery_words)

    # Store in DB
    conn = get_connection()
    conn.execute(
        """UPDATE users SET auth_verifier = ?, salt_pw = ?, salt_auth = ?, salt_rec = ?,
           master_key_blob_pw = ?, master_key_blob_rec = ?, recovery_words_shown = 0,
           pending_recovery = ?
           WHERE user_id = ?""",
        (auth_verifier, salt_pw, salt_auth, salt_rec, mp_blob_pw, mp_blob_rec, pending_rec, user_id),
    )
    conn.commit()
    conn.close()

    # Cache master_key in memory for the session
    _prune(_master_key_cache, _USER_CACHE_TTL)
    _master_key_cache[user_id] = (master_key, time.time())

    return auth_verifier, recovery_words, mp_blob_pw


# ═══════════════════════════════════════════════════════════════
# Master Key — Login
# ═══════════════════════════════════════════════════════════════

def login_and_unlock(user_id: str, password: str) -> bytes | None:
    """
    Verify password and unlock master_key into memory.

    1. Fetch salt_pw + auth_verifier + master_key_blob_pw from DB
    2. Derive auth_verifier_candidate + pw_key from password
    3. Compare auth_verifier (constant-time)
    4. If match: unwrap master_key with pw_key → cache in memory
    5. Return master_key or None
    """
    conn = get_connection()
    row = conn.execute(
        "SELECT salt_pw, auth_verifier, master_key_blob_pw, pending_recovery, recovery_words_shown FROM users WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    conn.close()

    if not row or not row["auth_verifier"] or not row["master_key_blob_pw"]:
        return None

    auth_candidate, pw_key = derive_auth_and_key(password, row["salt_pw"])
    if not verify_auth(password, row["salt_pw"], row["auth_verifier"]):
        import secrets as _secrets
        if not _secrets.compare_digest(auth_candidate, row["auth_verifier"]):
            return None

    master_key = unwrap_master_key(row["master_key_blob_pw"], pw_key)
    if not master_key:
        return None

    # ── First login : déchiffrer les mots de récupération ──
    if not row["recovery_words_shown"] and row["pending_recovery"]:
        words = aes_decrypt_string(pw_key, row["pending_recovery"])
        if words:
            _pending_recovery[user_id] = words
            # Effacer de la DB immédiatement
            conn2 = get_connection()
            conn2.execute("UPDATE users SET pending_recovery = '', recovery_words_shown = 1 WHERE user_id = ?", (user_id,))
            conn2.commit()
            conn2.close()

    _prune(_master_key_cache, _USER_CACHE_TTL)
    _master_key_cache[user_id] = (master_key, time.time())
    return master_key


def consume_pending_recovery(user_id: str) -> str:
    """Return recovery words if this was the first login. Empty string otherwise."""
    return _pending_recovery.pop(user_id, "")


def get_master_key(user_id: str) -> bytes | None:
    """Get master_key from memory cache. Returns None if not logged in."""
    entry = _master_key_cache.get(user_id)
    if entry and time.time() - entry[1] < _USER_CACHE_TTL:
        return entry[0]
    if entry:
        del _master_key_cache[user_id]
    return None


def clear_master_key(user_id: str):
    """Remove master_key from memory (logout). Also clears derived TVK/DEK caches."""
    _master_key_cache.pop(user_id, None)
    to_remove_tvk = [k for k in _tvk_cache if k[0] == user_id]
    for k in to_remove_tvk:
        del _tvk_cache[k]
    to_remove_dek = [k for k in _dek_cache if k[0] == user_id]
    for k in to_remove_dek:
        del _dek_cache[k]


# ═══════════════════════════════════════════════════════════════
# Master Key — Password Change
# ═══════════════════════════════════════════════════════════════

def change_password(user_id: str, old_password: str, new_password: str) -> bool:
    """
    Change password: re-wrap master_key with new pw_key.
    O(1) — no data re-encryption. New salt_pw generated.
    """
    master_key = login_and_unlock(user_id, old_password)
    if not master_key:
        return False

    new_salt_pw = __import__("secrets").token_bytes(16).hex()
    new_auth, new_pw_key = derive_auth_and_key(new_password, new_salt_pw)
    new_blob_pw = wrap_master_key(master_key, new_pw_key)

    conn = get_connection()
    conn.execute(
        "UPDATE users SET salt_pw = ?, auth_verifier = ?, master_key_blob_pw = ? WHERE user_id = ?",
        (new_salt_pw, new_auth, new_blob_pw, user_id),
    )
    conn.commit()
    conn.close()

    _master_key_cache[user_id] = (master_key, time.time())
    return True


# ═══════════════════════════════════════════════════════════════
# Master Key — Recovery
# ═══════════════════════════════════════════════════════════════

def recover_with_words(user_id: str, recovery_words: str) -> bytes | None:
    """
    Recover master_key using the 12-word recovery passphrase.
    Returns master_key (cached in memory) or None.
    """
    conn = get_connection()
    row = conn.execute(
        "SELECT salt_rec, master_key_blob_rec FROM users WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    conn.close()

    if not row or not row["master_key_blob_rec"]:
        return None

    rec_key = derive_rec_key(recovery_words, row["salt_rec"])
    master_key = unwrap_master_key(row["master_key_blob_rec"], rec_key)
    if master_key:
        _prune(_master_key_cache, _USER_CACHE_TTL)
        _master_key_cache[user_id] = (master_key, time.time())
    return master_key


# ═══════════════════════════════════════════════════════════════
# Collection DEK management
# ═══════════════════════════════════════════════════════════════

def create_collection_key(user_id: str, collection_id: str, team_id: str = "") -> bytes:
    """
    Create a DEK for a new collection.
    If team_id provided: DEK wrapped by TVK → stored in collection_keys.
    Otherwise: DEK wrapped by user's master_key.
    Returns the DEK (bytes, in-memory only).
    """
    parent_key = get_master_key(user_id)
    if not parent_key:
        raise RuntimeError("User not authenticated")

    if team_id:
        tvk = get_tvk(user_id, team_id)
        if not tvk:
            raise RuntimeError(f"User {user_id} does not have access to team {team_id}")
        parent_key = tvk

    dek, encrypted_dek = DEKManager.create_dek(parent_key)
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO collection_keys (collection_id, encrypted_dek, team_id) VALUES (?, ?, ?)",
        (collection_id, encrypted_dek, team_id or ""),
    )
    conn.commit()
    conn.close()

    _prune(_dek_cache, _USER_CACHE_TTL)
    _dek_cache[(user_id, collection_id)] = (dek, time.time())
    return dek


def get_collection_key(user_id: str, collection_id: str, team_id: str = "") -> bytes | None:
    """Get the DEK for a collection (from cache or DB). Scoped by user_id."""
    cache_key = (user_id, collection_id)
    entry = _dek_cache.get(cache_key)
    if entry and time.time() - entry[1] < _USER_CACHE_TTL:
        return entry[0]

    conn = get_connection()
    row = conn.execute(
        "SELECT encrypted_dek, team_id FROM collection_keys WHERE collection_id = ?",
        (collection_id,),
    ).fetchone()
    conn.close()

    if not row:
        return None

    if row["team_id"]:
        parent_key = get_tvk(user_id, row["team_id"])
    else:
        parent_key = get_master_key(user_id)

    if not parent_key:
        return None

    dek = DEKManager.unwrap_dek(row["encrypted_dek"], parent_key)
    if dek:
        _prune(_dek_cache, _USER_CACHE_TTL)
        _dek_cache[(user_id, collection_id)] = (dek, time.time())
    return dek


# ═══════════════════════════════════════════════════════════════
# Team Vault Key management
# ═══════════════════════════════════════════════════════════════

def create_tvk(team_id: str, creator_user_id: str) -> bytes:
    """Generate TVK, wrap it for the creator, store it. Returns TVK."""
    tvk = generate_key()
    creator_mk = get_master_key(creator_user_id)
    if not creator_mk:
        raise RuntimeError("Creator not authenticated")

    wrapped = aes_encrypt_string(creator_mk, tvk.hex())

    conn = get_connection()
    conn.execute(
        "UPDATE team_users SET wrapped_tvk = ? WHERE team_id = ? AND user_id = ?",
        (wrapped, team_id, creator_user_id),
    )
    conn.commit()
    conn.close()

    _prune(_tvk_cache, _TEAM_CACHE_TTL)
    _tvk_cache[(creator_user_id, team_id)] = (tvk, time.time())
    return tvk


def add_member_to_team(team_id: str, new_user_id: str, added_by_user_id: str):
    """Wrap TVK for a new member. O(1)."""
    tvk = get_tvk(added_by_user_id, team_id)
    if not tvk:
        raise RuntimeError("Caller does not have access to TVK")

    new_mk = get_master_key(new_user_id)
    if not new_mk:
        raise RuntimeError("New member not authenticated")

    wrapped = aes_encrypt_string(new_mk, tvk.hex())
    conn = get_connection()
    conn.execute(
        "UPDATE team_users SET wrapped_tvk = ? WHERE team_id = ? AND user_id = ?",
        (wrapped, team_id, new_user_id),
    )
    conn.commit()
    conn.close()

    _tvk_cache[(new_user_id, team_id)] = (tvk, time.time())


def remove_member_from_team(team_id: str, removed_user_id: str) -> int:
    """
    Rotate TVK and re-wrap all team collection DEKs. O(n) collections.
    Removes wrapped_tvk for the departing member.
    Returns number of collections re-encrypted.
    """
    conn = get_connection()

    # Get all remaining members and their master keys
    members = conn.execute(
        "SELECT user_id FROM team_users WHERE team_id = ? AND user_id != ?",
        (team_id, removed_user_id),
    ).fetchall()

    # Old TVK — get from any remaining member
    old_tvk = None
    for m in members:
        mk = get_master_key(m["user_id"])
        if mk:
            row = conn.execute(
                "SELECT wrapped_tvk FROM team_users WHERE team_id = ? AND user_id = ?",
                (team_id, m["user_id"]),
            ).fetchone()
            if row and row["wrapped_tvk"]:
                hex_key = aes_decrypt_string(mk, row["wrapped_tvk"])
                if hex_key and len(hex_key) == 64:
                    old_tvk = bytes.fromhex(hex_key)
                    break

    if not old_tvk:
        conn.close()
        return 0

    # Generate new TVK
    new_tvk = generate_key()
    count = 0

    # Re-wrap all collection DEKs
    collections = conn.execute(
        "SELECT collection_id, encrypted_dek FROM collection_keys WHERE team_id = ?",
        (team_id,),
    ).fetchall()
    for col in collections:
        dek = DEKManager.unwrap_dek(col["encrypted_dek"], old_tvk)
        if dek:
            _, new_edek = DEKManager.create_dek(new_tvk)  # re-wrap
            # Actually we need to re-wrap the SAME dek, not create a new one
            new_edek_fixed = aes_encrypt_string(new_tvk, dek.hex())
            conn.execute(
                "UPDATE collection_keys SET encrypted_dek = ? WHERE collection_id = ?",
                (new_edek_fixed, col["collection_id"]),
            )
            count += 1

    # Re-wrap TVK for remaining members
    now = time.time()
    for m in members:
        mk = get_master_key(m["user_id"])
        if mk:
            wrapped = aes_encrypt_string(mk, new_tvk.hex())
            conn.execute(
                "UPDATE team_users SET wrapped_tvk = ? WHERE team_id = ? AND user_id = ?",
                (wrapped, team_id, m["user_id"]),
            )
            _tvk_cache[(m["user_id"], team_id)] = (new_tvk, now)

    # Remove departing member's wrapped_tvk
    conn.execute(
        "UPDATE team_users SET wrapped_tvk = '' WHERE team_id = ? AND user_id = ?",
        (team_id, removed_user_id),
    )
    conn.commit()
    conn.close()

    # Clear TVK from departing member's cache
    _tvk_cache.pop((removed_user_id, team_id), None)
    return count


def get_tvk(user_id: str, team_id: str) -> bytes | None:
    """Get TVK for a team member (from cache or DB)."""
    cache_key = (user_id, team_id)
    entry = _tvk_cache.get(cache_key)
    if entry and time.time() - entry[1] < _TEAM_CACHE_TTL:
        return entry[0]

    mk = get_master_key(user_id)
    if not mk:
        return None

    conn = get_connection()
    row = conn.execute(
        "SELECT wrapped_tvk FROM team_users WHERE team_id = ? AND user_id = ?",
        (team_id, user_id),
    ).fetchone()
    conn.close()

    if not row or not row["wrapped_tvk"]:
        return None

    hex_key = aes_decrypt_string(mk, row["wrapped_tvk"])
    if hex_key and len(hex_key) == 64:
        tvk = bytes.fromhex(hex_key)
        _prune(_tvk_cache, _TEAM_CACHE_TTL)
        _tvk_cache[cache_key] = (tvk, time.time())
        return tvk
    return None


# ═══════════════════════════════════════════════════════════════
# System-level seal / open (server wrap key, no user context needed)
# ═══════════════════════════════════════════════════════════════

def seal_system(data: dict) -> str:
    """Encrypt system-level data with server wrap key. Always available."""
    if not data:
        return ""
    from database.crypto import get_server_wrap_key, aes_encrypt_json as _enc
    return _enc(get_server_wrap_key(), data)


def open_system(encrypted: str) -> dict:
    """Decrypt system-level data with server wrap key."""
    if not encrypted:
        return {}
    from database.crypto import get_server_wrap_key, aes_decrypt_json as _dec
    return _dec(get_server_wrap_key(), encrypted)


def seal_system_str(value: str) -> str:
    """Encrypt a string with server wrap key."""
    if not value:
        return ""
    from database.crypto import get_server_wrap_key, aes_encrypt_string as _enc
    return _enc(get_server_wrap_key(), value)


def open_system_str(encrypted: str) -> str:
    """Decrypt a string with server wrap key."""
    if not encrypted:
        return ""
    from database.crypto import get_server_wrap_key, aes_decrypt_string as _dec
    result = _dec(get_server_wrap_key(), encrypted)
    return result or ""


# ═══════════════════════════════════════════════════════════════
# Sensitive data seal / open (per-user master_key)
# ═══════════════════════════════════════════════════════════════

def seal_sensitive(user_id: str, data: dict) -> str:
    """Encrypt sensitive data with user's master_key. Returns base64 blob."""
    if not data:
        return ""
    mk = get_master_key(user_id)
    if not mk:
        return ""
    return aes_encrypt_json(mk, data)


def open_sensitive(user_id: str, encrypted: str) -> dict:
    """Decrypt sensitive data with user's master_key. Returns dict or {}."""
    if not encrypted:
        return {}
    mk = get_master_key(user_id)
    if not mk:
        return {}
    return aes_decrypt_json(mk, encrypted)


def seal_sensitive_str(user_id: str, value: str) -> str:
    """Encrypt a single string value with user's master_key."""
    if not value:
        return ""
    mk = get_master_key(user_id)
    if not mk:
        return ""
    return aes_encrypt_string(mk, value)


def open_sensitive_str(user_id: str, encrypted: str) -> str:
    """Decrypt a single string value with user's master_key."""
    if not encrypted:
        return ""
    mk = get_master_key(user_id)
    if not mk:
        return ""
    result = aes_decrypt_string(mk, encrypted)
    return result or ""


# ═══════════════════════════════════════════════════════════════
# Data seal / open (generic, for collections)
# ═══════════════════════════════════════════════════════════════

def crypto_seal(data: dict, user_id: str, collection_id: str = "", team_id: str = "") -> str:
    """Encrypt data. Uses DEK if collection_id provided, master_key otherwise."""
    if not data:
        return ""
    if collection_id:
        key = get_collection_key(user_id, collection_id, team_id)
    else:
        key = get_master_key(user_id)
    if not key:
        raise RuntimeError(f"Encryption key not available for user {user_id}")
    return aes_encrypt_json(key, data)


def crypto_open(encrypted: str, user_id: str, collection_id: str = "", team_id: str = "") -> dict:
    """Decrypt data. Returns {} on failure."""
    if not encrypted:
        return {}
    if collection_id:
        key = get_collection_key(user_id, collection_id, team_id)
    else:
        key = get_master_key(user_id)
    if not key:
        return {}
    return aes_decrypt_json(key, encrypted)
