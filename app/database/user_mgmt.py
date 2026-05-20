# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from database.database import connect
from datetime import datetime, timedelta
from core.logging import get_logger

logger = get_logger(__name__)


def add_user(user_id: str, hashed_digest: str, salt: str, email: str, username: str = "", teams: str = None):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO users (user_id, hashed_digest, salt, username, email, teams,
               salt_pw, salt_auth, salt_rec)
               VALUES (?, ?, ?, ?, ?, ?, '', '', '')""",
            (user_id, hashed_digest, salt, username or email, email, teams),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        return False
    finally:
        conn.close()


def get_user_teams(user_id: str) -> str:
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT team_id FROM team_users WHERE user_id = ?", (user_id,))
        rows = cursor.fetchall()
        return ",".join(row["team_id"] for row in rows) if rows else ""
    finally:
        conn.close()


def get_user_by_id(user_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, email, email_verified, teams FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()


def get_user_by_email(email: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, email, email_verified, teams FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        logger.error(f"Error fetching user by email: {e}")
        return None
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, email, email_verified, teams FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()


def get_user_salt(email: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT salt FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            return row["salt"]
        return None
    except Exception as e:
        logger.error(f"Error fetching user salt: {e}")
        return None
    finally:
        conn.close()


def is_valid_user(email: str, hashed_digest: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT hashed_digest FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row and row["hashed_digest"] == hashed_digest:
            return True
        return False
    except Exception as e:
        logger.error(f"Error validating user: {e}")
        return False
    finally:
        conn.close()


def is_email_taken(email: str) -> bool:
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        return cursor.fetchone()[0] > 0
    finally:
        conn.close()


def count_users() -> int:
    conn = connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Email Verification
# ═══════════════════════════════════════════

def save_verification_code(email: str, code: str, ttl_minutes: int = 30):
    """Store a verification code with expiry for the given email."""
    expiry = datetime.now() + timedelta(minutes=ttl_minutes)
    conn = connect()
    try:
        conn.execute(
            "UPDATE users SET verification_code = ?, verification_code_expiry = ? WHERE email = ?",
            (code, expiry.strftime("%Y-%m-%d %H:%M:%S"), email),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error saving verification code: {e}")
        return False
    finally:
        conn.close()


def verify_email_code(email: str, code: str) -> bool:
    """Check if the code matches and is not expired."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT verification_code, verification_code_expiry FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row or row["verification_code"] != code:
            return False
        expiry = row["verification_code_expiry"]
        if not expiry:
            return False
        if datetime.now() > datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S"):
            return False
        return True
    except Exception as e:
        logger.error(f"Error verifying email code: {e}")
        return False
    finally:
        conn.close()


def mark_email_verified(email: str):
    """Mark the user's email as verified and clear the verification code."""
    conn = connect()
    try:
        conn.execute(
            "UPDATE users SET email_verified = 1, verification_code = '', verification_code_expiry = '' WHERE email = ?",
            (email,),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error marking email verified: {e}")
        return False
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Account Lockout
# ═══════════════════════════════════════════

MAX_FAILED_ATTEMPTS = 10
LOCKOUT_MINUTES = 15


def get_login_lockout(email: str) -> tuple[bool, str]:
    """Check if account is locked. Returns (is_locked, message)."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT failed_login_attempts, locked_until FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            return False, ""
        if row["locked_until"]:
            locked = datetime.strptime(row["locked_until"], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < locked:
                remaining = int((locked - datetime.now()).total_seconds() / 60) + 1
                return True, f"Compte temporairement verrouille. Reessayez dans {remaining} minute(s)."
            # Lock expired, reset
            conn.execute("UPDATE users SET locked_until = '', failed_login_attempts = 0 WHERE email = ?", (email,))
            conn.commit()
        return False, ""
    finally:
        conn.close()


def increment_failed_login(email: str):
    """Record a failed login attempt. Locks account after MAX_FAILED_ATTEMPTS."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT failed_login_attempts FROM users WHERE email = ?", (email,)
        ).fetchone()
        if row:
            count = (row["failed_login_attempts"] or 0) + 1
            if count >= MAX_FAILED_ATTEMPTS:
                locked = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                conn.execute(
                    "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE email = ?",
                    (count, locked.strftime("%Y-%m-%d %H:%M:%S"), email),
                )
            else:
                conn.execute(
                    "UPDATE users SET failed_login_attempts = ? WHERE email = ?",
                    (count, email),
                )
            conn.commit()
    finally:
        conn.close()


def reset_failed_login(email: str):
    """Clear failed login counter on successful login."""
    conn = connect()
    try:
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = '' WHERE email = ?",
            (email,),
        )
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Verification Tokens (anti-abuse: token binds email, max 3 resends, 2min cooldown)
# ═══════════════════════════════════════════

def create_verification_token(email: str, code: str, ttl_minutes: int = 30) -> str:
    """Create a temporary verification token bound to an email. Returns the token."""
    import secrets as _secrets
    token = _secrets.token_hex(32)
    now = datetime.now()
    expires = now + timedelta(minutes=ttl_minutes)
    conn = connect()
    try:
        conn.execute(
            """INSERT INTO verification_tokens (token, email, code, resend_count, last_resend_at, created_at, expires_at)
               VALUES (?, ?, ?, 0, ?, ?, ?)""",
            (token, email, code, now.strftime("%Y-%m-%d %H:%M:%S"),
             now.strftime("%Y-%m-%d %H:%M:%S"), expires.strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        return token
    except Exception as e:
        logger.error(f"Error creating verification token: {e}")
        return ""
    finally:
        conn.close()


def get_verification_token(token: str) -> dict | None:
    """Look up a verification token. Returns dict or None if expired/invalid."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM verification_tokens WHERE token = ?", (token,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if datetime.now() > datetime.strptime(d["expires_at"], "%Y-%m-%d %H:%M:%S"):
            return None
        return d
    except Exception as e:
        logger.error(f"Error getting verification token: {e}")
        return None
    finally:
        conn.close()


def consume_verification_token(token: str) -> bool:
    """Delete a verification token after successful verification. Returns True if found."""
    conn = connect()
    try:
        conn.execute("DELETE FROM verification_tokens WHERE token = ?", (token,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error consuming verification token: {e}")
        return False
    finally:
        conn.close()


def try_resend_verification_token(token: str, new_code: str, cooldown_minutes: int = 2, max_resends: int = 3) -> tuple[bool, str]:
    """
    Attempt to resend a verification code. Returns (ok, error_message).
    Rate limits: max {max_resends} resends, {cooldown_minutes}min between each.
    """
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM verification_tokens WHERE token = ?", (token,)
        ).fetchone()
        if not row:
            return False, "Token introuvable ou expire."

        d = dict(row)
        if datetime.now() > datetime.strptime(d["expires_at"], "%Y-%m-%d %H:%M:%S"):
            return False, "Token expire."

        if d["resend_count"] >= max_resends:
            return False, f"Nombre maximum de renvois atteint ({max_resends})."

        last = datetime.strptime(d["last_resend_at"], "%Y-%m-%d %H:%M:%S")
        elapsed = (datetime.now() - last).total_seconds()
        if elapsed < cooldown_minutes * 60:
            remaining = int((cooldown_minutes * 60 - elapsed) / 60) + 1
            return False, f"Veuillez patienter {remaining} minute(s) avant de renvoyer."

        # Ok — update
        new_count = d["resend_count"] + 1
        conn.execute(
            "UPDATE verification_tokens SET code = ?, resend_count = ?, last_resend_at = ? WHERE token = ?",
            (new_code, new_count, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), token),
        )
        conn.commit()
        return True, ""
    except Exception as e:
        logger.error(f"Error resending verification token: {e}")
        return False, "Erreur interne."
    finally:
        conn.close()


# ═══════════════════════════════════════════
# User Management
# ═══════════════════════════════════════════

def update_user_teams(user_id: str, teams: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET teams = ? WHERE user_id = ?", (teams, user_id))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating user teams: {e}")
        return False
    finally:
        conn.close()


def delete_user(user_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Keys Management
# ═══════════════════════════════════════════

def _derive_jwt_secret(key_id: str) -> str:
    """Derive JWT signing secret from server key + key_id. Stored value is useless without server key."""
    import hmac as _hmac
    from database.crypto import get_server_wrap_key
    return _hmac.new(get_server_wrap_key(), key_id.encode(), "sha256").hexdigest()


def add_key(key_id: str, key_value: str, user_id: str = None,
            refresh_token_hash: str = ""):
    conn = connect()
    cursor = conn.cursor()
    try:
        # Store the raw secret temporarily — will be replaced by derived value
        # The key_value passed in is the JWT signing secret, we derive and store it
        derived = _derive_jwt_secret(key_id) if key_value else ""
        cursor.execute(
            "INSERT INTO keys (key_id, key_value, user_id, refresh_token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (key_id, derived, user_id, refresh_token_hash, datetime.now()),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error adding key: {e}")
        return False
    finally:
        conn.close()


def get_key(key_id: str):
    """Return the stored JWT signing secret."""
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT key_value FROM keys WHERE key_id = ?", (key_id,))
        row = cursor.fetchone()
        if row:
            return row["key_value"]
        return None
    except Exception as e:
        logger.error(f"Error fetching key: {e}")
        return None
    finally:
        conn.close()


def delete_key(key_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM keys WHERE key_id = ?", (key_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting key: {e}")
        return False
    finally:
        conn.close()


def delete_old_keys(max_age_seconds: int = 3600):
    conn = connect()
    cursor = conn.cursor()
    try:
        cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)
        cursor.execute("DELETE FROM keys WHERE created_at < ?", (cutoff_time,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting old keys: {e}")
        return False
    finally:
        conn.close()


def verify_refresh_token(refresh_token: str) -> dict | None:
    """Verify a refresh token against stored hashes. Returns key row dict or None."""
    import hashlib
    h = hashlib.sha3_512(refresh_token.encode()).hexdigest()
    conn = connect()
    try:
        row = conn.execute(
            "SELECT key_id, key_value, user_id, refresh_count, max_refreshes FROM keys WHERE refresh_token_hash = ?",
            (h,),
        ).fetchone()
        if row:
            d = dict(row)
            # Also fetch email for the JWT
            user = conn.execute("SELECT email FROM users WHERE user_id = ?", (d["user_id"],)).fetchone()
            if user:
                d["email"] = user["email"] or ""
            return d
        return None
    except Exception as e:
        logger.error(f"Error verifying refresh token: {e}")
        return None
    finally:
        conn.close()


def consume_refresh(key_id: str) -> bool:
    """Increment refresh count. Returns True if still within limit."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT refresh_count, max_refreshes FROM keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if not row:
            return False
        count = row["refresh_count"] + 1
        if count > row["max_refreshes"]:
            return False
        conn.execute(
            "UPDATE keys SET refresh_count = ? WHERE key_id = ?", (count, key_id)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error consuming refresh: {e}")
        return False
    finally:
        conn.close()


def rotate_key(key_id: str, new_secret: str, new_refresh_hash: str):
    """Replace JWT secret and refresh hash on an existing key (in-place rotation)."""
    conn = connect()
    try:
        conn.execute(
            "UPDATE keys SET key_value = ?, refresh_token_hash = ? WHERE key_id = ?",
            (new_secret, new_refresh_hash, key_id),
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Error rotating key: {e}")
    finally:
        conn.close()


# ═══════════════════════════════════════════
# OIDC User Management
# ═══════════════════════════════════════════

def find_oidc_user(sub: str, provider: str):
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE oidc_sub = ? AND oidc_provider = ?",
            (sub, provider),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_oidc_user(user_id: str, username: str, sub: str, provider: str,
                     id_token: str = "", access_token: str = "",
                     refresh_token: str = "", expires_at: float = 0):
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO users (user_id, hashed_digest, salt, username, email,
               oidc_sub, oidc_provider, oidc_id_token, oidc_access_token,
               oidc_refresh_token, oidc_expires_at, email_verified, last_login_at)
               VALUES (?, '', '', ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
            (user_id, username, username, sub, provider, id_token, access_token,
             refresh_token, expires_at, datetime.now()),
        )
        conn.commit()
        return user_id
    except Exception as e:
        logger.error(f"Error creating OIDC user: {e}")
        return None
    finally:
        conn.close()


def update_oidc_tokens(sub: str, provider: str, id_token: str = "",
                       access_token: str = "", refresh_token: str = "",
                       expires_at: float = 0):
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """UPDATE users SET oidc_id_token = ?, oidc_access_token = ?,
               oidc_refresh_token = ?, oidc_expires_at = ?, last_login_at = ?
               WHERE oidc_sub = ? AND oidc_provider = ?""",
            (id_token, access_token, refresh_token, expires_at,
             datetime.now(), sub, provider),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating OIDC tokens: {e}")
        return False
    finally:
        conn.close()


def find_or_create_oidc_user(user_id: str, username: str, sub: str,
                             provider: str, id_token: str = "",
                             access_token: str = "",
                             refresh_token: str = "",
                             expires_at: float = 0):
    existing = find_oidc_user(sub, provider)
    if existing:
        update_oidc_tokens(sub, provider, id_token, access_token,
                           refresh_token, expires_at)
        return existing
    base = username
    counter = 1
    while get_user_by_username(username):
        username = f"{base}{counter}"
        counter += 1
    created = create_oidc_user(user_id, username, sub, provider,
                               id_token, access_token, refresh_token, expires_at)
    if created:
        return {"user_id": user_id, "username": username, "email": username}
    return None
