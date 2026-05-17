from database.database import connect
from datetime import datetime, timedelta

def add_user(user_id: str, hashed_digest: str, salt: str, username: str, teams: str = None):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (user_id, hashed_digest, salt, username, teams) VALUES (?, ?, ?, ?, ?)",
                       (user_id, hashed_digest, salt, username, teams))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding user: {e}")
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
        cursor.execute("SELECT user_id, username, teams FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()

def get_user_by_username(username: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, teams FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()

def get_user_salt(username: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return row["salt"]
        return None
    except Exception as e:
        print(f"Error fetching user salt: {e}")
        return None
    finally:
        conn.close()

def is_valid_user(username: str, hashed_digest: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT hashed_digest FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and row["hashed_digest"] == hashed_digest:
            return True
        return False
    except Exception as e:
        print(f"Error validating user: {e}")
        return False
    finally:
        conn.close()

def update_user_teams(user_id: str, teams: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET teams = ? WHERE user_id = ?", (teams, user_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating user teams: {e}")
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
        print(f"Error deleting user: {e}")
        return False
    finally:
        conn.close()




"""

============================ Keys Management ============================

"""




def add_key(key_id: str, key_value: str, user_id: str = None,
            refresh_token_hash: str = ""):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO keys (key_id, key_value, user_id, refresh_token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (key_id, key_value, user_id, refresh_token_hash, datetime.now()),
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding key: {e}")
        return False
    finally:
        conn.close()


def get_key(key_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT key_value FROM keys WHERE key_id = ?", (key_id,))
        row = cursor.fetchone()
        if row:
            return row["key_value"]
        return None
    except Exception as e:
        print(f"Error fetching key: {e}")
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
        print(f"Error deleting key: {e}")
        return False
    finally:
        conn.close()

# ═══════════════════════════════════════════
# OIDC User Management
# ═══════════════════════════════════════════

def find_oidc_user(sub: str, provider: str):
    """Find a user by OIDC subject + provider."""
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
    """Create a new OIDC-authenticated user (no password)."""
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO users (user_id, hashed_digest, salt, username,
               oidc_sub, oidc_provider, oidc_id_token, oidc_access_token,
               oidc_refresh_token, oidc_expires_at, last_login_at)
               VALUES (?, '', '', ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, username, sub, provider, id_token, access_token,
             refresh_token, expires_at, datetime.now()),
        )
        conn.commit()
        return user_id
    except Exception as e:
        print(f"Error creating OIDC user: {e}")
        return None
    finally:
        conn.close()


def update_oidc_tokens(sub: str, provider: str, id_token: str = "",
                       access_token: str = "", refresh_token: str = "",
                       expires_at: float = 0):
    """Update OIDC tokens for an existing user."""
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
        print(f"Error updating OIDC tokens: {e}")
        return False
    finally:
        conn.close()


def find_or_create_oidc_user(user_id: str, username: str, sub: str,
                             provider: str, id_token: str = "",
                             access_token: str = "",
                             refresh_token: str = "",
                             expires_at: float = 0):
    """Find existing OIDC user or create a new one. Returns user dict."""
    existing = find_oidc_user(sub, provider)
    if existing:
        update_oidc_tokens(sub, provider, id_token, access_token,
                           refresh_token, expires_at)
        return existing
    # Username might already exist (non-OIDC user) — make unique
    base = username
    counter = 1
    while get_user_by_username(username):
        username = f"{base}{counter}"
        counter += 1
    created = create_oidc_user(user_id, username, sub, provider,
                               id_token, access_token, refresh_token, expires_at)
    if created:
        return {"user_id": user_id, "username": username}
    return None


def delete_old_keys(max_age_seconds: int = 3600):
    conn = connect()
    cursor = conn.cursor()
    try:
        cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)
        cursor.execute("DELETE FROM keys WHERE created_at < ?", (cutoff_time))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting old keys: {e}")
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
            return dict(row)
        return None
    except Exception as e:
        print(f"Error verifying refresh token: {e}")
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
        print(f"Error consuming refresh: {e}")
        return False
    finally:
        conn.close()


def rotate_refresh_token(key_id: str, new_refresh_token_hash: str):
    """Replace the refresh token hash after a successful refresh."""
    conn = connect()
    try:
        conn.execute(
            "UPDATE keys SET refresh_token_hash = ? WHERE key_id = ?",
            (new_refresh_token_hash, key_id),
        )
        conn.commit()
    except Exception as e:
        print(f"Error rotating refresh token: {e}")
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
        print(f"Error rotating key: {e}")
    finally:
        conn.close()