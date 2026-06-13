# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""User context storage — single JSON blob per user, accessible via {{ctx.xxx}} templates."""

import json
from database.database import connect
from core.logging import get_logger

_log = get_logger(__name__)

INIT_USER_CTX = """
CREATE TABLE IF NOT EXISTS user_ctx (
    user_id TEXT PRIMARY KEY,
    ctx_json TEXT NOT NULL DEFAULT '{}',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


def get_ctx(user_id: str) -> dict:
    """Return the full context dict for a user (empty dict if none)."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT ctx_json FROM user_ctx WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row:
            return json.loads(row["ctx_json"])
        return {}
    except Exception as e:
        _log.error(f"Error getting ctx for {user_id}: {e}")
        return {}
    finally:
        conn.close()


def put_ctx(user_id: str, ctx: dict) -> bool:
    """Replace the user's entire context dict."""
    conn = connect()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO user_ctx (user_id, ctx_json, updated_at)
               VALUES (?, ?, CURRENT_TIMESTAMP)""",
            (user_id, json.dumps(ctx)),
        )
        conn.commit()
        return True
    except Exception as e:
        _log.error(f"Error putting ctx for {user_id}: {e}")
        return False
    finally:
        conn.close()


def delete_ctx(user_id: str) -> bool:
    """Delete the user's context entirely."""
    conn = connect()
    try:
        conn.execute("DELETE FROM user_ctx WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    except Exception as e:
        _log.error(f"Error deleting ctx for {user_id}: {e}")
        return False
    finally:
        conn.close()
