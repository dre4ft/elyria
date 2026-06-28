# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
AI Provider configuration persistence — flash and pro slots, multi-provider.
"""

import uuid
from datetime import datetime, timezone
from database.connection import get_connection


def _connect():
    return get_connection()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_ai_config():
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_id TEXT UNIQUE NOT NULL,
            slot TEXT NOT NULL DEFAULT 'pro',
            name TEXT NOT NULL,
            provider_type TEXT NOT NULL DEFAULT 'openai',
            base_url TEXT NOT NULL DEFAULT '',
            api_key TEXT DEFAULT '',
            model TEXT DEFAULT '',
            is_default INTEGER DEFAULT 0,
            user_id TEXT NOT NULL DEFAULT '',
            payload_encrypted TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def _decrypt_api_key(row_dict):
    """If payload_encrypted is present, extract api_key from it. Fallback to plaintext."""
    if not row_dict:
        return row_dict
    if row_dict.get("payload_encrypted"):
        from database.crypto_store import open_system
        data = open_system(row_dict["payload_encrypted"])
        if data and "api_key" in data:
            row_dict["api_key"] = data["api_key"]
    return row_dict


def list_provider_configs(slot=None, user_id=None):
    conn = _connect()
    if user_id:
        if slot:
            rows = conn.execute(
                "SELECT * FROM ai_providers WHERE user_id=? AND slot=? ORDER BY is_default DESC, updated_at DESC",
                (user_id, slot),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ai_providers WHERE user_id=? ORDER BY slot, is_default DESC, updated_at DESC",
                (user_id,),
            ).fetchall()
    else:
        if slot:
            rows = conn.execute(
                "SELECT * FROM ai_providers WHERE slot=? ORDER BY is_default DESC, updated_at DESC",
                (slot,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ai_providers ORDER BY slot, is_default DESC, updated_at DESC").fetchall()
    conn.close()
    return [_decrypt_api_key(dict(r)) for r in rows]


def get_provider_config(config_id, user_id=None):
    conn = _connect()
    if user_id:
        row = conn.execute("SELECT * FROM ai_providers WHERE config_id=? AND (user_id=? OR user_id='')", (config_id, user_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM ai_providers WHERE config_id=?", (config_id,)).fetchone()
    conn.close()
    return _decrypt_api_key(dict(row)) if row else None


def get_default_config(slot, user_id=None):
    """Get the default config for a given slot (flash/pro), optionally scoped to a user."""
    conn = _connect()
    if user_id:
        # Prefer user's own default, fall back to system default (user_id='')
        row = conn.execute(
            "SELECT * FROM ai_providers WHERE slot=? AND is_default=1 AND (user_id=? OR user_id='') ORDER BY CASE WHEN user_id='' THEN 1 ELSE 0 END, updated_at DESC LIMIT 1",
            (slot, user_id),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM ai_providers WHERE slot=? AND is_default=1 ORDER BY updated_at DESC LIMIT 1",
            (slot,),
        ).fetchone()
    conn.close()
    return _decrypt_api_key(dict(row)) if row else None


def save_provider_config(slot, name, provider_type, base_url, api_key="", model="", is_default=False, user_id=""):
    conn = _connect()
    cid = str(uuid.uuid4())
    now = _now()
    if is_default:
        conn.execute("UPDATE ai_providers SET is_default=0 WHERE slot=? AND user_id=?", (slot, user_id))
    # Encrypt api_key into payload_encrypted (system-level)
    from database.crypto_store import seal_system
    payload = seal_system({"api_key": api_key}) if api_key else ""
    conn.execute(
        "INSERT INTO ai_providers (config_id, slot, name, provider_type, base_url, api_key, model, is_default, user_id, created_at, updated_at, payload_encrypted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, slot, name, provider_type, base_url, "", model, int(is_default), user_id, now, now, payload),
    )
    conn.commit()
    conn.close()
    return cid


def update_provider_config(config_id, user_id=None, **kwargs):
    conn = _connect()
    now = _now()
    if user_id:
        cfg = conn.execute("SELECT slot, is_default, user_id FROM ai_providers WHERE config_id=? AND (user_id=? OR user_id='')", (config_id, user_id)).fetchone()
    else:
        cfg = conn.execute("SELECT slot, is_default FROM ai_providers WHERE config_id=?", (config_id,)).fetchone()
    if not cfg:
        conn.close()
        return
    if kwargs.get("is_default"):
        owner = cfg["user_id"] if cfg["user_id"] else user_id or ""
        conn.execute("UPDATE ai_providers SET is_default=0 WHERE slot=? AND user_id=?", (cfg["slot"], owner))
    sets = ["updated_at=?"]
    args = [now]
    for k in ("name", "slot", "provider_type", "base_url", "model", "is_default"):
        if k in kwargs and kwargs[k] is not None:
            sets.append(f"{k}=?")
            args.append(kwargs[k])
    # Encrypt api_key if provided
    if "api_key" in kwargs and kwargs["api_key"] is not None:
        from database.crypto_store import seal_system
        sets.append("payload_encrypted=?")
        args.append(seal_system({"api_key": kwargs["api_key"]}) if kwargs["api_key"] else "")
        sets.append("api_key=?")
        args.append("")  # clear plaintext
    args.append(config_id)
    conn.execute(f"UPDATE ai_providers SET {', '.join(sets)} WHERE config_id=?", args)
    conn.commit()
    conn.close()


def delete_provider_config(config_id, user_id=None):
    conn = _connect()
    if user_id:
        conn.execute("DELETE FROM ai_providers WHERE config_id=? AND (user_id=? OR user_id='')", (config_id, user_id))
    else:
        conn.execute("DELETE FROM ai_providers WHERE config_id=?", (config_id,))
    conn.commit()
    conn.close()


# Initialize table on import
init_ai_config()
