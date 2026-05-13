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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migrations
    for col in ("slot",):
        try:
            conn.execute(f"ALTER TABLE ai_providers ADD COLUMN {col} TEXT DEFAULT 'pro'")
        except:
            pass
    conn.commit()
    conn.close()


def list_provider_configs(slot=None):
    conn = _connect()
    if slot:
        rows = conn.execute(
            "SELECT * FROM ai_providers WHERE slot=? ORDER BY is_default DESC, updated_at DESC",
            (slot,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM ai_providers ORDER BY slot, is_default DESC, updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_provider_config(config_id):
    conn = _connect()
    row = conn.execute("SELECT * FROM ai_providers WHERE config_id=?", (config_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_default_config(slot):
    """Get the default config for a given slot (flash/pro)."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM ai_providers WHERE slot=? AND is_default=1 ORDER BY updated_at DESC LIMIT 1",
        (slot,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def save_provider_config(slot, name, provider_type, base_url, api_key="", model="", is_default=False):
    conn = _connect()
    cid = str(uuid.uuid4())
    now = _now()
    if is_default:
        conn.execute("UPDATE ai_providers SET is_default=0 WHERE slot=?", (slot,))
    conn.execute(
        "INSERT INTO ai_providers (config_id, slot, name, provider_type, base_url, api_key, model, is_default, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (cid, slot, name, provider_type, base_url, api_key, model, int(is_default), now, now),
    )
    conn.commit()
    conn.close()
    return cid


def update_provider_config(config_id, **kwargs):
    conn = _connect()
    now = _now()
    cfg = conn.execute("SELECT slot, is_default FROM ai_providers WHERE config_id=?", (config_id,)).fetchone()
    if not cfg:
        conn.close()
        return
    if kwargs.get("is_default"):
        conn.execute("UPDATE ai_providers SET is_default=0 WHERE slot=?", (cfg["slot"],))
    sets = ["updated_at=?"]
    args = [now]
    for k in ("name", "slot", "provider_type", "base_url", "api_key", "model", "is_default"):
        if k in kwargs and kwargs[k] is not None:
            sets.append(f"{k}=?")
            args.append(kwargs[k])
    args.append(config_id)
    conn.execute(f"UPDATE ai_providers SET {', '.join(sets)} WHERE config_id=?", args)
    conn.commit()
    conn.close()


def delete_provider_config(config_id):
    conn = _connect()
    conn.execute("DELETE FROM ai_providers WHERE config_id=?", (config_id,))
    conn.commit()
    conn.close()


# Initialize table on import
init_ai_config()
