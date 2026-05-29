# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Ely — Database layer (audit, preferences)."""

import uuid
from datetime import datetime, timezone
from database.connection import get_connection


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_ely_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ely_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL,
            page TEXT DEFAULT '',
            action_name TEXT NOT NULL,
            action_args TEXT DEFAULT '',
            action_result TEXT DEFAULT '',
            status TEXT DEFAULT 'ok',
            tokens_used INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ely_preferences (
            user_id TEXT PRIMARY KEY,
            tone TEXT DEFAULT 'professional',
            verbosity TEXT DEFAULT 'concise',
            proactive INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            preferred_provider TEXT DEFAULT '',
            preferred_model TEXT DEFAULT '',
            max_turns INTEGER DEFAULT 5,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Migration: add max_turns if missing
        ALTER TABLE ely_preferences ADD COLUMN max_turns INTEGER DEFAULT 5;
    """)
    conn.commit()
    conn.close()


def log_action(user_id, page, action_name, action_args=None, action_result=None, status="ok", tokens_used=0):
    conn = get_connection()
    import json
    aid = str(uuid.uuid4())
    now = _now()
    conn.execute(
        """INSERT INTO ely_audit (audit_id, user_id, page, action_name, action_args, action_result, status, tokens_used, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (aid, user_id, page, action_name,
         json.dumps(action_args or {}, default=str)[:1000],
         json.dumps(action_result or {}, default=str)[:1000],
         status, tokens_used, now),
    )
    conn.commit()
    conn.close()
    return aid


def get_audit_logs(user_id, page=None, action=None, limit=50, offset=0):
    conn = get_connection()
    query = "SELECT * FROM ely_audit WHERE user_id=? "
    params = [user_id]
    if page:
        query += "AND page=? "
        params.append(page)
    if action:
        query += "AND action_name=? "
        params.append(action)
    query += "ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_audit_stats(user_id):
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as cnt FROM ely_audit WHERE user_id=?", (user_id,)).fetchone()
    success = conn.execute("SELECT COUNT(*) as cnt FROM ely_audit WHERE user_id=? AND status='ok'", (user_id,)).fetchone()
    tokens = conn.execute("SELECT COALESCE(SUM(tokens_used),0) as cnt FROM ely_audit WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    total_n = total["cnt"] if total else 0
    success_n = success["cnt"] if success else 0
    return {
        "total": total_n,
        "success": success_n,
        "rate": round(success_n / total_n * 100, 1) if total_n > 0 else 0,
        "tokens": tokens["cnt"] if tokens else 0,
    }


def get_preferences(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM ely_preferences WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["proactive"] = bool(d.get("proactive", 0))
        d["enabled"] = bool(d.get("enabled", 1))
        d["max_turns"] = int(d.get("max_turns", 5))
        return d
    return {"user_id": user_id, "tone": "professional", "verbosity": "concise",
            "proactive": False, "enabled": True, "preferred_provider": "", "preferred_model": "",
            "max_turns": 5}


def save_preferences(user_id, **kw):
    conn = get_connection()
    now = _now()
    existing = conn.execute("SELECT user_id FROM ely_preferences WHERE user_id=?", (user_id,)).fetchone()
    if existing:
        sets = []
        vals = []
        for k in ("tone", "verbosity", "preferred_provider", "preferred_model", "max_turns"):
            if k in kw:
                sets.append(f"{k}=?")
                vals.append(kw[k])
        for k in ("proactive", "enabled"):
            if k in kw:
                sets.append(f"{k}=?")
                vals.append(1 if kw[k] else 0)
        if sets:
            vals.extend([now, user_id])
            conn.execute(f"UPDATE ely_preferences SET {', '.join(sets)}, updated_at=? WHERE user_id=?", vals)
    else:
        conn.execute(
            """INSERT INTO ely_preferences (user_id, tone, verbosity, proactive, enabled, preferred_provider, preferred_model, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (user_id, kw.get("tone", "professional"), kw.get("verbosity", "concise"),
             1 if kw.get("proactive") else 0, 1 if kw.get("enabled", True) else 0,
             kw.get("preferred_provider", ""), kw.get("preferred_model", ""), now),
        )
    conn.commit()
    conn.close()
    return get_preferences(user_id)


# Init on import
init_ely_db()
