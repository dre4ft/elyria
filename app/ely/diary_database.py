# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Ely — Diary database layer."""

import json
import uuid
from datetime import datetime, timezone
from database.connection import get_connection


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_diary_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ely_diary (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            diary_id    TEXT UNIQUE NOT NULL,
            user_id     TEXT NOT NULL,
            page        TEXT DEFAULT '',
            title       TEXT DEFAULT '',
            content     TEXT DEFAULT '',
            context_url TEXT DEFAULT '',
            tags        TEXT DEFAULT '[]',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


def diary_create(user_id, page="", title="", content="", context_url="", tags=None):
    conn = get_connection()
    did = str(uuid.uuid4())
    now = _now()
    conn.execute(
        """INSERT INTO ely_diary (diary_id, user_id, page, title, content, context_url, tags, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (did, user_id, page, title, content[:5000], context_url,
         json.dumps(tags if tags else []), now, now),
    )
    conn.commit()
    conn.close()
    return did


def diary_get(diary_id, user_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM ely_diary WHERE diary_id=? AND user_id=?",
        (diary_id, user_id),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def diary_list(user_id, page=None, tag=None, limit=50, offset=0):
    conn = get_connection()
    if tag:
        rows = conn.execute(
            "SELECT * FROM ely_diary WHERE user_id=? AND tags LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, f'%"{tag}"%', limit, offset),
        ).fetchall()
    elif page:
        rows = conn.execute(
            "SELECT * FROM ely_diary WHERE user_id=? AND page=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, page, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM ely_diary WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def diary_search(user_id, query, limit=50):
    conn = get_connection()
    rows = conn.execute(
        """SELECT * FROM ely_diary WHERE user_id=?
           AND (title LIKE ? OR content LIKE ?)
           ORDER BY created_at DESC LIMIT ?""",
        (user_id, f"%{query}%", f"%{query}%", limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def diary_update(diary_id, user_id, **kw):
    conn = get_connection()
    existing = conn.execute(
        "SELECT * FROM ely_diary WHERE diary_id=? AND user_id=?",
        (diary_id, user_id),
    ).fetchone()
    if not existing:
        conn.close()
        return None

    sets = []
    vals = []
    for k in ("title", "content", "page", "context_url"):
        if k in kw:
            sets.append(f"{k}=?")
            val = kw[k]
            if k == "content":
                val = val[:5000]
            vals.append(val)
    if "tags" in kw:
        sets.append("tags=?")
        vals.append(json.dumps(kw["tags"] if isinstance(kw["tags"], list) else []))

    if sets:
        now = _now()
        vals.extend([now, diary_id, user_id])
        conn.execute(
            f"UPDATE ely_diary SET {', '.join(sets)}, updated_at=? WHERE diary_id=? AND user_id=?",
            vals,
        )
        conn.commit()
    conn.close()
    return diary_get(diary_id, user_id)


def diary_delete(diary_id, user_id):
    conn = get_connection()
    cur = conn.execute(
        "DELETE FROM ely_diary WHERE diary_id=? AND user_id=?",
        (diary_id, user_id),
    )
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


def diary_count(user_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM ely_diary WHERE user_id=?",
        (user_id,),
    ).fetchone()
    conn.close()
    return row["cnt"] if row else 0


# Init on import
init_diary_db()
