# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Blue Team module — database operations (profiles, reports).
"""

import json
import uuid
from datetime import datetime, timezone

from database.connection import get_connection


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_blueteam_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS blueteam_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            target_url TEXT NOT NULL,
            master_prompt TEXT DEFAULT '',
            documentation TEXT DEFAULT '',
            openapi_spec_url TEXT DEFAULT '',
            collection_id TEXT DEFAULT '',
            user_id TEXT DEFAULT '',
            team_ids TEXT DEFAULT '',
            pro_model TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS blueteam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            profile_id TEXT NOT NULL,
            report_markdown TEXT DEFAULT '',
            findings_count INTEGER DEFAULT 0,
            analysis_rounds INTEGER DEFAULT 0,
            tokens_used INTEGER DEFAULT 0,
            pro_model TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (profile_id) REFERENCES blueteam_profiles(profile_id) ON DELETE CASCADE
        );
    """)
    # Migrations
    for col, ctype in [("scan_progress", "INTEGER DEFAULT 0"), ("tokens_used", "INTEGER DEFAULT 0")]:
        try:
            conn.execute(f"ALTER TABLE blueteam_profiles ADD COLUMN {col} {ctype}")
        except:
            pass
    for col, ctype in [("source_type", "TEXT DEFAULT ''"), ("source_id", "TEXT DEFAULT ''")]:
        try:
            conn.execute(f"ALTER TABLE blueteam_profiles ADD COLUMN {col} {ctype}")
        except:
            pass
    conn.commit()
    conn.close()


# ── Profiles CRUD ──

def create_profile(name, target_url, user_id="", team_ids="", description="",
                   master_prompt="", documentation="", openapi_spec_url="", collection_id="",
                   source_type="", source_id=""):
    conn = get_connection()
    pid = str(uuid.uuid4())
    now = _now()
    conn.execute(
        "INSERT INTO blueteam_profiles (profile_id, name, description, target_url, master_prompt, documentation, openapi_spec_url, collection_id, user_id, team_ids, source_type, source_id, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid, name, description, target_url, master_prompt, documentation, openapi_spec_url, collection_id, user_id, team_ids, source_type, source_id, "pending", now, now),
    )
    conn.commit()
    conn.close()
    return pid


def list_profiles(user_id=None, team_ids=None, team_filter=None):
    conn = get_connection()
    q = "SELECT * FROM blueteam_profiles WHERE 1=1"
    args = []
    if team_filter:
        q += " AND team_ids LIKE ?"
        args.append(f"%{team_filter}%")
    elif user_id:
        q += " AND (user_id=? OR user_id=''"
        args.append(user_id)
        if team_ids:
            for t in team_ids.split(","):
                t = t.strip()
                if t:
                    q += " OR team_ids LIKE ?"
                    args.append(f"%{t}%")
        q += ")"
    q += " ORDER BY updated_at DESC"
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_profile(profile_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM blueteam_profiles WHERE profile_id=?", (profile_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_profile(profile_id, **kwargs):
    conn = get_connection()
    now = _now()
    sets = ["updated_at=?"]
    args = [now]
    allowed = ("name", "description", "target_url", "master_prompt", "documentation",
               "openapi_spec_url", "collection_id", "team_ids", "status", "pro_model",
               "scan_progress", "tokens_used", "source_type", "source_id")
    for k, v in kwargs.items():
        if k in allowed:
            sets.append(f"{k}=?")
            args.append(v)
    args.append(profile_id)
    conn.execute(f"UPDATE blueteam_profiles SET {', '.join(sets)} WHERE profile_id=?", args)
    conn.commit()
    conn.close()


def delete_profile(profile_id):
    conn = get_connection()
    conn.execute("DELETE FROM blueteam_profiles WHERE profile_id=?", (profile_id,))
    conn.commit()
    conn.close()


# ── Reports CRUD ──

def create_report(profile_id, report_md, findings_count=0, analysis_rounds=0, tokens_used=0, pro_model=""):
    conn = get_connection()
    rid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO blueteam_reports (report_id, profile_id, report_markdown, findings_count, analysis_rounds, tokens_used, pro_model, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (rid, profile_id, report_md, findings_count, analysis_rounds, tokens_used, pro_model, _now()),
    )
    conn.commit()
    conn.close()
    return rid


def get_reports(profile_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM blueteam_reports WHERE profile_id=? ORDER BY created_at DESC", (profile_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_report(report_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM blueteam_reports WHERE report_id=?", (report_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
