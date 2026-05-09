"""
Workflow graph storage — full canvas state as JSON.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone

DB_PATH = "database.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS workflow_graphs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            graph TEXT NOT NULL DEFAULT '{}',
            user_id TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def save_workflow(name, graph, user_id="", description=""):
    conn = _connect()
    wf_id = str(uuid.uuid4())
    now = _now()
    conn.execute(
        "INSERT INTO workflow_graphs (workflow_id, name, description, graph, user_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (wf_id, name, description, json.dumps(graph), user_id, now, now),
    )
    conn.commit()
    conn.close()
    return wf_id


def list_workflows(user_id=None, team_id=""):
    conn = _connect()
    if team_id == "__followed__":
        # Personal + followed teams
        import sqlite3 as _sq
        tc = _sq.connect(DB_PATH)
        followed = [r[0] for r in tc.execute("SELECT team_id FROM user_followed_teams WHERE user_id=?", (user_id,)).fetchall()]
        tc.close()
        if followed:
            ph = ",".join("?" * len(followed))
            rows = conn.execute(f"SELECT * FROM workflow_graphs WHERE user_id=? OR user_id='' OR team_id IN ({ph}) ORDER BY updated_at DESC", [user_id] + followed).fetchall()
        else:
            rows = conn.execute("SELECT * FROM workflow_graphs WHERE user_id=? OR user_id='' ORDER BY updated_at DESC", (user_id,)).fetchall()
    elif team_id:
        rows = conn.execute("SELECT * FROM workflow_graphs WHERE team_id=? ORDER BY updated_at DESC", (team_id,)).fetchall()
    elif user_id:
        rows = conn.execute(
            "SELECT workflow_id, name, description, user_id, created_at, updated_at FROM workflow_graphs WHERE user_id=? OR user_id='' ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT workflow_id, name, description, user_id, created_at, updated_at FROM workflow_graphs ORDER BY updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_workflow(workflow_id):
    conn = _connect()
    row = conn.execute("SELECT * FROM workflow_graphs WHERE workflow_id=?", (workflow_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["graph"] = json.loads(d.get("graph") or "{}")
        return d
    return None


def update_workflow(workflow_id, name, graph, description=""):
    conn = _connect()
    now = _now()
    conn.execute(
        "UPDATE workflow_graphs SET name=?, graph=?, description=?, updated_at=? WHERE workflow_id=?",
        (name, json.dumps(graph), description, now, workflow_id),
    )
    conn.commit()
    conn.close()


def delete_workflow(workflow_id):
    conn = _connect()
    conn.execute("DELETE FROM workflow_graphs WHERE workflow_id=?", (workflow_id,))
    conn.commit()
    conn.close()
