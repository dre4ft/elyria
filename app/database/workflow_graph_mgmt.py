# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Workflow graph storage — full canvas state as JSON.
"""

import json
import uuid
from datetime import datetime, timezone
from database.connection import get_connection


def _connect():
    return get_connection()


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
            team_id TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migration for existing tables that lack team_id
    try:
        conn.execute("ALTER TABLE workflow_graphs ADD COLUMN team_id TEXT DEFAULT ''")
    except:
        pass
    conn.commit()
    conn.close()


def _seal_graph(graph_data, user_id, team_id):
    """Encrypt the workflow graph JSON."""
    from database.crypto_store import crypto_seal
    return crypto_seal(graph_data, user_id, team_id) if graph_data else ""


def _open_graph(encrypted, user_id, team_id):
    """Decrypt the workflow graph JSON."""
    from database.crypto_store import crypto_open
    if not encrypted:
        return {}
    return crypto_open(encrypted, user_id, team_id)


def save_workflow(name, graph, user_id="", description="", team_id=""):
    conn = _connect()
    wf_id = str(uuid.uuid4())
    now = _now()
    # Encrypt the graph if team-scoped
    tid = team_id or ""
    graph_json = json.dumps(graph)
    payload_enc = _seal_graph({"graph": graph_json}, user_id, tid)
    conn.execute(
        "INSERT INTO workflow_graphs (workflow_id, name, description, graph, user_id, team_id, payload_encrypted, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (wf_id, name, description, graph_json, user_id, tid, payload_enc, now, now),
    )
    conn.commit()
    conn.close()
    return wf_id


def list_workflows(user_id=None, team_id=""):
    conn = _connect()
    if team_id == "__followed__":
        tc = get_connection()
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
            "SELECT * FROM workflow_graphs WHERE user_id=? OR user_id='' ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM workflow_graphs ORDER BY updated_at DESC").fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        tid = d.get("team_id", "")
        if d.get("payload_encrypted"):
            opened = _open_graph(d["payload_encrypted"], d.get("user_id", user_id or ""), tid)
            if opened.get("graph"):
                d["graph"] = json.loads(opened["graph"])
        else:
            d["graph"] = json.loads(d.get("graph") or "{}")
        results.append(d)
    return results


def get_workflow(workflow_id):
    conn = _connect()
    row = conn.execute("SELECT * FROM workflow_graphs WHERE workflow_id=?", (workflow_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        uid = d.get("user_id", "")
        tid = d.get("team_id", "")
        if d.get("payload_encrypted"):
            opened = _open_graph(d["payload_encrypted"], uid, tid)
            d["graph"] = json.loads(opened.get("graph", "{}"))
        else:
            d["graph"] = json.loads(d.get("graph") or "{}")
        return d
    return None


def update_workflow(workflow_id, name, graph, description="", team_id="", user_id=""):
    conn = _connect()
    now = _now()
    # Re-encrypt the graph
    graph_json = json.dumps(graph)
    tid = team_id or ""
    payload_enc = _seal_graph({"graph": graph_json}, user_id or "", tid)
    conn.execute(
        "UPDATE workflow_graphs SET name=?, graph=?, description=?, team_id=?, payload_encrypted=?, updated_at=? WHERE workflow_id=?",
        (name, graph_json, description, tid, payload_enc, now, workflow_id),
    )
    conn.commit()
    conn.close()


def delete_workflow(workflow_id):
    conn = _connect()
    conn.execute("DELETE FROM workflow_graphs WHERE workflow_id=?", (workflow_id,))
    conn.commit()
    conn.close()
