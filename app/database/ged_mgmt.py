# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""GED (Gestion Electronique de Documents) — database layer."""

import uuid
import os
from datetime import datetime, timezone
from database.connection import get_connection

GED_STORAGE = os.path.join(os.path.dirname(__file__), "..", "..", "ged_storage")

def _conn():
    return get_connection()

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def init_ged():
    conn = _conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ged_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            snippet TEXT DEFAULT '',
            file_type TEXT NOT NULL DEFAULT 'other',
            file_path TEXT NOT NULL DEFAULT '',
            user_id TEXT NOT NULL DEFAULT '',
            team_id TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migrations
    for col, cdef in [("snippet", "TEXT DEFAULT ''")]:
        try: conn.execute(f"ALTER TABLE ged_documents ADD COLUMN {col} {cdef}")
        except: pass
    conn.commit()
    conn.close()
    os.makedirs(GED_STORAGE, exist_ok=True)

init_ged()

VALID_TYPES = {"openapi", "arazzo", "markdown", "other"}


def create_document(name: str, file_type: str, user_id: str, file_content: bytes,
                    snippet: str = "", team_id: str = "", original_filename: str = "") -> str:
    """Store file on disk and metadata in DB. Returns doc_id."""
    if file_type not in VALID_TYPES:
        file_type = "other"
    doc_id = str(uuid.uuid4())
    ext = os.path.splitext(original_filename or name)[1] or ".bin"
    safe_filename = f"{doc_id}{ext}"
    disk_path = os.path.join(GED_STORAGE, safe_filename)
    with open(disk_path, "wb") as f:
        f.write(file_content)
    conn = _conn()
    conn.execute(
        "INSERT INTO ged_documents (doc_id, name, snippet, file_type, file_path, user_id, team_id, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (doc_id, name, snippet, file_type, disk_path, user_id, team_id, _now(), _now()),
    )
    conn.commit()
    conn.close()
    return doc_id


def list_documents(user_id: str = "", team_id: str = "", file_type: str = "",
                   search: str = "", limit: int = 50, offset: int = 0) -> list[dict]:
    """List documents scoped to user/team."""
    conn = _conn()
    q = "SELECT * FROM ged_documents WHERE 1=1"
    args = []
    if user_id:
        q += " AND (user_id=? OR team_id IN (SELECT team_id FROM team_users WHERE user_id=?))"
        args.extend([user_id, user_id])
    if team_id:
        q += " AND team_id=?"
        args.append(team_id)
    if file_type:
        q += " AND file_type=?"
        args.append(file_type)
    if search:
        q += " AND (name LIKE ? OR snippet LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%"])
    q += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_document(doc_id: str, user_id: str = "") -> dict | None:
    """Get document metadata. Checks ownership if user_id provided."""
    conn = _conn()
    if user_id:
        row = conn.execute(
            "SELECT * FROM ged_documents WHERE doc_id=? AND (user_id=? OR team_id IN (SELECT team_id FROM team_users WHERE user_id=?))",
            (doc_id, user_id, user_id),
        ).fetchone()
    else:
        row = conn.execute("SELECT * FROM ged_documents WHERE doc_id=?", (doc_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_document(doc_id: str, user_id: str, **kwargs) -> bool:
    """Update document metadata (name, snippet, team_id)."""
    allowed = {"name", "snippet", "team_id", "file_type"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False
    updates["updated_at"] = _now()
    conn = _conn()
    sets = ", ".join(f"{k}=?" for k in updates)
    args = list(updates.values()) + [doc_id, user_id]
    conn.execute(f"UPDATE ged_documents SET {sets} WHERE doc_id=? AND user_id=?", args)
    conn.commit()
    ok = conn.total_changes > 0
    conn.close()
    return ok


def delete_document(doc_id: str, user_id: str) -> bool:
    """Delete document file and metadata. Checks ownership."""
    conn = _conn()
    row = conn.execute("SELECT file_path FROM ged_documents WHERE doc_id=? AND user_id=?", (doc_id, user_id)).fetchone()
    if not row:
        conn.close()
        return False
    path = row["file_path"]
    conn.execute("DELETE FROM ged_documents WHERE doc_id=? AND user_id=?", (doc_id, user_id))
    conn.commit()
    conn.close()
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
    return True


def read_document_file(doc_id: str, user_id: str = "") -> tuple[bytes, str, str] | None:
    """Read document file from disk. Returns (content, filename, mime_type). Checks ownership."""
    doc = get_document(doc_id, user_id) if user_id else get_document(doc_id)
    if not doc or not doc.get("file_path"):
        return None
    path = doc["file_path"]
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        content = f.read()
    filename = doc.get("name", "document")
    ext = os.path.splitext(path)[1]
    mime_map = {".json": "application/json", ".yaml": "text/yaml", ".yml": "text/yaml",
                ".md": "text/markdown", ".txt": "text/plain"}
    mime = mime_map.get(ext, "application/octet-stream")
    return content, filename, mime
