import uuid
import json
from datetime import datetime, timezone
from database.connection import get_connection


def _connect():
    return get_connection()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_document_db():
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY autoincrement,
            filename TEXT,
            file_id TEXT,
            snippet TEXT,
            author_user_id TEXT,
            team_id TEXT,
            file_type TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_document(filename: str,  snippet: str, author_user_id: str, team_id: str = None,file_type: str = "other"):
    conn = _connect()
    doc_id = str(uuid.uuid4())
    now = _now()
    try : 
        conn.execute("""
            INSERT INTO documents (filename, file_id, snippet, author_user_id, team_id, file_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (filename, doc_id, snippet, author_user_id, team_id, file_type, now, now))
        conn.commit()
    except Exception as e:
        print(f"Error occurred while inserting document: {e}")
    finally:
        conn.close()
    return doc_id

def get_document(doc_id: str):
    conn = _connect()
    row = conn.execute(
        "SELECT filename AS name, file_id AS doc_id, file_type, snippet, author_user_id FROM documents WHERE file_id=?",
        (doc_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def get_document_owner(doc_id: str):
    conn = _connect()
    row = conn.execute("SELECT author_user_id FROM documents WHERE file_id=?", (doc_id,)).fetchone()
    conn.close()
    return row["author_user_id"] if row else None

def delete_document(doc_id: str):
    conn = _connect()
    try:
        conn.execute("DELETE FROM documents WHERE file_id=?", (doc_id,))
        conn.commit()
    except Exception as e:
        print(f"Error occurred while deleting document: {e}")
        return False
    finally:
        conn.close()
    return True
    

def list_documents(author_user_id: str = None, team_id: str = None,
                   file_type: str = None, search: str = None, limit: int = None):
    conn = _connect()
    query = "SELECT filename AS name, file_id AS doc_id, snippet, file_type, created_at FROM documents"
    conditions = []
    params = []
    if author_user_id:
        conditions.append("author_user_id=?")
        params.append(author_user_id)
    if team_id:
        conditions.append("team_id=?")
        params.append(team_id)
    if file_type:
        conditions.append("file_type=?")
        params.append(file_type)
    if search:
        conditions.append("(filename LIKE ? OR snippet LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC"
    if limit:
        query += f" LIMIT {int(limit)}"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]