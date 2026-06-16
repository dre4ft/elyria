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
            id TEXT PRIMARY KEY,
            filename TEXT,
            file_id TEXT,
            snippet TEXT,
            author_user_id TEXT,
            team_id TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_document(filename: str, file_id: str, snippet: str, author_user_id: str, team_id: str = None):
    conn = _connect()
    doc_id = str(uuid.uuid4())
    now = _now()
    try : 
        conn.execute("""
            INSERT INTO documents (id, filename, file_id, snippet, author_user_id, team_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (doc_id, filename, file_id, snippet, author_user_id, team_id, now, now))
        conn.commit()
    except Exception as e:
        print(f"Error occurred while inserting document: {e}")
    finally:
        conn.close()
    return doc_id

def get_document(doc_id: str):
    conn = _connect()
    row = conn.execute("SELECT filename FROM documents WHERE file_id=?", (doc_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def delete_document(doc_id: str):
    conn = _connect()
    conn.execute("DELETE FROM documents WHERE file_id=?", (doc_id,))
    conn.commit()
    conn.close()
    return True

def list_documents(author_user_id: str = None, team_id: str = None):
    conn = _connect()
    query = "SELECT filename, file_id, snippet FROM documents"
    conditions = []
    params = []
    if author_user_id:
        conditions.append("author_user_id=?")
        params.append(author_user_id)
    if team_id:
        conditions.append("team_id=?")
        params.append(team_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]