# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import os
import sqlite3
from threading import Lock
from database.connection import get_connection

DATABASE_NAME = "database.db"


_db_lock = Lock()
_IS_INIT = False


INIT_AI_MESSAGES = """
CREATE TABLE IF NOT EXISTS ai_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL
)
"""

INIT_KEYS = """
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT UNIQUE NOT NULL,
    key_value TEXT NOT NULL,
    user_id TEXT NOT NULL,
    refresh_token_hash TEXT DEFAULT '',
    refresh_count INTEGER DEFAULT 0,
    max_refreshes INTEGER DEFAULT 2,
    created_at DATETIME NOT NULL
)
"""

INIT_USER = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    hashed_digest TEXT NOT NULL DEFAULT '',
    salt TEXT NOT NULL DEFAULT '',
    username TEXT UNIQUE NOT NULL,
    teams TEXT,
    oidc_sub TEXT DEFAULT '',
    oidc_provider TEXT DEFAULT '',
    oidc_id_token TEXT DEFAULT '',
    oidc_access_token TEXT DEFAULT '',
    oidc_refresh_token TEXT DEFAULT '',
    oidc_expires_at REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME
)
"""

INIT_REQUEST = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT UNIQUE NOT NULL,
    date DATETIME NOT NULL, 
    author_user_id TEXT NOT NULL,
    is_done_by_ai BOOLEAN NOT NULL, 
    request_url TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_status_code INTEGER NOT NULL,
    request_headers TEXT,  
    request_body TEXT,
    request_body_is_json BOOLEAN,     
    response_headers TEXT,
    response_body TEXT,
    response_body_is_json BOOLEAN
)
"""


INIT_FOLDERS = """
CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    parent_id TEXT,
    author_user_id TEXT NOT NULL,
    created_at DATETIME NOT NULL
)
"""

INIT_SAVED_REQUESTS = """
CREATE TABLE IF NOT EXISTS saved_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    saved_request_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    folder_id TEXT,
    method TEXT NOT NULL DEFAULT 'GET',
    url TEXT NOT NULL DEFAULT '',
    headers TEXT,
    body TEXT,
    body_is_json BOOLEAN,
    is_done_by_ai BOOLEAN NOT NULL DEFAULT 0,
    author_user_id TEXT NOT NULL,
    team_id TEXT DEFAULT '',
    payload_encrypted TEXT DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)
"""


def connect():
    global _IS_INIT
    if not _IS_INIT:
        init_db()
    return get_connection()


def _table_columns(cursor, table: str) -> set:
    """Return the set of column names for a table (works on SQLite and PostgreSQL)."""
    db_backend = os.getenv("DB_BACKEND", "sqlite")
    if db_backend == "postgres":
        cursor.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
            (table,),
        )
        return {row[0] for row in cursor.fetchall()}
    else:
        return {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}


def _safe_add_column(cursor, table: str, col: str, col_def: str):
    """Add a column if it doesn't exist (DB-agnostic)."""
    if col not in _table_columns(cursor, table):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")


def _migrate_crypto_columns(cursor, conn):
    """Add encryption columns to tables that need them."""
    for tbl in ("saved_requests", "workflow_graphs"):
        _safe_add_column(cursor, tbl, "payload_encrypted", "TEXT DEFAULT ''")
        _safe_add_column(cursor, tbl, "team_id", "TEXT DEFAULT ''")
    _safe_add_column(cursor, "users", "wrapped_user_key", "TEXT DEFAULT ''")
    _safe_add_column(cursor, "team_users", "encrypted_team_key", "TEXT DEFAULT ''")
    # Refresh token columns on keys table
    for col, cdef in [("refresh_token_hash", "TEXT DEFAULT ''"), ("refresh_count", "INTEGER DEFAULT 0"), ("max_refreshes", "INTEGER DEFAULT 2")]:
        _safe_add_column(cursor, "keys", col, cdef)
    conn.commit()


def _migrate_oidc_columns(cursor, conn):
    """Add OIDC columns to users table if they don't exist (safe to call multiple times)."""
    oidc_cols = [
        ("oidc_sub", "TEXT DEFAULT ''"),
        ("oidc_provider", "TEXT DEFAULT ''"),
        ("oidc_id_token", "TEXT DEFAULT ''"),
        ("oidc_access_token", "TEXT DEFAULT ''"),
        ("oidc_refresh_token", "TEXT DEFAULT ''"),
        ("oidc_expires_at", "REAL DEFAULT 0"),
        ("created_at", "TEXT DEFAULT ''"),
        ("last_login_at", "TEXT DEFAULT ''"),
    ]
    existing = _table_columns(cursor, "users")
    for col_name, col_def in oidc_cols:
        if col_name not in existing:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
    conn.commit()


def init_db():
    global _IS_INIT
    if _IS_INIT:
        return
    with _db_lock:
        if _IS_INIT:
            return
        conn = get_connection()
        c = conn.cursor()
        c.execute(INIT_USER)
        c.execute(INIT_AI_MESSAGES)
        c.execute(INIT_REQUEST)
        c.execute(INIT_FOLDERS)
        c.execute(INIT_SAVED_REQUESTS)
        c.execute(INIT_KEYS)
        conn.commit()
        # ── Migrations: add columns that didn't exist in older schemas ──
        _migrate_oidc_columns(c, conn)
        _migrate_crypto_columns(c, conn)
        conn.close()
        _IS_INIT = True