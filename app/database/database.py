# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import os
import sqlite3
from threading import Lock
from database.connection import get_connection

DATABASE_NAME = "database.db"


_db_lock = Lock()
_IS_INIT = False


INIT_COLLECTION_KEYS = """
CREATE TABLE IF NOT EXISTS collection_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_id TEXT UNIQUE NOT NULL,
    encrypted_dek TEXT NOT NULL,
    team_id TEXT DEFAULT ''
)
"""

INIT_VERIFICATION_TOKENS = """
CREATE TABLE IF NOT EXISTS verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    resend_count INTEGER DEFAULT 0,
    last_resend_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
)
"""

INIT_AI_MESSAGES = """
CREATE TABLE IF NOT EXISTS ai_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    payload_encrypted TEXT DEFAULT ''
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
    email TEXT DEFAULT '',
    email_verified INTEGER DEFAULT 0,
    verification_code TEXT DEFAULT '',
    verification_code_expiry TEXT DEFAULT '',
    oidc_sub TEXT DEFAULT '',
    oidc_provider TEXT DEFAULT '',
    oidc_id_token TEXT DEFAULT '',
    oidc_access_token TEXT DEFAULT '',
    oidc_refresh_token TEXT DEFAULT '',
    oidc_expires_at REAL DEFAULT 0,
    wrapped_user_key TEXT DEFAULT '',
    salt_pw TEXT DEFAULT '',
    salt_auth TEXT DEFAULT '',
    salt_rec TEXT DEFAULT '',
    auth_verifier TEXT DEFAULT '',
    master_key_blob_pw TEXT DEFAULT '',
    master_key_blob_rec TEXT DEFAULT '',
    recovery_words_shown INTEGER DEFAULT 0,
    pending_recovery TEXT DEFAULT '',
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TEXT DEFAULT '',
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
    response_body_is_json BOOLEAN,
    payload_encrypted TEXT DEFAULT ''
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
        c.execute(INIT_VERIFICATION_TOKENS)
        c.execute(INIT_COLLECTION_KEYS)
        from database.ctx_mgmt import INIT_USER_CTX
        c.execute(INIT_USER_CTX)
        conn.commit()
        conn.close()
        _IS_INIT = True