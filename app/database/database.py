import sqlite3
from threading import Lock

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
    created_at DATETIME NOT NULL
)
"""


INIT_USER = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    hashed_digest TEXT NOT NULL,
    salt TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    teams TEXT
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
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)
"""


def connect():
    global _IS_INIT

    if not _IS_INIT:
        init_db()

    conn = sqlite3.connect(
        DATABASE_NAME,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row



    return conn


def init_db():
    global _IS_INIT

    if _IS_INIT:
        return

    with _db_lock:
        if _IS_INIT:
            return

        conn = sqlite3.connect(
            DATABASE_NAME,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        cursor.execute(INIT_USER)
        cursor.execute(INIT_AI_MESSAGES)
        cursor.execute(INIT_REQUEST)
        cursor.execute(INIT_FOLDERS)
        cursor.execute(INIT_SAVED_REQUESTS)
        cursor.execute(INIT_KEYS)
        conn.commit()
        conn.close()

        _IS_INIT = True