# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Centralized database connection factory with connection pooling.

Supports SQLite (default, pool of 5) and PostgreSQL (pool of 5-20).
Config via env vars: DB_BACKEND, DB_PATH, PG_HOST, PG_PORT, PG_DATABASE,
PG_USER, PG_PASSWORD, DB_POOL_MIN, DB_POOL_MAX.
"""

import os
import re
import sqlite3
import threading


# ── Config from environment (falling back to hardcoded) ──

_DB_BACKEND = os.getenv("DB_BACKEND", os.getenv("DB_PATH", "").endswith(".db") and "sqlite" or "sqlite")
_DB_PATH = os.getenv("DB_PATH", "database.db")
_PG_HOST = os.getenv("PG_HOST", "localhost")
_PG_PORT = int(os.getenv("PG_PORT", "5432"))
_PG_DATABASE = os.getenv("PG_DATABASE", "elyria")
_PG_USER = os.getenv("PG_USER", "elyria")
_PG_PASSWORD = os.getenv("PG_PASSWORD", "elyria")
_POOL_MIN = int(os.getenv("DB_POOL_MIN", "2"))
_POOL_MAX = int(os.getenv("DB_POOL_MAX", "10"))


def is_postgres():
    return _DB_BACKEND in ("postgres", "postgresql", "pg")


# ── SQLite pool (thread-local, WAL mode) ──

_sqlite_pool = []
_sqlite_lock = threading.Lock()


def _sqlite_connect():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


class _SqliteWrapper:
    """Wraps sqlite3.Connection so .close() returns to pool instead of closing."""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self._valid = True

    def close(self):
        if self._valid:
            _sqlite_put(self._conn)
            self._valid = False

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _sqlite_get():
    """Get a SQLite connection from the pool or create one."""
    with _sqlite_lock:
        if _sqlite_pool:
            conn = _sqlite_pool.pop()
            try:
                conn.execute("SELECT 1")
                return _SqliteWrapper(conn)
            except Exception:
                pass  # stale, create new
        return _SqliteWrapper(_sqlite_connect())


def _sqlite_put(conn):
    """Return a raw SQLite connection to the pool."""
    with _sqlite_lock:
        if len(_sqlite_pool) < _POOL_MAX:
            _sqlite_pool.append(conn)
        else:
            conn.close()


# ── PostgreSQL pool ──

_pg_pool = None
_pg_lock = threading.Lock()


def _pg_pool_get():
    global _pg_pool
    with _pg_lock:
        if _pg_pool is None:
            import psycopg2
            from psycopg2 import pool as pgpool
            import psycopg2.extras

            _pg_pool = pgpool.ThreadedConnectionPool(
                _POOL_MIN,
                _POOL_MAX,
                host=_PG_HOST,
                port=_PG_PORT,
                dbname=_PG_DATABASE,
                user=_PG_USER,
                password=_PG_PASSWORD,
            )
        return _PgWrapper(_pg_pool.getconn())


def _pg_pool_put(conn):
    with _pg_lock:
        if _pg_pool:
            _pg_pool.putconn(conn._conn)


# ── Public API (backward-compatible) ──

def get_connection():
    """Return a database connection from the pool. Caller MUST close it."""
    if is_postgres():
        return _pg_pool_get()
    return _sqlite_get()


def close_connection(conn):
    """Return a connection to the pool."""
    if conn is None:
        return
    if is_postgres():
        _pg_pool_put(conn)
    else:
        _sqlite_put(conn)


# ── Context manager ──

class Connection:
    """Context manager for pooled connections: `with Connection() as conn:`"""

    def __init__(self):
        self.conn = None

    def __enter__(self):
        self.conn = get_connection()
        return self.conn

    def __exit__(self, *args):
        close_connection(self.conn)


# ── PostgreSQL wrapper (unchanged logic, uses valid=True marker) ──

class _PgWrapper:
    """Wraps a psycopg2 connection to behave like sqlite3.Connection."""

    def __init__(self, pg_conn):
        self._conn = pg_conn
        self._valid = True

    def cursor(self):
        return self._conn.cursor()

    def execute(self, sql, *args):
        sql = self._translate(sql)
        c = self._conn.cursor()
        if args:
            params = args[0] if len(args) == 1 and isinstance(args[0], (tuple, list)) else args
            c.execute(sql, params)
        else:
            c.execute(sql)
        return c

    def executescript(self, sql):
        sql = self._translate_schema(sql)
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt:
                c = self._conn.cursor()
                c.execute(stmt)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        if self._valid:
            self._conn.rollback()
            self._valid = False

    def __getattr__(self, name):
        return getattr(self._conn, name)

    @staticmethod
    def _translate(sql):
        if sql.strip().upper().startswith("PRAGMA"):
            return "SELECT 1"
        return sql.replace("?", "%s").replace("BOOLEAN", "BOOLEAN")

    @staticmethod
    def _translate_schema(sql):
        sql = re.sub(r"PRAGMA\s+\w+[^;]*;", "", sql, flags=re.IGNORECASE)
        sql = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
            "SERIAL PRIMARY KEY",
            sql,
            flags=re.IGNORECASE,
        )
        return sql
