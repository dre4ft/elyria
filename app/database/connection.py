"""
Centralized database connection factory.
Supports SQLite (default) and PostgreSQL, configurable via .env.

Environment variables:
  DB_BACKEND=sqlite            # sqlite (default) or postgres
  DB_PATH=database.db          # SQLite file path
  PG_HOST=localhost            # PostgreSQL host
  PG_PORT=5432                 # PostgreSQL port
  PG_DATABASE=elyria           # PostgreSQL database name
  PG_USER=elyria               # PostgreSQL user
  PG_PASSWORD=elyria           # PostgreSQL password
"""

import os
import re
import sqlite3

from dotenv import load_dotenv

load_dotenv()

DB_BACKEND = os.getenv("DB_BACKEND", "sqlite").lower()


def is_postgres():
    return DB_BACKEND in ("postgres", "postgresql", "pg")


def get_connection():
    """Return a database connection (sqlite3 or psycopg2)."""
    if is_postgres():
        return _pg_connect()
    return _sqlite_connect()


def _sqlite_connect():
    db_path = os.getenv("DB_PATH", "database.db")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _pg_connect():
    import psycopg2
    import psycopg2.extras

    conn = psycopg2.connect(
        host=os.getenv("PG_HOST", "localhost"),
        port=int(os.getenv("PG_PORT", "5432")),
        dbname=os.getenv("PG_DATABASE", "elyria"),
        user=os.getenv("PG_USER", "elyria"),
        password=os.getenv("PG_PASSWORD", "elyria"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    conn.autocommit = False
    return _PgWrapper(conn)


class _PgWrapper:
    """Wraps a psycopg2 connection to behave like sqlite3.Connection."""

    def __init__(self, pg_conn):
        self._conn = pg_conn

    def cursor(self):
        return self._conn.cursor()

    def execute(self, sql, *args):
        sql = self._translate(sql)
        c = self._conn.cursor()
        if args:
            # args is a tuple of (params,) in sqlite3 convention
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
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._conn.__exit__(*args)

    @staticmethod
    def _translate(sql):
        """Convert SQLite SQL to PostgreSQL SQL for runtime queries."""
        if sql.strip().upper().startswith("PRAGMA"):
            return "SELECT 1"  # no-op for PRAGMA
        return sql.replace("?", "%s").replace("BOOLEAN", "BOOLEAN")

    @staticmethod
    def _translate_schema(sql):
        """Convert SQLite DDL to PostgreSQL DDL."""
        # Remove PRAGMA statements
        sql = re.sub(r"PRAGMA\s+\w+[^;]*;", "", sql, flags=re.IGNORECASE)
        # INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
        sql = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
            "SERIAL PRIMARY KEY",
            sql,
            flags=re.IGNORECASE,
        )
        # INTEGER PRIMARY KEY (standalone, not composite) → SERIAL PRIMARY KEY
        sql = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY(?=\s*[,)])",
            "SERIAL PRIMARY KEY",
            sql,
            flags=re.IGNORECASE,
        )
        return sql
