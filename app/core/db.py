# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Unified DB helpers — consistent connection handling, pagination, error wrapping.

Usage:
  from core.db import query, query_one, execute, paginate, transactional
"""

from contextlib import contextmanager
from database.connection import get_connection


def query(sql: str, params: tuple = ()) -> list[dict]:
    """Run a SELECT and return rows as dicts. Closes connection automatically."""
    conn = get_connection()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def query_one(sql: str, params: tuple = ()) -> dict | None:
    """Run a SELECT and return the first row as a dict, or None."""
    conn = get_connection()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def execute(sql: str, params: tuple = ()) -> int:
    """Run INSERT/UPDATE/DELETE. Returns rowcount. Commits and closes."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


@contextmanager
def transactional():
    """Context manager for multi-statement transactions. Commits on success, rolls back on error."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def paginate(sql: str, params: tuple, page: int, limit: int = 20) -> dict:
    """Run a paginated SELECT. Returns {'items': [...], 'total': int, 'page': int, 'pages': int}."""
    if page < 1:
        page = 1
    if limit < 1 or limit > 100:
        limit = 20

    conn = get_connection()
    try:
        # Count total
        count_sql = f"SELECT COUNT(*) as cnt FROM ({sql})"
        total_row = conn.execute(count_sql, params).fetchone()
        total = total_row[0] if total_row else 0
        pages = max(1, (total + limit - 1) // limit)

        # Fetch page
        offset = (page - 1) * limit
        page_sql = f"{sql} LIMIT {limit} OFFSET {offset}"
        rows = conn.execute(page_sql, params).fetchall()
        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "pages": pages,
            "limit": limit,
        }
    finally:
        conn.close()
