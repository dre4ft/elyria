# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Central proxy management — ensures all outgoing traffic uses the configured proxy.

Two layers:
  1. Global env vars (HTTP_PROXY / HTTPS_PROXY) set at startup from DB — covers
     libraries that read env vars automatically (requests, urllib, httpx, ollama).
  2. Per-request context (ContextVar) set by middleware — allows per-user proxy
     overrides, and updates env vars for the duration of the request.

Libraries that DON'T read env vars (Playwright, aiohttp) must read from
get_current_proxy_url() / get_current_proxy_dict() explicitly.
"""

import os
from contextvars import ContextVar

_current_proxy_url: ContextVar = ContextVar("current_proxy_url", default=None)
_global_proxy_url: str | None = None


def init_global_proxy():
    """Set HTTP_PROXY / HTTPS_PROXY env vars from the first enabled proxy in DB."""
    global _global_proxy_url
    _global_proxy_url = _load_first_enabled_proxy()
    _apply_env(_global_proxy_url)


def refresh_global_proxy():
    """Re-read DB and update env vars (called after proxy config changes)."""
    global _global_proxy_url
    _global_proxy_url = _load_first_enabled_proxy()
    _apply_env(_global_proxy_url)


def set_current_proxy(url: str | None):
    """Set proxy for the current request context + env vars.
    Pass None to restore the global proxy."""
    _current_proxy_url.set(url)
    if url is not None:
        _apply_env(url)
    else:
        _apply_env(_global_proxy_url)


def get_current_proxy_url() -> str | None:
    """Return the effective proxy URL, or None."""
    try:
        url = _current_proxy_url.get()
        if url is not None:
            return url or None
    except LookupError:
        pass
    return os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY") or None


def get_current_proxy_dict() -> dict | None:
    """Return {'http': url, 'https': url} or None."""
    url = get_current_proxy_url()
    if url:
        return {"http": url, "https": url}
    return None


def _load_first_enabled_proxy() -> str | None:
    """Query DB for the first enabled proxy URL. Returns None if none found."""
    try:
        from database.connection import get_connection
        conn = get_connection()
        row = conn.execute(
            """SELECT p.url FROM user_favorite_proxy f
               JOIN proxies p ON f.proxy_id = p.proxy_id
               WHERE f.enabled = 1 AND p.url != ''
               LIMIT 1"""
        ).fetchone()
        conn.close()
        if row and row["url"]:
            return row["url"]
    except Exception:
        pass
    return None


def _apply_env(url: str | None):
    """Set or clear HTTP_PROXY / HTTPS_PROXY / NO_PROXY env vars."""
    if url:
        os.environ["HTTP_PROXY"] = url
        os.environ["HTTPS_PROXY"] = url
        os.environ["NO_PROXY"] = "localhost,127.0.0.1,.local"
    else:
        os.environ.pop("HTTP_PROXY", None)
        os.environ.pop("HTTPS_PROXY", None)
        os.environ.pop("NO_PROXY", None)
