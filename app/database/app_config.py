# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Centralized enterprise configuration — single source of truth.
All settings stored in DB. No .env dependency at runtime.

Tables:
  app_config          — key/value store for all settings
  app_fqdn_whitelist  — FQDN whitelists by category (fetch, proxy, llm)
  app_provider_toggle — enable/disable provider types
"""

import re
import sqlite3
from database.connection import get_connection


def _connect():
    return get_connection()


# ── Schema init ───────────────────────────────────────────────────────
def init():
    c = _connect()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS app_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS app_fqdn_whitelist (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL DEFAULT 'fetch',
            pattern  TEXT NOT NULL,
            enabled  INTEGER DEFAULT 1,
            UNIQUE(category, pattern)
        );
        CREATE TABLE IF NOT EXISTS app_provider_toggle (
            provider_type TEXT PRIMARY KEY,
            enabled       INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS app_api_keys (
            key_name  TEXT PRIMARY KEY,
            key_value TEXT NOT NULL DEFAULT ''
        );
    """)
    c.commit()
    c.close()
init()


# ── Defaults ──────────────────────────────────────────────────────────
_DEFAULTS = {
    "app.host":       "127.0.0.1",
    "app.port":       "8000",
    "app.reload":     "1",
    "catcher.port":               "6767",
    "catcher.intercept_enabled":  "0",
    "ssl.cert_path":  "cert.pem",
    "ssl.key_path":   "key.pem",
    "db.backend":     "sqlite",
    "db.sqlite.path": "database.db",
    "db.pg.host":     "localhost",
    "db.pg.port":     "5432",
    "db.pg.database": "elyria",
    "db.pg.user":     "elyria",
    "db.pg.password": "elyria",
    # ── OIDC / SSO ──
    # Pour tester : lancer `python tools/oidc_test_provider.py` puis passer
    # oidc.enabled à "1"
    "oidc.enabled":           "0",
    "oidc.provider_name":     "test",
    "oidc.issuer":            "http://localhost:9001",
    "oidc.client_id":         "elyria-test",
    "oidc.client_secret":     "test-secret",
    "oidc.scope":             "openid profile email",
    "oidc.button_label":      "Test SSO",
    # ── SSRF protection ──
    "ssrf.blocked_hosts":     "metadata.google.internal,169.254.169.254,instance-data,169.254.170.2",
    # ── Logging ──
    "log.level":              "INFO",
    "log.dir":                "logs",
}

_DEFAULT_FQDN = {
    "fetch": ["localhost", "127.0.0.1", "*.example.com"],
    "proxy": ["localhost", "127.0.0.1"],
    "llm":   ["api.openai.com", "localhost", "127.0.0.1", "*.ollama.com"],
}

_DEFAULT_PROVIDERS = ["openai", "ollama", "lmstudio", "anthropic", "deepseek"]


def _seed_defaults():
    c = _connect()
    for k, v in _DEFAULTS.items():
        c.execute("INSERT OR IGNORE INTO app_config (key,value) VALUES(?,?)", (k, v))
    # Fixup: ensure SSL defaults are set even for existing rows that got seeded with ""
    c.execute("UPDATE app_config SET value='cert.pem' WHERE key='ssl.cert_path' AND value=''")
    c.execute("UPDATE app_config SET value='key.pem' WHERE key='ssl.key_path' AND value=''")
    # Fixup: seed OIDC defaults for rows that were created empty before defaults existed
    for k in ("oidc.issuer", "oidc.client_id", "oidc.client_secret",
              "oidc.provider_name", "oidc.scope", "oidc.button_label"):
        c.execute(
            "UPDATE app_config SET value = ? WHERE key = ? AND value = ''",
            (_DEFAULTS[k], k),
        )
    # Ensure oidc.enabled exists (but don't force-enable it)
    c.execute("INSERT OR IGNORE INTO app_config (key,value) VALUES('oidc.enabled','0')")
    for cat, hosts in _DEFAULT_FQDN.items():
        for h in hosts:
            c.execute("INSERT OR IGNORE INTO app_fqdn_whitelist (category,pattern) VALUES(?,?)", (cat, h))
    for pt in _DEFAULT_PROVIDERS:
        c.execute("INSERT OR IGNORE INTO app_provider_toggle (provider_type,enabled) VALUES(?,1)", (pt,))
    # Seed default API keys (empty, to be filled via API)
    for kn in ("openai_api_key",):
        c.execute("INSERT OR IGNORE INTO app_api_keys (key_name,key_value) VALUES(?,'')", (kn,))
    c.commit()
    c.close()
_seed_defaults()


# ── Keys that contain secrets → encrypted with server wrap key ──
_SECRET_KEYS = {
    "db.pg.password", "oidc.client_secret",
    "ssl.cert_path", "ssl.key_path",
}


def _decrypt_config(row):
    """If payload_encrypted present, decrypt value from it."""
    d = dict(row) if not isinstance(row, dict) else row
    if d.get("payload_encrypted"):
        from database.crypto_store import open_system
        data = open_system(d["payload_encrypted"])
        if data and "value" in data:
            return data["value"]
    return d.get("value", "")


# ── Public API ────────────────────────────────────────────────────────
def get(key: str, default: str = "") -> str:
    """Read a config value. Cached 30s. Decrypts if secret."""
    from core.cache import cache
    ck = f"cfg:{key}"
    val = cache.get(ck)
    if val is not None:
        return val
    c = _connect()
    try:
        row = c.execute("SELECT value, payload_encrypted FROM app_config WHERE key=?", (key,)).fetchone()
    except sqlite3.OperationalError:
        # payload_encrypted column doesn't exist yet (before migration)
        row = c.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
    c.close()
    if row:
        d = dict(row) if not isinstance(row, dict) else row
        val = _decrypt_config(d) if key in _SECRET_KEYS else d.get("value", "")
    else:
        val = _DEFAULTS.get(key, default)
    cache.set(ck, val, ttl=30)
    return val


def get_int(key: str, default: int = 0) -> int:
    try:
        return int(get(key, str(default)))
    except (ValueError, TypeError):
        return default


def set_kv(key: str, value: str):
    c = _connect()
    payload = ""
    plaintext = str(value)
    if key in _SECRET_KEYS and value:
        from database.crypto_store import seal_system
        payload = seal_system({"value": str(value)})
        plaintext = ""  # clear plaintext for secret keys
    c.execute(
        "INSERT OR REPLACE INTO app_config (key, value, payload_encrypted) VALUES(?,?,?)",
        (key, plaintext, payload),
    )
    c.commit()
    c.close()
    from core.cache import cache
    cache.invalidate(f"cfg:{key}")


def get_all() -> dict:
    c = _connect()
    rows = c.execute("SELECT key, value, payload_encrypted FROM app_config ORDER BY key").fetchall()
    c.close()
    result = dict(_DEFAULTS)
    for r in rows:
        d = dict(r) if not isinstance(r, dict) else dict(r)
        result[d["key"]] = _decrypt_config(d) if d["key"] in _SECRET_KEYS else d.get("value", "")
    return result


# ── FQDN whitelist ────────────────────────────────────────────────────
def _fqdn_matches(host: str, pattern: str) -> bool:
    """Check if host matches a pattern (exact or wildcard *.domain)."""
    host = host.lower().strip()
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def is_fqdn_allowed(hostname: str, category: str = "fetch") -> bool:
    """Check if hostname is in the whitelist for the given category."""
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(":")[0].lower().strip()
    c = _connect()
    rows = c.execute(
        "SELECT pattern FROM app_fqdn_whitelist WHERE category=? AND enabled=1",
        (category,),
    ).fetchall()
    c.close()
    for r in rows:
        if _fqdn_matches(host, r["pattern"]):
            return True
    return False


def get_fqdn_whitelist(category: str = None):
    c = _connect()
    if category:
        rows = c.execute(
            "SELECT * FROM app_fqdn_whitelist WHERE category=? ORDER BY pattern",
            (category,),
        ).fetchall()
    else:
        rows = c.execute("SELECT * FROM app_fqdn_whitelist ORDER BY category, pattern").fetchall()
    c.close()
    return [dict(r) for r in rows]


def add_fqdn(category: str, pattern: str):
    c = _connect()
    try:
        c.execute("INSERT INTO app_fqdn_whitelist (category,pattern) VALUES(?,?)", (category, pattern.lower().strip()))
        c.commit()
    except sqlite3.IntegrityError:
        pass
    c.close()


def remove_fqdn(fqdn_id: int):
    c = _connect()
    c.execute("DELETE FROM app_fqdn_whitelist WHERE id=?", (fqdn_id,))
    c.commit()
    c.close()


# ── Provider toggles ──────────────────────────────────────────────────
def is_provider_enabled(provider_type: str) -> bool:
    c = _connect()
    row = c.execute(
        "SELECT enabled FROM app_provider_toggle WHERE provider_type=?",
        (provider_type.lower(),),
    ).fetchone()
    c.close()
    return bool(row["enabled"]) if row else True  # enabled by default


def get_provider_toggles():
    c = _connect()
    rows = c.execute("SELECT * FROM app_provider_toggle ORDER BY provider_type").fetchall()
    c.close()
    return [dict(r) for r in rows]


def set_provider_toggle(provider_type: str, enabled: bool):
    c = _connect()
    c.execute(
        "INSERT OR REPLACE INTO app_provider_toggle (provider_type,enabled) VALUES(?,?)",
        (provider_type.lower(), int(enabled)),
    )
    c.commit()
    c.close()


# ── API keys ──────────────────────────────────────────────────────────
def get_api_key(name: str) -> str:
    c = _connect()
    row = c.execute("SELECT key_value, payload_encrypted FROM app_api_keys WHERE key_name=?", (name,)).fetchone()
    c.close()
    if not row:
        return ""
    if row["payload_encrypted"]:
        from database.crypto_store import open_system
        data = open_system(row["payload_encrypted"])
        return data.get("key_value", "") if data else ""
    return row["key_value"] or ""


def set_api_key(name: str, value: str):
    c = _connect()
    from database.crypto_store import seal_system
    payload = seal_system({"key_value": value}) if value else ""
    c.execute(
        "INSERT OR REPLACE INTO app_api_keys (key_name, key_value, payload_encrypted) VALUES(?,?,?)",
        (name, "", payload),
    )
    c.commit()
    c.close()


def get_all_api_keys():
    c = _connect()
    rows = c.execute("SELECT key_name, key_value, payload_encrypted FROM app_api_keys ORDER BY key_name").fetchall()
    c.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("payload_encrypted"):
            from database.crypto_store import open_system
            data = open_system(d["payload_encrypted"])
            d["key_value"] = data.get("key_value", "") if data else ""
        result.append(d)
    return result


# ── URL / host utilities ──────────────────────────────────────────────
def extract_host(url: str) -> str:
    """Extract hostname from a URL string."""
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def validate_fqdn_or_raise(url: str, category: str = "fetch"):
    """Raise HTTPException if the URL's host is not in the whitelist."""
    host = extract_host(url)
    if not host:
        return  # relative URLs or unparseable — let the request layer handle it
    if not is_fqdn_allowed(host, category):
        from fastapi import HTTPException
        raise HTTPException(403, "Host not allowed")
