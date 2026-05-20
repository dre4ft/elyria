# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Bootstrap configuration loader — reads elyria.cfg at server startup.
No .env dependency. No DB dependency.

Priority:
  1. elyria.cfg (project root)
  2. Hardcoded defaults (this file)
"""

import os
from configparser import ConfigParser


_CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "elyria.cfg")
_parser = ConfigParser()


# ── Hardcoded defaults (used if .cfg is missing) ──
_DEFAULTS = {
    "server": {"host": "127.0.0.1", "port": "8000", "reload": "1"},
    "ssl": {"cert_path": "cert.pem", "key_path": "key.pem", "verify": "0"},
    "database": {
        "backend": "sqlite", "sqlite_path": "database.db",
        "pg_host": "localhost", "pg_port": "5432", "pg_database": "elyria",
        "pg_user": "elyria", "pg_password": "elyria",
        "pool_min": "2", "pool_max": "10",
    },
    "logging": {"level": "INFO", "dir": "logs"},
    "oidc": {
        "enabled": "0", "provider_name": "", "issuer": "",
        "client_id": "", "client_secret": "",
        "scope": "openid profile email", "button_label": "Connexion SSO",
    },
    "security": {
        "server_wrap_key": "",
        "blocked_hosts": "metadata.google.internal,169.254.169.254,instance-data,host.docker.internal",
    },
}


def _load():
    """Load elyria.cfg if it exists, merging with defaults."""
    result = {}
    # Start with defaults
    for section, params in _DEFAULTS.items():
        for key, value in params.items():
            result[f"{section}.{key}"] = value

    # Override with .cfg file
    for path in (_CFG_PATH, "elyria.cfg"):
        if os.path.isfile(path):
            _parser.read(path)
            for section in _parser.sections():
                for key, value in _parser[section].items():
                    result[f"{section}.{key}"] = value
            break

    return result


# Load once at import time
_config = _load()


def get(section: str, key: str, default: str = "") -> str:
    """Read a config value. e.g. get('server', 'host') → '127.0.0.1'."""
    return _config.get(f"{section}.{key}", default)


def get_int(section: str, key: str, default: int = 0) -> int:
    try:
        return int(get(section, key, str(default)))
    except (ValueError, TypeError):
        return default


def get_bool(section: str, key: str, default: bool = False) -> bool:
    val = get(section, key, str(default)).lower()
    return val in ("1", "true", "yes", "on")


def _get_env_overrides():
    """Read ELYRIA_SECTION_KEY env vars for runtime overrides."""
    for k, v in os.environ.items():
        if k.startswith("ELYRIA_") and k not in ("ELYRIA_PRODUCTION",):
            parts = k[7:].lower().split("_", 1)
            if len(parts) == 2:
                yield parts[0], parts[1], v
