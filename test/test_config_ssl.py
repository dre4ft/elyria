# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
TU + TNR — Validation du système de config (.cfg) et SSL verify.

Couvre :
- Chargement du fichier .cfg
- Priorité : .cfg → defaults → env vars
- SSL verify : système forcé True, utilisateur paramétrable
- _make_request() avec verify_ssl
- RESTRequest accepte verify_ssl
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))


# ═══════════════════════════════════════════════════════════════
# Config File Loading
# ═══════════════════════════════════════════════════════════════

class TestConfigFileLoading:
    """Validation du chargement du fichier elyria.cfg."""

    def test_config_loads_all_sections(self):
        """Toutes les sections sont chargées avec leurs valeurs."""
        from core.config import get
        sections = {
            "server": ["host", "port", "reload"],
            "ssl": ["cert_path", "key_path", "verify"],
            "database": ["backend", "sqlite_path", "pg_host", "pg_port"],
            "logging": ["level", "dir"],
            "oidc": ["enabled", "issuer", "client_id", "client_secret"],
            "security": ["server_wrap_key", "blocked_hosts"],
        }
        for section, keys in sections.items():
            for key in keys:
                val = get(section, key, "NOTFOUND")
                assert val != "NOTFOUND", f"Missing: [{section}].{key}"

    def test_config_default_values(self):
        """Les valeurs par défaut sont cohérentes."""
        from core.config import get
        assert get("server", "host") in ("127.0.0.1", "0.0.0.0")
        assert get("server", "port") in ("8000", "8080") or get("server", "port").isdigit()
        assert get("database", "backend") in ("sqlite", "postgres")
        assert get("logging", "level") in ("DEBUG", "INFO", "WARNING", "ERROR")

    def test_get_int(self):
        from core.config import get_int
        port = get_int("server", "port", 8000)
        assert isinstance(port, int)
        assert 1 <= port <= 65535

    def test_get_bool(self):
        from core.config import get_bool
        reload_val = get_bool("server", "reload", False)
        assert isinstance(reload_val, bool)

    def test_config_used_by_connection(self):
        """La config est bien lue par connection.py (DB backend)."""
        from database.connection import is_postgres
        # Should not crash — config is loaded
        result = is_postgres()
        assert isinstance(result, bool)

    def test_config_cfg_file_exists(self):
        """Le fichier elyria.cfg existe à la racine du projet."""
        cfg_paths = [
            os.path.join(os.path.dirname(__file__), "..", "elyria.cfg"),
            os.path.join(os.path.dirname(__file__), "..", "app", "..", "elyria.cfg"),
        ]
        found = any(os.path.isfile(p) for p in cfg_paths)
        assert found, "elyria.cfg must exist at project root"


class TestConfigPriority:
    """Validation de la chaîne de priorité config."""

    def test_defaults_take_effect(self):
        """Sans override, les defaults sont utilisés."""
        from core.config import get
        # SQLite path should have a default value
        path = get("database", "sqlite_path", "UNSET")
        assert path != "UNSET"

    def test_config_is_deterministic(self):
        """Deux appels à get() retournent la même valeur."""
        from core.config import get
        a = get("server", "host", "127.0.0.1")
        b = get("server", "host", "127.0.0.1")
        assert a == b


# ═══════════════════════════════════════════════════════════════
# SSL Verify Logic
# ═══════════════════════════════════════════════════════════════

class TestSSLVerify:
    """Validation du mécanisme SSL verify à 3 niveaux."""

    def test_make_request_accepts_verify_ssl_param(self):
        """_make_request accepte le paramètre verify_ssl."""
        import inspect
        from request_manager.request_api import _make_request
        sig = inspect.signature(_make_request)
        assert "verify_ssl" in sig.parameters, "_make_request must accept verify_ssl"

    def test_handle_request_accepts_verify_ssl(self):
        """handle_request accepte verify_ssl."""
        import inspect
        from request_manager.request_api import handle_request
        sig = inspect.signature(handle_request)
        assert "verify_ssl" in sig.parameters, "handle_request must accept verify_ssl"

    def test_rest_request_has_verify_ssl_field(self):
        """RESTRequest a un champ verify_ssl."""
        from request_manager.request_api import RESTRequest
        assert hasattr(RESTRequest, "model_fields") or hasattr(RESTRequest, "__fields__")
        # Check the field exists
        fields = RESTRequest.model_fields if hasattr(RESTRequest, "model_fields") else RESTRequest.__fields__
        assert "verify_ssl" in fields, "RESTRequest must have verify_ssl field"

    def test_rest_request_verify_ssl_defaults_true(self):
        """verify_ssl est True par défaut dans RESTRequest."""
        from request_manager.request_api import RESTRequest
        req = RESTRequest(method="GET", url="https://example.com")
        assert req.verify_ssl is True, "verify_ssl must default to True"

    def test_system_calls_use_verify_true(self):
        """Les appels système (OIDC) utilisent verify=True."""
        with open("auth_users/oidc_api.py", "r") as f:
            source = f.read()
        assert "verify=True" in source, "OIDC token exchange must use verify=True"

    def test_ai_tools_no_longer_hardcode_verify_false(self):
        """Les AI tools n'ont plus verify=False en dur."""
        with open("ai_core/chat_tools.py", "r") as f:
            source = f.read()
        # Check for verify=False in actual function calls (not comments/docstrings)
        lines = [l for l in source.split("\n") if "verify=False" in l and not l.strip().startswith("#")]
        assert len(lines) == 0, f"Found hardcoded verify=False: {lines}"

    def test_ssl_verify_config_exists(self):
        """Le paramètre ssl.verify existe dans la config."""
        from core.config import get
        val = get("ssl", "verify", "UNSET")
        assert val in ("0", "1"), f"ssl.verify must be 0 or 1, got {val}"


# ═══════════════════════════════════════════════════════════════
# Non-Regression
# ═══════════════════════════════════════════════════════════════

class TestNonRegression:
    """Les fonctionnalités existantes ne sont pas cassées."""

    def test_app_starts(self):
        from entrypoint import app
        assert app is not None

    def test_make_request_still_works(self):
        """_make_request est toujours fonctionnel."""
        from request_manager.request_api import _make_request
        assert callable(_make_request)

    def test_ssrf_protection_still_active(self):
        """La protection SSRF est toujours intégrée à _make_request."""
        import inspect
        from request_manager.request_api import _make_request
        source = inspect.getsource(_make_request)
        assert "validate_url_or_raise" in source, "SSRF protection missing in _make_request"

    def test_verify_ssl_flag_passed_to_requests(self):
        """Le flag verify_ssl est bien passé à requests.request()."""
        import inspect
        from request_manager.request_api import _make_request
        source = inspect.getsource(_make_request)
        assert "verify=" in source, "verify param must be passed to requests.request()"


# ═══════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Cas limites."""

    def test_verify_ssl_none_falls_back_to_config(self):
        """verify_ssl=None utilise la config par défaut."""
        import inspect
        from request_manager.request_api import _make_request
        source = inspect.getsource(_make_request)
        assert "verify_ssl is None" in source, "Must fall back to config when verify_ssl is None"

    def test_verify_ssl_explicit_true_overrides_config(self):
        """verify_ssl=True explicite doit être passé tel quel."""
        import inspect
        from request_manager.request_api import _make_request
        source = inspect.getsource(_make_request)
        # verify_ssl is passed directly to verify= parameter
        assert "verify=verify_ssl" in source

    def test_server_key_can_come_from_cfg(self):
        """La server_wrap_key peut venir du .cfg (pas que env var)."""
        import inspect
        from database.crypto import get_server_wrap_key
        source = inspect.getsource(get_server_wrap_key)
        # Should check both env var AND .cfg
        assert "config" in source.lower() or "_cfg" in source.lower()

    def test_config_file_is_valid_ini(self):
        """Le fichier elyria.cfg est un INI valide."""
        from configparser import ConfigParser
        cfg_path = os.path.join(os.path.dirname(__file__), "..", "elyria.cfg")
        if not os.path.isfile(cfg_path):
            cfg_path = os.path.join(os.path.dirname(__file__), "..", "app", "..", "elyria.cfg")
        if os.path.isfile(cfg_path):
            parser = ConfigParser()
            parser.read(cfg_path)
            assert len(parser.sections()) >= 4, f"Expected at least 4 sections, got {parser.sections()}"
