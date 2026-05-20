# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Centralized logging — proper log format, human-readable.

Log files (rotated daily, kept 30 days):
  logs/elyria.log      — all application logs
  logs/audit.log       — audit trail only (WHO, WHAT, WHEN, RESULT)

Usage:
  from core.logging import get_logger
  logger = get_logger(__name__)
  logger.info("message")
"""

import logging
import logging.handlers
import os
import sys
from logging import Logger
from pathlib import Path


class _LogFormatter(logging.Formatter):
    """Standard log format: 2026-05-16 12:01:43 INFO [module] message"""
    def format(self, record):
        ts = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        return f"{ts} {record.levelname:5s} [{record.name}] {record.getMessage()}"


_log_initialized = False
_audit_logger: Logger | None = None


def _resolve_log_dir(base: str) -> str:
    """Resolve log directory: absolute path, fallback to app/logs."""
    if os.path.isabs(base):
        return base
    # Relative to the app directory
    app_root = Path(__file__).resolve().parent.parent  # core → app
    return str(app_root / base)


def _init():
    global _log_initialized, _audit_logger
    if _log_initialized:
        return
    _log_initialized = True

    from database.app_config import get as cfg
    level_name = cfg("log.level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_dir = _resolve_log_dir(cfg("log.dir", "logs"))
    os.makedirs(log_dir, exist_ok=True)

    formatter = _LogFormatter()

    # ── Root logger: console + file ──
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    # Console
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(level)
    root.addHandler(console)

    # File: rotated daily, 30 days
    app_file = logging.handlers.TimedRotatingFileHandler(
        os.path.join(log_dir, "elyria.log"),
        when="midnight", interval=1, backupCount=30, encoding="utf-8",
    )
    app_file.setFormatter(formatter)
    app_file.setLevel(level)
    root.addHandler(app_file)

    # ── Audit logger: separate file ──
    _audit_logger = logging.getLogger("audit")
    _audit_logger.propagate = False
    _audit_logger.setLevel(logging.INFO)

    audit_file = logging.handlers.TimedRotatingFileHandler(
        os.path.join(log_dir, "audit.log"),
        when="midnight", interval=1, backupCount=90, encoding="utf-8",
    )
    audit_file.setFormatter(formatter)
    audit_file.setLevel(logging.INFO)
    _audit_logger.addHandler(audit_file)

    # Audit also to console (prefixed)
    audit_console = logging.StreamHandler(sys.stdout)
    audit_console.setFormatter(logging.Formatter("%(asctime)s [AUDIT] %(message)s"))
    audit_console.setLevel(logging.INFO)
    _audit_logger.addHandler(audit_console)

    # Quiet noisy libs
    for name in ("uvicorn", "uvicorn.access", "httpx", "httpcore", "urllib3", "openai", "ollama"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str = "elyria") -> Logger:
    _init()
    if name == "audit":
        return _audit_logger or logging.getLogger("audit")
    return logging.getLogger(name)
