"""
Centralized structured logging. JSON format, request IDs, log levels.

Usage:
  from core.logging import get_logger
  logger = get_logger(__name__)
  logger.info("message", extra={"user_id": uid})
"""

import json
import logging
import os
import sys
import time
import uuid
from logging import Logger


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        obj = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.") + f"{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            obj["rid"] = record.request_id
        if record.exc_info and record.exc_info[1]:
            obj["error"] = str(record.exc_info[1])
        for k, v in record.__dict__.items():
            if k not in (
                "args", "asctime", "created", "exc_info", "exc_text",
                "filename", "funcName", "levelname", "levelno", "lineno",
                "module", "msecs", "message", "msg", "name", "pathname",
                "process", "processName", "relativeCreated", "request_id",
                "stack_info", "thread", "threadName", "ts",
            ):
                try:
                    json.dumps(v)
                    obj[k] = v
                except (TypeError, ValueError):
                    pass
        return json.dumps(obj, default=str)


_log_initialized = False


def _init():
    global _log_initialized
    if _log_initialized:
        return
    _log_initialized = True

    level_name = os.getenv("ELYRIA_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    handler.setLevel(level)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(handler)

    # Quiet noisy libs
    for name in ("uvicorn", "uvicorn.access", "httpx", "httpcore", "urllib3", "openai", "ollama"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str = "elyria") -> Logger:
    _init()
    return logging.getLogger(name)
