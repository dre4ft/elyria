# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Structured audit logging — WHO did WHAT, WHEN, with WHAT RESULT.

Two outputs:
  1. JSON to stdout (for log aggregation: ELK, Datadog, Loki)
  2. DB table audit_log (for in-app querying / admin panel)

Usage:
  from core.audit import audit

  audit.info("user.login", user_id=uid, success=True)
  audit.warn("team.member_removed", user_id=uid, team_id=tid, target=target_uid)
  audit.error("crypto.seal_failed", user_id=uid, detail=str(e))
"""

import json
import os
import time
import uuid
from typing import Optional

from core.logging import get_logger

_logger = get_logger("audit")

# ── Helpers ──

def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _rid() -> str:
    return str(uuid.uuid4())[:8]


# ── Public API ──

def audit(level: str, action: str, *,
          user_id: str = "",
          team_id: str = "",
          resource_type: str = "",
          resource_id: str = "",
          detail: str = "",
          success: bool = True,
          status_code: int = 0,
          ip: str = "",
          method: str = "",
          path: str = "",
          duration_ms: int = 0,
          extra: dict = None,
          **kwargs):
    """
    Record an audit event.

    action: dot-separated category (e.g. "user.login", "collection.create", "workflow.delete")
    """
    eid = _rid()
    ts = _now()

    # Build human-readable message
    status = "OK" if success else "FAIL"
    parts = [f"action={action}", f"user={user_id or '-'}", f"status={status}"]
    if team_id: parts.append(f"team={team_id[:12]}")
    if resource_type: parts.append(f"type={resource_type}")
    if resource_id: parts.append(f"id={resource_id}")
    if status_code: parts.append(f"http={status_code}")
    if duration_ms: parts.append(f"dur={duration_ms}ms")
    if ip: parts.append(f"ip={ip}")
    if method and path: parts.append(f"{method} {path}")
    if detail: parts.append(f"detail={detail[:200]}")
    if kwargs: parts.append("extra=" + " ".join(f"{k}={str(v)[:80]}" for k, v in kwargs.items()))
    msg = " | ".join(parts)

    # 1. Write to log file / console
    if success:
        _logger.info(msg)
    else:
        _logger.warning(msg)

    # 2. Write to DB
    entry = {
        "id": eid, "ts": ts, "level": level, "action": action,
        "user_id": user_id or "", "team_id": team_id or "",
        "resource_type": resource_type, "resource_id": resource_id,
        "success": success, "status_code": status_code,
        "detail": detail[:500] if detail else "",
        "ip": ip, "method": method, "path": path, "duration_ms": duration_ms,
    }
    _persist(entry)


def info(action: str, **kwargs):
    audit("INFO", action, **kwargs)


def warn(action: str, **kwargs):
    audit("WARN", action, **kwargs)


def error(action: str, **kwargs):
    audit("ERROR", action, **kwargs)


# ── DB persistence ──

def _persist(entry: dict):
    """Write audit entry to DB. Non-blocking, best-effort."""
    try:
        from database.connection import get_connection
        conn = get_connection()
        conn.execute(
            """INSERT INTO audit_log
               (id, ts, level, action, user_id, team_id, resource_type, resource_id,
                success, status_code, detail, ip, method, path, duration_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (entry["id"], entry["ts"], entry["level"], entry["action"],
             entry["user_id"], entry["team_id"], entry["resource_type"], entry["resource_id"],
             int(entry["success"]), entry["status_code"], entry["detail"],
             entry["ip"], entry["method"], entry["path"], entry["duration_ms"]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # audit logging must never break the main flow


# ── Middleware: log every API request ──

async def audit_middleware(request, call_next):
    """FastAPI middleware — logs every API request with result."""
    import time as _time
    start = _time.monotonic()

    # Extract user before processing (may fail for public routes)
    user_id = ""
    try:
        user_id = getattr(request.state, "token", "") or ""
    except Exception:
        pass

    path = request.url.path
    method = request.method
    ip = request.client.host if request.client else ""

    # Skip logging for static files and health-ish endpoints
    if path.startswith("/static/") or path == "/favicon.ico":
        return await call_next(request)

    response = None
    try:
        response = await call_next(request)
        status_code = response.status_code
        success = status_code < 400
        detail = ""
    except Exception as e:
        status_code = 500
        success = False
        detail = str(e)[:200]
        raise
    finally:
        duration = int((_time.monotonic() - start) * 1000)

    # Only log API calls and significant actions
    if path.startswith("/api/"):
        audit(
            level="ERROR" if status_code >= 400 else "INFO",
            action=f"http.{method.lower()}",
            user_id=user_id,
            path=path,
            method=method,
            status_code=status_code,
            success=success,
            detail=detail,
            ip=ip,
            duration_ms=duration,
        )

    return response


# ── Schema init ──

def init_audit_db():
    """Create audit_log table if not exists."""
    try:
        from database.connection import get_connection
        conn = get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                ts DATETIME NOT NULL,
                level TEXT NOT NULL DEFAULT 'INFO',
                action TEXT NOT NULL DEFAULT '',
                user_id TEXT DEFAULT '',
                team_id TEXT DEFAULT '',
                resource_type TEXT DEFAULT '',
                resource_id TEXT DEFAULT '',
                success INTEGER DEFAULT 1,
                status_code INTEGER DEFAULT 0,
                detail TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                method TEXT DEFAULT '',
                path TEXT DEFAULT '',
                duration_ms INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass
