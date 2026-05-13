"""
Catcher — Burp-like HTTP forward proxy interceptor.
External tools (browser, Postman) connect to localhost:8080.
Intercepted requests are queued for Forward/Drop/Load in the Elyria UI.
History is persisted in DB, scoped by user.
"""

import json

import socket
import threading
import time
import uuid

import requests as http_requests
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from database.connection import get_connection

app = APIRouter(prefix="/api/catcher")

# ── In-memory state ──
_pending = {}      # id → {id, method, url, headers, body, timestamp, _event}
_lock = threading.Lock()
# Intercept state is persisted in app_config (survives hot-reload)
_INTERCEPT_KEY = "catcher.intercept_enabled"

def _get_intercept():
    from database.app_config import get
    return get(_INTERCEPT_KEY, "0") == "1"

def _set_intercept(v: bool):
    from database.app_config import set_kv
    set_kv(_INTERCEPT_KEY, "1" if v else "0")

# ── Proxy server ──
from database.app_config import get_int as _cfg_int
_proxy_port = _cfg_int("catcher.port", 6767)
_proxy_server = None  # threading.Thread


# ── DB init ──
def _init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS catcher_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            request_headers TEXT DEFAULT '{}',
            request_body TEXT DEFAULT '',
            status_code INTEGER DEFAULT 0,
            response_headers TEXT DEFAULT '{}',
            response_body TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


def _save_history(entry, user_id=""):
    conn = get_connection()
    hid = str(uuid.uuid4())[:8]
    conn.execute(
        """INSERT INTO catcher_history (history_id, user_id, method, url, request_headers,
           request_body, status_code, response_headers, response_body)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (hid, user_id or "", entry.get("method", "GET"), entry.get("url", ""),
         json.dumps(entry.get("headers", {}) or {}), (entry.get("body") or "")[:10000],
         entry.get("status_code", 0), json.dumps(entry.get("response_headers", {}) or {}),
         (entry.get("response_body") or "")[:5000]),
    )
    conn.commit()
    conn.close()
    return hid


def _get_history(user_id="", limit=100):
    conn = get_connection()
    if user_id:
        rows = conn.execute(
            "SELECT * FROM catcher_history WHERE user_id=? OR user_id='' ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM catcher_history ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [{
        "id": r["history_id"],
        "method": r["method"],
        "url": r["url"],
        "headers": json.loads(r["request_headers"]) if r["request_headers"] else {},
        "body": r["request_body"],
        "status_code": r["status_code"],
        "response_headers": json.loads(r["response_headers"]) if r["response_headers"] else {},
        "response_body": r["response_body"],
        "created_at": r["created_at"],
    } for r in rows]


def _clear_history(user_id=""):
    conn = get_connection()
    if user_id:
        conn.execute("DELETE FROM catcher_history WHERE user_id=?", (user_id,))
    else:
        conn.execute("DELETE FROM catcher_history")
    conn.commit()
    conn.close()


_init_db()
from database.auth_utils import get_auth_user


# ═══════════════════════════════════════════
# PROXY SERVER (HTTP forward proxy)
# ═══════════════════════════════════════════

def _start_proxy():
    global _proxy_server
    if _proxy_server and _proxy_server.is_alive():
        return
    _proxy_server = threading.Thread(target=_run_proxy, daemon=True, name="catcher-proxy")
    _proxy_server.start()


def _run_proxy():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass  # Linux only
    try:
        srv.bind(("0.0.0.0", _proxy_port))
    except OSError:
        print(f"[catcher] Port {_proxy_port} already in use — proxy not started")
        return
    srv.listen(50)
    srv.settimeout(1)
    print(f"[catcher] Proxy HTTP forward demarre sur 0.0.0.0:{_proxy_port}")
    while True:
        try:
            client, addr = srv.accept()
            threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break


def _handle_client(client, addr):
    try:
        client.settimeout(30)
        data = b""
        while True:
            try:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            except socket.timeout:
                break

        if not data:
            client.close()
            return

        raw = data.decode("utf-8", errors="replace")
        lines = raw.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 3:
            client.close()
            return

        method = parts[0]
        full_url = parts[1]

        # Handle CONNECT (HTTPS tunneling) — pass through without interception
        if method == "CONNECT":
            _tunnel_connect(client, addr, parts)
            return

        # Parse headers and body
        headers = {}
        body = ""
        header_done = False
        for line in lines[1:]:
            if not header_done:
                if line == "":
                    header_done = True
                elif ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            else:
                body += line + "\n"
        body = body.strip()

        # Content-Length support
        content_length = int(headers.get("Content-Length", "0"))
        if content_length > 0 and len(body.encode()) < content_length:
            remaining = content_length - len(body.encode())
            try:
                client.settimeout(5)
                extra = client.recv(remaining + 4096)
                if extra:
                    body += extra.decode("utf-8", errors="replace")
            except:
                pass

        req_id = str(uuid.uuid4())[:8]
        entry = {
            "id": req_id,
            "method": method,
            "url": full_url,
            "headers": headers,
            "body": body[:10000],
            "timestamp": time.time(),
        }

        if _get_intercept():
            event = threading.Event()
            entry["_event"] = event
            with _lock:
                _pending[req_id] = entry
            # Wait for user to Forward or Drop
            signaled = event.wait(timeout=120)
            with _lock:
                entry = _pending.pop(req_id, entry)
            if not signaled:
                entry["status_code"] = 408
                entry["response_body"] = "Request timed out waiting for user action"
                entry["forwarded_at"] = time.time()
                _save_history(entry)
                _respond_raw(client, 408, "Request timed out waiting for user action")
                client.close()
                return
            if entry.get("_dropped"):
                entry["status_code"] = 410
                entry["response_body"] = "Request dropped by user"
                entry["forwarded_at"] = time.time()
                _save_history(entry)
                _respond_raw(client, 410, "Request dropped by user")
                client.close()
                return
            # Apply edits
            method = entry.get("method", method)
            full_url = entry.get("url", full_url)
            headers = entry.get("headers", headers) or {}
            body = entry.get("body", body) or ""

        # Forward to target
        try:
            if isinstance(headers, str):
                try: headers = json.loads(headers)
                except: headers = {}
            for h in list(headers.keys()):
                if h.lower() in ("proxy-connection", "proxy-authorization", "transfer-encoding"):
                    del headers[h]

            resp = http_requests.request(
                method, full_url, headers=headers, data=body or None,
                timeout=30, allow_redirects=False, verify=False,
            )
            entry["status_code"] = resp.status_code
            entry["response_headers"] = dict(resp.headers)
            entry["response_body"] = resp.text[:5000] if resp.text else ""
            entry["forwarded_at"] = time.time()

            status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
            client.sendall(status_line.encode())
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding",):
                    client.sendall(f"{k}: {v}\r\n".encode())
            client.sendall(b"\r\n")
            if resp.content:
                client.sendall(resp.content)
        except Exception as e:
            entry["status_code"] = 0
            entry["response_headers"] = {}
            entry["response_body"] = str(e)[:500]
            entry["forwarded_at"] = time.time()
            _respond_raw(client, 502, f"Proxy error: {e}")

        _save_history(entry)
        print(f"[catcher] {method} {full_url} → {entry.get('status_code','?')} saved to history", flush=True)

    except Exception as e:
        import traceback
        print(f"[catcher] Error handling client: {e}", flush=True)
        traceback.print_exc()
    finally:
        try:
            client.close()
        except:
            pass


def _tunnel_connect(client, addr, parts):
    """Basic CONNECT tunnel for HTTPS."""
    target = parts[1]  # host:port
    try:
        host, port = target.split(":")
        port = int(port)
    except ValueError:
        host, port = target, 443
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(10)
        remote.connect((host, port))
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # Bidirectional relay
        def _relay(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data: break
                    dst.sendall(data)
            except: pass
        t1 = threading.Thread(target=_relay, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=_relay, args=(remote, client), daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=30); t2.join(timeout=30)
    except Exception:
        pass
    finally:
        try: remote.close()
        except: pass
        try: client.close()
        except: pass


def _respond_raw(client, code, msg):
    try:
        body = msg.encode()
        client.sendall(f"HTTP/1.1 {code} {msg}\r\nContent-Length: {len(body)}\r\nContent-Type: text/plain\r\n\r\n".encode())
        client.sendall(body)
    except:
        pass


# ═══════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════

@app.get("/status")
def get_status(request: Request):
    user_id = get_auth_user(request)
    return {
        "intercept_enabled": _get_intercept(),
        "proxy_port": _proxy_port,
        "pending_count": len(_pending),
        "history_count": len(_get_history(user_id=user_id, limit=1000)),
    }


@app.post("/toggle")
def toggle_intercept(request: Request):
    user_id = get_auth_user(request)
    new_state = not _get_intercept()
    _set_intercept(new_state)
    _start_proxy()  # idempotent — starts only if not already running

    # Ensure the catcher proxy is set as favorite and routing is enabled
    try:
        from database.connection import get_connection
        conn = get_connection()
        proxy_url = f"http://localhost:{_proxy_port}"
        # Check if a proxy exists for the catcher, create if not
        existing = conn.execute(
            "SELECT proxy_id FROM proxies WHERE url=? AND user_id=?",
            (proxy_url, user_id),
        ).fetchone()
        if existing:
            proxy_id = existing["proxy_id"]
        else:
            import uuid
            proxy_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO proxies (proxy_id, name, url, user_id) VALUES(?,?,?,?)",
                (proxy_id, "Catcher", proxy_url, user_id),
            )
        # Set as favorite with enabled flag
        conn.execute(
            "INSERT OR REPLACE INTO user_favorite_proxy (user_id, proxy_id, enabled) VALUES(?,?,?)",
            (user_id, proxy_id, 1 if new_state else 0),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    return {"intercept_enabled": new_state, "proxy_port": _proxy_port}


# ── Pending queue ──

@app.get("/pending")
def list_pending(request: Request):
    get_auth_user(request)
    with _lock:
        items = [{k: v for k, v in p.items() if not k.startswith("_")} for p in _pending.values()]
    items.sort(key=lambda x: x.get("timestamp", 0))
    return items


@app.put("/pending/{req_id}")
async def edit_pending(req_id: str, request: Request):
    get_auth_user(request)
    body = await request.json()
    with _lock:
        if req_id not in _pending:
            raise HTTPException(404, "Request not found in pending queue")
        for field in ("method", "url", "headers", "body"):
            if field in body:
                _pending[req_id][field] = body[field]
    return {"status": "edited"}


@app.post("/pending/{req_id}/forward")
def forward_request(req_id: str, request: Request):
    get_auth_user(request)
    with _lock:
        entry = _pending.get(req_id)
    if not entry:
        raise HTTPException(404, "Request not found")
    evt = entry.get("_event")
    if evt:
        evt.set()
    return {"status": "forwarded", "id": req_id}


@app.post("/pending/{req_id}/drop")
def drop_request(req_id: str, request: Request):
    get_auth_user(request)
    with _lock:
        entry = _pending.get(req_id)
    if not entry:
        raise HTTPException(404, "Request not found")
    entry["_dropped"] = True
    evt = entry.get("_event")
    if evt:
        evt.set()
    return {"status": "dropped"}


@app.post("/pending/drop-all")
def drop_all(request: Request):
    get_auth_user(request)
    with _lock:
        for entry in _pending.values():
            entry["_dropped"] = True
            evt = entry.get("_event")
            if evt:
                evt.set()
        _pending.clear()
    return {"status": "all_dropped"}


# ── History ──

@app.get("/history")
def get_history(request: Request, limit: int = 100):
    user_id = get_auth_user(request)
    return _get_history(user_id=user_id, limit=limit)


@app.delete("/history")
def clear_history(request: Request):
    user_id = get_auth_user(request)
    _clear_history(user_id=user_id)
    return {"status": "cleared"}


# ── Start proxy on import ──
_start_proxy()
