"""
Catcher — Burp-like HTTP forward proxy interceptor.
External tools (browser, Postman) connect to localhost:8080.
Intercepted requests are queued for Forward/Drop/Load in the Elyria UI.
"""

import json
import os
import re
import socket
import threading
import time
import uuid

import requests as http_requests
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

app = APIRouter(prefix="/api/catcher")

# ── In-memory state ──
_intercept_enabled = False
_pending = {}      # id → {id, method, url, headers, body, timestamp, _event}
_history = []       # [{id, method, url, headers, body, status_code, response_headers, response_body, timestamp}]
_lock = threading.Lock()
MAX_HISTORY = 500

# ── Proxy server ──
_proxy_port = int(os.getenv("CATCHER_PORT", "8080"))
_proxy_server = None  # threading.Thread


def _get_user(r: Request):
    token = getattr(r.state, "token", None)
    if not token or token == "anonymous":
        raise HTTPException(401, "Authentication required")
    return token


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
    srv.bind(("0.0.0.0", _proxy_port))
    srv.listen(50)
    srv.settimeout(1)
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

        if _intercept_enabled:
            event = threading.Event()
            entry["_event"] = event
            with _lock:
                _pending[req_id] = entry
            # Wait for user to Forward or Drop
            signaled = event.wait(timeout=120)
            with _lock:
                entry = _pending.pop(req_id, entry)
            if not signaled:
                _respond_raw(client, 408, "Request timed out waiting for user action")
                client.close()
                return
            if entry.get("_dropped"):
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
                try:
                    headers = json.loads(headers)
                except:
                    headers = {}
            # Remove hop-by-hop headers
            for h in list(headers.keys()):
                if h.lower() in ("proxy-connection", "proxy-authorization", "transfer-encoding"):
                    del headers[h]
            headers["Host"] = headers.get("Host", full_url.split("/")[2] if "://" in full_url else "")

            resp = http_requests.request(
                method, full_url, headers=headers, data=body or None,
                timeout=30, allow_redirects=False, verify=False,
            )
            entry["status_code"] = resp.status_code
            entry["response_headers"] = dict(resp.headers)
            entry["response_body"] = resp.text[:5000] if resp.text else ""
            entry["forwarded_at"] = time.time()

            # Send response back to client
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

        with _lock:
            _history.insert(0, entry)
            if len(_history) > MAX_HISTORY:
                _history = _history[:MAX_HISTORY]

    except Exception:
        pass
    finally:
        try:
            client.close()
        except:
            pass


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
def get_status():
    return {
        "intercept_enabled": _intercept_enabled,
        "proxy_port": _proxy_port,
        "pending_count": len(_pending),
        "history_count": len(_history),
    }


@app.post("/toggle")
def toggle_intercept(request: Request):
    _get_user(request)
    global _intercept_enabled
    _intercept_enabled = not _intercept_enabled
    if _intercept_enabled:
        _start_proxy()
    return {"intercept_enabled": _intercept_enabled, "proxy_port": _proxy_port}


# ── Pending queue ──

@app.get("/pending")
def list_pending(request: Request):
    _get_user(request)
    with _lock:
        items = [{k: v for k, v in p.items() if not k.startswith("_")} for p in _pending.values()]
    items.sort(key=lambda x: x.get("timestamp", 0))
    return items


@app.put("/pending/{req_id}")
async def edit_pending(req_id: str, request: Request):
    _get_user(request)
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
    _get_user(request)
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
    _get_user(request)
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
    _get_user(request)
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
    _get_user(request)
    with _lock:
        items = list(_history[:limit])
    return items


@app.delete("/history")
def clear_history(request: Request):
    _get_user(request)
    with _lock:
        _history.clear()
    return {"status": "cleared"}


# ── Start proxy on import ──
_start_proxy()
