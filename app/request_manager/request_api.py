# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import json
import sqlite3

import requests
from requests import exceptions
from fastapi import APIRouter,Header,Depends,Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException

from core.logging import get_logger

_log = get_logger("request_manager")
from pydantic import BaseModel, Field
from .utils import _generate_request_uuid
from typing import Literal, List,Optional
from database.request_mgmt import add_request
import ssl
import socket
import re

# ── ctx template resolution ──
_CTX_RE = re.compile(r'\{\{(ctx\.)?(\w+(?:\.\w+)*)\}\}')


def resolve_ctx_templates(value: str, ctx: dict) -> str:
    """Replace {{ctx.xxx.yyy}} references with values from ctx dict."""
    if not value or not isinstance(value, str) or '{{' not in value:
        return value

    def _replacer(m):
        path = m.group(2)
        val = ctx
        for key in path.split('.'):
            if val is None or not isinstance(val, dict):
                return m.group(0)
            val = val.get(key)
            if val is None:
                return m.group(0)
        return str(val)
    return _CTX_RE.sub(_replacer, value)


def _resolve_request_ctx(request: Request) -> dict:
    """Load user context from DB for the current request."""
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)

    try:
        from database.ctx_mgmt import get_ctx
        if user_id:
            return get_ctx(user_id)
    except Exception:
        pass
    return {}


def _get_proxy_from_request(request: Request) -> dict:
    """Look up user's favorite proxy from DB. Returns None if disabled or not set."""
    try:
        user_id = getattr(request.state, "token", None)
        if not user_id:
            return None
        from database.connection import get_connection
        conn = get_connection()
        row = conn.execute(
            """SELECT p.url, f.enabled FROM user_favorite_proxy f
               JOIN proxies p ON f.proxy_id = p.proxy_id
               WHERE f.user_id = ?""",
            (user_id,),
        ).fetchone()
        conn.close()
        if row and row["enabled"] and row["url"]:
            return {"http": row["url"], "https": row["url"]}
    except Exception:
        pass
    return None

app = APIRouter(prefix="/api/request")





"""

===================== logique metier Prive =================

"""

def raw_http_parser(content: str, is_response: bool = False):
    first_section = content.split("\r\n\r\n")
    
        
    body = first_section[1] if len(first_section)  == 2 else None 
    other = first_section[0]

    lines = other.split("\r\n")

    context = lines.pop(0)

    split_context = context.split(" ")

    headers = {}
    for line in lines:
        if not line.strip():  
            continue
        split_line = line.split(":")
        if len(split_line) < 2:  
            raise ValueError(f"Invalid header format: {line}")
        headers[split_line[0].strip()] = ":".join(split_line[1:]).strip()
    
    if not is_response:
        return {"method": split_context[0],"path":split_context[1], "headers": headers, "body": body}
    else:
        return {"status": split_context[1] if len(split_context) > 1 else "", "headers": headers, "body": body}

        
#TODO  ajouter un meilleurs gestion de l'auth 
def _make_request(url : str,method :str ,headers:dict=None,query_params:dict =None,body:str=None,_json :dict=None,auth :str = None,allow_redirect:bool=False,proxies:dict=None, verify_ssl:bool|None=None)->dict:
    from core.security import validate_url_or_raise
    validate_url_or_raise(url)
    if verify_ssl is None:
        from database.app_config import get as _cfg
        verify_ssl = _cfg("ssl.verify", "0") == "1"
    if auth:
        if not headers:
            headers = {}
        headers["Authorization"] = f"Bearer {auth}"
    try :
        resp= requests.request(method=method,
                               url=url,
                               data=body,
                               params=query_params,
                               headers=headers,
                               json=_json,
                               allow_redirects=allow_redirect,
                               proxies=proxies,
                               verify=verify_ssl)

        # Safe body serialization: try JSON parse for pretty-printing, fallback to raw text
        raw_body = resp.text or ""
        response_body = raw_body
        if raw_body.startswith("{") or raw_body.startswith("["):
            try:
                response_body = json.dumps(resp.json())
            except Exception:
                response_body = raw_body

        return {"status_code" : resp.status_code,
                "url":resp.url,
                "headers":dict(resp.headers),
                "body" : response_body}

    except requests.exceptions.ProxyError as e:
        _log.warning(f"Proxy unreachable for {url}: {e}")
        return {"status_code": 502, "url": url, "headers": {},
                "body": f"Proxy unreachable: {str(e)[:200]}"}
    except requests.exceptions.SSLError as e:
        _log.warning(f"SSL error for {url}: {e}")
        return {"status_code": 502, "url": url, "headers": {},
                "body": f"SSL error — the server may use a self-signed certificate. Disable SSL verification or use HTTP.\n\n{str(e)[:200]}"}
    except requests.exceptions.ConnectionError as e:
        _log.warning(f"Connection failed for {url}: {e}")
        return {"status_code": 502, "url": url, "headers": {},
                "body": f"Connection failed — is the target server running?\n\n{str(e)[:200]}"}
    except HTTPException:
        raise
    except Exception as e:
        _log.error(f"Request failed: {method} {url} — {e}")
        return {"status_code": 500, "url": url, "headers": {},
                "body": f"Request failed: {str(e)[:200]}"}




def _handle_response(request_uuid:str,result:dict,valide_type:type):
    if isinstance(result, valide_type):
        return JSONResponse(content={'request_uuid':request_uuid,'response':result})
    raise HTTPException(status_code=500, detail="Request failed")

def _send_request(protocol="http", host="127.0.0.1", port=8000, raw_request=""):
    try:
        # Ensure request ends with \r\n\r\n (HTTP header terminator)
        if not raw_request.endswith("\r\n\r\n"):
            raw_request = raw_request.rstrip("\r\n") + "\r\n\r\n"

        import sys

        if protocol == "http":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect((host, port))
                    s.sendall(raw_request.encode())
                    s.shutdown(socket.SHUT_WR)

                    response = b""
                    while True:
                        try:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        except socket.timeout:
                            break

                    result = response.decode(errors="ignore")
                    _log.debug(f"[HTTP] {host}:{port} → {len(result)} bytes response")
                    return result

            except (socket.error, ConnectionError, OSError) as e:
                _log.debug(f"[HTTP] connection failed: {e}")
                raise HTTPException(status_code=502, detail="Connection failed")

        elif protocol == "https":
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                _log.debug(f"[HTTPS] connecting to {host}:{port}...")
                sock = socket.create_connection((host, port), timeout=5)
                _log.debug(f"[HTTPS] TCP connected, starting TLS handshake...")
                ssock = context.wrap_socket(sock, server_hostname=host)
                _log.debug(f"[HTTPS] TLS OK, sending {len(raw_request)} bytes")
                ssock.settimeout(5)
                ssock.sendall(raw_request.encode())

                response = b""
                chunks = 0
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            _log.debug(f"[HTTPS] server closed, got {chunks} chunks, {len(response)} bytes")
                            break
                        response += chunk
                        chunks += 1
                    except socket.timeout:
                        _log.debug(f"[HTTPS] timeout after {chunks} chunks, {len(response)} bytes")
                        break

                result = response.decode(errors="ignore")
                return result

            except (ssl.SSLError, socket.error, ConnectionError, OSError) as e:
                _log.debug(f"[HTTPS] failed: {e}")
                raise HTTPException(status_code=502, detail="Connection failed")

        else:
             raise Exception("[ERROR] Unsupported protocol")

    except Exception as e:
         raise HTTPException(status_code=500, detail="Request failed")


"""

===================== logique metier Public =================

"""


def handle_raw(user_id: str, url: str, request: str,is_done_by_ai:bool=False):
    from core.security import validate_url_or_raise
    validate_url_or_raise(url)
    request_uuid = _generate_request_uuid()
    author = user_id

    # parsing URL minimal
    if url.startswith("https://"):
        protocol = "https"
        url_clean = url.replace("https://", "")
        default_port = 443
    elif url.startswith("http://"):
        protocol = "http"
        url_clean = url.replace("http://", "")
        default_port = 80
    else:
        raise HTTPException(status_code=400, detail="Invalid URL scheme")

    if "/" in url_clean:
        host_port, path = url_clean.split("/", 1)
        path = "/" + path
    else:
        host_port = url_clean
        path = "/"

    if ":" in host_port:
        host, port = host_port.split(":")
        port = int(port)
    else:
        host = host_port
        port = default_port
    # Normalize line endings: CRLF→LF, then LF→CRLF (idempotent)
    normalized_request = request.replace("\r\n", "\n").replace("\n", "\r\n")
    try:
        raw_response = _send_request(
            protocol=protocol,
            host=host,
            port=port,
            raw_request=normalized_request
        )


    except Exception as e:
        return None, {"detail": "Request failed"}
    

    
    parsed_req = raw_http_parser(normalized_request)
    parsed_res = raw_http_parser(raw_response, True)
    url = url + parsed_req["path"]
    
    req = {
        "method": parsed_req["method"],
        "headers": parsed_req["headers"],
        "body": parsed_req["body"]
    }

    resp = {
        "status_code": parsed_res["status"],   
        "url": url,
        "headers": parsed_res["headers"],
        "body": parsed_res["body"]
    }

    add_request(
        request_uuid=request_uuid,
        author=author,
        request=req,
        response=resp,
        is_done_by_ai=is_done_by_ai
    )
    return request_uuid,resp


def handle_request(user_id : str, url : str,method :str ,headers:dict=None,query_params:dict =None,body:str=None,_json :dict=None,auth :str = None,allow_redirect:bool=False,proxies:dict=None,is_done_by_ai:bool=False, verify_ssl:bool|None=None):

    request_uuid = _generate_request_uuid()
    author = user_id

    # Smart body handling: try JSON parse, fallback to raw
    if _json is None and body and isinstance(body, str):
        bt = body.strip()
        if bt:
            try:
                _json = json.loads(bt)
                if not isinstance(_json, (dict, list)):
                    _json = None  # parsed but not JSON object/array
            except (json.JSONDecodeError, ValueError):
                pass  # keep as raw string body

    # If sending raw non-JSON body, strip Content-Type: application/json
    hdrs = dict(headers) if headers else {}
    if _json is None and body and isinstance(body, str) and not body.strip().startswith('{'):
        hdrs = {k: v for k, v in hdrs.items() if k.lower() != 'content-type'}

    # Store body for history
    stored_body = _json if _json is not None else body
    req = {"method":method, "headers": hdrs, "body": stored_body}
    try :
        resp = _make_request(method=method,
                            url=url,
                            body=body if _json is None else None,
                            query_params=query_params,
                            headers=hdrs,
                            _json=_json,
                            allow_redirect=allow_redirect,
                            proxies=proxies,
                            verify_ssl=verify_ssl)
        try:
            add_request(request_uuid=request_uuid,author=author,request=req,response=resp,is_done_by_ai=is_done_by_ai)
        except Exception as log_err:
            _log.error(f"Failed to save request log: {log_err}")
        return request_uuid, resp
    except HTTPException:
        raise
    except Exception as e:
        _log.error(f"handle_request failed: {method} {url} — {e}")
        return request_uuid, {"status_code": 500, "url": url, "headers": {},
                              "body": f"Internal error: {str(e)[:200]}"}






"""

======================== DTO ========================

"""


class RESTRequest(BaseModel):
    method : str
    url : str
    headers : dict  = None
    body : str = None
    verify_ssl : bool = True


class WWWFormRequest(BaseModel):
    method : List[Literal["get","put",'post','patch','delete','head','trace']]
    url : str
    headers : dict = None
    query_params : dict = None 

class RawRequest(BaseModel):
    url : str
    request : str

"""

======================== REST Controllers  ========================

"""

@app.post("/x-www-form-urlencoded")
def x_www_form_urlencoded_request(request:WWWFormRequest,_request:Request):

    token = _request.state.token
    ctx = _resolve_request_ctx(_request)

    if not request.headers:
        request.headers = {}
    if "content-type" not in {k.lower() for k in (request.headers or {})}:
        request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    rc = resolve_ctx_templates
    resolved_headers = {rc(k, ctx): rc(v, ctx) for k, v in (request.headers or {}).items()}
    resolved_qp = [(rc(k, ctx), rc(v, ctx)) for k, v in (request.query_params or [])]
    proxies = _get_proxy_from_request(_request)
    req_uuid, resp = handle_request(user_id=token, url=rc(request.url, ctx), method=request.method,
                                     headers=resolved_headers, query_params=resolved_qp, proxies=proxies)
    return _handle_response(req_uuid, resp, dict)


@app.post("")
def rest_request(request : RESTRequest, _request:Request):
    # Resolve ctx templates
    ctx = _resolve_request_ctx(_request)
    rc = resolve_ctx_templates
    resolved_url = rc(request.url, ctx)
    resolved_headers = {}
    if request.headers:
        for k, v in request.headers.items():
            resolved_headers[rc(k, ctx)] = rc(v, ctx)
    resolved_body = rc(request.body or "", ctx) if request.body else request.body

    # Smart body parsing: try JSON, fallback to raw string
    raw_body = (resolved_body or "").strip()
    body = None
    _json = None
    if raw_body:
        try:
            _json = json.loads(raw_body)
            if not isinstance(_json, (dict, list)):
                body = raw_body
                _json = None
        except (json.JSONDecodeError, ValueError):
            body = raw_body
    headers = resolved_headers
    # Strip Content-Type if no body
    if not raw_body:
        headers = {k: v for k, v in headers.items() if k.lower() != 'content-type'}
    token = _request.state.token
    proxies = _get_proxy_from_request(_request)
    req_uuid, resp = handle_request(user_id=token, method=request.method, url=resolved_url,
                                     body=body, _json=_json, headers=headers, proxies=proxies,
                                     verify_ssl=request.verify_ssl)
    return _handle_response(req_uuid, resp, dict)


@app.post("/raw")
def send_raw_request(request : RawRequest,_request:Request):
    token = _request.state.token
    ctx = _resolve_request_ctx(_request)
    rc = resolve_ctx_templates
    req_uuid, resp = handle_raw(user_id=token, url=rc(request.url, ctx), request=rc(request.request, ctx))
    return _handle_response(req_uuid, resp, dict)
    

"""

==================== DEBUG SECTION ================S


"""



if __name__ == "__main__":
    #print(make_request(url="http://localhost:9999",method='post'))
    #print(_generate_request_uuid())
    NotImplementedError