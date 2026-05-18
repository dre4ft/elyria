# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import requests
from requests import exceptions
import json
import sqlite3
from fastapi import APIRouter,Header,Depends,Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from .utils import _generate_request_uuid
from typing import Literal, List,Optional
from database.request_mgmt import add_request
import ssl
import socket

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
def _make_request(url : str,method :str ,headers:dict=None,query_params:dict =None,body:str=None,_json :dict=None,auth :str = None,allow_redirect:bool=False,proxies:dict=None)->dict:
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
                               verify=False)

        return {"status_code" : resp.status_code,
                "url":resp.url,
                "headers":dict(resp.headers),
                "body" : resp.text if not resp.text.startswith("{") or resp.text.startswith("[") else  json.dumps(resp.json())}

    except requests.exceptions.ProxyError:
        raise HTTPException(status_code=502, detail="Proxy unreachable")
    except requests.exceptions.SSLError:
        raise HTTPException(status_code=502, detail="SSL error")
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=502, detail="Connection failed")
    except Exception:
        raise HTTPException(status_code=500, detail="Request failed")




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
                    print(f"[DEBUG HTTP] {host}:{port} → {len(result)} bytes response", flush=True)
                    return result

            except (socket.error, ConnectionError, OSError) as e:
                print(f"[DEBUG HTTP] connection failed: {e}", flush=True)
                raise HTTPException(status_code=502, detail="Connection failed")

        elif protocol == "https":
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                print(f"[DEBUG HTTPS] connecting to {host}:{port}...", flush=True)
                sock = socket.create_connection((host, port), timeout=5)
                print(f"[DEBUG HTTPS] TCP connected, starting TLS handshake...", flush=True)
                ssock = context.wrap_socket(sock, server_hostname=host)
                print(f"[DEBUG HTTPS] TLS OK, sending {len(raw_request)} bytes", flush=True)
                ssock.settimeout(5)
                ssock.sendall(raw_request.encode())

                response = b""
                chunks = 0
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            print(f"[DEBUG HTTPS] server closed, got {chunks} chunks, {len(response)} bytes", flush=True)
                            break
                        response += chunk
                        chunks += 1
                    except socket.timeout:
                        print(f"[DEBUG HTTPS] timeout after {chunks} chunks, {len(response)} bytes", flush=True)
                        break

                result = response.decode(errors="ignore")
                return result

            except (ssl.SSLError, socket.error, ConnectionError, OSError) as e:
                print(f"[DEBUG HTTPS] failed: {e}", flush=True)
                raise HTTPException(status_code=502, detail="Connection failed")

        else:
             raise Exception("[ERROR] Unsupported protocol")

    except Exception as e:
         raise HTTPException(status_code=500, detail="Request failed")


"""

===================== logique metier Public =================

"""


def handle_raw(user_id: str, url: str, request: str,is_done_by_ai:bool=False):
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


def handle_request(user_id : str, url : str,method :str ,headers:dict=None,query_params:dict =None,body:str=None,_json :dict=None,auth :str = None,allow_redirect:bool=False,proxies:dict=None,is_done_by_ai:bool=False):

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
                            proxies=proxies)
        add_request(request_uuid=request_uuid,author=author,request=req,response=resp,is_done_by_ai=is_done_by_ai)
        return request_uuid,resp
    except Exception as e:
        raise HTTPException(status_code=500, detail="Request failed") 






"""

======================== DTO ========================

"""


class RESTRequest(BaseModel):
    method : str
    url : str
    headers : dict  = None
    body : str = None 


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
    
    if not request.headers :
        request.headers["Content-Type"] = "application/x-www-form-urlencoded"
    proxies = _get_proxy_from_request(_request)
    req_uuid, resp =  handle_request(user_id=token,url=request.url,method=request.method,headers= request.headers,query_params=request.query_params,proxies=proxies)
    return _handle_response(req_uuid,resp,dict)
    

@app.post("")
def rest_request(request : RESTRequest, _request:Request):
    # Smart body parsing: try JSON, fallback to raw string
    raw_body = (request.body or "").strip()
    body = None
    _json = None
    if raw_body:
        try:
            _json = json.loads(raw_body)
            if not isinstance(_json, (dict, list)):
                # Parsed JSON but not an object/array — treat as raw
                body = raw_body
                _json = None
        except (json.JSONDecodeError, ValueError):
            body = raw_body
    headers = request.headers or {}
    # Strip Content-Type if no body
    if not raw_body:
        headers = {k: v for k, v in headers.items() if k.lower() != 'content-type'}
    token = _request.state.token
    proxies = _get_proxy_from_request(_request)
    req_uuid, resp = handle_request(user_id=token, method=request.method, url=request.url,
                                     body=body, _json=_json, headers=headers, proxies=proxies)
    return _handle_response(req_uuid, resp, dict)


@app.post("/raw")
def send_raw_request(request : RawRequest,_request:Request):
    token = _request.state.token
    req_uuid, resp = handle_raw(user_id=token,url=request.url,request=request.request)                                          
    return _handle_response(req_uuid,resp,dict)
    

"""

==================== DEBUG SECTION ================S


"""



if __name__ == "__main__":
    #print(make_request(url="http://localhost:9999",method='post'))
    #print(_generate_request_uuid())
    NotImplementedError