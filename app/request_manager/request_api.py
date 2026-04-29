import requests
from requests import exceptions
import json
from fastapi import APIRouter,Header,Depends,Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from .utils import _generate_request_uuid
from typing import Literal, List,Optional
import sys
from database.request_mgmt import add_request
import ssl
import socket

app = APIRouter(prefix="/request")





"""

===================== logique metier Prive =================

"""
#TODO  ajouter un meilleurs gestion de l'auth 
def _make_request(url : str,method :str ,headers:dict=None,query_params:dict =None,body:str=None,json :dict=None,auth :str = None,allow_redirect:bool=False,proxies:dict=None)->dict:
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
                               json=json,
                               allow_redirects=allow_redirect,
                               proxies=proxies)
        
        return {"status_code" : resp.status_code,
                "url":resp.url,
                "headers":dict(resp.headers),
                "body" : resp.text if not resp.text.startswith("{") or resp.text.startswith("[") else  json.loads(resp.text)}
    
    except Exception as e:
        return f"code exception {e}"




def _handle_response(request_uuid:str,result:dict,valide_type:type):
    if isinstance(result,valide_type):
        return JSONResponse(content={'request_uuid':request_uuid,'response':result})
    return HTTPException(status_code=500,detail=result)

def _send_request(protocol="http", host="127.0.0.1", port=8000, raw_request=""):
    try:
        raw_request = raw_request.replace("\n", "\r\n")

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

                    return response.decode(errors="ignore")

            except (socket.error, ConnectionError, OSError) as e:
                raise Exception(f"[HTTP SOCKET ERROR] {str(e)}")

        elif protocol == "https":
            try:
                context = ssl.create_default_context()

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.settimeout(5)
                        ssock.sendall(raw_request.encode())

                        response = b""

                        while True:
                            try:
                                chunk = ssock.recv(4096)
                                if not chunk:
                                    break
                                response += chunk
                            except socket.timeout:
                                break

                        return response.decode(errors="ignore")

            except (ssl.SSLError, socket.error, ConnectionError, OSError) as e:
                 raise Exception(f"[HTTPS SOCKET ERROR] {str(e)}")

        else:
             raise Exception("[ERROR] Unsupported protocol")

    except Exception as e:
         raise Exception(f"[FATAL ERROR] {str(e)}")


"""

===================== logique metier Public =================

"""


def handle_raw(user_token: str, url: str, request: str):
    request_uuid = _generate_request_uuid()
    author = user_token

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

    try:
        raw_response = _send_request(
            protocol=protocol,
            host=host,
            port=port,
            raw_request=request
        )


    except Exception as e:
        return JSONResponse(status_code=500, content=f"an error as occured {str(e)}")


    req = {
        "method": "RAW",
        "url": url,
        "headers": None,
        "body": request
    }

    resp = {
        "status_code": None,   
        "url": url,
        "headers": None,
        "body": raw_response
    }

    add_request(
        request_uuid=request_uuid,
        author=author,
        request=req,
        response=resp
    )

    return _handle_response(request_uuid, resp, dict)

def handle_request(user_token : str, url : str,method :str ,headers:dict=None,query_params:dict =None,body:str=None,json :dict=None,auth :str = None,allow_redirect:bool=False,proxies:dict=None):
    
    request_uuid = _generate_request_uuid()
    author = user_token
    req = {"method":method,"headers" : headers,"body":body}
    resp = _make_request(method=method,
                        url=url,
                        body=body,
                        query_params=query_params,
                        headers=headers,
                        json=json,
                        allow_redirect=allow_redirect,
                        proxies=proxies)
    add_request(request_uuid=request_uuid,author=author,request=req,response=resp)
    return _handle_response(request_uuid,resp,dict)  



def get_auth(request: Request):
    token = getattr(request.state, "token", None)

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    return token

"""

======================== DTO ========================

"""


class RESTRequest(BaseModel):
    method : str
    url : str
    headers : dict = None
    body : dict = None 


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
def x_www_form_urlencoded_request(request:WWWFormRequest,auth:str = Depends(get_auth)):
    
    token = auth
    if token == "1234":
        if not request.headers :
            request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        return handle_request(user_token=token,url=request.url,method=request.method,headers= request.headers,query_params=request.query_params)
    raise HTTPException(status_code=403, detail="unauthorized")

@app.post("/rest")
def rest_request(request : RESTRequest,auth:str = Depends(get_auth)):
   
    token = auth
    if token == "1234":
        return handle_request(user_token=token,method=request.method,url=request.url,json=request.body,headers=request.headers)                                          
    raise HTTPException(status_code=403, detail="unauthorized")

@app.post("/raw")
def send_raw_request(request : RawRequest,auth:str = Depends(get_auth)):
   
    token = auth
    if token == "1234":
        return handle_raw(user_token=token,url=request.url,request=request.request)                                          
    raise HTTPException(status_code=403, detail="unauthorized")

"""

==================== DEBUG SECTION ================S


"""



if __name__ == "__main__":
    #print(make_request(url="http://localhost:9999",method='post'))
    #print(_generate_request_uuid())
    NotImplementedError