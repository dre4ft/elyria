from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
import uuid_utils 
from typing import Literal, List,Optional
from database.request_mgmt import add_request
from database.user_mgmt import add_user, get_user_salt, get_user_by_username, is_valid_user, add_key, delete_key, delete_old_keys
import hashlib
import jwt
import time
import secrets


app = APIRouter(prefix="/api/user")

"""

============================ Utils ============================

"""

def _generate_request_uuid()->str:
    return str(uuid_utils.uuid4())


def create_jwt_token(user_id: str, secret_key: str, key_id: str, expires_in: int = 3600, proxy_xor: str = "") -> str:
    payload = {
        "kid": key_id,
        "sub": user_id,
        "iat": int(time.time()),
        "exp": time.time() + expires_in,
        "pry": proxy_xor,
    }
    token = jwt.encode(payload, secret_key, algorithm="HS512")
    return token



"""

============================ DTO ============================

"""

class CreateUserRequest(BaseModel):
    username: str
    digest: str

class LoginRequest(BaseModel):
    username : str
    digest: str



"""

============================ REST Controllers ============================

"""

@app.post("/create")
async def create_user(request: CreateUserRequest):
    user_id = _generate_request_uuid()
    salt = secrets.token_bytes(16).hex()
    salted_digest = request.digest + salt
    hashed_digest = hashlib.sha3_512(salted_digest.encode()).hexdigest()
    success = add_user(user_id, hashed_digest, salt, request.username)
    if success:
        return JSONResponse(content={"user_id": user_id}, status_code=201)
    else:
        raise HTTPException(status_code=500, detail="Failed to create user")
    
@app.post("/login")
async def login(request: LoginRequest):
    salt = get_user_salt(request.username)
    if not salt:
        raise HTTPException(status_code=404, detail="User not found")
    salted_digest = request.digest + salt
    hashed_digest = hashlib.sha3_512(salted_digest.encode()).hexdigest()
    is_valid = is_valid_user(request.username, hashed_digest)
    if is_valid:
        user = get_user_by_username(request.username)
        # Look up proxy, XOR-encrypt with server key for JWT embed
        proxy_xor = ""
        try:
            import os, base64
            from database.connection import get_connection
            conn = get_connection()
            row = conn.execute("SELECT p.url FROM user_favorite_proxy u JOIN proxies p ON u.proxy_id=p.proxy_id WHERE u.user_id=?", (user["user_id"],)).fetchone()
            conn.close()
            if row and row[0]:
                xor_key = os.getenv("PROXY_XOR_KEY", "elyria-proxy-k")
                url_bytes = row[0].encode()
                key_bytes = xor_key.encode()
                result = bytearray(len(url_bytes))
                for i in range(len(url_bytes)):
                    result[i] = url_bytes[i] ^ key_bytes[i % len(key_bytes)]
                proxy_xor = base64.urlsafe_b64encode(bytes(result)).decode()
        except Exception: pass
        key_id = _generate_request_uuid()
        key = secrets.token_bytes(64).hex()
        add_key(key_id, key, user["user_id"])
        token = create_jwt_token(user["user_id"], key, key_id, proxy_xor=proxy_xor)
        return JSONResponse(content={"token": token, "user_id": user["user_id"], "username": user["username"]})
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
@app.get("/logout")
async def logout(request: Request):
    token = getattr(request.state, "token", None)
    if token:
        try:
            key_id = token.get("kid")
            if key_id:
                delete_key(key_id)
                delete_old_keys()
                return JSONResponse(content={"message": "Logged out successfully"})
            else:
                raise HTTPException(status_code=400, detail="Invalid token")    
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    raise HTTPException(status_code=403, detail="unauthorized")
