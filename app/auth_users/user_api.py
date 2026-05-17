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


def create_jwt_token(user_id: str, secret_key: str, key_id: str, expires_in: int = 3600, username: str = "") -> str:
    payload = {
        "kid": key_id,
        "sub": user_id,
        "username": username or user_id,
        "iat": int(time.time()),
        "exp": time.time() + expires_in,
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
    # Check if username already exists
    existing = get_user_by_username(request.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")
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
        # Derive and store user encryption key (BYOK)
        from database.crypto_store import derive_and_store_user_key, wrap_and_persist_user_key
        user_key = derive_and_store_user_key(user["user_id"], request.digest, salt)
        # Persist wrapped key for recovery (password reset)
        wrap_and_persist_user_key(user["user_id"], user_key)
        key_id = _generate_request_uuid()
        key = secrets.token_bytes(64).hex()
        # Generate refresh token (random, stored as SHA3-512 hash in DB)
        refresh_token = secrets.token_hex(64)
        refresh_hash = hashlib.sha3_512(refresh_token.encode()).hexdigest()
        add_key(key_id, key, user["user_id"], refresh_token_hash=refresh_hash)
        token = create_jwt_token(user["user_id"], key, key_id, username=user.get("username", ""))
        from core.audit import info
        info("user.login", user_id=user["user_id"], success=True)
        return JSONResponse(content={
            "token": token,
            "refresh_token": refresh_token,
            "user_id": user["user_id"],
            "username": user["username"],
        })
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
@app.get("/logout")
async def logout(request: Request):
    token_obj = getattr(request.state, "token_obj", None)
    if token_obj:
        try:
            user_id = token_obj.get("sub", "")
            if user_id:
                from database.crypto_store import clear_user_key
                clear_user_key(user_id)
            key_id = token_obj.get("kid")
            if key_id:
                delete_key(key_id)
                delete_old_keys()
                from core.audit import info
                info("user.logout", user_id=user_id, success=True)
                return JSONResponse(content={"message": "Logged out successfully"})
            else:
                raise HTTPException(status_code=401, detail="Invalid token")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Logout failed")
    raise HTTPException(status_code=401, detail="Not authenticated")


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/refresh")
async def refresh_session(request: RefreshRequest):
    """Issue a new access token + refresh token. Max 2 refreshes per session."""
    from database.user_mgmt import verify_refresh_token, consume_refresh, rotate_refresh_token, add_key
    from database.crypto_store import load_user_key, set_user_key

    row = verify_refresh_token(request.refresh_token)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Check refresh limit
    if not consume_refresh(row["key_id"]):
        # Limit reached — delete the session, force re-auth
        from database.user_mgmt import delete_key
        delete_key(row["key_id"])
        raise HTTPException(status_code=401, detail="Refresh limit reached — please re-authenticate")

    # Recover user key from DB (wrapped with server key)
    user_key = load_user_key(row["user_id"])
    if user_key:
        set_user_key(row["user_id"], user_key)

    # Rotate in-place on the same key: new JWT secret + new refresh token hash
    # The refresh_count persists on the key row (incremented by consume_refresh above)
    new_secret = secrets.token_bytes(64).hex()
    new_refresh_token = secrets.token_hex(64)
    new_refresh_hash = hashlib.sha3_512(new_refresh_token.encode()).hexdigest()

    # Update the existing key with new secret + refresh hash
    from database.user_mgmt import rotate_key
    rotate_key(row["key_id"], new_secret, new_refresh_hash)

    token = create_jwt_token(row["user_id"], new_secret, row["key_id"],
                             username=row.get("username", ""))
    from core.audit import info
    info("user.refresh", user_id=row["user_id"], success=True)
    return JSONResponse(content={
        "token": token,
        "refresh_token": new_refresh_token,
        "user_id": row["user_id"],
    })
