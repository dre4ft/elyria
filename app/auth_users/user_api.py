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


def create_jwt_token(user_id: str, secret_key: str, key_id: str, expires_in: int = 3600) -> str:
    payload = {
        "kid": key_id,
        "sub": user_id,
        "iat": int(time.time()),
        "exp": time.time() + expires_in
    }
    token = jwt.encode(payload, secret_key, algorithm="HS512")
    return token



"""

============================ DTO ============================

"""

class CreateUserRequest(BaseModel):
    username: str
    digest: str
    teams: Optional[List[str]] = Field(default_factory=list)

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
    teams_str = ",".join(request.teams) if request.teams else None
    success = add_user(user_id, hashed_digest, salt, request.username, teams_str)
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
        key_id = _generate_request_uuid()
        key = secrets.token_bytes(64).hex()
        add_key(key_id, key, user["user_id"])
        token = create_jwt_token(user["user_id"], key, key_id)
        return JSONResponse(content={"token": token, "user_id": user["user_id"], "username": user["username"], "teams": user["teams"]})
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
