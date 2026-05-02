from fastapi import FastAPI, Request,HTTPException
from fastapi.responses import JSONResponse,HTMLResponse
from fastapi.staticfiles import StaticFiles
from request_manager.request_api import app as request_router
from database.request_log_api import app as data_router
from database.collection_api import app as collection_router
from ai_core.ai_api import app as ai_router
from auth_users.user_api import app as user_router
from dotenv import load_dotenv
import os
import jwt 
from database.user_mgmt import get_key

load_dotenv()

app = FastAPI()


@app.middleware("http")
async def check_authorization(request: Request, call_next):
    public_routes = ["/", "/login", "/app", "/workflow", "/api/user/login", "/api/user/create"]
    auth = request.headers.get("authorization")
    if request.url.path in public_routes or request.url.path.startswith("/static/"):
        return await call_next(request)

    

    if not auth:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )

    if not auth.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )

    split_token = auth.split("Bearer ")[1]
    split_token_parts = split_token.split(".")
    if len(split_token_parts) != 3:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )
    try:
        unverified_payload = jwt.decode(split_token, options={"verify_signature": False})
        key_id = unverified_payload.get("kid")
        if not key_id:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid Authorization format"}
            )
        key_value = get_key(key_id)
        if not key_value:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid Authorization format"}
            )
        request.state.token = jwt.decode(split_token, key_value, algorithms=["HS512"])
    except jwt.ExpiredSignatureError:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )
    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )
    
    
    return await call_next(request)

@app.get("/")
async def second_route():
    try:
        with open("web_ui/login.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")


@app.get("/login")
async def serve_index():
    try:
        with open("web_ui/login.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")

@app.get("/app")
async def serve_index():
    try:
        with open("web_ui/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")
    
@app.get("/workflow")
async def serve_index():
    try:
        with open("web_ui/workflow.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")





app.mount("/static", StaticFiles(directory="web_ui/static", html=True), name="frontend")


app.include_router(request_router)
app.include_router(data_router)
app.include_router(collection_router)
app.include_router(ai_router)
app.include_router(user_router)




if __name__ == "__main__":
    import uvicorn 
    uvicorn.run(app, host=os.getenv("host"), port=int(os.getenv("port")))