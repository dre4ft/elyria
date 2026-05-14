from fastapi import FastAPI, Request,HTTPException
from fastapi.responses import JSONResponse,HTMLResponse
from fastapi.staticfiles import StaticFiles

from request_manager.request_api import app as request_router
from database.request_log_api import app as data_router
from database.collection_api import app as collection_router
from ai_core.ai_api import app as ai_router
from auth_users.user_api import app as user_router
from doc_mgmt.document_api import app as document_router
from pentest.campaign_api import app as pentest_router
from blueteam.api import app as blueteam_router
from database.workflow_graph_api import app as workflow_graph_router
from database.proxy_api import app as proxy_router
from database.teams_api import app as teams_router
from ai_core.ai_config_api import app as ai_config_router
from catcher.catcher_api import app as catcher_router
from database.app_config_api import app as app_config_router
from auth_users.oidc_api import app as oidc_router

import jwt
from database.user_mgmt import get_key

app = FastAPI()


@app.middleware("http")
async def check_authorization(request: Request, call_next):
    # Only login/auth flows, HTML shells, and static assets are public.
    # HTML shells (/app, /workflow, etc.) are served without auth so the SPA
    # can load auth.js — client-side auth handles the rest.
    PUBLIC_ROUTES = {
        "/", "/login", "/app", "/workflow", "/pentest", "/hub", "/doc", "/blueteam",
        "/api/user/login", "/api/user/create",
        "/api/user/oidc/login", "/api/user/oidc/callback", "/api/user/oidc/config",
    }
    path = request.url.path
    if path in PUBLIC_ROUTES or path.startswith("/static/"):
        return await call_next(request)

    # SSE streams: EventSource can't send custom headers → bypass middleware
    if path.endswith("/events") and ("/api/blueteam/" in path or "/api/pentest/" in path):
        return await call_next(request)

    auth = request.headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    token = auth.split("Bearer ")[1]
    if token.count(".") != 2:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        kid = unverified.get("kid")
        if not kid:
            return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})
        secret = get_key(kid)
        if not secret:
            return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})
        decoded = jwt.decode(token, secret, algorithms=["HS512"])
        request.state.token = decoded["sub"]
        request.state.token_obj = decoded
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})
    except jwt.InvalidTokenError:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

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

@app.get("/hub")
async def serve_hub():
    try:
        with open("web_ui/hub.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")

@app.get("/pentest")
async def serve_pentest():
    try:
        with open("web_ui/redteam.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")

@app.get("/blueteam")
async def serve_blueteam():
    try:
        with open("web_ui/blueteam.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")

@app.get("/doc")
async def serve_doc():
    try:
        with open("web_ui/doc.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")

@app.get("/api/doc")
async def get_doc(lang: str = "fr"):
    filename = "guide-utilisateur-en.md" if lang == "en" else "guide-utilisateur.md"
    try:
        with open(f"../doc/{filename}", "r") as f:
            return JSONResponse(content={"content": f.read(), "lang": lang})
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Documentation file not found")





app.mount("/static", StaticFiles(directory="web_ui/static", html=True), name="frontend")


app.include_router(request_router)
app.include_router(data_router)
app.include_router(collection_router)
app.include_router(ai_router)
app.include_router(user_router)
app.include_router(document_router)
app.include_router(pentest_router)
app.include_router(blueteam_router)
app.include_router(workflow_graph_router)
app.include_router(proxy_router)
app.include_router(teams_router)
app.include_router(ai_config_router)
app.include_router(catcher_router)
app.include_router(app_config_router)
app.include_router(oidc_router)


if __name__ == "__main__":
    import os
    import uvicorn
    from database.app_config import get

    cert = get("ssl.cert_path")
    key = get("ssl.key_path")
    ssl_kwargs = {}
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}

    uvicorn.run(
        "entrypoint:app",
        host=get("app.host", "127.0.0.1"),
        port=int(get("app.port", "8000")),
        reload=os.getenv("ELYRIA_RELOAD", "").lower() in ("1", "true", "yes"),
        **ssl_kwargs,
    )