from fastapi import FastAPI, Request,HTTPException
from fastapi.responses import JSONResponse,HTMLResponse
from fastapi.staticfiles import StaticFiles
from request_manager.request_api import app as request_router
from database.data_api import app as data_router
from database.collection_api import app as collection_router
from ai_core.ai_api import app as ai_router


app = FastAPI()


@app.middleware("http")
async def check_authorization(request: Request, call_next):
    public_routes = ["/", "/workflow", "/static"]

    if request.url.path in public_routes or request.url.path.startswith("/static"):
        return await call_next(request)

    auth = request.headers.get("authorization")

    if not auth:
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing Authorization header"}
        )

    if not auth.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )

    request.state.token = auth.replace("Bearer ", "")
    return await call_next(request)



@app.get("/")
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

if __name__ == "__main__":
    import uvicorn 
    uvicorn.run(app)