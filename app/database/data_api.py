from .request_mgmt import get_requests_by_id,get_requests_by_userid
from fastapi import APIRouter,Header,Depends
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException


app = APIRouter(prefix="/api")




@app.get("/requests/byId/{request_id}")
def get_req_by_id(request_id:str):
    result = get_requests_by_id(request_uuid=request_id)
    return JSONResponse(result)


@app.get("/requests/byUserId/{user_id}")
def get_req_by_id(user_id:str,limit: int = 10, page: int = 1):
    offset = (page - 1) * limit
    result = get_requests_by_userid(user_id,limit,offset)
    if result:
        return JSONResponse(result)
    raise HTTPException(500,detail="error with db")