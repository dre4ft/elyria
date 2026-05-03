from fastapi import APIRouter, Request, HTTPException, File, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json 
from yaml import safe_load
from doc_mgmt.openapi import parser as openapi_parser 
from doc_mgmt.arazzo import parser as arazzo_parser 

app = APIRouter(prefix="/api/document")


def _validate_file(file : File):
    if file.filename.endswith(".json") or file.filename.endswith(".yaml") or file.filename.endswith(".yml"):
        if file.content_type == "application/json" or file.content_type == "application/yaml" or file.content_type == "text/yaml":
            return file.content_type.split("/")[-1]

    raise  HTTPException(status_code=400,detail="invalid file format !")

@app.post("/openapi")
async def upload(request : Request,file: UploadFile = File(...)):
    user_id = request.state.token 
    file_type = _validate_file(file)
    try:
        content = file.file.read()
        if file_type == "json":
            content_as_dict = json.loads(content)
        elif file_type == "yaml":
            content_as_dict = safe_load(content)
        else :
            raise  HTTPException(status_code=400,detail="invalid file format")
        if openapi_parser.validate_wrapper(content_as_dict):
            result = openapi_parser.import_to_db(parsed=openapi_parser.parse_openapi(content=content_as_dict),author_user_id=user_id)
            return JSONResponse(status_code=201, content=result)
        else :
            raise HTTPException(status_code=400,detail="invalid file format")
    except Exception:
        raise HTTPException(status_code=500, detail='Something went wrong')
    
 