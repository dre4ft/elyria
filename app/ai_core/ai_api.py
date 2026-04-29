from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .ai_wrapper import AIWrapper
from database import ai_mgmt
import os 
from dotenv import load_dotenv
load_dotenv()

api_key = os.getenv("deepseek")



app = APIRouter(prefix="/api/chat")

"""

TODO:
make provider dynamic (ollama, openai, etc.) based on user/team settings

"""


AI_PROVIDER = AIWrapper(
    provider_type='openai',
    url='https://api.deepseek.com',
    api_key=api_key,
    model='deepseek-v4-flash')



"""

============================ DTO ============================


"""


class ChatRequest(BaseModel):
    message:str 
    conversation_id:str = None


class UpdateModelRequest(BaseModel):
    new_model: str


class InitProviderRequest(BaseModel):
    provider_type: str
    provider_url: str = None
    api_key: str = None 
    model: str = None

"""

============================ REST Controllers ============================

"""




@app.get("/models")
async def list_models():
    try:
        models = AI_PROVIDER.get_models()
        models_dict = models.model_dump()
        return JSONResponse(content={"models": [model['id'] for model in models_dict['data']]})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/update_model")
async def update_model(update_request: UpdateModelRequest):
    try:
        AI_PROVIDER.update_model(update_request.new_model)
        return JSONResponse(content={"message": f"Model updated to {update_request.new_model}"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/providers")
async def get_providers():
    return JSONResponse(content={"providers": ["openai", "ollama"]})

@app.post("/init_provider")
async def init_provider(init_request: InitProviderRequest):
    try:
        global AI_PROVIDER
        AI_PROVIDER = AIWrapper(
            provider_type=init_request.provider_type,
            url=init_request.provider_url,
            api_key=init_request.api_key,
            model=init_request.model
        )
        return JSONResponse(content={"message": f"Provider {init_request.provider_type} initialized successfully"})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/current_provider")
def get_provider_config():
    return JSONResponse(content=AI_PROVIDER.get_config())

@app.post("")
async def chat_endpoint(request: Request, chat_request: ChatRequest):
    user_id = request.state.token
    try:
        response = AI_PROVIDER.chat(
            message=chat_request.message,
            user_id=user_id,
            conversation_id=chat_request.conversation_id
        )
        return JSONResponse(content=response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


