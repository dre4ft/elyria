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

class ChatRequest(BaseModel):
    message:str 
    conversation_id:str = None



"""

TODO:
make provider dynamic (ollama, openai, etc.) based on user/team settings

"""

AI_PROVIDER = AIWrapper(
    provider_type='openai',
    provider_url='https://api.deepseek.com',
    api_key=api_key,
    model='deepseek-v4-flash')



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


