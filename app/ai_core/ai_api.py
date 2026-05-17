from fastapi import APIRouter, Request, HTTPException
from core.auth import get_user, require_admin
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .ai_wrapper import AIWrapper
from database import ai_mgmt


def _get_fallback_api_key():
    from database.app_config import get_api_key
    return get_api_key("openai_api_key")


def _init_provider_from_db():
    from database.ai_config_mgmt import get_default_config
    cfg = get_default_config("pro")
    if cfg:
        url = cfg["base_url"] or "https://api.openai.com/v1"
        api_key = cfg.get("api_key", "")
        if cfg["provider_type"] == "lmstudio":
            url = url.rstrip("/").replace("/api/v1", "/v1")
            if not url.endswith("/v1"):
                url = url.rstrip("/") + "/v1"
            if not api_key:
                api_key = "not-needed"
        if not api_key:
            api_key = _get_fallback_api_key()
        return AIWrapper(
            provider_type=cfg["provider_type"],
            url=url,
            api_key=api_key,
            model=cfg["model"] or "gpt-4o-mini",
        )
    api_key = _get_fallback_api_key()
    return AIWrapper(
        provider_type='openai',
        url='https://api.openai.com/v1',
        api_key=api_key,
        model='gpt-4o-mini',
    )


app = APIRouter(prefix="/api/chat")

AI_PROVIDER = _init_provider_from_db()

def _get_provider_for_slot(slot: str):
    """Lazy-init the right provider for pro/flash slot."""
    from database.ai_config_mgmt import get_default_config
    cfg = get_default_config(slot)
    if not cfg:
        return AI_PROVIDER  # fallback to default pro
    url = cfg["base_url"] or "https://api.openai.com/v1"
    api_key = cfg.get("api_key", "")
    if cfg["provider_type"] == "lmstudio":
        url = url.rstrip("/").replace("/api/v1", "/v1")
        if not url.endswith("/v1"):
            url = url.rstrip("/") + "/v1"
        if not api_key:
            api_key = "not-needed"
    if not api_key:
        api_key = _get_fallback_api_key()
    return AIWrapper(
        provider_type=cfg["provider_type"],
        url=url,
        api_key=api_key,
        model=cfg["model"] or ("gpt-4o-mini" if slot == "flash" else "gpt-4o"),
    )



"""

============================ DTO ============================


"""


class ChatRequest(BaseModel):
    message:str
    conversation_id:str = None
    slot: str = "pro"  # "pro" or "flash"


class UpdateModelRequest(BaseModel):
    new_model: str


class InitProviderRequest(BaseModel):
    provider_type: str
    provider_url: str = None
    api_key: str = None 
    model: str = None
    tools_rounds: int = 5

"""

============================ REST Controllers ============================

"""




@app.get("/models")
async def list_models(request: Request):
    get_user(request)
    try:
        models = AI_PROVIDER.get_models()
        models_dict = models.model_dump()
        return JSONResponse(content={"models": [model['id'] for model in models_dict['data']]})
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid request")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal error")


@app.post("/update_model")
async def update_model(request: Request, update_request: UpdateModelRequest):
    require_admin(request)
    try:
        AI_PROVIDER.update_model(update_request.new_model)
        return JSONResponse(content={"message": f"Model updated to {update_request.new_model}"})
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal error")

@app.get("/providers")
async def get_providers(request: Request):
    get_user(request)
    return JSONResponse(content={"providers": ["openai", "ollama", "lmstudio"]})

@app.post("/init_provider")
async def init_provider(request: Request, init_request: InitProviderRequest):
    require_admin(request)
    try:
        global AI_PROVIDER
        AI_PROVIDER = AIWrapper(
            provider_type=init_request.provider_type,
            url=init_request.provider_url,
            api_key=init_request.api_key,
            model=init_request.model,
            tools_rounds=init_request.tools_rounds
        )
        return JSONResponse(content={"message": f"Provider {init_request.provider_type} initialized successfully"})
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid request")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal error")
    
@app.get("/current_provider")
def get_provider_config(request: Request):
    get_user(request)
    return JSONResponse(content=AI_PROVIDER.get_config())

@app.post("")
async def chat_endpoint(request: Request, chat_request: ChatRequest):
    get_user(request)
    user_id = request.state.token
    try:
        from ai_core.chat_tools import is_slash_command, get_slash_prompt

        message = chat_request.message
        conversation_id = chat_request.conversation_id

        # Slash command → inject system message forcing the tool
        forced_tool = is_slash_command(message)
        if forced_tool:
            import ai_mgmt
            system_prompt = get_slash_prompt(forced_tool, message)
            ai_mgmt.add_message({"role": "system", "content": system_prompt}, user_id, conversation_id)

        provider = _get_provider_for_slot(chat_request.slot) if chat_request.slot else AI_PROVIDER
        response = provider.chat(
            message=message,
            user_id=user_id,
            conversation_id=conversation_id
        )
        return JSONResponse(content=response)
    except Exception as e:
        import traceback
        print(f"[CHAT ERROR] {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal error")


