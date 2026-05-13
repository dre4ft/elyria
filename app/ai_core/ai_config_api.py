"""
AI Provider configuration API — flash and pro slots, multi-provider.
"""

from fastapi import APIRouter, Request, HTTPException
from database.ai_config_mgmt import (
    list_provider_configs,
    get_provider_config,
    get_default_config,
    save_provider_config,
    update_provider_config,
    delete_provider_config,
)

app = APIRouter(prefix="/api/ai-configs", tags=["ai-configs"])


def _mask_key(cfg):
    """Never expose API keys — replace with placeholder if set."""
    if cfg and cfg.get("api_key"):
        cfg = dict(cfg)
        cfg["api_key"] = "****"
    return cfg


def _mask_keys(configs):
    return [_mask_key(c) for c in configs]


@app.post("/list-models")
async def api_list_models_from_params(request: Request):
    """List models from raw provider params (no saved config needed)."""
    body = await request.json()
    provider_type = body.get("provider_type", "openai")
    base_url = body.get("base_url", "")
    api_key = body.get("api_key", "")
    models = _fetch_models(provider_type, base_url, api_key)
    return {"models": models}


def _fetch_models(provider_type, base_url, api_key):
    """Fetch model list adapting method per provider type."""
    if provider_type == "ollama":
        try:
            import ollama
            if base_url:
                import os as _os
                old = _os.environ.get("OLLAMA_HOST")
                _os.environ["OLLAMA_HOST"] = base_url.rstrip("/")
                try:
                    result = ollama.list()
                finally:
                    if old:
                        _os.environ["OLLAMA_HOST"] = old
                    else:
                        _os.environ.pop("OLLAMA_HOST", None)
            else:
                result = ollama.list()
            if isinstance(result, dict):
                return [m.get("model") or m.get("name") for m in result.get("models", [])]
            return [getattr(m, "model", str(m)) for m in result] if result else []
        except Exception:
            return []

    if provider_type == "lmstudio":
        # LM Studio exposes /api/v1/models (not /v1/models like vanilla OpenAI)
        return _fetch_lmstudio_models(base_url)

    # OpenAI-compatible providers
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key or "not-needed", base_url=base_url or "https://api.openai.com/v1")
        models_data = client.models.list()
        if hasattr(models_data, 'model_dump'):
            models_data = models_data.model_dump()
        if isinstance(models_data, dict):
            model_list = models_data.get('data', models_data.get('models', []))
        elif hasattr(models_data, 'data'):
            model_list = models_data.data
        else:
            model_list = list(models_data) if models_data else []
        return _extract_model_ids(model_list)
    except Exception:
        return []


def _fetch_lmstudio_models(base_url):
    """LM Studio uses OpenAI-compatible /v1/models endpoint."""
    import requests as _req
    root = (base_url or "http://localhost:1234/v1").rstrip("/")
    # Try standard OpenAI path first, fallback to legacy /api/v1
    candidates = []
    if root.endswith("/v1") or root.endswith("/v1/"):
        candidates.append(f"{root}/models")
    elif root.endswith("/api/v1") or root.endswith("/api/v1/"):
        candidates.append(root.replace("/api/v1", "/v1") + "/models")
        candidates.append(f"{root}/models")
    else:
        candidates.append(f"{root}/v1/models")

    for url in candidates:
        try:
            resp = _req.get(url, timeout=5)
            if resp.status_code != 200:
                continue
            data = resp.json()
            ids = _extract_model_ids_from_data(data)
            if ids:
                return ids
        except Exception:
            continue

    # Last resort: OpenAI client
    try:
        from openai import OpenAI
        client = OpenAI(api_key="not-needed", base_url=root)
        models_data = client.models.list()
        if hasattr(models_data, 'model_dump'):
            models_data = models_data.model_dump()
        ids = _extract_model_ids_from_data(models_data)
        if ids:
            return ids
    except Exception:
        pass
    return []


def _extract_model_ids_from_data(data):
    """Robust model ID extraction from any response format."""
    if not data:
        return []
    found = []

    def _dig(obj):
        if isinstance(obj, dict):
            # Direct id field at this level
            if 'id' in obj and isinstance(obj['id'], str) and len(obj['id']) > 1:
                found.append(obj['id'])
            elif 'model' in obj and isinstance(obj['model'], str) and len(obj['model']) > 1:
                found.append(obj['model'])
            # Recurse into values
            for v in obj.values():
                _dig(v)
        elif isinstance(obj, list):
            for item in obj:
                _dig(item)

    _dig(data)
    # Dedup preserving order
    seen = set()
    result = []
    for m in found:
        if m not in seen and not m.startswith('/') and m not in ('model', 'id'):
            seen.add(m)
            result.append(m)
    return result


def _extract_model_ids(model_list):
    ids = []
    for m in (model_list or []):
        if isinstance(m, dict):
            ids.append(m.get('id', m.get('name', m.get('model', str(m)))))
        elif hasattr(m, 'id'):
            ids.append(m.id)
        elif hasattr(m, 'model'):
            ids.append(m.model)
        else:
            ids.append(str(m))
    return ids


@app.get("")
async def api_list_configs(slot: str = ""):
    return _mask_keys(list_provider_configs(slot=slot if slot else None))


@app.get("/defaults")
async def api_get_defaults():
    flash = get_default_config("flash")
    pro = get_default_config("pro")
    return {"flash": _mask_key(flash), "pro": _mask_key(pro)}


@app.get("/default/{slot}")
async def api_get_default_slot(slot: str):
    cfg = get_default_config(slot)
    if not cfg:
        raise HTTPException(404, f"No default provider for slot '{slot}'")
    return _mask_key(cfg)


@app.post("")
async def api_create_config(request: Request):
    body = await request.json()
    slot = body.get("slot", "pro")
    if slot not in ("flash", "pro"):
        raise HTTPException(400, "slot must be 'flash' or 'pro'")
    name = body.get("name", "").strip() or f"{slot.capitalize()} provider"
    provider_type = body.get("provider_type", "openai")
    if provider_type not in ("openai", "ollama", "lmstudio"):
        raise HTTPException(400, "provider_type must be openai, ollama, or lmstudio")
    return {
        "config_id": save_provider_config(
            slot=slot,
            name=name,
            provider_type=provider_type,
            base_url=body.get("base_url", ""),
            api_key=body.get("api_key", ""),
            model=body.get("model", ""),
            is_default=body.get("is_default", False),
        )
    }


@app.post("/{config_id}/set-default")
async def api_set_default(config_id: str):
    cfg = get_provider_config(config_id)
    if not cfg:
        raise HTTPException(404, "Config not found")
    update_provider_config(config_id, is_default=True)
    return {"status": "ok", "slot": cfg["slot"], "config_id": config_id}


@app.get("/{config_id}/models")
async def api_list_models(config_id: str):
    cfg = get_provider_config(config_id)
    if not cfg:
        raise HTTPException(404, "Config not found")
    from ai_core.ai_wrapper import AIWrapper
    wrapper = AIWrapper(
        provider_type=cfg["provider_type"],
        url=cfg["base_url"],
        api_key=cfg.get("api_key", ""),
        model=cfg.get("model") or "",
    )
    try:
        provider = wrapper.provider
        models_data = provider.get_models()
        if hasattr(models_data, 'model_dump'):
            models_data = models_data.model_dump()
        if isinstance(models_data, dict):
            model_list = models_data.get('data', models_data.get('models', []))
        elif isinstance(models_data, list):
            model_list = models_data
        else:
            model_list = []
        ids = []
        for m in model_list:
            if isinstance(m, dict):
                ids.append(m.get('id', m.get('name', str(m))))
            elif hasattr(m, 'id'):
                ids.append(m.id)
            else:
                ids.append(str(m))
        return {"models": ids}
    except Exception as e:
        raise HTTPException(500, f"Failed to list models: {str(e)}")


@app.get("/{config_id}")
async def api_get_config(config_id: str):
    cfg = get_provider_config(config_id)
    if not cfg:
        raise HTTPException(404, "Config not found")
    return _mask_key(cfg)


@app.put("/{config_id}")
async def api_update_config(config_id: str, request: Request):
    cfg = get_provider_config(config_id)
    if not cfg:
        raise HTTPException(404, "Config not found")
    body = await request.json()
    updates = {k: v for k, v in body.items() if v is not None}
    if not updates.get("api_key") or updates["api_key"] == "****":
        updates.pop("api_key", None)
    update_provider_config(config_id, **updates)
    return {"status": "updated"}


@app.delete("/{config_id}")
async def api_delete_config(config_id: str):
    cfg = get_provider_config(config_id)
    if not cfg:
        raise HTTPException(404, "Config not found")
    delete_provider_config(config_id)
    return {"status": "deleted"}
