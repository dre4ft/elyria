"""
Admin API for centralized configuration management.
"""

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from database.app_config import (
    get_all, set_kv, get,
    get_fqdn_whitelist, add_fqdn, remove_fqdn,
    get_provider_toggles, set_provider_toggle, is_provider_enabled,
    get_all_api_keys, set_api_key, get_api_key,
)
from database.auth_utils import get_auth_user, require_admin

app = APIRouter(prefix="/api/admin/config", tags=["config"])


@app.get("")
def get_full_config(request: Request):
    get_auth_user(request)
    return {
        "settings": get_all(),
        "fqdn_whitelist": get_fqdn_whitelist(),
        "provider_toggles": get_provider_toggles(),
        "api_keys": [{"key_name": k["key_name"], "key_value": "***" + k["key_value"][-4:] if k["key_value"] else ""} for k in get_all_api_keys()],
    }


@app.put("/settings/{key}")
async def update_setting(key: str, request: Request):
    require_admin(request)
    body = await request.json()
    set_kv(key, str(body.get("value", "")))
    return {"key": key, "value": get(key)}


# ── FQDN whitelist ────────────────────────────────────────────────────
@app.get("/fqdn")
def list_fqdn(category: str = None, request: Request = None):
    get_auth_user(request)
    return get_fqdn_whitelist(category)


@app.post("/fqdn")
async def add_fqdn_entry(request: Request):
    require_admin(request)
    body = await request.json()
    add_fqdn(body.get("category", "fetch"), body.get("pattern", ""))
    return get_fqdn_whitelist(body.get("category"))


@app.delete("/fqdn/{fqdn_id}")
def delete_fqdn_entry(fqdn_id: int, request: Request):
    require_admin(request)
    remove_fqdn(fqdn_id)
    return {"status": "deleted"}


# ── Provider toggles ──────────────────────────────────────────────────
@app.get("/providers")
def list_provider_toggles(request: Request):
    get_auth_user(request)
    return get_provider_toggles()


@app.put("/providers/{provider_type}")
async def update_provider_toggle(provider_type: str, request: Request):
    require_admin(request)
    body = await request.json()
    set_provider_toggle(provider_type, body.get("enabled", True))
    return {"provider_type": provider_type, "enabled": is_provider_enabled(provider_type)}


# ── API keys ──────────────────────────────────────────────────────────
@app.get("/apikeys")
def list_api_keys(request: Request):
    get_auth_user(request)
    return [{"key_name": k["key_name"], "key_value": "***" + k["key_value"][-4:] if k["key_value"] else ""} for k in get_all_api_keys()]


@app.put("/apikeys/{key_name}")
async def update_api_key(key_name: str, request: Request):
    require_admin(request)
    body = await request.json()
    set_api_key(key_name, body.get("key_value", ""))
    return {"key_name": key_name, "status": "ok"}
