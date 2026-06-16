# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Admin API for centralized configuration management.
"""

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from database.app_config import (
    get_all, set_kv, get,
    get_fqdn_whitelist, add_fqdn, remove_fqdn,
    get_provider_toggles, set_provider_toggle, is_provider_enabled,
    get_all_api_keys, set_api_key, get_api_key,
)
from database.auth_utils import get_auth_user, require_admin

app = APIRouter(prefix="/api/admin/config", tags=["config"])

class UpdateSettingRequest(BaseModel):
    value: str = ""

class AddFqdnRequest(BaseModel):
    category: str = "fetch"
    pattern: str

class SetProviderToggleRequest(BaseModel):
    enabled: bool = True

class SetApiKeyRequest(BaseModel):
    key_name: str
    key_value: str


@app.get("")
def get_full_config(request: Request):
    require_admin(request)
    return {
        "settings": get_all(),
        "fqdn_whitelist": get_fqdn_whitelist(),
        "provider_toggles": get_provider_toggles(),
        "api_keys": [{"key_name": k["key_name"], "key_value": "***" + k["key_value"][-4:] if k["key_value"] else ""} for k in get_all_api_keys()],
    }


@app.put("/settings/{key}")
async def update_setting(key: str, body: UpdateSettingRequest, request: Request):
    require_admin(request)
    set_kv(key, str(body.value))
    return {"key": key, "value": get(key)}


# ── FQDN whitelist ────────────────────────────────────────────────────
@app.get("/fqdn")
def list_fqdn(category: str = None, request: Request = None):
    require_admin(request)
    return get_fqdn_whitelist(category)


@app.post("/fqdn")
async def add_fqdn_entry(body: AddFqdnRequest, request: Request):
    require_admin(request)
    add_fqdn(body.category, body.pattern)
    return get_fqdn_whitelist(body.category)


@app.delete("/fqdn/{fqdn_id}")
def delete_fqdn_entry(fqdn_id: int, request: Request):
    require_admin(request)
    remove_fqdn(fqdn_id)
    return {"status": "deleted"}


# ── Provider toggles ──────────────────────────────────────────────────
@app.get("/providers")
def list_provider_toggles(request: Request):
    require_admin(request)
    return get_provider_toggles()


@app.put("/providers/{provider_type}")
async def update_provider_toggle(provider_type: str, body: SetProviderToggleRequest, request: Request):
    require_admin(request)
    set_provider_toggle(provider_type, body.enabled)
    return {"provider_type": provider_type, "enabled": is_provider_enabled(provider_type)}


# ── API keys ──────────────────────────────────────────────────────────
@app.get("/apikeys")
def list_api_keys(request: Request):
    require_admin(request)
    return [{"key_name": k["key_name"], "key_value": "***" + k["key_value"][-4:] if k["key_value"] else ""} for k in get_all_api_keys()]


@app.put("/apikeys/{key_name}")
async def update_api_key(key_name: str, body: SetApiKeyRequest, request: Request):
    require_admin(request)
    set_api_key(key_name, body.key_value)
    return {"key_name": key_name, "status": "ok"}
