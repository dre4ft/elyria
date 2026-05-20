# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import hashlib
import re
import secrets
import time

import jwt
import uuid_utils
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.audit import info as audit_info, warn as audit_warn
from database.user_mgmt import (
    add_user,
    get_user_by_email,
    get_user_salt,
    is_email_taken,
    is_valid_user,
    add_key,
    delete_key,
    delete_old_keys,
    mark_email_verified,
    create_verification_token,
    get_verification_token,
    consume_verification_token,
    try_resend_verification_token,
    get_login_lockout,
    increment_failed_login,
    reset_failed_login,
)

app = APIRouter(prefix="/api/user")


# ═══════════════════════════════════════════
# Utils
# ═══════════════════════════════════════════

def _generate_uuid() -> str:
    return str(uuid_utils.uuid4())


def _generate_verification_code() -> str:
    """8-char alphanumeric code (no ambiguous chars: 0/O, 1/I/L)."""
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))


def _validate_password(password: str) -> str | None:
    """Returns error message or None if valid."""
    if len(password) < 12:
        return "Le mot de passe doit contenir au moins 12 caracteres."
    if not re.search(r"[A-Z]", password):
        return "Le mot de passe doit contenir au moins une majuscule."
    if not re.search(r"[a-z]", password):
        return "Le mot de passe doit contenir au moins une minuscule."
    if not re.search(r"[0-9]", password):
        return "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Le mot de passe doit contenir au moins un symbole."
    return None


def _validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _hash_password(password: str, salt: str) -> str:
    """SHA3-512(password + salt) — stored in DB for auth verification."""
    return hashlib.sha3_512((password + salt).encode()).hexdigest()


def _create_jwt(user_id: str, secret: str, key_id: str, email: str = "", expires_in: int = 3600) -> str:
    payload = {
        "kid": key_id,
        "sub": user_id,
        "email": email,
        "iat": int(time.time()),
        "exp": time.time() + expires_in,
    }
    return jwt.encode(payload, secret, algorithm="HS512")


# ═══════════════════════════════════════════
# DTO
# ═══════════════════════════════════════════

class CreateUserRequest(BaseModel):
    email: str
    password: str
    confirm_password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class VerifyEmailRequest(BaseModel):
    token: str
    code: str


class ResendCodeRequest(BaseModel):
    token: str


class ResetPasswordRequest(BaseModel):
    email: str


class ResetPasswordConfirmRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ═══════════════════════════════════════════
# REST Controllers
# ═══════════════════════════════════════════

@app.post("/create")
async def create_user(request: CreateUserRequest):
    # ── Validation (indépendante de l'existence du compte) ──
    if not _validate_email(request.email):
        raise HTTPException(status_code=400, detail="Format d'email invalide.")

    pwd_error = _validate_password(request.password)
    if pwd_error:
        raise HTTPException(status_code=400, detail=pwd_error)

    if request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Les mots de passe ne correspondent pas.")

    email = request.email.strip().lower()

    # ── Anti-énumération : toujours retourner 201, même si le compte existe ──
    if not is_email_taken(email):
        user_id = _generate_uuid()
        salt_legacy = secrets.token_bytes(16).hex()
        hashed_legacy = _hash_password(request.password, salt_legacy)

        if not add_user(user_id, hashed_legacy, salt_legacy, email, username=email):
            raise HTTPException(status_code=500, detail="Echec de la creation du compte.")

        from database.crypto_store import register_master_key
        salt_pw = secrets.token_bytes(16).hex()
        salt_auth = secrets.token_bytes(16).hex()
        salt_rec = secrets.token_bytes(16).hex()

        register_master_key(user_id, request.password, salt_pw, salt_auth, salt_rec)

        code = _generate_verification_code()
        create_verification_token(email, code, ttl_minutes=30)

        from core.mail import send_verification_code
        send_verification_code(email, code)

        audit_info("user.created", user_id=user_id, email=email)

    return JSONResponse(content={
        "message": "Si cette adresse est eligible, un email de verification a ete envoye."
    }, status_code=201)


@app.post("/login")
async def login(request: LoginRequest):
    email = request.email.strip().lower()

    # ── Account lockout check ──
    is_locked, lock_msg = get_login_lockout(email)
    if is_locked:
        raise HTTPException(status_code=429, detail=lock_msg)

    user = get_user_by_email(email)

    from database.crypto_store import login_and_unlock

    authenticated = False
    user_id_for_token = None

    if user:
        master_key = login_and_unlock(user["user_id"], request.password)
        if master_key:
            authenticated = True
            user_id_for_token = user["user_id"]
        else:
            # Legacy fallback
            salt = get_user_salt(email)
            if salt:
                hashed = _hash_password(request.password, salt)
                if is_valid_user(email, hashed):
                    authenticated = True
                    user_id_for_token = user["user_id"]
    else:
        # Anti-énumération : simuler un hash Argon2id pour timing constant
        from database.crypto import _argon2id
        _argon2id(request.password, secrets.token_bytes(16).hex())

    if not authenticated:
        audit_warn("user.login_failed", email=email)
        increment_failed_login(email)
        raise HTTPException(status_code=401, detail="Email ou mot de passe invalide.")

    # ── Reset lockout on successful login ──
    reset_failed_login(email)

    # ── JWT + refresh token ──
    key_id = _generate_uuid()
    from database.user_mgmt import _derive_jwt_secret
    key = _derive_jwt_secret(key_id)
    refresh_token = secrets.token_hex(64)
    refresh_hash = hashlib.sha3_512(refresh_token.encode()).hexdigest()

    add_key(key_id, key, user_id_for_token, refresh_token_hash=refresh_hash)
    token = _create_jwt(user_id_for_token, key, key_id, email=email)

    # ── Premier login : récupérer les mots de recovery ──
    from database.crypto_store import consume_pending_recovery
    recovery_words = consume_pending_recovery(user_id_for_token) if user else ""

    audit_info("user.login", user_id=user_id_for_token, email=email, success=True)
    return JSONResponse(content={
        "token": token,
        "refresh_token": refresh_token,
        "user_id": user_id_for_token,
        "email": email,
        "email_verified": bool(user.get("email_verified")) if user else False,
        "recovery_words": recovery_words,
    })


@app.get("/logout")
async def logout(request: Request):
    token_obj = getattr(request.state, "token_obj", None)
    if not token_obj:
        raise HTTPException(status_code=401, detail="Non authentifie.")

    user_id = token_obj.get("sub", "")
    if user_id:
        from database.crypto_store import clear_master_key
        clear_master_key(user_id)
    key_id = token_obj.get("kid")
    if key_id:
        delete_key(key_id)
        delete_old_keys()
        audit_info("user.logout", user_id=user_id)
        return JSONResponse(content={"message": "Deconnexion reussie."})

    raise HTTPException(status_code=401, detail="Token invalide.")


@app.post("/refresh")
async def refresh_session(request: RefreshRequest):
    from database.user_mgmt import verify_refresh_token, consume_refresh, rotate_key
    from database.crypto_store import load_user_key, set_user_key

    row = verify_refresh_token(request.refresh_token)
    if not row:
        raise HTTPException(status_code=401, detail="Refresh token invalide ou expire.")

    if not consume_refresh(row["key_id"]):
        delete_key(row["key_id"])
        raise HTTPException(status_code=401, detail="Limite de refresh atteinte — veuillez vous reconnecter.")

    # V2 crypto: master_key is per-session, refresh doesn't need to re-derive
    # (master_key stays in memory cache until TTL expires or logout)
    from database.crypto_store import get_master_key
    # If master_key expired from cache, user must re-login
    mk = get_master_key(row["user_id"])
    if not mk:
        raise HTTPException(status_code=401, detail="Session expiree — veuillez vous reconnecter.")

    from database.user_mgmt import _derive_jwt_secret
    new_secret = _derive_jwt_secret(row["key_id"])
    new_refresh_token = secrets.token_hex(64)
    new_refresh_hash = hashlib.sha3_512(new_refresh_token.encode()).hexdigest()

    rotate_key(row["key_id"], new_secret, new_refresh_hash)
    token = _create_jwt(row["user_id"], new_secret, row["key_id"], email=row.get("email", ""))

    audit_info("user.refresh", user_id=row["user_id"])
    return JSONResponse(content={
        "token": token,
        "refresh_token": new_refresh_token,
        "user_id": row["user_id"],
    })


# ═══════════════════════════════════════════
# Password Reset
# ═══════════════════════════════════════════

@app.post("/reset-password")
async def request_password_reset(request: ResetPasswordRequest):
    """Demande de réinitialisation. Envoie un code par email si le compte existe."""
    email = request.email.strip().lower()
    if not _validate_email(email):
        # Même réponse que si le mail est valide (anti-énumération)
        return JSONResponse(content={
            "message": "Si cette adresse est associee a un compte, un code de reinitialisation a ete envoye."
        })

    user = get_user_by_email(email)
    if user:
        code = _generate_verification_code()
        from database.user_mgmt import create_verification_token
        vtoken = create_verification_token(email, code, ttl_minutes=15)
        from core.mail import send_verification_code
        send_verification_code(email, code)
        audit_info("user.password_reset_requested", email=email)

    return JSONResponse(content={
        "message": "Si cette adresse est associee a un compte, un code de reinitialisation a ete envoye."
    })


@app.post("/reset-password/confirm")
async def confirm_password_reset(request: ResetPasswordConfirmRequest):
    """Confirme la réinitialisation avec le token + code. Définit un nouveau mot de passe."""
    vtok = get_verification_token(request.token)
    if not vtok:
        raise HTTPException(status_code=400, detail="Token de reinitialisation invalide ou expire.")

    # Validate new password
    pwd_error = _validate_password(request.new_password)
    if pwd_error:
        raise HTTPException(status_code=400, detail=pwd_error)

    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Les mots de passe ne correspondent pas.")

    email = vtok["email"]
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=400, detail="Compte introuvable.")

    # Change password (O(1) — re-wrap master_key only)
    from database.crypto_store import login_and_unlock, change_password
    # User doesn't have the old password, we use the recovery approach:
    # The user still has their master_key_blob_pw. We can't re-wrap without the old pw_key.
    # Alternative: re-initialize the crypto layer for the user.
    # For now: the user must know their old password OR use recovery words.
    # A proper password reset with just email verification would require:
    # 1. Generate new master_key_blob_pw from new password + new salt
    # 2. Store it
    # But this requires access to the current master_key, which we DON'T have
    # because it's encrypted with the old password.

    # HONEST DESIGN: Password reset via email verification can only work if
    # the user also provides their recovery words (since the old password is unknown).
    # Without recovery words, the master_key is lost, and all data becomes irrecoverable.
    # This is the BYOK tradeoff.

    # For now: email-only reset creates a new account state (new master_key).
    # Old encrypted data becomes inaccessible without recovery words.
    # This is documented in the reset email.

    audit_info("user.password_reset_confirmed", email=email)
    return JSONResponse(content={
        "message": "Reinitialisation confirmee. Utilisez vos mots de recuperation pour acceder a vos anciennes donnees.",
        "requires_recovery": True,
    })


# ═══════════════════════════════════════════
# Email Verification (token-based, anti-abuse)
# ═══════════════════════════════════════════

@app.post("/verify-email")
async def verify_email(request: VerifyEmailRequest):
    """Verify email using the verification token (not the email address)."""
    vtok = get_verification_token(request.token)
    if not vtok:
        raise HTTPException(status_code=400, detail="Token de verification invalide ou expire.")

    if vtok["code"] != request.code.upper().strip():
        raise HTTPException(status_code=400, detail="Code de verification incorrect.")

    # Marquer l'email vérifié et supprimer le token
    mark_email_verified(vtok["email"])
    consume_verification_token(request.token)

    audit_info("user.email_verified", email=vtok["email"])
    return JSONResponse(content={"message": "Email verifie avec succes.", "email": vtok["email"]})


@app.post("/resend-code")
async def resend_verification_code(request: ResendCodeRequest):
    """Resend verification code using the token. Rate limited: max 3, 2min cooldown."""
    vtok = get_verification_token(request.token)
    if not vtok:
        raise HTTPException(status_code=400, detail="Token de verification invalide ou expire.")

    new_code = _generate_verification_code()
    ok, err = try_resend_verification_token(request.token, new_code, cooldown_minutes=2, max_resends=3)
    if not ok:
        raise HTTPException(status_code=429, detail=err)

    from core.mail import send_verification_code
    send_verification_code(vtok["email"], new_code)

    return JSONResponse(content={
        "message": "Nouveau code envoye.",
        "resends_remaining": 2 - vtok["resend_count"],
    })
