# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Authentication utility for pentest target auth_config resolution.

Supports: jwt_bearer, opaque_token, jwe, cookie, custom, basic, none.
Handles auto-detection for backward compatibility with existing profiles.
"""

import base64
import json
import logging

logger = logging.getLogger("elyria.redteam.auth")


def resolve_auth(auth_config):
    """Normalize and resolve an auth_config dict.

    Returns a new dict with auth_type always set. For JWE, attempts
    decryption and stores the result as bearer_token.
    """
    if not auth_config or not isinstance(auth_config, dict):
        return {"auth_type": "none", "headers": {}, "proxy": ""}

    cfg = dict(auth_config)  # shallow copy
    cfg.setdefault("headers", {})
    cfg.setdefault("proxy", "")

    auth_type = cfg.get("auth_type", "")
    if not auth_type:
        auth_type = _detect_auth_type(cfg)
    cfg["auth_type"] = auth_type

    # JWE: attempt decryption, store inner token as bearer_token
    if auth_type == "jwe":
        jwe_token = cfg.get("jwe_token", "")
        jwe_key = cfg.get("jwe_key", "")
        jwe_key_type = cfg.get("jwe_key_type", "symmetric")
        if jwe_token and jwe_key:
            inner = _try_decrypt_jwe(jwe_token, jwe_key, jwe_key_type)
            if inner:
                cfg["bearer_token"] = inner
                logger.info("JWE decrypted successfully for pentest auth")
            else:
                logger.warning("JWE decryption failed — scanner will run unauthenticated")

    return cfg


def _detect_auth_type(cfg):
    """Auto-detect the auth type from config fields (backward compat)."""
    # Custom: has custom_header_name and custom_header_value
    if cfg.get("custom_header_name") and cfg.get("custom_header_value"):
        return "custom"
    # Cookie: has both cookie_name and cookie_value
    if cfg.get("cookie_name") and cfg.get("cookie_value"):
        return "cookie"
    # JWE: has jwe_token
    if cfg.get("jwe_token"):
        return "jwe"
    # Bearer token present
    token = cfg.get("bearer_token", "")
    if token:
        # JWT-like: 3 dot-separated parts, first two are valid base64url JSON
        parts = token.split(".")
        if len(parts) == 3:
            if _is_valid_jwt_part(parts[0]) and _is_valid_jwt_part(parts[1]):
                return "jwt_bearer"
        # Not JWT → opaque
        return "opaque_token"
    # Basic auth
    if cfg.get("basic_user") and cfg.get("basic_pass"):
        return "basic"
    return "none"


def _is_valid_jwt_part(part):
    """Check if a JWT part is valid base64url-encoded JSON."""
    try:
        padded = part + "=" * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        json.loads(decoded)
        return True
    except Exception:
        return False


def _try_decrypt_jwe(jwe_token, key, key_type="symmetric"):
    """Attempt to decrypt a JWE compact serialization.

    Returns the inner plaintext (str) on success, None on failure.
    """
    # Try python-jose first
    try:
        from jose import jwe
        plaintext = jwe.decrypt(jwe_token, key)
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8")
        return plaintext
    except ImportError:
        pass
    except Exception:
        logger.debug("python-jose JWE decrypt failed, trying manual", exc_info=True)

    # Fallback: manual dir-alg decryption
    return _manual_jwe_decrypt(jwe_token, key)


def _manual_jwe_decrypt(jwe_token, key):
    """Manual JWE decryption for 'dir' algorithm (direct encryption).

    Parses compact serialization: header.encrypted_key.iv.ciphertext.tag
    Uses AES-GCM from cryptography library.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        parts = jwe_token.split(".")
        if len(parts) != 5:
            logger.warning("JWE: expected 5 parts, got %d", len(parts))
            return None

        header_b64, enc_key_b64, iv_b64, ct_b64, tag_b64 = parts

        # Decode header
        header = _b64decode_json(header_b64)
        if not header:
            return None
        enc = header.get("enc", "A256GCM")

        # Decode components
        iv = _b64url_decode(iv_b64)
        ct = _b64url_decode(ct_b64)
        tag = _b64url_decode(tag_b64)

        if not all([iv, ct, tag]):
            return None

        # Key: use raw bytes
        if isinstance(key, str):
            key_bytes = key.encode("utf-8")
            # If base64-encoded key, try decoding
            try:
                key_bytes = base64.urlsafe_b64decode(key + "=" * (4 - len(key) % 4))
            except Exception:
                key_bytes = key.encode("utf-8")
        else:
            key_bytes = key

        # AES key sizes
        key_sizes = {"A128GCM": 16, "A192GCM": 24, "A256GCM": 32}
        expected = key_sizes.get(enc, 32)
        if len(key_bytes) != expected:
            # Try to adjust key size
            if len(key_bytes) < expected:
                key_bytes = key_bytes.ljust(expected, b"\x00")
            else:
                key_bytes = key_bytes[:expected]

        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(iv, ct + tag, None)
        return plaintext.decode("utf-8")

    except ImportError:
        logger.warning("JWE manual decrypt requires 'cryptography' package")
        return None
    except Exception:
        logger.warning("JWE manual decryption failed", exc_info=True)
        return None


def _b64decode_json(b64_str):
    """Base64url-decode and parse JSON."""
    try:
        padded = b64_str + "=" * (4 - len(b64_str) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _b64url_decode(s):
    """Base64url-decode to bytes."""
    try:
        padded = s + "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def get_auth_description(auth):
    """Human-readable auth description for AI system prompts."""
    if not auth or not isinstance(auth, dict):
        return "AUTH: No authentication configured"

    auth_type = auth.get("auth_type", "none")

    descriptions = {
        "jwt_bearer": "AUTH: JWT Bearer token configured — make authenticated requests with Authorization header",
        "opaque_token": "AUTH: Opaque access token (Bearer) configured — make authenticated requests with Authorization header",
        "jwe": "AUTH: JWE encrypted token configured (decrypted to Bearer JWT) — make authenticated requests with Authorization header",
        "cookie": f"AUTH: Session cookie '{auth.get('cookie_name', 'session')}' configured — requests include Cookie header",
        "custom": f"AUTH: Custom header '{auth.get('custom_header_name', 'X-API-Key')}' configured",
        "basic": "AUTH: HTTP Basic authentication configured",
        "none": "AUTH: No authentication configured — make unauthenticated requests",
    }

    return descriptions.get(auth_type, f"AUTH: {auth_type} configured")
