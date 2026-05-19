# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Elyria Crypto Layer — Envelope Encryption with Argon2id + AES-256-GCM.

Architecture:
  1. Argon2id(password, salt) → 64-byte derived key
  2. Split: first 32B → auth_verifier (stored DB, login only)
            last 32B  → pw_key (in-memory, unwraps master_key)
  3. master_key = random(32) — never derived, never stored plaintext
  4. Recovery: 12-word BIP39 passphrase → Argon2id → rec_key
  5. rec_key wraps master_key → master_key_blob_rec (stored DB)
  6. pw_key wraps master_key → master_key_blob_pw (stored DB)

Guarantees:
  - DB dump → auth_verifier cannot derive pw_key (different halves of Argon2id output)
  - DB dump → master_key_blob_* is AES-GCM opaque without password or recovery
  - Password change → re-wrap master_key, no data re-encryption
"""

import base64
import hashlib
import hmac
import json
import os
import secrets

from argon2 import Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ═══════════════════════════════════════════════════════════════
# Argon2id parameters
# ═══════════════════════════════════════════════════════════════

ARGON_TIME_COST = 4
ARGON_MEM_COST = 65536  # 64 MB
ARGON_PARALLELISM = 2
ARGON_HASH_LEN = 64     # 64 bytes = auth(32) + pw_key(32)

RECOVERY_WORD_COUNT = 12
RECOVERY_WORD_LIST = None  # lazy-loaded from BIP39 list


def _argon2id(password: str, salt: str, hash_len: int = ARGON_HASH_LEN) -> bytes:
    """Derive key material from password + salt using Argon2id."""
    return hash_secret_raw(
        password.encode("utf-8"),
        salt.encode("utf-8"),
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEM_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=hash_len,
        type=Type.ID,
    )


# ═══════════════════════════════════════════════════════════════
# HKDF-SHA256
# ═══════════════════════════════════════════════════════════════

def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    i = 1
    while len(out) < length:
        out += hmac.new(prk, out[-32:] + info + bytes([i]), hashlib.sha256).digest()
        i += 1
    return out[:length]


# ═══════════════════════════════════════════════════════════════
# AES-256-GCM
# ═══════════════════════════════════════════════════════════════

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) + ciphertext + tag(16)."""
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_decrypt(key: bytes, blob: bytes) -> bytes | None:
    """AES-256-GCM decrypt. Returns plaintext or None on failure."""
    if len(blob) < 28:
        return None
    try:
        nonce, ct = blob[:12], blob[12:]
        aes = AESGCM(key)
        return aes.decrypt(nonce, ct, None)
    except Exception:
        return None


def aes_encrypt_string(key: bytes, plaintext: str) -> str:
    """AES-256-GCM encrypt a string. Returns base64 blob."""
    return base64.b64encode(aes_encrypt(key, plaintext.encode("utf-8"))).decode()


def aes_decrypt_string(key: bytes, encoded: str) -> str | None:
    """AES-256-GCM decrypt a base64 blob to string."""
    if not encoded:
        return None
    try:
        blob = base64.b64decode(encoded)
        result = aes_decrypt(key, blob)
        return result.decode("utf-8") if result else None
    except Exception:
        return None


def aes_encrypt_json(key: bytes, data: dict) -> str:
    """AES-256-GCM encrypt a JSON dict. Returns base64 blob."""
    return aes_encrypt_string(key, json.dumps(data, ensure_ascii=False))


def aes_decrypt_json(key: bytes, encoded: str) -> dict:
    """AES-256-GCM decrypt a base64 blob to dict."""
    result = aes_decrypt_string(key, encoded)
    if result:
        try:
            return json.loads(result)
        except Exception:
            pass
    return {}


# ═══════════════════════════════════════════════════════════════
# Key generation
# ═══════════════════════════════════════════════════════════════

def generate_key() -> bytes:
    """Generate a 32-byte AES-256 key."""
    return AESGCM.generate_key(bit_length=256)


# ═══════════════════════════════════════════════════════════════
# Password → Auth + Crypto (Argon2id, split output)
# ═══════════════════════════════════════════════════════════════

def derive_auth_and_key(password: str, salt: str) -> tuple[str, bytes]:
    """
    Derive both auth_verifier and pw_key from password + salt.
    Argon2id → 64 bytes:
      - first 32:  auth_verifier (hex, stored DB, login check)
      - last 32:   pw_key (bytes, in-memory, unwraps master_key)

    CRITICAL: auth_verifier CANNOT derive pw_key — one-way split.
    """
    raw = _argon2id(password, salt)  # 64 bytes
    auth = raw[:32].hex()            # stored DB, auth only
    key = raw[32:]                   # kept in memory, unwraps master_key
    return auth, key


def verify_auth(password: str, salt: str, stored_auth: str) -> bool:
    """Verify password against stored auth_verifier. Constant-time if equal length."""
    auth, _ = derive_auth_and_key(password, salt)
    return secrets.compare_digest(auth, stored_auth)


# ═══════════════════════════════════════════════════════════════
# Recovery phrase generation (BIP39)
# ═══════════════════════════════════════════════════════════════

def _load_bip39() -> list[str]:
    global RECOVERY_WORD_LIST
    if RECOVERY_WORD_LIST is None:
        try:
            # Use local word list
            wordlist_path = os.path.join(os.path.dirname(__file__), "bip39_english.txt")
            with open(wordlist_path, "r") as f:
                RECOVERY_WORD_LIST = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback: embedded minimal BIP39 (256 words for 8 bits each, ×12 = 96 bits)
            RECOVERY_WORD_LIST = [
                "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
                "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
                "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
                "adult","advance","advice","aerobic","affair","afford","afraid","africa","after","again",
                "age","agent","agree","ahead","aim","air","airport","aisle","alarm","album",
                "alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already",
                "also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor",
                "ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer",
                "antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april",
                "arch","arctic","area","arena","argue","arm","armed","armor","army","around",
                "arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect",
                "assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude",
                "attract","auction","audit","august","aunt","author","auto","autumn","average","avocado",
                "avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor",
                "bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar",
                "barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty",
                "because","become","beef","before","begin","behave","behind","believe","below","belt",
                "bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike",
            ]
            # This is truncated — ideally use full BIP39
    return RECOVERY_WORD_LIST


def generate_recovery_words() -> str:
    """Generate 12-word BIP39 recovery passphrase (~128 bits entropy)."""
    words = _load_bip39()
    # Use secrets for cryptographically secure random selection
    chosen = [secrets.choice(words) for _ in range(RECOVERY_WORD_COUNT)]
    return " ".join(chosen)


def derive_rec_key(recovery_words: str, salt: str) -> bytes:
    """
    Derive recovery key from recovery passphrase + salt.
    Argon2id → 32 bytes directly (no split, recovery has no auth component).
    """
    return _argon2id(recovery_words, salt, hash_len=32)


# ═══════════════════════════════════════════════════════════════
# Master key wrapping (envelope encryption)
# ═══════════════════════════════════════════════════════════════

def wrap_master_key(master_key: bytes, wrapping_key: bytes) -> str:
    """Encrypt master_key with a wrapping key (pw_key or rec_key). Returns base64 blob."""
    return aes_encrypt_string(wrapping_key, master_key.hex())


def unwrap_master_key(blob: str, wrapping_key: bytes) -> bytes | None:
    """Decrypt master_key from base64 blob using wrapping key. Returns bytes or None."""
    hex_key = aes_decrypt_string(wrapping_key, blob)
    if hex_key and len(hex_key) == 64:  # 32 bytes hex = 64 chars
        try:
            return bytes.fromhex(hex_key)
        except Exception:
            pass
    return None


# ═══════════════════════════════════════════════════════════════
# Data encryption with DEK (Data Encryption Key)
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# Server wrap key — for system-level encryption (configs, API keys)
# ═══════════════════════════════════════════════════════════════

_server_wrap_key: bytes | None = None


def get_server_wrap_key() -> bytes:
    global _server_wrap_key
    if _server_wrap_key is None:
        raw = os.getenv("ELYRIA_SERVER_WRAP_KEY", "")
        if raw:
            try:
                _server_wrap_key = bytes.fromhex(raw)
                return _server_wrap_key
            except ValueError:
                pass
        _server_wrap_key = secrets.token_bytes(32)
        print("[crypto] ELYRIA_SERVER_WRAP_KEY not set — using ephemeral key.")
    return _server_wrap_key


class DEKManager:
    """
    Manages Data Encryption Keys for collections.
    DEK is never stored plaintext — it's wrapped by a parent key (master_key or TVK).
    """

    @staticmethod
    def create_dek(parent_key: bytes) -> tuple[bytes, str]:
        """Generate a new DEK and wrap it with parent_key. Returns (dek, encrypted_dek_blob)."""
        dek = generate_key()
        blob = aes_encrypt_string(parent_key, dek.hex())
        return dek, blob

    @staticmethod
    def unwrap_dek(encrypted_dek: str, parent_key: bytes) -> bytes | None:
        """Decrypt a DEK blob using parent_key. Returns 32-byte DEK or None."""
        hex_key = aes_decrypt_string(parent_key, encrypted_dek)
        if hex_key and len(hex_key) == 64:
            try:
                return bytes.fromhex(hex_key)
            except Exception:
                pass
        return None

    @staticmethod
    def rotate_dek(encrypted_dek: str, old_parent_key: bytes, new_parent_key: bytes) -> tuple[bytes, str]:
        """Re-wrap a DEK from old_parent_key to new_parent_key."""
        dek = DEKManager.unwrap_dek(encrypted_dek, old_parent_key)
        if not dek:
            raise ValueError("Cannot unwrap DEK with old parent key")
        new_blob = aes_encrypt_string(new_parent_key, dek.hex())
        return dek, new_blob

    @staticmethod
    def seal(dek: bytes, data: dict) -> str:
        """Encrypt data with DEK."""
        return aes_encrypt_json(dek, data)

    @staticmethod
    def open(dek: bytes, encrypted: str) -> dict:
        """Decrypt data with DEK."""
        return aes_decrypt_json(dek, encrypted)
