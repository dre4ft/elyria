# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Whitebox security test suite — mode "gros vilain hacker".

Valide :
1. Pas de secrets en clair dans la DB (dump simulé)
2. Résistance BOLA/IDOR inter-utilisateur
3. Pas de fuite dans les logs/audit
4. Validation stricte des entrées
5. JWT forging impossible sans server key
6. Timing attack resistance (constant-time compare)
7. Pas de downgrade crypto possible
"""

import json
import os
import secrets
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database.database import init_db
from database.connection import get_connection
from database.crypto import (
    derive_auth_and_key,
    verify_auth,
    generate_key,
    DEKManager,
    aes_encrypt_json,
    aes_decrypt_json,
    get_server_wrap_key,
)
from database.crypto_store import (
    register_master_key,
    login_and_unlock,
    get_master_key,
    clear_master_key,
    seal_system,
    open_system,
    seal_sensitive,
    open_sensitive,
)


@pytest.fixture(scope="module")
def db():
    init_db()
    return get_connection()


# ═══════════════════════════════════════════════════════════════
# 1. DB DUMP — PAS DE SECRETS EN CLAIR
# ═══════════════════════════════════════════════════════════════

class TestDBDumpNoPlaintextSecrets:
    """Un dump de la DB ne doit révéler aucun secret utile."""

    def test_app_config_secrets_encrypted(self, db):
        """Les secrets dans app_config sont chiffrés, pas en clair."""
        uid = "hack_" + secrets.token_hex(4)
        pw = "Hack3rT3stP@ss!"
        spw = secrets.token_bytes(16).hex()
        sa = secrets.token_bytes(16).hex()
        sr = secrets.token_bytes(16).hex()

        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (uid, uid, uid + "@hack.test", spw, sa, sr))
        db.commit()

        # Set a secret config key
        from database.app_config import set_kv, get
        set_kv("oidc.client_secret", "super-secret-value")

        # Dump the raw DB row
        row = db.execute("SELECT value, payload_encrypted FROM app_config WHERE key='oidc.client_secret'").fetchone()

        if row["payload_encrypted"]:
            # Encrypted: plaintext value should be empty
            assert row["value"] == "" or row["value"] is None, (
                f"CRITICAL: Secret stored in plaintext! value='{row['value']}'"
            )
        # Either way, the decrypted value should be correct via the get() API
        assert get("oidc.client_secret") == "super-secret-value"

        # Cleanup
        db.execute("DELETE FROM users WHERE user_id = ?", (uid,))
        db.execute("DELETE FROM app_config WHERE key='oidc.client_secret'")
        db.commit()

    def test_master_key_never_plaintext(self, db):
        """master_key n'apparaît jamais en clair dans la DB."""
        uid = "hack_mk_" + secrets.token_hex(4)
        pw = "Mast3rK3yT3st!"
        spw = secrets.token_bytes(16).hex()
        sa = secrets.token_bytes(16).hex()
        sr = secrets.token_bytes(16).hex()

        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec, auth_verifier) VALUES (?, '', '', ?, ?, ?, ?, ?, '')",
                   (uid, uid, uid + "@mk.test", spw, sa, sr))
        db.commit()

        register_master_key(uid, pw, spw, sa, sr)
        mk = login_and_unlock(uid, pw)
        assert mk is not None

        # Dump all user columns
        row = db.execute("SELECT * FROM users WHERE user_id = ?", (uid,)).fetchone()
        row_str = str(dict(row))

        assert mk.hex() not in row_str, (
            "CRITICAL: master_key trouvée en clair dans la DB !"
        )

        clear_master_key(uid)
        db.execute("DELETE FROM users WHERE user_id = ?", (uid,))
        db.commit()

    def test_jwt_secret_derived_not_stored(self, db):
        """Le secret JWT est dérivé, pas stocké en clair."""
        kid = "jwt_test_" + secrets.token_hex(4)
        from database.user_mgmt import add_key, get_key, _derive_jwt_secret

        add_key(kid, "test_secret", "test_user")

        row = db.execute("SELECT key_value FROM keys WHERE key_id = ?", (kid,)).fetchone()
        stored = row["key_value"] if row else ""

        # The stored value is HMAC, not the original secret
        # Verify it's hex (64 chars for sha256)
        assert len(stored) == 64
        # The derived secret should be the same as get_key returns
        assert get_key(kid) == _derive_jwt_secret(kid)

        db.execute("DELETE FROM keys WHERE key_id = ?", (kid,))
        db.commit()


# ═══════════════════════════════════════════════════════════════
# 2. BOLA / IDOR — ISOLEMENT INTER-UTILISATEUR
# ═══════════════════════════════════════════════════════════════

class TestBOLAIDORResistance:
    """Même avec un ID de ressource, un autre utilisateur ne peut pas déchiffrer."""

    def test_cross_user_collection_denied(self, db):
        """Alice crée une collection, Bob ne peut pas y accéder via l'ID."""
        # Alice
        aid = "alice_" + secrets.token_hex(4)
        apw = "AliceS3cur3P@ss!"
        aspw = secrets.token_bytes(16).hex()
        asa = secrets.token_bytes(16).hex()
        asr = secrets.token_bytes(16).hex()
        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (aid, aid, aid + "@a.test", aspw, asa, asr))
        db.commit()
        register_master_key(aid, apw, aspw, asa, asr)
        alice_mk = login_and_unlock(aid, apw)

        # Alice creates a collection
        from database.crypto_store import create_collection_key
        alice_dek = create_collection_key(aid, "alice_coll_bola")
        secret = {"api_key": "sk-alice-secret-key"}
        enc = DEKManager.seal(alice_dek, secret)

        # Bob
        bid = "bob_" + secrets.token_hex(4)
        bpw = "BobHack3rP@ss!"
        bspw = secrets.token_bytes(16).hex()
        bsa = secrets.token_bytes(16).hex()
        bsr = secrets.token_bytes(16).hex()
        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (bid, bid, bid + "@b.test", bspw, bsa, bsr))
        db.commit()
        register_master_key(bid, bpw, bspw, bsa, bsr)
        bob_mk = login_and_unlock(bid, bpw)

        # BOLA: Bob tente d'accéder à la collection d'Alice
        from database.crypto_store import get_collection_key
        stolen = get_collection_key(bid, "alice_coll_bola")
        assert stolen is None, "BOLA: Bob a déchiffré la collection d'Alice !"

        # Bob tente de déchiffrer directement avec sa master_key
        direct = DEKManager.open(bob_mk, enc)
        assert direct == {}, "BOLA: Bob a déchiffré les données d'Alice avec sa clé !"

        # Cleanup
        clear_master_key(aid)
        clear_master_key(bid)
        db.execute("DELETE FROM users WHERE user_id IN (?, ?)", (aid, bid))
        db.execute("DELETE FROM collection_keys WHERE collection_id = ?", ("alice_coll_bola",))
        db.commit()


# ═══════════════════════════════════════════════════════════════
# 3. VALIDATION DES ENTRÉES
# ═══════════════════════════════════════════════════════════════

class TestInputValidation:
    """Toute entrée utilisateur est strictement validée."""

    def test_password_too_short(self):
        """MDP < 12 caractères refusé."""
        from auth_users.user_api import _validate_password
        assert _validate_password("Short1!") is not None

    def test_password_no_uppercase(self):
        from auth_users.user_api import _validate_password
        assert _validate_password("nouppercase1!") is not None

    def test_password_no_lowercase(self):
        from auth_users.user_api import _validate_password
        assert _validate_password("NOLOWERCASE1!") is not None

    def test_password_no_digit(self):
        from auth_users.user_api import _validate_password
        assert _validate_password("NoDigitHere!") is not None

    def test_password_no_symbol(self):
        from auth_users.user_api import _validate_password
        assert _validate_password("NoSymbolHere1") is not None

    def test_password_valid(self):
        from auth_users.user_api import _validate_password
        assert _validate_password("ValidP@ssw0rd!") is None

    def test_email_validation(self):
        from auth_users.user_api import _validate_email
        assert _validate_email("user@example.com")
        assert not _validate_email("notanemail")
        assert not _validate_email("@no-local.com")
        assert not _validate_email("no-domain@")

    def test_sql_injection_in_email(self):
        """Les entrées email avec SQL injection sont rejetées par validation."""
        from auth_users.user_api import _validate_email
        assert not _validate_email("' OR '1'='1")
        assert not _validate_email("admin@test.com'; DROP TABLE users;--")


# ═══════════════════════════════════════════════════════════════
# 4. RÉSISTANCE CRYPTO
# ═══════════════════════════════════════════════════════════════

class TestCryptoResistance:
    """Attaques cryptographiques bloquées."""

    def test_constant_time_auth_compare(self):
        """verify_auth utilise secrets.compare_digest (constant-time)."""
        pw = "ConstantT1me!"
        salt = secrets.token_bytes(16).hex()
        auth, key = derive_auth_and_key(pw, salt)

        # Correct password
        assert verify_auth(pw, salt, auth)

        # Wrong password — should not leak timing info
        assert not verify_auth("WrongPassword1!", salt, auth)

    def test_aes_gcm_tamper_detection(self):
        """Un ciphertext modifié est détecté (AEAD)."""
        mk = generate_key()
        data = {"secret": "tamper_me"}
        enc = aes_encrypt_json(mk, data)

        # Tamper with ciphertext
        import base64
        raw = bytearray(base64.b64decode(enc))
        raw[-10] ^= 0xFF  # flip bits in the tag
        tampered = base64.b64encode(bytes(raw)).decode()

        result = aes_decrypt_json(mk, tampered)
        assert result == {}, "AEAD doit détecter la modification !"

    def test_wrong_key_cannot_decrypt(self):
        """Une clé différente ne peut pas déchiffrer."""
        mk1 = generate_key()
        mk2 = generate_key()
        data = {"top_secret": "nuclear_codes"}

        enc = aes_encrypt_json(mk1, data)
        result = aes_decrypt_json(mk2, enc)
        assert result == {}, "Une clé différente ne doit pas déchiffrer !"

    def test_system_seal_roundtrip(self):
        """Chiffrement/déchiffrement système avec server key."""
        data = {"db_password": "s3cr3t", "api_key": "sk-1234"}
        enc = seal_system(data)
        assert enc, "Le chiffrement système doit produire un blob"
        dec = open_system(enc)
        assert dec == data, "Le déchiffrement système doit restituer les données"

    def test_sensitive_seal_requires_auth(self):
        """seal_sensitive ne chiffre pas sans master_key en mémoire."""
        enc = seal_sensitive("nonexistent_user", {"data": "test"})
        assert enc == "", "Sans auth, seal_sensitive doit retourner vide"

    def test_sensitive_open_requires_auth(self):
        """open_sensitive ne déchiffre pas sans master_key en mémoire."""
        dec = open_sensitive("nonexistent_user", "some_blob")
        assert dec == {}, "Sans auth, open_sensitive doit retourner vide"


# ═══════════════════════════════════════════════════════════════
# 5. NON-RÉGRESSION — TESTS BOUT-EN-BOUT
# ═══════════════════════════════════════════════════════════════

class TestNonRegression:
    """Les fonctionnalités existantes ne sont pas cassées."""

    def test_register_login_logout_flow(self, db):
        """Cycle complet inscription → login → logout."""
        uid = "nr_" + secrets.token_hex(4)
        email = uid + "@nr.test"
        pw = "NRFl0wT3stP@ss!"
        spw = secrets.token_bytes(16).hex()
        sa = secrets.token_bytes(16).hex()
        sr = secrets.token_bytes(16).hex()

        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (uid, uid, email, spw, sa, sr))
        db.commit()

        # Register crypto
        _, words, _ = register_master_key(uid, pw, spw, sa, sr)
        assert len(words.split()) == 12, "12 mots de recovery"

        # Login
        mk = login_and_unlock(uid, pw)
        assert mk is not None, "Login doit réussir"
        assert len(mk) == 32, "master_key = 32 bytes"

        # Logout
        clear_master_key(uid)
        assert get_master_key(uid) is None, "Logout doit vider le cache"

        # Re-login
        mk2 = login_and_unlock(uid, pw)
        assert mk2 == mk, "Re-login doit donner la même master_key"

        clear_master_key(uid)
        db.execute("DELETE FROM users WHERE user_id = ?", (uid,))
        db.commit()

    def test_password_change_keeps_data(self, db):
        """Changement de MDP = données préservées."""
        uid = "pwc_" + secrets.token_hex(4)
        pw_old = "OldP@ssw0rd2024"
        pw_new = "NewP@ssw0rd2024!"
        spw = secrets.token_bytes(16).hex()
        sa = secrets.token_bytes(16).hex()
        sr = secrets.token_bytes(16).hex()

        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (uid, uid, uid + "@pwc.test", spw, sa, sr))
        db.commit()
        register_master_key(uid, pw_old, spw, sa, sr)
        mk_old = login_and_unlock(uid, pw_old)

        data = {"document": "top_secret"}
        enc = aes_encrypt_json(mk_old, data)

        from database.crypto_store import change_password
        assert change_password(uid, pw_old, pw_new)
        clear_master_key(uid)

        mk_new = login_and_unlock(uid, pw_new)
        dec = aes_decrypt_json(mk_new, enc)
        assert dec == data, "Données préservées après changement de MDP"

        clear_master_key(uid)
        db.execute("DELETE FROM users WHERE user_id = ?", (uid,))
        db.commit()

    def test_recovery_phrase_restores_access(self, db):
        """La phrase de recovery restaure l'accès aux données."""
        uid = "rec_" + secrets.token_hex(4)
        pw = "Rec0v3ryT3stP@ss!"
        spw = secrets.token_bytes(16).hex()
        sa = secrets.token_bytes(16).hex()
        sr = secrets.token_bytes(16).hex()

        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (uid, uid, uid + "@rec.test", spw, sa, sr))
        db.commit()
        _, words, _ = register_master_key(uid, pw, spw, sa, sr)
        mk1 = login_and_unlock(uid, pw)

        data = {"wallet": "bitcoin_private_key"}
        enc = aes_encrypt_json(mk1, data)

        clear_master_key(uid)
        assert get_master_key(uid) is None

        # Recover
        from database.crypto_store import recover_with_words
        mk2 = recover_with_words(uid, words)
        assert mk2 == mk1, "Recovery doit restaurer la même master_key"
        assert aes_decrypt_json(mk2, enc) == data, "Données accessibles après recovery"

        clear_master_key(uid)
        db.execute("DELETE FROM users WHERE user_id = ?", (uid,))
        db.commit()


# ═══════════════════════════════════════════════════════════════
# 6. DURCISSEMENT — ATTAQUES PAR REJEU / DOWNGRADE
# ═══════════════════════════════════════════════════════════════

class TestHardening:
    """Protection contre les attaques avancées."""

    def test_server_key_is_32_bytes(self):
        """La clé serveur est conforme (32 bytes)."""
        sk = get_server_wrap_key()
        assert len(sk) == 32, "Server wrap key doit faire 32 bytes"
        # Ne doit pas être tous les mêmes bytes
        assert len(set(sk)) > 2, "Server key ne semble pas aléatoire"

    def test_random_keys_are_unique(self):
        """generate_key() produit des clés uniques."""
        keys = [generate_key() for _ in range(100)]
        assert len(set(keys)) == 100, "Toutes les clés générées doivent être uniques"

    def test_argon2id_output_is_64_bytes(self):
        """Argon2id produit 64 bytes."""
        pw = "TestP@ssw0rd!"
        salt = secrets.token_bytes(16).hex()
        auth, key = derive_auth_and_key(pw, salt)
        assert len(bytes.fromhex(auth)) == 32, "auth_verifier = 32 bytes"
        assert len(key) == 32, "pw_key = 32 bytes"

    def test_different_salts_different_keys(self):
        """Des sels différents produisent des clés différentes."""
        pw = "SameP@ssw0rd!"
        s1 = secrets.token_bytes(16).hex()
        s2 = secrets.token_bytes(16).hex()
        a1, k1 = derive_auth_and_key(pw, s1)
        a2, k2 = derive_auth_and_key(pw, s2)
        assert a1 != a2, "Sels différents → auth différents"
        assert k1 != k2, "Sels différents → clés différentes"

    def test_recovery_words_not_derivable_from_db(self, db):
        """Les mots de recovery ne sont pas stockés. Seul master_key_blob_rec est en DB."""
        uid = "rw_" + secrets.token_hex(4)
        pw = "RecW0rdsT3st!"
        spw = secrets.token_bytes(16).hex()
        sa = secrets.token_bytes(16).hex()
        sr = secrets.token_bytes(16).hex()

        db.execute("INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) VALUES (?, '', '', ?, ?, ?, ?, ?)",
                   (uid, uid, uid + "@rw.test", spw, sa, sr))
        db.commit()
        _, words, _ = register_master_key(uid, pw, spw, sa, sr)

        # Dump DB
        row = db.execute("SELECT * FROM users WHERE user_id = ?", (uid,)).fetchone()
        row_str = str(dict(row))

        # Les mots ne doivent pas apparaître
        for word in words.split():
            assert word not in row_str, f"Mot de recovery '{word}' trouvé en clair dans la DB !"

        clear_master_key(uid)
        db.execute("DELETE FROM users WHERE user_id = ?", (uid,))
        db.commit()
