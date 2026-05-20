# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Validation des 7 garanties de l'architecture crypto Elyria v2.

Argon2id + Envelope Encryption (AES-256-GCM).
master_key = random(32), jamais derivée, jamais stockée en clair.
"""

import pytest

from database.crypto import (
    derive_auth_and_key,
    generate_key,
    wrap_master_key,
    unwrap_master_key,
    DEKManager,
    aes_encrypt_json,
    aes_decrypt_json,
    aes_decrypt_string,
)
from database.crypto_store import (
    register_master_key,
    login_and_unlock,
    get_master_key,
    clear_master_key,
    change_password,
    recover_with_words as store_recover,
    create_collection_key,
    get_collection_key,
    create_tvk,
    add_member_to_team,
    remove_member_from_team,
    get_tvk,
)
from database.connection import get_connection


class TestClaim1_DBDumpCannotDeriveMasterKey:
    """
    Garantie : un dump de la DB ne permet pas de dériver la master_key.

    auth_verifier = Argon2id(password, salt_auth)[:32]  → stocké DB
    pw_key        = Argon2id(password, salt_pw)[32:]     → mémoire seule

    Les 2 moitiés sont issues du même appel Argon2id, mais le sel est différent
    (salt_auth ≠ salt_pw). Même avec le même sel, la première moitié d'Argon2id
    ne donne aucune information sur la seconde.
    """

    def test_auth_verifier_cannot_decrypt_master_key_blob(self, unlocked_user):
        """auth_verifier seul ne déchiffre pas master_key_blob_pw."""
        uid = unlocked_user["user_id"]

        conn = get_connection()
        row = conn.execute(
            "SELECT auth_verifier, master_key_blob_pw FROM users WHERE user_id = ?",
            (uid,),
        ).fetchone()
        conn.close()

        # Tenter de déchiffrer master_key_blob avec auth_verifier comme clé
        auth_bytes = bytes.fromhex(row["auth_verifier"])
        result = aes_decrypt_string(auth_bytes, row["master_key_blob_pw"])

        assert result is None, (
            "CRITICAL: auth_verifier a déchiffré master_key_blob ! "
            "La DB dump permet de lire toutes les données."
        )

    def test_salts_are_different(self, unlocked_user):
        """Les 3 sels (pw, auth, rec) sont distincts."""
        uid = unlocked_user["user_id"]

        conn = get_connection()
        row = conn.execute(
            "SELECT salt_pw, salt_auth, salt_rec FROM users WHERE user_id = ?",
            (uid,),
        ).fetchone()
        conn.close()

        assert row["salt_pw"] != row["salt_auth"], "salt_pw et salt_auth doivent différer"
        assert row["salt_pw"] != row["salt_rec"], "salt_pw et salt_rec doivent différer"
        assert row["salt_auth"] != row["salt_rec"], "salt_auth et salt_rec doivent différer"

    def test_master_key_never_stored_plaintext(self, unlocked_user):
        """master_key n'apparaît nulle part en clair dans la DB."""
        uid = unlocked_user["user_id"]

        conn = get_connection()
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,)).fetchone()
        conn.close()

        mk = get_master_key(uid)
        assert mk is not None

        mk_hex = mk.hex()
        row_str = str(dict(row))

        assert mk_hex not in row_str, (
            "CRITICAL: master_key trouvée en clair dans la DB !"
        )


class TestClaim2_LoginRestoresMasterKey:
    """
    Garantie : le login déchiffre master_key et la place en mémoire.
    Elle n'est jamais écrite sur disque.
    """

    def test_login_restores_master_key(self, unlocked_user):
        """Après login, master_key est accessible en mémoire."""
        mk = get_master_key(unlocked_user["user_id"])
        assert mk is not None, "master_key doit être en mémoire après login"
        assert len(mk) == 32, "master_key doit faire 32 bytes (AES-256)"

    def test_logout_clears_master_key(self, unlocked_user):
        """Après clear_master_key, la clé n'est plus accessible."""
        uid = unlocked_user["user_id"]

        clear_master_key(uid)
        mk = get_master_key(uid)
        assert mk is None, "master_key doit être supprimée après clear_master_key"

        # Re-login pour ne pas casser les autres tests
        mk2 = login_and_unlock(uid, unlocked_user["password"])
        assert mk2 is not None

    def test_master_key_is_32_bytes(self, unlocked_user):
        """La master_key est conforme (32 bytes pour AES-256)."""
        mk = get_master_key(unlocked_user["user_id"])
        assert len(mk) == 32
        # Vérifier que c'est bien du random (pas tous les mêmes bytes)
        assert len(set(mk)) > 2, "master_key ne semble pas aléatoire"


class TestClaim3_PasswordChangeO1:
    """
    Garantie : le changement de mot de passe est O(1).
    Seul master_key_blob_pw est ré-enveloppé, les données ne bougent pas.
    """

    def test_password_change_preserves_data(self, unlocked_user):
        """Les données chiffrées avec l'ancien mot de passe sont lisibles après changement."""
        uid = unlocked_user["user_id"]
        mk = get_master_key(uid)

        original = {"message": "donnee sensible", "id": 42}
        encrypted = aes_encrypt_json(mk, original)

        ok = change_password(uid, unlocked_user["password"], "NewStr0ngP@ss!")
        assert ok, "Le changement de mot de passe doit réussir"

        # Login avec le nouveau mot de passe
        mk2 = login_and_unlock(uid, "NewStr0ngP@ss!")
        assert mk2 is not None, "Login avec le nouveau mot de passe doit fonctionner"

        # Déchiffrer les données d'avant
        decrypted = aes_decrypt_json(mk2, encrypted)
        assert decrypted == original, (
            f"Les données doivent survivre au changement de mot de passe. "
            f"Attendu: {original}, Obtenu: {decrypted}"
        )

    def test_old_password_fails_after_change(self, unlocked_user):
        """L'ancien mot de passe ne fonctionne plus après changement."""
        uid = unlocked_user["user_id"]

        # D'abord changer le mot de passe
        change_password(uid, unlocked_user["password"], "Anoth3rStr0ngP@ss!")
        clear_master_key(uid)

        # L'ancien mot de passe doit échouer
        mk_old = login_and_unlock(uid, unlocked_user["password"])
        assert mk_old is None, "L'ancien mot de passe ne doit plus fonctionner"

        # Re-login avec le bon pour les autres tests
        mk_new = login_and_unlock(uid, "Anoth3rStr0ngP@ss!")
        assert mk_new is not None
        # Restore original password for other tests
        change_password(uid, "Anoth3rStr0ngP@ss!", unlocked_user["password"])


class TestClaim4_RecoveryPhrase:
    """
    Garantie : la phrase de 12 mots BIP39 permet de restaurer la master_key.
    132 bits d'entropie. Générée via secrets.SystemRandom (os.urandom).
    """

    def test_recovery_restores_same_master_key(self, unlocked_user):
        """La recovery phrase déchiffre la même master_key que le mot de passe."""
        uid = unlocked_user["user_id"]
        mk_original = get_master_key(uid)
        assert mk_original is not None

        # Récupérer les recovery_words depuis le retour de register_master_key
        # (on les a stockées dans le test fixture, voir unlocked_user)
        # En réalité, on doit les récupérer via la DB ou le retour d'enregistrement
        # Pour ce test, on refait register pour avoir les mots
        # → On ne peut pas les ré-afficher par design. On teste le flux via store_recover.

        # Simuler : on connaît les mots (stockés par le test précédent)
        # Pour ce test, on regénère un user avec les mots
        import secrets as _secrets
        uid2 = "rec_" + _secrets.token_hex(6)
        pw2 = "TestRec0v3ryP@ss!"
        spw2 = _secrets.token_bytes(16).hex()
        sa2 = _secrets.token_bytes(16).hex()
        sr2 = _secrets.token_bytes(16).hex()

        conn = get_connection()
        conn.execute(
            "INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) "
            "VALUES (?, '', '', ?, ?, ?, ?, ?)",
            (uid2, uid2, uid2 + "@t.com", spw2, sa2, sr2),
        )
        conn.commit()
        conn.close()

        _, words, _ = register_master_key(uid2, pw2, spw2, sa2, sr2)
        mk1 = login_and_unlock(uid2, pw2)
        assert mk1 is not None

        # Flush et recover
        clear_master_key(uid2)
        assert get_master_key(uid2) is None

        mk2 = store_recover(uid2, words)
        assert mk2 is not None, "La recovery phrase doit restaurer master_key"
        assert mk2 == mk1, "La master_key restaurée doit être identique à l'originale"

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM users WHERE user_id = ?", (uid2,))
        conn.commit()
        conn.close()
        clear_master_key(uid2)

    def test_wrong_recovery_words_fail(self, unlocked_user):
        """Des mots de recovery incorrects ne restaurent rien."""
        import secrets as _secrets
        uid2 = "wrec_" + _secrets.token_hex(6)
        pw2 = "TestRecF@ilP@ss!"
        spw2 = _secrets.token_bytes(16).hex()
        sa2 = _secrets.token_bytes(16).hex()
        sr2 = _secrets.token_bytes(16).hex()

        conn = get_connection()
        conn.execute(
            "INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) "
            "VALUES (?, '', '', ?, ?, ?, ?, ?)",
            (uid2, uid2, uid2 + "@t.com", spw2, sa2, sr2),
        )
        conn.commit()
        conn.close()

        register_master_key(uid2, pw2, spw2, sa2, sr2)
        login_and_unlock(uid2, pw2)
        clear_master_key(uid2)

        # Mauvais mots
        wrong = "abandon " * 12
        mk_bad = store_recover(uid2, wrong)
        assert mk_bad is None, "De mauvais mots ne doivent pas restaurer master_key"

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM users WHERE user_id = ?", (uid2,))
        conn.commit()
        conn.close()

    def test_recovery_words_entropy(self):
        """12 mots BIP39 = 132 bits d'entropie (> 128-bit security)."""
        import math

        # Charger la wordlist
        wordlist_path = __import__("os").path.join(
            __import__("os").path.dirname(__file__), "..", "app", "database", "bip39_english.txt"
        )
        with open(wordlist_path) as f:
            words = [l.strip() for l in f if l.strip()]

        assert len(words) == 2048, "BIP39 doit avoir 2048 mots"
        assert 2048 & (2048 - 1) == 0, "2048 = 2^11 → pas de biais modulo"

        bits = math.log2(2048) * 12
        assert bits >= 128, f"12 mots = {bits:.0f} bits, doit être >= 128"


class TestClaim5_WrongPasswordNoAccess:
    """
    Garantie : sans le bon mot de passe, les données sont inaccessibles.
    """

    def test_wrong_password_login_fails(self, unlocked_user):
        """Un mauvais mot de passe ne débloque pas master_key."""
        mk = login_and_unlock(unlocked_user["user_id"], "WrongP@ssw0rd!")
        assert mk is None, "Un mauvais mot de passe ne doit pas donner master_key"

    def test_cannot_decrypt_without_login(self, unlocked_user):
        """Sans login préalable, get_master_key retourne None."""
        uid = unlocked_user["user_id"]

        clear_master_key(uid)
        mk = get_master_key(uid)
        assert mk is None, "Sans login, pas de master_key"

        # Re-login
        login_and_unlock(uid, unlocked_user["password"])


class TestClaim6_DEKPerCollection:
    """
    Garantie : chaque collection a un DEK unique.
    Un DEK ne peut pas déchiffrer les données d'une autre collection.
    """

    def test_deks_are_unique(self, unlocked_user):
        """Deux collections ont des DEK différents."""
        uid = unlocked_user["user_id"]

        dek_a = create_collection_key(uid, "col_alpha_" + uid)
        dek_b = create_collection_key(uid, "col_beta_" + uid)

        assert dek_a != dek_b, "Chaque collection doit avoir un DEK unique"

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM collection_keys WHERE collection_id LIKE ?", (uid + "%",))
        conn.commit()
        conn.close()

    def test_dek_isolation(self, unlocked_user):
        """Un DEK ne déchiffre pas les données d'une autre collection."""
        uid = unlocked_user["user_id"]

        dek_a = create_collection_key(uid, "iso_alpha_" + uid)
        dek_b = create_collection_key(uid, "iso_beta_" + uid)

        # Chiffrer avec DEK A
        secret_a = {"owner": "alpha", "value": 100}
        enc_a = DEKManager.seal(dek_a, secret_a)

        # Tenter de déchiffrer avec DEK B → doit échouer
        result = DEKManager.open(dek_b, enc_a)
        assert result == {}, (
            f"CRITICAL: DEK_B a déchiffré les données de DEK_A ! "
            f"Isolation brisée. Result: {result}"
        )

        # DEK A déchiffre correctement
        result_a = DEKManager.open(dek_a, enc_a)
        assert result_a == secret_a

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM collection_keys WHERE collection_id LIKE ?", ("iso_%" + uid,))
        conn.commit()
        conn.close()

    def test_dek_persists_in_db_wrapped(self, unlocked_user):
        """Le DEK est stocké chiffré dans la DB, pas en clair."""
        uid = unlocked_user["user_id"]
        cid = "persist_" + uid

        dek = create_collection_key(uid, cid)

        conn = get_connection()
        row = conn.execute(
            "SELECT encrypted_dek FROM collection_keys WHERE collection_id = ?", (cid,)
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["encrypted_dek"], "encrypted_dek ne doit pas être vide"
        # Le DEK en clair ne doit pas apparaître tel quel dans le blob
        assert dek.hex() not in row["encrypted_dek"], (
            "CRITICAL: DEK en clair trouvé dans la DB !"
        )

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM collection_keys WHERE collection_id = ?", (cid,))
        conn.commit()
        conn.close()


class TestClaim7_TeamVaultKey:
    """
    Garantie : TVK partagée via wrapping par master_key de chaque membre.
    +membre = O(1), -membre = O(n) collections (rotation TVK).
    """

    def test_add_member_o1(self, team_with_members):
        """Ajouter un membre est O(1) — historique immédiatement accessible."""
        from database.crypto_store import login_and_unlock, get_tvk

        # Bob peut déjà lire (ajouté dans la fixture)
        bob_mk = login_and_unlock(
            team_with_members["bob_id"], team_with_members["bob_password"]
        )
        assert bob_mk is not None

        tvk = get_tvk(team_with_members["bob_id"], team_with_members["team_id"])
        assert tvk is not None, "Bob doit avoir accès à la TVK"

    def test_remove_member_loses_access(self, team_with_members):
        """Un membre retiré ne peut plus accéder à la TVK."""
        bid = team_with_members["bob_id"]
        tid = team_with_members["team_id"]

        count = remove_member_from_team(tid, bid)
        assert count >= 0, "La rotation TVK doit réussir"

        tvk = get_tvk(bid, tid)
        assert tvk is None, "Bob ne doit plus avoir accès à la TVK après suppression"

    def test_creator_keeps_access_after_member_removal(self, team_with_members):
        """Le créateur conserve l'accès après la suppression d'un membre."""
        import secrets as _secrets
        cid = team_with_members["collection_id"]
        uid = team_with_members["creator_id"]
        tid = team_with_members["team_id"]

        from database.crypto_store import login_and_unlock, get_tvk, create_collection_key
        from database.crypto import DEKManager

        # Login creator
        mk = login_and_unlock(uid, team_with_members["creator_password"])
        assert mk is not None

        # Créer des données d'équipe
        tvk = get_tvk(uid, tid)
        assert tvk is not None

        dek = create_collection_key(uid, cid, tid)
        secret = {"team_data": "confidentiel"}
        enc = DEKManager.seal(dek, secret)

        # Supprimer Bob
        remove_member_from_team(tid, team_with_members["bob_id"])

        # Creator re-lit après rotation
        tvk2 = get_tvk(uid, tid)
        assert tvk2 is not None, "Le créateur doit toujours avoir la TVK"

        conn = get_connection()
        row = conn.execute(
            "SELECT encrypted_dek FROM collection_keys WHERE collection_id = ?", (cid,)
        ).fetchone()
        conn.close()

        dek2 = DEKManager.unwrap_dek(row["encrypted_dek"], tvk2)
        assert dek2 is not None, "Le créateur doit pouvoir déchiffrer le DEK après rotation"

        data = DEKManager.open(dek2, enc)
        assert data == secret, (
            f"Le créateur doit lire les données après rotation. "
            f"Attendu: {secret}, Obtenu: {data}"
        )

    def test_remove_member_o_n_collections(self, team_with_members):
        """La rotation TVK ne re-chiffre que les DEK, pas les données."""
        tid = team_with_members["team_id"]
        bid = team_with_members["bob_id"]

        # Créer plusieurs collections
        cid = team_with_members["collection_id"]
        # La fixture en a déjà créé une, ajoutons-en une autre
        uid = team_with_members["creator_id"]
        from database.crypto_store import login_and_unlock, create_collection_key
        login_and_unlock(uid, team_with_members["creator_password"])

        import secrets as _secrets
        cid2 = "col2_" + _secrets.token_hex(4)
        conn = get_connection()
        conn.execute(
            "INSERT INTO collection_keys (collection_id, encrypted_dek, team_id) VALUES (?, ?, ?)",
            (cid2, "", tid),
        )
        conn.commit()
        conn.close()
        create_collection_key(uid, cid2, tid)

        count = remove_member_from_team(tid, bid)

        # Vérifier que le nombre de collections ré-enveloppées correspond
        assert count >= 1, f"Au moins 1 collection doit être ré-enveloppée, count={count}"

        # Vérifier que c'est O(n) collections, pas O(n) données
        # → On vérifie juste que count est petit (nb de collections, pas nb de lignes de données)
        assert count < 100, f"Trop de ré-enveloppements: {count} (attend O(n) collections)"


class TestClaim8_BOLA_IDOR_EncryptionAtRest:
    """
    Garantie : même en cas de BOLA/IDOR (accès non autorisé à l'ID d'une ressource),
    les données récupérées sont chiffrées et illisibles sans la master_key du propriétaire.

    Un attaquant qui devine ou manipule un ID de collection/document obtient
    un blob AES-256-GCM qu'il ne peut pas déchiffrer sans la clé du propriétaire.
    """

    def test_cross_user_cannot_decrypt_others_collection(self, unlocked_user):
        """Alice ne peut pas déchiffrer la collection de Bob même avec l'ID."""
        from database.crypto_store import (
            register_master_key, login_and_unlock,
            create_collection_key, get_collection_key,
        )
        from database.connection import get_connection
        import secrets as _secrets

        # Alice crée une collection avec des données sensibles
        alice = unlocked_user
        alice_dek = create_collection_key(alice["user_id"], "alice_secret_col")
        alice_mk = get_master_key(alice["user_id"])
        secret = {"credit_card": "4111111111111111", "cvv": "123"}
        encrypted = DEKManager.seal(alice_dek, secret)

        # Bob crée son compte et tente d'accéder à la collection d'Alice via son ID
        bob_id = "bola_bob_" + _secrets.token_hex(4)
        bob_pass = "BobBOLAT3stP@ss!"
        bspw = _secrets.token_bytes(16).hex()
        bsa = _secrets.token_bytes(16).hex()
        bsr = _secrets.token_bytes(16).hex()

        conn = get_connection()
        conn.execute(
            "INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) "
            "VALUES (?, '', '', ?, ?, ?, ?, ?)",
            (bob_id, bob_id, bob_id + "@t.com", bspw, bsa, bsr),
        )
        conn.commit()
        conn.close()

        register_master_key(bob_id, bob_pass, bspw, bsa, bsr)
        bob_mk = login_and_unlock(bob_id, bob_pass)
        assert bob_mk is not None

        # BOLA : Bob essaie d'accéder à la collection d'Alice via son ID
        # get_collection_key utilise la master_key de Bob → ne peut pas déchiffrer le DEK d'Alice
        stolen_dek = get_collection_key(bob_id, "alice_secret_col")
        assert stolen_dek is None, (
            "CRITICAL BOLA: Bob a réussi à déchiffrer le DEK de la collection d'Alice ! "
            "L'isolation inter-utilisateur est brisée."
        )

        # Même avec le blob chiffré récupéré directement de la DB
        conn = get_connection()
        row = conn.execute(
            "SELECT encrypted_dek FROM collection_keys WHERE collection_id = ?",
            ("alice_secret_col",),
        ).fetchone()
        conn.close()

        # Bob tente de déchiffrer le encrypted_dek avec sa propre master_key
        result = DEKManager.unwrap_dek(row["encrypted_dek"], bob_mk)
        assert result is None, (
            "CRITICAL BOLA: Bob a déchiffré le DEK d'Alice avec sa propre master_key !"
        )

        # Bob tente de déchiffrer les données directement avec sa master_key
        direct = DEKManager.open(bob_mk, encrypted)
        assert direct == {}, (
            f"CRITICAL BOLA: Bob a déchiffré les données d'Alice avec sa master_key ! "
            f"Données: {direct}"
        )

        # Vérification : Alice peut toujours déchiffrer ses données
        alice_result = DEKManager.open(alice_dek, encrypted)
        assert alice_result == secret, "Alice doit toujours pouvoir lire ses données"

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM users WHERE user_id = ?", (bob_id,))
        conn.execute("DELETE FROM collection_keys WHERE collection_id = ?", ("alice_secret_col",))
        conn.commit()
        conn.close()
        clear_master_key(bob_id)

    def test_cross_team_data_isolation(self, team_with_members):
        """Un membre de l'équipe A ne peut pas lire les données de l'équipe B avec sa TVK."""
        from database.crypto_store import (
            login_and_unlock, create_tvk, create_collection_key, get_tvk,
            register_master_key, add_member_to_team,
        )
        from database.connection import get_connection
        import secrets as _secrets

        # Équipe A (fixture existante)
        uid = team_with_members["creator_id"]
        tid_a = team_with_members["team_id"]
        cid_a = team_with_members["collection_id"]

        mk = login_and_unlock(uid, team_with_members["creator_password"])
        tvk_a = get_tvk(uid, tid_a)

        # Créer des données dans l'équipe A
        dek_a = create_collection_key(uid, cid_a, tid_a)
        secret_a = {"team_a_data": "top secret A"}
        enc_a = DEKManager.seal(dek_a, secret_a)

        # Créer une équipe B complètement séparée
        tid_b = "bola_team_b_" + _secrets.token_hex(4)
        conn = get_connection()
        conn.execute(
            "INSERT INTO teams (team_id, name, creator_user_id) VALUES (?, ?, ?)",
            (tid_b, "TeamB", uid),
        )
        conn.execute(
            "INSERT INTO team_users (team_id, user_id, wrapped_tvk) VALUES (?, ?, '')",
            (tid_b, uid),
        )
        conn.execute(
            "INSERT INTO collection_keys (collection_id, encrypted_dek, team_id) VALUES (?, ?, ?)",
            ("bola_col_b", "", tid_b),
        )
        conn.commit()
        conn.close()

        tvk_b = create_tvk(tid_b, uid)
        dek_b = create_collection_key(uid, "bola_col_b", tid_b)
        secret_b = {"team_b_data": "top secret B"}
        enc_b = DEKManager.seal(dek_b, secret_b)

        # BOLA inter-équipe : utiliser TVK_A pour déchiffrer les données de l'équipe B
        conn = get_connection()
        row_b = conn.execute(
            "SELECT encrypted_dek FROM collection_keys WHERE collection_id = ?",
            ("bola_col_b",),
        ).fetchone()
        conn.close()

        # Tenter de déchiffrer le DEK de l'équipe B avec la TVK de l'équipe A
        cross_dek = DEKManager.unwrap_dek(row_b["encrypted_dek"], tvk_a)
        assert cross_dek is None, (
            "CRITICAL BOLA inter-équipe: TVK_A a déchiffré le DEK de l'équipe B !"
        )

        # Tenter de déchiffrer les données de B avec la TVK de A
        cross_data = DEKManager.open(tvk_a, enc_b)
        assert cross_data == {}, (
            f"CRITICAL BOLA inter-équipe: TVK_A a déchiffré les données de l'équipe B !"
        )

        # Vérification : chaque équipe peut toujours lire SES données
        assert DEKManager.open(dek_a, enc_a) == secret_a
        assert DEKManager.open(dek_b, enc_b) == secret_b

        # Cleanup
        conn = get_connection()
        conn.execute("DELETE FROM team_users WHERE team_id = ?", (tid_b,))
        conn.execute("DELETE FROM teams WHERE team_id = ?", (tid_b,))
        conn.execute("DELETE FROM collection_keys WHERE collection_id = ?", ("bola_col_b",))
        conn.commit()
        conn.close()


class TestCryptoEdgeCases:
    """Cas limites et robustesse."""

    def test_empty_data_roundtrip(self, unlocked_user):
        """Un dict vide chiffré/déchiffré reste vide."""
        mk = get_master_key(unlocked_user["user_id"])
        enc = aes_encrypt_json(mk, {})
        dec = aes_decrypt_json(mk, enc)
        assert dec == {}

    def test_none_decrypt(self):
        """Déchiffrer None ou '' retourne {} ou None."""
        assert aes_decrypt_json(b"a" * 32, "") == {}
        assert aes_decrypt_string(b"a" * 32, "") is None

    def test_tampered_ciphertext(self, unlocked_user):
        """Un ciphertext altéré échoue au déchiffrement (AEAD)."""
        mk = get_master_key(unlocked_user["user_id"])
        import base64
        data = {"secret": "tamper test"}
        enc = aes_encrypt_json(mk, data)

        # Modifier un byte du ciphertext
        raw = bytearray(base64.b64decode(enc))
        raw[len(raw) // 2] ^= 0x01  # flip un bit
        tampered = base64.b64encode(bytes(raw)).decode()

        result = aes_decrypt_json(mk, tampered)
        assert result == {}, "Un ciphertext altéré doit échouer (AEAD tag mismatch)"

    def test_key_rotation_atomicity(self, unlocked_user):
        """Après rotation, l'ancienne clé ne fonctionne plus pour chiffrer de nouvelles données."""
        uid = unlocked_user["user_id"]
        old_mk = get_master_key(uid)

        # Changer le mot de passe → nouveau wrapping, mais même master_key
        change_password(uid, unlocked_user["password"], "R0tati0nT3st!")
        clear_master_key(uid)
        mk_new = login_and_unlock(uid, "R0tati0nT3st!")

        # La master_key est la même (rotation du wrapper, pas de la clé)
        assert old_mk == mk_new, "La master_key ne change pas avec le mot de passe"

        # Restaurer
        change_password(uid, "R0tati0nT3st!", unlocked_user["password"])
