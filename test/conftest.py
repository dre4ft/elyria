# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Test fixtures — setup/teardown for crypto architecture tests.
"""

import os
import secrets
import sys

import pytest

# Ensure we can import from app/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))


@pytest.fixture(scope="function")
def new_user():
    """Create a fresh user with crypto v2 material. Cleans up after test."""
    from database.database import init_db
    from database.connection import get_connection

    init_db()

    user_id = "test_" + secrets.token_hex(8)
    password = "MySecur3P@ssw0rd!"
    email = user_id + "@elyria.test"

    salt_pw = secrets.token_bytes(16).hex()
    salt_auth = secrets.token_bytes(16).hex()
    salt_rec = secrets.token_bytes(16).hex()

    conn = get_connection()
    conn.execute(
        "INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) "
        "VALUES (?, '', '', ?, ?, ?, ?, ?)",
        (user_id, user_id, email, salt_pw, salt_auth, salt_rec),
    )
    conn.commit()
    conn.close()

    yield {
        "user_id": user_id,
        "password": password,
        "email": email,
        "salt_pw": salt_pw,
        "salt_auth": salt_auth,
        "salt_rec": salt_rec,
    }

    # Cleanup
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM collection_keys WHERE collection_id LIKE ?", (user_id + "%",))
    conn.commit()
    conn.close()

    from database.crypto_store import clear_master_key
    clear_master_key(user_id)


@pytest.fixture(scope="function")
def unlocked_user(new_user):
    """Create user + register crypto + login. Returns user dict with master_key in memory."""
    from database.crypto_store import register_master_key, login_and_unlock

    register_master_key(
        new_user["user_id"],
        new_user["password"],
        new_user["salt_pw"],
        new_user["salt_auth"],
        new_user["salt_rec"],
    )

    mk = login_and_unlock(new_user["user_id"], new_user["password"])
    assert mk is not None, "Login must succeed after registration"

    new_user["master_key"] = mk
    return new_user


@pytest.fixture(scope="function")
def team_with_members(unlocked_user):
    """Create a team with 2 members (creator + bob). Returns team info."""
    from database.crypto_store import (
        create_tvk, add_member_to_team,
        register_master_key, login_and_unlock,
    )
    from database.connection import get_connection

    uid = unlocked_user["user_id"]

    # Create team
    tid = "team_" + secrets.token_hex(4)
    conn = get_connection()
    conn.execute(
        "INSERT INTO teams (team_id, name, creator_user_id) VALUES (?, ?, ?)",
        (tid, "TestTeam", uid),
    )
    conn.execute(
        "INSERT INTO team_users (team_id, user_id, wrapped_tvk) VALUES (?, ?, '')",
        (tid, uid),
    )
    conn.commit()
    conn.close()

    create_tvk(tid, uid)

    # Create shared collection
    cid = "col_" + secrets.token_hex(4)
    conn = get_connection()
    conn.execute(
        "INSERT INTO collection_keys (collection_id, encrypted_dek, team_id) VALUES (?, ?, ?)",
        (cid, "", tid),
    )
    conn.commit()
    conn.close()

    from database.crypto_store import create_collection_key
    create_collection_key(uid, cid, tid)

    # Create Bob
    bid = "bob_" + secrets.token_hex(4)
    bpass = "BobSecur3P@ss!"
    bspw = secrets.token_bytes(16).hex()
    bsa = secrets.token_bytes(16).hex()
    bsr = secrets.token_bytes(16).hex()

    conn = get_connection()
    conn.execute(
        "INSERT INTO users (user_id, hashed_digest, salt, username, email, salt_pw, salt_auth, salt_rec) "
        "VALUES (?, '', '', ?, ?, ?, ?, ?)",
        (bid, bid, bid + "@elyria.test", bspw, bsa, bsr),
    )
    conn.execute(
        "INSERT INTO team_users (team_id, user_id, wrapped_tvk) VALUES (?, ?, '')",
        (tid, bid),
    )
    conn.commit()
    conn.close()

    register_master_key(bid, bpass, bspw, bsa, bsr)
    bob_mk = login_and_unlock(bid, bpass)
    assert bob_mk is not None

    add_member_to_team(tid, bid, uid)

    yield {
        "team_id": tid,
        "collection_id": cid,
        "creator_id": uid,
        "creator_password": unlocked_user["password"],
        "bob_id": bid,
        "bob_password": bpass,
    }

    # Cleanup
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE user_id = ?", (bid,))
    conn.execute("DELETE FROM team_users WHERE team_id = ?", (tid,))
    conn.execute("DELETE FROM teams WHERE team_id = ?", (tid,))
    conn.execute("DELETE FROM collection_keys WHERE collection_id = ?", (cid,))
    conn.commit()
    conn.close()

    from database.crypto_store import clear_master_key
    clear_master_key(uid)
    clear_master_key(bid)
