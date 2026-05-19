# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from database.database import connect
from database import json_helper
import uuid_utils
from datetime import datetime




def generate_conversation_id() -> str:
    return f"conv-{str(uuid_utils.uuid4())[:8]}"

def get_conversation_messages(conversation_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM ai_messages WHERE conversation_id=? ORDER BY timestamp ASC",
            (conversation_id,)
        )
        rows = cursor.fetchall()
        return [json_helper.to_json(_decrypt_message_row(dict(r), r["user_id"]).get("message", "")) for r in rows]
    except Exception as e:
        print("get_conversation_messages error:", e)
        return []
    finally:
        if conn:
            conn.close()

def add_message(message :dict, user_id: str, conversation_id: str=None):
    if not conversation_id:
        conversation_id = generate_conversation_id()
    from database.crypto_store import seal_sensitive
    payload = seal_sensitive(user_id, {"message": json_helper.from_json(message)}) if user_id else ""
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO ai_messages (conversation_id, user_id, message, timestamp, payload_encrypted) VALUES (?, ?, ?, ?, ?)",
            (conversation_id, user_id, "", datetime.now(), payload)
        )
        conn.commit()
        return conversation_id
    except Exception as e:
        print("add_message error:", e)
        return None
    finally:
        if conn:
            conn.close()


def _decrypt_message_row(row_dict, user_id):
    if not row_dict or not row_dict.get("payload_encrypted"):
        return row_dict
    from database.crypto_store import open_sensitive
    data = open_sensitive(user_id, row_dict["payload_encrypted"])
    if data and "message" in data:
        row_dict["message"] = data["message"]
    return row_dict