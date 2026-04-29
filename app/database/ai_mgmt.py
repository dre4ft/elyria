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
            "SELECT message FROM ai_messages WHERE conversation_id=? ORDER BY timestamp ASC",
            (conversation_id,)
        )
        return [json_helper.to_json(row[0]) for row in cursor.fetchall()]
    except Exception as e:
        print("get_conversation_messages error:", e)
        return []
    finally:
        if conn:
            conn.close()

def add_message(message :dict, user_id: str, conversation_id: str=None):
    if not conversation_id:
        conversation_id = generate_conversation_id()
    message_str = json_helper.from_json(message)
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO ai_messages (conversation_id, user_id, message, timestamp) VALUES (?, ?, ?, ?)",
            (conversation_id, user_id, message_str, datetime.now())
        )
        conn.commit()
        return conversation_id
    except Exception as e:
        print("add_message error:", e)
        return None
    finally:
        if conn:
            conn.close()