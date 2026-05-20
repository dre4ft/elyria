# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from .database import connect
from database import json_helper
from database.connection import is_postgres
from datetime import datetime
"""
id INTEGER PRIMARY KEY AUTOINCREMENT,
request_id TEXT UNIQUE NOT NULL,
date DATETIME NOT NULL, 
author_user_id TEXT NOT NULL,
is_done_by_ai BOOLEAN NOT NULL, 
request_url TEXT NOT NULL,
request_method TEXT NOT NULL,
request_status_code INTEGER NOT NULL,
request_headers TEXT,  
request_body TEXT,
request_body_is_json BOOLEAN,     
response_headers TEXT,
response_body TEXT,
response_body_is_json BOOLEAN,
"""



def add_request(request_uuid:str, author:str,  request:dict,response:dict,is_done_by_ai:bool = False):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        request_body, req_body_is_json = json_helper.serialize_body(request.get("body"))
        response_body, res_body_is_json = json_helper.serialize_body(response.get("body"))
        # Encrypt sensitive fields
        from database.crypto_store import seal_sensitive
        payload = seal_sensitive(author, {
            "request_headers": json_helper.from_json(request.get("headers")),
            "request_body": request_body,
            "response_headers": json_helper.from_json(response.get("headers")),
            "response_body": response_body,
        }) if author else ""
        cursor.execute("""
        INSERT INTO requests (
            request_id,
            date,
            author_user_id,
            is_done_by_ai,
            request_url,
            request_method,
            request_status_code,
            request_headers,
            request_body,
            request_body_is_json,
            response_headers,
            response_body,
            response_body_is_json,
            payload_encrypted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_uuid,
            datetime.now(),
            author,
            is_done_by_ai,
            response["url"],
            request["method"],
            response["status_code"],
            "",  # clear plaintext headers
            "",  # clear plaintext body
            req_body_is_json,
            "",  # clear plaintext response headers
            "",  # clear plaintext response body
            res_body_is_json,
            payload,
        ))
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        from core.logging import get_logger
        logger = get_logger(__name__)
        if type(e).__name__ in ("IntegrityError", "UniqueViolation"):
            logger.warning(f"Integrity error: {e}")
        else:
            logger.exception(f"Unexpected error in add_request")
        return None
    finally:
        if conn:
            conn.close()


def _decrypt_request_row(row_dict, author_user_id):
    """If payload_encrypted is present, restore plaintext fields from it."""
    if not row_dict or not row_dict.get("payload_encrypted"):
        return row_dict
    from database.crypto_store import open_sensitive
    data = open_sensitive(author_user_id, row_dict["payload_encrypted"])
    if data:
        row_dict["request_headers"] = data.get("request_headers", "")
        row_dict["request_body"] = data.get("request_body", "")
        row_dict["response_headers"] = data.get("response_headers", "")
        row_dict["response_body"] = data.get("response_body", "")
    return row_dict



def get_requests_by_id(request_uuid:str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM requests WHERE request_id=?",(request_uuid,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            d.pop("id", None)
            return _decrypt_request_row(d, d.get("author_user_id", ""))
        return None
    except Exception as e:
        from core.logging import get_logger
        get_logger(__name__).exception("Unexpected error in get_requests_by_id")
        return None
    finally:
        if conn:
            conn.close()


def get_requests_by_userid(author_user_id:str, limit : int = 10, offset :int =0):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM requests WHERE author_user_id=? LIMIT ? OFFSET ?",(author_user_id,limit,offset))
        return [_decrypt_request_row(dict(row), author_user_id) for row in cursor.fetchall()]
    except Exception as e:
        from core.logging import get_logger
        get_logger(__name__).exception("Unexpected error in get_requests_by_userid")
        return None
    finally:
        if conn:
            conn.close()

def get_last_n_requests_by_user(author_user_id:str, n:int = 5):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM requests WHERE author_user_id=? ORDER BY date DESC LIMIT ?",(author_user_id,n))
        return [_decrypt_request_row(dict(row), author_user_id) for row in cursor.fetchall()]
    except Exception as e:
        from core.logging import get_logger
        get_logger(__name__).exception("Unexpected error in get_last_n_requests_by_user")
        return None
    finally:
        if conn:
            conn.close()