from .database import connect
from database import json_helper
import sqlite3
from datetime import  datetime
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
            response_body_is_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_uuid,
            datetime.now(),
            author,
            is_done_by_ai,
            response["url"],
            request["method"],
            response["status_code"],
            json_helper.from_json(request.get("headers")),
            request_body,
            req_body_is_json,
            json_helper.from_json(response.get("headers")),
            response_body,
            res_body_is_json
        ))

        conn.commit()
        return cursor.lastrowid

    except sqlite3.IntegrityError as e:
        print("Integrity error:", e)
        return None 

    except Exception as e:
        print("Unexpected error:", e)
        return None 

    finally:
        if conn:
            conn.close()



def get_requests_by_id(request_uuid:str):
    conn = None 
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM requests WHERE request_id=?",(request_uuid,))

        row = cursor.fetchone()
        if row :
            row.pop("id")
        return dict(row) if row else None

    except Exception as e:
        print("Unexpected error:", e)
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

        return [dict(row) for row in cursor.fetchall()]

    except Exception as e:
        print("Unexpected error:", e)
        return None 

    finally:
        if conn:
            conn.close()