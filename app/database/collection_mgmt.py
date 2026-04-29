from database.database import connect
from database import json_helper
import uuid_utils
from datetime import datetime


def _generate_collection_id(prefix: str) -> str:
    return f"{prefix}-{str(uuid_utils.uuid4())[:8]}"


# ═══════════════════════════════════════════════
# FOLDERS
# ═══════════════════════════════════════════════

def create_folder(name: str, author_user_id: str, parent_id: str = None):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        folder_id = _generate_collection_id("f")
        cursor.execute(
            "INSERT INTO folders (folder_id, name, parent_id, author_user_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (folder_id, name, parent_id, author_user_id, datetime.now())
        )
        conn.commit()
        return folder_id
    except Exception as e:
        print("create_folder error:", e)
        return None
    finally:
        if conn:
            conn.close()


def get_folders_by_user(author_user_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM folders WHERE author_user_id=? ORDER BY created_at ASC",
            (author_user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print("get_folders_by_user error:", e)
        return []
    finally:
        if conn:
            conn.close()


def delete_folder(folder_id: str, author_user_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()

        # Collect all folder ids to delete (the folder + all nested children)
        ids_to_delete = [folder_id]
        child_ids = _get_all_child_folder_ids(cursor, folder_id)
        ids_to_delete.extend(child_ids)

        for fid in ids_to_delete:
            # Delete saved requests inside this folder
            cursor.execute("DELETE FROM saved_requests WHERE folder_id=? AND author_user_id=?", (fid, author_user_id))
            # Delete the folder itself
            cursor.execute("DELETE FROM folders WHERE folder_id=? AND author_user_id=?", (fid, author_user_id))

        conn.commit()
        return True
    except Exception as e:
        print("delete_folder error:", e)
        return False
    finally:
        if conn:
            conn.close()


def _get_all_child_folder_ids(cursor, parent_id: str):
    """Recursively collect all child folder IDs."""
    cursor.execute("SELECT folder_id FROM folders WHERE parent_id=?", (parent_id,))
    children = [row["folder_id"] for row in cursor.fetchall()]
    all_ids = []
    for child_id in children:
        all_ids.append(child_id)
        all_ids.extend(_get_all_child_folder_ids(cursor, child_id))
    return all_ids


# ═══════════════════════════════════════════════
# SAVED REQUESTS
# ═══════════════════════════════════════════════

def create_saved_request(name: str, author_user_id: str, folder_id: str = None,
                         method: str = "GET", url: str = "",
                         headers: dict = None, body: str = None,
                         is_done_by_ai: bool = False):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        saved_id = _generate_collection_id("r")
        headers_str, body_str, body_is_json = None, None, False

        if headers:
            headers_str = json_helper.from_json(headers)
        if body:
            body_str, body_is_json = json_helper.serialize_body(body)

        now = datetime.now()
        cursor.execute(
            """INSERT INTO saved_requests
               (saved_request_id, name, folder_id, method, url, headers, body, body_is_json, is_done_by_ai, author_user_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (saved_id, name, folder_id, method.upper(), url, headers_str, body_str, body_is_json, is_done_by_ai, author_user_id, now, now)
        )
        conn.commit()
        return saved_id
    except Exception as e:
        print("create_saved_request error:", e)
        return None
    finally:
        if conn:
            conn.close()


def get_saved_requests_by_user(author_user_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM saved_requests WHERE author_user_id=? ORDER BY created_at ASC",
            (author_user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print("get_saved_requests_by_user error:", e)
        return []
    finally:
        if conn:
            conn.close()


def update_saved_request(saved_request_id: str, author_user_id: str, **kwargs):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()

        allowed_fields = ["name", "folder_id", "method", "url", "headers", "body"]
        updates = {}
        for field in allowed_fields:
            if field in kwargs:
                if field == "headers" and kwargs[field] is not None:
                    updates["headers"] = json_helper.from_json(kwargs[field])
                elif field == "body" and kwargs[field] is not None:
                    body_str, body_is_json = json_helper.serialize_body(kwargs[field])
                    updates["body"] = body_str
                    updates["body_is_json"] = body_is_json
                elif field != "headers" and field != "body":
                    updates[field] = kwargs[field]

        if not updates:
            return False

        updates["updated_at"] = datetime.now()
        set_clause = ", ".join(f"{k}=?" for k in updates.keys())
        values = list(updates.values()) + [saved_request_id, author_user_id]

        cursor.execute(
            f"UPDATE saved_requests SET {set_clause} WHERE saved_request_id=? AND author_user_id=?",
            values
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("update_saved_request error:", e)
        return False
    finally:
        if conn:
            conn.close()


def delete_saved_request(saved_request_id: str, author_user_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM saved_requests WHERE saved_request_id=? AND author_user_id=?",
            (saved_request_id, author_user_id)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("delete_saved_request error:", e)
        return False
    finally:
        if conn:
            conn.close()


# ═══════════════════════════════════════════════
# TREE BUILDER  (for GET /api/collections)
# ═══════════════════════════════════════════════

def get_collection_tree(author_user_id: str):
    folders = get_folders_by_user(author_user_id)
    saved = get_saved_requests_by_user(author_user_id)

    folder_map = {}
    for f in folders:
        folder_map[f["folder_id"]] = {
            "id": f["folder_id"],
            "name": f["name"],
            "type": "folder",
            "expanded": False,
            "children": [],
        }

    root_items = []

    for f in folders:
        node = folder_map[f["folder_id"]]
        if f["parent_id"] and f["parent_id"] in folder_map:
            folder_map[f["parent_id"]]["children"].append(node)
        else:
            root_items.append(node)

    for r in saved:
        req_node = {
            "id": r["saved_request_id"],
            "name": r["name"],
            "type": "request",
            "method": r["method"],
            "url": r["url"],
            "isDoneByAI": bool(r["is_done_by_ai"]),
        }
        if r["headers"]:
            req_node["headers"] = json_helper.to_json(r["headers"])
        if r["body"]:
            req_node["body"] = json_helper.deserialize_body(r["body"], r["body_is_json"])

        if r["folder_id"] and r["folder_id"] in folder_map:
            folder_map[r["folder_id"]]["children"].append(req_node)
        else:
            root_items.append(req_node)

    return root_items
