# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from database.database import connect
from database import json_helper
import uuid_utils
from datetime import datetime
from core.logging import get_logger

_log = get_logger(__name__)


def _generate_collection_id(prefix: str) -> str:
    return f"{prefix}-{str(uuid_utils.uuid4())[:8]}"


# ═══════════════════════════════════════════════
# FOLDERS
# ═══════════════════════════════════════════════

def create_folder(name: str, author_user_id: str, parent_id: str = None, team_id: str = ""):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        folder_id = _generate_collection_id("f")
        cursor.execute(
            "INSERT INTO folders (folder_id, name, parent_id, author_user_id, team_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (folder_id, name, parent_id, author_user_id, team_id, datetime.now())
        )
        conn.commit()
        return folder_id
    except Exception as e:
        _log.exception("create_folder error")
        return None
    finally:
        if conn:
            conn.close()


def find_folder_by_path(path: str, author_user_id: str, team_ids: list = None) -> str | None:
    """Resolve a folder path like 'Parent/Child' or simple name to a folder_id.

    Returns the folder_id (f-xxxxxxxx) of the deepest matching folder, or None.
    Matches case-insensitively. Searches personal folders + team folders if team_ids provided.
    """
    if not path or not path.strip():
        return None
    parts = [p.strip() for p in path.strip().split("/") if p.strip()]
    if not parts:
        return None
    folders = get_folders_by_user(author_user_id)
    # Also load team-scoped folders
    if team_ids:
        seen = {f["folder_id"] for f in folders}
        for tid in team_ids:
            try:
                conn = connect()
                tfolders = conn.execute("SELECT * FROM folders WHERE team_id=?", (tid,)).fetchall()
                conn.close()
                for r in tfolders:
                    d = dict(r)
                    if d["folder_id"] not in seen:
                        seen.add(d["folder_id"])
                        folders.append(d)
            except Exception:
                pass
    # Build lookup: parent_id -> list of children
    by_parent = {}
    for f in folders:
        pid = f["parent_id"] or "__root__"
        by_parent.setdefault(pid, []).append(f)
    current_parent = "__root__"
    for i, part in enumerate(parts):
        candidates = by_parent.get(current_parent, [])
        match = None
        for f in candidates:
            if f["name"].strip().lower() == part.lower():
                match = f
                break
        if not match:
            return None
        if i == len(parts) - 1:
            return match["folder_id"]
        current_parent = match["folder_id"]
    return None


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
        _log.exception("get_folders_by_user error")
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
        _log.exception("delete_folder error")
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

def get_request_by_id(saved_request_id: str, requester_user_id: str = ""):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM saved_requests WHERE saved_request_id=?",
            (saved_request_id,)
        )
        row = cursor.fetchone()
        # Verify ownership if requester is specified
        if row and requester_user_id:
            d = dict(row)
            if d.get("author_user_id") and d["author_user_id"] != requester_user_id:
                return None
        if row:
            d = dict(row)
            if d.get("payload_encrypted"):
                opened = _open_saved_payload(d["payload_encrypted"], d.get("author_user_id", ""), d.get("team_id", ""))
                if opened:
                    d["method"] = opened.get("method", d["method"])
                    d["url"] = opened.get("url", "")
                    d["headers"] = opened.get("headers")
                    d["body"] = opened.get("body")
                else:
                    d["url"] = ""
                    d["headers"] = None
                    d["body"] = None
            return d
        return None
    except Exception as e:
        _log.exception("get_request_by_id error")
        return None
    finally:
        if conn:
            conn.close()

def _seal_saved_payload(method: str, url: str, headers_str, body_str, user_id: str, team_id: str) -> str:
    """Encrypt sensitive columns into a payload_encrypted blob. Returns '' if crypto unavailable."""
    try:
        from database.crypto_store import crypto_seal
        payload = {"method": method, "url": url}
        if headers_str: payload["headers"] = headers_str
        if body_str: payload["body"] = body_str
        return crypto_seal(payload, user_id, team_id=team_id)
    except Exception:
        return ""


def _open_saved_payload(encrypted: str, user_id: str, team_id: str) -> dict:
    """Decrypt payload_encrypted back into column values. Returns {} if crypto unavailable."""
    from database.crypto_store import crypto_open
    if not encrypted:
        return {}
    try:
        return crypto_open(encrypted, user_id, team_id)
    except Exception:
        return {}


def create_saved_request(name: str, author_user_id: str, folder_id: str = None,
                         method: str = "GET", url: str = "",
                         headers: dict = None, body: str = None,
                         is_done_by_ai: bool = False, team_id: str = ""):
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

        # Encrypt sensitive columns
        tid = team_id or ""
        payload_enc = _seal_saved_payload(method.upper(), url, headers_str, body_str, author_user_id, tid)

        now = datetime.now()
        cursor.execute(
            """INSERT INTO saved_requests
               (saved_request_id, name, folder_id, method, url, headers, body, body_is_json,
                is_done_by_ai, author_user_id, team_id, payload_encrypted, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (saved_id, name, folder_id, method.upper(), url, headers_str, body_str, body_is_json,
             is_done_by_ai, author_user_id, tid, payload_enc, now, now)
        )
        conn.commit()
        return saved_id
    except Exception as e:
        _log.exception("create_saved_request error")
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
        rows = []
        for row in cursor.fetchall():
            d = dict(row)
            # Decrypt payload if present
            if d.get("payload_encrypted"):
                tid = d.get("team_id", "")
                opened = _open_saved_payload(d["payload_encrypted"], author_user_id, tid)
                # If decryption succeeds, use decrypted values; if it fails, clear sensitive columns
                d["method"] = opened.get("method", d["method"]) if opened else d["method"]
                d["url"] = opened.get("url", "") if opened else ""
                d["headers"] = opened.get("headers") if opened else None
                d["body"] = opened.get("body") if opened else None
            rows.append(d)
        return rows
    except Exception as e:
        _log.exception("get_saved_requests_by_user error")
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

        # Re-encrypt payload if any sensitive field changed (non-blocking — falls back to cleartext)
        sensitive = {"method", "url", "headers", "body"}
        if sensitive & set(updates.keys()):
            row = cursor.execute(
                "SELECT method, url, headers, body, team_id FROM saved_requests WHERE saved_request_id=? AND author_user_id=?",
                (saved_request_id, author_user_id)
            ).fetchone()
            if row:
                tid = row["team_id"] or ""
                m = updates.get("method", row["method"])
                u = updates.get("url", row["url"])
                h = updates.get("headers", row["headers"])
                b = updates.get("body", row["body"])
                updates["payload_encrypted"] = _seal_saved_payload(m, u, h, b, author_user_id, tid)

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
        _log.exception("update_saved_request error")
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
        _log.exception("delete_saved_request error")
        return False
    finally:
        if conn:
            conn.close()


# ═══════════════════════════════════════════════
# FOLDER CONTENTS (detailed view of a single folder)
# ═══════════════════════════════════════════════

def get_folder_contents(folder_id: str, author_user_id: str) -> dict | None:
    """Return the full contents of a folder: its info, child folders, and requests with details."""
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        # Get the folder itself
        frow = cursor.execute(
            "SELECT * FROM folders WHERE folder_id=? AND author_user_id=?",
            (folder_id, author_user_id)
        ).fetchone()
        if not frow:
            conn.close()
            return None
        folder = dict(frow)
        # Get child folders
        child_folders = cursor.execute(
            "SELECT folder_id, name FROM folders WHERE parent_id=? AND author_user_id=? ORDER BY name",
            (folder_id, author_user_id)
        ).fetchall()
        # Get requests in this folder (exclude payload_encrypted, use cleartext columns)
        requests = cursor.execute(
            "SELECT saved_request_id, name, method, url, headers, body, body_is_json, is_done_by_ai FROM saved_requests WHERE folder_id=? AND author_user_id=? ORDER BY name",
            (folder_id, author_user_id)
        ).fetchall()
        conn.close()

        result = {
            "id": folder["folder_id"],
            "name": folder["name"],
            "type": "folder",
            "parent_id": folder.get("parent_id"),
            "created_at": str(folder.get("created_at", "")),
            "folders": [{"id": f["folder_id"], "name": f["name"]} for f in child_folders],
            "requests": [],
        }
        for r in requests:
            rd = {
                "id": r["saved_request_id"],
                "name": r["name"],
                "method": r["method"],
                "url": r["url"] or "",
                "isDoneByAI": bool(r["is_done_by_ai"]),
            }
            if r["headers"]:
                rd["headers"] = json_helper.to_json(r["headers"])
            if r["body"]:
                rd["body"] = json_helper.deserialize_body(r["body"], r["body_is_json"])
            result["requests"].append(rd)
        return result
    except Exception as e:
        _log.exception("get_folder_contents error")
        return None
    finally:
        if conn:
            conn.close()


# ═══════════════════════════════════════════════
# TREE BUILDER  (for GET /api/collections)
# ═══════════════════════════════════════════════

def get_collection_tree(author_user_id: str, team_ids: list = None, light: bool = False):
    folders = get_folders_by_user(author_user_id)
    saved = get_saved_requests_by_user(author_user_id)
    # If team_ids is None: personal only. If empty list: no teams. If list: include those teams.
    if team_ids is not None and team_ids:
        seen_folder_ids = {f["folder_id"] for f in folders}
        seen_saved_ids = {r["saved_request_id"] for r in saved}
        for tid in team_ids:
            try:
                conn = connect()
                tfolders = conn.execute("SELECT * FROM folders WHERE team_id=?", (tid,)).fetchall()
                # Get requests inside team folders AND requests with team_id set directly
                folder_ids = [f["folder_id"] for f in tfolders]
                tsaved = conn.execute("SELECT * FROM saved_requests WHERE team_id=?", (tid,)).fetchall()
                if folder_ids:
                    placeholders = ",".join("?" * len(folder_ids))
                    tsaved += conn.execute(f"SELECT * FROM saved_requests WHERE folder_id IN ({placeholders})", folder_ids).fetchall()
                conn.close()
                for r in tfolders:
                    if r["folder_id"] not in seen_folder_ids:
                        seen_folder_ids.add(r["folder_id"])
                        folders.append(dict(r))
                for row in tsaved:
                    if row["saved_request_id"] not in seen_saved_ids:
                        d = dict(row)
                        # Decrypt team-scoped payload — if fails, blank the sensitive fields
                        if d.get("payload_encrypted"):
                            opened = _open_saved_payload(d["payload_encrypted"], author_user_id, tid)
                            if opened:
                                d["method"] = opened.get("method", d["method"])
                                d["url"] = opened.get("url", "")
                                d["headers"] = opened.get("headers")
                                d["body"] = opened.get("body")
                            else:
                                d["url"] = ""
                                d["headers"] = None
                                d["body"] = None
                        seen_saved_ids.add(d["saved_request_id"])
                        saved.append(d)
            except Exception as e:
                _log.warning(f"Team tree load error for {tid}: {e}")

    folder_map = {}
    for f in folders:
        node = {
            "id": f["folder_id"],
            "name": f["name"],
            "type": "folder",
            "children": [],
        }
        if not light:
            node["expanded"] = False
        folder_map[f["folder_id"]] = node

    root_items = []

    for f in folders:
        node = folder_map[f["folder_id"]]
        if f["parent_id"] and f["parent_id"] in folder_map:
            folder_map[f["parent_id"]]["children"].append(node)
        else:
            root_items.append(node)

    # In light mode, skip request nodes — only return folder tree with request counts
    if not light:
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

    # Add request counts to folders (both modes)
    request_counts = {}
    for r in saved:
        if r["folder_id"]:
            request_counts[r["folder_id"]] = request_counts.get(r["folder_id"], 0) + 1
    for fid, count in request_counts.items():
        if fid in folder_map:
            folder_map[fid]["request_count"] = count

    return root_items
