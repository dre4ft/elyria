from database.database import connect
from database import json_helper
import uuid_utils
from datetime import datetime


def _generate_id(prefix: str) -> str:
    return f"{prefix}-{str(uuid_utils.uuid4())[:8]}"


# ═══════════════════════════════════════════════
# WORKFLOWS
# ═══════════════════════════════════════════════

def create_workflow(name: str, author_user_id: str, description: str = None):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        wf_id = _generate_id("wf")
        now = datetime.now()
        cursor.execute(
            """INSERT INTO workflows (workflow_id, name, description, author_user_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (wf_id, name, description, author_user_id, now, now)
        )
        conn.commit()
        return wf_id
    except Exception as e:
        print("create_workflow error:", e)
        return None
    finally:
        if conn:
            conn.close()


def get_workflows_by_user(author_user_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM workflows WHERE author_user_id=? ORDER BY created_at ASC",
            (author_user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print("get_workflows_by_user error:", e)
        return []
    finally:
        if conn:
            conn.close()


def update_workflow(workflow_id: str, author_user_id: str, **kwargs):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        allowed = ["name", "description"]
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return False
        updates["updated_at"] = datetime.now()
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [workflow_id, author_user_id]
        cursor.execute(
            f"UPDATE workflows SET {set_clause} WHERE workflow_id=? AND author_user_id=?",
            values
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("update_workflow error:", e)
        return False
    finally:
        if conn:
            conn.close()


def delete_workflow(workflow_id: str, author_user_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM workflow_steps WHERE workflow_id=?", (workflow_id,))
        cursor.execute(
            "DELETE FROM workflows WHERE workflow_id=? AND author_user_id=?",
            (workflow_id, author_user_id)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("delete_workflow error:", e)
        return False
    finally:
        if conn:
            conn.close()


# ═══════════════════════════════════════════════
# STEPS
# ═══════════════════════════════════════════════

def create_step(workflow_id: str, name: str, step_order: int = None,
                saved_request_id: str = None,
                method: str = None, url: str = None,
                headers: dict = None, body: str = None,
                captures: dict = None, condition: str = None):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()

        if step_order is None:
            cursor.execute(
                "SELECT COALESCE(MAX(step_order), -1) + 1 FROM workflow_steps WHERE workflow_id=?",
                (workflow_id,)
            )
            step_order = cursor.fetchone()[0]

        step_id = _generate_id("ws")
        headers_str = json_helper.from_json(headers) if headers else None

        cursor.execute(
            """INSERT INTO workflow_steps
               (step_id, workflow_id, saved_request_id, name, method, url,
                headers, body, step_order, captures, condition)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (step_id, workflow_id, saved_request_id, name, method, url,
             headers_str, body, step_order,
             json_helper.from_json(captures) if captures else None,
             condition)
        )
        conn.commit()
        return step_id
    except Exception as e:
        print("create_step error:", e)
        return None
    finally:
        if conn:
            conn.close()


def get_steps_by_workflow(workflow_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM workflow_steps WHERE workflow_id=? ORDER BY step_order ASC",
            (workflow_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print("get_steps_by_workflow error:", e)
        return []
    finally:
        if conn:
            conn.close()


def update_step(step_id: str, **kwargs):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        allowed = ["name", "saved_request_id", "method", "url", "headers",
                   "body", "step_order", "captures", "condition"]
        updates = {}
        for k in allowed:
            if k in kwargs and kwargs[k] is not None:
                if k == "headers" or k == "captures":
                    updates[k] = json_helper.from_json(kwargs[k])
                else:
                    updates[k] = kwargs[k]
        if not updates:
            return False
        set_clause = ", ".join(f"{k}=?" for k in updates)
        cursor.execute(
            f"UPDATE workflow_steps SET {set_clause} WHERE step_id=?",
            list(updates.values()) + [step_id]
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("update_step error:", e)
        return False
    finally:
        if conn:
            conn.close()


def delete_step(step_id: str):
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM workflow_steps WHERE step_id=?", (step_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("delete_step error:", e)
        return False
    finally:
        if conn:
            conn.close()


def reorder_steps(workflow_id: str, step_ids: list[str]):
    """Persist a new order from a list of step IDs (first = order 0)."""
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        for i, sid in enumerate(step_ids):
            cursor.execute(
                "UPDATE workflow_steps SET step_order=? WHERE step_id=? AND workflow_id=?",
                (i, sid, workflow_id)
            )
        conn.commit()
        return True
    except Exception as e:
        print("reorder_steps error:", e)
        return False
    finally:
        if conn:
            conn.close()
