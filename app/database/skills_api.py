# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Ely copilot skills API — CRUD for custom agent personalities."""

import os
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from database.connection import get_connection

app = APIRouter(prefix="/api/skills", tags=["skills"])

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "skills")

# Static scanner skills (read-only, from files)
BUILT_IN = {
    "redteam":    {"name": "Red Team Pentest", "file": "redteam.md",    "description": "Offensive API security testing"},
    "greyteam":   {"name": "Grey Team OSINT",  "file": "greyteam.md",   "description": "Passive reconnaissance"},
    "purpleteam": {"name": "Purple Team IAST", "file": "purpleteam.md", "description": "White-box code audit"},
    "ely":        {"name": "Ely Copilot",      "file": "ely.md",        "description": "General security assistant"},
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _conn():
    return get_connection()


def init():
    c = _conn()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS ely_skills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            content TEXT NOT NULL DEFAULT '',
            category TEXT DEFAULT 'custom',
            user_id TEXT DEFAULT '',
            team_ids TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    try:
        c.execute("ALTER TABLE ely_skills ADD COLUMN category TEXT DEFAULT 'custom'")
    except Exception:
        pass
    c.commit(); c.close()


init()


def load_skill(skill_id: str) -> dict | None:
    """Load a skill — checks built-in first, then custom."""
    if skill_id in BUILT_IN:
        info = BUILT_IN[skill_id]
        path = os.path.join(SKILLS_DIR, info["file"])
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return {
                    "skill_id": skill_id,
                    "name": info["name"],
                    "description": info["description"],
                    "content": f.read(),
                    "builtin": True,
                }
    c = _conn()
    row = c.execute("SELECT * FROM ely_skills WHERE skill_id=?", (skill_id,)).fetchone()
    c.close()
    if row:
        return {
            "skill_id": row["skill_id"],
            "name": row["name"],
            "description": row["description"] or "",
            "content": row["content"],
            "category": row["category"] if "category" in row.keys() else "custom",
            "user_id": row["user_id"] or "",
            "builtin": False,
        }
    return None


def list_skills() -> list[dict]:
    """List all available skills (built-in + custom)."""
    skills = []
    for sid, info in BUILT_IN.items():
        skills.append({
            "skill_id": sid, "name": info["name"],
            "description": info["description"], "builtin": True,
        })
    c = _conn()
    rows = c.execute("SELECT skill_id, name, description, category, user_id FROM ely_skills ORDER BY name").fetchall()
    c.close()
    for r in rows:
        skills.append({
            "skill_id": r["skill_id"], "name": r["name"],
            "description": r["description"] or "",
            "category": r["category"] if "category" in r.keys() else "custom",
            "user_id": r["user_id"] or "", "builtin": False,
        })
    return skills


def load_custom_skills() -> list[dict]:
    """Load all custom skills for Ely copilot."""
    try:
        c = _conn()
        rows = c.execute("SELECT * FROM ely_skills ORDER BY name").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def save_skill(skill_id: str, name: str, description: str, content: str,
               category: str = "custom", user_id: str = "", team_ids: str = "") -> dict:
    """Create or update a skill in ely_skills. Shared by API and agent tools."""
    sid = skill_id.strip().lower().replace(" ", "-")
    if not sid or not content.strip():
        return {"error": "skill_id and content required"}
    if sid in BUILT_IN:
        return {"error": "Cannot override built-in skill"}
    c = _conn()
    existing = c.execute("SELECT 1 FROM ely_skills WHERE skill_id=?", (sid,)).fetchone()
    if existing:
        c.execute(
            "UPDATE ely_skills SET name=?, description=?, content=?, category=?, updated_at=? WHERE skill_id=?",
            (name or sid, description, content, category, _now(), sid),
        )
        c.commit(); c.close()
        return {"skill_id": sid, "status": "updated"}
    c.execute(
        "INSERT INTO ely_skills (skill_id,name,description,content,category,user_id,team_ids,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (sid, name or sid, description, content, category, user_id, team_ids, _now(), _now()),
    )
    c.commit(); c.close()
    return {"skill_id": sid, "status": "created"}


# ── API ──

class SkillRequest(BaseModel):
    skill_id: str
    name: str = ""
    description: str = ""
    content: str
    category: str = "custom"
    team_ids: str = ""


@app.get("")
def api_list_skills():
    return list_skills()


@app.get("/{skill_id}")
def api_get_skill(skill_id: str):
    s = load_skill(skill_id)
    if not s: raise HTTPException(404, "Skill not found")
    return s


@app.post("")
async def api_create_skill(body: SkillRequest, request: Request):
    from database.auth_utils import get_auth_user
    uid = get_auth_user(request)
    result = save_skill(body.skill_id, body.name, body.description, body.content,
                        body.category, uid, body.team_ids)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@app.delete("/{skill_id}")
def api_delete_skill(skill_id: str, request: Request):
    if skill_id in BUILT_IN:
        raise HTTPException(400, "Cannot delete built-in skill")
    from database.auth_utils import get_auth_user
    c = _conn()
    c.execute("DELETE FROM ely_skills WHERE skill_id=? AND user_id=?", (skill_id, get_auth_user(request)))
    c.commit(); c.close()
    return {"status": "deleted"}
