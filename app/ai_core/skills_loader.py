# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Skills loader — loads SKILLS.md for each agent type.

- Scanners (red/grey/purple): static SKILLS.md from filesystem, not user-modifiable
- Ely copilot: built-in ely.md + custom skills from DB
"""

import os

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "skills")

BUILT_IN = {
    "redteam": "redteam.md",
    "greyteam": "greyteam.md",
    "purpleteam": "purpleteam.md",
    "ely": "ely.md",
}


def load_agent_skill(agent_type: str) -> str:
    """Load skill content for an agent type. Returns empty string if not found."""
    filename = BUILT_IN.get(agent_type, "")
    if not filename:
        return ""

    path = os.path.join(SKILLS_DIR, filename)
    if not os.path.isfile(path):
        return ""

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return ""

    # Ely also gets custom skills from DB
    if agent_type == "ely":
        customs = _load_custom_skills()
        if customs:
            content += "\n\n## Custom Skills\n"
            for cs in customs:
                content += f"\n### {cs['name']}\n{cs['content']}\n"

    return content


def _load_custom_skills() -> list[dict]:
    """Load custom Ely skills from DB."""
    try:
        from database.skills_api import load_custom_skills
        return load_custom_skills()
    except Exception:
        return []
