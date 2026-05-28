# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Ely — User memory system.

Stores a compact user profile per user in SQLite (max 5000 chars).
Every N rounds, conversation history is compacted into the profile
via the LLM, keeping only the freshest and most relevant info.

The memory is injected at HIGH priority in the system prompt.
"""

import json
from core.logging import get_logger

_log = get_logger("ely.memory")

MAX_CHARS = 5000
COMPACT_EVERY = 6


# ═══════════════════════════════════════════════════════════════
# Database
# ═══════════════════════════════════════════════════════════════

def _ensure_table():
    from database.connection import get_connection
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ely_memory (
            user_id TEXT PRIMARY KEY,
            profile TEXT DEFAULT '',
            round_count INTEGER DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


def get_memory(user_id: str) -> str:
    _ensure_table()
    from database.connection import get_connection
    conn = get_connection()
    row = conn.execute(
        "SELECT profile FROM ely_memory WHERE user_id=?", (user_id,)
    ).fetchone()
    conn.close()
    return row["profile"] if row and row.get("profile") else ""


def save_memory(user_id: str, profile: str):
    profile = profile.strip()[:MAX_CHARS]
    _ensure_table()
    from database.connection import get_connection
    conn = get_connection()
    existing = conn.execute(
        "SELECT round_count FROM ely_memory WHERE user_id=?", (user_id,)
    ).fetchone()
    rc = existing["round_count"] if existing else 0
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT OR REPLACE INTO ely_memory (user_id, profile, round_count, updated_at)
           VALUES (?, ?, ?, ?)""",
        (user_id, profile, rc, now),
    )
    conn.commit()
    conn.close()


def get_round_count(user_id: str) -> int:
    _ensure_table()
    from database.connection import get_connection
    conn = get_connection()
    row = conn.execute("SELECT round_count FROM ely_memory WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    return row["round_count"] if row else 0


def increment_round(user_id: str):
    _ensure_table()
    from database.connection import get_connection
    conn = get_connection()
    conn.execute(
        """INSERT INTO ely_memory (user_id, round_count) VALUES (?, 1)
           ON CONFLICT(user_id) DO UPDATE SET round_count = round_count + 1""",
        (user_id,),
    )
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════
# Compaction
# ═══════════════════════════════════════════════════════════════

COMPACT_PROMPT = """Tu es un module de memoire. Compacter l'historique ci-dessous en un
PROFILE UTILISATEUR concis (max 600 caracteres). Capture UNIQUEMENT :
- Role (dev, pentester, architecte...)
- Technologies utilisees (APIs, frameworks, outils...)
- Projets en cours (noms, cibles, objectifs...)
- Preferences (modele IA, ton, langue...)
- Niveau d'expertise
- Demandes recentes et patterns recurrents
Sois FACTUEL et CONCIS. Priorise les infos les plus RECENTES.

Historique :
---
{history}
---

Profile actuel :
{existing}

Nouveau profile :"""


def _format_history(messages: list) -> str:
    lines = []
    for m in messages[-20:]:
        role = m.get("role", "?")
        content = (m.get("content") or "")[:300]
        if role == "user":
            lines.append(f"User: {content}")
        elif role == "assistant":
            lines.append(f"Assistant: {content.split(chr(10))[0][:200]}")
    return "\n".join(lines)


async def maybe_compact(user_id: str, recent_messages: list, provider):
    """Compact every N rounds. Returns the current profile."""
    if len(recent_messages) < 10:
        return get_memory(user_id)

    existing = get_memory(user_id)
    history_text = _format_history(recent_messages)
    if not history_text.strip():
        return existing

    prompt = COMPACT_PROMPT.format(
        history=history_text[-4000:],
        existing=existing or "(nouvel utilisateur)",
    )

    try:
        resp = provider.chat([{"role": "user", "content": prompt}], tools=None)
        new_profile = (resp.get("content") or "").strip()[:MAX_CHARS]
        if new_profile:
            save_memory(user_id, new_profile)
            _log.info(f"Memory compacted user={user_id[:8]}... ({len(new_profile)} chars)")
            return new_profile
    except Exception as e:
        _log.warning(f"Memory compaction failed: {e}")

    return existing


def build_memory_prompt(user_id: str) -> str:
    """Build the high-priority memory section for the system prompt."""
    profile = get_memory(user_id)
    if not profile:
        return ""
    return (
        "## Profil utilisateur (prioritaire)\n"
        "Voici ce que je sais de cet utilisateur. Utilise ces infos "
        "pour personnaliser tes reponses et anticiper ses besoins :\n\n"
        f"{profile}\n\n"
        "Fin du profil."
    )
