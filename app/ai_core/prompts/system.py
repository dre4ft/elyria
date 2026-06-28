# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
System-level prompts — memory compaction, slash commands, tool forcing.
"""

COMPACT_PROMPT = """Analyze the following conversation history and create a compact user profile.
Extract: role, technologies, ongoing projects, preferences, expertise level.

Conversation:
{history}

Existing profile (update if needed):
{existing}

Return ONLY a JSON object with these fields (all optional, omit if unknown):
{{"name": "...", "role": "...", "technologies": ["..."], "projects": ["..."], "preferences": {{"language": "fr|en", "verbosity": "concise|detailed"}}, "expertise": "beginner|intermediate|expert", "notes": "..."}}

Keep it concise. Only include information that would be useful for future interactions."""


def get_slash_prompt(tool_name: str, user_message: str) -> str:
    """Generate a system prompt that forces tool invocation for slash commands."""
    return f"""The user invoked /{tool_name}. You MUST call the `{tool_name}` function at least once in your response.
Do not explain what you're doing — just call the tool.
User message: {user_message}"""
