# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Modular prompt management system.

All agent prompts are defined here instead of inline in scanner code.
Use PromptBuilder to assemble prompts with context, skills, and configuration.

Architecture:
  identities.py   — Agent identity prompts (who the agent IS)
  contexts.py     — Page-level context blocks (Ely copilot)
  system.py       — System-level prompts (compaction, slash commands)
  rounds/         — Round templates for iterative agents
  reports.py      — Report generation templates

Usage:
  from ai_core.prompts import PromptBuilder

  builder = PromptBuilder("redteam")
  system = builder.build_system(target="https://api.example.com", auth="jwt_bearer")
  rounds = builder.get_rounds()
"""

from .identities import AGENT_IDENTITIES
from .system import COMPACT_PROMPT, SLASH_PROMPT


class PromptBuilder:
    """Builds prompts for a specific agent type."""

    def __init__(self, agent_type: str, language: str = "en"):
        self.agent_type = agent_type
        self.language = language

    def build_system(self, **kwargs) -> str:
        """Build the base system prompt with skill + identity."""
        identity = AGENT_IDENTITIES.get(self.agent_type, "")
        if not identity:
            return ""

        skill = self._load_skill()
        parts = [identity.format(**kwargs) if isinstance(identity, str) else identity]
        if skill:
            parts.append(skill)
        return "\n\n".join(parts)

    def build_context(self, **kwargs) -> str:
        """Build context block from kwargs (findings, endpoints, auth, etc.)."""
        context_parts = []
        for key, value in kwargs.items():
            if value:
                if isinstance(value, list):
                    value_str = "\n".join(f"- {item}" for item in value[:50])
                    context_parts.append(f"## {key.replace('_', ' ').title()}\n{value_str}")
                elif isinstance(value, str):
                    context_parts.append(value)
        return "\n\n".join(context_parts)

    def get_rounds(self, phase: str = "explore") -> list:
        """Get round templates for iterative agent loops."""
        if self.agent_type == "redteam":
            from .rounds.redteam import EXPLORE_ROUNDS
            return EXPLORE_ROUNDS
        elif self.agent_type == "redteam_expert":
            from .rounds.expert import EXPLORATION_ROUNDS, ANALYSIS_ROUNDS
            return EXPLORATION_ROUNDS if phase == "explore" else ANALYSIS_ROUNDS
        elif self.agent_type == "blueteam":
            from .rounds.blueteam import ANALYSIS_ROUNDS, REPORT_ROUNDS
            return ANALYSIS_ROUNDS if phase == "analyze" else REPORT_ROUNDS
        return []

    def get_report_prompt(self, report_type: str = "standard", **kwargs) -> str:
        """Get a report generation prompt."""
        from .reports import REPORT_PROMPTS
        prompt = REPORT_PROMPTS.get(self.agent_type, {}).get(report_type, "")
        if isinstance(prompt, str) and kwargs:
            return prompt.format(**kwargs)
        return prompt

    def _load_skill(self) -> str:
        try:
            from ai_core.skills_loader import load_agent_skill
            return load_agent_skill(self.agent_type)
        except Exception:
            return ""


# Convenience function
def get_prompt(agent_type: str, **kwargs) -> str:
    """Quick access: get the full system prompt for an agent type."""
    return PromptBuilder(agent_type).build_system(**kwargs)
