# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Ely — AI Agent core.

Orchestrates context collection, LLM calls with function calling,
and response streaming via SSE.
"""

import json
from core.logging import get_logger

_log = get_logger("ely.agent")

# ═══════════════════════════════════════════════════════════════
# System prompts per page
# ═══════════════════════════════════════════════════════════════

BASE_PROMPT = """Tu es Ely, l'assistant IA d'Elyria, une plateforme tout-en-un de securite API.
Tu aides l'utilisateur a naviguer dans l'application, comprendre les concepts de securite,
et executer des actions (scans, requetes, workflows, analyses).

Regles :
- Sois concis et utile. Pas de blabla.
- Tu as acces a des actions (functions) pour interagir avec la plateforme.
- Utilise les actions quand c'est pertinent, pas juste pour repondre.
- Tu vois la meme chose que l'utilisateur (memes permissions).
- Si tu n'es pas sur, demande a l'utilisateur de clarifier.
- Reponds en francais sauf si l'utilisateur parle anglais."""

PAGE_CONTEXTS = {
    "app": """Contexte : L'utilisateur est dans le Client API.
Il peut construire et envoyer des requetes HTTP, gerer des collections, et voir l'historique.
Actions cles : creer des requetes, organiser des collections, tester des APIs, expliauer les reponses.""",

    "workflow": """Contexte : L'utilisateur est dans le Workflow Builder.
Il peut creer des workflows no-code avec des blocs (start, request, if/else, for, etc.).
Actions cles : creer/modifier des workflows, ajouter des blocs, executer des workflows.""",

    "pentest": """Contexte : L'utilisateur est dans Red Team (pentest).
Il peut lancer des scans de securite automatises contre des APIs.
Actions cles : lancer un scan, analyser les findings, generer des rapports.""",

    "greyteam": """Contexte : L'utilisateur est dans Grey Team (OSINT).
Il peut lancer des scans de reconnaissance passive sur des domaines.
Actions cles : lancer un scan OSINT, analyser les DNS/WHOIS/SSL/crt.sh.""",

    "blueteam": """Contexte : L'utilisateur est dans Blue Team (SSDLC).
Il peut analyser des specifications API pour identifier les exigences de securite.
Actions cles : auditer une spec, generer des recommandations de securite.""",

    "hub": """Contexte : L'utilisateur est dans le Hub (configuration).
Il peut gerer les teams, les proxies, et les configurations AI.
Actions cles : configurer les providers LLM, gerer les teams, ajouter des proxies.""",

    "doc": """Contexte : L'utilisateur lit la documentation.
Tu peux l'aider a comprendre les concepts et trouver l'information qu'il cherche.
Tu n'as pas d'actions speciales ici, mais tu peux expliquer et guider.""",
}


def build_system_prompt(page, context_snapshot=None):
    parts = [BASE_PROMPT]
    if page in PAGE_CONTEXTS:
        parts.append(PAGE_CONTEXTS[page])
    if context_snapshot:
        parts.append(f"\nDonnees actuelles de la page :\n{json.dumps(context_snapshot, indent=2, default=str)[:2000]}")
    return "\n\n".join(parts)


# ═══════════════════════════════════════════════════════════════
# Provider resolution (same pattern as greyteam)
# ═══════════════════════════════════════════════════════════════

def _resolve_provider():
    """Resolve the AI provider for Ely. Prefers Flash model for speed."""
    from ai_core.ai_wrapper import AIWrapper
    from database.ai_config_mgmt import get_default_config
    from database.app_config import get_api_key

    def _resolve(slot, fallback_model):
        cfg = get_default_config(slot)
        if cfg:
            url = cfg.get("base_url", "") or "https://api.openai.com/v1"
            api_key = cfg.get("api_key", "")
            provider_type = cfg.get("provider_type", "openai")
            if provider_type == "lmstudio":
                url = url.rstrip("/").replace("/api/v1", "/v1")
                if not url.endswith("/v1"):
                    url = url.rstrip("/") + "/v1"
                if not api_key:
                    api_key = "not-needed"
            if not api_key:
                api_key = get_api_key("openai_api_key")
            if not api_key:
                return None
            return {
                "provider_type": provider_type, "url": url,
                "api_key": api_key, "model": cfg.get("model", "") or fallback_model,
            }
        api_key = get_api_key("openai_api_key")
        if api_key:
            return {
                "provider_type": "openai", "url": "https://api.openai.com/v1",
                "api_key": api_key, "model": fallback_model,
            }
        return None

    flash_cfg = _resolve("flash", "gpt-4o-mini")
    if not flash_cfg:
        flash_cfg = _resolve("pro", "gpt-4o")
    if not flash_cfg:
        return None, None

    wrapper = AIWrapper(
        provider_type=flash_cfg["provider_type"],
        url=flash_cfg["url"],
        api_key=flash_cfg["api_key"],
        model=flash_cfg["model"],
    )
    return wrapper.provider, flash_cfg["model"]


# ═══════════════════════════════════════════════════════════════
# Chat
# ═══════════════════════════════════════════════════════════════

async def chat(page, messages, context_snapshot, request, stream_cb=None):
    """
    Main chat entry point. Handles function calling loop.

    Returns: {"reply": "...", "actions": [...], "tokens": {...}}
    """
    from ely.tools import get_action_definitions, execute_action

    provider, model = _resolve_provider()
    if not provider:
        return {
            "reply": "Aucun fournisseur IA configure. Allez dans Hub > AI Agent pour configurer un modele.",
            "actions": [],
            "tokens": {"total": 0},
        }
    page = page or "app"
    system_msg = {"role": "system", "content": build_system_prompt(page, context_snapshot)}
    tools = get_action_definitions(page)
    tool_map = {t["function"]["name"]: t for t in tools}

    full_messages = [system_msg] + [m for m in messages if m.get("role") != "system"]
    tokens_used = 0
    actions_executed = []
    final_reply = ""

    # Up to 3 turns of function calling
    for turn in range(3):
        try:
            resp = provider.chat(full_messages, tools=tools if tools else None)
        except Exception as e:
            _log.error(f"LLM call failed: {e}")
            msg = str(e)
            if len(msg) > 200:
                msg = msg[:200] + "..."
            final_reply = f"Desole, erreur de communication avec l'IA : {msg}"
            break

        content = resp.get("content", "") or ""
        tokens_used += resp.get("usage", {}).get("total_tokens", 0) if isinstance(resp.get("usage"), dict) else 0
        final_reply = content

        if stream_cb and content:
            await stream_cb({"type": "text", "content": content})

        tool_calls = resp.get("tool_calls", [])
        if not tool_calls:
            break

        # Add assistant message with tool calls
        assistant_msg = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id if hasattr(tc, 'id') else tc.get("id", f"call_{turn}_{i}"),
                    "type": "function",
                    "function": {
                        "name": tc.function.name if hasattr(tc, 'function') else tc["function"]["name"],
                        "arguments": tc.function.arguments if hasattr(tc, 'function') else tc["function"]["arguments"],
                    },
                }
                for i, tc in enumerate(tool_calls)
            ]
        full_messages.append(assistant_msg)

        for tc in tool_calls:
            func = tc.function if hasattr(tc, 'function') else tc["function"]
            name = func.name if hasattr(func, 'name') else func["name"]
            args_str = func.arguments if hasattr(func, 'arguments') else func["arguments"]
            try:
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
            except (json.JSONDecodeError, TypeError):
                args = {}

            if stream_cb:
                await stream_cb({"type": "action_start", "action": name, "args": args})

            result = await execute_action(name, args, request, page=page)
            actions_executed.append({"name": name, "args": args, "result": result})

            if stream_cb:
                await stream_cb({"type": "action_done", "action": name, "result": result})

            tc_id = tc.id if hasattr(tc, 'id') else tc.get("id", f"call_{turn}")
            full_messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": json.dumps(result, default=str)[:2000],
            })

    return {
        "reply": final_reply,
        "actions": actions_executed,
        "tokens": {"total": tokens_used},
    }
