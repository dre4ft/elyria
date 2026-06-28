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
- Reponds en francais sauf si l'utilisateur parle anglais.
- Utilise les prompts specialises pour chaque page (pentest, greyteam, blueteam, etc.) pour guider ton comportement et tes suggestions d'actions.
- si un utilisateur te demande un tool que tu ne connais pas, dit que tu ne sais pas et liste tes tools disponibles. Ne suggere jamais d'outils que tu n'as pas et d'invente pas de reponse si tu ne sais pas, demande a l'utilisateur de clarifier ou de reformuler sa demande.
- L'usage du journal doit toujours venir de l'utilisateur, n'ajoute jamais d'entrée dans le journal sans que l'utilisateur te le demande explicitement. Si tu penses que quelque chose devrait être ajouté au journal, suggère à le a l'utilisateur mais attends sa confirmation avant de l'ajouter.
"""

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


BASH_TOOL_ADD = f"""Never suggest adding a new tool. Only use bash for executing commands in the sandbox.
If you need to run a command, use the existing bash tool and do not invent new tools or actions.
Ask yourself if the bash tool usage can harm Elyria, the serveur where the Elyria is or the user. If yes, never execute and ask the user for clarification instead.

sandox tools are powerful but can be dangerous if misused. Always double-check the command and its impact before executing.

Pkg Alpine:
- bash, curl, wget, ca-certificates, bind-tools, netcat-openbsd, socat
- nmap, nmap-scripts, git, openssh-client, python3, py3-pip
- jq, yq, unzip, tar, massdns, amass, wfuzz
- chromium, chromium-chromedriver

Python:
- sqlmap, requests, httpx, aiohttp, pyjwt, beautifulsoup4

Tool GO:
- nuclei v3.4.2, subfinder v2.7.0, httpx v1.7.2, katana v1.1.0, ffuf v2.1.0"""



def build_system_prompt(page, context_snapshot=None):
    parts = [BASE_PROMPT]
    # Load Ely skill
    try:
        from ai_core.skills_loader import load_agent_skill
        skill = load_agent_skill("ely")
        if skill:
            parts.append(skill)
    except Exception:
        pass
    if page in PAGE_CONTEXTS:
        parts.append(PAGE_CONTEXTS[page])
    if context_snapshot:
        parts.append(f"\nDonnees actuelles de la page :\n{json.dumps(context_snapshot, indent=2, default=str)[:2000]}")
    if page in ("app","pentest", "greyteam", "blueteam"):
        parts.append(BASH_TOOL_ADD)
    # Diary awareness
    diary_context = (context_snapshot or {}).get("recent_diary", [])
    if diary_context:
        parts.append(
            "\nNote: L'utilisateur a un journal de bord (Diary). "
            "Tu peux consulter ses entrees recentes avec ely_diary_list ou ely_diary_query "
            "pour comprendre le contexte de ses actions passees."
        )
    return "\n\n".join(parts)


# ═══════════════════════════════════════════════════════════════
# Provider resolution (same pattern as greyteam)
# ═══════════════════════════════════════════════════════════════

def _resolve_provider(slot="flash"):
    """Resolve the AI provider for Ely. slot = 'flash' or 'pro'."""
    from ai_core.ai_wrapper import AIWrapper
    from database.ai_config_mgmt import get_default_config
    from database.app_config import get_api_key

    def _resolve(s, fallback_model):
        cfg = get_default_config(s)
        if cfg:
            url = cfg.get("base_url", "") or "https://api.openai.com/v1"
            api_key = cfg.get("api_key", "")
            provider_type = cfg.get("provider_type", "openai")
            if provider_type == "lmstudio":
                url = url.rstrip("/").replace("/api/v1", "/v1")
                if not url.endswith("/v1"): url = url.rstrip("/") + "/v1"
                if not api_key: api_key = "not-needed"
            if not api_key: api_key = get_api_key("openai_api_key")
            if not api_key: return None
            return {"provider_type": provider_type, "url": url, "api_key": api_key, "model": cfg.get("model", "") or fallback_model}
        api_key = get_api_key("openai_api_key")
        if api_key: return {"provider_type": "openai", "url": "https://api.openai.com/v1", "api_key": api_key, "model": fallback_model}
        return None

    cfg = _resolve(slot, "gpt-4o-mini" if slot == "flash" else "gpt-4o")
    if not cfg: cfg = _resolve("flash" if slot == "pro" else "pro", "gpt-4o-mini")
    if not cfg: return None, None

    wrapper = AIWrapper(provider_type=cfg["provider_type"], url=cfg["url"], api_key=cfg["api_key"], model=cfg["model"])
    return wrapper.provider, cfg["model"]


# ═══════════════════════════════════════════════════════════════
# Chat
# ═══════════════════════════════════════════════════════════════

async def chat(page, messages, request, stream_cb=None, slot="flash"):
    """
    Main chat entry point. Handles function calling loop.

    Returns: {"reply": "...", "actions": [...], "tokens": {...}}
    """
    from ely.elys_tools import get_action_definitions, execute_action
    from ely.prompts import get_action_definitions as get_prompt, execute_action as execute_prompt
    from core.auth import get_user as get_user_id

    provider, model = _resolve_provider(slot)
    if not provider:
        return {
            "reply": "Aucun fournisseur IA configure. Allez dans Hub > AI Agent pour configurer un modele.",
            "actions": [],
            "tokens": {"total": 0},        
            }
    page = page or "app"
    user_id = get_user_id(request) if request else "anon"

    # ── Memory: increment round, inject profile into system prompt ──
    from ely.memory import build_memory_prompt, increment_round, maybe_compact
    #increment_round(user_id)
    memory_prompt = build_memory_prompt(user_id)

    context_snapshot = get_context_for_page(page, request)
    system_content = build_system_prompt(page, context_snapshot)
    if memory_prompt:
        system_content = memory_prompt + "\n\n" + system_content
    system_msg = {"role": "system", "content": system_content}
    tools = get_action_definitions(page)
    tools.extend(get_prompt(page))
    tool_map = {t["function"]["name"]: t for t in tools}

    full_messages = [system_msg] + [m for m in messages if m.get("role") != "system"]
    tokens_used = 0
    actions_executed = []
    final_reply = ""

    # ── Read max turns preference ──
    try:
        from ely.database import get_preferences
        prefs = get_preferences(user_id)
        max_turns = prefs.get("max_turns", 5)
    except Exception:
        max_turns = 5

    for turn in range(max_turns):
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
            if "prompt" in name:
                result = await execute_prompt(name, args, request, page=page)
            else:
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
    
    # ── Final call + force text if needed ──
    force_count = 0
    while force_count < 3:
        try:
            resp = provider.chat(full_messages, tools=tools if tools else None)
        except Exception as e:
            _log.error(f"LLM final call failed: {e}")
            final_reply = f"Desole, erreur de communication avec l'IA : {str(e)[:200]}"
            resp = None
            break

        content = resp.get("content", "") or ""
        tc = resp.get("tool_calls", [])
        reasoning = resp.get("reasoning_content", "") or ""

        # Has content → done
        if content:
            final_reply = content
            break

        # Has tool calls → process them
        if tc:
            assistant_msg = {"role": "assistant", "content": content, "tool_calls": [
                {"id": t.id if hasattr(t, 'id') else t.get("id", f"tc_{force_count}"), "type": "function",
                 "function": {"name": t.function.name if hasattr(t, 'function') else t["function"]["name"],
                              "arguments": t.function.arguments if hasattr(t, 'function') else t["function"]["arguments"]}}
                for t in tc
            ]}
            full_messages.append(assistant_msg)
            for t in tc:
                func = t.function if hasattr(t, 'function') else t["function"]
                name = func.name if hasattr(func, 'name') else func["name"]
                args_str = func.arguments if hasattr(func, 'arguments') else func["arguments"]
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except (json.JSONDecodeError, TypeError):
                    args = {}
                try:
                    result = await execute_action(name, args, request, page=page)
                except Exception:
                    result = {"error": "action failed"}
                actions_executed.append({"name": name, "args": args, "result": result})
                t_id = t.id if hasattr(t, 'id') else t.get("id", f"tc_{force_count}")
                full_messages.append({"role": "tool", "tool_call_id": t_id, "content": json.dumps(result, default=str)[:2000]})
            force_count += 1
            continue

        # No content, no tool calls but has reasoning → use reasoning as reply
        if reasoning:
            final_reply = reasoning[:2000]
            break

        # Empty response — force it
        full_messages.append({"role": "user", "content": "Reponds maintenant avec ton analyse finale."})
        force_count += 1

    reply = (resp.get("content", "") if resp else "") or final_reply

    # ── Fallback: if still no reply, force one last call WITHOUT tools ──
    if not reply:
        fallback_prompt = "Resume en 1-2 phrases ce que tu viens de faire et les resultats obtenus." if actions_executed else "Reponds a la question de l'utilisateur en 1-2 phrases."
        try:
            full_messages.append({"role": "user", "content": fallback_prompt})
            fallback_resp = provider.chat(full_messages, tools=[])  # no tools → forces text response
            reply = fallback_resp.get("content", "") or ""
            if reply:
                tokens_used += fallback_resp.get("usage", {}).get("total_tokens", 0) if isinstance(fallback_resp.get("usage"), dict) else 0
        except Exception:
            pass

    # ── Ultimate safety net ──
    if not reply:
        reply = "Action terminee" if actions_executed else "Je n'ai pas pu traiter ta demande. Peux-tu reformuler ?"

    # ── Memory compaction (fire and forget, errors are non-fatal) ──
    try:
        import asyncio
        asyncio.ensure_future(maybe_compact(user_id, full_messages, provider))
    except Exception:
        pass

    return {
        "reply": reply,
        "actions": actions_executed,
        "tokens": {"total": tokens_used},
    }

def get_context_for_page(page, request):
    """Collect additional context for the given page."""
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    if not user_id:
        return {}

    context = {}
    if page == "app":
        from database.collection_api import _get_followed_team_ids
        from database.request_mgmt import get_last_n_requests_by_user as list_recent_requests

        context["followed_team_ids"] = _get_followed_team_ids(user_id)
        context["recent_requests"] = list_recent_requests(user_id)
    if page == "pentest":
        from redteam.database import get_last_campaign_by_user,get_campaign_findings
        campaign = get_last_campaign_by_user(user_id)
        if campaign:
            findings = get_campaign_findings(campaign.get("campaign_id", ""))
            context["active_campaign"] = {
                "id": campaign.get("campaign_id"),
                "name": campaign.get("name", ""),
                "status": campaign.get("status", ""),
                "target": campaign.get("target_domain", "") or campaign.get("target_path", ""),
                "findings": findings,
            }
        context["preferred_tools"] = {
            "redteam": ["sqlmap", "netcat-openbsd", "socat", "wfuzz","nuclei","nmap","chronium"]}

    if page == "greyteam":
        from greyteam.database import get_last_report_by_user
        report = get_last_report_by_user(user_id=user_id)
        if report:
            context["active_report"] = {
                "id": report.get("report_id", ""),
                "target": report.get("target_domain", ""),
                "status": report.get("status", ""),
            }
        context["preferred_tools"] = {
            "Reconnaissance": ["subfinder", "amass", "massdns","katana","nslookup"],
            "Analyse": ["ssl", "httpx", "nuclei","bf4", "jq","yq"],
        }
    if page == "blueteam":
        from blueteam.database import get_last_report_by_user
        report = get_last_report_by_user(user_id=user_id)
        if report:
            context["active_report"] = {
                "id": report.get("report_id", ""),
                "target": report.get("target_path", ""),
                "status": report.get("status", ""),
            }

    # ── Recent diary entries as context ──
    try:
        from ely.diary_database import diary_list
        recent = diary_list(user_id, limit=5)
        if recent:
            context["recent_diary"] = [
                {"title": e["title"], "diary_id": e["diary_id"], "date": e["created_at"], "page": e["page"]}
                for e in recent
            ]
    except Exception:
        pass

    return context
