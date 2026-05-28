
import json
import threading
from core.logging import get_logger

_log = get_logger("ely.tools.prompts")

ACTIONS = {}


def _action(name, description, parameters):
    def decorator(handler):
        ACTIONS[name] = {
            "definition": {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": {
                        "type": "object",
                        "properties": parameters,
                        "required": list(parameters.keys()),
                    },
                },
            },
            "handler": handler,
        }
        return handler
    return decorator


@_action("ely_prompt_pentest", "get a pentest playbook",
         {})
def return_pentest_playbook(args, request):
    return {"playbook": """1. Reconnaissance passive : Collecte d'informations sur la cible à partir de sources publiques (OSINT).
                            2. Reconnaissance active : Utilisation d'outils pour scanner les ports, identifier les services et détecter les vulnérabilités.    
                            3. Exploitation : Tentative d'exploitation des vulnérabilités identifiées pour accéder au système.
                            4. Post-exploitation : Maintien de l'accès, escalade de privilèges et exfiltration de données.
                            5. Rapport : Documentation des découvertes, des vulnérabilités et des recommandations de remédiation.
            
                            quick scan not full on pentest"""}

@_action("ely_prompt_osint", "get an OSINT playbook",
         {})
def return_osint_playbook(args, request):
    return {"playbook": """1. Définition des objectifs : Identifier les informations spécifiques à collecter sur la cible.
                            2. Collecte d'informations : Utilisation de moteurs de recherche, de bases de données, de réseaux sociaux et d'autres sources publiques pour recueillir des données sur la cible.
                            3. Analyse des données : Tri, filtrage et analyse des informations collectées pour identifier des tendances, des connexions et des vulnérabilités potentielles.
                            4. Rapport : Documentation des découvertes, des vulnérabilités et des recommandations de remédiation.   
            
                            quick scan not full on osint campaign"""}


@_action("ely_prompt_api_expert", "get an API expert playbook",
         {})
def return_api_expert_playbook(args, request):
    return {"playbook": """1. Analyse de l'API : Comprendre les fonctionnalités, les points de terminaison, les méthodes HTTP utilisées et les mécanismes d'authentification.
                            2. Identification des vulnérabilités : Utilisation d'outils pour scanner les points de terminaison à la recherche de vulnérabilités courantes telles que l'injection, les failles d'authentification, les problèmes de configuration, etc.
                            3. Proposition de correctifs : Fournir des recommandations pour corriger les vulnérabilités identifiées, telles que l'amélioration de la validation des entrées, la mise en œuvre de mécanismes d'authentification plus robustes, etc. demande a l'utilisateur de fournir la stack.
                            4. Rapport : Documentation des découvertes, des vulnérabilités et des recommandations"""}




# ═══════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════

def get_action_definitions(page=None):
    all_defs = [v["definition"] for v in ACTIONS.values()]
    if not page:
        return all_defs
    page_actions = {
        "app":      ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"],
        "workflow": ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"],
        "pentest":  ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"],
        "greyteam": ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"],
        "blueteam": ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"],
        "hub":      ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"],
        "doc":      ["ely_prompt_pentest", "ely_prompt_osint", "ely_prompt_api_expert"]
    }
    allowed = set(page_actions.get(page, []))
    return [d for d in all_defs if d.get("function", {}).get("name") in allowed or page is None]


async def execute_action(name, args,request, page=None):
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    if name not in ACTIONS:
        return {"error": f"Unknown action: {name}"}
    handler = ACTIONS[name]["handler"]
    try:
        _log.info(f"Action '{name}' args={json.dumps(args, default=str)[:200]}")
        result = handler(args, request)
        if hasattr(result, '__await__'):
            result = await result
        if user_id:
            from ely.database import log_action
            log_action(user_id, page or "", name, args, result,
                       "ok" if "error" not in result else "error", 0)
        return result
    except Exception as e:
        _log.error(f"Action '{name}' failed: {e}")
        if user_id:
            from ely.database import log_action
            log_action(user_id, page or "", name, args, {"error": str(e)[:300]}, "error", 0)
        return {"error": str(e)[:300]}