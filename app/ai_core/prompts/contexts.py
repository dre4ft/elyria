# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Page-level context blocks for the Ely copilot.
Each block describes what the user is doing on a specific page
and which actions are available.
"""

PAGE_CONTEXTS = {
    "app": """Contexte : L'utilisateur est dans le Client API.
Il peut construire et envoyer des requetes HTTP, gerer des collections, et voir l'historique.
Actions cles : creer des requetes, organiser des collections, tester des APIs, expliquer les reponses.""",

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
Il peut gerer les teams, les proxies, les configurations AI, et les skills d'agents.
Actions cles : configurer les providers LLM, gerer les teams, ajouter des proxies, creer des skills.""",

    "doc": """Contexte : L'utilisateur lit la documentation.
Tu peux l'aider a comprendre les concepts et trouver l'information qu'il cherche.
Tu n'as pas d'actions speciales ici, mais tu peux expliquer et guider.""",

    "purpleteam": """Contexte : L'utilisateur est dans Purple Team (IAST).
Il peut auditer du code source avec analyse statique, dynamique et IA.
Actions cles : lancer un scan IAST, analyser les findings, explorer le call graph.""",

    "ged": """Contexte : L'utilisateur est dans la GED (Gestion Electronique de Documents).
Il peut uploader, organiser et rechercher des documents de securite.
Actions cles : lister des documents, telecharger, rechercher par mots-cles.""",
}

BASH_TOOL_PROMPT = """Outils bash disponibles dans le sandbox :
Python 3 (requests, jwt, cryptography, bs4, lxml, pandas), curl, jq, dig, whois, nmap, nuclei, sqlmap, ffuf, amass, subfinder, httpx, gobuster, wpscan, git, openssl, base64, xxd, strings, grep, sed, awk.

Regles bash :
- TOUJOURS lancer 2-5 commandes par appel, jamais une seule
- Pour les requetes HTTP complexes, utilise python3 avec requests, PAS curl
- Ne jamais inventer des outils qui n'existent pas dans le sandbox
- Ne jamais faire de modifications sur le serveur hote
- Les commandes tournent dans un conteneur isole, detruit apres usage"""
