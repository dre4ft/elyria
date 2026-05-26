# Elyria — TODO Next (Enterprise)

---

## 1. Ely — L'agent IA omniprésent

Agent IA contextuel qui suit l'utilisateur partout dans l'app, superposé en HUD sur chaque IHM du frontend.

### 1.1 Architecture permissionnelle

```
┌─────────────────────────────────────────────┐
│           HIÉRARCHIE DES DROITS             │
│                                             │
│   Utilisateur ←── miroir ──→ Ely            │
│   (peut voir ce      │       (peut voir ce  │
│    qu'Ely fait)      │       que l'user     │
│                      │       peut voir)     │
│                      │                      │
│   PAS de privilège   │   PAS d'accès aux    │
│   admin pour Ely     │   teams interdites   │
│   (sauf si user      │   (sauf si user      │
│    admin)            │    membre)           │
└─────────────────────────────────────────────┘
```

**Règles :**
- Ely hérite EXACTEMENT des permissions JWT de l'utilisateur (même token, mêmes scopes)
- Ely voit ce que l'utilisateur peut voir (collections, teams, configs)
- L'utilisateur voit ce qu'Ely fait (historique, logs, actions)
- Aucune élévation de privilège implicite
- Rate limiting identique à l'utilisateur

**Implémentation :**
- `app/ely/` — module backend dédié
  - `agent.py` — orchestration du contexte + LLM
  - `context.py` — collecte du contexte de la page courante
  - `actions.py` — mapping intentions → appels API internes
  - `memory.py` — mémoire conversationnelle (SQLite, par user)
- Réutilisation de `ai_core/` pour l'abstraction provider (OpenAI, Ollama, LM Studio, DeepSeek)
- Pas de nouveau système d'auth : le token JWT de l'utilisateur est transmis tel quel

### 1.2 UI — Mode HUD

```
┌──────────────────────────────────────────────┐
│  HEADER (header normal de la page)           │
├──────────────────────────────────────────────┤
│                                              │
│  MAIN CONTENT (la page en cours)             │
│                                              │
│                         ┌──────────────────┐ │
│                         │ ely  💬          │ │
│                         │ ──────────────── │ │
│                         │ Que veux-tu      │ │
│                         │ faire ?          │ │
│                         │                  │ │
│                         │ [input...] [→]   │ │
│                         └──────────────────┘ │
│                         ▲ draggable          │
│                         ▲ stickable coins    │
└──────────────────────────────────────────────┘
```

**Comportements :**
- Flottant au premier plan (`z-index: 1000`), par-dessus TOUT le contenu
- **Draggable** : drag & drop libre sur tout l'écran via `pointerdown/move/up`
- **Sticky corners** : aimantation automatique vers les 4 coins quand relâché proche d'un bord (8px threshold)
- **Opacité réglable** :
  - Slider dans le header du HUD ou molette (Ctrl+scroll sur le HUD)
  - Range : 20% (très transparent) → 100% (complètement opaque)
  - Arrière-plan : `bg-base-800/var(--ely-opacity)` avec `backdrop-blur` proportionnel
  - L'opacité n'affecte PAS le texte/input (seulement le fond du panneau via `background-color: rgba(...)` avec opacité variable sur le fond uniquement)
  - Persistée dans `localStorage` (`elyria-ely-opacity`)
- **États visuels** :
  - `collapsed` — icône bulle flottante (48×48px, ronde, avatar Ely)
  - `expanded` — panneau 380×480px avec zone de chat + input
  - `minimized` — barre fine en bas (360×32px) avec juste l'input
- **Persistance** : position + opacité sauvegardées dans `localStorage` par page (`elyria-ely-pos-{page}`)
- **Responsive** : sur mobile, snap automatique en bas de l'écran, largeur 100%
- **Thème** : suit le thème clair/sombre actif
- **Animations** : transitions fluides entre états (200ms ease-out)

### 1.3 Contextes par page

| Page | Contexte envoyé à Ely | Actions disponibles |
|---|---|---|
| **Client API** (`/app`) | Méthode, URL, headers, body de la requête en cours | Créer/modifier/envoyer une requête, sauver dans une collection, générer des assertions |
| **Workflows** | Blocs du canvas, workflow courant | Créer/modifier/supprimer des blocs, connecter, lancer le workflow |
| **Red Team** | Profil de scan, findings, campagne active | Lancer un scan, raffiner des findings, générer un rapport |
| **Grey Team** | Domaine cible, findings OSINT | Lancer un scan OSINT, analyser les résultats, suggérer des pivots |
| **Blue Team** | Spec API chargée, rapport en cours | Analyser la spec, générer des exigences de sécu, auditer |
| **Hub** | Teams, proxy, configs AI | Gérer les teams, configurer les providers AI |
| **Docs** | Page de doc affichée | Chercher dans la doc, expliquer un concept |

**Collecte du contexte :**
- Backend : endpoint `GET /api/ely/context?page={page}` qui collecte les données pertinentes selon la page
- Frontend : le HUD envoie un `POST /api/ely/chat` avec `{page, context_snapshot, message}`
- Le backend enrichit le prompt système avec le contexte avant d'appeler le LLM

### 1.4 Actions — Ely peut interagir

Ely ne fait pas que répondre : il **agit** via les API internes.

**Mécanisme : function calling standard**
- Le backend expose les actions disponibles sous forme de définitions de fonctions OpenAI-compatibles
- Le LLM choisit d'appeler une fonction → le backend l'exécute avec le token de l'utilisateur

**Catalogue d'actions :**

```
ely.requests.create(method, url, headers, body)     → POST /api/requests
ely.requests.send(request_id)                        → POST /api/requests/{id}/send
ely.collections.create(name, parent_id?)             → POST /api/collections
ely.collections.add_request(collection_id, req_data) → POST /api/collections/{id}/items
ely.workflows.create(name, blocks[])                 → POST /api/workflows
ely.workflows.run(workflow_id)                       → POST /api/workflows/{id}/run
ely.redteam.scan(profile_id)                         → POST /api/redteam/reports
ely.greyteam.osint(profile_id)                       → POST /api/greyteam/reports
ely.blueteam.analyze(profile_id)                     → POST /api/blueteam/reports
ely.teams.invite(team_id, email)                     → POST /api/teams/{id}/members
ely.config.get(key)                                  → GET /api/config/{key}
ely.config.set(key, value)                           → PUT /api/config/{key}
```

**Sécurité :**
- Chaque action est wrappée dans une vérification de permissions (le token user est passé tel quel)
- Les actions sont auditées dans `audit.log` avec `source: "ely"` + `user_id`
- Rate limit : max 10 actions/min (configurable par `ely.action_rate_limit` dans app_config)
- L'utilisateur peut voir l'historique des actions d'Ely dans le HUD (onglet "Activité")

### 1.5 Mémoire et personnalisation

**Par utilisateur :**
- Conversation history (SQLite `ely_conversations` + `ely_messages`)
- Préférences : ton, verbosité, mode proactif/réactif
- Contexte persistant : "souviens-toi que je travaille sur l'API X"

**Par page :**
- Contexte immédiat (requête en cours, workflow ouvert, etc.)
- Dernière action effectuée

**Modèle de données :**
```sql
CREATE TABLE ely_conversations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  page_context TEXT,       -- 'app', 'workflow', etc.
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE ely_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT REFERENCES ely_conversations(id),
  role TEXT,               -- 'user' | 'assistant' | 'system' | 'action'
  content TEXT,
  action_name TEXT,        -- si role='action', quelle fonction a été appelée
  action_result TEXT,      -- résultat JSON de l'action
  created_at DATETIME
);

CREATE TABLE ely_preferences (
  user_id TEXT PRIMARY KEY,
  tone TEXT DEFAULT 'professional',   -- 'casual' | 'professional' | 'technical'
  verbosity TEXT DEFAULT 'concise',   -- 'concise' | 'detailed'
  proactive BOOLEAN DEFAULT 0,        -- Ely prend-il l'initiative ?
  preferred_provider TEXT,
  preferred_model TEXT
);
```

### 1.6 Déploiement technique

**Frontend (`static/ely-hud.js`) :**
- Chargé conditionnellement si le user a activé Ely dans ses préférences Hub
- Crée le HUD en dehors du layout principal (append à `<body>`)
- Communique avec le backend en streaming SSE pour les réponses longues
- Indépendant du JS de la page (ne touche pas à `greyteam.js`, `app.js`, etc.)

**Backend (`app/ely/`) :**
- Route mountée sur `/api/ely/*`
- Streaming via SSE (`/api/ely/chat/stream`)
- Utilise le filetage asynchrone existant (comme `greyteam/api.py`)

### 1.7 Auditabilité — Onglet Ely dans le Hub

Toute l'activité d'Ely est consultable dans le Hub → nouvel onglet **"Ely"**.

```
┌─ HUB — Onglet Ely ───────────────────────────────────────────┐
│                                                               │
│  ┌─ Filtres ───────────────────────────────────────────────┐ │
│  │ Page: [toutes ▾]  Action: [toutes ▾]  Période: [7j ▾] │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─ Historique des actions ────────────────────────────────┐ │
│  │ Date       │ Page        │ Action              │ Statut │ │
│  │ 26/05 14:32│ Red Team    │ lancer scan         │ ✓ OK   │ │
│  │ 26/05 14:28│ Client API  │ créer requête       │ ✓ OK   │ │
│  │ 26/05 14:15│ Grey Team   │ lancer OSINT        │ ✗ err  │ │
│  │ 26/05 13:50│ Workflows   │ ajouter bloc If/Else│ ✓ OK   │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─ Stats ─────────────────────────────────────────────────┐ │
│  │ Actions totales : 142  │  Taux de succès : 94%          │ │
│  │ Tokens consommés : 48K │  Actions ce mois : 31          │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─ Préférences Ely ───────────────────────────────────────┐ │
│  │ Ton : [professionnel ▾]  Verbosité : [concis ▾]         │ │
│  │ Proactif : [○]  Provider : [OpenAI ▾]  Model : [gpt-4] │ │
│  │ [Désactiver Ely temporairement]                         │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

**Endpoints :**
```
GET  /api/ely/audit?page=&action=&from=&to=&limit=   → historique paginé
GET  /api/ely/stats                                   → stats globales (actions, tokens, succès)
PUT  /api/ely/preferences                             → maj préférences
POST /api/ely/disable                                 → désactiver Ely (flag user)
POST /api/ely/enable                                  → réactiver Ely
```

**Règles d'audit :**
- Chaque action d'Ely est loggée dans `ely_audit` avec : timestamp, page, action, paramètres, résultat, tokens consommés
- L'utilisateur voit UNIQUEMENT ses propres actions (filtrage par `user_id` du JWT)
- Les admins de team peuvent voir les actions Ely des membres (à des fins de revue de sécu)
- Rétention : 90 jours par défaut (configurable `ely.audit_retention_days`)

---

## 2. Sandbox Custom — Images personnalisables

Permettre aux utilisateurs de "pimper" leurs images de sandbox Docker avec des outils additionnels.

### 2.1 Concept

```
┌─────────────────────────────────────────────────────────────┐
│                 SANDBOX CUSTOM LIFECYCLE                    │
│                                                             │
│  Image Base (Elyria)  ──→  User Layers  ──→  Image Finale  │
│  (python3, curl,      │   (packages       │   (utilisée par │
│   dig, whois, ...)    │    additionnels)  │    Red/Grey     │
│                       │                   │    Team scans)  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Gestionnaire de paquets intégré

**Dans le Hub → onglet "Sandbox" :**

```
┌────────────────────────────────────────────┐
│  Sandbox — Customisation                  │
│  ───────────────────────                  │
│                                            │
│  Image de base : elyria/sandbox:latest     │
│  Votre image  : elyria/sandbox-user-xxx    │
│                                            │
│  Paquets disponibles :                     │
│  ┌──────────────────────────────────────┐ │
│  │ [✓] nmap        7.95-1   (déjà)    │ │
│  │ [✓] ffuf        2.1.0    (déjà)    │ │
│  │ [+] nuclei      3.3.0    (install)  │ │
│  │ [+] amass       4.2.0    (install)  │ │
│  │ [+] bloodhound  5.0.0    (install)  │ │
│  └──────────────────────────────────────┘ │
│                                            │
│  [Rebuild image]  [Reset to default]       │
└────────────────────────────────────────────┘
```

### 2.3 Limites et contraintes

- **Paquets whitelistés** : uniquement des outils de sécurité/reconnaissance approuvés (pas de miners, malware, reverse shells outbound)
- **Taille max** : 2 Go par couche utilisateur (configurable `sandbox.max_layer_size_mb`)
- **Temps de build** : timeout à 10 minutes
- **Network pendant le build** : sortant uniquement vers les registres officiels (PyPI, apt, npm)
- **Pas de persistance réseau** : la sandbox finale est air-gapped avec accès contrôlé
- **Audit** : chaque build est loggé avec la liste des paquets installés

### 2.4 Implémentation

**Backend (`app/sandbox/builder.py`) :**
```python
def build_user_image(user_id: str, packages: list[str]) -> str:
    """
    1. Pull l'image de base elyria/sandbox:latest
    2. Crée un Dockerfile temporaire avec les packages
    3. docker build → elyria/sandbox-{user_id}:latest
    4. Retourne le hash de l'image
    """
```

**Stockage :**
- Images stockées dans le registry Docker local
- Métadonnées dans `app_config` : `sandbox.user_image_{user_id}` = hash
- Nettoyage automatique des images non utilisées depuis 30 jours

**Endpoint API :**
```
GET  /api/sandbox/packages          → liste des paquets disponibles + statut
POST /api/sandbox/build             → lance un build avec la liste de paquets
GET  /api/sandbox/build/{id}/status → statut du build
POST /api/sandbox/reset             → reset à l'image de base
```

### 2.5 Catalogue de paquets initial

Défini dans `app/sandbox/packages.json` :

```json
{
  "packages": {
    "nmap":     { "manager": "apt", "pkg": "nmap",     "version": "7.95-1" },
    "ffuf":     { "manager": "go",  "pkg": "github.com/ffuf/ffuf/v2@latest" },
    "nuclei":   { "manager": "go",  "pkg": "github.com/projectdiscovery/nuclei/v3@latest" },
    "amass":    { "manager": "go",  "pkg": "github.com/owasp-amass/amass/v4@latest" },
    "sqlmap":   { "manager": "pip", "pkg": "sqlmap" },
    "testssl":  { "manager": "apt", "pkg": "testssl.sh" },
    "gobuster": { "manager": "go",  "pkg": "github.com/OJ/gobuster/v3@latest" }
  }
}
```

**Sécurité des paquets :**
- Checksum SHA256 vérifié pour chaque paquet
- Mise à jour du catalogue par le mainteneur Elyria uniquement (signé GPG)
- Pas d'upload de paquets custom par les utilisateurs (limite le risque)

---

## Roadmap

| Phase | Contenu | Priorité |
|---|---|---|
| **1** | Ely — HUD UI + chat basique + contexte page + opacité réglable | P0 |
| **2** | Ely — Actions (function calling) + audit temps réel | P1 |
| **3** | Ely — Mémoire conversationnelle + préférences + Hub onglet Ely | P1 |
| **4** | Sandbox — Catalogue de paquets + build d'image | P2 |
| **5** | Sandbox — UI Hub + gestion des builds | P2 |
| **6** | Ely — Mode proactif (Ely suggère des actions) | P3 |

---

*Document généré le 2026-05-26 — Romain / Dreaft*
