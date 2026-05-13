# Elyria

**Client HTTP pour le test d'API — du test fonctionnel au pentest.**

---

## Fonctionnalités

**Workflows** — Orchestrateur de requêtes avec moteur d'exécution local. Blocs Start, HTTP Request, Set Data, If/Else, For Loop, Assert, Delay. Sous-workflows, expressions `{{ctx.*}}`, exécution pas à pas. Import Arazzo → workflow exécutable.

**Red Team** — Scanner OWASP API Top 10 en 2 phases (déterministe + IA deep scan). Fuzzing paramètres, tests BOLA, analyse JWT, diff de réponses. Rapports Markdown avec annexe requêtes/réponses.

**Blue Team** — Analyse security-by-design de specs OpenAPI. L'IA audite auth, chiffrement, input validation, logging. Rapports SSDLC multi-rounds personnalisables.

**IA Copilot** — Agent IA intégré (OpenAI, Anthropic, Ollama, LM Studio, DeepSeek). Création de collections, exécution de tests, analyse de résultats. Function calling natif.

**Catcher** — Proxy intercepteur HTTP. Forward, Drop, Load dans le builder. Historique avec réponses. Polling variable (500ms–10s).

**Collections** — Arborescence dossiers/requêtes. Multi-teams avec permissions. Import OpenAPI, Postman. Export curl.

**Éditeur JSON** — Auto-pairing `{}[]""`, validation en temps réel, formatage (Ctrl+Shift+F) sur tous les champs JSON.

**Auth** — Login/password (SHA-512 → SHA3-512 + sel, JWT HS512 éphémère). Connecteur OIDC modulaire (Google, Azure, Keycloak…) avec découverte automatique et provisioning JIT.

---

## Déploiement

```bash
git clone https://github.com/dreaft/elyria.git
cd elyria
pip install -r requirements.txt
cd app && python entrypoint.py
```

Démarre sur `https://127.0.0.1:8000`. Hot-reload activé.

**Docker** : `docker compose up --build` → `http://localhost:8000`. Volume `./data` pour la persistence.

**Prérequis** : Python 3.12+.

---

## Configuration

Tout en base de données — pas de `.env`. Interface **Hub > Admin Config** ou API :

```json
{
  "settings": {
    "app.host": "127.0.0.1",     "app.port": "8000",
    "catcher.port": "6767",       "proxy.xor_key": "elyria-proxy-k",
    "db.backend": "sqlite",       "db.sqlite.path": "database.db"
  },
  "fqdn_whitelist": [
    {"category": "fetch", "pattern": "localhost"},
    {"category": "proxy", "pattern": "localhost"},
    {"category": "llm",   "pattern": "api.openai.com"}
  ],
  "provider_toggles": [
    {"provider_type": "openai", "enabled": 1},
    {"provider_type": "ollama", "enabled": 1}
  ],
  "api_keys": [{"key_name": "openai_api_key", "key_value": "***"}]
}
```

### SSO OIDC

```json
{
  "oidc.enabled": "1",
  "oidc.issuer": "https://accounts.google.com",
  "oidc.client_id": "…",
  "oidc.client_secret": "…",
  "oidc.button_label": "Google"
}
```

Test local : `python tools/oidc_test_provider.py` → user `alice` / `password123`.

---

## Architecture

- **SQLite** embarqué (PostgreSQL supporté)
- **Python** pur — moins de 100 Mo RAM au repos
- **JWT HS512** éphémères (clés en DB, durée 1h, rotation par session)
- **Static files** servis par FastAPI/Starlette

---

## Providers IA

| Local | Remote |
|-------|--------|
| Ollama | OpenAI |
| LM Studio | Anthropic |
| | DeepSeek |

Multi-provider : chaque slot (Flash/Pro) peut utiliser un provider différent.

---

## Mon setup perso

Elyria tourne sur un **Raspberry Pi 4 (carte SD 64 Go)** derrière ma box.

- **LLM rapide / tests** → provider externe (OpenAI, Anthropic, DeepSeek)
- **LLM local / hors-ligne** → **GPT-OSS-20B** via LM Studio sur mon poste principal — le Pi appelle `http://<ip-du-poste>:1234/v1`

Le Pi gère le serveur, la DB, le proxy Catcher, et les workflows. L'inférence locale reste sur la machine principale qui a le GPU. Zero lag en usage solo.

---

## Interopérabilité

- **OpenAPI** → collections
- **Arazzo** → workflows
- **Postman, Bruno** → import
