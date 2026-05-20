# Elyria

**Client HTTP pour le test d'API — du test fonctionnel au pentest.**

---

## Fonctionnalités

**Workflows** — Orchestrateur de requêtes avec moteur d'exécution local. Blocs Start, HTTP Request, Set Data, If/Else, For Loop, Assert, Delay. Sous-workflows, expressions `{{ctx.*}}`, exécution pas à pas. Import Arazzo → workflow exécutable.

**Red Team** — Scanner OWASP API Top 10 en 2 phases (déterministe + IA deep scan). Fuzzing paramètres, tests BOLA, analyse JWT, diff de réponses. Rapports Markdown avec annexe requêtes/réponses.

**Blue Team** — Analyse security-by-design de specs OpenAPI. L'IA audite auth, chiffrement, input validation, logging. Rapports SSDLC multi-rounds personnalisables.

**IA Copilot** — Agent IA intégré (OpenAI, Anthropic, Ollama, LM Studio, DeepSeek). Création de collections, exécution de tests, analyse de résultats. Function calling natif.

**Collections** — Arborescence dossiers/requêtes. Multi-teams avec permissions. Import OpenAPI, Postman. Export curl.

**Éditeur JSON** — Auto-pairing `{}[]""`, validation en temps réel, formatage (Ctrl+Shift+F) sur tous les champs JSON.

**Auth** — Login/email, Argon2id, JWT HS512 éphémère, 12 mots de récupération BIP39. Envelope encryption (AES-256-GCM) — master key + DEK par collection. Zero-knowledge at rest : DB dump = données illisibles. Connecteur OIDC modulaire (Google, Azure, Keycloak…).

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

Le fichier **`elyria.cfg`** à la racine remplace le `.env`. C'est un INI standard :

```ini
[server]     host, port, reload
[ssl]        cert_path, key_path, verify
[database]   backend (sqlite/postgres), pg_*
[logging]    level (DEBUG/INFO/WARNING/ERROR), dir
[oidc]       enabled, issuer, client_id, client_secret
[security]   server_wrap_key, blocked_hosts
```

Override par variable d'environnement : `ELYRIA_SERVER_PORT=9000` → `[server].port`.

### SSO OIDC

Dans `elyria.cfg`, section `[oidc]` :
```ini
enabled = 1
issuer = https://accounts.google.com
client_id = …
client_secret = …
button_label = Google
```

Test local : `python tools/oidc_test_provider.py` → user `alice` / `password123`.

---

## Architecture

- **SQLite** embarqué (PostgreSQL supporté)
- **Python** pur — moins de 100 Mo RAM au repos
- **Argon2id** + envelope encryption (AES-256-GCM) — master key, DEK, TVK
- **JWT HS512** éphémères (clés dérivées HMAC, durée 1h, rotation par session)
- **Static files** servis par FastAPI/Starlette
- **153 tests automatisés** — architecture crypto, OWASP Top 10, garde-fous

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

Le Pi gère le serveur, la DB, et les workflows. L'inférence locale reste sur la machine principale qui a le GPU. Zero lag en usage solo.

---

## Interopérabilité

- **OpenAPI** → collections
- **Arazzo** → workflows
- **Postman, Bruno** → import
