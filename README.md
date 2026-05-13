# Elyria

**Le client HTTP conçu pour le test d'API — du test unitaire au pentest.**

---

## 🇫🇷 Pourquoi Elyria

**Workflows de requêtes** — La feature qui change la donne. Simulez des parcours client bout en bout, testez des vulnérabilités (identifiants prédictibles, BOLA) et automatisez des flux d'autorisation complexes. Là où les autres outils s'arrêtent à la requête, Elyria orchestre des scénarios.

**IA Copilot intégré** — Un agent IA qui crée vos collections à partir d'une simple description, exécute vos tests et analyse les résultats. Pas de configuration, pas d'add-on.

**Red Team / Pentest** — Scannez vos APIs avec le moteur OWASP API Top 10. Scanner déterministe + IA deep scan en 2 phases (exploration flash, analyse pro). ID lists pour tests BOLA, collections pour fuzzing. Rapports Markdown professionnels avec annexe requêtes/réponses.

**Blue Team / SSDLC** — Analyse security-by-design de vos specs OpenAPI. L'IA audite votre surface d'API et votre documentation pour produire un rapport d'exigences de sécurité couvrant authentification, autorisation, chiffrement, input validation, logging et durcissement infrastructure. Profils SSDLC multi-rounds avec master prompt et documentation personnalisables.

**Catcher** — Proxy intercepteur façon Burp Suite. Activez l'interception, envoyez vos requêtes via le proxy : elles sont mises en file d'attente pour inspection. Forward, Drop, ou Load dans le builder API. Historique complet avec réponses.

**Raw requests** — Forgez vos requêtes HTTP from scratch. Testez les edge cases et le comportement de votre stack face à des requêtes malformées.

**Collections collaboratives** — Vos équipes travaillent sur des collections partagées. Support multi-teams avec permissions et filtrage.

## Déploiement

### Méthode 1 — Git clone + Uvicorn (recommandé pour le dev)

```bash
git clone https://github.com/dreaft/elyria.git
cd elyria
pip install -r requirements.txt
cd app
python entrypoint.py
```

L'application démarre sur `https://127.0.0.1:8000`. Le hot-reload est activé — les modifications Python sont prises en compte sans redémarrage.

**Prérequis** : Python 3.12+, pip.

**Configuration** : créez un fichier `app/.env` :
```
host=127.0.0.1
port=8000
cert_path=cert.pem
key_path=key.pem
openai_api_key=sk-votre-cle-api
```

### Méthode 2 — Docker

```bash
git clone https://github.com/dreaft/elyria.git
cd elyria
docker compose up --build
```

L'application est accessible sur `http://localhost:8000`.

**Persistance des données** : la base SQLite et les fichiers sont stockés dans un volume Docker monté sur `./data` (le dossier `data/` à la racine du projet). Ce dossier survit aux `docker compose down` et aux rebuilds de l'image. Pour une sauvegarde :

```bash
cp -r data/ data-backup-$(date +%Y%m%d)/
```

Pour réinitialiser complètement les données :

```bash
docker compose down
rm -rf data/
docker compose up --build
```

**Connexion aux APIs locales (Ollama / LM Studio)** : dans le Hub > AI Agent, utilisez `http://host.docker.internal:11434` pour Ollama et `http://host.docker.internal:1234/v1` pour LM Studio. `host.docker.internal` résout vers l'IP de la machine hôte depuis le conteneur.

### Léger et rapide — taillé pour le local-first

- **SQLite** embarqué — zéro infra, un fichier
- **Tout en Python** — `pip install` et c'est parti
- **Moins de 100 Mo** de mémoire au repos
- **Hot-reload** des templates et du code en développement

Tourne sur un **MacBook M5 Pro 24 Go** avec des modèles locaux type **OpenAI/GPT-OSS-20B** via LM Studio sans aucun problème. L'inférence locale couvre à la fois les phases de scan (flash + pro) et l'assistant IA.

Testé également avec un **Raspberry Pi 4 (carte SD 64 Go)** servant l'application et utilisant les API standars des provider d'AI 

## Providers IA supportés

| Local | Remote |
|-------|--------|
| Ollama | Anthropic |
| LM Studio | OpenAI |
| **Multi-provider** | OpenAI API |

**Configuration multi-provider** — Hub > AI Agent. Définissez indépendamment vos modèles Flash (exploration rapide) et Pro (analyse profonde). Chaque slot peut utiliser un provider différent (ex: Flash sur Ollama local, Pro sur OpenAI API cloud). Support complet du function calling et du mode texte pour les modèles sans support natif des tools.

## Base de données

SQLite par défaut. MySQL et PostgreSQL sur la roadmap.

## Interopérabilité

Importez vos specs et collections existantes. Pas de lock-in.

- Specifications OpenAI → collections Elyria
- Specifications Arazzo → workflows de test
- Import Postman, Bruno, captures réseau

## SaaS (Bientôt)

Une offre hébergée en France arrive bientôt. Zéro déploiement, zéro maintenance.

Open source. Pour toujours.

---

## 🇬🇧 Why Elyria

**Request workflows** — The game changer. Simulate end-to-end user journeys, test for vulnerabilities (predictable identifiers, BOLA), and automate complex authorization flows. Where other tools stop at the request, Elyria orchestrates scenarios.

**Built-in AI Copilot** — An AI agent that creates collections from a description, runs your tests, and analyzes results. No setup, no add-on.

**Red Team / Pentest** — Scan your APIs with the OWASP API Top 10 engine. Deterministic scanner + AI deep scan in 2 phases (flash exploration, pro analysis). ID lists for BOLA testing, collections for fuzzing. Professional Markdown reports with request/response appendix.

**Blue Team / SSDLC** — Security-by-design analysis of your OpenAPI specs. The AI audits your API surface and documentation to produce a comprehensive security requirements report covering authentication, authorization, encryption, input validation, logging, and infrastructure hardening. Multi-round SSDLC profiles with customizable master prompts and documentation.

**Catcher** — Burp Suite-style proxy interceptor. Enable interception, route requests through the proxy: they get queued for inspection. Forward, Drop, or Load into the API builder. Full history with responses.

**Raw requests** — Forge HTTP requests from scratch. Test edge cases and how your stack handles malformed input.

**Collaborative collections** — Teams work on shared collections. Multi-team support with permissions and filtering.

## Deployment

### Method 1 — Git clone + Uvicorn (recommended for dev)

```bash
git clone https://github.com/dreaft/elyria.git
cd elyria
pip install -r requirements.txt
cd app
python entrypoint.py
```

The app starts on `https://127.0.0.1:8000`. Hot-reload is enabled — Python changes are picked up without restart.

**Requirements**: Python 3.12+, pip.

**Configuration**: create an `app/.env` file:
```
host=127.0.0.1
port=8000
cert_path=cert.pem
key_path=key.pem
openai_api_key=sk-your-api-key
```

### Method 2 — Docker

```bash
git clone https://github.com/dreaft/elyria.git
cd elyria
docker compose up --build
```

The app is available at `http://localhost:8000`.

**Data persistence**: the SQLite database and all files are stored in a Docker volume mounted at `./data` (the `data/` folder at the project root). This folder survives `docker compose down` and image rebuilds. To back up:

```bash
cp -r data/ data-backup-$(date +%Y%m%d)/
```

To fully reset all data:

```bash
docker compose down
rm -rf data/
docker compose up --build
```

**Connecting to local APIs (Ollama / LM Studio)**: in Hub > AI Agent, use `http://host.docker.internal:11434` for Ollama and `http://host.docker.internal:1234/v1` for LM Studio. `host.docker.internal` resolves to the host machine's IP from inside the container.

### Lightweight & fast — built for local-first

Elyria is designed to start **instantly** on any machine. No containers, no orchestrators, no heavy stack.

- **SQLite** embedded — zero infra, a single file
- **Pure Python** — `pip install` and you're running
- **Under 100 MB** memory at idle
- **Hot-reload** for templates and code in development

Runs smoothly on an **M5 Pro MacBook with 24 GB RAM** using local models like **OpenAI/GPT-OSS-20B** via LM Studio. Local inference covers both scan phases (flash + pro) and the AI assistant — no external GPU required.

Also tested with a **Raspberry Pi 4 (64 GB SD card)** hosting the server and calling regular AI provider api 

## Supported AI providers

| Local | Remote |
|-------|--------|
| Ollama | Anthropic |
| LM Studio | OpenAI |
| **Multi-provider** | OpenAI API |

**Multi-provider configuration** — Hub > AI Agent. Independently define your Flash (fast exploration) and Pro (deep analysis) models. Each slot can use a different provider (e.g., Flash on local Ollama, Pro on OpenAI API cloud). Full function calling and text mode support for models without native tool support.

## Database

SQLite by default. MySQL and PostgreSQL on the roadmap.

## Interoperability

Import your existing specs and collections. No lock-in.

- OpenAI specs → Elyria collections
- Arazzo specs → test workflows
- Import Postman, Bruno, network captures

## SaaS (coming Soon)

A France-hosted offering is coming soon. Zero deployment, zero maintenance.

Open source. Forever.

---

## TODO

- dockerfile
- test bout en bout
- connecteur pour DB externe (MySQL)
- stockage local des requêtes le temps du premier envoi
- reload à l'envoi
