# Elyria

**Le client HTTP conçu pour le test d'API — du test unitaire au pentest.**

---

## 🇫🇷 Pourquoi Elyria

**Workflows de requêtes** — La feature qui change la donne. Simulez des parcours client bout en bout, testez des vulnérabilités (identifiants prédictibles, BOLA) et automatisez des flux d'autorisation complexes. Là où les autres outils s'arrêtent à la requête, Elyria orchestre des scénarios.

**IA Copilot intégré** — Un agent IA qui crée vos collections à partir d'une simple description, exécute vos tests et analyse les résultats. Pas de configuration, pas d'add-on.

**Red Team / Pentest** — Scannez vos APIs avec le moteur OWASP API Top 10. Scanner déterministe + IA deep scan en 2 phases (exploration flash, analyse pro). ID lists pour tests BOLA, collections pour fuzzing. Rapports Markdown professionnels avec annexe requêtes/réponses.

**Raw requests** — Forgez vos requêtes HTTP from scratch. Testez les edge cases et le comportement de votre stack face à des requêtes malformées.

**Collections collaboratives** — Vos équipes travaillent sur des collections partagées. Support multi-teams avec permissions et filtrage.

## Déploiement

Local, on-prem, ou dans votre cloud. Un seul binaire, pas de dépendances externes.

### Léger et rapide — taillé pour le local-first

Elyria est conçu pour démarrer **instantanément** sur n'importe quelle machine. Pas de container, pas d'orchestrateur, pas de stack lourde.

- **SQLite** embarqué — zéro infra, un fichier
- **Tout en Python** — `pip install` et c'est parti
- **Moins de 100 Mo** de mémoire au repos
- **Hot-reload** des templates et du code en développement

Tourne sur un **MacBook M5 Pro 24 Go** avec des modèles locaux type **OpenAI/GPT-OSS-20B** via LM Studio sans aucun problème. L'inférence locale couvre à la fois les phases de scan (flash + pro) et l'assistant IA — pas besoin de carte graphique externe.

Testé également avec un **Raspberry Pi 4 (carte SD 64 Go)** servant de serveur d'inférence distant : le modèle tourne sur le Pi, Elyria s'y connecte via l'API OpenAI-compatible. Les performances restent fluides pour l'assistant IA et les phases de scan.

## Providers IA supportés

| Local | Remote |
|-------|--------|
| Ollama | Anthropic |
| LM Studio | OpenAI |
| **Multi-provider** | DeepSeek |

**Configuration multi-provider** — Hub > AI Agent. Définissez indépendamment vos modèles Flash (exploration rapide) et Pro (analyse profonde). Chaque slot peut utiliser un provider différent (ex: Flash sur Ollama local, Pro sur DeepSeek cloud). Support complet du function calling et du mode texte pour les modèles sans support natif des tools.

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

**Raw requests** — Forge HTTP requests from scratch. Test edge cases and how your stack handles malformed input.

**Collaborative collections** — Teams work on shared collections. Multi-team support with permissions and filtering.

## Deployment

Local, on-prem, or in your cloud. Single binary, no external dependencies.

### Lightweight & fast — built for local-first

Elyria is designed to start **instantly** on any machine. No containers, no orchestrators, no heavy stack.

- **SQLite** embedded — zero infra, a single file
- **Pure Python** — `pip install` and you're running
- **Under 100 MB** memory at idle
- **Hot-reload** for templates and code in development

Runs smoothly on an **M5 Pro MacBook with 24 GB RAM** using local models like **OpenAI/GPT-OSS-20B** via LM Studio. Local inference covers both scan phases (flash + pro) and the AI assistant — no external GPU required.

Also tested with a **Raspberry Pi 4 (64 GB SD card)** acting as a remote inference server: the model runs on the Pi, and Elyria connects via its OpenAI-compatible API. Performance stays smooth for the AI assistant and scan phases alike.

## Supported AI providers

| Local | Remote |
|-------|--------|
| Ollama | Anthropic |
| LM Studio | OpenAI |
| **Multi-provider** | DeepSeek |

**Multi-provider configuration** — Hub > AI Agent. Independently define your Flash (fast exploration) and Pro (deep analysis) models. Each slot can use a different provider (e.g., Flash on local Ollama, Pro on DeepSeek cloud). Full function calling and text mode support for models without native tool support.

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
- connecteur pour DB externe
- stockage local des requêtes le temps du premier envoi
- reload à l'envoi
