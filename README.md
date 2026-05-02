# Elyria

**Le client HTTP conçu pour le test d'API — du test unitaire au pentest.**

---

## Pourquoi Elyria

**Workflows de requêtes** — La feature qui change la donne. Simulez des parcours client bout en bout, testez des vulnérabilités (identifiants prédictibles, BOLA) et automatisez des flux d'autorisation complexes. Là où les autres outils s'arrêtent à la requête, Elyria orchestre des scénarios.

**IA Copilot intégré** — Un agent IA qui crée vos collections à partir d'une simple description, exécute vos tests et analyse les résultats. Pas de configuration, pas d'add-on.

**Raw requests** — Forgez vos requêtes HTTP from scratch. Testez les edge cases et le comportement de votre stack face à des requêtes malformées.

**Collections collaboratives** — Vos équipes travaillent sur des collections partagées. Versioning Git sur la roadmap.

## Déploiement

Local, on-prem, ou dans votre cloud. Un seul binaire, pas de dépendances externes.

## Providers IA supportés

| Local | Remote |
|-------|--------|
| Ollama | Anthropic |
| LM Studio (en cours) | OpenAI |

## Base de données

SQLite par défaut. MySQL et PostgreSQL sur la roadmap.

## Interopérabilité

Importez vos specs et collections existantes. Pas de lock-in.

- Specifications OpenAI → collections Elyria
- Specifications Arazzo → workflows de test
- Import Postman, Bruno, captures réseau

## SaaS (Bientot)

Une offre hébergée en France arrive bientôt. Zéro déploiement, zéro maintenance.

Open source. Pour toujours.

---

## Why Elyria

**Request workflows** — The game changer. Simulate end-to-end user journeys, test for vulnerabilities (predictable identifiers, BOLA), and automate complex authorization flows. Where other tools stop at the request, Elyria orchestrates scenarios.

**Built-in AI Copilot** — An AI agent that creates collections from a description, runs your tests, and analyzes results. No setup, no add-on.

**Raw requests** — Forge HTTP requests from scratch. Test edge cases and how your stack handles malformed input.

**Collaborative collections** — Teams work on shared collections. Git versioning on the roadmap.

## Deployment

Local, on-prem, or in your cloud. Single binary, no external dependencies.

## Supported AI providers

| Local | Remote |
|-------|--------|
| Ollama | Anthropic |
| LM Studio (in progress) | OpenAI |

## Database

SQLite by default. MySQL and PostgreSQL on the roadmap.

## Interoperability

Import your existing specs and collections. No lock-in.

- OpenAI specs → Elyria collections
- Arazzo specs → test workflows
- Import Postman, Bruno, network captures

## SaaS (comming Soon)

A France-hosted offering is coming soon. Zero deployment, zero maintenance.

Open source. Forever.

---

## TODO

- dockerfile
- parser pour raw HTTP
- test bout en bout
- connecteur pour DB externe
- stockage local des requêtes le temps du premier envoi
- reload à l'envoi
