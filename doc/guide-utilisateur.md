# Guide Utilisateur — Elyria

**Client HTTP conçu pour le test d'API — du test unitaire au pentest.**

---

## Table des matières

1. [Présentation](#1--présentation)
2. [Démarrage rapide](#2--démarrage-rapide)
3. [L'interface principale](#3--linterface-principale)
4. [Les Collections](#4--les-collections)
5. [L'Historique](#5--lhistorique)
6. [Le Catcher (proxy intercepteur)](#6--le-catcher-proxy-intercepteur)
7. [L'Assistant IA](#7--lassistant-ia)
8. [Import de documents (OpenAPI / Arazzo)](#8--import-de-documents-openapi--arazzo)
9. [Requêtes Raw HTTP](#9--requêtes-raw-http)
10. [Le Workflow Builder](#10--le-workflow-builder)
11. [Le Hub](#11--le-hub)
12. [Red Team / Pentest](#12--red-team--pentest)
13. [Blue Team / SSDLC](#13--blue-team--ssdlc)
14. [Raccourcis clavier](#14--raccourcis-clavier)

---

## 1. Présentation

Elyria est un client API complet qui combine :

- **Requêtes structurées** — GET, POST, PUT, PATCH, DELETE avec headers, query params et body
- **Requêtes Raw HTTP** — forgez vos requêtes HTTP from scratch (socket TCP)
- **Collections** — organisez vos requêtes en dossiers hiérarchiques, partagées en équipe
- **Workflow Builder** — automatisez des scénarios multi-requêtes avec logique conditionnelle, boucles et tests de sécurité
- **Catcher** — proxy intercepteur façon Burp Suite pour inspecter les requêtes de votre navigateur ou Postman
- **Assistant IA intégré** — créez des collections, exécutez des tests et analysez les résultats par chat
- **Red Team / Pentest** — scannez vos APIs avec le moteur OWASP API Top 10 + AI deep scan
- **Blue Team / SSDLC** — analyse security-by-design de vos specs pour produire des rapports d'exigences de sécurité
- **Import OpenAPI / Arazzo** — importez vos specs pour générer automatiquement des collections

---

## 2. Démarrage rapide

### Lancement

```bash
cd /chemin/vers/elyria
uvicorn app.entrypoint:app --host 127.0.0.1 --port 8000
```

Ouvrez `https://127.0.0.1:8000` dans votre navigateur.

### Premier lancement

1. Cliquez sur l'onglet **S'inscrire**
2. Choisissez un nom d'utilisateur et un mot de passe
3. Connectez-vous avec ces identifiants

Vous arrivez sur l'interface principale.

---

## 3. L'interface principale

L'écran est divisé en plusieurs zones :

| Zone | Description |
|------|-------------|
| **Barre latérale gauche** | Collections (dossiers + requêtes sauvegardées) |
| **Zone centrale** | Builder de requête (structuré ou raw) + panneau de réponse |
| **Panneaux latéraux droits** | Historique, Catcher, Assistant IA, JWT Decoder — s'ouvrent via les boutons du header |

### 3.1. La barre d'URL et l'envoi de requêtes

1. Sélectionnez la **méthode HTTP** (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
2. Saisissez l'**URL** complète (ex: `https://api.example.com/v1/users`)
3. Cliquez sur **Envoyer** ou appuyez sur `Ctrl+Enter`

Les query parameters sont automatiquement extraits de l'URL et affichés dans l'onglet **Params**.

### 3.2. Le builder structuré

L'onglet **Structurée** propose 3 sous-onglets :

**Params** — Query parameters sous forme de paires clé/valeur.
- Activez/désactivez un paramètre avec la coche
- Ajoutez avec le bouton **+ Ajouter un paramètre**
- Le bouton **Depuis l'URL** re-parse l'URL pour extraire les paramètres
- Toute modification est synchronisée avec l'URL en temps réel

**Headers** — En-têtes HTTP sous forme de paires clé/valeur.
- Le header `Content-Type` est géré automatiquement selon le type de body sélectionné
- Ajoutez des headers personnalisés avec le bouton **+ Ajouter un header**

**Body** — Corps de la requête.
- Sélectionnez le **Content-Type** : JSON, Text, XML, Form URL Encoded
- Saisissez le contenu dans l'éditeur

### 3.3. La réponse

Après envoi, le panneau de réponse affiche :

- **Code HTTP** avec badge coloré (vert 2xx, bleu 3xx, orange 4xx, rouge 5xx)
- **Temps de réponse** en millisecondes
- **Body** — formaté automatiquement si JSON
- **Headers** de réponse

Le panneau est **redimensionnable** — tirez la poignée entre le builder et la réponse.

---

## 4. Les Collections

Les collections permettent d'organiser vos requêtes sauvegardées en dossiers.

### Créer une collection

1. Dans la barre latérale, onglet **Collections**
2. Cliquez sur le bouton **+ dossier** (icône violette)
3. Donnez un nom au dossier

### Créer une requête sauvegardée

1. Survolez un dossier, cliquez sur le **+** qui apparaît à droite
2. Donnez un nom à la requête
3. La requête apparaît dans le dossier — cliquez dessus pour la charger dans le builder

### Actions sur les collections

| Action | Comment |
|--------|---------|
| **Charger une requête** | Clic simple sur la requête |
| **Renommer un dossier ou une requête** | Double-clic |
| **Supprimer une requête** | Survolez, cliquez sur l'icône poubelle |
| **Supprimer un dossier** | Survolez, cliquez sur l'icône poubelle (supprime récursivement le contenu) |
| **Rechercher** | Utilisez la barre de recherche en haut de la section Collections |

### Sauvegarde automatique

Quand vous modifiez une requête chargée depuis une collection, elle est automatiquement sauvegardée :
- À chaque envoi de requête
- Quand vous changez de requête active
- Quand vous quittez la page

---

## 5. L'Historique

L'onglet **Historique** (dans la barre latérale) conserve la liste des requêtes envoyées.

- Les 50 dernières requêtes sont chargées automatiquement
- Cliquez sur une entrée pour recharger la requête et sa réponse dans le builder
- La barre de recherche filtre par URL, méthode ou ID

---

## 6. Le Catcher (proxy intercepteur)

Le Catcher est un proxy HTTP forward inspiré de Burp Suite qui intercepte les requêtes de votre navigateur ou de Postman pour inspection.

### Activation

1. Cliquez sur le bouton **Catcher** (rose) dans la barre du haut
2. Dans le panneau, cliquez sur **Intercept OFF** pour activer l'interception → le bouton devient **Intercept ON**
3. Un badge `Proxy: localhost:8080` apparaît — c'est l'adresse du proxy

### Configuration navigateur / Postman

- **Navigateur** : paramètres réseau → proxy HTTP → `localhost:8080`
- **Postman** : Settings → Proxy → `localhost:8080`
- **Ligne de commande** : `curl -x http://localhost:8080 https://api.example.com`

### File d'attente

Quand **Intercept ON** est actif, les requêtes sont mises en file d'attente au lieu d'être envoyées directement. La première requête s'affiche en mode expanded :

- **Méthode** : modifiable via le dropdown
- **URL** : champ éditable
- **Headers** : textarea éditable
- **Body** : textarea éditable

Les champs sont éditables en direct — les modifications sont sauvegardées automatiquement.

### Actions

| Action | Description |
|--------|-------------|
| **Forward** | Exécute la requête vers la cible et renvoie la réponse au client |
| **Drop** | Rejette la requête, le client reçoit une erreur 410 Gone |
| **Load** | Charge la requête dans le builder API Elyria |

### Historique

Toutes les requêtes forwardées et droppées sont enregistrées dans l'historique (persisté en base). Chaque entrée affiche :
- Méthode, code statut HTTP, URL
- Bouton **Load** pour charger dans le builder API
- Clic sur une ligne → détail du body de réponse

L'historique est cloisonné par utilisateur.

### Port du proxy

Configurable via la variable d'environnement `CATCHER_PORT` (défaut : 8080).

---

## 7. L'Assistant IA

L'assistant IA peut créer des collections, envoyer des requêtes et analyser les résultats.

### Ouvrir l'assistant

- Bouton **Assistant IA** dans la barre du haut, ou
- Raccourci `Ctrl+I`

### Utilisation

1. Saisissez votre message dans le champ en bas du panneau
2. Appuyez sur `Entrée` pour envoyer

Exemples de prompts :
- *"Crée une collection pour tester l'API de paiement Stripe"*
- *"Envoie une requête GET à https://api.example.com/users et vérifie que le statut est 200"*
- *"Analyse la dernière réponse et dis-moi si le token JWT est valide"*

L'assistant a accès à vos collections, peut créer des dossiers, des requêtes, les exécuter et lire l'historique.

---

## 8. Import de documents (OpenAPI / Arazzo)

Importez vos spécifications d'API pour générer automatiquement des collections.

### Formats supportés

- **OpenAPI 3.x** et **Swagger 2.x** (`.json`, `.yaml`, `.yml`)
- **Arazzo 1.0** — workflows de test

### Comment importer

1. Cliquez sur le bouton **Documents** dans la barre du haut
2. Glissez-déposez un fichier dans la zone, ou cliquez pour parcourir
3. Cliquez sur **Importer**

### Résultat d'un import OpenAPI

- Un dossier racine est créé avec le nom de l'API
- Chaque opération (endpoint) devient une requête sauvegardée dans un sous-dossier par tag
- Les paramètres, headers et body d'exemple sont pré-remplis

### Résultat d'un import Arazzo

- Les workflows sont importés comme scénarios exécutables
- Les références entre étapes (`$steps.x.outputs.y`) sont traduites en syntaxe `{{ctx.xxx}}`

---

## 9. Requêtes Raw HTTP

Le mode Raw HTTP permet d'envoyer des requêtes forgées manuellement pour tester des edge cases.

### Accès

Cliquez sur l'onglet **Raw HTTP** dans le builder.

### Format

```
METHODE /chemin HTTP/1.1
Host: exemple.com
Header: valeur

Corps de la requête
```

Exemple :
```
POST /api/v1/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...

{"name": "Jean", "email": "jean@example.com"}
```

### Particularités

- La requête est envoyée via un **socket TCP brut**, sans modification
- Le parsing de la première ligne extrait automatiquement la méthode et le chemin
- Après envoi, les composants parsés remplissent automatiquement l'onglet Structurée

---

## 10. Le Workflow Builder

Le Workflow Builder permet de créer des scénarios de test automatisés par glisser-déposer.

### Accès

Depuis l'interface principale, cliquez sur le bouton **Workflows** dans la barre du haut.

### Interface

| Zone | Description |
|------|-------------|
| **Palette gauche** | Briques disponibles, classées par catégorie + collections sauvegardées |
| **Canvas central** | Zone de travail où vous placez et connectez les briques |
| **Panneau droit** | Configuration de la brique sélectionnée + logs d'exécution |

### 10.1. Les briques

Glissez-déposez les briques depuis la palette vers le canvas. Connectez-les en tirant depuis le port de sortie (rond en bas) vers le port d'entrée (rond en haut) d'une autre brique.

#### Contrôle de flux

| Brique | Rôle | Ports de sortie |
|--------|------|-----------------|
| **Start** | Point d'entrée obligatoire du workflow | `out` |
| **If / Else** | Branchement conditionnel (expression JavaScript) | `TRUE`, `FALSE` |
| **For Loop** | Boucle sur N itérations. Variable `ctx.i` = index courant. | `BODY` (chaque itération — branchez sur une requête et faites-la revenir au `in`), `DONE` (après la boucle) |
| **Delay** | Pause en millisecondes | `out` |

#### Données

| Brique | Rôle |
|--------|------|
| **Set Data** | Définit des variables dans le contexte du workflow |

La brique **Set Data** possède deux modes :
- **Sans nom de dataset** : les variables sont injectées directement dans `ctx` → accessibles via `{{ctx.maVariable}}`
- **Avec nom de dataset** (champ `Nom du dataset`) : les variables sont regroupées dans `ctx.nomDuDataset` → accessibles via `{{ctx.nomDuDataset.maVariable}}`

#### Requêtes

| Brique | Rôle |
|--------|------|
| **HTTP Request** | Envoie une requête HTTP structurée (méthode, URL, headers, body) |
| **Raw Request** | Envoie une requête HTTP brute via socket TCP |

Chaque brique de requête possède un champ **Sauver réponse dans** qui détermine sous quel nom la réponse est stockée dans le contexte (par défaut : `response`).

#### Assertions

| Brique | Rôle |
|--------|------|
| **Assert** | Vérifie une condition — le workflow échoue si la condition est fausse |

Le panneau de config du bloc Assert propose des snippets d'exemples prêts à l'emploi.

#### Red Team / Sécurité

| Brique | Rôle | Ports de sortie |
|--------|------|-----------------|
| **Fuzz Requête** | Boucle de fuzzing sur une wordlist | `BODY` (chaque itération), `DONE` (après la boucle) |
| **BOLA Test** | Test IDOR — substitue `{{ctx.id_list}}` dans l'URL | `VULN` (si 200), `SAFE` (sinon) |
| **JWT Analyze** | Analyse un token JWT : décode le header/payload, vérifie l'expiration | `out` |
| **Response Diff** | Compare deux réponses HTTP (status, headers, body) | `out_diff` (différentes), `out_same` (identiques) |
| **Extract & Replay** | Extrait une valeur d'une réponse et la rejoue dans une nouvelle requête | `out` |

**Fuzz Requête** — Boucle de fuzzing
- Champ **Wordlist** : une valeur par ligne. À chaque itération, `ctx.fuzz` contient la valeur courante.
- Sortie `BODY` : reliez-la à une requête HTTP. Dans la requête, utilisez `{{ctx.fuzz}}` dans l'URL, les headers ou le body.
- La sortie de la requête DOIT revenir sur l'entrée `in` du Fuzz (boucle).
- Sortie `DONE` : une fois la wordlist épuisée. `ctx[saveTo]` contient `{ iterations: N, results: [...] }`.
- Exemple : wordlist = `admin\nuser\ntest`, URL = `https://api.example.com/users/{{ctx.fuzz}}`

**BOLA Test** — Test IDOR (Insecure Direct Object Reference)
- Champ **ID List (JSON)** : mapping d'IDs à substituer.
- Placez `{{id}}` dans l'URL de la requête connectée en amont. La brique substitue chaque ID et vérifie si la ressource est accessible (HTTP 200).
- Sortie `VULN` si une ressource d'un autre utilisateur est accessible.
- Sortie `SAFE` si toutes les requêtes retournent 403/404.

**JWT Analyze** — Décodeur de JWT
- Décode le header et le payload d'un token JWT présent dans `ctx.jwt` ou `ctx.response.body`.
- Vérifie l'expiration (`exp`) et la date d'émission (`iat`).
- Stocke les résultats dans `ctx.jwt_analysis` : `{ header, payload, expired, issued_at, expires_at }`.

**Response Diff** — Comparaison de réponses
- Compare les deux dernières réponses stockées dans `ctx`. Détecte les différences de status, headers, et body.
- Utile pour comparer la réponse avant/après un changement (ex: requête admin vs user normal).
- Sortie `out_diff` si les réponses diffèrent, `out_same` si elles sont identiques.

**Extract & Replay** — Extraction et réexécution
- Extrait une valeur d'une réponse avec une expression régulière et la réinjecte dans une nouvelle requête.
- Utile pour extraire un token CSRF, un ID de ressource, ou un token JWT et le réutiliser.
- Stocke la valeur extraite dans `ctx.extracted_value`.

### 10.2. Le contexte (ctx)

Toutes les briques partagent un objet `ctx` qui circule à travers le workflow.

**Syntaxe de template** : `{{ctx.chemin.vers.valeur}}`

| Expression | Description |
|------------|-------------|
| `{{ctx.response.status_code}}` | Code HTTP de la dernière réponse |
| `{{ctx.response.body}}` | Corps de la dernière réponse |
| `{{ctx.response.headers["Content-Type"]}}` | Header spécifique de la réponse |
| `{{ctx.response.url}}` | URL de la réponse |
| `{{ctx.nomDataset.champ}}` | Champ d'un dataset nommé (Set Data avec nom) |
| `{{ctx.maVariable}}` | Variable racine définie par Set Data |

**Variables injectées par les briques Red Team :**

| Variable | Injectée par | Description |
|----------|-------------|-------------|
| `{{ctx.fuzz}}` | Fuzz Requête | Valeur courante de la wordlist (une par itération) |
| `{{ctx.fuzzResults}}` | Fuzz Requête | Résultats complets après la boucle : `{ iterations, results }` |
| `{{ctx.id_list}}` | BOLA Test | Un ID de la liste à chaque itération (substitué dans `{{id}}`) |
| `{{ctx.jwt_analysis}}` | JWT Analyze | Résultat du décodage : `{ header, payload, expired }` |
| `{{ctx.extracted_value}}` | Extract & Replay | Valeur extraite par la regex |
| `{{ctx._lastResponse}}` | Toute requête | Dernière réponse complète (interne) |

**Snippets ctx** : dans le panneau de configuration des briques HTTP Request, Raw Request, Set Data et If/Else, une section *ctx — Contexte du workflow* affiche des snippets cliquables qui s'insèrent à la position du curseur dans le champ actif.

### 10.3. Exécution

1. Placez un bloc **Start** sur le canvas
2. Ajoutez vos blocs et connectez-les dans l'ordre souhaité
3. Cliquez sur **Exécuter** (bouton vert en haut)
4. Les logs d'exécution apparaissent dans l'onglet **Logs** du panneau droit

Pendant l'exécution, les briques changent de couleur :
- **Jaune** = en cours
- **Vert** = succès
- **Rouge** = erreur

Vous pouvez **arrêter** l'exécution à tout moment avec le bouton Stop.

### Actions sur le canvas

| Action | Comment |
|--------|---------|
| **Sélectionner une brique** | Clic sur la brique |
| **Déplacer une brique** | Glisser-déposer |
| **Supprimer une brique** | Clic sur le × (apparaît au survol) ou touche `Suppr` |
| **Créer une connexion** | Tirer depuis un port de sortie vers un port d'entrée |
| **Sélectionner une connexion** | Clic sur le lien |
| **Supprimer une connexion** | Sélectionner puis `Suppr` |
| **Zoom** | Boutons +/− ou molette |
| **Tout effacer** | Bouton Clear |

---

## 11. Le Hub

Le Hub (accessible via l'icône utilisateur dans le header) centralise la gestion de votre compte et de vos ressources.

### 11.1. Teams

- **Créer une team** : bouton "Créer", donnez un nom. Vous êtes automatiquement membre.
- **Rejoindre une team** : entrez un Team ID et cliquez "Rejoindre". Une demande est envoyée aux membres.
- **Valider une demande** : dans la team, développez pour voir les demandes en attente. La validation nécessite 80% d'approbation des membres.
- **Suivre/Ne plus suivre** : les teams suivies apparaissent dans vos filtres de collections, workflows et pentest.
- **Copier l'ID** : cliquez sur l'icône de copie à côté du Team ID.

### 11.2. Proxy

Configurez vos proxies HTTP pour le forwarding des requêtes.

- **Ajouter** : nom + URL (ex: `http://proxy:8080`).
- **Définir comme favori** : le proxy favori est injecté dans vos requêtes lorsqu'il est activé.
- **Supprimer** : icône X sur chaque proxy.

### 11.3. Agent IA

Gérez vos providers LLM pour le chat IA et le pentest AI.

- **Deux slots indépendants** :
  - **Flash Model** : utilisé pour l'exploration rapide (batch de requêtes parallèles)
  - **Pro Model** : utilisé pour l'analyse profonde et le chat IA principal
- **Chaque slot peut utiliser un provider différent** (ex: Flash sur Ollama local, Pro sur OpenAI API cloud)
- **Providers supportés** : OpenAI API, LM Studio (local), Ollama (local)
- **Lister les modèles** : après avoir configuré l'URL, cliquez "Lister" pour voir les modèles disponibles
- **Définir par défaut** : un seul provider par slot peut être le défaut
- **Sécurité** : les clés API ne sont jamais renvoyées au frontend (masquées `****`). Vous pouvez les remplacer mais pas les lire.

## 12. Red Team / Pentest

Le module Red Team (accessible via le header ou `/pentest`) permet de scanner vos APIs avec le moteur OWASP API Top 10.

### 12.1. Profils de scan

- **Créer un profil** : bouton "+" dans la sidebar "Scan Profiles"
- **Configurer** : URL cible, authentification (Bearer, headers), OpenAPI spec, ID list (pour BOLA), collection existante, équipe
- **Onglet IA** : réglez le nombre de rounds d'exploration (1-50, défaut 15) et d'analyse (1-25, défaut 5)
- **Modifier** : icône crayon sur le profil
- **Supprimer** : icône X sur le profil

### 12.2. Campagnes

- **Lancer un scan** : sélectionnez un profil, cliquez "Lancer le scan". Une campagne est créée.
- **Progression** : barre de progression avec dégradé de couleurs (rouge → orange → violet)
- **Arrêter** : bouton Stop pendant le scan
- **Supprimer** : icône X sur chaque campagne (purge complète : findings, logs, campagne)
- **Refresh** : bouton Refresh dans le header ou automatique toutes les 60s

### 12.3. Findings et Logs

- **Dashboard** : compteurs par sévérité (Critical, High, Medium, Low, Info)
- **Findings** : chaque vulnérabilité affiche titre, sévérité, description, remédiation, CWE/CVSS
- **Détails requête/réponse** : cliquez sur un finding pour voir les onglets Requête/Réponse (URL, headers, body)
- **Analyse IA** : les findings de l'agent IA incluent une courte analyse en 3 phrases
- **Logs** : historique de toutes les requêtes envoyées pendant le scan, avec détails requête/réponse au clic
- **Filtre par sévérité** : dropdown dans l'onglet Findings
- **Rafraîchir** : boutons Refresh dans chaque onglet

### 12.4. Rapport

- **Rapport Markdown** : accessible dans l'onglet Rapport
- **Navigation rapide** : table des matières sticky avec les sections principales
- **Téléchargement** : bouton Rapport dans le header pour exporter en .md
- **Annexes** : détails requête/réponse pour chaque finding

## 13. Blue Team / SSDLC

Le module Blue Team (accessible via le header ou `/blueteam`) analyse vos spécifications API avec un agent IA expert en security-by-design pour produire un rapport d'exigences de sécurité.

### 13.1. Profils SSDLC

- **Créer un profil** : bouton "+" dans la sidebar "Profils SSDLC"
- **Configurer** : URL cible, Master Prompt (instructions pour l'agent), Documentation (contexte métier), spécification OpenAPI, collection
- **Filtre par équipe** : dropdown dans la sidebar pour filtrer les profils par équipe
- **Modifier** : bouton crayon dans le header du profil
- **Supprimer** : bouton poubelle dans le header du profil

### 13.2. Analyse

- **Lancer l'analyse** : sélectionnez un profil, cliquez "Lancer l'analyse"
- **Progression** : barre de progression + messages de statut en temps réel (polling adaptatif)
- **Arrêter** : bouton Stop pendant l'analyse
- **Modèle Pro** : badge affichant le modèle IA utilisé

### 13.3. Rapport

L'agent IA analyse votre spec à travers 8 domaines de sécurité :
1. Authentification & Autorisation
2. Protection des données (transit, stockage, traitement)
3. Input validation & injection
4. Architecture API (rate limiting, versioning, CORS)
5. Gestion d'erreurs & logging
6. Logique métier & workflows
7. Supply chain & dépendances
8. Conformité & gouvernance (GDPR, PCI-DSS, SOC2)

Le rapport inclut :
- Résumé exécutif avec score de maturité sécurité
- Analyse par domaine (forces, faiblesses, risques)
- Tableau d'exigences de sécurité avec priorités et références OWASP/NIST
- Plan d'action priorisé (immédiat, court terme, moyen terme)
- Diagrammes Mermaid pour illustrer les flux et l'architecture

### 13.4. Import depuis Red Team

Vous pouvez importer une campagne Red Team pour générer un plan de remédiation :
- Depuis Red Team, bouton "Envoyer vers Blue Team" sur une campagne terminée
- Ou depuis Blue Team, utilisez l'API `POST /api/blueteam/import-from-pentest`

---

## 14. Raccourcis clavier

| Raccourci | Action |
|-----------|--------|
| `Ctrl+Enter` | Envoyer la requête courante |
| `Ctrl+I` | Ouvrir/fermer l'assistant IA |
| `Suppr` | Supprimer la brique sélectionnée (workflow) |
| `Suppr` | Supprimer la connexion sélectionnée (workflow) |
| `Échap` | Fermer les modales |
| `Entrée` | Valider dans les modales |
