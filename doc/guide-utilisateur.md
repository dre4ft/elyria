# Guide Utilisateur — Elyria

**Client HTTP conçu pour le test d'API — du test unitaire au pentest.**

---

## 1. Présentation

Elyria est un client API complet qui combine :

- **Requêtes structurées** — GET, POST, PUT, PATCH, DELETE avec headers, query params et body
- **Requêtes Raw HTTP** — forgez vos requêtes HTTP from scratch (socket TCP)
- **Collections** — organisez vos requêtes en dossiers hiérarchiques, partagées en équipe
- **Workflow Builder** — automatisez des scénarios multi-requêtes avec logique conditionnelle, boucles et tests de sécurité
- **Assistant IA intégré** — créez des collections, exécutez des tests et analysez les résultats par chat
- **Red Team / Pentest** — scannez vos APIs avec le moteur OWASP API Top 10 + AI deep scan
- **Blue Team / SSDLC** — analyse security-by-design de vos specs pour produire des rapports d'exigences de sécurité
- **Grey Team / OSINT** — reconnaissance passive de domaine (DNS, WHOIS, SSL, sous-domaines, technologies, emails, GitHub, Google)
- **Purple Team / IAST** — analyse de code source (SAST + SCA) couplée à des tests dynamiques (IAST), avec scan CVE, CWE, mauvaises pratiques et deep code review IA
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
| **Panneaux latéraux droits** | Historique, ELY Copilot, JWT Decoder — s'ouvrent via les boutons du header |

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

### 3.4. Contexte utilisateur (`{{ctx.xxx}}`)

Le **contexte utilisateur** est un dictionnaire JSON persistant qui permet de stocker des données extraites des réponses HTTP et de les réutiliser dans vos requêtes suivantes via la syntaxe `{{ctx.xxx}}`.

**Ouvrir le panneau** : bouton **Ctx** dans la barre du haut.

Le panneau est divisé en deux zones :

| Zone | Description |
|------|-------------|
| **Éditeur JSON** (haut) | Éditeur avec coloration syntaxique. Toute modification est sauvegardée automatiquement. |
| **Variables disponibles** (bas) | Arborescence des clés disponibles. Cliquer sur une clé copie `{{ctx.xxx.yyy}}` dans le presse-papier. |

**Sauvegarder une réponse dans le contexte** :

1. Envoyez une requête
2. Dans la barre de réponse, cliquez sur **Ctx**
3. Donnez un nom à la variable (ex: `loginResponse`)
4. Les champs `status_code`, `url`, `method`, `headers` et `body` sont stockés

**Utiliser le contexte dans une requête** :

Dans n'importe quel champ (URL, headers, body, query params), utilisez la syntaxe `{{ctx.xxx}}` :

```
URL      : https://api.example.com/users/{{ctx.loginResponse.body.user.id}}
Header   : Authorization: Bearer {{ctx.loginResponse.body.token}}
Body     : {"userId": "{{ctx.loginResponse.body.id}}"}
Query    : token={{ctx.loginResponse.body.access_token}}
```

Les templates `{{ctx.xxx}}` sont résolus **avant l'envoi** de la requête, à la fois côté client (navigateur) et côté serveur (proxy).

**Arborescence** : les clés imbriquées sont affichées sous forme d'arbre avec connecteurs `├` et `└`. Les branches (objets) ont un chevron ▶ pour les déplier, les feuilles (strings, nombres, booléens) affichent un aperçu de leur valeur.

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

## 7. ELY Copilot

ELY Copilot est l'assistant IA contextuel intégré à chaque page d'Elyria. Il apparaît dans un panneau latéral (ouvrable via le bouton **Ely** dans la barre du haut ou `Ctrl+I`).

### Architecture

ELY combine trois couches d'intelligence :

| Couche | Rôle |
|--------|------|
| **Context Awareness** | Détecte la page active et collecte les données pertinentes (requête en cours, workflow ouvert, profil de scan sélectionné...) |
| **Function Calling** | Exécute des actions réelles via les API internes d'Elyria — crée des requêtes, lance des scans, génère des workflows |
| **Memory** | Conserve un profil utilisateur compact qui s'enrichit au fil des conversations |

### Context Awareness

ELY sait sur quelle page vous êtes et adapte ses capacités :

| Page | Contexte collecté | Actions disponibles |
|------|-------------------|---------------------|
| **Client API** | Méthode, URL, headers, body en cours | Créer/modifier/envoyer des requêtes, gérer les collections |
| **Workflows** | Workflow ouvert, blocs du canvas | Créer/modifier des workflows, ajouter des blocs |
| **Red Team** | Profil de scan, campagne active | Lancer un scan, analyser les findings, générer un rapport |
| **Grey Team** | Domaine cible, findings OSINT | Lancer un scan OSINT, explorer les résultats |
| **Blue Team** | Spécification chargée, rapport en cours | Auditer une spec, générer des exigences |
| **Purple Team** | Profil de scan, scan actif | Lancer un scan IAST, analyser les findings, générer un rapport |
| **Hub** | Configuration courante | Gérer les teams, configurer les providers IA |
| **Docs** | Page de documentation affichée | Expliquer des concepts, guider l'utilisateur |

### Tools (Function Calling)

ELY peut **agir** directement sur la plateforme via des fonctions internes :

| Action | Description | Pages |
|--------|-------------|-------|
| `ely_create_request` | Créer et envoyer une requête HTTP | Client API, Hub |
| `ely_create_collection` | Créer un dossier/collection | Client API, Hub |
| `ely_run_scan` | Lancer un scan pentest Red Team | Red Team |
| `ely_osint_scan` | Lancer un scan OSINT | Grey Team |
| `ely_blueteam_analyze` | Lancer une analyse Blue Team | Blue Team |
| `ely_create_workflow` | Créer un workflow no-code | Workflows |
| `ely_get_findings` | Récupérer les findings d'un rapport | Red/Grey/Blue/Purple Team |
| `ely_purpleteam_scan` | Lancer un scan IAST sur un dépôt de code | Purple Team |
| `ely_purpleteam_get_findings` | Récupérer les findings Purple Team | Purple Team |
| `ely_list_resources` | Lister profils, collections, workflows | Toutes |

Chaque action est :
- **Auditée** : tracée dans l'historique (Hub → onglet Ely)
- **Limité** : mêmes permissions que l'utilisateur (token JWT partagé)
- **Sécurisée** : pas d'élévation de privilège possible

### Memory (Profil utilisateur)

ELY conserve un **profil mémoire** (max 5000 caractères) par utilisateur :

- Tous les 6 rounds de conversation, l'historique est **compacté** en un profil structuré
- Le profil capture : rôle, technologies utilisées, projets en cours, préférences, niveau d'expertise, patterns récurrents
- La mémoire est injectée en **priorité haute** dans le prompt système
- Stockée en base de données (SQLite `ely_memory`), persistante entre les sessions

**Exemple de profil mémoire :**
> Développeur backend senior, travaille sur une API REST en Go. Utilise JWT pour l'auth. Teste régulièrement avec Elyria sur http://localhost:8080. Préfère le modèle Pro pour les analyses. Fait souvent des requêtes POST vers /api/users. Niveau expert en sécurité API.

### Commandes slash `/`

Dans le chat, tapez `/` pour voir les commandes disponibles :

| Commande | Description |
|----------|-------------|
| `/explain` | Analyser une réponse HTTP (status, headers, erreurs) |
| `/scan` | Lancer un scan de sécurité Red Team |
| `/osint` | Lancer un scan OSINT (Grey Team) |
| `/analyze` | Analyser une spécification (Blue Team) |
| `/create` | Créer une requête, collection ou workflow |
| `/help` | Aide sur Elyria |

Navigation au clavier (↑↓ Enter) ou clic souris dans le menu.

### Modèle Flash / Pro

Le toggle **Flash** / **Pro** dans le header du panneau permet de choisir le modèle IA :
- **Flash** (gpt-4o-mini) : réponses rapides pour les tâches simples
- **Pro** (gpt-4o) : analyse approfondie avec reasoning

### Hub → Onglet Ely

Le Hub dispose d'un onglet **Ely** pour suivre l'activité :

- **Historique** : toutes les actions exécutées par Ely (page, action, statut, timestamp)
- **Stats** : total d'actions, taux de succès, tokens consommés
- **Préférences** : ton, verbosité, activer/désactiver Ely

### Utilisation

1. Cliquez sur **Ely** dans la barre du haut pour ouvrir le panneau
2. Saisissez votre message dans le champ en bas
3. Appuyez sur `Entrée` pour envoyer

Exemples de prompts :
- *"Crée une collection pour tester l'API de paiement Stripe"*
- *"Envoie une requête GET à https://api.example.com/users et vérifie que le statut est 200"*
- *"Analyse la dernière réponse et dis-moi si le token JWT est valide"*
- *"Lance un scan de sécu sur mon profil Red Team"*
- *"Explique-moi la différence entre OAuth 2.0 et JWT"*

---

## 8. Import de documents

Importez vos spécifications d'API et collections pour générer automatiquement des dossiers et requêtes.

### Formats supportés

- **OpenAPI 3.x** et **Swagger 2.x** (`.json`, `.yaml`, `.yml`)
- **Arazzo 1.0** — workflows de test
- **Postman** — collections Postman (`.json`)
- **Bruno** — collections Bruno (`.json`, `.bru`)

### Comment importer

1. Dans la barre d'import (en haut du builder), cliquez sur le format souhaité : **OpenAPI**, **cURL**, **Postman** ou **Bruno**
2. Glissez-déposez un fichier dans la zone, ou cliquez pour parcourir
3. Cliquez sur **Importer**

### Résultat d'un import OpenAPI

- Un dossier racine est créé avec le nom de l'API
- Chaque opération (endpoint) devient une requête sauvegardée dans un sous-dossier par tag
- Les paramètres, headers et body d'exemple sont pré-remplis

### Résultat d'un import Arazzo

- Les workflows sont importés comme scénarios exécutables
- Les références entre étapes (`$steps.x.outputs.y`) sont traduites en syntaxe `{{ctx.xxx}}`

### Résultat d'un import Postman ou Bruno

- Les dossiers Postman/Bruno sont convertis en dossiers de collection Elyria
- Les requêtes conservent leurs headers, paramètres et body
- Les variables d'environnement sont importées comme variables de contexte

---

## 9. GED — Gestion Électronique de Documents

La GED (accessible via `/ged`) stocke vos spécifications OpenAPI, Arazzo, fichiers markdown et autres documents. Elle sert de bibliothèque centrale pour tous les modules (Red/Blue/Purple Team).

### 9.1. Interface

| Zone | Description |
|------|-------------|
| **Sidebar gauche** | Liste des documents avec filtres par type et recherche textuelle |
| **Zone centrale** | Visualiseur de document — markdown rendu, JSON formaté, ou texte brut |
| **Bouton +** | Ajouter un nouveau document |

### 9.2. Ajouter un document

1. Cliquez sur le bouton **+** dans la sidebar
2. Glissez-déposez un fichier dans la zone, ou cliquez pour parcourir
3. Renseignez le nom, le type (OpenAPI, Arazzo, Markdown, Autre) et un snippet descriptif
4. Cliquez **Enregistrer**

Le type est auto-détecté selon l'extension du fichier (`.json`/`.yaml` → OpenAPI, `.md` → Markdown).

### 9.3. Visualiser un document

Cliquez sur un document dans la liste pour l'ouvrir dans le visualiseur :

- **Markdown** : rendu HTML avec coloration syntaxique (titres, tableaux, code, liens)
- **OpenAPI / Arazzo** : JSON formaté avec indentation
- **Autre** : texte brut

### 9.4. Actions

| Action | Comment |
|--------|---------|
| **Télécharger** | Bouton violet dans le header du visualiseur |
| **Supprimer** | Icône ✕ sur chaque document dans la sidebar (confirmation demandée) |
| **Filtrer** | Dropdown par type (OpenAPI, Arazzo, Markdown, Autre) |
| **Rechercher** | Barre de recherche dans la sidebar (filtre sur nom et snippet) |

### 9.5. Picker GED

Depuis les modules Red Team, Blue Team et Purple Team, vous pouvez lier un document de la GED :

- Cliquez sur **Depuis la GED** dans l'onglet OpenAPI des profils de scan
- Une modale liste tous les documents disponibles
- Sélectionnez un document pour l'associer au profil

---

## 10. Requêtes Raw HTTP

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

## 11. Le Workflow Builder

Le Workflow Builder permet de créer des scénarios de test automatisés par glisser-déposer.

### Accès

Depuis l'interface principale, cliquez sur le bouton **Workflows** dans la barre du haut.

### Interface

| Zone | Description |
|------|-------------|
| **Palette gauche** | Briques disponibles, classées par catégorie + collections sauvegardées |
| **Canvas central** | Zone de travail où vous placez et connectez les briques |
| **Panneau droit** | Configuration de la brique sélectionnée + logs d'exécution |

### 11.1. Les briques

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

### 11.2. Le contexte (ctx)

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

### 11.3. Exécution

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

## 12. Le Hub

Le Hub (accessible via l'icône utilisateur dans le header) centralise la gestion de votre compte et de vos ressources.

### 12.1. Teams

- **Créer une team** : bouton "Créer", donnez un nom. Vous êtes automatiquement membre.
- **Rejoindre une team** : entrez un Team ID et cliquez "Rejoindre". Une demande est envoyée aux membres.
- **Valider une demande** : dans la team, développez pour voir les demandes en attente. La validation nécessite 80% d'approbation des membres.
- **Suivre/Ne plus suivre** : les teams suivies apparaissent dans vos filtres de collections, workflows et pentest.
- **Copier l'ID** : cliquez sur l'icône de copie à côté du Team ID.

### 12.2. Configuration serveur (`elyria.cfg`)

Elyria se configure via le fichier **`elyria.cfg`** à la racine du projet. C'est un fichier INI standard, sans dépendance `.env`.

**Sections disponibles :**

```ini
[server]
host = 127.0.0.1     # Adresse d'écoute
port = 8000          # Port
reload = 1           # Hot reload (0 en production)

[ssl]
cert_path = cert.pem # Chemin certificat TLS
key_path = key.pem   # Chemin clé privée
verify = 0           # Vérification SSL sortant (1 en production)

[database]
backend = sqlite     # sqlite ou postgres
sqlite_path = database.db
pg_host = localhost  # PostgreSQL (si backend=postgres)
pg_port = 5432
pg_database = elyria
pg_user = elyria
pg_password = elyria

[logging]
level = INFO         # DEBUG, INFO, WARNING, ERROR
dir = logs

[oidc]
enabled = 0          # 1 pour activer le SSO
provider_name =      # Nom du provider
issuer =             # URL de découverte OIDC
client_id =          # Client ID
client_secret =      # Client Secret

[security]
server_wrap_key =    # Clé de chiffrement (64 hex chars). Générée si absente.
blocked_hosts = metadata.google.internal,169.254.169.254,host.docker.internal
```

**Ordre de priorité :**
1. Variables d'environnement `ELYRIA_*` (ex: `ELYRIA_SERVER_PORT=9000`)
2. Base de données `app_config` (modifiable via l'API admin)
3. Fichier `elyria.cfg`
4. Valeurs par défaut codées en dur

**Override par env var** : le format est `ELYRIA_SECTION_KEY`. Exemples :
- `ELYRIA_SERVER_PORT=9000` → `[server].port`
- `ELYRIA_DATABASE_PG_PASSWORD=secret` → `[database].pg_password`

### 12.3. Proxy

Configurez vos proxies HTTP pour le forwarding des requêtes.

- **Ajouter** : nom + URL (ex: `http://proxy:8080`).
- **Définir comme favori** : le proxy favori est injecté dans vos requêtes lorsqu'il est activé.
- **Supprimer** : icône X sur chaque proxy.

### 12.4. Agent IA

Gérez vos providers LLM pour le chat IA et le pentest AI.

- **Deux slots indépendants** :
  - **Flash Model** : utilisé pour l'exploration rapide (batch de requêtes parallèles)
  - **Pro Model** : utilisé pour l'analyse profonde et le chat IA principal
- **Chaque slot peut utiliser un provider différent** (ex: Flash sur Ollama local, Pro sur OpenAI API cloud)
- **Providers supportés** : OpenAI API, LM Studio (local), Ollama (local)
- **Lister les modèles** : après avoir configuré l'URL, cliquez "Lister" pour voir les modèles disponibles
- **Définir par défaut** : un seul provider par slot peut être le défaut
- **Sécurité** : les clés API ne sont jamais renvoyées au frontend (masquées `****`). Vous pouvez les remplacer mais pas les lire.

## 13. Red Team / Pentest

Le module Red Team (accessible via le header ou `/pentest`) permet de scanner vos APIs avec le moteur OWASP API Top 10.

### 13.1. Profils de scan

- **Créer un profil** : bouton "+" dans la sidebar "Scan Profiles"
- **Configurer** : URL cible, authentification multi-type, OpenAPI spec, ID list (pour BOLA), collection existante, équipe
  - **JWT Bearer** : token JWT classique (analyse automatique de l'algorithme, des claims, de la signature)
  - **Jeton d'accès opaque** : token non-JWT (GitHub PAT, API key opaque) — pas d'analyse JWT
  - **JWE (JSON Web Encryption)** : token chiffré + clé de déchiffrement — le scanner déchiffre puis analyse le JWT interne
  - **Cookie de session** : nom + valeur du cookie — injecté comme `Cookie` header
  - **Header personnalisé** : nom + valeur de header libre (ex: `X-API-Key`)
  - **Headers supplémentaires (JSON)** : headers additionnels quel que soit le type d'auth
- **Onglet IA** : réglez le nombre de rounds d'exploration (1-50, défaut 15) et d'analyse (1-25, défaut 5)
    - **Mode Expert** : activez l'option Expert pour un scan approfondi (30 rounds d'exploration, 15 d'analyse, rapport détaillé avec documentation)
- **Modifier** : icône crayon sur le profil
- **Supprimer** : icône X sur le profil

### 13.2. Campagnes

- **Lancer un scan** : sélectionnez un profil, cliquez "Lancer le scan". Une campagne est créée.
- **Progression** : barre de progression avec dégradé de couleurs (rouge → orange → violet)
- **Arrêter** : bouton Stop pendant le scan
- **Supprimer** : icône X sur chaque campagne (purge complète : findings, logs, campagne)
- **Refresh** : bouton Refresh dans le header ou automatique toutes les 60s

### 13.3. Sandbox (Bash Tool)

Lors de la **Phase 2** (AI Deep Scan), Elyria spawn automatiquement un **conteneur Docker jetable** (`strike-sandbox`) — un environnement Linux isolé équipé d'outils de pentest réels que l'IA peut appeler.

#### Outils disponibles dans le conteneur

| Outil | Usage |
|-------|-------|
| **nmap** | Scan de ports, détection de services et OS |
| **sqlmap** | Détection et exploitation d'injection SQL |
| **nuclei** | 5000+ templates de vulnérabilités (CVE, misconfig, exposures) |
| **ffuf** | Fuzzer web (bruteforce de chemins, paramètres, sous-domaines) |
| **subfinder** | Énumération de sous-domaines via sources passives |
| **curl, jq, python3** | Scripting HTTP, parsing JSON, scripting python (requests, httpx, pyjwt) |

#### Comment l'IA interagit avec le sandbox

L'agent IA dispose d'un **tool unique appelé `bash`** exposé via le protocole OpenAI function calling. L'IA décide elle-même quelle commande exécuter en fonction de ce qu'elle découvre. Le tool accepte :

- **Mode simple** : une commande unique (`"command": "nmap -sV TARGET"`)
- **Mode batch** : jusqu'à 10 commandes exécutées séquentiellement (`"commands": ["cmd1", "cmd2"]`)
- **Timeout** : configurable par commande (défaut 30s, max 60s)

Le mot-clé `TARGET` dans les commandes est automatiquement remplacé par la cible réelle du scan.

#### Cycle de vie du conteneur

1. **Spawn** — `SandboxManager.spawn()` crée un conteneur Docker nommé `strike-{id_unique}` avec `--rm` (suppression automatique à l'arrêt), limité à 1 CPU et 512 Mo RAM
2. **Idle** — L'entrypoint attend les commandes (`tail -f /dev/null`) tout en surveillant un **TTL de 30 minutes** (configurable) : si le TTL expire, le conteneur s'arrête tout seul
3. **Exécution** — Chaque commande est injectée via `docker exec` : la commande est encodée en **base64** pour éviter les problèmes d'échappement shell, décodée dans le conteneur, puis exécutée dans un shell bash. Stdout (50k chars max) et stderr (10k max) sont capturés
4. **Destroy** — À la fin du scan (ou si le scan est stoppé), `docker rm -f --volumes` détruit le conteneur et ses volumes. `purge_expired()` nettoie les conteneurs orphelins

#### Résolution de localhost

Les adresses `127.0.0.1` et `localhost` dans les commandes ou URLs peuvent être converties en un host Docker personnalisé pour que le conteneur puisse atteindre l'hôte (le conteneur est sur un réseau Docker isolé, donc `localhost` pointerait vers lui-même). Cette fonctionnalité est **opt-in** :

- Définissez `ELYRIA_DOCKER_HOST=host.docker.internal` pour activer le remplacement automatique
- Sans cette variable, les URLs passent inchangées (comportement par défaut)
- S'applique à tous les tools : `ely_send_request`, `ely_bash`, `ely_fuzz`, `ely_browser_query`

#### Sanitization

- **Target** : seuls les caractères `[a-zA-Z0-9.\-:/_@?=&%#]` sont conservés, limité à 2000 caractères
- **Commandes** : blocage explicite des patterns destructeurs (`rm -rf /`, fork bomb, `/etc/shadow`, etc.)
- **Isolation** : conteneur Alpine `--rm`, ressources limitées, pas de persistance disque

#### Mode passif (Grey Team)

Pour les scans Grey Team (OSINT), le sandbox est **optionnel** et restreint aux outils **passifs uniquement** : `nmap`, `sqlmap`, `ffuf`, `nuclei` et autres outils actifs sont bloqués. Seuls `dig`, `whois`, `curl` vers des APIs publiques (crt.sh, archive.org), `python3` et `jq` sont autorisés.

#### Logging

Chaque commande bash exécutée par l'IA est logguée dans la base de données (`pentest_scan_logs`, `log_type='bash'`) avec stdout, stderr, exit code et temps d'exécution — visibles dans l'onglet **Logs** de la campagne.

### 13.4. Findings et Logs

- **Dashboard** : compteurs par sévérité (Critical, High, Medium, Low, Info)
- **Findings** : chaque vulnérabilité affiche titre, sévérité, description, remédiation, CWE/CVSS
- **Détails requête/réponse** : cliquez sur un finding pour voir les onglets Requête/Réponse (URL, headers, body)
- **Analyse IA** : les findings de l'agent IA incluent une courte analyse en 3 phrases
- **Logs** : historique de toutes les requêtes envoyées pendant le scan, avec détails requête/réponse au clic
- **Filtre par sévérité** : dropdown dans l'onglet Findings
- **Rafraîchir** : boutons Refresh dans chaque onglet

### 13.5. Rapport

- **Rapport Markdown** : accessible dans l'onglet Rapport
- **Navigation rapide** : table des matières sticky avec les sections principales
- **Téléchargement** : bouton Rapport dans le header pour exporter en .md
- **Annexes** : détails requête/réponse pour chaque finding

## 14. Blue Team / SSDLC

Le module Blue Team (accessible via le header ou `/blueteam`) analyse vos spécifications API avec un agent IA expert en security-by-design pour produire un rapport d'exigences de sécurité.

### 14.1. Profils SSDLC

- **Créer un profil** : bouton "+" dans la sidebar "Profils SSDLC"
- **Configurer** : URL cible, Master Prompt (instructions pour l'agent), Documentation (contexte métier), spécification OpenAPI, collection
- **Filtre par équipe** : dropdown dans la sidebar pour filtrer les profils par équipe
- **Modifier** : bouton crayon dans le header du profil
- **Supprimer** : bouton poubelle dans le header du profil

### 14.2. Analyse

- **Lancer l'analyse** : sélectionnez un profil, cliquez "Lancer l'analyse"
- **Progression** : barre de progression + messages de statut en temps réel (polling adaptatif)
- **Arrêter** : bouton Stop pendant l'analyse
- **Modèle Pro** : badge affichant le modèle IA utilisé

### 14.3. Rapport

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

### 14.4. Import depuis Red Team

Vous pouvez importer une campagne Red Team pour générer un plan de remédiation :
- Depuis Red Team, bouton "Envoyer vers Blue Team" sur une campagne terminée
- Ou depuis Blue Team, utilisez l'API `POST /api/blueteam/import-from-pentest`

---

## 15. Grey Team / OSINT

Le module Grey Team (accessible via le header ou `/greyteam`) effectue de la **reconnaissance passive** (OSINT) sur un domaine cible. Contrairement au Red Team qui attaque activement, le Grey Team collecte des informations publiques sans interagir directement avec les serveurs cibles.

### 15.1. Profils OSINT

- **Créer un profil** : bouton "+" dans la sidebar "Domains"
- **Configurer** : nom, domaine cible, description, modules OSINT à activer, nombre de rounds d'analyse IA
- **Filtre par équipe** : dropdown dans la sidebar
- **Modifier** : bouton Edit dans le header
- **Supprimer** : bouton Delete dans le header

### 15.2. Dashboard

- **Risk Score** : jauge 0-100 basée sur le nombre et la sévérité des findings
- **Compteurs** : Critical, High, Total Findings
- **6 cartes d'indicateurs** : DNS Health, SSL/TLS, HTTP Security, Subdomains, Email Exposure, Tech Stack
- **Scan progress** : barre de progression avec polling adaptatif

### 15.3. Modules OSINT (Phase 1)

13 modules de collecte passive en parallèle : DNS Records, WHOIS, SSL/TLS, Cert Transparency (crt.sh + Cert Spotter + AlienVault OTX), HTTP Headers, Web Paths, Tech Fingerprint (30+ patterns : CMS, frameworks, CDN/WAF), Email Enumeration, Trivial Pages (190+ chemins : .env, .git, wp-admin, backups, configs), Wayback Machine, GitHub Dorks, Google Dorks, Frontend Code (secrets, endpoints API, CVE, déobfuscation IA).

### 15.4. Phase 2 — AI Refinement

L'agent IA (modèles Flash + Pro) enrichit les findings :

- **osint_refine_finding** : score d'exploitabilité (1-10), vecteur MITRE ATT&CK, priorité de remédiation
- **osint_create_finding** : crée de nouveaux findings découverts pendant l'analyse
- **osint_correlate_findings** : chaîne les findings en scénarios d'attaque
- **bash** : commandes OSINT passives en sandbox (dig, whois, curl crt.sh/archive.org/GitHub API)

### 15.5. Findings et filtres

- Tableau trié par sévérité avec titre, catégorie, description, et badge `AI` pour les findings enrichis
- **Filtres** : sévérité, type de module, source (System / AI Refined)
- **Panneau de détail** : sévérité, description, catégorie, évidence formatée, remédiation, analyse IA
- **Rafraîchissement** automatique pendant le scan
- **KPIs** : jauge de score de risque (0-100), compteurs Critical/High/Total, indicateurs DNS/SSL/HTTP/Subdomains/Emails/Tech Stack avec dots de statut (vert/orange/rouge)

---

## 16. Purple Team / IAST

Le module Purple Team (accessible via le header ou `/purpleteam`) combine **SAST** (Static Application Security Testing), **SCA** (Software Composition Analysis) et **IAST** (Interactive Application Security Testing) pour analyser votre code source.

### 16.1. Profils de scan

- **Créer un profil** : bouton "+" dans la sidebar "Repositories"
- **Configurer** :
  - **Repo Source** : GitHub, GitLab, Bitbucket, ou local (upload zip)
  - **Repository URL** : URL du dépôt Git (ex: `https://github.com/user/repo.git`)
  - **Auth** : Token Bearer ou API Key (optionnel, pour dépôts privés)
  - **Target Endpoint** : URL de l'API cible pour les tests IAST dynamiques (optionnel)
  - **OpenAPI Spec URL** : spécification OpenAPI pour guider les tests
  - **Scan Depth** : Quick (statique uniquement), Full (statique + IA), IAST (statique + dynamique)
- **Modifier** : bouton Edit dans le header
- **Supprimer** : bouton Delete dans le header

### 16.2. Phases de scan

Le scan Purple Team s'exécute en trois phases :

| Phase | Description |
|-------|-------------|
| **Phase 1 — Analyse statique** | Détection du langage/framework, parsing des dépendances, scan CVE (NIST NVD), pattern matching CWE (25+ patterns), détection de mauvaises pratiques (30+ patterns) |
| **Phase 2 — IAST dynamique** | Si un endpoint cible est fourni : validation des findings statiques contre l'API live, tests de configuration (headers, CORS, HTTP methods, error disclosure, auth bypass) |
| **Phase 3 — Deep Code Review IA** | L'agent IA lit le code source, grep les patterns, fait des requêtes HTTP vers l'API cible, et reporte les vulnérabilités confirmées (business logic, auth flaws, crypto weaknesses, race conditions) |

### 16.3. Rapport en 3 parties

Le rapport Purple Team est structuré en trois sections :

1. **CVE Connues** — Vulnérabilités CVE trouvées dans les dépendances (via NIST NVD), avec score CVSS
2. **CWE (Common Weakness Enumeration)** — Faiblesses de code classifiées par CWE ID (CWE-79 XSS, CWE-89 SQLi, CWE-78 CMDi, CWE-798 Hardcoded Credentials, etc.)
3. **Mauvaises Pratiques & Exploitations Réelles** — Debug mode, secrets hardcodés, CORS permissif, auth désactivée, crypto faible, + findings IA (business logic, IDOR, race conditions)

### 16.4. Findings et filtres

- **Dashboard** : compteurs CVE, CWE, Practices, Critical, High
- **Filtres** : par partie (CVE, CWE, Practices, AI Discovered), par sévérité, **par CWE/CVE ID** (ex: `CWE-578`), et **par fichier** (filtre textuel sur le chemin du fichier contenant le finding)
- **Badge AI** : les findings découverts par l'IA sont marqués d'un badge violet `AI`
- **Panneau de détail** : sévérité, titre, catégorie, CVE/CWE, localisation (fichier:ligne), CVSS, description, remédiation, analyse IA
- **Rapport** : visualisation markdown avec **table des matières** et rendu Mermaid dans l'interface, téléchargement .md
- **Toggle View Report / View Findings** : le bouton View Report permet de basculer entre la vue rapport et la liste des findings

### 16.5. Envoi vers Blue Team

Comme pour Red Team, vous pouvez envoyer un rapport Purple Team vers Blue Team pour obtenir un plan de remédiation :
- Bouton **Send to Blue Team** après un scan terminé
- Crée automatiquement un profil Blue Team avec un prompt spécial Purple Team
- L'analyse Blue Team démarre automatiquement

### 16.6. Sécurité du clonage

- **Sandbox Docker** : si Docker est disponible, le clonage du dépôt s'effectue dans un conteneur isolé — le token d'auth ne touche jamais le filesystem host
- **Fallback direct** : si Docker n'est pas disponible, clonage direct avec `--depth 1` et suppression immédiate du `.git`
- **Purge automatique** : les fichiers clonés sont supprimés automatiquement après le scan

---

## 17. Raccourcis clavier

| Raccourci | Action |
|-----------|--------|
| `Ctrl+Enter` | Envoyer la requête courante |
| `Ctrl+I` | Ouvrir/fermer l'assistant IA |
| `Suppr` | Supprimer la brique sélectionnée (workflow) |
| `Suppr` | Supprimer la connexion sélectionnée (workflow) |
| `Échap` | Fermer les modales |
| `Entrée` | Valider dans les modales |
