# Guide Utilisateur — Elyria

**Client HTTP conçu pour le test d'API — du test unitaire au pentest.**

---

## Table des matières

1. [Présentation](#1--présentation)
2. [Démarrage rapide](#2--démarrage-rapide)
3. [L'interface principale](#3--linterface-principale)
   - [La barre d'URL et l'envoi de requêtes](#31--la-barre-durl-et-lenvoi-de-requêtes)
   - [Le builder structuré](#32--le-builder-structuré)
   - [La réponse](#33--la-réponse)
4. [Les Collections](#4--les-collections)
5. [L'Historique](#5--lhistorique)
6. [L'Assistant IA](#6--lassistant-ia)
7. [Import de documents (OpenAPI / Arazzo)](#7--import-de-documents-openapi--arazzo)
8. [Requêtes Raw HTTP](#8--requêtes-raw-http)
9. [Le Workflow Builder](#9--le-workflow-builder)
   - [Les briques](#91--les-briques)
   - [Le contexte (ctx)](#92--le-contexte-ctx)
   - [Exécution](#93--exécution)
10. [Raccourcis clavier](#10--raccourcis-clavier)

---

## 1. Présentation

Elyria est un client API complet qui combine :

- **Requêtes structurées** — GET, POST, PUT, PATCH, DELETE avec headers, query params et body
- **Requêtes Raw HTTP** — forgez vos requêtes HTTP from scratch (socket TCP)
- **Collections** — organisez vos requêtes en dossiers hiérarchiques
- **Workflow Builder** — automatisez des scénarios multi-requêtes avec logique conditionnelle et boucles
- **Assistant IA intégré** — créez des collections, exécutez des tests et analysez les résultats par chat
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

L'écran est divisé en 3 zones :

| Zone | Description |
|------|-------------|
| **Barre latérale gauche** | Collections (dossiers + requêtes sauvegardées) et Historique |
| **Zone centrale** | Builder de requête (structuré ou raw) + panneau de réponse |
| **Panneau chat (droite)** | Assistant IA, masqué par défaut, s'ouvre avec le bouton **Assistant IA** ou `Ctrl+I` |

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

## 6. L'Assistant IA

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

## 7. Import de documents (OpenAPI / Arazzo)

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

## 8. Requêtes Raw HTTP

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

## 9. Le Workflow Builder

Le Workflow Builder permet de créer des scénarios de test automatisés par glisser-déposer.

### Accès

Depuis l'interface principale, cliquez sur le bouton **Workflows** dans la barre du haut.

### Interface

| Zone | Description |
|------|-------------|
| **Palette gauche** | Briques disponibles, classées par catégorie + collections sauvegardées |
| **Canvas central** | Zone de travail où vous placez et connectez les briques |
| **Panneau droit** | Configuration de la brique sélectionnée + logs d'exécution |

### 9.1. Les briques

Glissez-déposez les briques depuis la palette vers le canvas. Connectez-les en tirant depuis le port de sortie (rond en bas) vers le port d'entrée (rond en haut) d'une autre brique.

#### Contrôle de flux

| Brique | Rôle | Ports de sortie |
|--------|------|-----------------|
| **Start** | Point d'entrée obligatoire du workflow | `out` |
| **If / Else** | Branchement conditionnel (expression JavaScript) | `TRUE`, `FALSE` |
| **For Loop** | Boucle sur N itérations avec variable d'index | `BODY` (chaque itération), `DONE` (après la boucle) |
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

### 9.2. Le contexte (ctx)

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

**Snippets ctx** : dans le panneau de configuration des briques HTTP Request, Raw Request, Set Data et If/Else, une section *ctx — Contexte du workflow* affiche des snippets cliquables qui s'insèrent à la position du curseur dans le champ actif.

### 9.3. Exécution

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

## 10. Raccourcis clavier

| Raccourci | Action |
|-----------|--------|
| `Ctrl+Enter` | Envoyer la requête courante |
| `Ctrl+I` | Ouvrir/fermer l'assistant IA |
| `Suppr` | Supprimer la brique sélectionnée (workflow) |
| `Suppr` | Supprimer la connexion sélectionnée (workflow) |
| `Échap` | Fermer les modales |
| `Entrée` | Valider dans les modales |
