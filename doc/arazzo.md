👉 **OpenAPI** décrit *une API endpoint par endpoint*
👉 **Arazzo** décrit *comment enchaîner plusieurs appels API pour faire une vraie action métier*

> 💡 En une phrase :
> **Arazzo = scénarios / workflows d’API**

---

## 🎯 Exemple concret

Avec OpenAPI tu sais :

* `GET /products`
* `POST /orders`

Mais avec Arazzo tu décris :

1. chercher un produit
2. sélectionner
3. payer
4. confirmer

👉 donc un **workflow complet**

➡️ Arazzo décrit **la logique entre les appels**, pas juste les appels eux-mêmes ([Bump.sh Docs & Guides][1])

---

# ⚙️ À quoi sert Arazzo ?

* documenter des **use cases réels**
* automatiser des workflows API
* tests end-to-end
* orchestration multi-API

👉 C’est complémentaire à OpenAPI (ça ne le remplace pas) ([Bump.sh Docs & Guides][1])

---

# 🧩 Structure d’un fichier Arazzo

Un fichier Arazzo = JSON ou YAML ([OpenAPI Initiative Publications][2])

## 🔑 Les blocs principaux

```yaml
arazzo: 1.0.1   # version
info:           # metadata
sourceDescriptions:   # APIs sources (OpenAPI)
workflows:      # scénarios
components:     # réutilisable (optionnel)
```

👉 Ces champs sont obligatoires sauf `components` ([OpenAPI Initiative Publications][2])

---

# 🔥 Cheat Sheet Arazzo (version rapide)

## 1. Version

```yaml
arazzo: 1.0.1
```

---

## 2. Info (metadata)

```yaml
info:
  title: My Workflow
  version: 1.0.0
```

---

## 3. Sources (les APIs utilisées)

```yaml
sourceDescriptions:
  - name: myAPI
    url: ./openapi.yaml
    type: openapi
```

👉 référence ton OpenAPI

---

## 4. Workflows (le cœur 💥)

```yaml
workflows:
  - workflowId: buyProduct
    steps:
      - stepId: getProducts
      - stepId: createOrder
```

---

## 5. Steps (étapes)

Chaque step = un appel API ou workflow

```yaml
- stepId: createOrder
  operationId: createOrder
```

👉 peut pointer vers :

* `operationId` (OpenAPI)
* `operationPath`
* `workflowId` (autre workflow)

---

## 6. Paramètres

```yaml
parameters:
  - name: id
    in: path
    value: $inputs.productId
```

---

## 7. Request Body

```yaml
requestBody:
  content:
    application/json:
      schema:
        type: object
```

---

## 8. Outputs (très important 🔥)

```yaml
outputs:
  orderId: $response.body#/id
```

👉 permet de réutiliser la réponse dans les étapes suivantes

---

## 9. Conditions / logique

```yaml
successCriteria:
  - condition: $statusCode == 200
```

---

## 10. Actions (flow control)

### ✔️ succès

```yaml
onSuccess:
  - type: goto
    stepId: nextStep
```

### ❌ erreur

```yaml
onFailure:
  - type: retry
    retryLimit: 3
```

---

## 11. Expressions dynamiques (clé du système)

👉 super important à retenir

```yaml
$inputs.userId
$response.body#/id
$steps.step1.outputs.token
```

👉 c’est comme du **JavaScript pour lier les steps**

---

# 🧠 Ultra résumé (examen)

* Arazzo = **workflow d’API**
* Basé sur OpenAPI
* Permet :

  * enchaînement d’appels
  * conditions
  * logique
* Structure :

  * `arazzo`
  * `info`
  * `sourceDescriptions`
  * `workflows`
* Concepts clés :

  * **steps**
  * **outputs**
  * **expressions**
  * **success / failure**

---

# 🧩 Différence OpenAPI vs Arazzo

| OpenAPI          | Arazzo           |
| ---------------- | ---------------- |
| décrit endpoints | décrit workflows |
| statique         | dynamique        |
| une requête      | séquence         |
| doc API          | logique métier   |

---

# ⚡ Ce que change la v1.0.1

* corrections et clarifications
* pas de changement majeur
* compatible avec 1.0.0 ([OpenAPI Initiative][3])

---

# 🚀 Astuce pour comprendre vite

Pense toujours :

> OpenAPI = “QUOI appeler”
> Arazzo = “DANS QUEL ORDRE et POURQUOI”

---

Si tu veux, je peux te faire :

* un **exemple complet (type projet e-commerce)**
* ou un **exercice avec correction (très utile pour examen)**
* ou une **mindmap ultra simple à mémoriser**

[1]: https://docs.bump.sh/arazzo/v1.0/introduction/what-is-arazzo/?utm_source=chatgpt.com "What is Arazzo? | Bump.sh Docs & Guides"
[2]: https://spec.openapis.org/arazzo/v1.0.1.html?utm_source=chatgpt.com "The Arazzo Specification v1.0.1"
[3]: https://www.openapis.org/blog/2025/01/24/announcing-arazzo-specification-version-1-0-1?utm_source=chatgpt.com "Announcing Arazzo Specification version 1.0.1 – OpenAPI Initiative"
