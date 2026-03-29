# CyberForm

Plateforme web d’**évaluation des risques cyber**, de **quiz personnalisés** et de **formation générative** (IA), articulée autour du profil utilisateur, des actifs et du cadre **MITRE ATT&CK**.

## Aperçu

- **Espace utilisateur** : profil, quiz pré/post, formation HTML générée, historique.
- **Espace administrateur** : suivi des collaborateurs, comparaison de scores, statistiques, paramètres d’organisation (seuils, objectifs, techniques critiques, catalogue MITRE).
- **Boucle métier** : analyse de risque → scores requis par thème → quiz → évaluation → contenu de formation ciblé (voir `ARCHITECTURE.md`).

## Stack technique

| Couche | Technologie |
|--------|-------------|
| Frontend | [Angular](https://angular.io/) 17, Bootstrap 5, ngx-translate (FR / EN / ES), ApexCharts |
| Backend | [Flask](https://flask.palletsprojects.com/) (Python), JWT, rate limiting |
| Données | [MongoDB](https://www.mongodb.com/) (PyMongo) |
| IA | API OpenAI (clé dans l’environnement) |

## Prérequis

- **Node.js** (LTS recommandé) et **npm**
- **Python** 3.10+ (ou version compatible avec vos dépendances)
- **MongoDB** accessible (local ou distant)
- (Optionnel) clé **OpenAI** pour la génération quiz / formation

## Structure du dépôt

```
CyberForm/          # Application Angular (UI)
backend/            # API Flask, logique métier, génération (generate.py, module.py, …)
ARCHITECTURE.md     # Décrit la boucle risque / test / IA, rôles, endpoints
.env.example        # Modèle des variables d’environnement
```

## Installation

### 1. Cloner le dépôt

```bash
git clone <url-de-votre-depot>
cd CyberForm
```

### 2. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

À la **racine** du projet (pas dans `backend/`), copier la configuration :

```bash
cp .env.example .env
```

Éditer **`.env`** : au minimum `MONGO_URI`, `JWT_SECRET`, et `OPENAI_API_KEY` si vous utilisez l’IA. Les variables SMTP (`SMTP_*`) servent à la réinitialisation de mot de passe et au formulaire contact — voir les commentaires dans `.env.example`. Ne commitez **jamais** `.env` (déjà listé dans `.gitignore`).

### 3. Frontend

```bash
cd CyberForm
npm install
```

Le fichier `CyberForm/proxy.conf.json` redirige les appels `/api`, `/login`, `/evaluate`, etc. vers le backend en développement (**`http://localhost:5001`**).

## Lancer en développement

**Terminal 1 — API Flask** (port **5001**) :

```bash
cd backend
source .venv/bin/activate
python app.py
```

**Terminal 2 — Angular** (port **4200**) :

```bash
cd CyberForm
npm start
# ou : ng serve
```

Ouvrir **http://localhost:4200**. Les requêtes API passent par le proxy vers Flask.

## Build production (frontend)

```bash
cd CyberForm
npm run build
```

Les fichiers générés sont dans `CyberForm/dist/`. Adaptez le déploiement (serveur statique + reverse proxy vers l’API) selon votre hébergement.

## Documentation complémentaire

| Fichier | Contenu |
|---------|---------|
| `ARCHITECTURE.md` | Schéma fonctionnel, routes clés, rôles, admin, collections Mongo |
| `backend/README_PROFILE_VALIDATION.md` | Validation des profils de risque MITRE (human / hybrid / non_human) |
| `backend/README_TRAINING_PIPELINE.md` | Pipeline de formation (qualité, variables d’environnement) |
| `backend/README_QUIZ_METRICS.md` | Métriques qualité quiz et onglet admin associé |

## Sécurité

- Ne versionnez pas **`.env`**, clés API ni mots de passe.
- En production, définissez `JWT_SECRET` fort, restreignez `CORS_ORIGINS`, et consultez les variables `CYBERFORM_PRODUCTION` / SMTP dans `.env.example`.

---

*Projet CyberForm.*
