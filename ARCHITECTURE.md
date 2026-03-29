# Architecture CyberForm – Boucle Risque / Test / IA

Ce document décrit l’architecture mise en place pour le système d’évaluation et de formation en cybersécurité, alignée sur le schéma **Analyse des risques → Test de cyberconnaissance → IA générative**. Il décrit aussi la **partie utilisateur** et la **partie administrateur**.

---

## Partie Utilisateur et partie Administrateur

L’application comporte deux espaces selon le rôle renvoyé au login (`basic_info.role` : `'utilisateur'` ou `'admin'`).

| Rôle | Redirection après login | Espace |
|------|-------------------------|--------|
| **utilisateur** | `/user` | Espace personnel : profil, quiz, formation |
| **admin** | `/admin` | Tableau de bord : liste des utilisateurs, graphiques, création de comptes, statistiques |

- **AuthGuard** : exige un `userID` en session. Protège `/user`, `/editprofile`, `/quiz`, `/formation`.
- **AdminGuard** : exige en plus `userData.role === 'admin'`. Protège `/admin`. Sinon redirection vers `/login`.

**Header** : selon le rôle, affiche le lien « Espace utilisateur » ou « Espace administrateur ».

**Backend** : les routes sensibles (création d’utilisateurs, statistiques globales, paramètres d’organisation, métriques quiz, etc.) utilisent `@require_jwt(require_admin=True)` dans `app.py`. Les routes utilisateur standard vérifient l’identité via JWT (`check_self_or_admin` ou équivalent) pour limiter l’accès aux données du bon `userID`.

---

## Schéma global (Boucle Risque / Test / IA)

1. **Analyse des risques**  
   Entrées : seuil de risque (policy), actifs classifiés, cadre MITRE.  
   Sortie : **Score requis par thread** (par technique / thème).

2. **Test de cyberconnaissance**  
   Entrées : utilisateur, profil utilisateur, contenu de test par thread.  
   Sortie : **Score utilisateur par thread**.

3. **IA générative**  
   Entrées : score requis par thread, score utilisateur par thread.  
   Sorties : **contenu de test par thread**, **contenu de formation par thread**.

4. **Utilisateur**  
   Reçoit le **contenu de formation par thread**.

---

## Implémentation dans CyberForm

### 1. Analyse des risques (Required Score per thread)

- **Où** : `backend/app.py`, route `/evaluate`.
- **Entrées** :
  - Seuil de risque politique (`policy_threshold_pct`, `policy_threshold_value`).
  - Actifs et techniques (MITRE) issus de `profile_risks` / `attack_graphs` (module `generate_profile_risk`, `module.ensure_attack_graph_for_asset`).
- **Sortie** : `required_scores` (liste de `{ technique_id, technique_name, required_correct_answers, target_Vpre, local_threshold }`).

Les scores requis par technique sont calculés à partir des risques locaux (KMeans, seuils appris) et du nombre de bonnes réponses cibles pour atteindre le seuil.

### 2. Test de cyberconnaissance (User Score per thread)

- **Où** : `backend/app.py`, route `/evaluate`.
- **Entrées** : `userID`, `quiz_type`, `answers`, `profile`, et les questions du quiz (contenu de test).
- **Sortie** :
  - Score global : `user_score`, `total_questions`, `vulnerability_score`, etc.
  - **Score par thread** : `user_scores_per_thread` (liste de `{ technique_id, technique_name, correct_count, total_count, score_pct }`).

Ces champs sont aussi enregistrés dans `quiz_history` pour alimenter la génération suivante.

### 3. IA générative (Testing-content & Learning-content per thread)

- **Génération du quiz**  
  - Route : `POST /generate_quiz`.  
  - Utilise `required_scores` et `user_scores_per_thread` (corps de la requête ou dernière évaluation en base).  
  - `generate.select_quiz_targets()` priorise les threads où **score utilisateur < score requis** (écart), puis risque/threat.  
  - Sortie : quiz (contenu de test) personnalisé.

- **Génération de la formation**  
  - Route : `POST /generate_training`.  
  - Utilise `results` (dernier `quiz_history`, qui contient `required_scores` et `user_scores_per_thread`) et optionnellement `required_scores` / `user_scores_per_thread` en paramètres.  
  - `generate.select_training_targets()` priorise les mêmes écarts (gap) pour choisir les modules.  
  - Sortie : HTML de formation (learning-content) par thème/technique.

### 4. Utilisateur

- Le frontend envoie les réponses à `/evaluate`, reçoit `required_scores`, `user_scores_per_thread` et le détail des réponses.
- Après évaluation, il peut appeler `/generate_training` pour obtenir la formation personnalisée et l’afficher à l’utilisateur.

---

## Endpoints utiles

| Route | Rôle |
|-------|------|
| `POST /evaluate` | Évalue le quiz, retourne `required_scores` et `user_scores_per_thread`, enregistre dans `quiz_history`. |
| `POST /generate_quiz` | Génère un quiz (optionnel : `required_scores`, `user_scores_per_thread` ; sinon pris depuis la dernière évaluation). |
| `POST /generate_training` | Génère la formation ; utilise `results` (avec `required_scores` / `user_scores_per_thread`) pour prioriser les threads en écart. |
| `GET /api/risk/scores_per_thread?userID=...&quiz_type=pre` | Retourne les derniers `required_scores` et `user_scores_per_thread` pour un utilisateur (pour affichage ou intégration). |
| `GET /api/statistics` | Statistiques globales (admin) : moyenne de risque affichée, % à risque, % objectifs, % utilisateurs avec **formation encore planifiée** (`nextTrainingDate` ≥ maintenant). |
| `GET /api/statistics/mois` | Séries mensuelles (risque, vulnérabilité, objectifs, formations planifiées à venir par mois d’évaluation). |
| `GET` / `PUT` / `POST` `/api/admin/organization_settings` | Lecture et mise à jour des paramètres d’organisation (seuils, critiques MITRE, catalogue). |
| `POST /generate_profile_risk` | Génère ou met à jour le profil de risque utilisateur (validation MITRE, qualité, réparation optionnelle). |

---

## Flux de données (résumé)

```
Risk Analysis (seuils, actifs, MITRE)
    → required_scores par technique
    ↓
Testing (user + profile + quiz)
    → user_scores_per_thread
    ↓
Generative IA (required_scores + user_scores_per_thread)
    → testing-content (quiz)  → re-boucle vers Testing
    → learning-content (formation)  → Utilisateur
```

Les collections Mongo clés incluent notamment : `users`, `quiz_history` (avec `required_scores`, `user_scores_per_thread`), `quiz_genere`, `profile_risks` (par utilisateur : par actif, listes **`human_techniques`**, **`hybrid_techniques`**, **`non_human_techniques`** dérivées des techniques exposées), `attack_graphs`, `trainings`, `assets_catalog`, `role_assets`, paramètres d’organisation selon stockage backend.

**Techniques hybrid** : le profil de risque sépare explicitement les techniques classées **hybrid** dans `profile_risks`. Les chemins qui alimentent quiz, formation et statistiques agrègent **human + hybrid** comme menaces comportementales (ex. `get_all_techniques_from_profile_risk` dans `app.py`). Les graphes d’attaque fusionnent en pratique human et hybrid dans `human_related` ; les APIs catalogue (`/api/assets_catalog`, `/api/user/.../assets`) fusionnent aussi `hybrid_techniques` avec les techniques « comportementales » pour l’affichage.

---

## Architecture technique globale

### Frontend – Angular (`CyberForm/`)

- **Framework** : Angular.
- **Point d’entrée** : `app.module.ts` + `app-routing.module.ts`.
- **Routage principal** :
  - `/login`, `/forgot-password`, `/reset-password`
  - `/user`, `/editprofile`, `/quiz`, `/formation`, `/history-user`, `/comparaisonscore`
  - `/admin` + sous-écrans d’administration
- **Guards** :
  - `AuthGuard` : vérifie la présence du `userID` (session/localStorage) avant d’autoriser l’accès aux routes protégées.
  - `AdminGuard` : vérifie `userData.role === 'admin'` en plus ; sinon redirige vers `/login`.
  - `QuizAccessGuard` : optionnellement utilisé pour contrôler l’accès au quiz selon l’état de l’utilisateur (profil, historique, etc.).
- **Services principaux** :
  - `AuthService` : login/logout, stockage du token/session, récupération du profil de base de l’utilisateur.
  - `UserService` : gestion du profil, création d’utilisateurs (admin), mise à jour des informations.
  - `QuizService` : génération de quiz, envoi des réponses vers `/evaluate`, gestion de l’historique côté frontend.
  - `ProfileService` : interaction avec les API de profil/risque si exposées par le backend.
- **Composants clés** :
  - `LoginComponent`, `ForgotPasswordComponent`, `ResetPasswordComponent` : cycle d’authentification.
  - `UserComponent` : tableau de bord utilisateur (profil, accès aux quiz et à la formation).
  - `QuizComponent` / `ReviewQuizComponent` : affichage des questions, saisie des réponses, révision.
  - `FormationComponent` : affichage du contenu de formation HTML généré par `/generate_training`.
  - `HistoryUserComponent`, `ComparaisonScoreComponent`, `StatisticsMoisComponent` : visualisation de l’historique et des scores dans le temps.
  - `AdminComponent` : tableau de bord administrateur (liste des utilisateurs, création de comptes, accès aux statistiques globales).
- **UX** :
  - Layout commun : `HeaderComponent` + `FooterComponent` + pages de contenu.
  - Le header adapte les liens visibles selon le rôle (`utilisateur` vs `admin`).

### Backend – Flask (`backend/`)

- **Framework** : Flask.
- **Fichier principal** : `app.py`.
- **Modules auxiliaires** :
  - `generate.py` : génération de quiz et de formation (`generate_profile_risk`, sélection des cibles, prompts IA, post-traitement HTML).
  - `module.py` : graphes d’attaque, normalisation MITRE, `ensure_attack_graph_for_asset`, classification **human / hybrid / non_human** alignée sur `m.py`.
  - `profile_validation.py` : règles de cohérence des profils et graphes (diversité, bucket `non_human` vide, etc.) — voir `backend/README_PROFILE_VALIDATION.md`.
  - `m.py` : `mitre_classification`, facteur humain, libellés MITRE.
- **Technologies** :
  - **Base de données** : MongoDB (collections `profile_risks`, `risk_history`, `quiz_history`, `attack_graphs`, `trainings`, etc.).
  - **IA générative** : appel à un modèle externe (via API HTTP) pour produire questions et contenus de formation à partir du profil et de l’historique.
- **Responsabilités de `app.py`** :
  - Exposer les endpoints REST (auth, profil, risque, quiz, formation).
  - Orchestrer le flux **Analyse des risques → Test → IA → Formation**.
  - Enregistrer systématiquement les évaluations et contenus générés dans MongoDB pour traçabilité et réutilisation.

---

## Scénarios de flux détaillés

### 1. Parcours utilisateur – Pré‑quiz et formation

1. L’utilisateur se connecte via `/login` → `AuthService` stocke le `userID` et le rôle.
2. `AuthGuard` laisse accéder à `/user` :
   - Le tableau de bord propose de lancer un quiz (`/quiz`) ou de consulter l’historique / la comparaison de scores.
3. L’utilisateur lance un quiz :
   - `QuizService` appelle `POST /generate_quiz` pour récupérer un quiz personnalisé (ou un quiz “de base” si pas d’historique).
   - L’utilisateur répond aux questions, puis le frontend envoie les réponses à `POST /evaluate`.
4. Le backend :
   - Calcule `required_scores` par technique (analyse de risque).
   - Calcule `user_scores_per_thread` à partir des réponses.
   - Enregistre tout dans `quiz_history`.
   - Retourne au frontend le détail des résultats.
5. Le frontend propose alors :
   - De voir le détail du quiz (`ReviewQuizComponent`).
   - De lancer la formation : appel `POST /generate_training`.
6. `POST /generate_training` :
   - Utilise le dernier `quiz_history` (ou des paramètres passés) pour cibler les écarts les plus importants.
   - Génère du contenu HTML de formation par thread/technique.
   - Retourne ce contenu au frontend, qui l’affiche dans `FormationComponent`.

### 2. Parcours administrateur – Supervision et création de comptes

1. L’admin se connecte → redirection vers `/admin` (protégé par `AdminGuard`).
2. `AdminComponent` — **colonne de droite (onglets)** :
   - **Comparaison des scores** : `ComparaisonScoreComponent`.
   - **Seuils & objectifs** : formulaire des paramètres d’organisation (`GET` / `PUT` / `POST` `/api/admin/organization_settings`) — seuil politique, fenêtre « appris », techniques critiques MITRE, plafonds par technique (catalogue), etc.
   - **Statistiques mensuelles** : `StatisticsMoisComponent` (`GET /api/statistics/mois`).
   - **Métriques quiz (qualité)** : métriques détaillées (`GET /api/quiz_quality_metrics`, export CSV).
   Les KPI en tête de page (risque, objectifs, **formations planifiées**) s’appuient sur `GET /api/statistics` : le pourcentage « formations planifiées » compte les utilisateurs dont **`nextTrainingDate` est à venir** (date ≥ maintenant), pas seulement une date renseignée dans le passé.
3. Liste des utilisateurs (colonne gauche) : filtres (dont profil MITRE à revoir), dates d’évaluation / formation, statuts.
4. Création de comptes : `CreerUserComponent` + API admin dédiées.
5. Suivi : historique quiz (`quiz_history`), comparaisons, réglages organisationnels persistés (collection ou document d’organisation selon implémentation backend).

---

## Résumé des responsabilités par couche

- **Frontend (Angular)** :
  - Gère l’interface utilisateur, la navigation, les formulaires de quiz et de profil.
  - Implémente les guards (`AuthGuard`, `AdminGuard`, `QuizAccessGuard`) pour sécuriser la navigation.
  - Consomme les API backend pour l’authentification, l’évaluation, la génération de quiz et de formation.

- **Backend (Flask)** :
  - Fournit les endpoints métiers (`/evaluate`, `/generate_quiz`, `/generate_training`, APIs admin).
  - Implémente l’analyse de risque, le calcul des scores requis/utilisateur par thread.
  - Orchestre les appels à l’IA générative et persiste toutes les données dans MongoDB.

- **Base de données (MongoDB)** :
  - Stocke l’historique des risques et des quiz, les graphes d’attaque, les profils utilisateurs et les contenus de formation.
  - Sert de mémoire à long terme pour permettre à l’IA de personnaliser les prochains quiz et formations.
