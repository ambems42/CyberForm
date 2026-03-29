# Pipeline formation (aligné sur le quiz)

## Comportement

1. **Blueprint par module** (`build_training_module_blueprint`) : `technique_id` / `technique_name` canoniques (`m.MITRE_NAMES`), niveau Bloom cyclique, actif, contexte pré/post.
2. **Génération JSON** (GPT) : menace, exemple réel, indicateurs de détection, mitigations, résultats mesurables, question d’auto-évaluation orientée **application**.
3. **Autorité du plan** : `technique_id` / `technique_name` réinjectés depuis le blueprint (comme le quiz).
4. **Validation structurelle** : longueurs minimales, listes complètes, citation de l’ID MITRE dans les textes clés.
5. **Score qualité heuristique** 0–100 (`compute_training_module_quality_metrics`).
6. **Boucle de réparation** : jusqu’à `TRAINING_GPT_MAX_ATTEMPTS` avec prompt de correction (comme `_build_quiz_repair_prompt`).
7. **Seuil d’acceptation** : si score ≥ `TRAINING_MIN_QUALITY_SCORE` (défaut **70**), sortie anticipée ; sinon meilleur essai valide conservé (comme le quiz avec `quality_below_threshold`).
8. **Validateur GPT optionnel** : si `TRAINING_GPT_VALIDATOR=1`, second appel LLM qui note le module ; fusion **55 %** heuristique + **45 %** score `overall`.

## Variables d’environnement

| Variable | Défaut | Rôle |
|----------|--------|------|
| `TRAINING_MIN_QUALITY_SCORE` | `70` | Cible minimale pour terminer la boucle tôt par module. |
| `TRAINING_GPT_MAX_ATTEMPTS` | `3` | Tentatives GPT + réparation par module. |
| `TRAINING_GPT_VALIDATOR` | `0` | `1` / `true` : active le juge GPT profond (coût API ×2 par module validé). |

## API `/generate_training`

Réponse enrichie : `quality_metrics`, `training_blueprint`, `learning_summary` (notes sur mesure pré/post et alignement post-test). Mongo `trainings` stocke aussi ces champs.

## API `GET /api/user_with_history/:userID`

Réponse enrichie : `lastTrainingMeta` (dernier document `trainings` : `quality_metrics`, `learning_summary`, `training_blueprint`, `quiz_type`, `date`) pour affichage admin / page Formation sans repasser par localStorage.

## Mesure d’apprentissage (piste produit)

- Comparer **quiz pré vs post** et erreurs par `technique_id` (déjà dans `quiz_history` / profils).
- Les métriques formation exposent le **score qualité par module** ; un tableau de bord peut croiser avec les mêmes techniques au quiz post.
