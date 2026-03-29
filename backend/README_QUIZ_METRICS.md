# Métriques qualité quiz

## Variables d’environnement

| Variable | Défaut | Rôle |
|----------|--------|------|
| `QUIZ_MIN_QUALITY_SCORE` | `70` | Si le score heuristique reste **strictement inférieur** après toutes les tentatives, le quiz est quand même livré (meilleur des essais) avec `quality_below_threshold: true`. Entre deux générations complètes, on garde le **meilleur** score. |
| `QUIZ_MAX_QUALITY_REGEN` | `1` | Nombre de **régénérations** en plus de la première (ex. `1` ⇒ au plus 2 appels à `generate_quiz`). |

## API

- `GET /api/quiz_quality_metrics?userID=&limit=100` — JSON (`items`, `count`).
- `GET /api/quiz_quality_metrics.csv?userID=&limit=200` — CSV (UTF-8 avec BOM pour Excel).

Mongo : champs dans `quiz_genere.quality_metrics` (score, seuil, tentatives, etc.).

## Interface admin (Angular)

Dans l’app : route **`/admin`** → onglet **« Métriques quiz (qualité) »**.  
Les données sont chargées via `QuizService.getQuizQualityMetrics()` (même schéma que l’API ci-dessus).  
Le bouton **« Télécharger CSV »** ouvre `GET /api/quiz_quality_metrics.csv` avec les mêmes filtres (`userID`, `limit`).
