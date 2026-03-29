# Validation du profil de risque

## Fichiers

- `profile_validation.py` — règles (entrées, graphe MITRE, diversité, facteur humain, T, risque), `compute_profile_quality_metrics`, `build_profile_repair_prompt`.
- `generate.py` — `generate_profile_risk` appelle les validateurs et enrichit le JSON retourné + persistance Mongo (`profile_risks`).
- `m.py` — `mitre_classification` (**human** / **hybrid** / **non_human**), `human_factor`, libellés `MITRE_NAMES`.

## Contraintes graphe / profil (durcies) — **facteur humain**

Le profil cible des techniques **human** et **hybrid** uniquement (comportements, erreurs, abus de comptes). Le bucket **`non_human` du graphe doit être vide** (`graph:*:non_human_bucket_interdit`).

- **Pas uniquement T1566 + T1204** : refus si les seules familles présentes sont phishing + exécution utilisateur (`graph:*:uniquement_t1566_t1204`).
- **≥ 3 techniques distinctes** par actif (`min_3_techniques_distinctes` / `exposed:*:min_3_techniques_distinctes`).
- **Au moins une technique « compte / identité »** parmi **T1078, T1110, T1550, T1098** (`technique_compte_requise_*`).
- **Maximum 1 technique de phishing** (famille **T1566**) par actif (`max_1_phishing`).
- **Aucune technique purement technique** (`mitre_classification` = `non_human`) dans le graphe ou le profil livré (`technique_purement_technique`).
- **Profils distincts** entre actifs (`diversity:profil_mitre_identique`).

Pipeline : `generate_attack_graph_with_gpt` (prompt + post-traitement), `merge_local_attack_seeds`, `inject_graph_signature_diversity`, défauts par famille **sans T1059/T1190/…**, plafond phishing dans `merge_and_enrich_techniques`. Revérification sur **`exposed_techniques`** (`validate_exposed_techniques_constraints`).

Schéma Mongo `attack_graphs` : version **1.2** ; graphes anciens avec `non_human` non vide sont **régénérés** si `regen_if_empty` (cf. `ensure_attack_graph_for_asset`).

## Taxonomie MITRE (human / hybrid / non_human)

- **Human** : bases `T1566`, `T1204`, `T1534` (ingénierie sociale / exécution utilisateur).
- **Hybrid** : comptes, identifiants, accès distant (`T1078`, `T1021`, `T1110`, `T1133`, `T1056`, `T1552`, `T1550`, `T1098`, …).
- **Non-human** : exclu du **graphe** de ce produit ; toujours filtré côté génération / validation.

Les défauts par famille d’actif et le pool de signature privilégient **human/hybrid**. Pénalités qualité si **T1078** apparaît sur **tous** les actifs (biais). `generate_profile_risk` expose toujours `human_techniques`, `hybrid_techniques` et `non_human_techniques` (souvent vide).

## Réponse `POST /generate_profile_risk`

Corps JSON optionnel : `maxProfileRepairAttempts` ou `max_profile_repair_attempts` (entier **0–3**, défaut **1**).  
Indique combien de **tours de réparation** sont autorisés après le premier calcul : à chaque tour, les graphes d’attaque de tous les actifs sont **régénérés** (`ensure_attack_graph_for_asset(..., force=True)`) puis le profil est recalculé. La boucle s’arrête dès que `profile_acceptable` est vrai ou qu’il n’y a plus de tours.

Champs ajoutés :

| Champ | Description |
|--------|-------------|
| `profile_valid` | Aucune erreur structurelle / calcul |
| `profile_acceptable` | Score qualité ≥ seuil (55) + pas d’erreurs bloquantes |
| `validation_errors` | Liste de codes d’erreur |
| `validation_warnings` | Alertes (biais MITRE, T, human_factor, etc.) |
| `profile_quality_metrics` | Score 0–100, compteurs MITRE, ratios, variances… |
| `repair_attempts` | Index du dernier passage exécuté (0 = premier calcul seul, 1 = une réparation, etc.) |

## Lecture

`GET /api/profile_quality/<userID>` — dernier document `profile_risks` (métriques + erreurs).

## Admin

`GET /api/users` inclut `profile_acceptable` et `profile_quality_score` (depuis `profile_risks`). Filtre **« Profil à revoir »** : collaborateurs avec `profile_acceptable === false`.

## Boucle de réparation

`build_profile_repair_prompt(errors, profile_preview)` produit un prompt pour régénérer un graphe ; à brancher sur `generate_attack_graph_with_gpt` ou un flux dédié.

## Pré-génération

Échec → `ValueError` avec message listant les problèmes (`input:*`).
