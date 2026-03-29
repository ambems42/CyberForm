# Axes d'amélioration (CyberForm) — référence mémoire

Ce document formalise les limites actuelles et les pistes d'évolution, alignées sur le code existant (`generate.py`, `module.py`, `m.py`, Mongo `attack_graphs`).

---

## 1. Dépendance aux graphes GPT

**Constat**  
Les techniques par actif reposent encore largement sur la génération / enrichissement GPT (`generate_attack_graph_with_gpt`, `ensure_attack_graph_for_asset` dans `module.py`), avec persistance en collection **`attack_graphs`**.  
- **Atouts** : flexibilité, scénarios variés, adaptation au rôle / à l'actif.  
- **Risques résiduels** : biais de répétition (mêmes familles TTP), coût / latence des appels — même avec validation et graines locales.

**Déjà en place (implémenté)**  
- **Canonisation MITRE** : `canonicalize_mitre_id` + `MITRE_ID_PATTERN` dans `m.py` ; tout ID doit exister dans `MITRE_NAMES` (sinon **rejet** ; sous-technique absente mais **parent** présent → remappage avec `inferred_parent` + `original_technique_id`). Utilisé par `normalize_mitre_technique` (`module.py`) et `normalize_technique` dans `generate_profile_risk` (`generate.py`).  
- **Traçabilité Mongo** : champ **`graph_meta`** sur les documents `attack_graphs` : `graph_version` (`ATTACK_GRAPH_SCHEMA_VERSION`), `llm_model`, `prompt_sha256`, `source` (`gpt` \| `fallback`).  
- **Graphe hybride (minimal)** : `merge_local_attack_seeds` — TTP figées (ex. T1190 pour SIEM / firewall ; T1566.002 pour email) fusionnées avec la sortie GPT, sans doublon.  
- **Classification `hybrid`** : regroupée avec `human` dans `human_related` pour le graphe.  
- **Contrôle qualité profil** : `profile_validation.py` + cache graphe dans `ensure_attack_graph_for_asset`.
- **Rôle métier dans le prompt** : la consigne canonique « profil de risque MITRE ATT&CK réaliste et diversifié… » est dans `system_msg` ; le **`jobRole`** de l’utilisateur est passé à `generate_attack_graph_with_gpt` / `ensure_attack_graph_for_asset` depuis `generate_profile_risk` pour adapter les TTP (nom, rôle, tags).

**Pistes restantes (priorité)**  
| Priorité | Piste | Détail |
|----------|--------|--------|
| Haute | **Matrice locale étendue** | Table **`asset_family` × TTP** (catalogue) et règles métier pour enrichir / remplacer les graines codées en dur. |
| Moyenne | **Réduction des appels GPT** | « Packs » TTP par famille d'actif ; GPT seulement pour reformulation ou compléments contraints. |
| Moyenne | **Rejeu / audit** | Exploiter `prompt_sha256` pour invalider le cache ou comparer deux générations. |
| Basse | **UI / admin** | Afficher `graph_meta` et `inferred_parent` côté support. |

**Fichiers concernés** : `module.py`, `m.py`, `generate.py`, `profile_validation.py`, collection `attack_graphs`.

---

## 2. Du filtrage humain binaire au score continu

**Constat (historique)**  
Les ensembles `HUMAN_TECHNIQUES` / `NON_HUMAN_TECHNIQUES` dans `m.py` imposaient une **décision tranchée** ; peu adapté aux techniques **hybrides** (comptes valides, MFA, matériel d'authentification).

**État actuel du code**  
- **Classification trinaire** : `mitre_classification(tid, name, desc)` → `human` | `hybrid` | `non_human` à partir des bases `PURE_HUMAN_TECHNIQUE_BASES`, `HYBRID_TECHNIQUE_BASES`, `NON_HUMAN_TECHNIQUES` et de **mots-clés** sur le texte GPT (repli si ID inconnu).  
- **Score continu** : `MITRE_HUMAN_FACTOR` et **`human_factor(tid)`** ∈ [0, 1] dans `m.py` (valeurs tabulaires pour les TTP clés, défauts dérivés de la classe).  
- **Intégration** : `module.py` s'aligne sur `mitre_classification` ; les entrées **`human_techniques`** / **`hybrid_techniques`** dans `generate_profile_risk` exposent `classification` et **`human_factor`** (le produit **V×I×T** reste inchangé pour l'instant).

**Pistes restantes**  
- **Pondération risque** : utiliser `human_factor` (ou un sous-score « exposition humaine ») dans une **métrique dérivée** (ex. risque « RH » vs « technique ») sans casser la comparaison historique du V×I×T, ou offrir les **deux** vues.  
- **Contexte** : étendre le score à la **paire (technique × actif)** ou au **poste** (`jobRole`) si les données le permettent.  
- **Quiz / formation** : filtrer ou prioriser les questions selon `human_factor` ou `classification` (ex. poids plus fort sur les TTP à fort facteur humain pour les profils métiers exposés).

**Fichiers concernés** : `m.py` (`mitre_classification`, `MITRE_HUMAN_FACTOR`, `human_factor`), `module.py`, `generate.py` (`generate_profile_risk`), `profile_validation.py` (cohérence et diversité).

---

## 3. Distribution limitée des techniques (ex. T1566, T1204)

**Constat**  
Les prompts et le comportement du modèle favorisent souvent les mêmes TTP « visibles » (phishing, exécution utilisateur).

**Pistes**  
- **Diversification contrôlée** : tirage pondéré dans `HUMAN_TECHNIQUES` (ou sous-ensemble par vertical IoT) lors de la construction / complétion du graphe.  
- **Contraintes dans le prompt** : « au moins N familles distinctes », « interdiction de répéter 2× la même sous-technique sur 2 actifs ».  
- **Données externes** : top TTP du secteur (rapports ANSSI, MITRE campaigns) injectés comme liste obligatoire de candidats.

**Fichiers concernés** : `module.py` (prompts `generate_attack_graph_with_gpt`, `ensure_attack_graph_for_asset`), `generate.py` (`select_quiz_targets`, `build_quiz_blueprint`).

---

## 4. Score **T** encore heuristique

**Constat**  
`T` (menace / technique, 0–1) reste une **estimation** : ce n’est pas une probabilité d’exploitation mesurée sur le terrain. Elle combine plusieurs sources (GPT, défauts numériques).

**Déjà en place (code)**  
- **Graphe** : chaque technique porte un `T` (souvent ~0,6 côté GPT) ; le graphe expose aussi un **`threat_score`** agrégé (défaut 0,6 si absent).  
- **Table `T_BASE`** dans `generate_profile_risk` (`generate.py`) : références par **base** MITRE (ex. T1566 → 0,72). Le `T` retenu vient du graphe normalisé, puis `T_BASE[tid_base]` si défini, sinon **`threat_score`**. Si la base est dans `T_BASE` et que le `T` du graphe **s’écarte de plus de 0,35** de cette référence, la **référence** l’emporte.  
- **Validation** : `T_BASE_LOCAL` dans `profile_validation.py` (mêmes ordres de grandeur) pour `validate_t_scores`.  
- **Risque** : `compute_risk_metrics(V, impact, T, hf)` — si **V = 0**, risque brut = **`impact × T`** ; si **V > 0**, le produit inclut une **`effective_weight`** dérivée de **`human_factor`** (`0,30 + 0,70 × hf`), donc pondération humaine **en plus** de `T`.

**Pistes restantes**  
- **Étendre / documenter `T_BASE`** : plus de bases, calibration externe (ANSSI, ENISA) avec version de table.  
- **Unifier** : une seule source `T_BASE` / `T_BASE_LOCAL` (import partagé) pour éviter les divergences.  
- **Données opérationnelles** : ajuster `T` via incidents, agrégats quiz, SIEM (long terme).  
- **Transparence** : indiquer côté API / UI que `T` est une **estimation** ; optionnel : bornes pessimiste / optimiste.

**Fichiers concernés** : `generate.py` (`generate_profile_risk`, `compute_risk_metrics`, `T_BASE`), `profile_validation.py` (`T_BASE_LOCAL`, `validate_t_scores`), `module.py` (T dans le graphe).

---

## Synthèse pour le mémoire

| Axe | Limite résiduelle | Direction |
|-----|-------------------|-----------|
| Graphes | Matrice TTP × actif encore partielle (graines) | Packs par `asset_family`, moins d'appels LLM |
| Humain | Risque brut déjà pondéré par `hf` si V>0 ; pas de vue « RH » séparée | Métrique dérivée dédiée, quiz/formation, score contextuel |
| Diversité | Répétition TTP | Règles + pondération + sources externes |
| T | Toujours pas une mesure terrain ; `T_BASE` partielle | Unifier tables, enrichir calibration, transparence utilisateur |

## Implémentation « profil = génération + contrôle » (référence)

Module `profile_validation.py` + intégration dans `generate_profile_risk` : validation des entrées (user, jobRole, actifs catalogue, CIA), structure du graphe (ID MITRE, CIA, T, doublons), pertinence par famille d'actif (`ASSET_FAMILY_EXPECTED_BASES`), anti-biais (diversité, paires dominantes), cohérence `human_factor`, contrôle des T vs `T_BASE_LOCAL`, cohérence V×I×T, score qualité 0–100, champs `profile_valid` / `profile_acceptable`, stockage dans `profile_risks`. Voir `README_PROFILE_VALIDATION.md`.

*Document généré pour structurer la discussion scientifique et la feuille de route produit ; à mettre à jour au fil des implémentations.*
