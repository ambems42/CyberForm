import re, unicodedata, string, json, re, traceback, os, html as html_escape
from datetime import datetime, timezone
from extensions import mongo
from collections import Counter
from difflib import SequenceMatcher
from module import ensure_attack_graph_for_asset, inject_graph_signature_diversity
from m import MITRE_NAMES, canonicalize_mitre_id, human_factor, mitre_classification
from technique_cia import get_cia_for_technique
from profile_validation import (
    validate_profile_inputs,
    validate_attack_graph_structure,
    validate_asset_technique_relevance,
    validate_mitre_diversity,
    validate_human_factor_consistency,
    validate_t_scores,
    validate_risk_calculations,
    compute_profile_quality_metrics,
    profile_acceptable,
    validate_unique_asset_profiles,
    validate_exposed_techniques_constraints,
)

from openai_client import client

POST_TRAINING_PASS_THRESHOLD = 80

# --- Formation : même esprit que le quiz (blueprint, validation, score, réparation) ---
TRAINING_GPT_MAX_ATTEMPTS = int(os.environ.get("TRAINING_GPT_MAX_ATTEMPTS", "3"))
TRAINING_MIN_QUALITY_SCORE = float(os.environ.get("TRAINING_MIN_QUALITY_SCORE", "70"))
MIN_TRAINING_THREAT_CHARS = 80
MIN_TRAINING_EXAMPLE_CHARS = 55
MIN_TRAINING_LIST_ITEM_CHARS = 15
MIN_TRAINING_DETECTION_ITEMS = 3
MIN_TRAINING_MITIGATION_ITEMS = 3
MIN_TRAINING_OUTCOMES = 2
MIN_TRAINING_SELF_CHECK_CHARS = 25
TRAINING_BLOOM_CYCLE = ["remember", "understand", "apply", "analyze"]

# --- Adaptation formation : critique / stricte vs faible / légère (aligné esprit evaluate & org_settings) ---
TRAINING_DEFAULT_CRITICAL_BASES = frozenset({
    "T1566", "T1566.001", "T1566.002", "T1566.003",
    "T1586", "T1587", "T1588",
    "T1539", "T1542", "T1543",
})
TRAINING_STRICT_RISK_SIGNAL = float(os.environ.get("TRAINING_STRICT_RISK_SIGNAL", "0.44"))
TRAINING_STRICT_THREAT_T = float(os.environ.get("TRAINING_STRICT_THREAT_T", "0.58"))
TRAINING_STRICT_WRONG_COUNT = int(os.environ.get("TRAINING_STRICT_WRONG_COUNT", "2"))

# Mode léger : seuils validation légèrement plus bas (prompt demande moins de verbosité)
TRAINING_LIGHT_MIN_THREAT_CHARS = int(os.environ.get("TRAINING_LIGHT_MIN_THREAT_CHARS", "58"))
TRAINING_LIGHT_MIN_EXAMPLE_CHARS = int(os.environ.get("TRAINING_LIGHT_MIN_EXAMPLE_CHARS", "42"))

# MITRE ATT&CK : identifiant technique (Txxxx ou Txxxx.xxx)
MITRE_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4,5}(?:\.\d{3})?$", re.IGNORECASE)

# Progression Bloom (10 questions) : cycle pédagogique explicite avant GPT
BLOOM_LEVELS_10 = [
    "remember", "understand", "apply", "analyze",
    "remember", "understand", "apply", "analyze",
    "apply", "analyze",
]
BLOOM_LABELS_FR = {
    "remember": "Se souvenir / reconnaître un indicateur",
    "understand": "Comprendre la menace et ses conséquences",
    "apply": "Appliquer : choisir la bonne action concrète",
    "analyze": "Analyser : comparer des options ou évaluer un risque",
}


def normalize_devices(dev_list):
    """lower + trim + dédup + tri pour stabiliser la clé Mongo."""
    return sorted({str(d).strip().lower() for d in (dev_list or []) if str(d).strip()})

def normalize_text(text: str) -> str:
    text = ''.join(
        c for c in unicodedata.normalize('NFD', text)
        if unicodedata.category(c) != 'Mn'
    )
    text = text.translate(str.maketrans('', '', string.punctuation))
    return text.lower().strip()


def is_similar(a: str, b: str, threshold: float = 0.75) -> bool:
    a_norm = normalize_text(a)
    b_norm = normalize_text(b)
    ratio = SequenceMatcher(None, a_norm, b_norm).ratio()
    return ratio >= threshold


def clean_api_response(response):
    if isinstance(response, list):
        response = "\n".join(
            str(item) if isinstance(item, str) else item.get("text", "")
            for item in response
            if isinstance(item, (str, dict))
        )

    lines = response.strip().split("\n")
    cleaned_lines = []

    for line in lines:
        line = line.strip()
        # Supprime les phrases inutiles
        if line.lower().startswith(
            ("bien sûr", "voici", "réponse :", "réponses :", "bonne réponse")
        ):
            continue
        cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def norm_list(items):
    """lower+trim + dédup + tri ; retourne une liste stable pour la clé Mongo."""
    seen = {}
    for it in items or []:
        s = str(it or "").strip()
        if not s:
            continue
        k = s.lower()
        if k not in seen:
            seen[k] = s
    return [seen[k] for k in sorted(seen.keys())]

def select_quiz_targets(user_id, quiz_type="pre", human_threats=None, max_questions=10, required_scores=None):
    """
    Retourne toujours exactement max_questions cibles.
    Pré :
      - techniques humaines les plus probables pour ce profil
      - si required_scores est fourni, on répartit les questions selon ces poids
    Post :
      - techniques mal répondues avant
      - techniques à plus haut risque
      - erreurs fréquentes
      - filtrées pour rester cohérentes avec le profil de risque
      - si required_scores est fourni, on force la répartition
    """
    if human_threats is None:
        human_threats = []
    if required_scores is None:
        required_scores = []

    max_questions = 10
    targets = []

    def complete_to_ten(base_targets, source_name):
        completed = list(base_targets)

        if not completed:
            return []

        i = 0
        while len(completed) < max_questions:
            src = dict(completed[i % len(base_targets)])
            src["rank"] = len(completed) + 1
            src["source"] = source_name
            src["priority_reason"] = (
                src.get("priority_reason", "") + " | variante complémentaire"
            ).strip(" |")  
            completed.append(src)
            i += 1

        return completed[:max_questions]

    def normalize_required_scores(required_scores):
        """
        Accepte une liste comme :
        [
          {"threadId": "T1566", "required_score": 4},
          {"threadId": "T1115", "required_score": 3}
        ]
        """
        result = {}

        if not isinstance(required_scores, list):
            return result

        for item in required_scores:
            if not isinstance(item, dict):
                continue

            tid = (
                item.get("threadId")
                or item.get("technique_id")
                or item.get("techniqueId")
                or ""
            )
            tid = str(tid).strip().upper()
            if not tid:
                continue

            score = (
                item.get("required_score")
                or item.get("requiredScore")
                or item.get("score")
                or item.get("count")
                or 0
            )

            try:
                score = int(score)
            except Exception:
                score = 0

            if score > 0:
                result[tid] = score

        return result

    # PRE-QUIZ
    if quiz_type == "pre":
        ranked_human = []

        for t in human_threats:
            if not isinstance(t, dict):
                continue

            ranked_human.append({
                "technique_id": str(t.get("technique_id") or t.get("id") or "NA").strip().upper(),
                "technique_name": t.get("technique_name") or t.get("name") or "",
                "asset_id": t.get("asset_id") or "",
                "asset_name": t.get("asset_name") or "",
                "threat_score": float(t.get("threat_score", t.get("T", 0.0)) or 0.0),
                "risk_local": float(t.get("risk_local", 0.0) or 0.0),
                "priority_reason": "Technique humaine probable pour ce profil"
            })

        ranked_human.sort(
            key=lambda x: (x["risk_local"], x["threat_score"]),
            reverse=True
        )

        # Utiliser required_scores si fourni
        rs_map = normalize_required_scores(required_scores)

        if rs_map:
            by_tid = {}
            for item in ranked_human:
                tid = item["technique_id"]
                if tid not in by_tid:
                    by_tid[tid] = item

            distributed = []
            for tid, count in rs_map.items():
                if tid not in by_tid:
                    continue

                for _ in range(count):
                    distributed.append(dict(by_tid[tid]))

            if distributed:
                ranked_human = distributed

        for i, t in enumerate(ranked_human[:max_questions], start=1):
            targets.append({
                "rank": i,
                "source": "human_threats_profile",
                "priority_reason": t["priority_reason"],
                "technique_id": t["technique_id"],
                "technique_name": t["technique_name"],
                "asset_id": t["asset_id"],
                "asset_name": t["asset_name"],
                "threat_score": t["threat_score"],
                "risk_local": t["risk_local"],
                "wrong_count": 0
            })

        targets = complete_to_ten(targets, "human_threats_profile_completed")
        return targets[:max_questions]

    # POST-QUIZ

    wrong_counter = Counter()
    risk_map = {}
    meta_map = {}

    # 1) quiz précédent : réponses mal répondues
    last_pre = mongo.db.quiz_history.find_one(
        {"userID": user_id, "quiz_type": "pre"},
        sort=[("date", -1)]
    ) or {}

    previous_answers = last_pre.get("answers", []) or []
    for ans in previous_answers:
        if not isinstance(ans, dict):
            continue
        if ans.get("is_correct") is True:
            continue

        tid = ans.get("technique_id") or ans.get("techniqueId")
        if not tid:
            continue

        tid = str(tid).strip().upper()
        wrong_counter[tid] += 1

        meta_map[tid] = {
            "technique_name": ans.get("technique_name") or ans.get("techniqueName") or "",
            "asset_id": ans.get("asset_id") or "",
            "asset_name": ans.get("asset_name") or ""
        }

    # 2) risques humains élevés depuis profile_risks
    profil_risque = mongo.db.profile_risks.find_one({"userID": user_id}) or {}
    assets = profil_risque.get("assets", []) or []

    for a in assets:
        if not isinstance(a, dict):
            continue

        asset_id = a.get("asset_id") or ""
        asset_name = a.get("asset_name") or ""

        ht = a.get("human_techniques") or []
        hb = a.get("hybrid_techniques") or []
        if isinstance(ht, dict):
            ht = [ht]
        if isinstance(hb, dict):
            hb = [hb]
        if not isinstance(ht, list):
            ht = []
        if not isinstance(hb, list):
            hb = []

        for t in ht + hb:
            if not isinstance(t, dict):
                continue

            tid = t.get("technique_id") or t.get("id")
            if not tid:
                continue

            tid = str(tid).strip().upper()
            risk_local = float(t.get("risk_local", 0.0) or 0.0)
            risk_map[tid] = max(risk_map.get(tid, 0.0), risk_local)

            if tid not in meta_map:
                meta_map[tid] = {
                    "technique_name": t.get("technique_name") or t.get("name") or "",
                    "asset_id": asset_id,
                    "asset_name": asset_name
                }

    # 3) erreurs fréquentes sur historique récent
    hist = mongo.db.quiz_history.find(
        {"userID": user_id},
        {"answers": 1}
    ).sort("date", -1).limit(10)

    for doc in hist:
        answers_hist = doc.get("answers", []) or []
        for ans in answers_hist:
            if not isinstance(ans, dict):
                continue
            if ans.get("is_correct") is True:
                continue

            tid = ans.get("technique_id") or ans.get("techniqueId")
            if not tid:
                continue

            tid = str(tid).strip().upper()
            wrong_counter[tid] += 1

            if tid not in meta_map:
                meta_map[tid] = {
                    "technique_name": ans.get("technique_name") or ans.get("techniqueName") or "",
                    "asset_id": ans.get("asset_id") or "",
                    "asset_name": ans.get("asset_name") or ""
                }

    all_tids = set(wrong_counter.keys()) | set(risk_map.keys())

    # Limiter strictement aux techniques présentes dans le profil de risque
    allowed_tids = set(risk_map.keys())
    if not allowed_tids and human_threats:
        for t in human_threats:
            if not isinstance(t, dict):
                continue
            tid_allowed = t.get("technique_id") or t.get("id")
            if tid_allowed:
                allowed_tids.add(str(tid_allowed).strip().upper())

    ranked = []
    for tid in all_tids:
        # Si une whitelist existe, ignorer les techniques hors profil
        if allowed_tids and tid not in allowed_tids:
            continue
        meta = meta_map.get(tid, {})
        ranked.append({
            "technique_id": tid,
            "technique_name": meta.get("technique_name", ""),
            "asset_id": meta.get("asset_id", ""),
            "asset_name": meta.get("asset_name", ""),
            "wrong_count": wrong_counter.get(tid, 0),
            "risk_local": risk_map.get(tid, 0.0),
            "priority_reason": "Erreur fréquente / mal répondu avant / risque élevé"
        })

    ranked.sort(
        key=lambda x: (x["wrong_count"], x["risk_local"]),
        reverse=True
    )

    # Utiliser required_scores si fourni
    rs_map = normalize_required_scores(required_scores)
    if rs_map:
        by_tid = {}
        for item in ranked:
            tid = item["technique_id"]
            if tid not in by_tid:
                by_tid[tid] = item

        distributed = []
        for tid, count in rs_map.items():
            if tid not in by_tid:
                continue

            for _ in range(count):
                distributed.append(dict(by_tid[tid]))

        if distributed:
            ranked = distributed

    for i, item in enumerate(ranked[:max_questions], start=1):
        targets.append({
            "rank": i,
            "source": "post_priority_mix",
            "priority_reason": item["priority_reason"],
            "technique_id": item["technique_id"],
            "technique_name": item["technique_name"],
            "asset_id": item["asset_id"],
            "asset_name": item["asset_name"],
            "threat_score": 0.0,
            "risk_local": item["risk_local"],
            "wrong_count": item["wrong_count"]
        })

    if not targets:
        fallback_pre = []
        for t in human_threats:
            if not isinstance(t, dict):
                continue

            fallback_pre.append({
                "rank": len(fallback_pre) + 1,
                "source": "post_fallback_human_profile",
                "priority_reason": "Fallback post basé sur menaces humaines du profil",
                "technique_id": str(t.get("technique_id") or t.get("id") or "NA").strip().upper(),
                "technique_name": t.get("technique_name") or t.get("name") or "",
                "asset_id": t.get("asset_id") or "",
                "asset_name": t.get("asset_name") or "",
                "threat_score": float(t.get("threat_score", t.get("T", 0.0)) or 0.0),
                "risk_local": float(t.get("risk_local", 0.0) or 0.0),
                "wrong_count": 0
            })

        fallback_pre.sort(
            key=lambda x: (x["risk_local"], x["threat_score"]),
            reverse=True
        )

        targets = fallback_pre[:max_questions]

    targets = complete_to_ten(targets, "post_priority_mix_completed")
    return targets[:max_questions]

def _sanitize_mitre_id_for_blueprint(raw_id: str, fallback_name: str = "") -> str:
    """
    Garantit un technique_id au format MITRE plausible pour le blueprint.
    Si invalide, retourne 'NA' (le prompt interdira NA côté génération si possible).
    """
    if not raw_id:
        return "NA"
    s = str(raw_id).strip().upper()
    if MITRE_TECHNIQUE_ID_PATTERN.match(s):
        return s
    return "NA"


def build_quiz_blueprint(user_profile, quiz_type="pre", targets=None):
    """
    Construit le plan détaillé du quiz, question par question.
    Force exactement 10 questions.

    Contraintes scientifiques / pédagogiques (avant appel GPT) :
    - technique_id MITRE validé ou marqué NA
    - structure Bloom (remember → understand → apply → analyze) sur 10 questions
    - consigne d'actionnabilité par question (verbes opérationnels)
    """
    if targets is None:
        targets = []

    if not isinstance(targets, list):
        targets = []

    user_id = user_profile.get("userID", "unknown")
    job_role = user_profile.get("jobRole", "")
    qualifications = user_profile.get("qualifications", [])
    responsibilities = user_profile.get("keyResponsibilities", [])

    # Forcer exactement 10 targets
    max_questions = 10

    if len(targets) == 0:
        raise ValueError("Aucune target disponible pour construire le blueprint.")

    if len(targets) < max_questions:
        base_targets = list(targets)
        i = 0
        while len(targets) < max_questions:
            cloned = dict(base_targets[i % len(base_targets)])
            targets.append(cloned)
            i += 1

    targets = targets[:max_questions]

    blueprint = []

    for idx, t in enumerate(targets, start=1):
        # Ne pas alterner bêtement QCM/VF : apply & analyze exigent presque toujours
        # un QCM (choix d'action, comparaison d'options). Un V/F sur « laquelle des… » est incohérent.
        bloom = BLOOM_LEVELS_10[idx - 1] if idx <= len(BLOOM_LEVELS_10) else "apply"
        if bloom in ("analyze", "apply"):
            qtype = "qcm"
        else:
            # remember / understand : alterner pour garder des V/F pédagogiques (affirmation nette)
            qtype = "qcm" if idx % 2 == 1 else "vf"

        tid_raw = t.get("technique_id") or t.get("id") or "NA"
        tname_raw = (t.get("technique_name") or t.get("name") or "").strip()
        tid = _sanitize_mitre_id_for_blueprint(tid_raw, tname_raw)
        tname = tname_raw
        if tid != "NA":
            base = tid.split(".")[0]
            tname = MITRE_NAMES.get(tid) or MITRE_NAMES.get(base) or tname_raw or base

        bloom_label_fr = BLOOM_LABELS_FR.get(bloom, BLOOM_LABELS_FR["apply"])

        # Actionnable : verbes attendus selon le niveau Bloom (consigne pour GPT)
        action_hints = {
            "remember": "L'utilisateur doit identifier ou reconnaître un signal / une tactique liée à la technique.",
            "understand": "L'utilisateur doit expliquer pourquoi la situation est dangereuse ou quel est l'enjeu.",
            "apply": "L'utilisateur doit choisir UNE action concrète à entreprendre (refuser, signaler, vérifier, isoler, etc.).",
            "analyze": "L'utilisateur doit comparer des options ou évaluer la meilleure réponse face au scénario.",
        }
        if qtype == "vf":
            # « Comprendre » + VF : ne pas demander « expliquer pourquoi » en texte (incompatible avec Vrai/Faux).
            actionability_requirement = (
                f"Niveau Bloom « {bloom} » ({bloom_label_fr}). "
                "Vrai/Faux : une seule proposition (affirmation) sur la technique ou ses conséquences, jugeable Vrai ou Faux. "
                "Interdit de commencer la question par « Pourquoi », « Comment », « En quoi », « Quels », « Quelle » "
                "(quiz pré et post : même règle)."
            )
        else:
            actionability_requirement = action_hints.get(bloom, action_hints["apply"])

        blueprint.append({
            "question_index": idx,
            "question_id": f"{user_id}_{quiz_type}_{idx}",
            "quiz_type": quiz_type,
            "question_type": qtype,
            "job_role": job_role,
            "qualifications": qualifications,
            "responsibilities": responsibilities,
            "technique_id": tid,
            "technique_name": tname,
            "asset_id": t.get("asset_id", ""),
            "asset_name": t.get("asset_name", ""),
            "priority_reason": t.get("priority_reason", ""),
            "risk_local": t.get("risk_local", 0.0),
            "wrong_count": t.get("wrong_count", 0),
            # --- Contraintes pédagogiques (pré-GPT) ---
            "bloom_level": bloom,
            "bloom_label_fr": bloom_label_fr,
            "pedagogical_structure": "scenario_obligatoire + question_centree_technique + reponse_actionnable",
            "actionability_requirement": actionability_requirement,
            "mitre_constraint": (
                "Chaque question DOIT porter explicitement sur technique_id / technique_name ci-dessus ; "
                "interdit de remplacer par une autre technique MITRE."
            ),
        })

    return blueprint

    
def parse_questions(raw_text):
    """
    Parse et normalise les questions générées par GPT.
    """

    def _safe_str(v, default=""):
        if v is None:
            return default
        return str(v).strip()

    def _normalize_type(value):
        v = _safe_str(value).lower()
        if v in ("vf", "vrai/faux", "truefalse", "true_false", "boolean"):
            return "vf"
        return "qcm"

    def _normalize_choices(choices, q_type):
        if q_type == "vf":
            return ["Vrai", "Faux"]

        if not isinstance(choices, list):
            return []

        cleaned = []
        for c in choices:
            s = _safe_str(c)
            if s:
                cleaned.append(s)

        result = []
        seen = set()
        for c in cleaned:
            key = c.lower()
            if key not in seen:
                seen.add(key)
                result.append(c)

        return result[:4]

    def _normalize_correct_answer(correct, choices, q_type):
        correct = _safe_str(correct)

        if q_type == "vf":
            lc = correct.lower()
            if lc in ("vrai", "true", "v", "1"):
                return "Vrai"
            if lc in ("faux", "false", "f", "0"):
                return "Faux"
            return "Vrai"

        if not correct:
            return choices[0] if choices else ""

        letter_map = {"a": 0, "b": 1, "c": 2, "d": 3}
        if len(correct) == 1 and correct.lower() in letter_map:
            idx = letter_map[correct.lower()]
            if 0 <= idx < len(choices):
                return choices[idx]

        for c in choices:
            if c.strip().lower() == correct.strip().lower():
                return c

        return correct

    def _extract_json_block(text):
        text = text.strip()

        if text.startswith("[") and text.endswith("]"):
            return text

        if text.startswith("{") and text.endswith("}"):
            return text

        match_array = re.search(r"\[\s*\{.*\}\s*\]", text, flags=re.DOTALL)
        if match_array:
            return match_array.group(0)

        match_obj = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match_obj:
            return match_obj.group(0)

        return text

    text = _safe_str(raw_text)
    text = _extract_json_block(text)

    try:
        data = json.loads(text)
    except Exception:
        return []

    if isinstance(data, dict):
        if isinstance(data.get("questions"), list):
            data = data["questions"]
        elif isinstance(data.get("quiz"), list):
            data = data["quiz"]
        elif isinstance(data.get("generated_quiz"), list):
            data = data["generated_quiz"]
        else:
            data = [data]

    if not isinstance(data, list):
        return []

    normalized = []

    for i, q in enumerate(data, start=1):
        if not isinstance(q, dict):
            continue

        question_id = (
            q.get("question_id")
            or q.get("questionId")
            or q.get("id")
            or f"q_{i}"
        )
        question_id = _safe_str(question_id, f"q_{i}")

        question = _safe_str(
            q.get("question")
            or q.get("text")
            or q.get("texte")
        )

        scenario = _safe_str(
            q.get("scenario")
            or q.get("mise_en_situation")
            or q.get("context")
        )

        q_type = _normalize_type(
            q.get("type")
            or q.get("qtype")
        )

        choices = (
            q.get("choices")
            or q.get("options")
            or q.get("reponses")
            or q.get("answers")
            or []
        )
        choices = _normalize_choices(choices, q_type)

        correct_answer = _normalize_correct_answer(
            q.get("correct_answer")
            or q.get("correctAnswer")
            or q.get("correct")
            or q.get("bonne_reponse")
            or q.get("answer"),
            choices,
            q_type
        )

        technique_id = _safe_str(
            q.get("technique_id")
            or q.get("techniqueId")
            or "NA"
        )

        technique_name = _safe_str(
            q.get("technique_name")
            or q.get("techniqueName")
        )

        asset_id = _safe_str(
            q.get("asset_id")
            or q.get("assetId")
        )

        if not question:
            continue

        if q_type == "qcm" and len(choices) < 2:
            continue

        normalized.append({
            "question_id": question_id,
            "questionId": question_id,
            "id": question_id,
            "question": question,
            "scenario": scenario,
            "choices": choices,
            "options": choices,
            "correct_answer": correct_answer,
            "type": q_type,
            "technique_id": technique_id,
            "techniqueId": technique_id,
            "technique_name": technique_name,
            "techniqueName": technique_name,
            "asset_id": asset_id
        })

    return normalized

def enrich_questions(parsed_questions, blueprint):
    """
    Complète les champs métier à partir du blueprint.
    """
    blueprint_map = {
        str(item.get("question_id")): item
        for item in blueprint
        if isinstance(item, dict) and item.get("question_id")
    }

    enriched = []

    for q in parsed_questions:
        if not isinstance(q, dict):
            continue

        qid = str(q.get("question_id") or q.get("questionId") or q.get("id") or "")
        meta = blueprint_map.get(qid, {})

        question_id = qid or meta.get("question_id") or ""

        q["question_id"] = question_id
        q["questionId"] = question_id
        q["id"] = question_id

        q["technique_id"] = q.get("technique_id") or q.get("techniqueId") or meta.get("technique_id") or "NA"
        q["techniqueId"] = q["technique_id"]

        q["technique_name"] = q.get("technique_name") or q.get("techniqueName") or meta.get("technique_name") or ""
        q["techniqueName"] = q["technique_name"]

        q["asset_id"] = q.get("asset_id") or meta.get("asset_id") or ""
        q["asset_name"] = q.get("asset_name") or meta.get("asset_name") or ""

        if not q.get("type"):
            q["type"] = meta.get("question_type", "qcm")

        # sécuriser choices pour vf
        if q.get("type") == "vf":
            q["choices"] = ["Vrai", "Faux"]
            q["options"] = ["Vrai", "Faux"]

        # Métadonnées pédagogiques du blueprint (contraintes pré-GPT)
        if meta.get("bloom_level"):
            q["bloom_level"] = meta.get("bloom_level")
            q["bloom_label_fr"] = meta.get("bloom_label_fr", "")
        if meta.get("actionability_requirement"):
            q["actionability_requirement"] = meta.get("actionability_requirement")

        enriched.append(q)

    return enriched


# --- Validation post-GPT (alignement blueprint + contrôle de qualité) ---

MIN_QUIZ_QUESTION_CHARS = 12
MIN_QUIZ_SCENARIO_CHARS = 18
QUIZ_GPT_MAX_ATTEMPTS = 3

# Tournures qui exigent un QCM (plusieurs propositions), pas un Vrai/Faux binaire.
QUIZ_VF_INCOMPATIBLE_PATTERN = re.compile(
    r"(?is)\b(laquelle|lesquelles|parmi\s+(les\s+)?|quel(le)?s?\s+des|"
    r"options?\s+suivantes|actions?\s+suivantes|plusieurs\s+mesures|"
    r"la\s+moins\s+(efficace|pertinente|adaptée)|la\s+plus\s+(efficace|pertinente))\b",
)
# VF = juger une affirmation ; pas de question ouverte « pourquoi / comment » (incompatible avec Vrai/Faux).
QUIZ_VF_OPENING_INCOMPATIBLE_VF = re.compile(
    r"(?is)^\s*(?:\d+\s*[\.\)]\s*)*"
    r"(pourquoi|comment|en\s+quoi|en\s+quelle\s+mesure|"
    r"à\s+quel(le)?\s+point|quels?|quelles?|de\s+quelle\s+manière)\b",
)


class QuizValidationError(Exception):
    """Le JSON du modèle ne satisfait pas les contrôles automatiques."""

    def __init__(self, message, errors=None, last_cleaned_preview=None):
        super().__init__(message)
        self.errors = errors or []
        self.last_cleaned_preview = last_cleaned_preview or ""


def order_and_align_questions_to_blueprint(parsed, blueprint):
    """
    Réordonne les questions selon le blueprint et normalise les question_id.
    Si les id ne correspondent pas mais que len(parsed)==len(blueprint), alignement par position.
    """
    if not isinstance(parsed, list) or not isinstance(blueprint, list):
        return None
    if len(blueprint) != 10:
        return None

    by_id = {}
    for q in parsed:
        if not isinstance(q, dict):
            continue
        qid = str(q.get("question_id") or q.get("questionId") or q.get("id") or "").strip()
        if qid:
            by_id[qid] = q

    aligned = []
    for i, row in enumerate(blueprint):
        if not isinstance(row, dict):
            return None
        qid = str(row.get("question_id") or "").strip()
        if not qid:
            return None
        q = by_id.get(qid)
        if not q and i < len(parsed) and isinstance(parsed[i], dict):
            q = dict(parsed[i])
        if not isinstance(q, dict):
            return None
        q = dict(q)
        q["question_id"] = qid
        q["questionId"] = qid
        q["id"] = qid
        aligned.append(q)

    return aligned if len(aligned) == 10 else None


def apply_blueprint_authority_to_questions(questions, blueprint):
    """
    Le blueprint fait foi : technique, type, actifs, Bloom (évite dérive MITRE du modèle).
    """
    out = []
    for q, meta in zip(questions, blueprint):
        if not isinstance(q, dict) or not isinstance(meta, dict):
            continue
        q = dict(q)
        q["technique_id"] = str(meta.get("technique_id") or "NA").strip().upper()
        q["techniqueId"] = q["technique_id"]
        q["technique_name"] = str(meta.get("technique_name") or "").strip()
        q["techniqueName"] = q["technique_name"]
        q["type"] = meta.get("question_type") or q.get("type") or "qcm"
        q["asset_id"] = str(meta.get("asset_id") or q.get("asset_id") or "").strip()
        q["asset_name"] = str(meta.get("asset_name") or q.get("asset_name") or "").strip()
        q["bloom_level"] = meta.get("bloom_level")
        q["bloom_label_fr"] = meta.get("bloom_label_fr", "")
        q["actionability_requirement"] = meta.get("actionability_requirement", "")
        if q["type"] == "vf":
            q["choices"] = ["Vrai", "Faux"]
            q["options"] = ["Vrai", "Faux"]
        out.append(q)
    return out


def compute_quiz_quality_metrics(normalized_questions, blueprint):
    """
    Métriques post-génération sans LLM : score heuristique 0–100, Bloom, diversité MITRE.
    `normalized_questions` : liste telle que renvoyée à l'API (10 items).
    `blueprint` : plan avec bloom_level par question (source de vérité pour la répartition).
    """
    out = {
        "quality_score": 0.0,
        "bloom_distribution": {},
        "bloom_coverage": 0,
        "technique_unique_count": 0,
        "avg_scenario_chars": 0.0,
        "avg_question_chars": 0.0,
        "qcm_count": 0,
        "vf_count": 0,
    }
    if not isinstance(normalized_questions, list) or len(normalized_questions) != 10:
        return out

    bloom_levels = []
    if isinstance(blueprint, list):
        for row in blueprint[:10]:
            if isinstance(row, dict):
                bl = row.get("bloom_level")
                if bl:
                    bloom_levels.append(str(bl).strip().lower())

    dist = Counter(bloom_levels)
    out["bloom_distribution"] = dict(dist)
    out["bloom_coverage"] = len(dist)

    scen_lens = []
    q_lens = []
    tech_ids = set()
    for q in normalized_questions:
        if not isinstance(q, dict):
            continue
        scen_lens.append(len(str(q.get("scenario") or "").strip()))
        q_lens.append(len(str(q.get("question") or "").strip()))
        tid = str(q.get("techniqueId") or q.get("technique_id") or "").strip().upper()
        if tid and tid != "NA":
            tech_ids.add(tid)
        qt = str(q.get("type") or "").lower()
        if qt == "qcm":
            out["qcm_count"] += 1
        elif qt == "vf":
            out["vf_count"] += 1

    n = max(len(scen_lens), 1)
    avg_scen = sum(scen_lens) / n
    avg_q = sum(q_lens) / n
    out["avg_scenario_chars"] = round(avg_scen, 1)
    out["avg_question_chars"] = round(avg_q, 1)
    out["technique_unique_count"] = len(tech_ids)

    def _band(v, lo, hi):
        if v >= hi:
            return 1.0
        if v <= lo:
            return max(0.0, v / lo) if lo else 0.0
        return 0.5 + 0.5 * (v - lo) / (hi - lo)

    # Pondération : richesse des textes + couverture Bloom du plan + diversité MITRE
    scen_score = 40.0 * _band(avg_scen, 18.0, 100.0)
    q_score = 30.0 * _band(avg_q, 12.0, 90.0)
    bloom_balance = min(20.0, 5.0 * out["bloom_coverage"])
    diversity_score = 10.0 * (min(10, out["technique_unique_count"]) / 10.0)

    total = scen_score + q_score + bloom_balance + diversity_score
    out["quality_score"] = round(min(100.0, max(0.0, total)), 1)

    return out


def validate_questions_after_gpt(questions, blueprint):
    """
    Contrôles structurels après application du blueprint.
    Retourne (ok, liste de messages d'erreur).
    """
    errors = []
    if not isinstance(questions, list) or not isinstance(blueprint, list):
        return False, ["invalid_lists"]

    if len(questions) != 10 or len(blueprint) != 10:
        return False, [f"count_mismatch: questions={len(questions or [])} blueprint={len(blueprint or [])}"]

    for i, (q, meta) in enumerate(zip(questions, blueprint), start=1):
        if not isinstance(q, dict):
            errors.append(f"q{i}: not_a_dict")
            continue
        qtext = (q.get("question") or "").strip()
        scen = (q.get("scenario") or "").strip()
        if len(qtext) < MIN_QUIZ_QUESTION_CHARS:
            errors.append(f"q{i}: question_too_short (min {MIN_QUIZ_QUESTION_CHARS} chars)")
        if len(scen) < MIN_QUIZ_SCENARIO_CHARS:
            errors.append(f"q{i}: scenario_too_short (min {MIN_QUIZ_SCENARIO_CHARS} chars)")

        qtype = str(q.get("type") or "").lower()
        expected = str(meta.get("question_type") or "").lower()
        if expected and qtype != expected:
            errors.append(f"q{i}: type_mismatch want {expected} got {qtype}")

        if qtype == "qcm":
            choices = q.get("choices") or q.get("options") or []
            if not isinstance(choices, list) or len(choices) != 4:
                errors.append(f"q{i}: qcm_requires_4_choices")
            ca = str(q.get("correct_answer") or "").strip()
            if isinstance(choices, list) and choices and ca:
                if not any(ca.lower() == str(c).strip().lower() for c in choices):
                    errors.append(f"q{i}: correct_answer_not_in_choices")
        elif qtype == "vf":
            ca = str(q.get("correct_answer") or "").strip()
            if ca not in ("Vrai", "Faux"):
                errors.append(f"q{i}: vf_correct_must_be_Vrai_or_Faux")
            combined = f"{scen} {qtext}"
            if QUIZ_VF_INCOMPATIBLE_PATTERN.search(combined):
                errors.append(
                    f"q{i}: vf_incompatible_stem (formulation type « laquelle / parmi » → QCM obligatoire)"
                )
            if qtext and QUIZ_VF_OPENING_INCOMPATIBLE_VF.search(qtext):
                errors.append(
                    f"q{i}: vf_must_be_statement_not_why_how "
                    f"(interdit « Pourquoi/Comment/… » en Vrai/Faux — utiliser une affirmation vérifiable)"
                )

        # Cohérence Bloom ↔ type : analyze/apply ne doivent pas être en VF
        bl = str(meta.get("bloom_level") or "").strip().lower()
        if bl in ("analyze", "apply") and qtype == "vf":
            errors.append(f"q{i}: bloom_{bl}_requires_qcm_not_vf")

    return (len(errors) == 0), errors


def postprocess_gpt_quiz(parsed, blueprint):
    """
    Alignement sur le blueprint, autorité du plan, validation.
    Retourne la liste de 10 questions validée ou lève QuizValidationError.
    """
    aligned = order_and_align_questions_to_blueprint(parsed, blueprint)
    if aligned is None:
        raise QuizValidationError(
            "Alignement blueprint impossible (questions manquantes ou mal formées).",
            errors=["align_failed"],
        )

    fixed = apply_blueprint_authority_to_questions(aligned, blueprint)
    ok, errs = validate_questions_after_gpt(fixed, blueprint)
    if not ok:
        raise QuizValidationError(
            "Validation post-GPT échouée.",
            errors=errs,
        )
    return fixed


def _build_quiz_repair_prompt(base_prompt, blueprint, validation_errors, last_cleaned_preview):
    err_txt = json.dumps(validation_errors, ensure_ascii=False, indent=2)
    preview = (last_cleaned_preview or "")[:4500]
    return f"""{base_prompt}

=== CORRECTION OBLIGATOIRE (tentative de réparation) ===
La sortie précédente n'a pas passé la validation automatique du serveur.

Erreurs détectées :
{err_txt}

Tu dois produire UN NOUVEAU tableau JSON de exactement 10 objets qui corrige ces problèmes :
- Chaque scenario : au moins {MIN_QUIZ_SCENARIO_CHARS} caractères (mise en situation concrète).
- Chaque question : au moins {MIN_QUIZ_QUESTION_CHARS} caractères.
- Types : respecter question_type du plan pour chaque question_id (qcm = 4 choix distincts ; vf = choices ["Vrai","Faux"]).
  Si bloom_level est apply ou analyze, le plan impose "qcm" : ne jamais mettre Vrai/Faux pour ces lignes.
  Si le texte demande « laquelle », « parmi les actions », etc., c'est un QCM (4 choix), pas du VF.
  Pour VF (quiz pré/post) : la question doit être une **affirmation** vérifiable, jamais « Pourquoi… » ni « Comment… » (sinon erreur vf_must_be_statement_not_why_how).
- correct_answer : pour QCM, doit être exactement l'une des 4 chaînes de choices ; pour VF, "Vrai" ou "Faux" uniquement.
- question_id : identiques au plan, dans le même ordre (1 à 10).

Ne répète pas les erreurs ci-dessous. Aucun texte hors JSON.

Référence (extrait de la sortie invalide, à ne pas recopier telle quelle) :
{preview}
"""


def _call_openai_quiz(prompt: str, temperature: float = 0.3):
    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "Tu produis uniquement un tableau JSON valide. "
                    "Tu respectes strictement chaque technique_id et technique_name du plan, "
                    "le niveau Bloom (bloom_level) par question, et des scénarios concrets et actionnables."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        temperature=temperature,
    )
    return response.choices[0].message.content


def generate_quiz(profile, quiz_type="pre", human_threats=None, max_questions=10, required_scores=None):
    if human_threats is None:
        human_threats = []
    if required_scores is None:
         required_scores = {}

    user_id = profile.get("userID", "unknown")
    max_questions = 10  # force toujours 10

    # 1) Sélection des cibles
    targets = select_quiz_targets(
        user_id=user_id,
        quiz_type=quiz_type,
        human_threats=human_threats,
        max_questions=max_questions,
        required_scores=required_scores
    )

    if not isinstance(targets, list):
        targets = []

    # 2) Si pas assez de targets, compléter
    if len(targets) < max_questions:
        base_targets = list(targets)

        # on réutilise les targets existantes pour atteindre 10
        i = 0
        while len(targets) < max_questions and base_targets:
            source = dict(base_targets[i % len(base_targets)])
            source["question_id"] = f"{user_id}_{quiz_type}_{len(targets)+1}"
            targets.append(source)
            i += 1

    # 3) Si trop, couper à 10
    targets = targets[:max_questions]

    # 4) Construire le blueprint
    blueprint = build_quiz_blueprint(
        user_profile=profile,
        quiz_type=quiz_type,
        targets=targets
    )

    if not isinstance(blueprint, list):
        blueprint = []

    # 5) Reforcer exactement 10 éléments
    if len(blueprint) < max_questions:
        base_blueprint = list(blueprint)
        i = 0
        while len(blueprint) < max_questions and base_blueprint:
            cloned = dict(base_blueprint[i % len(base_blueprint)])
            cloned["question_id"] = f"{user_id}_{quiz_type}_{len(blueprint)+1}"
            blueprint.append(cloned)
            i += 1

    blueprint = blueprint[:max_questions]

    # 6) Sécurité finale
    if len(blueprint) != 10:
        raise ValueError(f"Blueprint invalide : {len(blueprint)} éléments au lieu de 10")

    prompt = f"""
Tu es un expert en cybersécurité, en MITRE ATT&CK, en pédagogie (taxonomie de Bloom) et en quiz adaptatifs.

Ta tâche est de générer un quiz de cybersécurité en français, strictement basé sur le PLAN JSON ci-dessous (contraintes pré-définies, non négociables).
Le plan indique quiz_type (pre ou post) : les mêmes règles s'appliquent, notamment pour les questions Vrai/Faux.

=== CONTRAINTES MITRE (obligatoires) ===
- Pour chaque ligne du plan, la question DOIT porter sur EXACTEMENT le technique_id et technique_name indiqués (copie-les tels quels dans la sortie JSON).
- Interdit de substituer une autre technique ATT&CK ou d'inventer un faux identifiant.
- Si technique_id vaut "NA", base la question sur le contexte actif / risque du plan tout en restant réaliste pour le rôle ; n'invente pas un faux Txxxx.
- Le texte de la question ou du scénario doit mentionner ou décrire clairement le comportement associé à cette technique (pas seulement un titre générique).

=== STRUCTURE PÉDAGOGIQUE (obligatoire par question) ===
- Chaque élément du plan contient bloom_level et bloom_label_fr : tu DOIS calibrer la difficulté et la formulation sur ce niveau.
  * remember : reconnaissance d'un signal, d'un indicateur ou d'une tactique.
  * understand : explication des conséquences ou du "pourquoi c'est risqué".
  * apply : décision d'une action concrète (une seule bonne conduite à tenir).
  * analyze : comparaison d'options ou jugement entre plusieurs réponses plausibles.
- scenario : courte mise en situation (2–5 phrases) ancrée dans le métier (job_role, qualifications, responsibilities) et l'actif (asset_name) si présent.
- question : formulation claire qui teste le niveau Bloom indiqué pour CETTE ligne du plan.

=== CONTENU ACTIONNABLE ===
- Les choix (QCM) ou la proposition V/F doivent permettre de mesurer un comportement ou une décision, pas seulement de la mémorisation de définitions vides.
- Préfère des verbes d'action : signaler, vérifier, refuser, isoler, escalader, archiver de façon sûre, contacter le SOC, etc., lorsque bloom_level est "apply" ou "analyze".

=== Règles techniques de sortie ===
1. Génère exactement 10 questions, ni plus ni moins.
2. Une question par élément du plan, dans le même ordre (index 1 à 10).
3. Respecte strictement chaque question_id du plan.
4. Respecte strictement question_type du plan ("qcm" ou "vf").
   - Si bloom_level est "apply" ou "analyze", question_type sera toujours "qcm" dans le plan (choix multiples).
5. Pour type "qcm" : exactement 4 choix, tous plausibles, une seule bonne réponse.
6. Pour type "vf" : choices = ["Vrai", "Faux"] uniquement ; correct_answer = "Vrai" ou "Faux".
   Même règle pour quiz pré et post : la clé "question" doit être une **affirmation** ou une proposition jugeable (ex. « La détection d'un fichier lié à T1204.002 sur un serveur critique … »), pas une question ouverte.
   Interdit en VF : commencer par « Pourquoi », « Comment », « En quoi », « Quels », « Quelle » — incompatible avec Vrai/Faux.
   Interdit pour le VF : formulations du type « laquelle », « parmi les actions suivantes », « lequel des choix »
   (cela impose un QCM à 4 réponses, pas un Vrai/Faux).
7. Retourne uniquement un JSON valide ; aucun texte avant ou après le tableau.
8. Si deux lignes partagent la même technique, varie impérativement le scénario, le contexte et l'angle Bloom.

Plan question par question (contraintes pré-GPT) :
{json.dumps(blueprint, ensure_ascii=False, indent=2)}

Format attendu (exemple de structure ; reproduis pour les 10 objets) :
[
  {{
    "question_id": "u002_pre_1",
    "technique_id": "T1566",
    "technique_name": "Phishing",
    "asset_id": "email_gateway",
    "question": "....",
    "scenario": "....",
    "choices": ["....", "....", "....", "...."],
    "correct_answer": "....",
    "type": "qcm"
  }}
]
"""

    last_content = ""
    last_cleaned = ""
    last_errors = []

    for attempt in range(QUIZ_GPT_MAX_ATTEMPTS):
        temperature = 0.22 if attempt > 0 else 0.3
        if attempt == 0:
            prompt_use = prompt
        else:
            prompt_use = _build_quiz_repair_prompt(
                prompt, blueprint, last_errors, last_cleaned
            )

        last_content = _call_openai_quiz(prompt_use, temperature=temperature)
        last_cleaned = clean_api_response(last_content or "")

        try:
            parsed = parse_questions(last_cleaned or "")
            validated = postprocess_gpt_quiz(parsed, blueprint)
            return last_content, blueprint, validated
        except QuizValidationError as e:
            last_errors = list(e.errors or ["validation_failed"])
            continue

    raise QuizValidationError(
        f"Quiz : échec validation après {QUIZ_GPT_MAX_ATTEMPTS} tentatives.",
        errors=last_errors,
        last_cleaned_preview=(last_cleaned or "")[:1200],
    )

#   Évaluation du quiz
def calculate_results(answers, userID, quiz_type, total_questions):
    """
    Retourne exactement 3 valeurs :
    (score, vulnerability, enriched_answers)
    """
    correct_count = 0
    enriched_answers = []

    try:
        if mongo is None or mongo.db is None:
            raise RuntimeError("MongoDB non connecté")

        quiz = mongo.db.quiz_genere.find_one(
            {"userID": userID, "quiz_type": quiz_type},
            sort=[("date", -1)]
        )

        # fallback si ancien document avec userId
        if not quiz:
            quiz = mongo.db.quiz_genere.find_one(
                {"userId": userID, "quiz_type": quiz_type},
                sort=[("date", -1)]
            )

        if not quiz:
            raise ValueError("Quiz introuvable")

        questions = quiz.get("questions") or quiz.get("quiz") or quiz.get("generated_quiz") or []
        if not isinstance(questions, list) or not questions:
            raise ValueError("Questions manquantes dans le quiz")

        def _norm(v):
            return str(v).strip().lower()

        # Index par question_id
        questions_map = {}
        # Index secours par texte
        questions_text_map = {}

        for q in questions:
            if not isinstance(q, dict):
                continue

            qid = q.get("question_id") or q.get("questionId") or q.get("id")
            qtext = q.get("question") or q.get("text") or q.get("texte") or ""

            if qid:
                questions_map[str(qid)] = q

            if qtext:
                questions_text_map[_norm(qtext)] = q

        for a in answers:
            if not isinstance(a, dict):
                continue

            q_id = a.get("question_id") or a.get("questionId") or a.get("id")
            q_text = (a.get("question") or "").strip()

            selected_raw = (
                a.get("selected")
                or a.get("answer")
                or a.get("user_answer")
                or a.get("response")
                or ""
            )
            selected = _norm(selected_raw)

            matched = None

            # 1) priorité au question_id
            if q_id:
                matched = questions_map.get(str(q_id))

            # 2) fallback ancien format : matching par texte
            if matched is None and q_text:
                matched = questions_text_map.get(_norm(q_text))

            if not matched:
                enriched_answers.append({
                    "question_id": str(q_id or ""),
                    "question": q_text,
                    "selected": selected_raw,
                    "correct_answer": "",
                    "is_correct": False,
                    "scenario": "",
                    "technique_id": "",
                    "technique_name": "",
                    "asset_id": "",
                    "asset_name": ""
                })
                continue

            correct_raw = (
                matched.get("correct_answer")
                or matched.get("correct")
                or matched.get("correctAnswer")
                or ""
            )
            correct = _norm(correct_raw)

            is_correct = bool(correct) and is_similar(selected, correct) and selected != ""

            enriched_answers.append({
                "question_id": str(
                    matched.get("question_id")
                    or matched.get("questionId")
                    or matched.get("id")
                    or q_id
                    or ""
                ),
                "question": matched.get("question") or q_text,
                "selected": selected_raw,
                "correct_answer": correct_raw,
                "is_correct": is_correct,
                "scenario": matched.get("scenario", ""),

                "technique_id": (
                    matched.get("technique_id")
                    or matched.get("techniqueId")
                    or ""
                ),
                "technique_name": (
                    matched.get("technique_name")
                    or matched.get("techniqueName")
                    or ""
                ),
                "asset_id": matched.get("asset_id") or "",
                "asset_name": matched.get("asset_name") or ""
            })

            if is_correct:
                correct_count += 1

        total_questions = int(total_questions or len(questions) or 1)
        vulnerability = (total_questions - correct_count) / total_questions

        return correct_count, vulnerability, enriched_answers

    except Exception as e:
        print(f"[WARNING] Fallback mode activé : {e}")

        score = 0
        fallback_enriched = []

        for item in answers:
            if not isinstance(item, dict):
                continue

            q_id = item.get("question_id") or item.get("questionId") or item.get("id") or ""
            question = (item.get("question") or "").strip()

            selected_raw = (
                item.get("selected")
                or item.get("answer")
                or item.get("user_answer")
                or item.get("response")
                or ""
            )
            selected = str(selected_raw).strip().lower()

            correct_raw = (
                item.get("correct_answer")
                or item.get("correct")
                or item.get("correctAnswer")
                or ""
            )
            correct = str(correct_raw).strip().lower()

            is_correct = bool(correct) and is_similar(selected, correct) and selected != ""

            fallback_enriched.append({
                "question_id": str(q_id),
                "question": question,
                "selected": selected_raw,
                "correct_answer": correct_raw,
                "is_correct": is_correct,
                "scenario": item.get("scenario", ""),

                "technique_id": item.get("technique_id") or item.get("techniqueId") or "",
                "technique_name": item.get("technique_name") or item.get("techniqueName") or "",
                "asset_id": item.get("asset_id") or "",
                "asset_name": item.get("asset_name") or ""
            })

            if is_correct:
                score += 1

        total_questions = int(total_questions or len(answers) or 1)
        vulnerability = (total_questions - score) / total_questions

        return score, vulnerability, fallback_enriched

def select_training_targets(profile, quiz_type="pre", results=None, human_threats=None, max_modules=4):
    """
    Retourne les cibles pédagogiques à traiter dans la formation.
    Chaque cible correspond à un module.
    """
    if human_threats is None:
        human_threats = []

    user_id = profile.get("userID", "unknown")

    # PRE : techniques humaines probables
    if quiz_type == "pre":
        ranked = []

        for t in human_threats:
            if not isinstance(t, dict):
                continue

            rl = float(t.get("risk_local", 0.0) or t.get("risk_norm", 0.0) or 0.0)
            if rl <= 0.0 and t.get("risk_pct") is not None:
                try:
                    rp = float(t.get("risk_pct") or 0)
                    rl = rp / 100.0 if rp > 1.5 else rp
                except (TypeError, ValueError):
                    pass

            ranked.append({
                "source": "human_threats_profile",
                "priority_reason": "Technique humaine probable pour ce profil",
                "technique_id": str(t.get("technique_id") or t.get("id") or "NA").strip().upper(),
                "technique_name": t.get("technique_name") or t.get("name") or "",
                "asset_id": t.get("asset_id") or "",
                "asset_name": t.get("asset_name") or "",
                "risk_local": rl,
                "risk_norm": float(t.get("risk_norm", rl) or 0.0),
                "risk_pct": float(t.get("risk_pct", 0.0) or 0.0),
                "threat_score": float(t.get("threat_score", t.get("T", 0.0)) or 0.0),
                "wrong_count": 0,
                "error_example": ""
            })

        ranked.sort(
            key=lambda x: (x["risk_local"], x["threat_score"]),
            reverse=True
        )

        # déduplication par technique
        unique_ranked = []
        seen = set()
        for item in ranked:
            tid = item["technique_id"]
            if tid in seen:
                continue
            seen.add(tid)
            unique_ranked.append(item)

        return unique_ranked[:max_modules]

    # POST : erreurs + risque élevé
    wrong_counter = Counter()
    meta_map = {}
    risk_map = {}

    enriched_answers = []
    if isinstance(results, dict):
        enriched_answers = results.get("answers") or results.get("enriched_answers") or []

    # 1) erreurs du quiz courant
    for ans in enriched_answers:
        if not isinstance(ans, dict):
            continue

        if ans.get("is_correct") is True:
            continue

        tid = ans.get("technique_id") or ans.get("techniqueId")
        if not tid:
            continue

        tid = str(tid).strip().upper()

        wrong_counter[tid] += 1
        meta_map[tid] = {
            "technique_name": ans.get("technique_name") or ans.get("techniqueName") or "",
            "asset_id": ans.get("asset_id") or "",
            "asset_name": ans.get("asset_name") or "",
            "error_example": ans.get("question") or ""
        }

    # 2) risques humains élevés depuis profile_risks
    profil_risque = mongo.db.profile_risks.find_one({"userID": user_id}) or {}
    assets = profil_risque.get("assets", []) or []

    for a in assets:
        if not isinstance(a, dict):
            continue

        asset_id = a.get("asset_id") or ""
        asset_name = a.get("asset_name") or ""

        ht = a.get("human_techniques") or []
        hb = a.get("hybrid_techniques") or []
        if isinstance(ht, dict):
            ht = [ht]
        if isinstance(hb, dict):
            hb = [hb]
        if not isinstance(ht, list):
            ht = []
        if not isinstance(hb, list):
            hb = []

        for t in ht + hb:
            if not isinstance(t, dict):
                continue

            tid = t.get("technique_id") or t.get("id")
            if not tid:
                continue

            tid = str(tid).strip().upper()
            risk_local = float(t.get("risk_local", 0.0) or t.get("risk_norm", 0.0) or 0.0)
            if risk_local <= 0.0 and t.get("risk_pct") is not None:
                try:
                    rp = float(t.get("risk_pct") or 0)
                    risk_local = rp / 100.0 if rp > 1.5 else rp
                except (TypeError, ValueError):
                    pass
            risk_map[tid] = max(risk_map.get(tid, 0.0), risk_local)

            prof_meta = {
                "technique_name": t.get("technique_name") or t.get("name") or "",
                "asset_id": asset_id,
                "asset_name": asset_name,
                "risk_norm": float(t.get("risk_norm", risk_local) or 0.0),
                "risk_pct": float(t.get("risk_pct", 0.0) or 0.0),
            }
            if tid not in meta_map:
                prof_meta["error_example"] = ""
                meta_map[tid] = prof_meta
            else:
                meta_map[tid]["risk_norm"] = prof_meta["risk_norm"]
                meta_map[tid]["risk_pct"] = prof_meta["risk_pct"]
                if not (meta_map[tid].get("technique_name") or "").strip():
                    meta_map[tid]["technique_name"] = prof_meta["technique_name"]

    # 3) classement final
    all_tids = set(list(wrong_counter.keys()) + list(risk_map.keys()))

    ranked = []
    for tid in all_tids:
        meta = meta_map.get(tid, {})
        wc = wrong_counter.get(tid, 0)
        rl = risk_map.get(tid, 0.0)

        # ignorer les techniques sans erreur et sans risque
        if wc <= 0 and rl <= 0:
            continue

        ranked.append({
            "source": "post_priority_mix",
            "priority_reason": "Erreur observée ou risque humain élevé",
            "technique_id": tid,
            "technique_name": meta.get("technique_name", ""),
            "asset_id": meta.get("asset_id", ""),
            "asset_name": meta.get("asset_name", ""),
            "risk_local": rl,
            "risk_norm": float(meta.get("risk_norm", rl) or 0.0),
            "risk_pct": float(meta.get("risk_pct", 0.0) or 0.0),
            "threat_score": 0.0,
            "wrong_count": wc,
            "error_example": meta.get("error_example", "")
        })

    # priorité d'abord aux erreurs, puis au risque
    ranked.sort(
        key=lambda x: (x["wrong_count"], x["risk_local"]),
        reverse=True
    )

    # déduplication par technique
    unique_ranked = []
    seen = set()
    for item in ranked:
        tid = item["technique_id"]
        if tid in seen:
            continue
        seen.add(tid)
        unique_ranked.append(item)

    return unique_ranked[:max_modules]

class TrainingModuleValidationError(Exception):
    """Le JSON module formation ne satisfait pas les contrôles automatiques."""

    def __init__(self, message, errors=None, last_cleaned_preview=None):
        super().__init__(message)
        self.errors = errors or []
        self.last_cleaned_preview = last_cleaned_preview or ""


def _load_critical_bases_for_training() -> frozenset:
    """
    Bases MITRE « critiques » depuis organization_settings (liste admin), sinon défaut.
    Si la règle critique est désactivée (liste vide), retourne ensemble vide.
    """
    try:
        doc = mongo.db.organization_settings.find_one({"_id": "default"}) or {}
        crit = doc.get("critical_technique_ids")
        if crit is None:
            return frozenset(TRAINING_DEFAULT_CRITICAL_BASES)
        if isinstance(crit, list) and len(crit) == 0:
            return frozenset()
        if isinstance(crit, list):
            out = set()
            for x in crit:
                u = str(x).strip().upper()
                if not u:
                    continue
                out.add(u.split(".")[0])
                out.add(u)
            return frozenset(out)
    except Exception:
        pass
    return frozenset(TRAINING_DEFAULT_CRITICAL_BASES)


def _training_risk_signal(mt: dict) -> float:
    """Signal de risque 0..1 à partir des champs profil / cible formation."""
    if not isinstance(mt, dict):
        return 0.0
    r = 0.0
    for k in ("risk_norm", "risk_local"):
        v = mt.get(k)
        if v is not None:
            try:
                r = max(r, float(v))
            except (TypeError, ValueError):
                pass
    rp = mt.get("risk_pct")
    if rp is not None:
        try:
            x = float(rp)
            r = max(r, x / 100.0 if x > 1.5 else x)
        except (TypeError, ValueError):
            pass
    return max(0.0, min(1.0, r))


def _enrich_training_targets_from_eval_results(targets: list, results: dict | None) -> None:
    """
    Marque les cibles dont la dernière évaluation indique une vulnérabilité non acceptable
    (seuils admin : critique, par technique, etc.) — aligné quiz_history.per_technique_vulnerability_evaluation.
    """
    if not targets or not isinstance(results, dict):
        return
    rows = results.get("per_technique_vulnerability_evaluation")
    if not isinstance(rows, list):
        return
    failed: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("acceptable") is True:
            continue
        tid = str(row.get("technique_id") or "").strip().upper()
        if not tid:
            continue
        failed.add(tid)
        failed.add(tid.split(".")[0])
    for t in targets:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("technique_id") or "").strip().upper()
        if not tid:
            continue
        base = tid.split(".")[0]
        if tid in failed or base in failed:
            t["vuln_evaluation_failed"] = True


def classify_training_adaptation(
    module_target: dict,
    quiz_type: str,
    critical_bases: frozenset,
) -> tuple[str, str]:
    """
    Retourne ( « strict » | « light », justification courte FR pour le blueprint ).
    strict = technique critique OU erreurs répétées OU risque / menace élevé.
    """
    if not isinstance(module_target, dict):
        return "strict", "Données cible insuffisantes : mode sûr (strict)."
    tid = str(module_target.get("technique_id") or "").strip().upper()
    base = tid.split(".")[0] if tid else ""
    q = str(quiz_type or "pre").strip().lower()

    ts = 0.0
    try:
        ts = float(module_target.get("threat_score", module_target.get("T", 0.0)) or 0.0)
    except (TypeError, ValueError):
        ts = 0.0

    rs = _training_risk_signal(module_target)
    wc = int(module_target.get("wrong_count", 0) or 0)

    if module_target.get("vuln_evaluation_failed"):
        return (
            "strict",
            "Vulnérabilité sur cette technique au-dessus du seuil défini dans les paramètres organisation (évaluation).",
        )

    if critical_bases and (tid in critical_bases or base in critical_bases):
        return "strict", "Technique dans le périmètre « critique » (organisation ou défaut)."

    if q == "post" and wc >= TRAINING_STRICT_WRONG_COUNT:
        return "strict", f"Plusieurs erreurs sur cette technique au quiz ({wc} ≥ {TRAINING_STRICT_WRONG_COUNT})."

    if q == "post" and wc >= 1 and rs >= 0.28:
        return "strict", "Erreur au quiz et risque contextualisé non négligeable."

    if rs >= TRAINING_STRICT_RISK_SIGNAL:
        return "strict", f"Signal de risque élevé (≥ {TRAINING_STRICT_RISK_SIGNAL:.2f})."

    if ts >= TRAINING_STRICT_THREAT_T:
        return "strict", f"Score de menace T élevé (≥ {TRAINING_STRICT_THREAT_T:.2f})."

    return (
        "light",
        "Technique non critique, faible signal de risque : rappel ciblé sans surcharge.",
    )


def build_training_module_blueprint(
    profile,
    module_target,
    module_index,
    quiz_type,
    critical_bases: frozenset | None = None,
):
    tid = str(module_target.get("technique_id") or "NA").strip().upper()
    tname = (module_target.get("technique_name") or "").strip()
    if tid in MITRE_NAMES:
        tname = MITRE_NAMES[tid]
    elif not tname:
        tname = tid
    bloom = TRAINING_BLOOM_CYCLE[(module_index - 1) % len(TRAINING_BLOOM_CYCLE)]
    cb = critical_bases if critical_bases is not None else _load_critical_bases_for_training()
    tier, tier_reason = classify_training_adaptation(module_target, quiz_type, cb)
    min_th = MIN_TRAINING_THREAT_CHARS if tier == "strict" else TRAINING_LIGHT_MIN_THREAT_CHARS
    min_ex = MIN_TRAINING_EXAMPLE_CHARS if tier == "strict" else TRAINING_LIGHT_MIN_EXAMPLE_CHARS
    return {
        "module_id": f"mod_{module_index}",
        "module_index": module_index,
        "technique_id": tid,
        "technique_name": tname,
        "asset_id": str(module_target.get("asset_id") or "").strip(),
        "asset_name": str(module_target.get("asset_name") or "").strip(),
        "quiz_type": quiz_type,
        "priority_reason": module_target.get("priority_reason", ""),
        "error_example": module_target.get("error_example", ""),
        "risk_local": float(module_target.get("risk_local", 0.0) or 0.0),
        "adaptation_tier": tier,
        "adaptation_rationale_fr": tier_reason,
        "min_threat_chars": min_th,
        "min_example_chars": min_ex,
        "bloom_level": bloom,
        "bloom_label_fr": BLOOM_LABELS_FR.get(bloom, ""),
        "mitre_constraint": (
            "Répondre UNIQUEMENT au sujet de technique_id / technique_name ; "
            "ne pas substituer une autre technique ATT&CK."
        ),
    }


def parse_training_module_json(raw_text: str):
    raw = (raw_text or "").strip()
    candidates = [raw, clean_api_response(raw)]
    for candidate in candidates:
        if not candidate or "{" not in candidate:
            continue
        start = candidate.find("{")
        try:
            obj, _ = json.JSONDecoder().raw_decode(candidate, start)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return None


def _normalize_str_list(val):
    if isinstance(val, str) and val.strip():
        return [val.strip()]
    if not isinstance(val, list):
        return []
    return [str(x).strip() for x in val if str(x).strip()]


def normalize_training_module_structured(data: dict, blueprint: dict):
    if not isinstance(data, dict):
        return None
    out = dict(data)
    out["detection_indicators"] = _normalize_str_list(
        out.get("detection_indicators") or out.get("indicateurs_detection")
    )
    out["mitigation_actions"] = _normalize_str_list(
        out.get("mitigation_actions") or out.get("mitigations")
    )
    out["measurable_learning_outcomes"] = _normalize_str_list(
        out.get("measurable_learning_outcomes") or out.get("learning_outcomes")
    )
    if not out.get("real_world_example"):
        out["real_world_example"] = out.get("real_example") or out.get("exemple_reel") or ""
    if not out.get("threat_description"):
        out["threat_description"] = out.get("menace") or out.get("description_menace") or ""
    return out


def apply_training_blueprint_authority(structured: dict, blueprint: dict) -> dict:
    s = dict(structured)
    s["technique_id"] = blueprint["technique_id"]
    s["technique_name"] = blueprint["technique_name"]
    return s


def _text_mentions_technique(text: str, tid: str) -> bool:
    if not tid or tid == "NA":
        return True
    return tid.upper() in (text or "").upper()


def validate_training_module_after_gpt(structured: dict, blueprint: dict):
    errors = []
    if not isinstance(structured, dict):
        return False, ["not_a_dict"]
    tid = blueprint.get("technique_id", "")
    stid = str(structured.get("technique_id") or "").strip().upper()
    if stid != tid:
        errors.append(f"technique_id_mismatch: want {tid} got {stid}")

    min_th = int(blueprint.get("min_threat_chars") or MIN_TRAINING_THREAT_CHARS)
    min_ex = int(blueprint.get("min_example_chars") or MIN_TRAINING_EXAMPLE_CHARS)

    threat = (structured.get("threat_description") or "").strip()
    if len(threat) < min_th:
        errors.append(f"threat_description_too_short (min {min_th})")

    ex = (structured.get("real_world_example") or "").strip()
    if len(ex) < min_ex:
        errors.append(f"real_world_example_too_short (min {min_ex})")

    det = structured.get("detection_indicators") or []
    good_det = [str(x).strip() for x in det if len(str(x).strip()) >= MIN_TRAINING_LIST_ITEM_CHARS]
    if len(good_det) < MIN_TRAINING_DETECTION_ITEMS:
        errors.append(
            f"detection_indicators: need {MIN_TRAINING_DETECTION_ITEMS} items of min {MIN_TRAINING_LIST_ITEM_CHARS} chars"
        )

    mit = structured.get("mitigation_actions") or []
    good_mit = [str(x).strip() for x in mit if len(str(x).strip()) >= MIN_TRAINING_LIST_ITEM_CHARS]
    if len(good_mit) < MIN_TRAINING_MITIGATION_ITEMS:
        errors.append(
            f"mitigation_actions: need {MIN_TRAINING_MITIGATION_ITEMS} items of min {MIN_TRAINING_LIST_ITEM_CHARS} chars"
        )

    outcomes = structured.get("measurable_learning_outcomes") or []
    good_out = [str(x).strip() for x in outcomes if len(str(x).strip()) >= 10]
    if len(good_out) < MIN_TRAINING_OUTCOMES:
        errors.append(f"measurable_learning_outcomes: need at least {MIN_TRAINING_OUTCOMES} non-trivial items")

    sq = (structured.get("self_check_question") or "").strip()
    if len(sq) < MIN_TRAINING_SELF_CHECK_CHARS:
        errors.append(f"self_check_question_too_short (min {MIN_TRAINING_SELF_CHECK_CHARS})")

    comb = threat + " " + ex + " " + sq
    if not _text_mentions_technique(comb, tid):
        errors.append("technique_id_not_cited_in_core_texts (mentionner l'ID MITRE dans menace, exemple ou question)")

    return (len(errors) == 0), errors


def _band_score(v: float, lo: float, hi: float) -> float:
    if v >= hi:
        return 1.0
    if v <= lo:
        return max(0.0, v / lo) if lo else 0.0
    return 0.5 + 0.5 * (v - lo) / (hi - lo)


def compute_training_module_quality_metrics(structured: dict, blueprint: dict) -> dict:
    min_th = float(blueprint.get("min_threat_chars") or MIN_TRAINING_THREAT_CHARS)
    min_ex = float(blueprint.get("min_example_chars") or MIN_TRAINING_EXAMPLE_CHARS)
    out = {
        "quality_score": 0.0,
        "threat_chars": 0,
        "example_chars": 0,
        "detection_count_ok": 0,
        "mitigation_count_ok": 0,
        "outcomes_count": 0,
        "bloom_level": blueprint.get("bloom_level"),
        "adaptation_tier": blueprint.get("adaptation_tier"),
    }
    if not isinstance(structured, dict):
        return out
    threat = len((structured.get("threat_description") or "").strip())
    ex = len((structured.get("real_world_example") or "").strip())
    det = [
        str(x).strip()
        for x in (structured.get("detection_indicators") or [])
        if len(str(x).strip()) >= MIN_TRAINING_LIST_ITEM_CHARS
    ]
    mit = [
        str(x).strip()
        for x in (structured.get("mitigation_actions") or [])
        if len(str(x).strip()) >= MIN_TRAINING_LIST_ITEM_CHARS
    ]
    outcomes = [
        str(x).strip()
        for x in (structured.get("measurable_learning_outcomes") or [])
        if len(str(x).strip()) >= 10
    ]

    out["threat_chars"] = threat
    out["example_chars"] = ex
    out["detection_count_ok"] = len(det)
    out["mitigation_count_ok"] = len(mit)
    out["outcomes_count"] = len(outcomes)

    t_sc = 30.0 * _band_score(float(threat), min_th, 320.0)
    e_sc = 25.0 * _band_score(float(ex), min_ex, 280.0)
    d_sc = 20.0 * min(1.0, len(det) / float(MIN_TRAINING_DETECTION_ITEMS))
    m_sc = 15.0 * min(1.0, len(mit) / float(MIN_TRAINING_MITIGATION_ITEMS))
    o_sc = 10.0 * min(1.0, len(outcomes) / float(MIN_TRAINING_OUTCOMES))

    total = t_sc + e_sc + d_sc + m_sc + o_sc
    out["quality_score"] = round(min(100.0, max(0.0, total)), 1)
    return out


def render_training_module_html(structured: dict, blueprint: dict, module_index: int) -> str:
    title = structured.get("module_title") or f"Module {module_index} — {blueprint.get('technique_name', '')}"
    tid = html_escape.escape(str(blueprint.get("technique_id") or ""))
    tname = html_escape.escape(str(blueprint.get("technique_name") or ""))
    bloom = html_escape.escape(str(blueprint.get("bloom_label_fr") or blueprint.get("bloom_level") or ""))
    tier = blueprint.get("adaptation_tier") or "strict"
    tier_label = "Stricte (prioritaire)" if tier == "strict" else "Légère (rappel ciblé)"
    tier_note = html_escape.escape(str(blueprint.get("adaptation_rationale_fr") or ""))

    def esc(s):
        return html_escape.escape(str(s or ""))

    items_det = "".join(f"<li>{esc(x)}</li>" for x in (structured.get("detection_indicators") or []))
    items_mit = "".join(f"<li>{esc(x)}</li>" for x in (structured.get("mitigation_actions") or []))
    items_out = "".join(f"<li>{esc(x)}</li>" for x in (structured.get("measurable_learning_outcomes") or []))

    return f"""<section data-module-index="{module_index}" data-technique-id="{tid}" data-adaptation-tier="{html_escape.escape(str(tier))}">
  <h4>{esc(title)}</h4>
  <p><strong>Adaptation :</strong> {esc(tier_label)} — <em>{tier_note}</em></p>
  <p><strong>MITRE ATT&amp;CK :</strong> {tid} — {tname}</p>
  <p><strong>Niveau pédagogique visé :</strong> {bloom}</p>
  <p><strong>Description de la menace :</strong> {esc(structured.get("threat_description"))}</p>
  <p><strong>Exemple réaliste :</strong> {esc(structured.get("real_world_example"))}</p>
  <p><strong>Indicateurs de détection :</strong></p>
  <ul>{items_det}</ul>
  <p><strong>Actions de mitigation :</strong></p>
  <ul>{items_mit}</ul>
  <p><strong>Résultats d&apos;apprentissage mesurables :</strong></p>
  <ul>{items_out}</ul>
  <p><strong>Auto-évaluation (application) :</strong> {esc(structured.get("self_check_question"))}</p>
</section>"""


def _fallback_training_module_html(blueprint: dict, module_index: int) -> str:
    tid = html_escape.escape(str(blueprint.get("technique_id") or ""))
    tname = html_escape.escape(str(blueprint.get("technique_name") or ""))
    return f"""<section data-module-index="{module_index}">
  <h4>Module {module_index} — {tname}</h4>
  <p>Contenu en cours de régénération : les contrôles qualité automatiques n&apos;ont pas produit de module JSON valide pour <strong>{tid}</strong>. Réessayez ou contactez un administrateur.</p>
</section>"""


def _build_training_repair_prompt(base_prompt: str, blueprint: dict, validation_errors, last_cleaned_preview: str) -> str:
    err_txt = json.dumps(validation_errors, ensure_ascii=False, indent=2)
    preview = (last_cleaned_preview or "")[:4000]
    min_th = int(blueprint.get("min_threat_chars") or MIN_TRAINING_THREAT_CHARS)
    min_ex = int(blueprint.get("min_example_chars") or MIN_TRAINING_EXAMPLE_CHARS)
    return f"""{base_prompt}

=== CORRECTION OBLIGATOIRE (tentative de réparation) ===
La sortie précédente n'a pas passé la validation automatique du serveur.

Erreurs détectées :
{err_txt}

Tu dois produire UN NOUVEL objet JSON unique qui corrige ces problèmes, avec les champs :
module_title, technique_id, technique_name, threat_description (min ~{min_th} caractères utiles),
real_world_example (min ~{min_ex} caractères),
detection_indicators (liste d'au moins {MIN_TRAINING_DETECTION_ITEMS} chaînes concrètes),
mitigation_actions (au moins {MIN_TRAINING_MITIGATION_ITEMS} actions vérifiables),
measurable_learning_outcomes (au moins {MIN_TRAINING_OUTCOMES} résultats mesurables),
self_check_question (une question qui teste l'application concrète, pas la définition).

Contraintes : technique_id doit être exactement "{blueprint.get("technique_id")}", technique_name "{blueprint.get("technique_name")}".
Mentionne l'identifiant MITRE {blueprint.get("technique_id")} dans threat_description, real_world_example ou self_check_question.

Référence invalide (extrait) :
{preview}
"""


def _call_openai_training_json(prompt: str, temperature: float = 0.35) -> str:
    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "Tu produis uniquement un objet JSON valide UTF-8, sans markdown. "
                    "Tu respectes strictement le blueprint MITRE (technique_id / technique_name). "
                    "Les contenus sont en français, actionnables et alignés MITRE ATT&CK Enterprise."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        max_tokens=2500,
        temperature=temperature,
    )
    return (response.choices[0].message.content or "").strip()


def _call_openai_training_gpt_validator(structured: dict, blueprint: dict):
    try:
        prompt = f"""Tu es un validateur pédagogique et MITRE ATT&CK.

Évalue le module de formation JSON ci-dessous par rapport au blueprint.
Réponds UNIQUEMENT par un objet JSON avec des entiers 0-100 :
{{
  "overall": <0-100>,
  "accuracy": <exactitude factuelle>,
  "mitre_alignment": <alignement technique_id et comportements>,
  "clarity": <clarté>,
  "actionability": <actions concrètes utiles>,
  "difficulty_calibration": <adéquation au niveau Bloom indiqué>
}}

Blueprint :
{json.dumps(blueprint, ensure_ascii=False, indent=2)}

Module :
{json.dumps(structured, ensure_ascii=False, indent=2)}
"""
        raw = _call_openai_training_json(prompt, temperature=0.1)
        start = raw.find("{")
        if start < 0:
            return None
        obj, _ = json.JSONDecoder().raw_decode(raw, start)
        if not isinstance(obj, dict):
            return None
        return obj
    except Exception:
        return None


def generate_training_module(
    profile,
    module_target,
    module_index=1,
    quiz_type="pre",
    critical_bases: frozenset | None = None,
    blueprint: dict | None = None,
):
    """
    Génère un module : JSON structuré (GPT) → validation → rendu HTML.
    Retourne (html_fragment, quality_metrics_dict).
    """
    if blueprint is None:
        blueprint = build_training_module_blueprint(
            profile, module_target, module_index, quiz_type, critical_bases=critical_bases
        )

    job_role = profile.get("jobRole", "utilisateur")
    tier = blueprint.get("adaptation_tier") or "strict"
    if tier == "light":
        adaptation_block = f"""
=== Adaptation intelligente : FORMATION LÉGÈRE ===
Justification : {blueprint.get("adaptation_rationale_fr", "")}
- Module court et direct : prioriser l'essentiel (pas de procédure encyclopédique).
- Menace : description claire mais concise ; focus sur 2–3 réflexes prioritaires à ancrer.
- Exemple réel : situation plausible minimale mais utile pour le poste « {job_role} ».
- Détection / mitigation : concret, mais éviter la redondance ; l'apprenant a un profil à risque modéré sur cette technique.
- Ton : pédagogique, respectueux du temps ; pas de dramatisation inutile.
"""
    else:
        adaptation_block = f"""
=== Adaptation intelligente : FORMATION STRICTE ===
Justification : {blueprint.get("adaptation_rationale_fr", "")}
- Contenu exigeant : procédures détaillées, erreurs fréquentes à éviter, conséquences pour l'organisation.
- Menace : analyse approfondie du mode opératoire et du facteur humain ; ne pas trivialiser.
- Exemple réel : scénario crédible et stressant (sans fiction invraisemblable) pour « {job_role} ».
- Mitigation : actions priorisées, vérifiables, rôles et escalade ; conformité et discipline opérationnelle.
- Ton : sérieux ; cette technique est traitée comme prioritaire (critique ou forte exposition).
"""

    prompt = f"""
Tu es un expert MITRE ATT&CK Enterprise, cybersécurité IoT et ingénierie pédagogique (Bloom).

Tâche : produire UN objet JSON pour UN module de formation en français, strictement aligné sur le PLAN ci-dessous.

=== PLAN (source de vérité — ne pas modifier technique_id / technique_name) ===
{json.dumps(blueprint, ensure_ascii=False, indent=2)}
{adaptation_block}
=== Exigences de contenu (toutes obligatoires) ===
- Menace : décrire la technique {blueprint.get("technique_id")} ({blueprint.get("technique_name")}), son mode opératoire et le lien avec le facteur humain.
- Exemple réel : scénario crédible pour le poste « {job_role} », l'actif {blueprint.get("asset_name") or blueprint.get("asset_id") or "N/A"}.
- Indicateurs de détection : signaux observables (réseau, messagerie, comportement, journaux…) — liste concrète.
- Mitigation : actions priorisées (procédure, configuration, coordination SOC…) — applicables par l'utilisateur.
- Résultats mesurables : verbes d'action + critères observables (ce que l'apprenant sait faire après).
- Auto-évaluation : une question qui teste l'APPLICATION (que faire dans une situation), pas une définition.
- Calibrer le discours sur bloom_level = {blueprint.get("bloom_level")} ({blueprint.get("bloom_label_fr")}).

=== Règles MITRE ===
- Copier technique_id et technique_name EXACTEMENT depuis le plan.
- Mentionner l'identifiant {blueprint.get("technique_id")} dans au moins une des clés threat_description, real_world_example ou self_check_question.

Schéma JSON attendu :
{{
  "module_title": "string",
  "technique_id": "{blueprint.get("technique_id")}",
  "technique_name": "{blueprint.get("technique_name")}",
  "threat_description": "string longue",
  "real_world_example": "string",
  "detection_indicators": ["...", "...", "..."],
  "mitigation_actions": ["...", "...", "..."],
  "measurable_learning_outcomes": ["...", "..."],
  "self_check_question": "string"
}}

Retourne uniquement le JSON, aucun texte avant ou après.
"""

    last_errors = []
    last_cleaned = ""
    best_pair = None
    best_score = -1.0

    use_gpt_val = os.environ.get("TRAINING_GPT_VALIDATOR", "0").strip().lower() in ("1", "true", "yes", "on")

    for _attempt in range(TRAINING_GPT_MAX_ATTEMPTS):
        temperature = 0.32 if _attempt == 0 else 0.18
        prompt_use = (
            prompt
            if _attempt == 0
            else _build_training_repair_prompt(prompt, blueprint, last_errors, last_cleaned)
        )
        content = _call_openai_training_json(prompt_use, temperature=temperature)
        last_cleaned = content or ""
        parsed = parse_training_module_json(content)
        if not parsed:
            last_errors = ["invalid_json_or_empty"]
            continue

        normalized = normalize_training_module_structured(parsed, blueprint)
        if not normalized:
            last_errors = ["normalize_failed"]
            continue

        fixed = apply_training_blueprint_authority(normalized, blueprint)
        ok, errs = validate_training_module_after_gpt(fixed, blueprint)
        metrics = compute_training_module_quality_metrics(fixed, blueprint)
        score = float(metrics.get("quality_score") or 0)

        if use_gpt_val and ok:
            gpt_val = _call_openai_training_gpt_validator(fixed, blueprint)
            if gpt_val and gpt_val.get("overall") is not None:
                try:
                    g = float(gpt_val["overall"])
                    merged = 0.55 * score + 0.45 * g
                    metrics["heuristic_quality_score"] = score
                    metrics["gpt_validator_scores"] = gpt_val
                    metrics["quality_score"] = round(min(100.0, max(0.0, merged)), 1)
                    score = float(metrics["quality_score"])
                except (TypeError, ValueError):
                    metrics["gpt_validator_scores"] = gpt_val

        if ok:
            mfinal = dict(metrics)
            mfinal["quality_threshold"] = TRAINING_MIN_QUALITY_SCORE
            mfinal["validation_ok"] = True
            if score > best_score:
                best_score = score
                best_pair = (fixed, mfinal)
            if score >= TRAINING_MIN_QUALITY_SCORE:
                mfinal["quality_below_threshold"] = False
                html = render_training_module_html(fixed, blueprint, module_index)
                return html, mfinal

        if not ok:
            last_errors = errs
        else:
            last_errors = [f"quality_below_threshold: score={score}"]

    if best_pair is None:
        fb = _fallback_training_module_html(blueprint, module_index)
        return fb, {
            "quality_score": 0.0,
            "quality_below_threshold": True,
            "quality_threshold": TRAINING_MIN_QUALITY_SCORE,
            "validation_ok": False,
            "error": "no_valid_module",
        }

    fixed, metrics = best_pair
    metrics = dict(metrics)
    metrics["quality_below_threshold"] = float(metrics.get("quality_score") or 0) < TRAINING_MIN_QUALITY_SCORE
    metrics["quality_threshold"] = TRAINING_MIN_QUALITY_SCORE
    metrics["validation_ok"] = True
    html = render_training_module_html(fixed, blueprint, module_index)
    return html, metrics

def generate_training_content(profile, quiz_type="pre", results=None, human_threats=None):
    """
    Génère une formation HTML complète + métriques qualité + blueprints.
    Retourne un dict : html, quality_metrics, blueprint, modules_metrics, learning_summary.
    """
    if human_threats is None:
        human_threats = []

    job_role = profile.get("jobRole", "utilisateur")

    quiz_type = str(quiz_type or "pre").strip().lower()
    if quiz_type not in ("pre", "post"):
        quiz_type = "pre"

    targets = select_training_targets(
        profile=profile,
        quiz_type=quiz_type,
        results=results,
        human_threats=human_threats,
        max_modules=4
    )

    if not targets and human_threats:
        for t in human_threats[:4]:
            if not isinstance(t, dict):
                continue
            targets.append({
                "technique_id": str(t.get("technique_id") or t.get("id") or "NA").strip().upper(),
                "technique_name": t.get("technique_name") or t.get("name") or "",
                "asset_id": t.get("asset_id") or "",
                "asset_name": t.get("asset_name") or "",
                "priority_reason": "Menace humaine prioritaire par défaut",
                "risk_local": float(t.get("risk_local", 0.0) or 0.0),
                "error_example": ""
            })

    unique_targets = []
    seen = set()
    for t in targets:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("technique_id") or "NA").strip().upper()
        if tid in seen:
            continue
        seen.add(tid)
        unique_targets.append(t)
    unique_targets = unique_targets[:4]
    _enrich_training_targets_from_eval_results(unique_targets, results)

    try:
        modules_html = []
        modules_metrics = []
        blueprints = []
        outcomes_by_technique = []
        critical_bases = _load_critical_bases_for_training()

        for idx, target in enumerate(unique_targets, start=1):
            bp = build_training_module_blueprint(
                profile, target, idx, quiz_type, critical_bases=critical_bases
            )
            blueprints.append(bp)
            module_html, qm = generate_training_module(
                profile=profile,
                module_target=target,
                module_index=idx,
                quiz_type=quiz_type,
                critical_bases=critical_bases,
                blueprint=bp,
            )
            modules_html.append(module_html)
            modules_metrics.append(dict(qm or {}))
            outcomes_by_technique.append({
                "technique_id": bp.get("technique_id"),
                "technique_name": bp.get("technique_name"),
                "adaptation_tier": bp.get("adaptation_tier"),
                "adaptation_rationale_fr": bp.get("adaptation_rationale_fr"),
                "quality_score": (qm or {}).get("quality_score") if isinstance(qm, dict) else None,
            })

        scores = [float(m.get("quality_score") or 0) for m in modules_metrics if m]
        avg_score = round(sum(scores) / max(len(scores), 1), 1) if scores else 0.0
        below = any(float(m.get("quality_score") or 0) < TRAINING_MIN_QUALITY_SCORE for m in modules_metrics)

        aggregate_metrics = {
            "quality_score": avg_score,
            "quality_threshold": TRAINING_MIN_QUALITY_SCORE,
            "quality_below_threshold": below,
            "modules": modules_metrics,
            "quality_attempts_note": f"max {TRAINING_GPT_MAX_ATTEMPTS} tentatives par module",
            "gpt_validator_enabled": os.environ.get("TRAINING_GPT_VALIDATOR", "0").strip().lower()
            in ("1", "true", "yes", "on"),
        }

        learning_summary = {
            "quiz_type": quiz_type,
            "techniques": outcomes_by_technique,
            "adaptation_note": (
                "Chaque module est étiqueté strict (technique critique, seuils admin non respectés à l’évaluation, "
                "erreurs répétées ou risque élevé) ou léger (rappel ciblé) selon la liste critique Mongo, "
                "per_technique_vulnerability_evaluation du dernier quiz et variables TRAINING_STRICT_*."
            ),
            "progress_note": (
                "Mesurer la progression : comparer quiz pré vs post, scores par technique_id, "
                "et taux d'erreurs sur les mêmes familles MITRE après formation."
            ),
            "post_test_alignment_note": (
                "Le post-test (quiz post) doit réutiliser les mêmes technique_id que la formation ; "
                "privilégier les questions d'application (Bloom apply/analyze) générées via /generate_quiz."
            ),
        }

        intro_focus = (
            "Cette formation a été construite pour sensibiliser l’utilisateur aux menaces humaines les plus probables dans son environnement IoT."
            if quiz_type == "pre"
            else "Cette formation a été construite pour corriger les erreurs observées au quiz, renforcer les bons réflexes et réduire le risque humain. Les modules ciblent les techniques identifiées et l’alignement MITRE ATT&CK."
        )

        jr_esc = html_escape.escape(job_role)
        techniques_intro_items = "".join(
            f"<li><strong>{html_escape.escape(str(t.get('technique_id', '')))}</strong> – "
            f"{html_escape.escape(str(t.get('technique_name', '')))}</li>"
            for t in unique_targets if isinstance(t, dict)
        )

        techniques_block = (
            "<p><strong>Techniques MITRE couvertes :</strong></p><ul>"
            + techniques_intro_items
            + "</ul>"
        ) if techniques_intro_items else ""

        intro_html = f"""
<h2>Formation personnalisée en cybersécurité IoT</h2>
{techniques_block}
<p>Cette formation s’adresse à un profil occupant le poste de <strong>{jr_esc}</strong>.
{intro_focus}</p>
<p><em>Chaque module inclut : description de menace, exemple réel, indicateurs de détection, mitigations et critères d’apprentissage mesurables (score qualité moyen : {avg_score}/100).</em></p>
"""

        reco_html = """
<h3>Recommandations pratiques</h3>
<ul>
  <li>Vérifier systématiquement la légitimité des messages, liens, pièces jointes et demandes inhabituelles avant toute action. Dans un contexte IoT, une erreur humaine sur un poste de travail, une passerelle ou une console d’administration peut avoir des effets étendus sur plusieurs équipements connectés.</li>
  <li>Adopter une discipline opérationnelle claire : signaler les comportements suspects, éviter les contournements de sécurité, protéger les accès et documenter les incidents. Ces réflexes réduisent directement le risque d’exploitation des techniques humaines les plus probables.</li>
</ul>
"""

        scenario_html = f"""
<h3>Mise en situation réaliste</h3>
<p>Un employé occupant le rôle de <strong>{jr_esc}</strong> reçoit une demande apparemment urgente liée à un actif ou un système IoT qu’il utilise dans son travail.
Le message semble crédible, mais plusieurs indices montrent qu’il peut s’agir d’une tentative d’ingénierie sociale ou d’une attaque ciblée.
La bonne réponse consiste à interrompre l’action, vérifier la source, appliquer la procédure interne et signaler l’événement, plutôt que de cliquer, répondre ou modifier la configuration sans validation.</p>
"""

        indices_html = """
<h3>Analyse des indices</h3>
<ul>
  <li>Un ton d’urgence inhabituel, une demande de secret, un changement de procédure ou une pression temporelle excessive doivent immédiatement faire penser à une tentative de manipulation humaine. Ces signaux sont fréquents dans les scénarios de phishing, d’exécution involontaire ou de vol d’identifiants.</li>
  <li>Dans un contexte IoT, tout message demandant un accès, une mise à jour, un changement de configuration ou une action sur un équipement connecté doit être recoupé avec les procédures prévues. Une simple erreur humaine peut devenir un vecteur d’attaque sur l’ensemble de l’environnement technique.</li>
</ul>
"""

        mini_test_html = """
<h3>Mini test simulé</h3>
<ol>
  <li>Si vous recevez une demande urgente liée à un système IoT critique, quelle première vérification devez-vous effectuer avant d’agir ? Le bon réflexe consiste à valider la source, le canal, la cohérence de la demande et le respect de la procédure.</li>
  <li>Pourquoi une technique humaine comme le phishing ou la manipulation d’accès peut-elle avoir un fort impact en environnement IoT ? Parce qu’une seule action incorrecte peut exposer des équipements, des accès, des flux ou des mises à jour touchant plusieurs composants connectés.</li>
</ol>
"""

        conclusion_html = """
<h3>Conclusion</h3>
<p>Réduire le risque humain en cybersécurité IoT ne repose pas seulement sur des outils, mais aussi sur des réflexes fiables, répétés et adaptés au contexte réel de travail.
En identifiant mieux les signaux faibles, en appliquant les bonnes procédures et en comprenant les techniques humaines les plus probables, l’utilisateur peut diminuer concrètement son exposition et protéger plus efficacement les actifs dont il a la responsabilité.</p>
"""

        final_html = (
            intro_html
            + "<h3>Modules</h3>"
            + "".join(modules_html)
            + reco_html
            + scenario_html
            + indices_html
            + mini_test_html
            + conclusion_html
        )

        return {
            "html": final_html.strip(),
            "quality_metrics": aggregate_metrics,
            "blueprint": blueprints,
            "modules_metrics": modules_metrics,
            "learning_summary": learning_summary,
        }

    except Exception as e:
        print(f"Erreur génération contenu formation modulaire : {e}")
        return {
            "html": "<h2>Erreur</h2><p>Erreur lors de la génération du contenu de formation.</p>",
            "quality_metrics": {"quality_score": 0.0, "error": str(e)},
            "blueprint": [],
            "modules_metrics": [],
            "learning_summary": {},
        }


def _safe_float(v, default=0.0) -> float:
    try:
        if v is None:
            return float(default)
        if isinstance(v, str):
            v = v.strip().replace(",", ".")
            if v == "":
                return float(default)
        return float(v)
    except Exception:
        return float(default)
def vulnerability_score(user_id: str) -> float:
    """
    V = (total - score) / total à partir du dernier quiz **avec scores exploitables**.

    /evaluate insère un document avec user_score + total_questions ; /api/save_quiz_result peut
    insérer un second document avec une autre valeur de `date` (ISO string vs datetime) et des
    champs manquants — un tri par date seul pouvait alors prendre la mauvaise entrée et renvoyer V=0.
    """
    last = mongo.db.quiz_history.find_one(
        {
            "userID": user_id,
            "user_score": {"$ne": None, "$exists": True},
            "total_questions": {"$gt": 0},
        },
        sort=[("date", -1)],
    )

    if not last:
        return 0.0

    user_score = last.get("user_score")
    total_questions = last.get("total_questions")

    try:
        tq = int(total_questions)
        us = int(user_score)
        if tq <= 0:
            return 0.0
        V = (tq - us) / tq
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0

    return max(0.0, min(1.0, V))


def generate_profile_risk(user_id: str, max_profile_repair_attempts: int = 1) -> dict:
    user_id = str(user_id).strip()

    if not user_id:
        raise ValueError("user_id vide")

    user = mongo.db.users.find_one({"basic_info.userID": user_id})
    if not user:
        raise ValueError(f"Utilisateur {user_id} introuvable dans 'users'")

    profil = user.get("profil", {}) or {}
    job_role = (profil.get("jobRole") or user.get("jobRole") or "").strip()

    role_doc = mongo.db.role_assets.find_one({"jobRole": job_role}) or {}
    asset_ids = role_doc.get("asset_ids", []) or []
    asset_ids = [str(x).strip() for x in asset_ids if str(x).strip()]

    vin = validate_profile_inputs(user_id, user, role_doc, asset_ids)
    if not vin.get("ok"):
        raise ValueError(
            "Validation pré-génération échouée : " + "; ".join(vin.get("errors") or [])
        )

    # Rmax théorique : Vmax=1, Impact max=9, Tmax=1
    RISK_MAX = 9.0
    V_FLOOR = 0.10

    T_BASE = {
        "T1566": 0.72,
        "T1204": 0.68,
        "T1078": 0.55,
        "T1190": 0.75,
        "T1203": 0.70,
        "T1059": 0.65,
        "T1110": 0.58,
        "T1133": 0.50,
        "T1040": 0.52,
        "T1046": 0.48,
        "T1021": 0.54,
        "T1534": 0.57,
        "T1552": 0.45,
    }

    def get_risk_level(score_norm: float) -> str:
        score_norm = max(0.0, min(1.0, _safe_float(score_norm, 0.0)))
        if score_norm < 0.33:
            return "faible"
        if score_norm < 0.66:
            return "moyen"
        return "élevé"

    def normalize_technique(t: dict, asset_name: str) -> dict | None:
        if not isinstance(t, dict):
            return None

        tid_raw = (t.get("technique_id") or t.get("id") or "").strip()
        canon, inferred_parent, orig_id = canonicalize_mitre_id(tid_raw)
        if not canon:
            return None

        tid = canon
        tid_base = tid.split(".")[0]

        raw_name = (t.get("technique_name") or t.get("name") or "").strip()
        tname = (
            MITRE_NAMES.get(tid)
            or MITRE_NAMES.get(tid_base)
            or raw_name
            or tid_base
        )

        desc = (t.get("description") or "").strip()

        cia = t.get("cia_impact", [])
        if isinstance(cia, str):
            cia = [c for c in cia if c in ("C", "I", "D")]
        elif isinstance(cia, list):
            cia = [str(c).strip().upper() for c in cia if str(c).strip().upper() in ("C", "I", "D")]
        else:
            cia = []

        override = get_cia_for_technique(tid) or get_cia_for_technique(tid_base)
        if override:
            cia = list(override)

        out = dict(t)
        out["technique_id"] = tid
        out["technique_name"] = tname
        out["description"] = desc
        out["asset_name"] = asset_name
        out["cia_impact"] = cia
        if inferred_parent and orig_id:
            out["inferred_parent"] = True
            out["original_technique_id"] = orig_id
        return out

    def infer_asset_family(asset_doc: dict) -> str:
        name = str(asset_doc.get("name") or asset_doc.get("_id") or "").lower()
        tags = asset_doc.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        blob = name + " " + " ".join(str(t).lower() for t in tags)

        if any(k in blob for k in ("switch", "routeur", "router", "firewall", "pare-feu", "lan", "vlan", "network", "réseau", "wifi", "wi-fi", "contrôleur", "controller", "sonde")):
            return "network"
        if any(k in blob for k in ("web", "http", "serveur web", "apache", "nginx", "iis", "api")):
            return "web"
        if any(k in blob for k in ("cloud", "azure", "aws", "gcp", "saas", "office365")):
            return "cloud"
        if any(k in blob for k in ("vpn", "tunnel", "remote access")):
            return "vpn"
        if any(k in blob for k in ("poste", "laptop", "workstation", "utilisateur", "desktop", "pc", "mail", "messagerie", "github", "ide")):
            return "user"
        return "generic"

    def default_techniques_for_asset(asset_doc: dict) -> list[dict]:
        fam = infer_asset_family(asset_doc)
        mapping = {
            "network": [
                {"technique_id": "T1021", "technique_name": "Remote Services", "cia_impact": ["C", "I"], "T": 0.54},
                {"technique_id": "T1110", "technique_name": "Brute Force", "cia_impact": ["C", "I"], "T": 0.58},
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "cia_impact": ["C", "I"], "T": 0.55},
                {"technique_id": "T1133", "technique_name": "External Remote Services", "cia_impact": ["C", "I", "D"], "T": 0.50},
            ],
            "vpn": [
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "cia_impact": ["C", "I"], "T": 0.55},
                {"technique_id": "T1133", "technique_name": "External Remote Services", "cia_impact": ["C", "I", "D"], "T": 0.50},
                {"technique_id": "T1110", "technique_name": "Brute Force", "cia_impact": ["C", "I"], "T": 0.58},
            ],
            "web": [
                {"technique_id": "T1534", "technique_name": "Internal Spearphishing", "cia_impact": ["C"], "T": 0.57},
                {"technique_id": "T1204", "technique_name": "User Execution", "cia_impact": ["C", "I"], "T": 0.68},
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "cia_impact": ["C", "I"], "T": 0.55},
            ],
            "cloud": [
                {"technique_id": "T1552", "technique_name": "Unsecured Credentials", "cia_impact": ["C", "I"], "T": 0.45},
                {"technique_id": "T1534", "technique_name": "Internal Spearphishing", "cia_impact": ["C"], "T": 0.57},
                {"technique_id": "T1110", "technique_name": "Brute Force", "cia_impact": ["C", "I"], "T": 0.58},
            ],
            "user": [
                {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "cia_impact": ["C"], "T": 0.72},
                {"technique_id": "T1204", "technique_name": "User Execution", "cia_impact": ["C", "I"], "T": 0.68},
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "cia_impact": ["C", "I"], "T": 0.55},
            ],
            "generic": [
                {"technique_id": "T1552", "technique_name": "Unsecured Credentials", "cia_impact": ["C", "I"], "T": 0.45},
                {"technique_id": "T1110", "technique_name": "Brute Force", "cia_impact": ["C", "I"], "T": 0.58},
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "cia_impact": ["C", "I"], "T": 0.55},
            ],
        }
        return mapping.get(fam, mapping["generic"])

    def merge_and_enrich_techniques(asset_doc: dict, graph: dict) -> list[dict]:
        raw_items = []

        for key in (
            "human_techniques",
            "human_related",
            "hybrid_techniques",
            "non_human_techniques",
            "non_human",
        ):
            val = graph.get(key) or []
            if isinstance(val, dict):
                val = [val]
            if isinstance(val, list):
                raw_items.extend(val)

        existing_bases = {
            str(t.get("technique_id") or t.get("id") or "").strip().upper().split(".")[0]
            for t in raw_items
            if isinstance(t, dict)
        }
        existing_bases.discard("")

        for extra in default_techniques_for_asset(asset_doc):
            base = str(extra.get("technique_id") or "").strip().upper().split(".")[0]
            if base and base not in existing_bases:
                raw_items.append(extra)

        # Signature distincte par actif (évite profils MITRE identiques après défauts famille)
        aid = str(asset_doc.get("_id") or "").strip()
        if aid:
            have = {
                str(t.get("technique_id") or "").strip().upper().split(".")[0]
                for t in raw_items
                if isinstance(t, dict)
            }
            have.discard("")
            pool = ["T1110", "T1550", "T1098", "T1021", "T1133", "T1552"]
            want = pool[abs(hash(aid)) % len(pool)]
            if want not in have:
                raw_items.append(
                    {
                        "technique_id": want,
                        "technique_name": MITRE_NAMES.get(want),
                        "cia_impact": ["C", "I"],
                        "T": 0.48,
                    }
                )

        # dédup par technique_id complet
        dedup = {}
        for t in raw_items:
            if not isinstance(t, dict):
                continue
            tid = str(t.get("technique_id") or t.get("id") or "").strip().upper()
            if tid:
                dedup[tid] = t

        vals = list(dedup.values())
        # Max 1 technique phishing (famille T1566) — aligné profil humain/hybride
        kept_phish = False
        capped: list = []
        for t in vals:
            base = str(t.get("technique_id") or "").strip().upper().split(".")[0]
            if base == "T1566":
                if not kept_phish:
                    kept_phish = True
                    capped.append(t)
                continue
            capped.append(t)

        return capped

    def compute_risk_metrics(v: float, impact_value: float, t_score: float, hf: float) -> dict:
        # pondération humaine continue
        effective_weight = 0.30 + 0.70 * max(0.0, min(1.0, hf))
        if v == 0:
            # AVANT QUIZ → risque contextuel (pas de V de quiz)
            risk_brut = impact_value * t_score
        else:
            # APRÈS QUIZ → risque humain réel
            risk_brut = v * impact_value * t_score * effective_weight
        risk_norm = risk_brut / RISK_MAX if RISK_MAX > 0 else 0.0
        risk_pct = risk_norm * 100

        return {
            "risk_brut": round(risk_brut, 4),
            "risk_norm": round(risk_norm, 4),
            "risk_pct": round(risk_pct, 2),
            "riskLevel": get_risk_level(risk_norm),
        }

    V_raw = vulnerability_score(user_id)
    V_raw = max(0.0, min(1.0, _safe_float(V_raw, 0.0)))

    quiz_done = V_raw > 0

    # IMPORTANT : on garde V = 0 si pas de quiz
    V = V_raw

    def _build_once(force_regen_all: bool, repair_attempt: int = 0) -> dict:
        assets_analysis = []
        structural_errors: list[str] = []
        global_warnings: list[str] = []
        global_errors: list[str] = []

        graphs_by_asset: dict[str, dict] = {}
        asset_docs_by_id: dict[str, dict] = {}

        diversity_key = f"r{repair_attempt}"

        for asset_id in asset_ids:
            asset_doc = mongo.db.assets_catalog.find_one({"_id": asset_id})
            if not asset_doc:
                print(f"[WARN] Asset {asset_id} non trouvé dans assets_catalog")
                continue

            if asset_doc.get("tags") is None:
                asset_doc = {**asset_doc, "tags": []}

            asset_name = (asset_doc.get("name") or asset_id).strip()
            asset_docs_by_id[asset_id] = asset_doc

            if force_regen_all:
                print(f"[PROFILE_RISK] Réparation : régénération forcée du graphe pour {asset_name} ({asset_id})")
                graph = ensure_attack_graph_for_asset(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    tags=asset_doc.get("tags", []) or [],
                    force=True,
                    regen_if_empty=True,
                    job_role=job_role or None,
                    diversity_nonce=f"{asset_id}-{diversity_key}",
                ) or {}
            else:
                graph = (
                    mongo.db.attack_graphs.find_one({"asset_id": asset_id})
                    or mongo.db.attack_graphs.find_one({"_id": asset_id})
                    or {}
                )

                if not graph or graph.get("threat_score") is None:
                    graph = ensure_attack_graph_for_asset(
                        asset_id=asset_id,
                        asset_name=asset_name,
                        tags=asset_doc.get("tags", []) or [],
                        force=True,
                        regen_if_empty=True,
                        job_role=job_role or None,
                        diversity_nonce=f"{asset_id}-{diversity_key}",
                    ) or {}

            graphs_by_asset[asset_id] = graph

        inject_graph_signature_diversity(graphs_by_asset)

        for asset_id in asset_ids:
            asset_doc = asset_docs_by_id.get(asset_id)
            if not asset_doc:
                continue

            asset_name = (asset_doc.get("name") or asset_id).strip()

            C = _safe_float(asset_doc.get("C"), 0)
            I = _safe_float(asset_doc.get("I"), 0)
            D = _safe_float(asset_doc.get("D"), 0)

            impact = _safe_float(asset_doc.get("impact"), 0)
            if impact <= 0:
                impact = C + I + D
            impact = max(0.0, min(9.0, impact))

            graph = graphs_by_asset.get(asset_id) or {}

            threat_score = max(0.0, min(1.0, _safe_float(graph.get("threat_score"), 0.6)))

            structural_errors.extend(validate_attack_graph_structure(graph, asset_id))

            raw_items = merge_and_enrich_techniques(asset_doc, graph)
            structural_errors.extend(validate_asset_technique_relevance(asset_doc, raw_items))

            exposed_techniques = []

            for t in raw_items:
                norm = normalize_technique(t, asset_name)
                if not norm:
                    continue

                tid = norm["technique_id"]
                tid_base = tid.split(".")[0]

                cls = mitre_classification(
                    tid,
                    norm.get("technique_name", ""),
                    norm.get("description", ""),
                )

                try:
                    hf = float(human_factor(tid))
                except Exception:
                    if cls == "human":
                        hf = 1.0
                    elif cls == "hybrid":
                        hf = 0.5
                    else:
                        hf = 0.0

                hf = max(0.0, min(1.0, hf))

                T = _safe_float(norm.get("T"), T_BASE.get(tid_base, threat_score))
                if tid_base in T_BASE:
                    T = T_BASE[tid_base] if abs(T - T_BASE[tid_base]) > 0.35 else T
                T = max(0.0, min(1.0, T))

                risk_metrics = compute_risk_metrics(V, impact, T, hf)

                norm["V_raw"] = round(V_raw, 4)
                norm["V"] = round(V, 4)
                norm["impact"] = round(impact, 4)
                norm["T"] = round(T, 4)
                norm["risk_brut"] = risk_metrics["risk_brut"]
                norm["risk_norm"] = risk_metrics["risk_norm"]
                norm["risk_pct"] = risk_metrics["risk_pct"]
                norm["riskLevel"] = risk_metrics["riskLevel"]
                norm["human_factor"] = round(hf, 4)
                norm["classification"] = cls

                global_warnings.extend(validate_human_factor_consistency([norm]))
                global_warnings.extend(validate_t_scores([norm], asset_id))

                exposed_techniques.append(norm)

            exposed_techniques = sorted(
                exposed_techniques,
                key=lambda x: x.get("risk_brut", 0),
                reverse=True
            )

            structural_errors.extend(
                validate_exposed_techniques_constraints(asset_id, exposed_techniques)
            )

            if exposed_techniques:
                top_risks_brut = [x["risk_brut"] for x in exposed_techniques[:3]]
                top_T = [x["T"] for x in exposed_techniques[:3]]

                asset_risk_brut = sum(top_risks_brut) / len(top_risks_brut)
                asset_T = sum(top_T) / len(top_T)
            else:
                asset_T = threat_score
                asset_risk_brut = V * impact * asset_T

            asset_risk_norm = asset_risk_brut / RISK_MAX if RISK_MAX > 0 else 0.0
            asset_risk_pct = asset_risk_norm * 100

            cia_impact = []
            if C > 0:
                cia_impact.append("C")
            if I > 0:
                cia_impact.append("I")
            if D > 0:
                cia_impact.append("D")

            human_techniques = [x for x in exposed_techniques if x.get("classification") == "human"]
            hybrid_techniques = [x for x in exposed_techniques if x.get("classification") == "hybrid"]
            non_human_techniques = [x for x in exposed_techniques if x.get("classification") == "non_human"]

            assets_analysis.append({
                "asset_id": asset_id,
                "asset_name": asset_name,

                "V_raw": round(V_raw, 4),
                "V": round(V, 4),
                "T": round(asset_T, 4),

                "C": round(C, 2),
                "I": round(I, 2),
                "D": round(D, 2),
                "impact": round(impact, 4),

                "risk_brut": round(asset_risk_brut, 4),
                "risk_norm": round(asset_risk_norm, 4),
                "risk_pct": round(asset_risk_pct, 2),
                "riskLevel": get_risk_level(asset_risk_norm),

                "cia_impact": cia_impact,
                "rationale": graph.get("rationale", ""),

                "human_techniques": human_techniques,
                "hybrid_techniques": hybrid_techniques,
                "non_human_techniques": non_human_techniques,
                "exposed_techniques": exposed_techniques,
                "technique_count": len(exposed_techniques),
            })

            print(
                f"[PROFILE_RISK] {asset_id} "
                f"all={len(exposed_techniques)} "
                f"human={len(human_techniques)} "
                f"risk={round(asset_risk_pct, 2)}%"
            )

        if assets_analysis:
            weighted_sum = sum(a["risk_brut"] * max(a["impact"], 0.001) for a in assets_analysis)
            weight_total = sum(max(a["impact"], 0.001) for a in assets_analysis)
            global_risk_brut = (weighted_sum / weight_total) if weight_total > 0 else 0.0
        else:
            global_risk_brut = 0.0

        global_risk_norm = global_risk_brut / RISK_MAX if RISK_MAX > 0 else 0.0
        global_risk_pct = global_risk_norm * 100

        div_errs, div_warns = validate_mitre_diversity(assets_analysis)
        global_errors.extend(div_errs)
        global_warnings.extend(div_warns)

        global_errors.extend(validate_unique_asset_profiles(assets_analysis))

        risk_calc_errs = validate_risk_calculations(assets_analysis)
        structural_errors.extend(risk_calc_errs)

        profile_quality = compute_profile_quality_metrics(
            assets_analysis=assets_analysis,
            structural_errors=structural_errors,
            global_warnings=global_warnings,
            global_errors=global_errors,
        )

        acceptable = profile_acceptable(
            profile_quality=profile_quality,
            structural_errors=structural_errors,
            global_errors=global_errors,
            quality_threshold=55.0,
        )

        validation_flat = list(dict.fromkeys(structural_errors + global_errors))
        warnings_flat = list(dict.fromkeys(global_warnings))

        return {
            "assetCount": len(assets_analysis),

            "globalRisk": round(global_risk_brut, 4),
            "globalRiskBrut": round(global_risk_brut, 4),
            "globalRiskNorm": round(global_risk_norm, 4),
            "globalRiskPct": round(global_risk_pct, 2),
            "globalRiskLevel": get_risk_level(global_risk_norm),

            "assets": assets_analysis,

            "profile_valid": len(validation_flat) == 0,
            "profile_acceptable": acceptable,
            "validation_errors": validation_flat,
            "validation_warnings": warnings_flat,
            "profile_quality_metrics": profile_quality,
        }

    last_result: dict | None = None
    attempt = 0

    for attempt in range(max_profile_repair_attempts + 1):
        last_result = _build_once(
            force_regen_all=(attempt > 0),
            repair_attempt=attempt,
        )
        if last_result.get("profile_acceptable") or attempt >= max_profile_repair_attempts:
            break

    assert last_result is not None
    last_result["userID"] = user_id
    last_result["jobRole"] = job_role
    last_result["repair_attempts"] = attempt
    try:
        last_result["has_quiz_evaluation"] = (
            mongo.db.quiz_history.count_documents({"userID": user_id}) > 0
        )
    except Exception:
        last_result["has_quiz_evaluation"] = False
    return last_result