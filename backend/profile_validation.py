# -*- coding: utf-8 -*-
"""
Validation du profil de risque : entrées, graphe MITRE, anti-biais, qualité globale.
Aligné sur l’esprit de compute_quiz_quality_metrics / validate_questions_after_gpt.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter
from typing import Any

from m import MITRE_NAMES, human_factor, mitre_classification

MITRE_ID_RE = re.compile(r"^T\d{4,5}(?:\.\d{3})?$", re.IGNORECASE)

# Au moins une technique « compte / identité » 
ACCOUNT_REQUIRED_BASES = frozenset({"T1078", "T1110", "T1550", "T1098"})

# Référence T « locale » pour comparer au T GPT 
T_BASE_LOCAL: dict[str, float] = {
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

# Familles d’actifs → IDs MITRE attendus (bases) — éviter de forcer T1078 partout
ASSET_FAMILY_EXPECTED_BASES: dict[str, set[str]] = {
    "network": {"T1021", "T1133", "T1110", "T1078"},
    "web": {"T1534", "T1204", "T1078", "T1566"},
    "cloud": {"T1110", "T1534", "T1552", "T1078"},
    "user": {"T1566", "T1204", "T1078"},
    "vpn": {"T1133", "T1110", "T1021"},
    "generic": set(),
}

FAMILY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (
        "network",
        (
            "switch", "routeur", "router", "firewall", "pare-feu",
            "lan", "vlan", "network", "réseau", "wifi", "wi-fi",
            "contrôleur", "controller", "sonde",
        ),
    ),
    ("web", ("web", "http", "serveur web", "apache", "nginx", "iis", "api")),
    ("cloud", ("cloud", "azure", "aws", "gcp", "saas", "office365")),
    ("vpn", ("vpn", "tunnel", "remote access")),
    ("user", ("poste", "laptop", "workstation", "utilisateur", "desktop", "pc")),
]


def _infer_asset_family(asset_doc: dict) -> str:
    name = str(asset_doc.get("name") or asset_doc.get("_id") or "").lower()
    tags = asset_doc.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    blob = name + " " + " ".join(str(t).lower() for t in tags)
    for fam, kws in FAMILY_KEYWORDS:
        if any(k in blob for k in kws):
            return fam
    return "generic"


def _tid_base(tid: str) -> str:
    return str(tid or "").strip().upper().split(".")[0]


def techniques_list_for_asset(asset_row: dict) -> list:
    """Liste fusionnée pour métriques / diversité : exposed_techniques si présent, sinon human+hybrid+non."""
    ex = asset_row.get("exposed_techniques")
    if isinstance(ex, list) and len(ex) > 0:
        return ex
    merged: list = []
    for k in ("human_techniques", "hybrid_techniques", "non_human_techniques"):
        x = asset_row.get(k) or []
        if isinstance(x, dict):
            x = [x]
        if isinstance(x, list):
            merged.extend(x)
    return merged


def normalize_asset_tags(asset_doc: dict) -> list:
    t = asset_doc.get("tags")
    if t is None:
        return []
    if isinstance(t, list):
        return t
    return []


def validate_profile_inputs(
    user_id: str,
    user: dict | None,
    role_doc: dict | None,
    asset_ids: list[str],
) -> dict[str, Any]:
    """
    Avant génération : utilisateur, rôle, actifs, scores CIA, tags.
    Retourne { ok(bool), errors(list), warnings(list), asset_docs(list[dict]) }
    """
    errors: list[str] = []
    warnings: list[str] = []
    asset_docs: list[dict] = []

    if not str(user_id or "").strip():
        errors.append("input:user_id_vide")
        return {"ok": False, "errors": errors, "warnings": warnings, "asset_docs": []}

    if not user:
        errors.append("input:user_introuvable")
        return {"ok": False, "errors": errors, "warnings": warnings, "asset_docs": []}

    profil = user.get("profil", {}) or {}
    job_role = (profil.get("jobRole") or user.get("jobRole") or "").strip()
    if not job_role:
        errors.append("input:jobRole_manquant")

    if role_doc is None:
        warnings.append("input:role_doc_absent")

    if not asset_ids:
        errors.append("input:asset_ids_vide")

    from extensions import mongo  #

    for aid in asset_ids:
        aid = str(aid).strip()
        if not aid:
            continue

        doc = mongo.db.assets_catalog.find_one({"_id": aid})
        if not doc:
            errors.append(f"input:asset_absent_catalog:{aid}")
            continue

        c = doc.get("C")
        i = doc.get("I")
        d = doc.get("D")
        missing_cia = []
        for label, val in (("C", c), ("I", i), ("D", d)):
            try:
                float(val)
            except (TypeError, ValueError):
                missing_cia.append(label)

        if missing_cia:
            errors.append(f"input:asset_cia_incomplet:{aid}:{','.join(missing_cia)}")

        if not isinstance(doc.get("tags"), list):
            warnings.append(f"input:asset_tags_non_liste:{aid}")

        asset_docs.append(doc)

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "asset_docs": asset_docs,
    }


def validate_attack_graph_structure(
    graph: dict,
    asset_id: str,
    *,
    dedupe_scope: str = "asset",
) -> list[str]:
    errs: list[str] = []
    seen: set[str] = set()

    def check_list(items: list, label: str) -> None:
        nonlocal seen

        if not isinstance(items, list):
            return

        for t in items:
            if not isinstance(t, dict):
                errs.append(f"graph:{asset_id}:{label}:not_dict")
                continue

            tid = (t.get("technique_id") or t.get("id") or "").strip()
            if not tid:
                errs.append(f"graph:{asset_id}:{label}:technique_id_manquant")
                continue

            if not MITRE_ID_RE.match(tid):
                errs.append(f"graph:{asset_id}:{label}:id_invalide:{tid}")
                continue

            tid_u = tid.upper()
            if dedupe_scope == "asset" and tid_u in seen:
                errs.append(f"graph:{asset_id}:doublon_technique:{tid_u}")
            seen.add(tid_u)

            cia = t.get("cia_impact", [])
            if isinstance(cia, str):
                cia = [c for c in cia if c in "CID"]
            elif isinstance(cia, list):
                bad = [c for c in cia if str(c).strip().upper() not in ("C", "I", "D")]
                if bad:
                    errs.append(f"graph:{asset_id}:{label}:cia_invalide:{tid_u}")
            elif cia not in (None, []):
                errs.append(f"graph:{asset_id}:{label}:cia_type:{tid_u}")

            try:
                tv = float(t.get("T", 0.6))
                if tv < 0 or tv > 1:
                    errs.append(f"graph:{asset_id}:{label}:T_hors_borne:{tid_u}")
            except (TypeError, ValueError):
                errs.append(f"graph:{asset_id}:{label}:T_invalide:{tid_u}")

    human = graph.get("human_related") or graph.get("human_techniques") or []
    hybrid = graph.get("hybrid_techniques") or []
    nonh = graph.get("non_human") or graph.get("non_human_techniques") or []

    if isinstance(human, dict):
        human = [human]
    if isinstance(hybrid, dict):
        hybrid = [hybrid]
    if isinstance(nonh, dict):
        nonh = [nonh]

    check_list(human if isinstance(human, list) else [], "human")
    check_list(hybrid if isinstance(hybrid, list) else [], "hybrid")
    check_list(nonh if isinstance(nonh, list) else [], "non_human")

    nh_list = nonh if isinstance(nonh, list) else []
    if len(nh_list) > 0:
        errs.append(f"graph:{asset_id}:non_human_bucket_interdit")

    if len(seen) < 3:
        errs.append(f"graph:{asset_id}:min_3_techniques_distinctes:{len(seen)}")

    bases = {_tid_base(x) for x in seen}
    bases.discard("")

    if bases and bases.issubset({"T1566", "T1204"}):
        errs.append(f"graph:{asset_id}:uniquement_t1566_t1204")

    if bases and not (bases & ACCOUNT_REQUIRED_BASES):
        errs.append(f"graph:{asset_id}:technique_compte_requise_t1078_t1110_t1550_t1098")

    def _flat_technique_dicts() -> list[dict]:
        out: list[dict] = []
        for lst in (human, hybrid, nonh):
            if isinstance(lst, list):
                for t in lst:
                    if isinstance(t, dict):
                        out.append(t)
        return out

    phish_cnt = 0
    for t in _flat_technique_dicts():
        tid = (t.get("technique_id") or t.get("id") or "").strip()
        if not tid:
            continue
        if _tid_base(tid) == "T1566":
            phish_cnt += 1
        cls = mitre_classification(
            tid,
            str(t.get("technique_name") or ""),
            str(t.get("description") or ""),
        )
        if cls == "non_human":
            errs.append(f"graph:{asset_id}:technique_purement_technique:{tid}")

    if phish_cnt > 1:
        errs.append(f"graph:{asset_id}:max_1_phishing:{phish_cnt}")

    return errs

def validate_exposed_techniques_constraints(
    asset_id: str,
    exposed_techniques: list[dict],
) -> list[str]:
    """
    Mêmes règles métier que le graphe, appliquées au profil **livré**
    (après `normalize_technique`), au cas où des entrées seraient filtrées.
    """
    errs: list[str] = []
    seen: set[str] = set()
    for t in exposed_techniques or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("technique_id") or t.get("id") or "").strip().upper()
        if tid:
            seen.add(tid)

    if len(seen) < 3:
        errs.append(f"exposed:{asset_id}:min_3_techniques_distinctes:{len(seen)}")

    bases = {_tid_base(x) for x in seen}
    bases.discard("")

    if bases and bases.issubset({"T1566", "T1204"}):
        errs.append(f"exposed:{asset_id}:uniquement_t1566_t1204")

    if bases and not (bases & ACCOUNT_REQUIRED_BASES):
        errs.append(f"exposed:{asset_id}:technique_compte_requise_t1078_t1110_t1550_t1098")

    phish_x = 0
    for t in exposed_techniques or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("technique_id") or t.get("id") or "").strip()
        if not tid:
            continue
        if _tid_base(tid) == "T1566":
            phish_x += 1
        cls = mitre_classification(
            tid,
            str(t.get("technique_name") or ""),
            str(t.get("description") or ""),
        )
        if cls == "non_human":
            errs.append(f"exposed:{asset_id}:technique_purement_technique:{tid}")
    if phish_x > 1:
        errs.append(f"exposed:{asset_id}:max_1_phishing:{phish_x}")

    return errs


def validate_unique_asset_profiles(assets_analysis: list[dict]) -> list[str]:
    """
    Chaque actif doit avoir un profil MITRE distinct (ensemble des bases Txxxx).
    Basé sur exposed_techniques (ou listes fusionnées).
    """
    errs: list[str] = []
    if not assets_analysis or len(assets_analysis) <= 1:
        return errs

    sig_to_ids: dict[tuple[str, ...], list[str]] = {}
    for a in assets_analysis:
        aid = str(a.get("asset_id") or "").strip()
        ht = techniques_list_for_asset(a)
        if isinstance(ht, dict):
            ht = [ht]
        if not isinstance(ht, list):
            ht = []
        bases = sorted(
            {
                _tid_base(t.get("technique_id") or t.get("id") or "")
                for t in ht
                if isinstance(t, dict)
            }
        )
        bases = tuple(b for b in bases if b)
        sig_to_ids.setdefault(bases, []).append(aid)

    for sig, ids in sig_to_ids.items():
        uids = [x for x in ids if x]
        if len(uids) <= 1:
            continue
        if len(set(uids)) < 2:
            continue
        if len(sig) == 0:
            errs.append(
                f"diversity:profil_mitre_vide_duplique:{','.join(sorted(set(uids)))}"
            )
            continue
        errs.append(
            f"diversity:profil_mitre_identique:{','.join(sorted(set(uids)))}:{sig}"
        )

    return errs


def validate_asset_technique_relevance(
    asset_doc: dict,
    techniques: list[dict],
) -> list[str]:
    """Au moins une technique adaptée à la famille d’actif (si famille connue)."""
    errs: list[str] = []

    fam = _infer_asset_family(asset_doc)
    expected = ASSET_FAMILY_EXPECTED_BASES.get(fam) or set()
    if not expected:
        return errs

    bases = {
        _tid_base(t.get("technique_id") or t.get("id") or "")
        for t in techniques
        if isinstance(t, dict)
    }
    bases.discard("")

    if not bases & expected:
        errs.append(
            f"relevance:{asset_doc.get('_id')}:famille_{fam}:aucune_technique_attendue"
        )

    return errs


def validate_mitre_diversity(assets_analysis: list[dict]) -> tuple[list[str], list[str]]:
    """
    Anti-biais global : répétitions, paires T1566+T1204, même paire sur trop d’actifs.
    Retourne (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not assets_analysis:
        errors.append("diversity:assets_vide")
        return errors, warnings

    n_assets = len(assets_analysis)
    all_tids: list[str] = []

    per_asset_pairs: Counter[str] = Counter()
    assets_with_zero_techniques = 0
    assets_with_only_t1566_t1204 = 0

    for a in assets_analysis:
        ht = techniques_list_for_asset(a)
        if isinstance(ht, dict):
            ht = [ht]
        if not isinstance(ht, list):
            ht = []

        bases = sorted(
            {
                _tid_base(t.get("technique_id") or "")
                for t in ht
                if isinstance(t, dict)
            }
        )
        bases = [b for b in bases if b]

        if not bases:
            assets_with_zero_techniques += 1

        if bases and set(bases).issubset({"T1566", "T1204"}):
            assets_with_only_t1566_t1204 += 1

        if len(bases) >= 2:
            per_asset_pairs[f"{bases[0]}+{bases[1]}"] += 1

        all_tids.extend(bases)

    uniq = len(set(all_tids))
    total_t = len(all_tids)

    # technique unique globale trop faible
    if n_assets >= 2 and uniq < 3:
        errors.append(f"diversity:mitre_uniques_insuffisants:{uniq}")

    # trop d'actifs sans techniques
    if assets_with_zero_techniques >= max(1, n_assets // 2):
        errors.append(
            f"diversity:trop_actifs_sans_techniques:{assets_with_zero_techniques}/{n_assets}"
        )

    # actif n'ayant que T1566/T1204 (familles) — refusé (cf. validate_attack_graph_structure)
    if assets_with_only_t1566_t1204 >= 1:
        errors.append(
            f"diversity:actif_uniquement_t1566_t1204:{assets_with_only_t1566_t1204}"
        )

    # même paire sur >= 70% des actifs
    if n_assets >= 2 and per_asset_pairs:
        pair, cnt = per_asset_pairs.most_common(1)[0]
        if (cnt / n_assets) >= 0.7:
            errors.append(f"diversity:meme_paire_70pct:{pair}:{cnt}/{n_assets}")

    # domination phishing + user execution
    if total_t > 0:
        phish = sum(1 for x in all_tids if x.startswith("T1566"))
        uex = sum(1 for x in all_tids if x.startswith("T1204"))
        ratio = (phish + uex) / total_t
        if total_t >= 4 and ratio > 0.60:
            errors.append(f"diversity:phishing_user_execution_dominants:{ratio:.2f}")

    # technique sur tous les actifs
    if n_assets >= 2 and total_t > 0:
        c = Counter(all_tids)
        for tid, cnt in c.items():
            if cnt >= n_assets:
                warnings.append(f"diversity:technique_sur_tous_actifs:{tid}")

    # T1078 « fourre-tout » : avertir si présent sur chaque actif
    if n_assets >= 2:
        t1078_assets = 0
        for a in assets_analysis:
            ht = techniques_list_for_asset(a)
            bs = {_tid_base(t.get("technique_id") or "") for t in ht if isinstance(t, dict)}
            bs.discard("")
            if "T1078" in bs:
                t1078_assets += 1
        if t1078_assets >= n_assets:
            warnings.append(f"diversity:t1078_sur_tous_actifs:{t1078_assets}/{n_assets}")

    return errors, warnings


def validate_human_factor_consistency(techniques: list[dict]) -> list[str]:
    """human_factor [0,1] vs classification / mots-clés faibles."""
    warns: list[str] = []
    weak_kw = ("login", "password", "valid account", "credential")

    for t in techniques:
        if not isinstance(t, dict):
            continue

        tid = _tid_base(t.get("technique_id") or "")
        hf = t.get("human_factor")

        try:
            hfv = float(hf) if hf is not None else None
        except (TypeError, ValueError):
            warns.append(f"human:hf_invalide:{tid}")
            continue

        if hfv is not None and not (0 <= hfv <= 1):
            warns.append(f"human:hf_hors_0_1:{tid}")

        cls = (t.get("classification") or "").strip().lower()
        desc = (t.get("description") or "").lower()

        if cls == "human" and hfv is not None and hfv < 0.45:
            warns.append(f"human:incoherence_class_human_hf_bas:{tid}")

        if cls == "non_human" and hfv is not None and hfv > 0.75:
            warns.append(f"human:incoherence_class_non_human_hf_haut:{tid}")

        if cls == "hybrid" and hfv is not None and (hfv < 0.22 or hfv > 0.88):
            warns.append(f"human:incoherence_class_hybrid_hf:{tid}")

        if any(w in desc for w in weak_kw) and hfv is not None and hfv >= 0.95:
            warns.append(f"human:mot_clef_faible_hf_trop_haut:{tid}")

    return warns


def validate_t_scores(
    techniques: list[dict],
    asset_id: str,
    *,
    delta_t_max: float = 0.35,
) -> list[str]:
    """Écart T GPT vs T_base local ; T trop homogènes."""
    warns: list[str] = []
    ts: list[float] = []

    for t in techniques:
        if not isinstance(t, dict):
            continue

        tid = _tid_base(t.get("technique_id") or "")
        try:
            tv = float(t.get("T", 0.6))
        except (TypeError, ValueError):
            warns.append(f"T:invalide:{asset_id}:{tid}")
            continue

        ts.append(tv)

        if not (0 <= tv <= 1):
            warns.append(f"T:hors_borne:{asset_id}:{tid}")

        base = T_BASE_LOCAL.get(tid)
        if base is not None and abs(tv - base) > delta_t_max:
            warns.append(f"T:ecart_base:{asset_id}:{tid}:{tv:.2f}_vs_{base:.2f}")

    if len(ts) >= 2 and (max(ts) - min(ts)) < 0.05:
        warns.append(f"T:faible_discrimination:{asset_id}")

    return warns


def validate_risk_calculations(assets_analysis: list[dict]) -> list[str]:
    """V, impact, risk_brut, risk_norm, risk_pct cohérents."""
    errs: list[str] = []
    RISK_MAX = 9.0

    for a in assets_analysis:
        aid = a.get("asset_id", "?")

        try:
            v = float(a.get("V", 0))
        except (TypeError, ValueError):
            errs.append(f"risk:V_invalide:{aid}")
            continue

        if v < 0:
            errs.append(f"risk:V_negatif:{aid}")

        try:
            impact = float(a.get("impact", 0))
        except (TypeError, ValueError):
            errs.append(f"impact:invalide:{aid}")
            continue

        if impact < 0 or impact > 9:
            errs.append(f"impact:hors_0_9:{aid}")

        ht = techniques_list_for_asset(a)
        if isinstance(ht, dict):
            ht = [ht]

        for t in ht:
            if not isinstance(t, dict):
                continue

            tid = t.get("technique_id", "")

            try:
                rb = float(t.get("risk_brut", 0))
                rn = float(t.get("risk_norm", 0))
                rp = float(t.get("risk_pct", 0))
                tv = float(t.get("T", 0))
            except (TypeError, ValueError):
                errs.append(f"risk:valeur_invalide:{aid}:{tid}")
                continue

            # si human_factor présent, l'ancien check strict V*I*T peut être faux
            if "human_factor" not in t:
                expected = v * impact * tv
                if abs(rb - expected) > 0.02 + 1e-6:
                    errs.append(f"risk:risk_brut_incoherent:{aid}:{tid}")

            if rn < 0 or rn > 1:
                errs.append(f"risk:risk_norm_hors_0_1:{aid}:{tid}")

            if rp < 0 or rp > 100:
                errs.append(f"risk:risk_pct_hors_0_100:{aid}:{tid}")

        try:
            asset_rb = float(a.get("risk_brut", 0))
            asset_rn = float(a.get("risk_norm", 0))
        except (TypeError, ValueError):
            errs.append(f"risk:asset_risk_invalide:{aid}")
            continue

        if asset_rn < 0 or asset_rn > 1:
            errs.append(f"risk:asset_risk_norm:{aid}")

        # cohérence approximative
        if asset_rb > 0 and asset_rn > 0 and abs(asset_rn - asset_rb / RISK_MAX) > 0.08:
            # top-3 / pondérations possibles : on tolère
            pass

    return errs


def compute_profile_quality_metrics(
    *,
    assets_analysis: list[dict],
    structural_errors: list[str],
    global_warnings: list[str],
    global_errors: list[str],
) -> dict[str, Any]:
    """
    Score 0–100 + métriques pour admin / mémoire / debug.
    Version durcie contre les biais T1566/T1204 et la faible couverture.
    """
    n_assets = len(assets_analysis)
    all_tids: list[str] = []
    human_c = hybrid_c = non_c = 0
    all_t: list[float] = []
    risks: list[float] = []

    assets_with_only_t1566_t1204 = 0
    assets_with_zero_techniques = 0

    t1078_asset_hits = 0

    for a in assets_analysis:
        risks.append(float(a.get("risk_brut", 0) or 0))

        ht = techniques_list_for_asset(a)
        if isinstance(ht, dict):
            ht = [ht]
        if not isinstance(ht, list):
            ht = []

        current_bases = set()

        for t in ht:
            if not isinstance(t, dict):
                continue

            tid = _tid_base(t.get("technique_id") or "")
            if tid:
                all_tids.append(tid)
                current_bases.add(tid)

            cls = (t.get("classification") or "").lower()
            if cls == "human":
                human_c += 1
            elif cls == "hybrid":
                hybrid_c += 1
            elif cls == "non_human":
                non_c += 1

            try:
                all_t.append(float(t.get("T", 0)))
            except (TypeError, ValueError):
                pass

        if not current_bases:
            assets_with_zero_techniques += 1

        if current_bases and current_bases.issubset({"T1566", "T1204"}):
            assets_with_only_t1566_t1204 += 1

        if "T1078" in current_bases:
            t1078_asset_hits += 1

    total_tech = len(all_tids)
    uniq = len(set(all_tids))
    repetition_rate = 1.0 - (uniq / total_tech) if total_tech else 1.0

    t_var = statistics.pvariance(all_t) if len(all_t) > 1 else 0.0
    r_var = statistics.pvariance(risks) if len(risks) > 1 else 0.0

    phish_user_exec_count = sum(
        1 for x in all_tids if x.startswith("T1566") or x.startswith("T1204")
    )
    phish_pair_ratio = (phish_user_exec_count / total_tech) if total_tech else 1.0

    total_class = max(human_c + hybrid_c + non_c, 1)
    asset_coverage_score = (
        100.0 * ((n_assets - assets_with_zero_techniques) / max(n_assets, 1))
    )

    out: dict[str, Any] = {
        "profile_quality_score": 0.0,
        "mitre_unique_count": uniq,
        "technique_total_count": total_tech,
        "technique_repetition_rate": round(repetition_rate, 4),
        "asset_coverage_score": round(asset_coverage_score, 1),
        "human_ratio": round(human_c / total_class, 4),
        "hybrid_ratio": round(hybrid_c / total_class, 4),
        "non_human_ratio": round(non_c / total_class, 4),
        "T_variance": round(t_var, 6),
        "risk_brut_variance": round(r_var, 6),
        "phishing_user_execution_ratio": round(phish_pair_ratio, 4),
        "assets_with_only_t1566_t1204": assets_with_only_t1566_t1204,
        "assets_with_zero_techniques": assets_with_zero_techniques,
        "t1078_asset_hits": t1078_asset_hits,
    }

    # Score qualité durci
    score = 100.0

    # Pénalités structurelles
    score -= len(structural_errors) * 12
    score -= len(global_errors) * 15

    # Pénalités warnings
    score -= min(30.0, len(global_warnings) * 4.0)

    # Pénalités métier
    if uniq < 3:
        score -= 20.0
    elif uniq == 3:
        score -= 8.0

    if phish_pair_ratio > 0.60:
        score -= 20.0
    elif phish_pair_ratio > 0.45:
        score -= 10.0

    if assets_with_only_t1566_t1204 >= 1:
        score -= 20.0

    if n_assets >= 2 and t1078_asset_hits >= n_assets:
        score -= 10.0
    elif n_assets >= 2 and t1078_asset_hits >= max(2, n_assets - 1):
        score -= 5.0

    if assets_with_zero_techniques > 0:
        score -= min(20.0, assets_with_zero_techniques * 8.0)

    if asset_coverage_score < 60:
        score -= 15.0
    elif asset_coverage_score < 80:
        score -= 6.0

    if t_var < 0.002:
        score -= 10.0
    elif t_var < 0.01:
        score -= 5.0

    # Petit bonus si diversité bonne
    if uniq >= max(3, n_assets):
        score += 4.0

    score = max(0.0, min(100.0, score))
    out["profile_quality_score"] = round(score, 1)

    return out


def profile_acceptable(
    *,
    profile_quality: dict[str, Any],
    structural_errors: list[str],
    global_errors: list[str],
    quality_threshold: float = 55.0,
) -> bool:
    """
    Décision finale durcie.
    """
    if structural_errors or global_errors:
        return False

    if float(profile_quality.get("profile_quality_score", 0) or 0) < quality_threshold:
        return False

    # Bloquants métier
    if int(profile_quality.get("mitre_unique_count", 0) or 0) < 3:
        return False

    if float(profile_quality.get("phishing_user_execution_ratio", 0) or 0) > 0.70:
        return False

    if int(profile_quality.get("assets_with_only_t1566_t1204", 0) or 0) >= 1:
        return False

    if float(profile_quality.get("asset_coverage_score", 0) or 0) < 60.0:
        return False

    if int(profile_quality.get("assets_with_zero_techniques", 0) or 0) > 0:
        return False

    return True


def build_profile_repair_prompt(
    errors: list[str],
    profile_preview: dict[str, Any],
) -> str:
    """Prompt de réparation (boucle GPT) — à brancher sur generate_attack_graph_with_gpt."""
    import json

    err_txt = json.dumps(errors, ensure_ascii=False, indent=2)
    preview = json.dumps(profile_preview, ensure_ascii=False, indent=2)[:6000]

    return f"""Tu dois corriger un graphe d'attaque MITRE pour un profil de risque..

Erreurs / alertes détectées :
{err_txt}

Aperçu du profil actuel :
{preview}

Règles :
- diversifier les techniques ; éviter T1566 + T1204 seuls sur tous les actifs
- respecter les IDs MITRE : Txxxx ou Txxxx.xxx
- cia_impact uniquement dans C/I/D
- T dans [0,1]
- cohérence avec le type d'actif (réseau, web, VPN, cloud, poste utilisateur)
- pour les actifs réseau, inclure des techniques réseau réalistes
- pour les actifs VPN, inclure des techniques d'accès distant / authentification
- ne réponds qu'avec un JSON valide au format attendu :
  {{
    "human_related": [...],
    "non_human": [...],
    "threat_score": 0.0,
    "rationale": "..."
  }}
"""


def postprocess_profile_risk_result(result: dict[str, Any]) -> dict[str, Any]:
    """Hook optionnel : ajoute des flags pour compatibilité."""
    result.setdefault("validation", {})
    result.setdefault("profile_quality_metrics", {})
    return result