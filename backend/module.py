import hashlib
import json, re
from datetime import datetime, timezone
from bson import ObjectId
from extensions import mongo
from m import MITRE_NAMES, canonicalize_mitre_id, mitre_classification
from technique_cia import get_cia_for_technique

# Version du schéma graphe stocké Mongo (traçabilité / migrations)
ATTACK_GRAPH_SCHEMA_VERSION = "1.2"

from openai_client import client

def enrich_feedback_with_gpt(answers):
    try:
        content = "Voici les réponses incorrectes de l'utilisateur à un quiz de cybersécurité. Donne un court retour pédagogique pour aider à corriger ces erreurs :\n"
        for i, a in enumerate(answers):
            if not a.get("is_correct", True):
                scenario = a.get("scenario", "").strip()
                if scenario:
                    content += f"\nScénario : {scenario}"
                content += (
                f"\nQ{i+1}: {a['question']}\n"
                f"Réponse donnée : {a['selected']}\n"
                f"Bonne réponse : {a['correct_answer']}\n"
                )
        if "Q" not in content:
            return "Toutes vos réponses sont correctes. Bravo !"
         
        messages = [
            {"role": "system", "content": "Tu es un formateur expert en cybersécurité."},
            {"role": "user", "content": content}
        ]

        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            max_tokens=700,
            temperature=0.5
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Erreur de feedback IA : {str(e)}"



def _safe_float(value, default=0.0) -> float:
    try:
        if value is None:
            return float(default)
        if isinstance(value, str):
            value = value.strip().replace(",", ".")
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def classify_mitre_technique(tid_full: str, name: str = "", description: str = "") -> str:
    """
    Classe une technique en 'human', 'hybrid' ou 'non_human' (aligné sur m.mitre_classification).
    """
    return mitre_classification(tid_full or "", name or "", description or "")


def normalize_mitre_technique(raw: dict) -> dict | None:
    """
    Normalise une technique MITRE brute venant de GPT ou MongoDB.

    Retour :
    {
        "technique_id": "...",
        "technique_name": "...",
        "description": "...",
        "cia_impact": ["C", ...],
        "classification": "human" | "hybrid" | "non_human",
        "T": 0.0,
        "inferred_parent": optional bool,
        "original_technique_id": optional str
    }
    """
    if not isinstance(raw, dict):
        return None

    tid_raw = (raw.get("technique_id") or raw.get("id") or "").strip()
    if not tid_raw:
        return None

    canon, inferred_parent, orig_id = canonicalize_mitre_id(tid_raw)
    if not canon:
        return None

    tid = canon
    tid_base = tid.split(".")[0]

    tname = (
        MITRE_NAMES.get(tid)
        or MITRE_NAMES.get(tid_base)
        or (raw.get("technique_name") or raw.get("name") or "").strip()
        or tid
    )

    desc = (raw.get("description") or "").strip()

    cia = raw.get("cia_impact", [])
    if isinstance(cia, str):
        cia = [c for c in cia if c in ("C", "I", "D")]
    elif isinstance(cia, list):
        cia = [
            str(c).strip().upper()
            for c in cia
            if str(c).strip().upper() in ("C", "I", "D")
        ]
    else:
        cia = []

    # priorité au mapping local
    override = get_cia_for_technique(tid) or get_cia_for_technique(tid_base)
    if override:
        cia = list(override)

    classification = classify_mitre_technique(tid, tname, desc)

    T = round(max(0.0, min(1.0, _safe_float(raw.get("T"), 0.6))), 3)

    out: dict = {
        "technique_id": tid,
        "technique_name": tname,
        "description": desc,
        "cia_impact": cia,
        "classification": classification,
        "T": T,
    }
    if inferred_parent and orig_id:
        out["inferred_parent"] = True
        out["original_technique_id"] = orig_id
    return out


def merge_local_attack_seeds(
    asset_name: str,
    tags,
    human_related: list,
    non_human: list,
) -> tuple[list, list]:
    """
    Sous-graphe minimal figé (matrice locale) fusionné avec la sortie GPT.
    N’ajoute pas de doublon (technique_id).
    """
    tags = tags or []
    text = f"{asset_name} {' '.join(tags)}".lower()
    existing = {t.get("technique_id") for t in (human_related + non_human) if isinstance(t, dict)}

    def _add_h(tdict: dict | None, bucket: list) -> None:
        if not tdict or not tdict.get("technique_id"):
            return
        tid = tdict["technique_id"]
        if tid in existing:
            return
        existing.add(tid)
        bucket.append(tdict)

    h = list(human_related)
    n = list(non_human)

    if any(k in text for k in ("siem", "soc", "idps", "ids", "firewall", "waf")):
        _add_h(
            normalize_mitre_technique({
                "technique_id": "T1021",
                "technique_name": MITRE_NAMES.get("T1021"),
                "description": "Accès distant ou abus de services distants (comportement opérateur / compte)",
                "cia_impact": ["C", "I"],
                "T": 0.54,
            }),
            h,
        )

    if any(k in text for k in ("email", "messagerie", "mail", "outlook", "exchange")):
        _add_h(
            normalize_mitre_technique({
                "technique_id": "T1566.002",
                "technique_name": MITRE_NAMES.get("T1566.002"),
                "description": "Liens malveillants ciblant les utilisateurs de la messagerie",
                "cia_impact": ["C", "I"],
                "T": 0.62,
            }),
            h,
        )

    # Profil risque humain / hybride uniquement 
    return h, []


# Au moins une technique « compte / identité » — aligné profile_validation.ACCOUNT_REQUIRED_BASES
ACCOUNT_TECHNIQUE_BASES = frozenset({"T1078", "T1110", "T1550", "T1098"})


def inject_graph_signature_diversity(graphs_by_asset: dict[str, dict]) -> None:
    """
    Mutations in-place : si ≥2 actifs partagent exactement le même ensemble de bases MITRE,
    ajoute une technique distincte sur les actifs en trop (hors le premier de chaque groupe).
    """
    from collections import defaultdict

    if len(graphs_by_asset) <= 1:
        return

    def _bases_of(g: dict) -> set[str]:
        out: set[str] = set()
        for k in (
            "human_related",
            "human_techniques",
            "hybrid_techniques",
            "non_human",
            "non_human_techniques",
        ):
            for t in g.get(k) or []:
                if isinstance(t, dict):
                    tid = (t.get("technique_id") or "").strip().upper()
                    if tid:
                        out.add(tid.split(".")[0])
        return out

    def _add_technique(g: dict, base_tid: str) -> None:
        raw = {
            "technique_id": base_tid,
            "technique_name": MITRE_NAMES.get(base_tid),
            "description": "Technique ajoutée pour distinguer le profil MITRE de cet actif.",
            "cia_impact": ["C", "I"],
            "T": 0.56,
        }
        nt = normalize_mitre_technique(raw)
        if not nt:
            return
        # Profil humain/hybride uniquement : tout est stocké côté human_related
        g.setdefault("human_related", []).append(nt)

    sig_map: dict[frozenset[str], list[str]] = defaultdict(list)
    for aid, g in graphs_by_asset.items():
        sig_map[frozenset(_bases_of(g))].append(aid)

    extras = ["T1110", "T1550", "T1098", "T1021", "T1133", "T1552", "T1534", "T1204"]
    for sig, ids in sig_map.items():
        if len(sig) == 0 or len(ids) <= 1:
            continue
        ids_sorted = sorted(ids)
        for idx, aid in enumerate(ids_sorted):
            if idx == 0:
                continue
            g = graphs_by_asset[aid]
            cur = _bases_of(g)
            for j in range(len(extras)):
                cand = extras[(idx + j) % len(extras)]
                if cand not in cur:
                    _add_technique(g, cand)
                    break


def generate_attack_graph_with_gpt(
    asset_name: str,
    tags=None,
    job_role: str | None = None,
    diversity_nonce: str | None = None,
) -> dict:
    """
    Génère un graphe d'attaque « facteur humain » pour un actif via GPT.

    Uniquement techniques **human** et **hybrid** ; `non_human` toujours vide.
    ≥3 techniques, au moins une T1078/T1110/T1550/T1098, max 1 phishing (T1566), etc.

    Retour garanti :
    {
      "human_related": [ {technique_id, technique_name, description, cia_impact, T, classification}, ... ],
      "non_human": [],
      "threat_score":  <float 0..1>,
      "rationale":     "<str>"
    }
    """
    tags = tags or []
    jr = (job_role or "").strip() or None
    dn = (diversity_nonce or "").strip() or asset_name

    def _clamp01(x, default=0.6) -> float:
        return max(0.0, min(1.0, _safe_float(x, default)))

    def _normalize_cia(v):
        if isinstance(v, str):
            v = [c for c in v if c in ("C", "I", "D")]
        elif isinstance(v, list):
            v = [
                str(c).strip().upper()
                for c in v
                if str(c).strip().upper() in ("C", "I", "D")
            ]
        else:
            v = []

        order = {"C": 0, "I": 1, "D": 2}
        v = sorted(list(dict.fromkeys(v)), key=lambda c: order.get(c, 99))

        if not v:
            v = ["C"]

        return v

    def _normalize_generated_T(T_value, default_t: float = 0.6) -> float:
        return round(_clamp01(T_value, default_t), 3)

    def _tech_score(t: dict) -> float:
        return _clamp01(t.get("T"), 0.6)

    def _sanitize_list(lst):
        if isinstance(lst, dict):
            lst = [lst]
        if not isinstance(lst, list):
            return []

        out = []
        for item in lst:
            nt = normalize_mitre_technique(item)
            if not nt:
                continue

            nt["cia_impact"] = _normalize_cia(nt.get("cia_impact", []))
            nt["T"] = _normalize_generated_T(nt.get("T"), 0.6)
            out.append(nt)
        return out

    def _dedupe_by_tid(items):
        seen = set()
        result = []
        for item in items:
            tid = str(item.get("technique_id", "")).strip().upper()
            if tid and tid not in seen:
                seen.add(tid)
                item["technique_id"] = tid
                result.append(item)
        return result

    system_msg = """
Tu es un expert MITRE ATT&CK et cybersécurité « facteur humain ».

Consigne maître (respecter strictement) :
Produit un profil de risque composé UNIQUEMENT de techniques MITRE de type **humain** ou **hybride** (comportements d’utilisateurs, erreurs, mauvaises pratiques, abus de comptes, authentification, accès distant piloté par l’humain). Aucune technique purement automatisée / infrastructure sans lien comportemental (ex. pas d’exploitation serveur sans dimension humaine, pas d’exécution purement machine sans acteur).

Obligations :
- Au moins 3 identifiants MITRE distincts au total.
- Au moins une technique hybride « compte / authentification » parmi T1078, T1110, T1550, T1098.
- Interdit : n’avoir que les familles T1566 (phishing) et T1204 (user execution).
- Maximum **1** technique de phishing (famille T1566 ou sous-techniques) par actif.
- Varier les combinaisons entre actifs ; adapter au contexte (ex. admin IAM, utilisateur Linux, VPN, télétravail, erreurs humaines).

Ta mission :
- proposer un graphe réaliste pour l’actif décrit,
- retourner UNIQUEMENT un objet JSON valide,
- ne jamais ajouter de texte avant ou après le JSON.

Contraintes absolues :
- Les SEULES clés autorisées à la racine sont : human_related, non_human, threat_score, rationale
- Réponse strictement en JSON ; aucun markdown ; aucun commentaire
- Remplis **human_related** avec toutes les techniques (humain + hybride) ; **non_human** doit être une liste **vide** [] (aucune technique purement technique).
""".strip()

    user_msg = f"""
Actif : {asset_name}
Tags / contexte : {', '.join(tags)}
Rôle métier (utilisateur / poste) : {jr if jr else "non renseigné — déduis uniquement depuis le nom d’actif et les tags"}
Identifiant de variante (unicité des profils entre actifs) : {dn}

Retourne STRICTEMENT un JSON avec **non_human** = [] et toutes les techniques dans **human_related** :

{{
  "human_related": [
    {{
      "technique_id": "Txxxx" ou "Txxxx.xxx",
      "technique_name": "Nom MITRE",
      "description": "Description courte (comportement humain / erreur / abus de compte)",
      "cia_impact": ["C", "I", "D"],
      "T": 0.0
    }}
  ],
  "non_human": [],
  "threat_score": 0.0,
  "rationale": "Justification courte"
}}

RÈGLES DE FORMAT :
- Au total, au moins 3 identifiants MITRE distincts dans human_related.
- Au moins une technique parmi T1078, T1110, T1550, T1098 (hybride compte / authentification).
- Maximum **1** technique de phishing (base T1566 ou sous-techniques) pour cet actif.
- Interdit : n’avoir que les familles T1566 et T1204.
- Chaque entrée : technique_id, technique_name, description, cia_impact, T
- Pas de techniques purement « machine » (ex. T1059, T1190, T1046, T1040).

DIVERSITÉ T1566 / T1204 (important) :
- Ne réserve pas systématiquement T1566 et T1204 : pour un actif orienté infrastructure ou sans surface « utilisateur », n’inclus pas le couple phishing + user execution par défaut.
- Pour un actif messagerie / poste utilisateur, tu peux inclure T1566 ou des sous-techniques ; n’ajoute T1204 que si la chaîne d’attaque le justifie (pas par habitude sur chaque actif).

RÈGLE CRITIQUE SUR LE PHISHING :
- T1566 (ou sous-techniques de phishing) est autorisé seulement si l’actif implique directement un utilisateur, un poste utilisateur, un email, une messagerie, un outil de communication, un IDE ou une plateforme collaborative comme GitHub
- Ne PAS proposer T1566 pour des actifs purement techniques comme :
  SIEM, EDR, IDPS, firewall, syslog, serveurs d’infrastructure, outils forensics
- Si l’actif est purement technique, human_related peut être vide

RÈGLE USER EXECUTION (T1204) :
- N’impose pas T1204 sur chaque actif : uniquement si une chaîne crédible l’exige (ex. exécution après pièce jointe ou script sur un poste utilisateur).

RÈGLE DE CHAÎNE D’ATTAQUE :
- Les techniques proposées doivent représenter des étapes complémentaires d’une attaque réaliste, par exemple :
  entrée → action utilisateur → accès → exécution / impact
- Éviter une liste composée uniquement de variantes très proches d’une même phase

RÈGLE DE DIVERSITÉ :
- Varie les familles MITRE (humain / hybride) ; ne pas recopier la même combinaison que pour d’autres actifs génériques.

RÈGLES DE COHÉRENCE :
- Toutes les techniques dans human_related ; non_human = []
- Les techniques proposées doivent être directement applicables à l’actif (nom + tags + rôle)
- Scores T modérés si exposition faible

IMPORTANT :
- Retourne uniquement le JSON final
- Aucun texte hors JSON
""".strip()

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=900,
            temperature=0.3,
        )

        raw = (response.choices[0].message.content or "").strip()

        print("\n=== RAW GPT ATTACK GRAPH ===")
        print("asset:", asset_name)
        print(raw)

        if raw.startswith("```"):
            raw = raw.strip("`").strip()
            if "\n" in raw:
                raw = raw.split("\n", 1)[1].strip()

        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(f"Réponse GPT sans JSON exploitable: {raw}")

        json_str = raw[start:end + 1]

        replacements = {
            '"human_techniques"': '"human_related"',
            '"techniques_humaines"': '"human_related"',
            '"technique_humaine"': '"human_related"',
            '"non_human_techniques"': '"non_human"',
            '"techniques_non_humaines"': '"non_human"',
        }
        for old, new in replacements.items():
            json_str = json_str.replace(old, new)

        data = json.loads(json_str)
        if not isinstance(data, dict):
            data = {}

        hr_s = _sanitize_list(data.get("human_related", []))
        nh_s = _sanitize_list(data.get("non_human", []))
        combined: list = []
        for t in hr_s + nh_s:
            cls = t.get("classification")
            if cls == "non_human":
                continue
            if cls in ("human", "hybrid"):
                combined.append(t)

        human_related = _dedupe_by_tid(combined)
        non_human: list = []

        human_related, non_human = merge_local_attack_seeds(
            asset_name, tags, human_related, non_human
        )

        def _bases(hr: list, nh: list) -> set[str]:
            s: set[str] = set()
            for t in hr + nh:
                tid = (t.get("technique_id") or "").strip().upper()
                if tid:
                    s.add(tid.split(".")[0])
            return s

        def _enforce_mitre_constraints(hr: list, nh: list) -> tuple[list, list]:
            """Refuse équivalent : pas uniquement T1566+T1204 ; au moins une technique « compte »."""
            hr = list(hr)
            nh = list(nh)
            b = _bases(hr, nh)
            if b and b.issubset({"T1566", "T1204"}):
                nt = normalize_mitre_technique(
                    {
                        "technique_id": "T1552",
                        "technique_name": MITRE_NAMES.get("T1552"),
                        "description": "Mauvaise gestion ou fuite d’identifiants par erreur humaine",
                        "cia_impact": ["C", "I"],
                        "T": 0.52,
                    }
                )
                if nt:
                    hr.append(nt)
                    b = _bases(hr, nh)
            if b and not (b & ACCOUNT_TECHNIQUE_BASES):
                pick = ["T1078", "T1110", "T1550", "T1098"][
                    abs(hash(asset_name + dn)) % 4
                ]
                nt = normalize_mitre_technique(
                    {
                        "technique_id": pick,
                        "technique_name": MITRE_NAMES.get(pick),
                        "description": "Scénario d’accès / abus de compte ou d’identité pertinent pour l’actif",
                        "cia_impact": ["C", "I"],
                        "T": 0.57,
                    }
                )
                if nt:
                    hr.append(nt)
            return hr, nh

        human_related, non_human = _enforce_mitre_constraints(
            human_related, non_human
        )

        def _pad_to_min_three_techniques(hr: list, nh: list) -> tuple[list, list]:
            """Au moins 3 techniques distinctes (aligné prompt diversité)."""
            hr = list(hr)
            nh = list(nh)
            seen: set[str] = set()
            for t in hr + nh:
                tid = (t.get("technique_id") or "").strip().upper()
                if tid:
                    seen.add(tid)
            if len(seen) >= 3:
                return hr, nh
            extras = [
                {
                    "technique_id": "T1552",
                    "technique_name": MITRE_NAMES.get("T1552"),
                    "description": "Identifiants exposés par négligence ou mauvaise pratique",
                    "cia_impact": ["C", "I"],
                    "T": 0.50,
                },
                {
                    "technique_id": "T1021",
                    "technique_name": MITRE_NAMES.get("T1021"),
                    "description": "Usage abusif de services distants par un opérateur ou un compte compromis",
                    "cia_impact": ["C", "I"],
                    "T": 0.54,
                },
                {
                    "technique_id": "T1133",
                    "technique_name": MITRE_NAMES.get("T1133"),
                    "description": "Accès distant externalisé (VPN, RDP) avec décision humaine erronée",
                    "cia_impact": ["C", "I", "D"],
                    "T": 0.52,
                },
            ]
            for raw in extras:
                nt = normalize_mitre_technique(raw)
                if not nt:
                    continue
                tid = nt["technique_id"]
                if tid in seen:
                    continue
                if nt.get("classification") == "non_human":
                    continue
                seen.add(tid)
                hr.append(nt)
                if len(seen) >= 3:
                    break
            return hr, nh

        def _enforce_max_one_phishing(hr: list) -> list:
            """Au plus une technique dont la base est T1566 (phishing)."""
            hr = list(hr)
            kept = False
            out: list = []
            for t in hr:
                tid = (t.get("technique_id") or "").strip().upper()
                base = tid.split(".")[0] if tid else ""
                if base == "T1566":
                    if not kept:
                        kept = True
                        out.append(t)
                    continue
                out.append(t)
            return out

        human_related, non_human = _pad_to_min_three_techniques(human_related, non_human)
        human_related = _enforce_max_one_phishing(human_related)
        human_related = _dedupe_by_tid(human_related)
        non_human = []

        scores = [_tech_score(t) for t in (human_related + non_human)]
        scores.sort(reverse=True)

        if scores:
            topk = scores[:3]
            threat_score = sum(topk) / len(topk)
        else:
            threat_score = _clamp01(data.get("threat_score"), 0.6)

        threat_score = round(_clamp01(threat_score, 0.6), 3)

        rationale = str(data.get("rationale", "") or "").strip()
        if not rationale:
            rationale = f"Graphe généré pour {asset_name} selon le contexte de l’actif et ses tags."

        def _prompt_sha256(*parts: str) -> str:
            h = hashlib.sha256()
            for p in parts:
                h.update(p.encode("utf-8", errors="replace"))
                h.update(b"\n")
            return h.hexdigest()

        result = {
            "human_related": human_related,
            "non_human": non_human,
            "threat_score": threat_score,
            "rationale": rationale,
            "_graph_meta": {
                "graph_version": ATTACK_GRAPH_SCHEMA_VERSION,
                "llm_model": "gpt-4o-mini",
                "prompt_sha256": _prompt_sha256(system_msg, user_msg),
                "source": "gpt",
            },
        }

        print("\n[ATTACK_GRAPH] source=GPT")
        print(result)
        return result

    except Exception as e:
        print(f"\n[WARNING] Erreur generate_attack_graph_with_gpt : {e}")
        print("[ATTACK_GRAPH] source=FALLBACK")
        print("asset:", asset_name)
        print("tags:", tags)

        # Fallback humain/hybride : ≥3 techniques, compte / auth, pas uniquement T1566+T1204
        hr_fb: list = []
        for raw in (
            {
                "technique_id": "T1078",
                "technique_name": MITRE_NAMES.get("T1078"),
                "description": "Comptes valides ou sessions abusées (comportement utilisateur)",
                "cia_impact": ["C", "I"],
                "T": 0.58,
            },
            {
                "technique_id": "T1110",
                "technique_name": MITRE_NAMES.get("T1110"),
                "description": "Tentatives de devinette de mot de passe ou réutilisation de mots de passe faibles",
                "cia_impact": ["C", "I"],
                "T": 0.56,
            },
            {
                "technique_id": "T1204",
                "technique_name": MITRE_NAMES.get("T1204"),
                "description": "Exécution d’un fichier ou d’un script après action utilisateur",
                "cia_impact": ["C", "I"],
                "T": 0.62,
            },
        ):
            nt = normalize_mitre_technique(raw)
            if not nt or nt.get("classification") == "non_human":
                continue
            hr_fb.append(nt)

        return {
            "human_related": hr_fb,
            "non_human": [],
            "threat_score": 0.6,
            "rationale": f"Graphe de secours (contraintes MITRE) pour {asset_name}.",
            "_graph_meta": {
                "graph_version": ATTACK_GRAPH_SCHEMA_VERSION,
                "llm_model": None,
                "prompt_sha256": None,
                "source": "fallback",
            },
        }


def ensure_attack_graph_for_asset(
    asset_doc: dict | None = None,
    asset_id: str | None = None,
    asset_name: str | None = None,
    tags=None,
    force: bool = False,
    regen_if_empty: bool = False,
    job_role: str | None = None,
    diversity_nonce: str | None = None,
) -> dict:
    """
    Compatible avec :
      - ensure_attack_graph_for_asset(asset_doc=doc)
      - ensure_attack_graph_for_asset(asset_id="idps", asset_name="...", tags=[...], force=True)
    job_role : optionnel, transmis au prompt GPT pour adapter les TTP au métier (profil de risque).
    diversity_nonce : chaîne pour différencier les générations (unicité des profils entre actifs).
    """

    print("\n==================================================")
    print("[ATTACK_GRAPH] ensure_attack_graph_for_asset START")
    print("asset_doc:", asset_doc)
    print("asset_id:", asset_id)
    print("asset_name:", asset_name)
    print("tags:", tags)
    print("force:", force)
    print("regen_if_empty:", regen_if_empty)
    print("job_role:", job_role)
    print("diversity_nonce:", diversity_nonce)
    print("==================================================")

    if asset_doc is not None:
        asset_id = asset_id or asset_doc.get("_id")
        asset_name = asset_name or asset_doc.get("name") or asset_doc.get("asset_name")
        if tags is None:
            tags = asset_doc.get("tags", [])

    tags = tags or []
    asset_id = str(asset_id).strip() if asset_id is not None else None
    asset_name = str(asset_name).strip() if asset_name is not None else None

    print("\n[ATTACK_GRAPH] AFTER INPUT NORMALIZATION")
    print("asset_id:", asset_id)
    print("asset_name:", asset_name)
    print("tags:", tags)

    if not asset_id or not asset_name:
        raise ValueError("ensure_attack_graph_for_asset nécessite au moins asset_id et asset_name")

    def clamp01(x, default=0.6) -> float:
        return max(0.0, min(1.0, _safe_float(x, default)))

    def normalize_list(items):
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            return []

        out = []
        for t in items:
            nt = normalize_mitre_technique(t)
            if not nt:
                continue
            nt["T"] = round(clamp01(nt.get("T", 0.6), 0.6), 3)
            out.append(nt)
        return out

    def dedupe_by_tid(items):
        seen = set()
        out = []
        for item in items:
            tid = item.get("technique_id")
            if tid and tid not in seen:
                seen.add(tid)
                out.append(item)
        return out

    def build_normalized_doc(source: dict) -> dict:
        print("\n[ATTACK_GRAPH] build_normalized_doc SOURCE")
        print("asset_name:", asset_name)
        print("source:", source)

        src = dict(source) if isinstance(source, dict) else {}
        graph_meta = src.pop("_graph_meta", None)

        human_related_raw = src.get("human_related") or src.get("human_techniques") or []
        non_human_raw = src.get("non_human") or src.get("non_human_techniques") or []

        all_norm = normalize_list((human_related_raw or []) + (non_human_raw or []))

        human_related = [t for t in all_norm if t.get("classification") in ("human", "hybrid")]
        non_human = [t for t in all_norm if t.get("classification") == "non_human"]

        human_related = dedupe_by_tid(human_related)
        human_ids = {t["technique_id"] for t in human_related}

        non_human = dedupe_by_tid(non_human)
        non_human = [t for t in non_human if t["technique_id"] not in human_ids]

        threat_score = round(clamp01(src.get("threat_score", 0.6), 0.6), 3)
        rationale = str(src.get("rationale", "") or "").strip()

        cia_set = set()
        for t in human_related + non_human:
            for c in t.get("cia_impact", []):
                cia_set.add(c)

        if cia_set:
            order = {"C": 0, "I": 1, "D": 2}
            cia_list = sorted(list(cia_set), key=lambda x: order.get(x, 99))
            cia_label = "".join(cia_list)
        else:
            cia_list = []
            cia_label = ""

        normalized = {
            "asset_id": asset_id,
            "asset_name": asset_name,
            "human_related": human_related,
            "human_techniques": human_related,
            "non_human": non_human,
            "non_human_techniques": non_human,
            "threat_score": threat_score,
            "rationale": rationale,
            "cia_impact": cia_list,
            "cia_label": cia_label,
            "updatedAt": datetime.utcnow(),
        }
        if graph_meta:
            normalized["graph_meta"] = graph_meta

        return normalized

    existing = (
        mongo.db.attack_graphs.find_one({"asset_id": asset_id})
        or mongo.db.attack_graphs.find_one({"_id": asset_id})
    )

    print("\n=== EXISTING GRAPH FROM DB ===")
    print("asset:", asset_name)
    print("existing:", existing)

    if existing and not force:
        human_list = existing.get("human_related") or existing.get("human_techniques") or []
        nonhuman_list = existing.get("non_human") or existing.get("non_human_techniques") or []

        human_len = len(human_list) if isinstance(human_list, list) else 0
        nonhuman_len = len(nonhuman_list) if isinstance(nonhuman_list, list) else 0

        print("\n[ATTACK_GRAPH] EXISTING GRAPH SUMMARY")
        print("asset:", asset_name)
        print("human_len:", human_len)
        print("nonhuman_len:", nonhuman_len)

        def _base_tid(tid: str) -> str:
            return str(tid or "").strip().upper().split(".")[0]

        human_bases = set()
        if isinstance(human_list, list):
            for t in human_list:
                if isinstance(t, dict):
                    human_bases.add(_base_tid(t.get("technique_id")))
        human_bases.discard("")

        only_phishing_family = bool(human_bases) and human_bases.issubset({"T1566"})
        low_human_diversity = human_len < 2 or len(human_bases) < 2 or only_phishing_family

        # Schéma profil humain/hybride : plus de techniques dans non_human
        if regen_if_empty and nonhuman_len > 0:
            print(
                f"[ATTACK_GRAPH] existing LEGACY_NON_HUMAN_BUCKET -> regen: {asset_name} ({asset_id})"
            )
        elif regen_if_empty and human_len == 0 and nonhuman_len == 0:
            print(f"[ATTACK_GRAPH] existing EMPTY -> regen: {asset_name} ({asset_id})")
        elif regen_if_empty and low_human_diversity:
            print(
                f"[ATTACK_GRAPH] existing LOW_DIVERSITY_HUMAN -> regen: {asset_name} ({asset_id}) "
                f"human_len={human_len} human_bases={sorted(human_bases)}"
            )
        else:
            normalized_existing = build_normalized_doc(existing)
            normalized_existing["createdAt"] = existing.get("createdAt", datetime.utcnow())
            if "_id" in existing:
                normalized_existing["_id"] = existing["_id"]

            print("\n=== RETURN EXISTING NORMALIZED GRAPH ===")
            print(normalized_existing)
            return normalized_existing

    print(f"\n[ATTACK_GRAPH] GENERATING NEW GRAPH FOR: {asset_name} ({asset_id})")
    graph_data = (
        generate_attack_graph_with_gpt(
            asset_name=asset_name,
            tags=tags,
            job_role=job_role,
            diversity_nonce=diversity_nonce,
        )
        or {}
    )

    print("\n=== GENERATED GRAPH BEFORE SAVE ===")
    print("asset:", asset_name)
    print("graph_data:", graph_data)

    doc = build_normalized_doc(graph_data)

    print("\n=== NORMALIZED GRAPH BEFORE SAVE ===")
    print("asset:", asset_name)
    print("doc:", doc)

    created_at = datetime.utcnow()
    if existing and existing.get("createdAt"):
        created_at = existing["createdAt"]

    mongo.db.attack_graphs.update_one(
        {"asset_id": asset_id},
        {
            "$set": doc,
            "$setOnInsert": {"createdAt": created_at}
        },
        upsert=True
    )

    saved = mongo.db.attack_graphs.find_one({"asset_id": asset_id}) or doc

    print(
        f"\n[ATTACK_GRAPH] saved: {asset_name} ({asset_id}) "
        f"human={len(doc['human_related'])} nonhuman={len(doc['non_human'])}"
    )
    print("\n=== SAVED GRAPH FROM DB ===")
    print(saved)

    return saved