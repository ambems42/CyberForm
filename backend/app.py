import bcrypt, uuid
import csv
import traceback, json, math, os, smtplib
from io import StringIO
from email.message import EmailMessage
from email.mime.text import MIMEText
from flask import Flask, g, jsonify, make_response, request, Response
from auth_jwt import (
    JWT_EXPIRE_HOURS,
    check_self_or_admin,
    create_access_token,
    require_jwt,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_pymongo import PyMongo
from bson import ObjectId, errors
from bson.son import SON
from module import enrich_feedback_with_gpt
from datetime import datetime, timezone, timedelta
from extensions import mongo
from password_policy import validate_new_password
from generate import (
    generate_quiz,
    QuizValidationError,
    calculate_results,
    compute_quiz_quality_metrics,
    generate_training_content,
    generate_profile_risk,
    ensure_attack_graph_for_asset,
)
from m import MITRE_NAMES

app = Flask(__name__)
app.config["MONGO_URI"] = os.environ.get(
    "MONGO_URI", "mongodb://localhost:27017/cyberform"
)
mongo.init_app(app)


def _ensure_db_indexes():
    try:
        mongo.db.users.create_index([("basic_info.userID", 1)], unique=True, name="uniq_basic_userID")
    except Exception as e:
        app.logger.warning("Index Mongo basic_info.userID : %s", e)


with app.app_context():
    _ensure_db_indexes()

if os.environ.get("TRUST_PROXY", "").lower() in ("1", "true", "yes"):
    from werkzeug.middleware.proxy_fix import ProxyFix

    _trusted = max(1, int(os.environ.get("TRUSTED_PROXY_COUNT", "1") or "1"))
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=_trusted,
        x_proto=1,
        x_host=1,
        x_port=1,
        x_prefix=1,
    )

# CORS : par défaut origines dev Angular (plus de * implicite). Prod : CORS_ORIGINS=https://app.example.com
# Pour autoriser toutes les origines (déconseillé) : CORS_ORIGINS=*
_cors_raw = (os.environ.get("CORS_ORIGINS") or "").strip()
if not _cors_raw:
    _cors_origins = [
        "http://localhost:4200",
        "http://127.0.0.1:4200",
        "http://[::1]:4200",
    ]
elif _cors_raw == "*":
    _cors_origins = "*"
    app.logger.warning(
        "CORS_ORIGINS=* : toutes les origines sont autorisées (déconseillé en production)."
    )
else:
    _cors_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]

_use_jwt_cookie = os.environ.get("USE_JWT_COOKIE", "true").lower() in ("1", "true", "yes")
# Avec cookie HttpOnly, credentials cross-origin ; interdit avec CORS_ORIGINS=*
_supports_credentials = _use_jwt_cookie and _cors_origins != "*"
if _use_jwt_cookie and _cors_origins == "*":
    app.logger.warning(
        "USE_JWT_COOKIE actif mais CORS_ORIGINS=* : le navigateur peut refuser les cookies en cross-origin."
    )
CORS(
    app,
    resources={r"/*": {"origins": _cors_origins}},
    supports_credentials=_supports_credentials,
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    default_limits=[],
)


@app.errorhandler(RateLimitExceeded)
def _rate_limit_exceeded(_exc: RateLimitExceeded):
    return jsonify({"error": "Trop de requêtes. Réessayez plus tard."}), 429


def _expose_api_error_details() -> bool:
    return os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes") or os.environ.get(
        "SHOW_ERROR_DETAILS", ""
    ).lower() in ("1", "true", "yes")


def json_api_error(message: str, status: int = 500, exception: Exception | None = None, extra: dict | None = None):
    """Réponses d'erreur : pas de détails techniques sauf FLASK_DEBUG ou SHOW_ERROR_DETAILS."""
    body: dict = {"error": message}
    if extra:
        body.update(extra)
    if exception is not None and _expose_api_error_details():
        body["details"] = str(exception)
        body["type"] = exception.__class__.__name__
    return jsonify(body), status


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if os.environ.get("HSTS_ENABLE", "").lower() in ("1", "true", "yes"):
        _max = int(os.environ.get("HSTS_MAX_AGE", "31536000") or "31536000")
        response.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={_max}; includeSubDomains",
        )
    return response

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = os.environ.get("SMTP_PORT", "587")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM") or SMTP_USER
CYBERFORM_APP_URL = os.environ.get("CYBERFORM_APP_URL", "http://localhost:4200")


def _is_production_env() -> bool:
    return os.environ.get("FLASK_ENV", "").strip().lower() == "production" or os.environ.get(
        "CYBERFORM_PRODUCTION", ""
    ).lower() in ("1", "true", "yes")


def _validate_production_security() -> None:
    """
    Quand FLASK_ENV=production ou CYBERFORM_PRODUCTION=true : vérifie secrets,
    HTTPS, CORS, détails d'erreur, SMTP si SMTP_REQUIRED. Log ERROR ; lève RuntimeError si CYBERFORM_STRICT_PRODUCTION.
    """
    if not _is_production_env():
        return
    issues: list[str] = []
    jwt_secret = (os.environ.get("JWT_SECRET") or "").strip()
    if len(jwt_secret) < 32:
        issues.append("JWT_SECRET doit faire au moins 32 caractères en production.")
    weak = {"changeme", "secret", "password", "jwt_secret", "devsecret", "dev"}
    if jwt_secret.lower() in weak:
        issues.append("JWT_SECRET est une valeur de test connue.")

    if _expose_api_error_details():
        issues.append("SHOW_ERROR_DETAILS ou FLASK_DEBUG ne doit pas être activé en production.")

    if _use_jwt_cookie and os.environ.get("COOKIE_SECURE", "").lower() not in ("1", "true", "yes"):
        issues.append("COOKIE_SECURE=true est requis en production avec USE_JWT_COOKIE.")

    mongo_uri = (os.environ.get("MONGO_URI") or "").lower()
    if "localhost" in mongo_uri or "127.0.0.1" in mongo_uri:
        issues.append(
            "MONGO_URI pointe vers localhost : en production la base doit être sur réseau privé (VPC), "
            "sans exposition Internet (hôte MongoDB ≠ localhost si l’app est sur un autre serveur)."
        )

    app_url = (CYBERFORM_APP_URL or "").strip().lower()
    if app_url.startswith("http://"):
        issues.append("CYBERFORM_APP_URL doit utiliser https:// en production.")

    if os.environ.get("HSTS_ENABLE", "").lower() not in ("1", "true", "yes"):
        issues.append("HSTS_ENABLE=true recommandé derrière HTTPS en production.")

    cors_raw = (os.environ.get("CORS_ORIGINS") or "").strip()
    if not cors_raw or cors_raw == "*":
        issues.append("CORS_ORIGINS doit lister explicitement l'origine HTTPS du front (pas vide ni *).")

    if os.environ.get("SMTP_REQUIRED", "").lower() in ("1", "true", "yes"):
        if not (SMTP_USER or "").strip() or not (SMTP_PASSWORD or "").strip():
            issues.append(
                "SMTP_REQUIRED=true : définir SMTP_USER et SMTP_PASSWORD (secrets via l’environnement, pas dans le dépôt)."
            )

    for msg in issues:
        app.logger.error("Production : %s", msg)

    if os.environ.get("CYBERFORM_STRICT_PRODUCTION", "").lower() in ("1", "true", "yes") and issues:
        raise RuntimeError("Configuration production invalide : " + "; ".join(issues))


_validate_production_security()

# Techniques humaines critiques (ingénierie sociale, phishing, etc.) : si la vulnérabilité
# d'une de ces techniques dépasse le seuil, une formation ciblée est déclenchée même si
# le risque global reste sous le seuil organisationnel.
CRITICAL_HUMAN_TECHNIQUE_IDS = {
    "T1566", "T1566.001", "T1566.002", "T1566.003",  # Phishing / Spearphishing
    "T1586", "T1587", "T1588",  # Compromise accounts (vecteurs humains)
    "T1539", "T1542", "T1543",  # Steal / Obtain credentials
}
CRITICAL_TECHNIQUE_VULNERABILITY_THRESHOLD_PCT = 50.0  # au-dessus = formation déclenchée

# Quiz : si le score qualité (heuristique) reste sous le seuil, nouvelle génération complète
# (en plus des tentatives de validation GPT internes à generate_quiz).
QUIZ_MIN_QUALITY_SCORE = float(os.environ.get("QUIZ_MIN_QUALITY_SCORE", "70"))
QUIZ_MAX_QUALITY_REGEN = max(0, int(os.environ.get("QUIZ_MAX_QUALITY_REGEN", "1")))

# Formation : seuil qualité heuristique (generate.py) + validateur GPT optionnel (2e appel / module)

ORG_SETTINGS_COLLECTION = "organization_settings"
ORG_SETTINGS_DOC_ID = "default"


def _default_organization_settings() -> dict:
    """Valeurs par défaut (env > constantes code)."""
    return {
        "policy_threshold_pct": float(os.environ.get("DEFAULT_POLICY_THRESHOLD_PCT", "30")),
        "k_threshold": float(os.environ.get("DEFAULT_K_THRESHOLD", "0.95")),
        "learned_history_window": int(os.environ.get("DEFAULT_LEARNED_WINDOW", "10")),
        "learned_min_pct": float(os.environ.get("DEFAULT_LEARNED_MIN_PCT", "15")),
        "learned_max_pct": float(os.environ.get("DEFAULT_LEARNED_MAX_PCT", "45")),
        "critical_vulnerability_threshold_pct": float(
            os.environ.get("CRITICAL_TECHNIQUE_VULNERABILITY_THRESHOLD_PCT", "50")
        ),
        "critical_technique_ids": None,
        # Max vulnérabilité (%) autorisée par ID MITRE ; prioritaire sur le seuil « critique » si les deux s'appliquent
        "per_technique_vulnerability_thresholds": {},
    }


def load_organization_settings() -> dict:
    """
    Paramètres organisation (Mongo). Document unique _id=default.
    critical_technique_ids: None = liste code CRITICAL_HUMAN_TECHNIQUE_IDS ;
    [] = désactiver la règle ; liste non vide = IDs MITRE (ex. T1566).
    """
    defaults = _default_organization_settings()
    try:
        doc = mongo.db[ORG_SETTINGS_COLLECTION].find_one({"_id": ORG_SETTINGS_DOC_ID})
    except Exception:
        doc = None
    if not doc:
        return dict(defaults)
    out = dict(defaults)
    for key in defaults:
        if key in doc and doc[key] is not None:
            out[key] = doc[key]
    if "critical_technique_ids" in doc:
        out["critical_technique_ids"] = doc["critical_technique_ids"]
    if "per_technique_vulnerability_thresholds" in doc and isinstance(
        doc["per_technique_vulnerability_thresholds"], dict
    ):
        out["per_technique_vulnerability_thresholds"] = normalize_per_technique_vulnerability_thresholds(
            doc["per_technique_vulnerability_thresholds"]
        )
    return out


def normalize_per_technique_vulnerability_thresholds(raw: dict) -> dict:
    """Clés MITRE en majuscules, valeurs dans [0, 100]."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        ku = str(k).strip().upper()
        if not ku:
            continue
        try:
            fv = float(v)
        except (TypeError, ValueError):
            continue
        fv = max(0.0, min(100.0, fv))
        out[ku] = fv
    return out


def _effective_technique_vulnerability_threshold(tid, per_map, crit_set, crit_thr_default):
    """
    Seuil max de vulnérabilité (%) pour une technique : d'abord carte admin, sinon règle « techniques critiques ».
    Retourne (seuil ou None, source) ; None = aucune règle → toujours acceptable pour ce critère.
    """
    tid = str(tid or "").strip().upper()
    if not tid or tid == "OTHER":
        return None, None
    tid_base = tid.split(".")[0]
    if tid in per_map:
        return per_map[tid], "per_technique"
    if tid_base in per_map:
        return per_map[tid_base], "per_technique"
    if crit_set and (tid_base in crit_set or tid in crit_set):
        return crit_thr_default, "critical_default"
    return None, None


def _critical_match_set_from_config(raw_ids):
    """Construit un set pour le test tid / tid_base (comme CRITICAL_HUMAN_TECHNIQUE_IDS)."""
    s = set()
    if not raw_ids:
        return s
    for item in raw_ids:
        u = str(item).strip().upper()
        if not u:
            continue
        s.add(u.split(".")[0])
        s.add(u)
    return s


def sanitize_for_json_bson(obj):
    """
    Rend un dict/list JSON/BSON-compatible : supprime NaN/Inf (Mongo et jsonify).
    """
    if obj is None:
        return None
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json_bson(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_json_bson(v) for v in obj]
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    return obj


def normalize_quiz_questions_for_api(parsed):
    """
    Normalise les 10 questions pour l'API / Mongo. Retourne None si invalide.
    """
    if not isinstance(parsed, list) or len(parsed) != 10:
        return None
    normalized = []
    for i, q in enumerate(parsed, start=1):
        if not isinstance(q, dict):
            return None
        normalized.append({
            "id": str(q.get("id") or i),
            "question": q.get("question") or q.get("text") or "",
            "scenario": q.get("scenario") or "",
            "choices": q.get("choices") or q.get("options") or [],
            "options": q.get("choices") or q.get("options") or [],
            "type": q.get("type") or "",
            "correct_answer": str(q.get("correct_answer") or q.get("correctAnswer") or "").strip(),
            "threadId": q.get("threadId") or q.get("thread_id") or "other",
            "techniqueId": q.get("techniqueId") or q.get("technique_id") or "NA",
            "techniqueName": q.get("techniqueName") or q.get("technique_name") or "",
            "bloomLevel": q.get("bloom_level") or q.get("bloomLevel"),
            "bloomLabelFr": q.get("bloom_label_fr") or q.get("bloomLabelFr"),
        })
    return normalized


def _quiz_date_iso(dt):
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def send_reset_email(to_email: str, reset_link: str) -> None:
    host = SMTP_HOST
    port = int(SMTP_PORT)
    user = SMTP_USER
    password = SMTP_PASSWORD
    sender = SMTP_FROM or user or ""

    if not (host and user and password and sender):
        print("[RESET PASSWORD][NO SMTP CONFIG] Envoi email indisponible (lien non journalisé).")
        return

    msg = EmailMessage()
    msg["Subject"] = "CyberForm – Réinitialisation de votre mot de passe"
    msg["From"] = sender
    msg["To"] = to_email

    msg.set_content(
        f"""Bonjour,

Vous avez demandé la réinitialisation de votre mot de passe CyberForm.

Pour choisir un nouveau mot de passe, cliquez sur le lien suivant (valide 24 heures) :
{reset_link}

Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet email.

— CyberForm
""",
        charset="utf-8",
    )

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
        print(f"[RESET PASSWORD] Email de réinitialisation envoyé à {to_email}")
    except Exception as e:
        print(f"[RESET PASSWORD][SMTP ERROR] Impossible d'envoyer l'e-mail : {e}")
        print("[RESET PASSWORD] Lien non journalisé pour raisons de sécurité.")


def send_contact_form_email(*, nom: str, from_email: str, body: str) -> None:
    """Envoie le message du formulaire contact (MIMEText + STARTTLS). Destinataire : CONTACT_TO_EMAIL ou SMTP_USER."""
    host = (SMTP_HOST or "").strip() or "smtp.gmail.com"
    port = int(SMTP_PORT or "587")
    user = (SMTP_USER or "").strip()
    # Mot de passe d’application Gmail : souvent affiché par groupes de 4 avec espaces — les retirer
    password = "".join((SMTP_PASSWORD or "").strip().split())
    sender = (SMTP_FROM or user or "").strip()
    to_addr = (os.environ.get("CONTACT_TO_EMAIL") or "").strip() or user

    if not user or not password:
        raise RuntimeError("Configuration SMTP manquante.")
    if not sender or not to_addr:
        raise RuntimeError("SMTP_FROM / destinataire (CONTACT_TO_EMAIL ou SMTP_USER) manquant.")

    content = f"""
Nouveau message depuis le formulaire de contact CyberForm

Nom : {nom}
Email : {from_email}

Message :
{body}
""".strip()

    msg = MIMEText(content, "plain", "utf-8")
    msg["Subject"] = "Nouveau message de contact - CyberForm"
    msg["From"] = sender
    msg["To"] = to_addr
    msg["Reply-To"] = from_email

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)


# === Page d'accueil
@app.route('/')
def home():
    return "CyberForm API is running"

def normalize_devices(devices):
    """
    Nettoie une liste de devices :
    - accepte str, list, ou autres types -> tout converti en str
    - strip espaces, supprime les vides
    - dé-duplique (insensible à la casse) tout en conservant la 1re casse vue
    - trie pour rendre l'ordre déterministe (utile pour la clé d'unicité Mongo)
    """
    if not devices:
        return []

    # si un seul device en str => transforme en liste
    if isinstance(devices, str):
        devices = [devices]

    cleaned = {}
    for d in devices:
        if d is None:
            continue
        s = str(d).strip()
        if not s:
            continue
        key = s.lower()
        # garde la 1re forme rencontrée 
        if key not in cleaned:
            cleaned[key] = s

    # tri déterministe par clé minuscule
    return [cleaned[k] for k in sorted(cleaned.keys())]


def _asset_technique_list(raw):
    """Normalise une entrée asset (liste ou dict unique) en liste de dicts."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return raw
    return []


def _behavioral_techniques_from_attack_graph(graph: dict) -> list:
    """
    Fusionne human_related / human_techniques et hybrid_techniques (dédoublonnage par ID MITRE).
    Les graphes module.py stockent souvent tout dans human_related ; d'autres sources peuvent
    séparer explicitement hybrid_techniques.
    """
    if not isinstance(graph, dict):
        return []
    combined = _asset_technique_list(
        graph.get("human_related") or graph.get("human_techniques")
    ) + _asset_technique_list(graph.get("hybrid_techniques"))
    seen: set[str] = set()
    out: list = []
    for t in combined:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("technique_id") or t.get("id") or "").strip().upper().split(".")[0]
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out.append(t)
    return out


def _non_human_techniques_from_attack_graph(graph: dict) -> list:
    if not isinstance(graph, dict):
        return []
    nh = graph.get("non_human_techniques") or graph.get("non_human") or []
    return _asset_technique_list(nh)


def get_human_threats_for_user(user_id: str):
    """
    Récupère les menaces comportementales (human + hybrid) du profil de risque
    (collection profile_risks) — aligné sur la séparation generate_profile_risk.
    """
    threats = get_all_techniques_from_profile_risk(user_id, human_only=True)
    return threats


def get_all_techniques_from_profile_risk(user_id: str, human_only: bool = False):
    """
    Récupère les techniques du dernier profil de risque pour un utilisateur.

    - human_only=True : human_techniques + hybrid_techniques (exclut non_human).
    - human_only=False : human + hybrid + non_human_techniques.
    """
    if not user_id:
        return []

    doc = (
        mongo.db.profile_risks
        .find({"userID": user_id})
        .sort("date", -1)
        .limit(1)
    )
    doc = list(doc)
    if not doc:
        return []

    doc = doc[0]
    out = []

    for asset in doc.get("assets", []):
        asset_name = (
            asset.get("asset_name") or
            asset.get("name") or
            asset.get("asset_id")
        )
        threat_score = float(asset.get("threat_score", 0.0) or asset.get("T", 0.0) or 0.0)

        if human_only:
            techniques = _asset_technique_list(asset.get("human_techniques")) + _asset_technique_list(
                asset.get("hybrid_techniques")
            )
        else:
            techniques = (
                _asset_technique_list(asset.get("human_techniques"))
                + _asset_technique_list(asset.get("hybrid_techniques"))
                + _asset_technique_list(asset.get("non_human_techniques"))
            )

        for t in techniques:
            if not isinstance(t, dict):
                continue
            out.append({
                "technique_id": t.get("technique_id") or t.get("id"),
                "technique_name": t.get("technique_name") or t.get("name") or "",
                "description": t.get("description") or "",
                "asset_name": asset_name,
                "asset_id": asset.get("asset_id"),
                "threat_score": threat_score,
                "risk_local": float(t.get("risk", 0) or t.get("risk_local", 0) or 0),
            })

    return out

@app.route('/generate_quiz', methods=['POST'])
@require_jwt()
def api_generate_quiz():
    data = request.get_json(silent=True)

    if data is None:
        raw = request.data.decode("utf-8", errors="ignore").strip()
        try:
            data = json.loads(raw) if raw else {}
        except Exception:
            return jsonify({
                "error": "JSON invalide (string non parseable)",
                "raw_preview": raw[:300]
            }), 400

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return jsonify({
                "error": "JSON invalide (double stringify)",
                "raw_preview": data[:300]
            }), 400

    if not isinstance(data, dict):
        return jsonify({"error": "JSON invalide (objet attendu)"}), 400

    # 1) Profile
    profile = data.get("profile", {}) or {}

    if isinstance(profile, str):
        try:
            profile = json.loads(profile)
        except Exception:
            return jsonify({
                "error": "profile invalide (string non parseable)",
                "profile_preview": profile[:300]
            }), 400

    if not isinstance(profile, dict):
        return jsonify({"error": "profile doit être un objet JSON"}), 400

    quiz_type = str(data.get("quiz_type") or "pre").strip().lower()
    if quiz_type not in ("pre", "post"):
        quiz_type = "pre"

    human_only = bool(data.get("human_only", True))
    max_questions = 10

    # 2) userID + fallback racine
    userID = (
        profile.get("userID")
        or (profile.get("profil", {}) or {}).get("userID")
        or data.get("userID")
        or data.get("userId")
        or data.get("user_id")
        or "unknown"
    )
    userID = str(userID).strip() if userID is not None else "unknown"
    profile["userID"] = userID

    denied = check_self_or_admin(userID)
    if denied:
        return denied

    # 3) Extraction / validations
    job_role = str(profile.get("jobRole", "") or "").strip()
    qualifications = profile.get("qualifications", []) or []
    responsibilities = profile.get("keyResponsibilities", []) or []

    if not isinstance(qualifications, list) or not isinstance(responsibilities, list):
        return jsonify({
            "error": "Les champs 'qualifications' et 'keyResponsibilities' doivent être des listes."
        }), 400

    profil_formate = {
        "userID": userID,
        "jobRole": job_role,
        "qualifications": qualifications,
        "keyResponsibilities": responsibilities
    }

    # 4) Techniques human + hybrid du profil de risque (comportementales ; non_human exclu en human_only)
    human_threats = []
    if userID != "unknown":
        try:
            human_threats = get_all_techniques_from_profile_risk(userID, human_only=True) or []
            if not human_threats:
                try:
                    result_risk = generate_profile_risk(userID)
                    mongo.db.profile_risks.update_one(
                        {"userID": userID},
                        {"$set": {**result_risk, "date": datetime.now(timezone.utc)}},
                        upsert=True
                    )
                    human_threats = get_all_techniques_from_profile_risk(userID, human_only=True) or []
                except Exception as e2:
                    print(f"[generate_quiz] génération profil de risque de secours : {e2}")
        except Exception as e:
            print("get_all_techniques_from_profile_risk a échoué, on continue sans.", e)
            traceback.print_exc()
            human_threats = []

    # 4b) Required scores / scores par thème
    required_scores = data.get("required_scores")
    user_scores_per_thread = data.get("user_scores_per_thread")

    if quiz_type == "pre":
        user_scores_per_thread = []
        if not isinstance(required_scores, list):
            required_scores = []
    else:
        if not isinstance(required_scores, list) or not isinstance(user_scores_per_thread, list):
            last_quiz = mongo.db.quiz_history.find_one(
                {"userID": userID, "quiz_type": quiz_type},
                sort=[("date", -1)],
                projection={"required_scores": 1, "user_scores_per_thread": 1}
            ) or {}

            if not isinstance(required_scores, list):
                required_scores = last_quiz.get("required_scores") or []

            if not isinstance(user_scores_per_thread, list):
                user_scores_per_thread = last_quiz.get("user_scores_per_thread") or []

    # 5) Génération IA (+ régénération si score qualité sous le seuil)
    try:
        attempts_log = []
        best_bundle = None
        max_total = 1 + QUIZ_MAX_QUALITY_REGEN

        for attempt_idx in range(max_total):
            raw_quiz, blueprint, parsed = generate_quiz(
                profil_formate,
                quiz_type=quiz_type,
                human_threats=human_threats,
                max_questions=max_questions,
                required_scores=required_scores
            )

            normalized = normalize_quiz_questions_for_api(parsed)
            if normalized is None:
                return jsonify({
                    "error": "Le quiz généré ne contient pas 10 questions valides.",
                    "debug": {
                        "userID": userID,
                        "quiz_type": quiz_type,
                        "questions_count": len(parsed) if isinstance(parsed, list) else 0,
                    }
                }), 500

            parsed = normalized
            quality_metrics = compute_quiz_quality_metrics(parsed, blueprint)
            score = float(quality_metrics.get("quality_score") or 0)
            attempts_log.append({"attempt": attempt_idx + 1, "quality_score": score})

            best_score = (
                float(best_bundle[3].get("quality_score") or -1)
                if best_bundle is not None else -1.0
            )
            if best_bundle is None or score > best_score:
                best_bundle = (raw_quiz, blueprint, parsed, quality_metrics)

            if score >= QUIZ_MIN_QUALITY_SCORE:
                break

        _raw, blueprint, parsed, quality_metrics = best_bundle
        quality_metrics = dict(quality_metrics)
        quality_metrics["quality_threshold"] = QUIZ_MIN_QUALITY_SCORE
        quality_metrics["quality_below_threshold"] = (
            float(quality_metrics.get("quality_score") or 0) < QUIZ_MIN_QUALITY_SCORE
        )
        quality_metrics["quality_attempts"] = len(attempts_log)
        quality_metrics["quality_attempts_log"] = attempts_log

    except QuizValidationError as e:
        traceback.print_exc()
        return jsonify({
            "error": "Le quiz généré n'a pas passé la validation automatique après plusieurs tentatives.",
            "validation_errors": getattr(e, "errors", []),
            "raw_preview": (getattr(e, "last_cleaned_preview", None) or "")[:800],
        }), 500
    except Exception as e:
        traceback.print_exc()
        return json_api_error("Erreur lors de la génération du quiz.", 500, e)

    # 6) Sauvegarde Mongo
    doc = {
        "userID": userID,
        "quiz_type": quiz_type,
        "profile": profil_formate,
        "human_threats_used": human_threats,
        "blueprint": blueprint,
        "questions": parsed,
        "quality_metrics": quality_metrics,
        "date": datetime.now(timezone.utc)
    }

    res = mongo.db.quiz_genere.insert_one(doc)

    return jsonify({
        "quiz_id": str(res.inserted_id),
        "quiz": parsed,
        "userID": userID,
        "quiz_type": quiz_type,
        "total_questions": len(parsed),
        "quality_metrics": quality_metrics,
    }), 200


@app.route('/api/quiz_quality_metrics', methods=['GET'])
@require_jwt(require_admin=True)
def api_quiz_quality_metrics():
    """Liste les métriques qualité des quiz enregistrés (JSON). Filtre optionnel : userID, limit."""
    user_id = (request.args.get('userID') or request.args.get('user_id') or '').strip()
    try:
        limit = min(max(int(request.args.get('limit', '100')), 1), 500)
    except (TypeError, ValueError):
        limit = 100

    q = {}
    if user_id:
        q['userID'] = user_id

    cursor = mongo.db.quiz_genere.find(q, sort=[('date', -1)], limit=limit)
    out = []
    for doc in cursor:
        qm = doc.get('quality_metrics') or {}
        out.append({
            'quiz_id': str(doc.get('_id', '')),
            'userID': doc.get('userID'),
            'quiz_type': doc.get('quiz_type'),
            'date': _quiz_date_iso(doc.get('date')),
            'quality_metrics': qm,
        })
    return jsonify({'items': out, 'count': len(out)}), 200


@app.route('/api/quiz_quality_metrics.csv', methods=['GET'])
@require_jwt(require_admin=True)
def api_quiz_quality_metrics_csv():
    """Export CSV des métriques qualité (collection quiz_genere). Filtre optionnel : userID, limit."""
    user_id = (request.args.get('userID') or request.args.get('user_id') or '').strip()
    try:
        limit = min(max(int(request.args.get('limit', '200')), 1), 500)
    except (TypeError, ValueError):
        limit = 200

    q = {}
    if user_id:
        q['userID'] = user_id

    cursor = mongo.db.quiz_genere.find(q, sort=[('date', -1)], limit=limit)
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow([
        'date_iso', 'userID', 'quiz_type', 'quiz_id',
        'quality_score', 'quality_below_threshold', 'quality_threshold',
        'bloom_coverage', 'technique_unique_count',
        'avg_scenario_chars', 'avg_question_chars', 'qcm_count', 'vf_count',
        'quality_attempts',
    ])
    for doc in cursor:
        qm = doc.get('quality_metrics') or {}
        w.writerow([
            _quiz_date_iso(doc.get('date')),
            doc.get('userID', ''),
            doc.get('quiz_type', ''),
            str(doc.get('_id', '')),
            qm.get('quality_score', ''),
            qm.get('quality_below_threshold', ''),
            qm.get('quality_threshold', ''),
            qm.get('bloom_coverage', ''),
            qm.get('technique_unique_count', ''),
            qm.get('avg_scenario_chars', ''),
            qm.get('avg_question_chars', ''),
            qm.get('qcm_count', ''),
            qm.get('vf_count', ''),
            qm.get('quality_attempts', ''),
        ])
    # BOM UTF-8 pour Excel
    payload = '\ufeff' + buf.getvalue()
    return Response(
        payload.encode('utf-8'),
        mimetype='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': 'attachment; filename=quiz_quality_metrics.csv',
        },
    )


@app.route(
    '/api/admin/organization_settings',
    methods=['GET', 'PUT', 'POST'],
    strict_slashes=False,
)
@require_jwt(require_admin=True)
def api_organization_settings():
    """
    Paramètres de seuils pour l'évaluation quiz / objectifs (utilisés par /evaluate).
    GET : lecture. PUT ou POST : mise à jour (document unique Mongo).
    POST est un alias de PUT (certains proxies / vieux déploiements renvoient 404 sur PUT).
    """
    if request.method == 'GET':
        s = load_organization_settings()
        crit = s.get("critical_technique_ids")
        s["critical_technique_ids_default"] = crit is None
        s["critical_technique_ids_disabled"] = isinstance(crit, list) and len(crit) == 0
        return jsonify(s), 200

    if request.method not in ('PUT', 'POST'):
        return jsonify({"error": "Method not allowed"}), 405

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Corps JSON objet attendu"}), 400

    def _f(key, default, lo, hi):
        if key not in payload or payload[key] is None:
            return default
        try:
            v = float(payload[key])
        except (TypeError, ValueError):
            return default
        return max(lo, min(hi, v))

    def _i(key, default, lo, hi):
        if key not in payload or payload[key] is None:
            return default
        try:
            v = int(payload[key])
        except (TypeError, ValueError):
            return default
        return max(lo, min(hi, v))

    current = load_organization_settings()
    out = dict(current)

    out["policy_threshold_pct"] = _f("policy_threshold_pct", current["policy_threshold_pct"], 0.0, 100.0)
    out["k_threshold"] = _f("k_threshold", current["k_threshold"], 0.5, 1.5)
    out["learned_history_window"] = _i("learned_history_window", current["learned_history_window"], 1, 200)
    out["learned_min_pct"] = _f("learned_min_pct", current["learned_min_pct"], 0.0, 100.0)
    out["learned_max_pct"] = _f("learned_max_pct", current["learned_max_pct"], 0.0, 100.0)
    if out["learned_min_pct"] > out["learned_max_pct"]:
        out["learned_min_pct"], out["learned_max_pct"] = out["learned_max_pct"], out["learned_min_pct"]

    out["critical_vulnerability_threshold_pct"] = _f(
        "critical_vulnerability_threshold_pct",
        current["critical_vulnerability_threshold_pct"],
        0.0,
        100.0,
    )

    if "critical_technique_ids" in payload:
        ct = payload["critical_technique_ids"]
        if ct is None:
            out["critical_technique_ids"] = None
        elif isinstance(ct, list):
            out["critical_technique_ids"] = [
                str(x).strip() for x in ct if str(x).strip()
            ]
        else:
            return jsonify({"error": "critical_technique_ids doit être null ou une liste de chaînes"}), 400

    if "per_technique_vulnerability_thresholds" in payload:
        pt = payload["per_technique_vulnerability_thresholds"]
        if pt is None:
            out["per_technique_vulnerability_thresholds"] = {}
        elif isinstance(pt, dict):
            out["per_technique_vulnerability_thresholds"] = normalize_per_technique_vulnerability_thresholds(pt)
        else:
            return jsonify({"error": "per_technique_vulnerability_thresholds doit être un objet {Txxxx: pourcentage}"}), 400

    doc = {"_id": ORG_SETTINGS_DOC_ID}
    for k in _default_organization_settings().keys():
        doc[k] = out[k]
    mongo.db[ORG_SETTINGS_COLLECTION].replace_one(
        {"_id": ORG_SETTINGS_DOC_ID},
        doc,
        upsert=True,
    )
    return jsonify(load_organization_settings()), 200


@app.route('/api/admin/mitre_techniques_catalog', methods=['GET'])
@require_jwt(require_admin=True)
def api_mitre_techniques_catalog():
    """
    Catalogue MITRE (IDs + libellés anglais) aligné sur ``m.MITRE_NAMES``.
    Utilisé par l’admin pour fixer un seuil de vulnérabilité par technique.
    """
    items = [{"id": k, "name": v} for k, v in sorted(MITRE_NAMES.items(), key=lambda x: x[0])]
    return jsonify({"items": items, "count": len(items)}), 200


# === Générer une formation personnalisée
@app.route('/generate_training', methods=['POST'])
@require_jwt()
def api_generate_training():
    try:
        data = request.get_json(silent=True) or {}

        # 1) userID
        user_id = (
            data.get("userID")
            or data.get("userId")
            or data.get("user_id")
        )

        if not user_id:
            return jsonify({"error": "userID manquant"}), 400

        denied = check_self_or_admin(str(user_id))
        if denied:
            return denied

        # 2) quiz_type
        quiz_type = (
            data.get("quiz_type")
            or data.get("quizType")
            or "pre"
        )
        quiz_type = str(quiz_type).strip().lower()

        if quiz_type not in ("pre", "post"):
            quiz_type = "pre"

    
        # 3) récupérer le profil utilisateur
        user_doc = mongo.db.users.find_one(
            {"basic_info.userID": user_id}
        ) or mongo.db.users.find_one(
            {"userID": user_id}
        ) or {}

        if not user_doc:
            return jsonify({"error": f"Utilisateur introuvable : {user_id}"}), 404

        # adapter selon ta structure Mongo
        basic_info = user_doc.get("basic_info", {}) or {}
        profil = user_doc.get("profil", {}) or {}

        profile = {
            "userID": basic_info.get("userID") or user_doc.get("userID") or user_id,
            "jobRole": (
                profil.get("jobRole")
                or user_doc.get("jobRole")
                or ""
            ),
            "qualifications": (
                profil.get("qualifications")
                or user_doc.get("qualifications")
                or []
            ),
            "keyResponsibilities": (
                profil.get("keyResponsibilities")
                or user_doc.get("keyResponsibilities")
                or []
            ),
            "preQuizErreurs": (
                profil.get("preQuizErreurs")
                or user_doc.get("preQuizErreurs")
                or []
            )
        }

        # sécuriser listes
        if not isinstance(profile["qualifications"], list):
            profile["qualifications"] = []
        if not isinstance(profile["keyResponsibilities"], list):
            profile["keyResponsibilities"] = []
        if not isinstance(profile["preQuizErreurs"], list):
            profile["preQuizErreurs"] = []

        # 4) récupérer résultats
        results = data.get("results")

        # si le frontend ne passe pas results, on prend le dernier quiz_history
        if not isinstance(results, dict):
            results = mongo.db.quiz_history.find_one(
                {"userID": user_id, "quiz_type": quiz_type},
                sort=[("date", -1)]
            ) or {}

        # 5) récupérer menaces humaines
        human_threats = data.get("human_threats")

        if not isinstance(human_threats, list):
            try:
                human_threats = get_human_threats_for_user(user_id) or []
            except Exception as e:
                print(f"[WARNING] get_human_threats_for_user a échoué : {e}")
                human_threats = []

        # 6) générer le contenu de formation (pipeline : blueprint JSON, validation, score, réparation)
        training_bundle = generate_training_content(
            profile=profile,
            quiz_type=quiz_type,
            results=results,
            human_threats=human_threats
        )

        if not isinstance(training_bundle, dict):
            return jsonify({
                "error": "Réponse de génération formation invalide"
            }), 500

        training_html = training_bundle.get("html") or ""
        training_quality = training_bundle.get("quality_metrics") or {}
        training_blueprint = training_bundle.get("blueprint") or []
        learning_summary = training_bundle.get("learning_summary") or {}

        if not isinstance(training_html, str) or not training_html.strip():
            return jsonify({
                "error": "Contenu de formation vide ou invalide"
            }), 500

        # 7) extraire quelques métadonnées utiles
        user_score = results.get("user_score")
        total_questions = results.get("total_questions")
        vulnerability_score = results.get("vulnerability_score")
        normalized_risk_score = results.get("normalized_risk_score")
        risk_level = results.get("risk_level")
        objectif_atteint = results.get("objectifAtteint")

        # 8) sauvegarde trainingHistory + lastTrainingContent
        now_utc = datetime.now(timezone.utc)

        training_doc = {
            "userID": user_id,
            "quiz_type": quiz_type,
            "date": now_utc,
            "profile_snapshot": profile,
            "results_snapshot": {
                "user_score": user_score,
                "total_questions": total_questions,
                "vulnerability_score": vulnerability_score,
                "normalized_risk_score": normalized_risk_score,
                "risk_level": risk_level,
                "objectifAtteint": objectif_atteint,
                "top_threat": results.get("top_threat"),
                "answers": results.get("answers", [])
            },
            "human_threats_used": human_threats,
            "content": training_html,
            "quality_metrics": training_quality,
            "training_blueprint": training_blueprint,
            "learning_summary": learning_summary,
        }

        inserted = mongo.db.trainings.insert_one(training_doc)

        # mise à jour user : dernière formation + historique
        mongo.db.users.update_one(
            {"basic_info.userID": user_id},
            {
                "$set": {
                    "lastTrainingContent": training_html,
                    "lastTrainingDate": now_utc
                },
                "$push": {
                    "trainingHistory": {
                        "training_id": str(inserted.inserted_id),
                        "quiz_type": quiz_type,
                        "date": now_utc,
                        "risk_level": risk_level,
                        "normalized_risk_score": normalized_risk_score,
                        "objectifAtteint": objectif_atteint
                    }
                }
            }
        )

        # fallback si ancien schéma
        mongo.db.users.update_one(
            {"userID": user_id},
            {
                "$set": {
                    "lastTrainingContent": training_html,
                    "lastTrainingDate": now_utc
                },
                "$push": {
                    "trainingHistory": {
                        "training_id": str(inserted.inserted_id),
                        "quiz_type": quiz_type,
                        "date": now_utc,
                        "risk_level": risk_level,
                        "normalized_risk_score": normalized_risk_score,
                        "objectifAtteint": objectif_atteint
                    }
                }
            }
        )

        # 9) réponse frontend
        return jsonify({
            "message": "Formation générée avec succès",
            "training_id": str(inserted.inserted_id),
            "userID": user_id,
            "quiz_type": quiz_type,
            "training": training_html,
            "quality_metrics": training_quality,
            "training_blueprint": training_blueprint,
            "learning_summary": learning_summary,
            "metadata": {
                "user_score": user_score,
                "total_questions": total_questions,
                "vulnerability_score": vulnerability_score,
                "normalized_risk_score": normalized_risk_score,
                "risk_level": risk_level,
                "objectifAtteint": objectif_atteint
            }
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return json_api_error("Erreur interne lors de la génération de la formation.", 500, e)

def _mean_std(values):
    if not values:
        return 0.0, 0.0
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / len(values)
    return m, math.sqrt(var)

def _kmeans_threshold(values, k=2, iters=8):
    """
    K-Means 1D minimal pour séparer faible/élevé.
    Retourne un seuil = moyenne des 2 centroïdes (triés).
    """
    if not values or len(values) < 2:
        return 0.0
    c1, c2 = min(values), max(values)
    for _ in range(iters):
        g1 = [v for v in values if abs(v - c1) <= abs(v - c2)]
        g2 = [v for v in values if v not in g1] or [c2]
        c1 = sum(g1) / len(g1) if g1 else c1
        c2 = sum(g2) / len(g2) if g2 else c2
    lo, hi = sorted([c1, c2])
    return (lo + hi) / 2.0

def learned_thresholds_from_history(user_id, quiz_type, window=10, k=1.0):
    """
    Seuils appris à partir de l'historique uniquement :
      learned_global_threshold = mean(global) + k*std(global)
      learned_local_threshold  = mean(local)  + k*std(local)
    """
    cursor = mongo.db.risk_history.find(
        {"userID": user_id, "quiz_type": quiz_type},
        {"global_risk_sum_local": 1, "local_risks": 1, "date": 1}
    ).sort("date", -1).limit(window)

    hist_globals = []
    hist_locals = []

    for doc in cursor:
        g = doc.get("global_risk_sum_local")
        if isinstance(g, (int, float)):
            hist_globals.append(float(g))

        lr = doc.get("local_risks", [])
        if isinstance(lr, list):
            for x in lr:
                if isinstance(x, (int, float)):
                    hist_locals.append(float(x))

    g_mean, g_std = _mean_std(hist_globals)
    l_mean, l_std = _mean_std(hist_locals)

    learned_global = g_mean + k * g_std
    learned_local = l_mean + k * l_std

    return learned_local, learned_global, g_mean, g_std, l_mean, l_std

@app.route('/evaluate', methods=['POST'])
@require_jwt()
def evaluate():
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type doit être application/json"}), 415

        data = request.get_json(silent=True) or {}

        user_id = (
            data.get("userID")
            or data.get("userId")
            or data.get("user_id")
        )

        quiz_type = (
            data.get("quiz_type")
            or data.get("quizType")
            or "pre"
        )
        quiz_type = str(quiz_type).strip().lower()

        answers = data.get("answers", [])
        if answers is None:
            answers = []

        tq_raw = data.get("total_questions", data.get("totalQuestions"))
        if tq_raw is None:
            total_questions = len(answers) if isinstance(answers, list) else 0
        else:
            try:
                total_questions = int(tq_raw)
            except (TypeError, ValueError):
                return jsonify({"error": "total_questions invalide"}), 400

        if not user_id:
            return jsonify({"error": "userID manquant"}), 400

        denied = check_self_or_admin(str(user_id))
        if denied:
            return denied

        if quiz_type not in ("pre", "post"):
            quiz_type = "pre"

        if not isinstance(answers, list):
            return jsonify({"error": "answers doit être une liste"}), 400

        if total_questions <= 0:
            return jsonify({"error": "total_questions invalide"}), 400

        # Helpers
        def _safe_float(value, default=0.0):
            try:
                if value in (None, "", "null"):
                    return float(default)
                return float(value)
            except (TypeError, ValueError):
                return float(default)

        def _extract_selected(ans):
            if isinstance(ans, dict):
                return (
                    ans.get("selected")
                    or ans.get("answer")
                    or ans.get("user_answer")
                    or ans.get("response")
                    or ""
                )
            return ans if ans is not None else ""

        def _extract_correct(q):
            if not isinstance(q, dict):
                return ""
            return (
                q.get("correct_answer")
                or q.get("correct")
                or q.get("bonne_reponse")
                or q.get("answer")
                or q.get("correctAnswer")
                or ""
            )

        def _extract_question_text(q):
            if not isinstance(q, dict):
                return ""
            return (
                q.get("question")
                or q.get("text")
                or q.get("texte")
                or ""
            )

        def _extract_scenario(q):
            if not isinstance(q, dict):
                return ""
            return (
                q.get("scenario")
                or q.get("mise_en_situation")
                or q.get("context")
                or ""
            )

        def _extract_question_id(obj):
            if not isinstance(obj, dict):
                return ""
            return (
                obj.get("question_id")
                or obj.get("questionId")
                or obj.get("id")
                or ""
            )

        def _extract_technique_id(obj):
            if not isinstance(obj, dict):
                return ""
            return (
                obj.get("technique_id")
                or obj.get("techniqueId")
                or ""
            )

        def _extract_technique_name(obj):
            if not isinstance(obj, dict):
                return ""
            return (
                obj.get("technique_name")
                or obj.get("techniqueName")
                or ""
            )

        def _extract_asset_id(obj):
            if not isinstance(obj, dict):
                return ""
            return obj.get("asset_id") or obj.get("assetId") or ""

        def _extract_asset_name(obj):
            if not isinstance(obj, dict):
                return ""
            return obj.get("asset_name") or obj.get("assetName") or ""

        def _normalize(v):
            return str(v).strip().lower()

        def _compute_learned_threshold_pct(history_scores, k=0.95, default_value=30.0,
                                           min_threshold=15.0, max_threshold=45.0):
            if not history_scores:
                return round(default_value, 2), 0.0, 0.0

            mean_val = sum(history_scores) / len(history_scores)

            if len(history_scores) > 1:
                variance = sum((x - mean_val) ** 2 for x in history_scores) / len(history_scores)
                std_val = variance ** 0.5
            else:
                std_val = 0.0

            learned = mean_val * k
            learned = max(min_threshold, min(learned, max_threshold))
            return round(learned, 2), round(mean_val, 2), round(std_val, 2)

        # 1) profil de risque + assets
        profil_risque = mongo.db.profile_risks.find_one({"userID": user_id}) or {}
        assets = profil_risque.get("assets", [])
        if not isinstance(assets, list):
            assets = []

        # 2) récupérer le quiz sauvegardé
        quiz_doc = mongo.db.quiz_genere.find_one(
            {"userID": user_id, "quiz_type": quiz_type},
            sort=[("date", -1)]
        ) or {}

        quiz_questions = (
            quiz_doc.get("questions")
            or quiz_doc.get("quiz")
            or quiz_doc.get("generated_quiz")
            or []
        )

        if not isinstance(quiz_questions, list):
            quiz_questions = []

        if not quiz_questions:
            alt_quiz_doc = mongo.db.quiz_genere.find_one(
                {"userId": user_id, "quiz_type": quiz_type},
                sort=[("date", -1)]
            ) or {}

            quiz_questions = (
                alt_quiz_doc.get("questions")
                or alt_quiz_doc.get("quiz")
                or alt_quiz_doc.get("generated_quiz")
                or []
            )

            if not isinstance(quiz_questions, list):
                quiz_questions = []

        questions_by_id = {}
        questions_by_text = {}

        for q in quiz_questions:
            if not isinstance(q, dict):
                continue

            qid = _extract_question_id(q)
            qtext = _extract_question_text(q)

            if qid:
                questions_by_id[str(qid)] = q
            if qtext:
                questions_by_text[_normalize(qtext)] = q

        # 3) score quiz + vulnérabilité
        try:
            user_score, V_norm, corrected = calculate_results(
                answers=answers,
                userID=user_id,
                quiz_type=quiz_type,
                total_questions=total_questions
            )
        except Exception as e:
            return json_api_error("Erreur lors du calcul des résultats du quiz.", 500, e)

        if not isinstance(corrected, list):
            corrected = []

        vulnerability_score_pct = round(float(V_norm) * 100, 2)

        # 4) réparer corrected si vide/incomplet
        needs_rebuild = False

        if not corrected:
            needs_rebuild = True
        else:
            for item in corrected:
                if not isinstance(item, dict):
                    needs_rebuild = True
                    break

                q_empty = not str(item.get("question", "")).strip()
                c_empty = not str(item.get("correct_answer", "")).strip()
                s_empty = not str(item.get("scenario", "")).strip()

                if q_empty and c_empty and s_empty:
                    needs_rebuild = True
                    break

        if needs_rebuild and quiz_questions:
            rebuilt = []

            for ans in answers:
                if not isinstance(ans, dict):
                    continue

                ans_qid = _extract_question_id(ans)
                ans_qtext = (ans.get("question") or "").strip()

                matched = None
                if ans_qid:
                    matched = questions_by_id.get(str(ans_qid))

                if matched is None and ans_qtext:
                    matched = questions_by_text.get(_normalize(ans_qtext))

                selected = _extract_selected(ans)

                if matched is None:
                    rebuilt.append({
                        "question_id": ans_qid,
                        "question": ans_qtext,
                        "selected": selected,
                        "correct_answer": "",
                        "is_correct": False,
                        "scenario": "",
                        "technique_id": "",
                        "technique_name": "",
                        "asset_id": "",
                        "asset_name": ""
                    })
                    continue

                correct_answer = _extract_correct(matched)
                question_text = _extract_question_text(matched)
                scenario_text = _extract_scenario(matched)

                is_correct = (
                    _normalize(selected) == _normalize(correct_answer)
                    if correct_answer != "" else False
                )

                rebuilt.append({
                    "question_id": _extract_question_id(matched) or ans_qid,
                    "question": question_text,
                    "selected": selected,
                    "correct_answer": correct_answer,
                    "is_correct": is_correct,
                    "scenario": scenario_text,
                    "technique_id": _extract_technique_id(matched),
                    "technique_name": _extract_technique_name(matched),
                    "asset_id": _extract_asset_id(matched),
                    "asset_name": _extract_asset_name(matched)
                })

            corrected = rebuilt
            user_score = sum(1 for x in corrected if x.get("is_correct") is True)

            if total_questions > 0:
                V_norm = round(max(0.0, min(1.0, 1 - (user_score / total_questions))), 4)
                vulnerability_score_pct = round(V_norm * 100, 2)

        # 5) calcul des risques locaux
        local_risks = []
        local_rows = []
        threat_values = []
        n_techniques = 0

        for a in assets:
            if not isinstance(a, dict):
                continue

            asset_name = a.get("asset_name") or a.get("asset_id") or "-"

            asset_threat = _safe_float(a.get("threat_score", a.get("T", 0.0)), 0.0)
            asset_threat = max(0.0, min(1.0, asset_threat))

            C = _safe_float(a.get("C", 0), 0)
            I_val = _safe_float(a.get("I", 0), 0)
            D = _safe_float(a.get("D", 0), 0)

            impact_asset = _safe_float(a.get("impact"), C + I_val + D)

            ht = a.get("human_techniques") or []
            hb = a.get("hybrid_techniques") or []
            nh = a.get("non_human_techniques") or a.get("non_human") or []

            if isinstance(ht, dict):
                ht = [ht]
            if isinstance(hb, dict):
                hb = [hb]
            if isinstance(nh, dict):
                nh = [nh]
            if not isinstance(ht, list):
                ht = []
            if not isinstance(hb, list):
                hb = []
            if not isinstance(nh, list):
                nh = []

            techniques = []
            techniques.extend(ht)
            techniques.extend(hb)
            techniques.extend(nh)

            if not techniques:
                techniques = [{
                    "technique_id": a.get("asset_id"),
                    "technique_name": a.get("asset_name") or asset_name,
                    "T": asset_threat
                }]

            for t in techniques:
                if not isinstance(t, dict):
                    continue

                n_techniques += 1

                # On laisse GPT (ou le profil de risque) fournir directement T
                # avec repli sur threat_score / T d'actif si absent.
                T_local_exact = _safe_float(
                    t.get("T", t.get("threat_score", asset_threat)),
                    asset_threat
                )
                T_local_exact = max(0.0, min(1.0, T_local_exact))
                threat_values.append(T_local_exact)

                impact_eff = _safe_float(t.get("impact", impact_asset), impact_asset)

                r_local = float(V_norm) * impact_eff * T_local_exact
                local_risks.append(r_local)

                # Option 2 : triade au niveau de la technique (cia_impact de la technique)
                cia_tech = t.get("cia_impact") or []
                if isinstance(cia_tech, str):
                    cia_tech = [c for c in cia_tech if c in ("C", "I", "D")]
                elif not isinstance(cia_tech, list):
                    cia_tech = []
                triade_parts = []
                if "C" in cia_tech:
                    triade_parts.append("Confidentialité")
                if "I" in cia_tech:
                    triade_parts.append("Intégrité")
                if "D" in cia_tech:
                    triade_parts.append("Disponibilité")
                if not triade_parts:
                    if C > 0:
                        triade_parts.append("Confidentialité")
                    if I_val > 0:
                        triade_parts.append("Intégrité")
                    if D > 0:
                        triade_parts.append("Disponibilité")
                triade_concernee = ", ".join(triade_parts) if triade_parts else "Non spécifiée"

                local_rows.append({
                    "asset_id": a.get("asset_id"),
                    "asset_name": asset_name,
                    "technique_id": t.get("technique_id") or t.get("id") or a.get("asset_id"),
                    "technique_name": t.get("technique_name") or t.get("name") or t.get("description") or a.get("asset_name") or asset_name,
                    "impact_eff": round(impact_eff, 2),
                    "T": round(T_local_exact, 3),
                    "V": round(float(V_norm), 4),
                    "risk_local": round(r_local, 2),
                    "C": C,
                    "I": I_val,
                    "D": D,
                    "cia_impact": cia_tech,
                    "triade_concernee": triade_concernee,
                })

        # 6) agrégats
        global_risk_sum_local = round(sum(local_risks), 2) if local_risks else 0.0
        mean_threat_probability_exact = (sum(threat_values) / len(threat_values)) if threat_values else 0.0
        mean_threat_probability = round(mean_threat_probability_exact, 2)

        if local_rows:
            impact_total = sum(r["impact_eff"] for r in local_rows) / len(local_rows)
        else:
            impact_total = 10.0

        impact_total = float(impact_total)

        risk_brut = float(V_norm) * impact_total * mean_threat_probability_exact
        risk_brut = round(risk_brut, 2)
        risk_formula = f"({float(V_norm):.4f} × {impact_total:.2f} × {mean_threat_probability_exact:.2f}) = {risk_brut:.2f}"

        # 7) normalisation
        # max théorique local = somme des maxima par technique
        # Vmax = 1 ; Imax = 9 ; Tmax = 1
        n_items = max(n_techniques, 1)
        max_theorique = round(9.0 * n_items, 2)

        risk_norm_pct = round((global_risk_sum_local / max_theorique) * 100.0, 2) if max_theorique > 0 else 0.0
        risk_norm_pct = min(100.0, max(0.0, risk_norm_pct))

        if risk_norm_pct >= 60:
            risk_level = "Critique"
        elif risk_norm_pct >= 40:
            risk_level = "Élevé"
        elif risk_norm_pct >= 20:
            risk_level = "Moyen"
        else:
            risk_level = "Faible"

        # 8) seuils organisation (Mongo) — le corps de requête peut encore surcharger
        org = load_organization_settings()

        if data.get("policy_threshold_pct") is not None:
            policy_threshold_pct = _safe_float(data.get("policy_threshold_pct"), org["policy_threshold_pct"])
        else:
            policy_threshold_pct = float(org["policy_threshold_pct"])
        policy_threshold_pct = max(0.0, min(100.0, policy_threshold_pct))

        # 9) seuil appris sur historique normalisé + KMeans
        if data.get("k_threshold") is not None:
            k = _safe_float(data.get("k_threshold"), org["k_threshold"])
        else:
            k = float(org["k_threshold"])

        if data.get("window") is not None:
            try:
                window = int(data.get("window"))
            except (TypeError, ValueError):
                window = int(org["learned_history_window"])
        else:
            window = int(org["learned_history_window"])

        learned_min_pct = max(0.0, min(100.0, float(org["learned_min_pct"])))
        learned_max_pct = max(0.0, min(100.0, float(org["learned_max_pct"])))
        if learned_min_pct > learned_max_pct:
            learned_min_pct, learned_max_pct = learned_max_pct, learned_min_pct

        hist_norms = []
        for doc in mongo.db.risk_history.find(
            {"userID": user_id, "quiz_type": quiz_type},
            {"risk_norm_pct": 1}
        ).sort("date", -1).limit(window):
            g = doc.get("risk_norm_pct")
            if isinstance(g, (int, float)):
                hist_norms.append(float(g))

        learned_threshold_pct, hist_mean_pct, hist_std_pct = _compute_learned_threshold_pct(
            history_scores=hist_norms,
            k=k,
            default_value=policy_threshold_pct,
            min_threshold=learned_min_pct,
            max_threshold=learned_max_pct
        )

        kmeans_local_thr = round(_kmeans_threshold(local_risks), 2) if len(local_risks) >= 2 else 0.0
        kmeans_global_pct = round(_kmeans_threshold(hist_norms), 2) if len(hist_norms) >= 2 else risk_norm_pct

        # seuil final strict
        final_threshold_pct = min(policy_threshold_pct, learned_threshold_pct)

        # 10) décisions
        max_local = round(max(local_risks), 2) if local_risks else 0.0

        objectifAtteint_learned = risk_norm_pct < learned_threshold_pct
        objectifAtteint_policy = risk_norm_pct < policy_threshold_pct
        objectifAtteint_final = bool(risk_norm_pct < final_threshold_pct)

        alerte_kmeans = bool(
            (max_local >= kmeans_local_thr if kmeans_local_thr > 0 else False) or
            (risk_norm_pct >= kmeans_global_pct if kmeans_global_pct > 0 else False)
        )

        # 11) scores requis par technique
        quiz_tech_ids = set()
        if quiz_questions:
            for q in quiz_questions:
                if not isinstance(q, dict):
                    continue
                tid = q.get("techniqueId") or q.get("technique_id")
                if tid:
                    quiz_tech_ids.add(str(tid))

        required_scores = []
        denom_eps = 1e-9

        for row in local_rows:
            tid = row.get("technique_id")
            if quiz_tech_ids and (tid is None or str(tid) not in quiz_tech_ids):
                continue

            T_local = float(row.get("T", 0.0))
            I_eff = float(row.get("impact_eff", 0.0))

            denom = max(T_local * I_eff, denom_eps)
            target_V = kmeans_local_thr / denom if kmeans_local_thr > 0 else 1.0
            target_V = min(1.0, max(0.0, target_V))

            required_correct = math.ceil(total_questions * (1.0 - target_V))
            required_correct = min(total_questions, max(0, required_correct))

            required_scores.append({
                "technique_id": tid,
                "technique_name": row.get("technique_name"),
                "required_correct_answers": required_correct,
                "target_Vpre": round(target_V, 2),
                "local_threshold": round(kmeans_local_thr, 2)
            })

        # User score per technique
        user_scores_per_technique = []
        tid_stats = {}

        for item in corrected:
            if not isinstance(item, dict):
                continue

            tid = item.get("technique_id") or item.get("techniqueId")
            if not tid:
                tid = "other"

            tid = str(tid)

            if tid not in tid_stats:
                tid_stats[tid] = {
                    "correct": 0,
                    "total": 0,
                    "technique_name": item.get("technique_name") or item.get("techniqueName") or ""
                }

            tid_stats[tid]["total"] += 1
            if item.get("is_correct") is True:
                tid_stats[tid]["correct"] += 1

        for tid, st in tid_stats.items():
            total_t = max(st["total"], 1)
            score_pct = round(100.0 * st["correct"] / total_t, 2)
            vuln_pct = round(100.0 * (1 - (st["correct"] / total_t)), 2)

            user_scores_per_technique.append({
                "technique_id": tid,
                "technique_name": st["technique_name"],
                "correct_count": st["correct"],
                "total_count": st["total"],
                "score_pct": score_pct,
                "vulnerability_score": vuln_pct
            })

        # 11b) Vulnérabilité par technique : seuils admin (prioritaires) puis règle « critiques »
        crit_vuln_thr = max(0.0, min(100.0, float(org["critical_vulnerability_threshold_pct"])))
        crit_raw = org["critical_technique_ids"]
        if crit_raw is None:
            crit_set = CRITICAL_HUMAN_TECHNIQUE_IDS
        elif isinstance(crit_raw, list) and len(crit_raw) == 0:
            crit_set = set()
        else:
            crit_set = _critical_match_set_from_config(crit_raw)

        per_map = normalize_per_technique_vulnerability_thresholds(
            org.get("per_technique_vulnerability_thresholds") or {}
        )

        per_technique_vulnerability_evaluation = []
        formation_triggered_critical_technique = False
        critical_techniques_above_threshold = []

        for u in user_scores_per_technique:
            vuln = float(u.get("vulnerability_score", 0))
            thr, src = _effective_technique_vulnerability_threshold(
                u.get("technique_id"), per_map, crit_set, crit_vuln_thr
            )
            if thr is None:
                per_technique_vulnerability_evaluation.append({
                    "technique_id": u.get("technique_id"),
                    "technique_name": u.get("technique_name"),
                    "vulnerability_score": round(vuln, 2),
                    "threshold_pct": None,
                    "threshold_source": None,
                    "acceptable": True,
                })
            else:
                acceptable = vuln < thr
                per_technique_vulnerability_evaluation.append({
                    "technique_id": u.get("technique_id"),
                    "technique_name": u.get("technique_name"),
                    "vulnerability_score": round(vuln, 2),
                    "threshold_pct": round(thr, 2),
                    "threshold_source": src,
                    "acceptable": bool(acceptable),
                })
                if not acceptable:
                    formation_triggered_critical_technique = True
                    critical_techniques_above_threshold.append({
                        "technique_id": u.get("technique_id"),
                        "technique_name": u.get("technique_name"),
                        "vulnerability_score": round(vuln, 2),
                        "threshold_pct": round(thr, 2),
                        "threshold_source": src,
                    })
        if formation_triggered_critical_technique:
            objectifAtteint_final = False

        # 12) menace principale
        top_threat = None
        if local_rows:
            top = max(local_rows, key=lambda x: x.get("risk_local", 0))
            top_threat = {
                "technique_id": top.get("technique_id"),
                "technique_name": top.get("technique_name"),
                "risk_local": top.get("risk_local"),
                "asset_name": top.get("asset_name")
            }

        # 13) horodatage
        now_utc = datetime.now(timezone.utc)

        # 14) sauvegarde risk_history
        mongo.db.risk_history.insert_one({
            "userID": user_id,
            "quiz_type": quiz_type,
            "date": now_utc,
            "global_risk_sum_local": float(global_risk_sum_local),
            "mean_threat_probability": float(mean_threat_probability_exact),
            "local_risks": [float(x) for x in local_risks],
            "n_assets": int(len(local_risks)),
            "n_techniques": int(n_items),
            "V_norm": float(V_norm),
            "impact_total": float(impact_total),
            "user_score": int(user_score),
            "total_questions": int(total_questions),
            "max_theorique": float(max_theorique),
            "risk_norm_pct": float(risk_norm_pct),
            "policy_threshold_pct": float(policy_threshold_pct),
            "learned_threshold_pct": float(learned_threshold_pct),
            "final_threshold_pct": float(final_threshold_pct),
            "risk_level": risk_level
        })

        # 15) sauvegarde quiz_history
        mongo.db.quiz_history.insert_one({
            "userID": user_id,
            "quiz_type": quiz_type,
            "date": now_utc,
            "user_score": int(user_score),
            "total_questions": int(total_questions),
            "vulnerability_score": float(vulnerability_score_pct),
            "V_norm": float(V_norm),
            "global_risk_sum_local": float(global_risk_sum_local),
            "risk_norm_pct": float(risk_norm_pct),
            "risk_level": risk_level,
            "objectifAtteint": bool(objectifAtteint_final),
            "objectifAtteint_learned": bool(objectifAtteint_learned),
            "objectifAtteint_policy": bool(objectifAtteint_policy),
            "formation_triggered_critical_technique": bool(formation_triggered_critical_technique),
            "critical_techniques_above_threshold": critical_techniques_above_threshold,
            "per_technique_vulnerability_evaluation": per_technique_vulnerability_evaluation,
            "policy_threshold_pct": float(policy_threshold_pct),
            "learned_threshold_pct": float(learned_threshold_pct),
            "final_threshold_pct": float(final_threshold_pct),
            "top_threat": top_threat,
            "required_scores": required_scores,
            # Alias pour compatibilité avec la boucle IA (thread = technique ici)
            "user_scores_per_technique": user_scores_per_technique,
            "user_scores_per_thread": user_scores_per_technique,
            "answers": corrected
        })

        # mise à jour utilisateur
        mongo.db.users.update_one(
            {"basic_info.userID": user_id},
            {
                "$set": {
                    "lastScore": int(user_score),
                    "lastEvaluationDate": now_utc,
                    "riskScore": float(global_risk_sum_local),
                    "riskNormPct": float(risk_norm_pct),
                    "riskLevel": risk_level,
                    "objectifAtteint": bool(objectifAtteint_final)
                }
            }
        )

        # 16) réponse
        res = {
            "userID": user_id,
            "quiz_type": quiz_type,
            "date": now_utc.isoformat(),

            "user_score": int(user_score),
            "total_questions": int(total_questions),

            "vulnerability_score": vulnerability_score_pct,
            "V_norm": round(float(V_norm), 2),

            "impact_total": round(impact_total, 2),
            "mean_threat_probability": mean_threat_probability,
            "risk_brut": round(risk_brut, 2),
            "risk_formula": risk_formula,

            "global_risk_sum_local": round(global_risk_sum_local, 2),
            "risk_norm_pct": round(risk_norm_pct, 2),
            "risk_level": risk_level,

            "policy_threshold_pct": round(policy_threshold_pct, 2),
            "learned_threshold_pct": round(learned_threshold_pct, 2),
            "final_threshold_pct": round(final_threshold_pct, 2),

            "kmeans_local_threshold": round(kmeans_local_thr, 2),
            "kmeans_global_pct": round(kmeans_global_pct, 2),

            "objectifAtteint_learned": bool(objectifAtteint_learned),
            "objectifAtteint_policy": bool(objectifAtteint_policy),
            "objectifAtteint": bool(objectifAtteint_final),
            "formation_triggered_critical_technique": bool(formation_triggered_critical_technique),
            "critical_techniques_above_threshold": critical_techniques_above_threshold,
            "per_technique_vulnerability_evaluation": per_technique_vulnerability_evaluation,
            "alerte_kmeans": bool(alerte_kmeans),

            "threshold_debug": {
                "window": window,
                "k": k,
                "history_mean_pct": round(hist_mean_pct, 2),
                "history_std_pct": round(hist_std_pct, 2),
                "max_theorique": round(max_theorique, 2),
                "n_techniques": int(n_items)
            },

            "top_threat": top_threat,
            "assets_risk_details": local_rows,
            "required_scores": required_scores,
            # Alias pour compatibilité avec la boucle IA (thread = technique ici)
            "user_scores_per_technique": user_scores_per_technique,
            "user_scores_per_thread": user_scores_per_technique,
            "answers": corrected
        }

        return jsonify(res), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return json_api_error("Erreur interne lors de l'évaluation du quiz.", 500, e)

# === Required Score / User Score per thread (boucle schéma Analyse risque -> Test -> IA)
@app.route('/api/risk/scores_per_thread', methods=['GET'])
@require_jwt()
def get_scores_per_thread():
    """
    Retourne les derniers required_scores et user_scores_per_thread pour un utilisateur
    (issus de la dernière évaluation). Permet d'alimenter la boucle Risk Analysis -> Testing -> IA.
    """
    user_id = request.args.get("userID") or request.args.get("user_id")
    quiz_type = request.args.get("quiz_type", "pre").strip().lower()
    if quiz_type not in ("pre", "post"):
        quiz_type = "pre"
    if not user_id:
        return jsonify({"error": "userID manquant"}), 400

    denied = check_self_or_admin(str(user_id))
    if denied:
        return denied

    doc = mongo.db.quiz_history.find_one(
        {"userID": user_id, "quiz_type": quiz_type},
        sort=[("date", -1)],
        projection={"required_scores": 1, "user_scores_per_thread": 1, "date": 1}
    )
    if not doc:
        return jsonify({
            "userID": user_id,
            "quiz_type": quiz_type,
            "required_scores": [],
            "user_scores_per_thread": [],
            "message": "Aucune évaluation trouvée"
        }), 200
    return jsonify({
        "userID": user_id,
        "quiz_type": quiz_type,
        "date": doc.get("date").isoformat() if hasattr(doc.get("date"), "isoformat") else str(doc.get("date")),
        "required_scores": doc.get("required_scores") or [],
        "user_scores_per_thread": doc.get("user_scores_per_thread") or []
    }), 200

# === Lister tous les utilisateurs
@app.route('/api/users', methods=['GET'])
@require_jwt(require_admin=True)
def get_users():
    users = list(mongo.db.users.find())
    uids = [
        (u.get("basic_info") or {}).get("userID")
        for u in users
        if (u.get("basic_info") or {}).get("userID")
    ]
    profile_by_uid = {
        p["userID"]: p
        for p in mongo.db.profile_risks.find(
            {"userID": {"$in": uids}},
            {"userID": 1, "profile_acceptable": 1, "profile_quality_metrics": 1},
        )
    }

    result = []

    def _num(v, default=None):
        try:
            if v in (None, "", "null"):
                return default
            return float(v)
        except (TypeError, ValueError):
            return default

    def _pick_positive(*values, default=0.0):
        for v in values:
            n = _num(v, None)
            if n is not None and n > 0:
                return n
        return default

    for u in users:
        basic = u.get("basic_info", {}) or {}
        profil = u.get("profil", {}) or {}

        user_id = basic.get("userID")

        last_quiz = {}
        if user_id:
            last_quiz = mongo.db.quiz_history.find_one(
                {"userID": user_id},
                sort=[("date", -1)]
            ) or {}

        # Valeurs stockées dans users
        stored_risk_brut = u.get("riskScore", u.get("risk_score"))
        stored_risk_norm = u.get("riskNormPct", u.get("risk_norm_pct"))
        stored_vuln = u.get("vulnerability_score")

        # Valeurs du dernier quiz
        quiz_risk_norm = _pick_positive(
            last_quiz.get("risk_norm_pct"),
            last_quiz.get("normalized_risk_score"),
            last_quiz.get("riskNormPct")
        )

        quiz_risk_brut = _pick_positive(
            last_quiz.get("riskScore"),
            last_quiz.get("risk_score")
        )

        quiz_vuln = _num(last_quiz.get("vulnerability_score"), None)

        # Priorité : users si valeur exploitable, sinon quiz_history
        risk_brut = _pick_positive(stored_risk_brut, quiz_risk_brut, default=0.0)
        risk_norm = _pick_positive(stored_risk_norm, quiz_risk_norm, default=0.0)

        vulnerability_score = _num(stored_vuln, None)
        if vulnerability_score is None:
            vulnerability_score = _num(quiz_vuln, 0.0)

        # Objectif : priorité au résultat enregistré du dernier test (quiz), pas au seuil de risque seul
        if last_quiz and last_quiz.get("objectifAtteint") is not None:
            objectif_atteint = bool(last_quiz.get("objectifAtteint"))
        else:
            objectif_atteint = bool(u.get("objectifAtteint", False))

        pr_doc = profile_by_uid.get(user_id) or {}
        pqm = pr_doc.get("profile_quality_metrics") or {}

        result.append({
            "basic_info": {
                "userID": user_id,
                "nom": basic.get("nom"),
                "prenom": basic.get("prenom"),
                "role": basic.get("role"),
                "email": basic.get("email"),
            },

            "profil": {
                "jobRole": profil.get("jobRole"),
                "qualifications": profil.get("qualifications", []),
                "keyResponsibilities": profil.get("keyResponsibilities", []),
            },

            "user_score": u.get("user_score", 0),

            # Risque brut
            "risk_score": risk_brut,
            "riskScore": risk_brut,

            # Risque normalisé affichable
            "riskNormPct": risk_norm,
            "risk_norm_pct": risk_norm,
            "normalized_risk_score": risk_norm,

            "vulnerability_score": vulnerability_score,

            "objectifAtteint": objectif_atteint,

            "profile_acceptable": pr_doc.get("profile_acceptable"),
            "profile_quality_score": pqm.get("profile_quality_score"),

            "lastEvaluationDate": u.get("lastEvaluationDate"),
            "nextEvaluationDate": u.get("nextEvaluationDate"),
            "lastTrainingDate": u.get("lastTrainingDate"),
            "nextTrainingDate": u.get("nextTrainingDate"),

            "lastTrainingContent": u.get("lastTrainingContent", ""),
        })

    return jsonify(result), 200

def _to_ts_safe(value) -> float:
    """
    Convertit une valeur de date (str ou datetime) en timestamp (float)
    pour le tri, en gérant :
    - datetime avec ou sans timezone
    - string isoformat
    - valeurs bizarres
    """
    dt = None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except Exception:
            dt = None

    if dt is None:
        # vieille date par défaut pour ne pas casser le tri
        dt = datetime.min.replace(tzinfo=timezone.utc)

    # normaliser : si pas de tz → on force UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # on renvoie un float timestamp
    return dt.timestamp()


def _serialize_date(value):
    """
    Convertit une date en string ISO pour le JSON.
    """
    if isinstance(value, datetime):
        # si pas de timezone, on met UTC
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return value


def _parse_next_training_datetime(raw):
    """Datetime UTC pour nextTrainingDate (Mongo datetime ou chaîne ISO), ou None."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        dt = raw
    elif isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _user_has_upcoming_training(u: dict, now: datetime) -> bool:
    """
    True si une formation est encore planifiée à venir (date >= now).
    Exclut les dates passées, pour éviter un KPI « formations planifiées » à 100 % alors que tout est en retard.
    """
    dt = _parse_next_training_datetime(u.get("nextTrainingDate"))
    if dt is None:
        return False
    return dt >= now


@app.route('/api/user_with_history/<userID>', methods=['GET'])
@require_jwt()
def api_user_with_history(userID):
    try:
        denied = check_self_or_admin(userID)
        if denied:
            return denied

        def _pick_risk_value(*values):
            for v in values:
                if v is None:
                    continue
                try:
                    num = float(v)
                    if num > 0:
                        return num
                except Exception:
                    continue
            return 0

        user = mongo.db.users.find_one(
            {"basic_info.userID": userID},
            {"_id": 0}
        )

        if not user:
            return jsonify({"error": "Utilisateur introuvable"}), 404

        basic_info = user.get("basic_info", {}) or {}
        profil = user.get("profil", {}) or {}

        profile = {
            "userID": basic_info.get("userID", userID),
            "nom": basic_info.get("nom", ""),
            "prenom": basic_info.get("prenom", ""),
            "role": basic_info.get("role", ""),
            "email": basic_info.get("email", ""),
            "jobRole": profil.get("jobRole", basic_info.get("role", "")),
            "qualifications": profil.get("qualifications", []),
            "responsibilities": profil.get("keyResponsibilities", []),

            "user_score": user.get("user_score", 0),
            "vulnerability_score": user.get("vulnerability_score", 0),
            "objectifAtteint": user.get("objectifAtteint", False),

            "lastEvaluationDate": user.get("lastEvaluationDate"),
            "nextEvaluationDate": user.get("nextEvaluationDate"),
            "lastTrainingDate": user.get("lastTrainingDate"),
            "nextTrainingDate": user.get("nextTrainingDate"),
        }

        quiz_history = list(
            mongo.db.quiz_history.find(
                {"userID": userID},
                {
                    "_id": 1,
                    "date": 1,
                    "vulnerability_score": 1,
                    "risk_score": 1,
                    "risk_norm_pct": 1,
                    "riskNormPct": 1,
                    "riskScore": 1,
                    "normalized_risk_score": 1,
                    "risk_level": 1,
                    "quiz_type": 1,
                    "user_score": 1,
                    "total_questions": 1,
                    "objectifAtteint": 1,
                    "required_scores": 1,
                    "user_scores_per_thread": 1,
                    "top_threat": 1
                }
            )
        )

        if quiz_history:
            quiz_history.sort(
                key=lambda x: _to_ts_safe(x.get("date")),
                reverse=True
            )

            last_quiz = quiz_history[0]

            normalized = _pick_risk_value(
                last_quiz.get("risk_norm_pct"),
                last_quiz.get("normalized_risk_score"),
                last_quiz.get("riskNormPct"),
                last_quiz.get("riskScore"),
                last_quiz.get("risk_score")
            )

            profile["lastQuizType"] = last_quiz.get("quiz_type")
            profile["lastQuizDate"] = last_quiz.get("date")
            profile["risk_score"] = last_quiz.get("risk_score", profile.get("risk_score", 0))
            profile["vulnerability_score"] = last_quiz.get(
                "vulnerability_score",
                profile.get("vulnerability_score", 0)
            )
            profile["normalized_risk_score"] = normalized
            profile["risk_norm_pct"] = normalized
            profile["riskNormPct"] = normalized
            profile["riskScore"] = normalized
            profile["lastUserScore"] = last_quiz.get("user_score")
            profile["lastTotalQuestions"] = last_quiz.get("total_questions")
            profile["objectifAtteint"] = last_quiz.get(
                "objectifAtteint",
                profile["objectifAtteint"]
            )

        # Indique si l'utilisateur doit repasser une formation/test
        threshold = user.get("finalThresholdPct") or user.get("policyThresholdPct") or 0
        current_normalized = profile.get("normalized_risk_score") or profile.get("riskNormPct") or 0
        must_retake = (not profile.get("objectifAtteint", False)) or (
            threshold and current_normalized > threshold
        )
        profile["mustRetakeTraining"] = bool(must_retake)

        profile["lastEvaluationDate"] = _serialize_date(profile.get("lastEvaluationDate"))
        profile["nextEvaluationDate"] = _serialize_date(profile.get("nextEvaluationDate"))
        profile["lastTrainingDate"] = _serialize_date(profile.get("lastTrainingDate"))
        profile["nextTrainingDate"] = _serialize_date(profile.get("nextTrainingDate"))
        profile["lastQuizDate"] = _serialize_date(profile.get("lastQuizDate"))

        for q in quiz_history:
            q["date"] = _serialize_date(q.get("date"))

            if q.get("_id") is not None:
                q["id"] = str(q["_id"])

            normalized = _pick_risk_value(
                q.get("risk_norm_pct"),
                q.get("normalized_risk_score"),
                q.get("riskNormPct"),
                q.get("riskScore"),
                q.get("risk_score")
            )

            q["normalized_risk_score"] = normalized
            q["risk_norm_pct"] = normalized
            q["riskNormPct"] = normalized
            q["riskScore"] = normalized

        last_training = user.get("lastTrainingContent", "")

        profile_risks_doc = mongo.db.profile_risks.find_one({"userID": userID}) or {}
        mitre_exposure = {
            "globalRisk": profile_risks_doc.get("globalRisk"),
            "globalRiskLevel": profile_risks_doc.get("globalRiskLevel"),
            "assetCount": profile_risks_doc.get("assetCount", 0),
            "assets": profile_risks_doc.get("assets", [])
        }

        training_history = list(
            mongo.db.trainings.find(
                {"userID": userID},
                {
                    "_id": 1,
                    "date": 1,
                    "quiz_type": 1,
                    "content": 1,
                    "quality_metrics": 1,
                    "learning_summary": 1,
                    "training_blueprint": 1,
                },
            ).sort("date", -1).limit(20)
        )

        last_training_meta = None
        for t in training_history:
            t["date"] = _serialize_date(t.get("date"))
            t["training_id"] = str(t.pop("_id", ""))
        if training_history:
            tr0 = training_history[0]
            last_training_meta = {
                "training_id": tr0.get("training_id"),
                "quiz_type": tr0.get("quiz_type"),
                "date": tr0.get("date"),
                "quality_metrics": tr0.get("quality_metrics"),
                "learning_summary": tr0.get("learning_summary"),
                "training_blueprint": tr0.get("training_blueprint"),
            }

        return jsonify({
            "profile": profile,
            "quiz_history": quiz_history,
            "lastTrainingContent": last_training,
            "lastTrainingMeta": last_training_meta,
            "mitre_exposure": mitre_exposure,
            "training_history": training_history
        }), 200

    except Exception as e:
        print("Erreur /api/user_with_history:", userID, "->", repr(e))
        traceback.print_exc()
        return json_api_error("Erreur interne lors de la récupération du profil.", 500, e)

# === Sauvegarder un résultat de quiz
@app.route("/api/save_quiz_result", methods=["POST"])
@require_jwt()
def save_quiz_result():
    try:
        data = request.get_json(silent=True) or {}

        user_id = data.get("userID")
        result = data.get("result", {}) or {}
        training = data.get("training", "") or ""
        now = datetime.now(timezone.utc)
        quiz_type = data.get("type", "pre")

        if not user_id or not isinstance(result, dict) or not result:
            return jsonify({"error": "Données manquantes"}), 400

        denied = check_self_or_admin(str(user_id))
        if denied:
            return denied

        # date sûre
        quiz_date = data.get("date")
        if not quiz_date:
            quiz_date = now.isoformat()

        user_score = result.get("user_score")
        total_questions = result.get("total_questions")
        if user_score is None and isinstance(result.get("resultat"), dict):
            user_score = result["resultat"].get("user_score")
        if total_questions is None and isinstance(result.get("resultat"), dict):
            total_questions = result["resultat"].get("total_questions")

        quiz_data = {
            "userID": user_id,
            "quiz_type": quiz_type,
            "date": quiz_date,
            "user_score": user_score,
            "total_questions": total_questions,
            "risk_norm_pct": result.get("risk_norm_pct"),
            "risk_level": result.get("risk_level"),
            "vulnerability_score": result.get("vulnerability_score"),
            "V_norm": result.get("V_norm"),
            "global_risk_sum_local": result.get("global_risk_sum_local"),
            "policy_threshold_pct": result.get("policy_threshold_pct"),
            "learned_threshold_pct": result.get("learned_threshold_pct"),
            "final_threshold_pct": result.get("final_threshold_pct"),
            "objectifAtteint": result.get("objectifAtteint"),
            "objectifAtteint_learned": result.get("objectifAtteint_learned"),
            "objectifAtteint_policy": result.get("objectifAtteint_policy"),
            "top_threat": result.get("top_threat"),
            "required_scores": result.get("required_scores", []),
            "user_scores_per_technique": result.get("user_scores_per_technique", []),
            "answers": result.get("answers", []),
        }

        if training:
            quiz_data["training"] = training

        # évite les doublons si /evaluate a déjà sauvegardé quiz_history
        existing = mongo.db.quiz_history.find_one({
            "userID": user_id,
            "quiz_type": quiz_type,
            "date": quiz_date
        })

        # Évite un doublon juste après /evaluate : même quiz, date client ≠ date serveur,
        # ce qui faisait une 2e entrée parfois sans scores cohérents et cassait vulnerability_score().
        if not existing:
            latest = mongo.db.quiz_history.find_one(
                {"userID": user_id, "quiz_type": quiz_type},
                sort=[("date", -1)],
            )
            latest_ok = (
                latest
                and latest.get("user_score") is not None
                and int(latest.get("total_questions") or 0) > 0
            )
            if latest_ok:
                if training:
                    mongo.db.quiz_history.update_one(
                        {"_id": latest["_id"]},
                        {"$set": {"training": training}},
                    )
            else:
                mongo.db.quiz_history.insert_one(quiz_data)

        user_update_fields = {
            "lastScore": user_score,
            "riskScore": result.get("global_risk_sum_local"),
            "riskNormPct": result.get("risk_norm_pct"),
            "riskLevel": result.get("risk_level"),
            "objectifAtteint": result.get("objectifAtteint"),
            "lastEvaluationDate": now,
            "nextEvaluationDate": now + timedelta(days=15),
            "totalQuestions": total_questions,
            "policyThresholdPct": result.get("policy_threshold_pct"),
            "learnedThresholdPct": result.get("learned_threshold_pct"),
            "finalThresholdPct": result.get("final_threshold_pct"),
        }

        if quiz_type == "pre":
            user_update_fields["lastTrainingDate"] = now
        elif quiz_type == "post":
            user_update_fields["nextTrainingDate"] = now + timedelta(days=15)

        if training:
            user_update_fields["lastTrainingContent"] = training

        if result.get("top_threat"):
            user_update_fields["topThreat"] = result.get("top_threat")

        mongo.db.users.update_one(
            {"basic_info.userID": user_id},
            {"$set": user_update_fields}
        )

        return jsonify({
            "message": "Résultat du quiz enregistré et profil mis à jour avec succès."
        }), 201

    except Exception as e:
        return json_api_error("Erreur lors de l'enregistrement du résultat du quiz.", 500, e)

# === Mettre à jour le profil d’un utilisateur
@app.route('/api/update_profile', methods=['POST'])
@require_jwt()
def update_profile():
    data = request.json or {}
    userID = data.get("userID")

    if not userID:
        return jsonify({"error": "userID manquant"}), 400

    denied = check_self_or_admin(str(userID))
    if denied:
        return denied

    # Préparation des champs à modifier
    set_fields = {}
    if data.get("nom"):
        set_fields["basic_info.nom"] = data["nom"]
    if data.get("prenom"):
        set_fields["basic_info.prenom"] = data["prenom"]

    if not set_fields:
        return jsonify({"error": "Aucune donnée à mettre à jour."}), 400

    result = mongo.db.users.update_one(
        {"basic_info.userID": userID},
        {"$set": set_fields}
    )

    if result.matched_count == 0:
        return jsonify({"error": "Utilisateur non trouvé."}), 404

    return jsonify({"message": "Profil mis à jour avec succès."})

# === Login
@app.route("/login", methods=["POST", "OPTIONS"])
@limiter.limit(
    os.environ.get("RATELIMIT_LOGIN") or "15 per minute",
    exempt_when=lambda: request.method != "POST",
)
def login():
    if request.method == "OPTIONS":
        return "", 204
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Champs requis"}), 400

    # Recherche dans le champ imbriqué "basic_info.email"
    user = mongo.db.users.find_one({"basic_info.email": email})

    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    basic = user.get("basic_info", {})
    hashed_pw = basic.get("password")

    if not hashed_pw:
        return jsonify({"error": "Mot de passe non défini"}), 500

    if bcrypt.checkpw(password.encode("utf-8"), hashed_pw.encode("utf-8")):
        try:
            tv = int(user.get("jwt_token_version") or 0)
            access_token = create_access_token(
                str(basic.get("userID") or ""),
                str(basic.get("role") or ""),
                token_version=tv,
            )
        except RuntimeError as e:
            return json_api_error(
                "Configuration serveur incorrecte (authentification).",
                500,
                e,
            )
        body = {
            "userID": basic.get("userID"),
            "role": basic.get("role"),
            "nom": basic.get("nom"),
            "prenom": basic.get("prenom"),
        }
        if os.environ.get("JWT_RETURN_BODY_TOKEN", "false").lower() in ("1", "true", "yes"):
            body["access_token"] = access_token
        resp = make_response(jsonify(body), 200)
        if os.environ.get("USE_JWT_COOKIE", "true").lower() in ("1", "true", "yes"):
            cn = os.environ.get("JWT_COOKIE_NAME", "access_token")
            secure = os.environ.get("COOKIE_SECURE", "").lower() in ("1", "true", "yes")
            samesite = os.environ.get("COOKIE_SAMESITE", "Lax") or "Lax"
            resp.set_cookie(
                cn,
                access_token,
                httponly=True,
                secure=secure,
                samesite=samesite,
                max_age=int(JWT_EXPIRE_HOURS) * 3600,
                path="/",
            )
        return resp
    else:
        return jsonify({"error": "Mot de passe incorrect"}), 401


@app.route("/api/change-password", methods=["POST", "OPTIONS"])
@require_jwt()
def change_password():
    """Changement de mot de passe connecté (invalide les JWT + cookie)."""
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json(silent=True) or {}
    old_pw = (data.get("old_password") or data.get("current_password") or "").strip()
    new_pw = (data.get("new_password") or "").strip()
    if not old_pw or not new_pw:
        return jsonify({"error": "Mot de passe actuel et nouveau requis."}), 400
    err = validate_new_password(new_pw)
    if err:
        return jsonify({"error": err}), 400

    user = mongo.db.users.find_one({"basic_info.userID": g.user_id})
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    basic = user.get("basic_info", {}) or {}
    hashed_pw = basic.get("password")
    if not hashed_pw:
        return jsonify({"error": "Mot de passe non défini"}), 500
    if not bcrypt.checkpw(old_pw.encode("utf-8"), hashed_pw.encode("utf-8")):
        return jsonify({"error": "Mot de passe actuel incorrect"}), 401

    new_hashed = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    mongo.db.users.update_one(
        {"basic_info.userID": g.user_id},
        {"$set": {"basic_info.password": new_hashed}, "$inc": {"jwt_token_version": 1}},
    )
    resp = make_response(
        jsonify(
            {
                "message": "Mot de passe modifié. Reconnectez-vous.",
                "relogin": True,
            }
        ),
        200,
    )
    if os.environ.get("USE_JWT_COOKIE", "true").lower() in ("1", "true", "yes"):
        resp.delete_cookie(os.environ.get("JWT_COOKIE_NAME", "access_token"), path="/")
    return resp


@app.route("/api/logout", methods=["POST", "OPTIONS"])
@require_jwt()
def api_logout():
    """Invalide les JWT existants (incrémente jwt_token_version)."""
    if request.method == "OPTIONS":
        return "", 204
    mongo.db.users.update_one(
        {"basic_info.userID": g.user_id},
        {"$inc": {"jwt_token_version": 1}},
    )
    resp = make_response(jsonify({"message": "Déconnecté"}), 200)
    if os.environ.get("USE_JWT_COOKIE", "true").lower() in ("1", "true", "yes"):
        resp.delete_cookie(os.environ.get("JWT_COOKIE_NAME", "access_token"), path="/")
    return resp


# === Endpoint pour générer un token de réinitialisation
RESET_REQUEST_MESSAGE = (
    "Si un compte existe pour cette adresse, un e-mail de réinitialisation a été envoyé."
)


@app.route("/api/contact", methods=["GET", "POST", "OPTIONS"])
@limiter.limit(
    os.environ.get("RATELIMIT_CONTACT") or "5 per minute",
    exempt_when=lambda: request.method != "POST",
)
def api_contact():
    """Formulaire public : envoie un e-mail via SMTP (même config que la réinitialisation de mot de passe)."""
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "GET":
        return jsonify(
            {
                "message": "Endpoint actif. Envoyez un POST JSON : {nom, email, message}.",
                "methods": ["POST", "OPTIONS"],
            }
        ), 200
    data = request.get_json(silent=True) or {}
    nom = (data.get("nom") or "").strip()
    email = (data.get("email") or "").strip()
    message = (data.get("message") or "").strip()
    if not nom or len(nom) > 200:
        return jsonify({"error": "Nom invalide."}), 400
    if not email or "@" not in email or len(email) > 254:
        return jsonify({"error": "Adresse e-mail invalide."}), 400
    if not message or len(message) > 10000:
        return jsonify({"error": "Message invalide ou trop long (max. 10 000 caractères)."}), 400
    try:
        send_contact_form_email(nom=nom, from_email=email, body=message)
    except RuntimeError as e:
        app.logger.warning("Contact : %s", e)
        return jsonify(
            {"error": "L'envoi d'e-mails n'est pas configuré sur le serveur (SMTP). Vérifiez la configuration."}
        ), 503
    except Exception as e:
        if isinstance(e, smtplib.SMTPAuthenticationError):
            app.logger.error(
                "SMTP authentification refusée (Gmail : validation en 2 étapes + mot de passe d'application dans SMTP_PASSWORD ; "
                "SMTP_USER = adresse Gmail complète ; sans espaces dans le mot de passe). Détail : %s",
                e,
            )
            return jsonify(
                {
                    "error": "Le service d'envoi d'e-mails est indisponible (identifiants SMTP incorrects côté serveur). "
                    "Réessayez plus tard ou contactez l'administrateur."
                }
            ), 503
        app.logger.exception("Contact SMTP : %s", e)
        return jsonify({"error": "Impossible d'envoyer le message pour le moment. Réessayez plus tard."}), 500
    return jsonify({"message": "Message envoyé."}), 200


@app.route('/request-reset', methods=['POST'])
@limiter.limit(
    os.environ.get("RATELIMIT_REQUEST_RESET") or "5 per minute",
    exempt_when=lambda: request.method != "POST",
)
def request_password_reset():
    data = request.json or {}
    email = (data.get('email') or "").strip()

    if not email:
        return jsonify({"error": "Email manquant."}), 400

    user = mongo.db.users.find_one({"basic_info.email": email})
    if user:
        token = str(uuid.uuid4())
        expiration = datetime.now(timezone.utc) + timedelta(hours=24)

        mongo.db.password_resets.insert_one({
            "userID": user['basic_info']['userID'],
            "email": user['basic_info']['email'],
            "token": token,
            "expires_at": expiration
        })

        reset_link = f"{CYBERFORM_APP_URL.rstrip('/')}/reset-password?token={token}"

        try:
            send_reset_email(user['basic_info']['email'], reset_link)
        except Exception as e:
            print(f"[RESET PASSWORD] Erreur lors de l'envoi de l'email : {e}")

    return jsonify({"message": RESET_REQUEST_MESSAGE}), 200

# === Endpoint pour réinitialiser le mot de passe
@app.route('/reset-password', methods=['POST'])
@limiter.limit(
    os.environ.get("RATELIMIT_RESET_PASSWORD") or "10 per minute",
    exempt_when=lambda: request.method != "POST",
)
def reset_password():
    data = request.json or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("new_password")

    # 1) Validation 
    if not token:
        return jsonify({"error": "Token manquant."}), 400
    if not new_password:
        return jsonify({"error": "Nouveau mot de passe requis."}), 400
    err = validate_new_password(str(new_password))
    if err:
        return jsonify({"error": err}), 400

    # 2) Recherche du token
    entry = mongo.db.password_resets.find_one({"token": token})
    if not entry:
        return jsonify({"error": "Token invalide."}), 400

    # 3) Vérification d’expiration
    if datetime.now(timezone.utc) > entry["expires_at"]:
        return jsonify({"error": "Token expiré."}), 400

    # 4) Hash du mot de passe
    hashed_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode()

    # 5) Mise à jour dans users (+ invalider les JWT existants)
    mongo.db.users.update_one(
        {"basic_info.userID": entry["userID"]},
        {
            "$set": {"basic_info.password": hashed_pw},
            "$inc": {"jwt_token_version": 1},
        },
    )

    # 6) Suppression du token
    mongo.db.password_resets.delete_one({"_id": entry["_id"]})

    return jsonify({"message": "Mot de passe réinitialisé avec succès."}), 200

# === statistics
@app.route('/api/statistics', methods=['GET'])
@require_jwt(require_admin=True)
def get_statistics():
    try:
        # On calcule les statistiques uniquement sur les utilisateurs non-admin
        users = list(mongo.db.users.find({"basic_info.role": {"$ne": "admin"}}))

        if not users:
            return jsonify({
                "risk_moyen": 0.0,
                "nbr_utilisateurs_a_risque": 0,
                "pourcentage_utilisateurs_a_risque": 0.0,
                "pourcentage_objectifs_atteints": 0.0,
                "formations_planifiees": 0,
                "pourcentage_formations_planifiees": 0.0,
            }), 200

        total_users = len(users)

        def _num(v, default=None):
            try:
                if v in (None, "", "null"):
                    return default
                return float(v)
            except (TypeError, ValueError):
                return default

        def _pick_positive(*values, default=0.0):
            for v in values:
                n = _num(v, None)
                if n is not None and n > 0:
                    return n
            return default

        # Seuil de risque en pourcentage (aligné paramètres organisation / admin)
        org = load_organization_settings()
        seuil_risque = float(org["policy_threshold_pct"])
        # Valeur de risque « effective » pour la moyenne KPI quand l’objectif test n’est pas atteint
        # (pour que la jauge « Risque global » passe en orange/rouge comme le tableau)
        risque_effectif_si_objectif_non = 71.0

        risk_values_kpi = []  # moyenne affichée : objectif non → min. 71 % pour la couleur
        flags_a_risque = []
        flags_objectif_ok = []

        for u in users:
            user_id = (u.get("basic_info", {}) or {}).get("userID")

            last_quiz = {}
            if user_id:
                last_quiz = mongo.db.quiz_history.find_one(
                    {"userID": user_id},
                    sort=[("date", -1)]
                ) or {}

            risk_norm = _pick_positive(
                u.get("riskNormPct"),
                u.get("risk_norm_pct"),
                u.get("normalized_risk_score"),
                last_quiz.get("risk_norm_pct"),
                last_quiz.get("normalized_risk_score"),
                last_quiz.get("riskNormPct"),
                default=0.0
            )

            if last_quiz and last_quiz.get("objectifAtteint") is not None:
                objectif_ok = bool(last_quiz.get("objectifAtteint"))
            else:
                objectif_ok = bool(u.get("objectifAtteint", False))

            # Même règle que l’admin : sans objectif au test → compte comme à risque même si % bas
            est_a_risque = (risk_norm > seuil_risque) or (not objectif_ok)
            flags_a_risque.append(est_a_risque)
            flags_objectif_ok.append(objectif_ok)

            eff = max(risk_norm, risque_effectif_si_objectif_non) if not objectif_ok else risk_norm
            risk_values_kpi.append(eff)

        risk_moyen = sum(risk_values_kpi) / total_users if total_users > 0 else 0.0

        nb_a_risque = sum(1 for x in flags_a_risque if x)
        pct_a_risque = (nb_a_risque / total_users) * 100.0 if total_users > 0 else 0.0

        nb_objectifs_atteints = sum(1 for x in flags_objectif_ok if x)
        pct_objectifs_atteints = (nb_objectifs_atteints / total_users) * 100.0 if total_users > 0 else 0.0

        now_stats = datetime.now(timezone.utc)
        formations_planifiees = sum(
            1 for u in users if _user_has_upcoming_training(u, now_stats)
        )
        pct_formations_planifiees = (formations_planifiees / total_users) * 100.0 if total_users > 0 else 0.0

        stats = {
            "risk_moyen": round(risk_moyen, 1),
            "nbr_utilisateurs_a_risque": nb_a_risque,
            "pourcentage_utilisateurs_a_risque": round(pct_a_risque, 1),
            "pourcentage_objectifs_atteints": round(pct_objectifs_atteints, 1),
            "formations_planifiees": formations_planifiees,
            "pourcentage_formations_planifiees": round(pct_formations_planifiees, 1)
        }

        return jsonify(stats), 200

    except Exception as e:
        print("Erreur stats :", e)
        return json_api_error("Erreur lors du calcul des statistiques.", 500, e)


@app.route('/api/send_evaluation_reminders', methods=['POST'])
@require_jwt(require_admin=True)
def send_evaluation_reminders():
    """
    Envoie des emails de rappel pour les évaluations à venir.

    - Cible les utilisateurs non-admin dont nextEvaluationDate est dans
      les N prochains jours (par défaut 3, overridable via JSON {\"days\": N}).
    - Utilise la même configuration SMTP que `send_reset_email`.
    - Sûr à lancer depuis un cron ou manuellement.
    """
    try:
        payload = request.get_json(silent=True) or {}
        days = int(payload.get("days", 3))
    except Exception:
        days = 3

    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=days)

    # On ne prend que les utilisateurs non admin avec une prochaine évaluation planifiée
    users = mongo.db.users.find(
        {
            "basic_info.role": {"$ne": "admin"},
            "nextEvaluationDate": {"$ne": None}
        }
    )

    reminders = []

    for u in users:
        basic = u.get("basic_info", {}) or {}
        email = (basic.get("email") or "").strip()
        user_id = basic.get("userID")
        prenom = basic.get("prenom", "")
        nom = basic.get("nom", "")

        next_eval = u.get("nextEvaluationDate")
        if isinstance(next_eval, str):
            try:
                next_eval = datetime.fromisoformat(next_eval)
            except Exception:
                next_eval = None

        if not isinstance(next_eval, datetime):
            continue

        if next_eval.tzinfo is None:
            next_eval = next_eval.replace(tzinfo=timezone.utc)

        if not (now <= next_eval <= horizon):
            continue

        if not email:
            continue

        # Construire un lien vers l'application (simple redirection vers /login ou /user)
        app_url = os.environ.get("CYBERFORM_APP_URL", "http://localhost:4200")
        link = f"{app_url}/login"

        msg = EmailMessage()
        msg["Subject"] = "CyberForm – Rappel de votre prochaine évaluation"
        sender = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER") or "no-reply@cyberform.local"
        msg["From"] = sender
        msg["To"] = email

        date_str = next_eval.astimezone(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
        msg.set_content(
            f"""Bonjour {prenom} {nom},

        Votre prochaine évaluation de cybersécurité est planifiée le {date_str}.

        Pour consulter votre profil et réaliser le test au moment prévu, connectez-vous à CyberForm :
        {link}

        Si cette date ne vous convient plus, merci de contacter votre gestionnaire ou l'équipe sécurité.

        — CyberForm
        """,
            charset="utf-8",
        )

        try:
            host = os.environ.get("SMTP_HOST")
            port = int(os.environ.get("SMTP_PORT", "587"))
            user = os.environ.get("SMTP_USER")
            password = os.environ.get("SMTP_PASSWORD")

            if host and user and password:
                with smtplib.SMTP(host, port) as server:
                    server.starttls()
                    server.login(user, password)
                    server.send_message(msg)
                print(f"[EVAL REMINDER] Email envoyé à {email} pour nextEvaluationDate={next_eval}")
                reminders.append({"userID": user_id, "email": email, "status": "sent"})
            else:
                # Pas de SMTP → on log seulement
                print(f"[EVAL REMINDER][NO SMTP CONFIG] Prévu pour {user_id} ({email}) le {next_eval}")
                reminders.append({"userID": user_id, "email": email, "status": "logged"})
        except Exception as e:
            print(f"[EVAL REMINDER][ERROR] {user_id} {email} -> {e}")
            reminders.append({"userID": user_id, "email": email, "status": f"error: {e}"})

    return jsonify({
        "message": "Rappels d'évaluation traités.",
        "days_window": days,
        "reminders": reminders
    }), 200

@app.route('/api/statistics/mois', methods=['GET'])
@require_jwt(require_admin=True)
def get_mois_statistics():
    try:
        pipeline = [
            {
                "$match": {
                    "lastEvaluationDate": {"$ne": None},
                    "basic_info.role": {"$ne": "admin"}
                }
            },
            {
                "$project": {
                    "lastEvaluationDate": {
                        "$cond": {
                            "if": {"$eq": [{"$type": "$lastEvaluationDate"}, "date"]},
                            "then": "$lastEvaluationDate",
                            "else": {"$toDate": "$lastEvaluationDate"}
                        }
                    },
                    "riskNormPct": {
                        "$ifNull": [
                            "$riskNormPct",
                            {
                                "$ifNull": [
                                    "$risk_norm_pct",
                                    {
                                        "$ifNull": [
                                            "$normalized_risk_score",
                                            0
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    "vulnerability_score": {
                        "$ifNull": [
                            "$vulnerability_score",
                            0
                        ]
                    },
                    "objectifAtteint": 1,
                    "nextTrainingDate": 1
                }
            },
            {
                "$project": {
                    "year": {"$year": "$lastEvaluationDate"},
                    "month": {"$month": "$lastEvaluationDate"},
                    "riskNormPct": 1,
                    "vulnerability_score": 1,
                    "objectifAtteint": 1,
                    "nextTrainingDate": 1
                }
            },
            {
                "$group": {
                    "_id": {
                        "year": "$year",
                        "month": "$month"
                    },
                    "moyenne_risque": {"$avg": "$riskNormPct"},
                    "moyenne_vulnerabilite": {"$avg": "$vulnerability_score"},
                    "objectifs_atteints": {
                        "$sum": {
                            "$cond": ["$objectifAtteint", 1, 0]
                        }
                    },
                    "formations_planifiees": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$and": [
                                        {"$ne": ["$nextTrainingDate", None]},
                                        {"$ne": ["$nextTrainingDate", ""]},
                                        {
                                            "$gt": [
                                                {
                                                    "$cond": {
                                                        "if": {"$eq": [{"$type": "$nextTrainingDate"}, "date"]},
                                                        "then": "$nextTrainingDate",
                                                        "else": {"$toDate": "$nextTrainingDate"}
                                                    }
                                                },
                                                "$$NOW"
                                            ]
                                        }
                                    ]
                                },
                                1,
                                0
                            ]
                        }
                    },
                    "nombre_utilisateurs": {"$sum": 1}
                }
            },
            {
                "$sort": SON([("_id.year", 1), ("_id.month", 1)])
            }
        ]

        stats = list(mongo.db.users.aggregate(pipeline))

        results = []
        for s in stats:
            year = s["_id"].get("year")
            month = s["_id"].get("month")

            if year is None or month is None:
                continue

            results.append({
                "mois": f"{month:02d}/{year}",
                "moyenne_risque": round(float(s.get("moyenne_risque", 0)), 2),
                "moyenne_vulnerabilite": round(float(s.get("moyenne_vulnerabilite", 0)), 2),
                "objectifs_atteints": int(s.get("objectifs_atteints", 0)),
                "formations_planifiees": int(s.get("formations_planifiees", 0)),
                "nombre_utilisateurs": int(s.get("nombre_utilisateurs", 0))
            })

        return jsonify(results), 200

    except Exception as e:
        print("Erreur /api/statistics/mois:", e)
        return json_api_error("Erreur lors du calcul des statistiques mensuelles.", 500, e)

@app.route('/api/quiz/<quiz_id>', methods=['GET'])
@require_jwt()
def quiz(quiz_id): 
    try:
        object_id = ObjectId(quiz_id)
    except errors.InvalidId:
        return jsonify({"error": "ID invalide"}), 400                                                                                                              
    
    quiz = mongo.db.quiz_history.find_one({"_id": object_id})
    if not quiz:
        return jsonify({"error": "Quiz non trouvé"}), 404

    owner = quiz.get("userID") or ""
    denied = check_self_or_admin(str(owner))
    if denied:
        return denied

    quiz["_id"] = str(quiz["_id"])
    return jsonify(quiz), 200

@app.route('/api/create_user', methods=['POST'])
@require_jwt(require_admin=True)
def create_user():
    data = request.json or {}

    required_fields = ["userID", "prenom", "nom", "email", "password", "role"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Champs requis manquants"}), 400

    # Vérifier si userID existe
    if mongo.db.users.find_one({"basic_info.userID": data["userID"]}):
        return jsonify({"error": "Cet identifiant utilisateur existe déjà"}), 400

    err = validate_new_password(str(data.get("password") or ""))
    if err:
        return jsonify({"error": err}), 400

    # Hashage du mot de passe
    hashed_password = bcrypt.hashpw(
        data["password"].encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    # Structure propre et adaptée
    user_data = {
        "basic_info": {
            "userID": data["userID"],
            "prenom": data["prenom"],
            "nom": data["nom"],
            "email": data["email"],
            "role": data["role"],
            "password": hashed_password
        },

        "profil": {
            "jobRole": data.get("jobRole", ""),
            "qualifications": data.get("qualifications", []),
            "keyResponsibilities": data.get("keyResponsibilities", [])
        },

        "user_score": 0,
        "risk_score": 0,
        "vulnerability_score": 0,
        "objectifAtteint": False,

        # === Dates ===
        "lastEvaluationDate": None,
        "nextEvaluationDate": None,
        "lastTrainingDate": None,
        "nextTrainingDate": None,
        "lastTrainingContent": "",
        "jwt_token_version": 0,
    }

    mongo.db.users.insert_one(user_data)
    return jsonify({"message": "Utilisateur créé avec succès"}), 201

@app.route('/generate_profile_risk', methods=['POST', 'OPTIONS'])
@require_jwt()
def api_generate_profile_risk():
    if request.method == 'OPTIONS':
        return ('', 200)

    data = request.get_json() or {}
    user_id = (
        data.get("userID")
        or data.get("userId")
        or data.get("user_id")
    )

    if not user_id:
        return jsonify({"error": "userID manquant dans le corps de la requête"}), 400

    denied = check_self_or_admin(str(user_id))
    if denied:
        return denied

    print(f"[generate_profile_risk] userID reçu : {user_id}")

    try:
        max_repair = data.get("maxProfileRepairAttempts")
        if max_repair is None:
            max_repair = data.get("max_profile_repair_attempts")
        if max_repair is None:
            max_repair = 1
        try:
            max_repair = int(max_repair)
        except (TypeError, ValueError):
            max_repair = 1
        max_repair = max(0, min(3, max_repair))

        result = generate_profile_risk(user_id, max_profile_repair_attempts=max_repair)
        result = sanitize_for_json_bson(result)

        mongo.db.profile_risks.update_one(
            {"userID": user_id},
            {"$set": result},
            upsert=True
        )
        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] /generate_profile_risk : {e}")
        traceback.print_exc()
        return json_api_error("Erreur lors de la génération du profil de risque.", 500, e)


@app.route("/api/profile_risk/<user_id>", methods=["GET", "OPTIONS"])
@require_jwt()
def api_profile_risk_cached(user_id):
    """
    Dernier profil de risque enregistré (sans régénération). Utile si POST /generate_profile_risk
    expire ou coupe la connexion (génération longue).
    """
    if request.method == "OPTIONS":
        return ("", 200)

    denied = check_self_or_admin(user_id)
    if denied:
        return denied

    doc = mongo.db.profile_risks.find_one({"userID": user_id}, {"_id": 0})
    if not doc:
        return jsonify({"error": "Aucun profil de risque enregistré pour cet utilisateur"}), 404
    if "has_quiz_evaluation" not in doc:
        try:
            doc["has_quiz_evaluation"] = (
                mongo.db.quiz_history.count_documents({"userID": user_id}) > 0
            )
        except Exception:
            doc["has_quiz_evaluation"] = False
    return jsonify(sanitize_for_json_bson(doc)), 200


@app.route("/api/profile_quality/<user_id>", methods=["GET"])
@require_jwt()
def api_profile_quality(user_id):
    """
    Métriques et validations du dernier profil de risque stocké (collection profile_risks).
    """
    denied = check_self_or_admin(user_id)
    if denied:
        return denied

    doc = mongo.db.profile_risks.find_one({"userID": user_id}, {"_id": 0})
    if not doc:
        return jsonify({"error": "Profil de risque introuvable pour cet utilisateur"}), 404
    return jsonify(
        {
            "userID": user_id,
            "profile_valid": doc.get("profile_valid"),
            "profile_acceptable": doc.get("profile_acceptable"),
            "profile_quality_metrics": doc.get("profile_quality_metrics"),
            "validation_errors": doc.get("validation_errors", []),
            "validation_warnings": doc.get("validation_warnings", []),
            "repair_attempts": doc.get("repair_attempts", 0),
        }
    ), 200


@app.route("/api/user-scores", methods=["GET"])
@require_jwt(require_admin=True)
def get_user_scores():
    users = mongo.db.users.find(
        {"basic_info.role": {"$ne": "admin"}},
        {
            "basic_info.userID": 1,
            "basic_info.prenom": 1,
            "basic_info.nom": 1,
            "risk_score": 1,
            "riskNormPct": 1,
            "normalized_risk_score": 1,
            "risk_norm_pct": 1,
            "vulnerability_score": 1,
            "resultat": 1,
            "objectifAtteint": 1
        }
    )

    result = []

    for user in users:
        basic = user.get("basic_info", {}) or {}
        fullname = f"{basic.get('prenom', '')} {basic.get('nom', '')}".strip()

        resultat = user.get("resultat", {}) or {}
        if isinstance(resultat, list) and resultat:
            resultat = resultat[0]
        elif not isinstance(resultat, dict):
            resultat = {}

        risk_score = (
            user.get("riskNormPct")
            or user.get("normalized_risk_score")
            or user.get("risk_norm_pct")
            or user.get("risk_score")
            or 0
        )

        vulnerability_score = (
            user.get("vulnerability_score")
            or resultat.get("vulnerability_score")
            or resultat.get("score_vulnerabilite")
            or 0
        )

        result.append({
            "userID": basic.get("userID"),
            "fullname": fullname,
            "risk_score": float(risk_score),
            "vulnerability_score": float(vulnerability_score),
            "objectifAtteint": bool(user.get("objectifAtteint", False))
        })

    return jsonify(result)

@app.route("/api/users/<user_id>/score", methods=["PATCH"])
@require_jwt()
def update_score(user_id):
    denied = check_self_or_admin(user_id)
    if denied:
        return denied

    payload = request.get_json(silent=True) or {}
    score = payload.get("score", None)

    # 1) Validation / normalisation du score
    try:
        if score is None or str(score).strip() == "":
            raise ValueError("empty")
        score = float(str(score).replace(",", "."))  # accepte "12,5" ou "12.5"
    except Exception:
        return jsonify({"error": "score invalide"}), 400

    # 2) Filtre utilisateur (toujours via basic_info.userID)
    q = {"basic_info.userID": user_id}

    # 3) Mise à jour : on écrit directement user_score
    upd = {
        "$set": {
            "user_score": score,
            "lastEvaluationDate": datetime.now(timezone.utc)
        }
    }

    # 4) Update
    res = mongo.db.users.update_one(q, upd)
    if res.matched_count == 0:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    # 5) Relecture du doc mis à jour
    doc = mongo.db.users.find_one(q)
    if not doc:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    # 6) Sérialisation propre
    doc["_id"] = str(doc["_id"])
    led = doc.get("lastEvaluationDate")
    if hasattr(led, "isoformat"):
        doc["lastEvaluationDate"] = led.isoformat()

    return jsonify(doc), 200

@app.route('/api/savehistory_training', methods=['POST'])
@require_jwt()
def api_savehistory_training():
    try:
        data = request.get_json(force=True) or {}
        app.logger.info(f"Payload reçu /api/savehistory_training: {data}")

        userID    = data.get('userID')
        training  = data.get('training')
        date_str  = data.get('date')
        objective = bool(data.get('objective'))
        quizType  = data.get('quizType') or 'pre'

        if not userID or not training:
            return jsonify({
                "error": "userID ou training manquant",
                "received": data
            }), 400

        denied = check_self_or_admin(str(userID))
        if denied:
            return denied

        if date_str:
            try:
                date = datetime.fromisoformat(date_str)
            except Exception:
                date = datetime.now(timezone.utc)
        else:
            date = datetime.now(timezone.utc)

        history_doc = {
            "userID": userID,
            "training": training,
            "objective": objective,
            "quizType": quizType,
            "date": date.isoformat()
        }
        mongo.db.training_history.insert_one(history_doc)

        mongo.db.users.update_one(
            {"basic_info.userID": userID},
            {
                "$set": {
                    "lastTrainingContent": training,
                    "lastTrainingDate": date,
                    "nextTrainingDate": date + timedelta(days=15)
                }
            }
        )

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        app.logger.exception("Erreur /api/savehistory_training")
        return json_api_error("Erreur interne lors de l'enregistrement de la formation.", 500, e)

@app.route('/api/assets_catalog', methods=['GET'])
@require_jwt()
def api_assets_catalog():
    """
    GET /api/assets_catalog?ids=idps,siem
    Si aucun ids n'est fourni, retourne tout le catalogue.

    Enrichi avec les infos de menace venant de attack_graphs :
      - threat_score (T)
      - rationale
      - human_techniques / non_human_techniques (techniques MITRE)
    """

    print(">>> /api/assets_catalog appelé")

    try:

        ids_param = request.args.get('ids', '').strip()
        print("ids_param =", ids_param)

        query = {}

        if ids_param:
            ids_list = [i.strip() for i in ids_param.split(',') if i.strip()]
            query = {"_id": {"$in": ids_list}}

        print("query =", query)

        cursor = mongo.db.assets_catalog.find(query)
        assets = []

        for doc in cursor:

            asset_id = doc.get("_id")

            if not asset_id:
                continue

            print("doc trouvé:", doc)

            # 1. Chercher le graphe existant

            graph = (
                mongo.db.attack_graphs.find_one({"asset_id": asset_id})
                or mongo.db.attack_graphs.find_one({"_id": asset_id})
            )

            # 2. Si aucun graphe -> génération automatique

            if not graph:
                try:
                    graph = ensure_attack_graph_for_asset(doc)
                    print(f"[INFO] Graphe généré pour {asset_id}")
                except Exception as e:
                    print(f"[WARN] Impossible de générer le graphe pour {asset_id} :", e)
                    graph = None

            # 3. Construction de l'asset

            asset = {
                "_id": asset_id,
                "name": doc.get("name"),
                "description": doc.get("description"),
                "classification": doc.get("classification", {}),
                "C": doc.get("C"),
                "I": doc.get("I"),
                "D": doc.get("D"),
                "tags": doc.get("tags", [])
            }
            # 4. Ajout des infos de menace

            if graph:

                asset["threat_score"] = graph.get("threat_score")
                asset["rationale"] = graph.get("rationale", "")

                # human + hybrid (comportementales), puis non_human
                asset["human_techniques"] = _behavioral_techniques_from_attack_graph(graph)
                asset["non_human_techniques"] = _non_human_techniques_from_attack_graph(graph)

            else:

                asset["threat_score"] = None
                asset["rationale"] = ""
                asset["human_techniques"] = []
                asset["non_human_techniques"] = []

            assets.append(asset)

        print(">>> assets renvoyés:", assets)

        return jsonify(assets), 200

    except Exception as e:

        print("Erreur /api/assets_catalog:", e)

        return json_api_error("Erreur interne lors du chargement du catalogue d'actifs.", 500, e)

@app.route('/api/role_assets/<path:jobRole>', methods=['GET'])
@require_jwt()
def api_role_assets(jobRole):
    """
    Retourne la liste des asset_ids associées à un jobRole.
    """
    try:
        doc = mongo.db.role_assets.find_one({"jobRole": jobRole})

        if not doc:
            return jsonify({
                "jobRole": jobRole,
                "asset_ids": [],
                "message": "Aucun actif trouvé pour ce rôle"
            }), 404

        return jsonify({
            "jobRole": doc.get("jobRole"),
            "asset_ids": doc.get("asset_ids", [])
        }), 200

    except Exception as e:
        print("Erreur /api/role_assets:", e)
        return json_api_error("Erreur lors du chargement des actifs du rôle.", 500, e)

@app.route('/api/user/<user_id>/assets', methods=['GET'])
@require_jwt()
def api_user_assets(user_id):
    """
    GET /api/user/<user_id>/assets

    Retourne les actifs associés au user :
      - à partir de son profil.jobRole
      - via la collection role_assets (jobRole -> asset_ids)
      - enrichis avec classification CIA + threat_score + techniques MITRE
    """
    print(f">>> /api/user/{user_id}/assets appelé")

    try:
        denied = check_self_or_admin(user_id)
        if denied:
            return denied

        # 1) Récupérer l'utilisateur
        user = mongo.db.users.find_one({"basic_info.userID": user_id})
        if not user:
            print("[WARN] Utilisateur non trouvé")
            return jsonify({"error": "Utilisateur non trouvé"}), 404

        profil = user.get("profil", {}) or {}
        job_role = profil.get("jobRole")
        print("jobRole =", job_role)

        if not job_role:
            print("[WARN] Aucun jobRole pour cet utilisateur")
            return jsonify([]), 200

        # 2) Récupérer les assets liés à ce jobRole
        role_doc = mongo.db.role_assets.find_one({"jobRole": job_role})
        if not role_doc:
            print(f"[WARN] Aucun mapping role_assets pour jobRole={job_role}")
            return jsonify([]), 200

        asset_ids = role_doc.get("asset_ids", []) or []
        print("asset_ids pour ce user =", asset_ids)

        if not asset_ids:
            return jsonify([]), 200

        # 3) Reprendre la logique de /api/assets_catalog, mais filtrée
        query = {"_id": {"$in": asset_ids}}
        cursor = mongo.db.assets_catalog.find(query)

        assets = []

        for doc in cursor:
            asset_id = doc.get("_id")
            if not asset_id:
                continue

            print("doc trouvé pour user:", doc)

            # Chercher un graphe existant
            graph = mongo.db.attack_graphs.find_one({"asset_id": asset_id})

            # Si pas de graphe -> on tente d'en générer un
            if not graph:
                try:
                    graph = ensure_attack_graph_for_asset(doc)
                    print(f"[INFO] Graphe généré pour {asset_id}")
                except Exception as e:
                    print(f"[WARN] Impossible de générer le graphe pour {asset_id} :", e)
                    graph = None

            asset = {
                "_id": asset_id,
                "name": doc.get("name"),
                "description": doc.get("description"),
                "classification": doc.get("classification", {}),
                "C": doc.get("C"),
                "I": doc.get("I"),
                "D": doc.get("D"),
                "tags": doc.get("tags", []),
            }

            if graph:
                asset["threat_score"] = graph.get("threat_score")
                asset["rationale"] = graph.get("rationale", "")
                asset["human_techniques"] = _behavioral_techniques_from_attack_graph(graph)
                asset["non_human_techniques"] = _non_human_techniques_from_attack_graph(graph)
            else:
                asset["threat_score"] = None
                asset["rationale"] = ""
                asset["human_techniques"] = []
                asset["non_human_techniques"] = []

            assets.append(asset)

        print(">>> assets user renvoyés:", assets)
        return jsonify(assets), 200

    except Exception as e:
        print("Erreur /api/user/<id>/assets:", e)
        return json_api_error("Erreur lors du chargement des actifs utilisateur.", 500, e)

@app.route('/test-email', methods=['GET'])
@require_jwt(require_admin=True)
def test_email():
    if os.environ.get("ENABLE_TEST_EMAIL", "").lower() not in ("1", "true", "yes"):
        return jsonify({"error": "Endpoint désactivé"}), 404
    try:
        send_reset_email(
            os.environ.get("TEST_EMAIL_TO", "test@example.com"),
            f"{CYBERFORM_APP_URL.rstrip('/')}/reset-password/test-token"
        )
        return jsonify({"message": "Test email lancé"}), 200
    except Exception as e:
        return json_api_error("Échec du test d'envoi d'e-mail.", 500, e)
# === Démarrage
if __name__ == '__main__':
    _debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="localhost", port=5001, debug=_debug)
