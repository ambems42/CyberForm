import re

# Noms de techniques alignés sur MITRE ATT&CK Enterprise (attack.mitre.org), libellés anglais officiels.
MITRE_NAMES = {
    # --- Phishing / exécution utilisateur (Initial Access, Execution) ---
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1566.004": "Spearphishing Voice",
    "T1204": "User Execution",
    "T1204.001": "Malicious Link",
    "T1204.002": "Malicious File",
    "T1204.003": "Malicious Image",
    "T1534": "Internal Spearphishing",
    # --- Accès / identités / credentials ---
    "T1078": "Valid Accounts",
    "T1056": "Input Capture",
    "T1552": "Unsecured Credentials",
    "T1203": "Exploitation for Client Execution",
    "T1550": "Use Alternate Authentication Material",
    "T1110": "Brute Force",
    "T1098": "Account Manipulation",
    # --- Exécution / post-exploitation ---
    "T1059": "Command and Scripting Interpreter",
    "T1070": "Indicator Removal on Host",
    "T1090": "Proxy",
    "T1210": "Exploitation of Remote Services",
    "T1115": "Clipboard Data",
    "T1113": "Screen Capture",
    "T1114": "Email Collection",
    "T1190": "Exploit Public-Facing Application",
    "T1560": "Archive Collected Data",
    "T1562": "Impair Defenses",
    "T1564": "Hide Artifacts",
    "T1568": "Dynamic Resolution",
    "T1556": "Modify Authentication Process",
    "T1583": "Acquire Infrastructure",
    "T1593": "Search Open Websites/Domains",
    "T1119": "Automated Collection",
    # --- Réseau / accès distant ---
    "T1040": "Network Sniffing",
    "T1046": "Network Service Discovery",
    "T1021": "Remote Services",
    "T1133": "External Remote Services",
}

# Motif strict MITRE Enterprise (T + 4–5 chiffres, sous-technique .xxx optionnelle)
MITRE_ID_PATTERN = re.compile(r"^T\d{4,5}(?:\.\d{3})?$", re.IGNORECASE)


def canonicalize_mitre_id(tid: str) -> tuple[str | None, bool, str | None]:
    """
    Valide un ID contre le motif MITRE et la base locale ``MITRE_NAMES``.

    Retourne ``(id_canonical, inferred_parent, original_id)`` :
    - ``inferred_parent`` True si une sous-technique absente de ``MITRE_NAMES`` est
      remappée vers la technique parente présente dans la base ;
    - ``original_id`` renseigné dans ce cas ;
    - ``(None, False, None)`` si rejet (format invalide ou technique inconnue).
    """
    if not tid or not isinstance(tid, str):
        return None, False, None
    t = tid.strip().upper()
    if not MITRE_ID_PATTERN.match(t):
        return None, False, None
    if t in MITRE_NAMES:
        return t, False, None
    base = t.split(".")[0]
    if "." in t and base in MITRE_NAMES:
        return base, True, t
    if base in MITRE_NAMES:
        return base, False, None
    return None, False, None


# --- Classification stricte (meilleure séparation human / hybrid / non_human) ---
# Human pur : tehniques purement humaines.
PURE_HUMAN_TECHNIQUE_BASES = {
    "T1566",
    "T1534",
    "T1204",
}

# Hybride : comptes valides, accès distant, identifiants — souvent automatisé OU piloté par humain.
HYBRID_TECHNIQUE_BASES = {
    "T1078",
    "T1021",
    "T1110",
    "T1133",
    "T1056",
    "T1552",
    "T1550",
    "T1098",
}

# Compat : ancien nom utilisé dans le code → techniques purement humaines
HUMAN_TECHNIQUES = PURE_HUMAN_TECHNIQUE_BASES

NON_HUMAN_TECHNIQUES = {
    "T1059",
    "T1070",
    "T1071.001",
    "T1090",
    "T1115",  # clipboard Data
    "T1113",  # screen capture
    "T1114",
    "T1190",
    "T1485",
    "T1203",
    "T1560",
    "T1562",
    "T1564",
    "T1568",
    "T1556",  # modify authentication process
    "T1583",
    "T1593",
    "T1119",
}


def mitre_classification(tid: str, name: str = "", desc: str = "") -> str:
    """
    Retourne 'human' | 'hybrid' | 'non_human' pour un ID MITRE (et optionnellement nom/description GPT).
    Les sous-techniques (Txxxx.xxx) suivent la base (ex. T1566.001 → human).
    """
    tid = (tid or "").strip().upper()
    if not tid:
        return "non_human"
    base = tid.split(".")[0]
    text = f"{name or ''} {desc or ''}".lower()

    if base in PURE_HUMAN_TECHNIQUE_BASES:
        return "human"
    if base in HYBRID_TECHNIQUE_BASES:
        return "hybrid"
    if base in NON_HUMAN_TECHNIQUES:
        return "non_human"

    # ID inconnu du registre : heuristique texte (sortie GPT)
    human_kw = (
        "phishing",
        "spearphishing",
        "social engineering",
        "user execution",
        "malicious link",
        "malicious file",
        "internal spearphishing",
        "open attachment",
        "click",
    )
    if any(k in text for k in human_kw):
        return "human"
    hybrid_kw = (
        "valid account",
        "credential",
        "password",
        "authentication",
        "brute force",
        "remote service",
        "vpn",
        "login",
        "session",
    )
    if any(k in text for k in hybrid_kw):
        return "hybrid"
    return "non_human"


# --- Évolution mémoire : score de « facteur humain » continu [0, 1] (voir MEMOIRE_AXES_AMELIORATION.md)
# 1.0 = interaction humaine dominante ; 0.0 = automatisé / technique pur
# Les IDs absents retombent sur une règle dérivée de HUMAN / NON_HUMAN .
MITRE_HUMAN_FACTOR = {
    "T1566": 1.0,
    "T1566.001": 1.0,
    "T1566.002": 1.0,
    "T1566.003": 1.0,
    "T1566.004": 1.0,
    "T1534": 1.0,
    "T1204": 0.95,
    "T1204.002": 0.95,
    "T1078": 0.55,
    "T1056": 0.5,
    "T1552": 0.45,
    "T1550": 0.5,
    "T1550.001": 0.5,
    "T1098": 0.42,
}

_HYBRID_FACTOR_DEFAULT = 0.48


def human_factor(tid: str) -> float:
    """
    Retourne un score dans [0, 1] pour le facteur humain d'une technique MITRE.
    À utiliser pour dépasser le binaire human/non_human (cf. mémoire).
    """
    if not tid:
        return 0.0
    t = str(tid).strip().upper()
    base = t.split(".")[0]
    if t in MITRE_HUMAN_FACTOR:
        return float(MITRE_HUMAN_FACTOR[t])
    if base in MITRE_HUMAN_FACTOR:
        return float(MITRE_HUMAN_FACTOR[base])
    cls = mitre_classification(t)
    if cls == "human":
        return 0.78
    if cls == "hybrid":
        return _HYBRID_FACTOR_DEFAULT
    if t in NON_HUMAN_TECHNIQUES or base in NON_HUMAN_TECHNIQUES:
        return 0.15
    return 0.35  # inconnu : légèrement sous hybride
