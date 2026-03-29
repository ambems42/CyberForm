# Triade CIA par technique 
# Utilisé pour écraser les valeurs génériques/forcées du GPT.

TECHNIQUE_CIA_DEFAULT = {
    # --- Phishing / ingénierie sociale ---
    "T1566": ["C"],           # Phishing
    "T1566.001": ["C"],       # Spearphishing Attachment
    "T1566.002": ["C"],       # Spearphishing Link
    "T1566.003": ["C"],       # Spearphishing via Service
    "T1566.004": ["C"],       # Spearphishing Voice
    # ID hérité / données anciennes : remplacé par T1566.002 dans ATT&CK Enterprise actuel
    "T1192": ["C"],           # (deprecated) Spearphishing Link → utiliser T1566.002
    "T1534": ["C"],           # Internal Spearphishing
    # --- Exécution / compte utilisateur ---
    "T1204": ["C", "I"],      # User Execution
    "T1078": ["C", "I", "D"], # Valid Accounts
    "T1098": ["C", "I"],      # Account Manipulation
    # --- Accès aux identifiants / données ---
    "T1110": ["C"],           # Brute Force (credentials)
    "T1056": ["C"],           # Input Capture (keylogging)
    "T1115": ["C"],           # Clipboard Data
    "T1113": ["C"],           # Screen Capture
    "T1552": ["C"],           # Unsecured Credentials
    "T1556": ["I"],           # Modify Authentication Process
}


def get_cia_for_technique(technique_id: str) -> list | None:
    """Retourne la triade CIA canonique pour une technique, ou None si non mappée."""
    if not technique_id:
        return None
    tid = (technique_id or "").strip().upper()
    base = tid.split(".")[0]
    return TECHNIQUE_CIA_DEFAULT.get(tid) or TECHNIQUE_CIA_DEFAULT.get(base)
