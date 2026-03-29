"""Politique minimale pour les nouveaux mots de passe (hors login sur anciens comptes)."""

from __future__ import annotations

# Top listes de mots de passe faibles 
_WEAK = frozenset(
    {
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "password",
        "password123",
        "qwerty",
        "abc123",
        "111111",
        "123123",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "cyberform",
        "football",
        "iloveyou",
    }
)


def validate_new_password(pw: str) -> str | None:
    """
    Retourne un message d'erreur en français si le mot de passe est refusé, sinon None.
    """
    if not pw or not isinstance(pw, str):
        return "Mot de passe requis."
    if len(pw) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères."
    if pw.lower() in _WEAK:
        return "Ce mot de passe est trop courant ou trop faible. Choisissez-en un autre."
    if not re.search(r"[A-Z]", pw):
        return "Le mot de passe doit contenir au moins une majuscule."
    if not re.search(r"\d", pw):
        return "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]", pw):
        return "Le mot de passe doit contenir au moins un caractère spécial."

    return None
