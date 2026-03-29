"""
JWT : authentification API après /login (Bearer token).
Variables : JWT_SECRET (obligatoire en production), JWT_EXPIRE_HOURS (défaut 24).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import g, jsonify, request

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

JWT_SECRET = (os.environ.get("JWT_SECRET") or "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))


def _ensure_secret() -> str:
    if JWT_SECRET:
        return JWT_SECRET
    raise RuntimeError(
        "JWT_SECRET n'est pas définie. Ajoutez-la dans .env (voir .env.example)."
    )


def create_access_token(user_id: str, role: str, token_version: int = 0) -> str:
    secret = _ensure_secret()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": str(role or ""),
        "tv": int(token_version),
        "exp": now + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": now,
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    secret = _ensure_secret()
    return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])


def _use_jwt_cookie() -> bool:
    return os.environ.get("USE_JWT_COOKIE", "true").lower() in ("1", "true", "yes")


def get_bearer_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        t = auth[7:].strip()
        if t:
            return t
    if _use_jwt_cookie():
        name = os.environ.get("JWT_COOKIE_NAME", "access_token")
        c = request.cookies.get(name)
        if c:
            return c.strip() or None
    return None


def require_jwt(require_admin: bool = False):
    """
    Vérifie Authorization: Bearer <JWT>.
    Remplit g.user_id et g.user_role.
    OPTIONS : laisse passer (souvent géré par CORS avant la vue).
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.method == "OPTIONS":
                return f(*args, **kwargs)
            token = get_bearer_token()
            if not token:
                return jsonify({"error": "Non authentifié"}), 401
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Session expirée"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token invalide"}), 401
            g.user_id = str(payload.get("sub") or "")
            g.user_role = str(payload.get("role") or "")
            if require_admin and g.user_role != "admin":
                return jsonify({"error": "Accès refusé"}), 403
            # Révocation : le compteur Mongo doit correspondre au claim « tv » du JWT
            from extensions import mongo

            doc = mongo.db.users.find_one(
                {"basic_info.userID": g.user_id},
                {"jwt_token_version": 1},
            )
            if not doc:
                return jsonify({"error": "Non authentifié"}), 401
            tv_claim = int(payload.get("tv", 0))
            current = int(doc.get("jwt_token_version") or 0)
            if tv_claim != current:
                return jsonify({"error": "Session expirée"}), 401
            return f(*args, **kwargs)

        return wrapped

    return decorator


def check_self_or_admin(target_user_id: str):
    """
    None si l'utilisateur JWT peut agir pour ce user_id (lui-même ou admin).
    Sinon retourne (jsonify(...), code) pour return direct.
    """
    if not target_user_id:
        return jsonify({"error": "Identifiant manquant"}), 400
    if getattr(g, "user_role", None) == "admin":
        return None
    if str(getattr(g, "user_id", "")) != str(target_user_id):
        return jsonify({"error": "Accès refusé"}), 403
    return None
