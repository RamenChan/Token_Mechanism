'''(AED)--> This file implements the core authentication logic for the SuperApp Identity Platform.
It includes functions for user registration, login, and access token claim construction.
The `register_user` function allows new users to register by hashing their passwords and storing them in
an in-memory dictionary (for demo purposes). The `verify_user` function checks user credentials during login.
The `build_access_claims` function constructs the claims for the access token, which includes standard
JWT claims as well as custom claims specific to the application's needs. The `login` function orchestrates
the login process by verifying the user, creating session information, building claims, issuing an access token,
and minting a refresh token.
'''

import time, uuid
from typing import Dict
from passlib.context import CryptContext
from app.core.config import settings
from app.tokens.jwt import issue_access_token
from app.tokens.refresh_store import mint_refresh

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MVP: in-memory user store (demo). Prod'da DB olacak.
_USERS: Dict[str, str] = {}

def register_user(username: str, password: str):
    _USERS[username] = pwd.hash(password)

def verify_user(username: str, password: str) -> str | None:
    h = _USERS.get(username)
    if not h:
        return None
    if not pwd.verify(password, h):
        return None
    # sub için stabil id: MVP’de username; prod'da user_id
    return f"usr_{username}"

def build_access_claims(user_id: str, session_id: str, device_id: str, client_id: str, scope: str, acr: str = "1"):
    now = int(time.time())
    return {
        "iss": settings.JWT_ISSUER,
        "sub": user_id,
        "aud": ["identity-api"],  # Bu token'ın hedef kitlesi. Prod'da farklı servisler olabilir.
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_TTL_SECONDS,
        "jti": f"at_{uuid.uuid4().hex}",
        "scope": scope,
        "sid": session_id,
        "cid": client_id,
        "device_id": device_id,
        "acr": acr,
        "amr": ["pwd"],
        "roles": ["user"],
        "ver": 1,
    }

def login(username: str, password: str, device_id: str, client_id: str):
    user_id = verify_user(username, password)
    if not user_id:
        return None

    session_id = f"sid_{uuid.uuid4().hex}"
    scope = "profile:read wallet:read"  # MVP. sonra policy ile genişletiriz.

    claims = build_access_claims(user_id, session_id, device_id, client_id, scope, acr="1")
    access = issue_access_token(claims)
    refresh = mint_refresh(user_id, session_id, device_id)

    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": settings.ACCESS_TOKEN_TTL_SECONDS,
        "acr": claims["acr"],
    }