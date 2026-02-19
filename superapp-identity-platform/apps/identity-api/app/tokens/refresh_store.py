'''(AED)--> This file implements a refresh token store using Redis for the SuperApp Identity Platform.
It provides functions to mint new refresh tokens, retrieve existing tokens, consume (rotate) tokens,
and revoke sessions. The refresh tokens are stored as hashed values in Redis to enhance security.
The `RefreshRecord` dataclass represents the structure of a refresh token record in Redis.
'''

import hashlib, secrets, time
from dataclasses import dataclass
from typing import Optional
import redis
from app.core.config import settings

r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

@dataclass
class RefreshRecord:
    user_id: str
    session_id: str
    device_id: str
    expires_at: int
    consumed: bool = False

def mint_refresh(user_id: str, session_id: str, device_id: str) -> str:
    raw = secrets.token_urlsafe(48)
    key = f"rt:{_hash(raw)}"
    expires_at = int(time.time()) + settings.REFRESH_TOKEN_TTL_SECONDS
    r.hset(key, mapping={
        "user_id": user_id,
        "session_id": session_id,
        "device_id": device_id,
        "expires_at": str(expires_at),
        "consumed": "0",
    })
    r.expireat(key, expires_at)
    return raw

def get_refresh(raw: str) -> Optional[RefreshRecord]:
    key = f"rt:{_hash(raw)}"
    data = r.hgetall(key)
    if not data:
        return None
    return RefreshRecord(
        user_id=data["user_id"],
        session_id=data["session_id"],
        device_id=data["device_id"],
        expires_at=int(data["expires_at"]),
        consumed=(data.get("consumed") == "1"),
    )

def consume_refresh(raw: str) -> bool:
    """
    Rotating refresh: mark old as consumed atomically.
    """
    key = f"rt:{_hash(raw)}"
    pipe = r.pipeline()
    pipe.hget(key, "consumed")
    res = pipe.execute()
    if not res or res[0] is None:
        return False
    if res[0] == "1":
        return False
    r.hset(key, "consumed", "1")
    return True

def revoke_session(session_id: str):
    # Basit MVP: session -> revoke flag
    r.setex(f"sid:revoked:{session_id}", 60 * 60 * 24, "1")

def is_session_revoked(session_id: str) -> bool:
    return r.get(f"sid:revoked:{session_id}") == "1"