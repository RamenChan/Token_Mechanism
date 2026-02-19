'''(AED)--> This file implements a simple rate limiting mechanism using Redis for the SuperApp Identity Platform.
The `rate_limit_guard` function is designed to be used as a FastAPI dependency to protect
endpoints from excessive requests. It uses the client's IP address and the current time (in minutes) to create 
a unique key for counting requests. If the number of requests exceeds the configured limit within a minute, 
it raises an HTTP 429 Too Many Requests error.
'''

import time
import redis
from fastapi import Request, HTTPException
from app.core.config import settings

r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

def _key(req: Request) -> str:
    # gerçek hayatta: ip + cid + path bazlı daha iyi
    ip = req.client.host if req.client else "unknown"
    return f"rl:{ip}:{int(time.time() // 60)}"

async def rate_limit_guard(request: Request):
    key = _key(request)
    current = r.incr(key)
    if current == 1:
        r.expire(key, 70)
    if current > settings.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="rate_limited")