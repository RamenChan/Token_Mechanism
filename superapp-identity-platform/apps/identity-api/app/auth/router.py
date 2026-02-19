'''(AED)--> This file defines the API routes for authentication in the SuperApp Identity Platform.
It includes endpoints for user registration, login, and a JWKS endpoint for public key discovery.
The authentication routes utilize the service layer for business logic and the rate limit guard to protect against abuse.
'''

from fastapi import APIRouter, Depends, HTTPException, Request
from app.core.rate_limit import rate_limit_guard
from app.auth.schemas import RegisterIn, LoginIn, TokenOut
from app.auth.service import register_user, login
from app.tokens.jwt import jwks

router = APIRouter(prefix="/v1")

@router.post("/auth/register")
async def register(payload: RegisterIn, _: None = Depends(rate_limit_guard)):
    register_user(payload.username, payload.password)
    return {"ok": True}

@router.post("/auth/login", response_model=TokenOut)
async def do_login(payload: LoginIn, _: None = Depends(rate_limit_guard)):
    res = login(payload.username, payload.password, payload.device_id, payload.client_id)
    if not res:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    return {
        **res,
        "token_type": "Bearer",
    }

@router.get("/.well-known/jwks.json")
async def well_known_jwks():
    return jwks()