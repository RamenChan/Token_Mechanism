'''(AED)--> This file defines the API routes for authentication in the SuperApp Identity Platform.
It includes endpoints for user registration, login, and a JWKS endpoint for public key discovery.
The authentication routes utilize the service layer for business logic and the rate limit guard to protect against abuse.
The `/auth/register` endpoint allows new users to register by providing a username and password. 
The `/auth/login` endpoint authenticates users and issues access and refresh tokens. The `/.well-known/jwks.json` 
endpoint exposes the JSON Web Key Set for clients to verify JWT signatures. The `/auth/refresh` endpoint allows 
clients to obtain new access tokens using a valid refresh token.

'''

from fastapi import APIRouter, Depends, HTTPException, Request
from app.core.rate_limit import rate_limit_guard
from app.auth.schemas import RegisterIn, LoginIn, TokenOut
from app.auth.service import register_user, login
from app.auth.schemas import RefreshIn
from app.auth.service import refresh as refresh_tokens
from app.tokens.jwt import jwks
from app.auth.deps import get_current_claims
from app.auth.deps import require_role

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


@router.post("/auth/refresh", response_model=TokenOut)
async def do_refresh(payload: RefreshIn, _: None = Depends(rate_limit_guard)):
    res, err = refresh_tokens(payload.refresh_token, payload.client_id)
    if err:
        raise HTTPException(status_code=401, detail=err)
    return {**res, "token_type": "Bearer"}


@router.get("/auth/me")
async def me(claims = Depends(get_current_claims)):
    # return minimal claims for the authenticated subject
    return {
        "sub": claims.sub,
        "cid": claims.cid,
        "scope": claims.scope,
        "roles": claims.roles,
    }



@router.get("/auth/admin")
async def admin_area(claims = Depends(require_role("admin"))):
    """Admin-only endpoint to verify role-based access control."""
    return {"ok": True, "sub": claims.sub}