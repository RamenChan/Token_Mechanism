from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.tokens import jwt as jwt_mod

bearer = HTTPBearer()


def get_current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials
    try:
        claims = jwt_mod.verify_access_token(token)
    except jwt_mod.TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token_expired")
    except jwt_mod.TokenInvalidAudienceError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid_audience")
    except jwt_mod.TokenInvalidSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_signature")
    except jwt_mod.TokenInvalidError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")

    return claims


def require_role(role: str):
    """Factory dependency that requires a specific role be present in token claims."""
    def _dep(claims = Depends(get_current_claims)):
        if role not in getattr(claims, "roles", []):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_role")
        return claims

    return _dep


def require_any_role(roles: list[str]):
    """Factory dependency that requires the claims to have any of the provided roles."""
    def _dep(claims = Depends(get_current_claims)):
        if not any(r in getattr(claims, "roles", []) for r in roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_role")
        return claims

    return _dep


def require_scope(scope: str):
    """Factory dependency that requires the given scope to be present in the space-separated `scope` claim."""
    def _dep(claims = Depends(get_current_claims)):
        scopes = getattr(claims, "scope", "")
        if scope not in scopes.split():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_scope")
        return claims

    return _dep
