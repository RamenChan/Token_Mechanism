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
