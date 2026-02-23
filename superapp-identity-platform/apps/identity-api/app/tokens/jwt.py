'''
(AED)--> This file implements JWT token generation and JWKS endpoint for the SuperApp Identity Platform.
It uses RSA keys for signing and verifying tokens. The keys are generated and stored on disk if they don't already exist.
The `issue_access_token` function creates a JWT access token with the given claims, and the
`jwks` function returns the JSON Web Key Set containing the public key information for token verification.
'''

import time, json
from pathlib import Path
from typing import Any, Dict, Tuple, Optional
import jwt
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidSignatureError, InvalidTokenError, PyJWTError
from app.tokens.claims import AccessTokenClaims


# Custom exceptions for clearer error handling in verification
class TokenVerificationError(Exception):
    pass


class TokenExpiredError(TokenVerificationError):
    pass


class TokenInvalidAudienceError(TokenVerificationError):
    pass


class TokenInvalidSignatureError(TokenVerificationError):
    pass


class TokenInvalidError(TokenVerificationError):
    pass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from app.core.config import settings

KEY_DIR = Path(__file__).resolve().parent / "_keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE_KEY_PATH = KEY_DIR / "jwt_private.pem"  # legacy; not used for per-kid storage
PUBLIC_KEY_PATH  = KEY_DIR / "jwt_public.pem"
KID_PATH         = KEY_DIR / "kid.txt"

# simple in-memory cache for public keys by kid
_PUBLIC_KEY_CACHE: Dict[str, bytes] = {}

def _generate_keys() -> Tuple[bytes, bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kid = f"kid-{int(time.time())}"
    return private_pem, public_pem, kid

def ensure_keys():
    # Create an initial keypair if none exist
    if not KID_PATH.exists():
        priv, pub, kid = _generate_keys()
        # write per-kid files
        (KEY_DIR / f"jwt_private_{kid}.pem").write_bytes(priv)
        (KEY_DIR / f"jwt_public_{kid}.pem").write_bytes(pub)
        KID_PATH.write_text(kid)
        # also keep generic paths for compatibility
        PRIVATE_KEY_PATH.write_bytes(priv)
        PUBLIC_KEY_PATH.write_bytes(pub)
        _PUBLIC_KEY_CACHE[kid] = pub

def load_private_key() -> bytes:
    ensure_keys()
    # return current private key bytes for signing
    kid = load_kid()
    path = KEY_DIR / f"jwt_private_{kid}.pem"
    if path.exists():
        return path.read_bytes()
    # fallback to legacy path
    if PRIVATE_KEY_PATH.exists():
        return PRIVATE_KEY_PATH.read_bytes()
    # As a last resort, rotate to create a fresh keypair
    new_kid = rotate_keys()
    return (KEY_DIR / f"jwt_private_{new_kid}.pem").read_bytes()


def get_current_private_key_and_kid() -> Tuple[str, bytes]:
    """Return a tuple of (kid, private_key_bytes). If the per-kid private file is missing,
    rotate to a new keypair and use that as current.
    """
    ensure_keys()
    kid = load_kid()
    path = KEY_DIR / f"jwt_private_{kid}.pem"
    if path.exists():
        return kid, path.read_bytes()
    if PRIVATE_KEY_PATH.exists():
        return kid, PRIVATE_KEY_PATH.read_bytes()
    # missing files for current kid: create new pair
    new_kid = rotate_keys()
    return new_kid, (KEY_DIR / f"jwt_private_{new_kid}.pem").read_bytes()

def load_public_key() -> bytes:
    # return current public key bytes
    kid = load_kid()
    return load_public_key_for_kid(kid)


def load_public_key_for_kid(kid: str) -> bytes:
    ensure_keys()
    if kid in _PUBLIC_KEY_CACHE:
        return _PUBLIC_KEY_CACHE[kid]
    path = KEY_DIR / f"jwt_public_{kid}.pem"
    if not path.exists():
        raise FileNotFoundError(f"public key for kid {kid} not found")
    data = path.read_bytes()
    _PUBLIC_KEY_CACHE[kid] = data
    return data

def load_kid() -> str:
    ensure_keys()
    return KID_PATH.read_text().strip()


def rotate_keys() -> str:
    """Generate a new keypair and make it the current kid. Returns new kid."""
    priv, pub, kid = _generate_keys()
    (KEY_DIR / f"jwt_private_{kid}.pem").write_bytes(priv)
    (KEY_DIR / f"jwt_public_{kid}.pem").write_bytes(pub)
    # update current pointers
    KID_PATH.write_text(kid)
    PRIVATE_KEY_PATH.write_bytes(priv)
    PUBLIC_KEY_PATH.write_bytes(pub)
    _PUBLIC_KEY_CACHE[kid] = pub
    return kid

def issue_access_token(claims: Dict[str, Any]) -> str:
    kid, priv = get_current_private_key_and_kid()
    headers = {"kid": kid, "typ": "at+jwt"}
    token = jwt.encode(claims, priv, algorithm=settings.JWT_ALG, headers=headers)
    return token


def _get_kid_from_token(token: str) -> str:
    try:
        hdr = jwt.get_unverified_header(token)
    except PyJWTError as e:
        raise TokenInvalidError("cannot parse token headers") from e
    kid = hdr.get("kid")
    if not kid:
        raise TokenInvalidError("missing kid header")
    return kid


def verify_access_token(token: str, expected_audience: Optional[str] = "identity-api") -> AccessTokenClaims:
    """Verify JWT signature and return validated `AccessTokenClaims`.

    Raises one of the `TokenVerificationError` subclasses on failure.
    """
    # select public key by kid header
    kid = _get_kid_from_token(token)
    try:
        pub = load_public_key_for_kid(kid)
    except FileNotFoundError as e:
        raise TokenInvalidError("unknown kid") from e
    try:
        payload = jwt.decode(
            token,
            pub,
            algorithms=[settings.JWT_ALG],
            audience=expected_audience,
            options={"require": ["exp", "iat", "iss", "sub", "jti"]},
        )
    except ExpiredSignatureError as e:
        raise TokenExpiredError("token expired") from e
    except InvalidAudienceError as e:
        raise TokenInvalidAudienceError("invalid audience") from e
    except InvalidSignatureError as e:
        raise TokenInvalidSignatureError("invalid signature") from e
    except InvalidTokenError as e:
        raise TokenInvalidError("invalid token") from e

    # validate payload structure with Pydantic model
    try:
        claims = AccessTokenClaims(**payload)
    except Exception as e:  # Pydantic ValidationError or others
        raise TokenInvalidError("invalid claims") from e

    return claims


def parse_token_headers(token: str) -> Dict[str, Any]:
    """Return JWT headers without verifying signature."""
    try:
        headers = jwt.get_unverified_header(token)
    except PyJWTError:
        raise
    return headers

def jwks() -> Dict[str, Any]:
    """
    Minimal JWKS for RS256 public key.
    """
    ensure_keys()
    public_key = serialization.load_pem_public_key(load_public_key(), backend=default_backend())
    numbers = public_key.public_numbers()
    e = numbers.e
    n = numbers.n

    def b64url_uint(val: int) -> str:
        import base64
        b = val.to_bytes((val.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": settings.JWT_ALG,
            "kid": load_kid(),
            "n": b64url_uint(n),
            "e": b64url_uint(e),
        }]
    }