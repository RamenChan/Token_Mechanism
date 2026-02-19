'''
(AED)--> This file implements JWT token generation and JWKS endpoint for the SuperApp Identity Platform.
It uses RSA keys for signing and verifying tokens. The keys are generated and stored on disk if they don't already exist.
The `issue_access_token` function creates a JWT access token with the given claims, and the
`jwks` function returns the JSON Web Key Set containing the public key information for token verification.
'''

import time, json
from pathlib import Path
from typing import Any, Dict, Tuple
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from app.core.config import settings

KEY_DIR = Path(__file__).resolve().parent / "_keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE_KEY_PATH = KEY_DIR / "jwt_private.pem"
PUBLIC_KEY_PATH  = KEY_DIR / "jwt_public.pem"
KID_PATH         = KEY_DIR / "kid.txt"

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
    if not PRIVATE_KEY_PATH.exists() or not PUBLIC_KEY_PATH.exists() or not KID_PATH.exists():
        priv, pub, kid = _generate_keys()
        PRIVATE_KEY_PATH.write_bytes(priv)
        PUBLIC_KEY_PATH.write_bytes(pub)
        KID_PATH.write_text(kid)

def load_private_key() -> bytes:
    ensure_keys()
    return PRIVATE_KEY_PATH.read_bytes()

def load_public_key() -> bytes:
    ensure_keys()
    return PUBLIC_KEY_PATH.read_bytes()

def load_kid() -> str:
    ensure_keys()
    return KID_PATH.read_text().strip()

def issue_access_token(claims: Dict[str, Any]) -> str:
    kid = load_kid()
    headers = {"kid": kid, "typ": "at+jwt"}
    token = jwt.encode(claims, load_private_key(), algorithm=settings.JWT_ALG, headers=headers)
    return token

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