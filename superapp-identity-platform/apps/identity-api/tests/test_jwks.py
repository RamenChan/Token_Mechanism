from app.auth.service import build_access_claims
from app.tokens import jwt as jwt_mod


def test_issue_and_verify_access_token():
    # build basic claims
    claims = build_access_claims(
        user_id="usr_test",
        session_id="sid_test",
        device_id="dev1",
        client_id="cid_test",
        scope="profile:read",
    )

    token = jwt_mod.issue_access_token(claims)
    assert isinstance(token, str)

    verified = jwt_mod.verify_access_token(token)
    assert verified.sub == "usr_test"
    assert "identity-api" in verified.aud

    hdrs = jwt_mod.parse_token_headers(token)
    assert "kid" in hdrs


def test_verify_invalid_and_expired():
    claims = build_access_claims(
        user_id="usr_test2",
        session_id="sid_test2",
        device_id="dev1",
        client_id="cid_test",
        scope="profile:read",
    )

    # create expired token
    claims_expired = dict(claims)
    claims_expired["exp"] = 1
    token_expired = jwt_mod.issue_access_token(claims_expired)

    try:
        jwt_mod.verify_access_token(token_expired)
        assert False, "expected TokenExpiredError"
    except jwt_mod.TokenExpiredError:
        pass

    # tamper token (invalid signature)
    # create a fresh valid token and then tamper
    token = jwt_mod.issue_access_token(claims)
    parts = token.split(".")
    tampered = parts[0] + "." + parts[1] + ".tampered"
    try:
        jwt_mod.verify_access_token(tampered)
        assert False, "expected TokenInvalidError or signature error"
    except (jwt_mod.TokenInvalidError, jwt_mod.TokenInvalidSignatureError):
        pass


def test_key_rotation_keeps_old_tokens_valid():
    # issue token with current key
    claims = build_access_claims(
        user_id="usr_rotate",
        session_id="sid_rotate",
        device_id="dev1",
        client_id="cid_test",
        scope="profile:read",
    )

    token_old = jwt_mod.issue_access_token(claims)
    kid_old = jwt_mod.load_kid()

    # rotate keys
    new_kid = jwt_mod.rotate_keys()
    assert new_kid != kid_old

    # token issued with old kid should still verify (we keep old public key file)
    verified = jwt_mod.verify_access_token(token_old)
    assert verified.sub == "usr_rotate"
