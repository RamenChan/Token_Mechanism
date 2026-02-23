from fastapi.testclient import TestClient
from app.main import app
from app.auth.service import build_access_claims
from app.tokens import jwt as jwt_mod


client = TestClient(app)


def test_me_endpoint_valid_token():
    claims = build_access_claims(
        user_id="usr_me",
        session_id="sid_me",
        device_id="dev1",
        client_id="cid_me",
        scope="profile:read",
    )
    token = jwt_mod.issue_access_token(claims)
    resp = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["sub"] == "usr_me"
    assert data["cid"] == "cid_me"


def test_me_endpoint_invalid_token():
    resp = client.get("/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert resp.status_code == 401


def test_me_endpoint_expired_token():
    claims = build_access_claims(
        user_id="usr_exp",
        session_id="sid_exp",
        device_id="dev1",
        client_id="cid_exp",
        scope="profile:read",
    )
    c = dict(claims)
    c["exp"] = 1
    token = jwt_mod.issue_access_token(c)
    resp = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_admin_endpoint_role_enforcement():
    # token without admin role
    claims = build_access_claims(
        user_id="usr_noadmin",
        session_id="sid_noadmin",
        device_id="dev1",
        client_id="cid_noadmin",
        scope="profile:read",
    )
    token = jwt_mod.issue_access_token(claims)
    resp = client.get("/v1/auth/admin", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403

    # token with admin role
    claims_admin = dict(claims)
    claims_admin["roles"] = ["user", "admin"]
    token2 = jwt_mod.issue_access_token(claims_admin)
    resp2 = client.get("/v1/auth/admin", headers={"Authorization": f"Bearer {token2}"})
    assert resp2.status_code == 200
    assert resp2.json()["sub"] == "usr_noadmin"
