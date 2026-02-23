from app.auth import service as auth_service
from app.auth.service import register_user, verify_user, build_access_claims
import time


def test_register_and_verify_user():
	username = "alice"
	password = "s3cret"
	# patch the password backend to avoid bcrypt dependency in tests
	class FakePwd:
		def hash(self, secret):
			return f"hashed:{secret}"

		def verify(self, secret, hashed):
			return hashed == f"hashed:{secret}"

	auth_service.pwd = FakePwd()

	register_user(username, password)
	user_id = verify_user(username, password)
	assert user_id is not None


def test_build_access_claims_structure():
	user_id = "usr_alice"
	session_id = "sid_test"
	device_id = "dev1"
	client_id = "cid_test"
	scope = "profile:read"

	claims = build_access_claims(user_id, session_id, device_id, client_id, scope)
	# Basic required claims
	assert claims["sub"] == user_id
	assert claims["sid"] == session_id
	assert claims["cid"] == client_id
	assert "exp" in claims and claims["exp"] > int(time.time())
