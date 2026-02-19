'''
(AED)--> This script creates the directory structure and empty files for the SuperApp Identity Platform project.
first run this script to set up the scaffold, then populate the files with the appropriate content.
'''

from pathlib import Path

FILES = [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    "docs/README.md",
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/api.md",
    "docs/runbooks.md",
    "infra/docker-compose.yml",
    "infra/nginx/nginx.conf",
    "apps/identity-api/Dockerfile",
    "apps/identity-api/pyproject.toml",
    "apps/identity-api/README.md",
    "apps/identity-api/app/main.py",
    "apps/identity-api/app/core/config.py",
    "apps/identity-api/app/core/security_headers.py",
    "apps/identity-api/app/core/rate_limit.py",
    "apps/identity-api/app/core/logging.py",
    "apps/identity-api/app/core/errors.py",
    "apps/identity-api/app/auth/router.py",
    "apps/identity-api/app/auth/service.py",
    "apps/identity-api/app/auth/schemas.py",
    "apps/identity-api/app/auth/deps.py",
    "apps/identity-api/app/tokens/jwt.py",
    "apps/identity-api/app/tokens/refresh_store.py",
    "apps/identity-api/app/tokens/one_time.py",
    "apps/identity-api/app/tokens/claims.py",
    "apps/identity-api/app/users/router.py",
    "apps/identity-api/app/users/service.py",
    "apps/identity-api/app/users/models.py",
    "apps/identity-api/app/users/schemas.py",
    "apps/identity-api/app/db/base.py",
    "apps/identity-api/app/db/session.py",
    "apps/identity-api/app/db/models.py",
    "apps/identity-api/app/db/migrations/.keep",
    "apps/identity-api/app/audit/router.py",
    "apps/identity-api/app/audit/service.py",
    "apps/identity-api/tests/test_auth_flow.py",
    "apps/identity-api/tests/test_refresh_rotation.py",
    "apps/identity-api/tests/test_jwks.py",
    "packages/python-auth-client/pyproject.toml",
    "packages/python-auth-client/README.md",
    "packages/python-auth-client/auth_client/__init__.py",
    "packages/python-auth-client/auth_client/verify.py",
    "packages/python-auth-client/auth_client/middleware_fastapi.py",
    "packages/python-auth-client/auth_client/middleware_flask.py",
]

def main():
    root = Path("superapp-identity-platform")
    for f in FILES:
        path = root / f
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("", encoding="utf-8")
    print(f"✅ Scaffold created: {root.resolve()}")

if __name__ == "__main__":
    main()