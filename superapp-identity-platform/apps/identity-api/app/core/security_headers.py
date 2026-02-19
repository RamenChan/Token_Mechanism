'''(AED)--> This file implements a middleware for adding security headers to all HTTP responses in the SuperApp Identity Platform API.
The `SecurityHeadersMiddleware` class extends FastAPI's `BaseHTTPMiddleware` and overrides the
`dispatch` method to inject various security-related headers into the response. These headers include protections against
content sniffing, clickjacking, referrer leakage, and cross-origin resource sharing. The middleware can be added to the FastAPI application to enhance the security posture of the API.

Note: The HSTS header is commented out by default, as it should only be enabled when the API is served over HTTPS in production environments.
'''

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Basic hardening headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # HSTS only if behind HTTPS (in prod)
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Minimal CSP for API (no HTML content)
        response.headers["Content-Security-Policy"] = "default-src 'none'"

        return response