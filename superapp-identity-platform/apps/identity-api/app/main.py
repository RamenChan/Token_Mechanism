'''(AED)--> This is the main entry point for the SuperApp Identity Platform API. It sets up the FastAPI application, 
configures CORS middleware, and includes the authentication router. It also defines a simple health check endpoint 
to verify that the service is running and to provide environment information.
'''

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.auth.router import router as auth_router
from app.core.security_headers import SecurityHeadersMiddleware


app = FastAPI(title=settings.APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth_router)

@app.get("/health")
async def health():
    return {"status": "ok", "env": settings.ENV}