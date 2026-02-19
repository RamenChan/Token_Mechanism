'''
(AED)--> This file defines the configuration settings for
the SuperApp Identity Platform application using Pydantic's BaseSettings.
The settings can be loaded from environment variables or a .env file.
'''
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "SuperApp Identity Platform"
    ENV: str = "dev"

    # JWT
    JWT_ISSUER: str = "https://auth.local"
    JWT_ALG: str = "RS256"
    ACCESS_TOKEN_TTL_SECONDS: int = 600  # 10 min
    INTEGRATION_TOKEN_TTL_SECONDS: int = 60

    # Refresh
    REFRESH_TOKEN_TTL_SECONDS: int = 60 * 60 * 24 * 30  # 30 days

    # Storage
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@db:5432/identity"
    REDIS_URL: str = "redis://redis:6379/0"

    # Rate limit
    RATE_LIMIT_PER_MINUTE: int = 120

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"

    class Config:
        env_file = ".env"

settings = Settings()