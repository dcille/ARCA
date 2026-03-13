"""D-ARCA configuration."""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "D-ARCA"
    APP_DESCRIPTION: str = "Asset Risk & Cloud Analysis"
    SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    DATABASE_URL: str = "postgresql+asyncpg://darca:darca@postgres:5432/darca"
    REDIS_URL: str = "redis://valkey:6379/0"

    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://ui:3000"]

    CELERY_BROKER_URL: str = "redis://valkey:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://valkey:6379/1"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
