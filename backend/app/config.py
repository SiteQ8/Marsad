"""Application configuration, environment-driven for 12-factor deployment."""
from __future__ import annotations
import os
from functools import lru_cache


class Settings:
    APP_NAME: str = "Marsad"
    APP_TITLE: str = "Marsad — Vulnerability Management Platform"
    VERSION: str = "1.0.0"

    # SQLite by default (zero-config dev); set DATABASE_URL to Postgres in prod:
    #   postgresql+psycopg://marsad:marsad@db:5432/marsad
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./marsad.db")

    SECRET_KEY: str = os.getenv("MARSAD_SECRET_KEY", "dev-secret-change-me-in-production")
    ACCESS_TOKEN_TTL_MIN: int = int(os.getenv("MARSAD_TOKEN_TTL_MIN", "480"))
    ALGORITHM: str = "HS256"

    # Remediation SLA in days, keyed by severity band.
    SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180, "Info": 365}

    CORS_ORIGINS = os.getenv("MARSAD_CORS", "*").split(",")


@lru_cache
def get_settings() -> Settings:
    return Settings()
