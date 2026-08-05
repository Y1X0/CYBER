"""Typed, environment-driven settings (12-factor). Validated once at startup and cached.

All variables are prefixed ``GUARDIAN_`` so they can't collide with unrelated env. Secrets have
NO real defaults — the JWT secret default is a dev-only sentinel and refused outside `local`.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_JWT_SENTINEL = "change-me-dev-only-do-not-use-in-production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_", env_file=".env", extra="ignore", case_sensitive=False
    )

    env: str = "local"
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg://guardian:guardian@localhost:5432/guardian"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = _DEV_JWT_SENTINEL
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 60

    # Envelope-encryption key for credential references (5A). Generate: openssl rand -hex 32.
    # Empty falls back to a dev-only key (refused outside local/dev, like the JWT secret).
    encryption_key: str = ""

    # RLS: the API connects as a non-owner, RLS-enforced role. Falls back to the main URL in dev
    # (app-level tenant scoping still applies; production must set this to the guardian_app role).
    app_database_url: str = ""

    cors_origins: str = "http://localhost:5173"

    # Worker sandboxing (5A). When true, untrusted-input engines run in a resource-limited,
    # egress-restricted child process. Off by default so the in-process path stays simple for
    # internal/authorized scanning; turn on before scanning external/untrusted targets at scale.
    sandbox_engines: bool = False

    # DevSecOps: GitHub webhook HMAC secret (empty = webhook endpoint rejects all deliveries).
    github_webhook_secret: str = ""

    bootstrap_tenant: str = "Acme Security"
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: str = "ChangeMe123!"  # noqa: S105 - dev bootstrap default only

    # AI analyst (Phase 3). With no API key the platform uses the deterministic stub provider.
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-5"
    ai_effort: str = "medium"  # low | medium | high | xhigh | max
    ai_max_tokens: int = 8192

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"prod", "production"}

    @field_validator("jwt_secret")
    @classmethod
    def _reject_dev_secret_in_prod(cls, v: str, info) -> str:  # noqa: ANN001
        # Fail fast: never allow the sentinel secret outside local/dev.
        env = (info.data.get("env") or "local").lower()
        if env in {"prod", "production", "staging"} and v == _DEV_JWT_SENTINEL:
            raise ValueError("GUARDIAN_JWT_SECRET must be set to a strong value outside local/dev")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
