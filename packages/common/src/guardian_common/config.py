"""Typed, environment-driven settings (12-factor). Validated once at startup and cached.

All variables are prefixed ``GUARDIAN_`` so they can't collide with unrelated env. Secrets have
NO real defaults — the JWT secret default is a dev-only sentinel and refused outside `local`.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_JWT_SENTINEL = "change-me-dev-only-do-not-use-in-production"
_DEV_ENCRYPTION_SENTINEL = "dev-only-encryption-key-change-me"
_LOCAL_ENVS = {"local", "dev", "development", "test", "ci"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_", env_file=".env", extra="ignore", case_sensitive=False
    )

    env: str = "local"
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg://guardian:guardian@localhost:5432/guardian"
    redis_url: str = "redis://localhost:6379/0"

    # Connection-pool sizing (per engine, per process). Total backend connections =
    # (pool_size + max_overflow) x engines x processes — keep it under Postgres max_connections
    # (front with PgBouncer for real scale). Tunable via GUARDIAN_DB_POOL_SIZE etc.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

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

    @property
    def is_local_or_dev(self) -> bool:
        """True only for local/dev-class environments. Staging is treated as production-grade."""
        return self.env.lower() in _LOCAL_ENVS

    @field_validator("jwt_secret")
    @classmethod
    def _reject_dev_secret_in_prod(cls, v: str, info) -> str:  # noqa: ANN001
        # Fail fast: never allow the sentinel secret outside local/dev.
        env = (info.data.get("env") or "local").lower()
        if env not in _LOCAL_ENVS and v == _DEV_JWT_SENTINEL:
            raise ValueError("GUARDIAN_JWT_SECRET must be set to a strong value outside local/dev")
        return v

    @model_validator(mode="after")
    def _enforce_production_invariants(self) -> Settings:
        """Fail fast at startup on misconfigurations that would silently weaken security.

        Outside local/dev we require: (1) a distinct RLS app-role URL so requests never fall back to
        the RLS-bypassing owner, and (2) a real encryption key so credentials aren't sealed with the
        dev sentinel. Staging counts as production-grade here (mirrors the JWT rule)."""
        if self.is_local_or_dev:
            return self
        if not self.app_database_url or self.app_database_url == self.database_url:
            raise ValueError(
                "GUARDIAN_APP_DATABASE_URL must be set to the non-owner guardian_app role "
                "(distinct from GUARDIAN_DATABASE_URL) outside local/dev — otherwise RLS is inert"
            )
        if not self.encryption_key or self.encryption_key == _DEV_ENCRYPTION_SENTINEL:
            raise ValueError(
                "GUARDIAN_ENCRYPTION_KEY must be set to a strong value outside local/dev"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
