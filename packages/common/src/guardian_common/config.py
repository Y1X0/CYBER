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

    # Platform Owner principals (Phase A capability governance): a comma-separated allowlist of
    # user ids with platform-level authority, distinct from any per-tenant "owner" membership role.
    # Empty in dev. Platform owners are still subject to authorization, scope, policy, and audit.
    platform_owner_ids: str = ""

    # Job signing (Phase C execution-plane trust): Ed25519 keys, base64 raw 32 bytes. The trusted
    # dispatcher holds ONLY the private key; the tool plane (worker-tools) holds ONLY the public key
    # and can never mint a valid job. Empty in local/dev falls back to a fixed dev keypair (refused
    # outside local/dev). The PRIVATE key must NEVER be set on worker-tools.
    job_signing_private_key: str = ""
    job_signing_public_key: str = ""

    # Worker sandboxing (5A). When true, untrusted-input engines run in a resource-limited,
    # egress-restricted child process. Off by default so the in-process path stays simple for
    # internal/authorized scanning; turn on before scanning external/untrusted targets at scale.
    sandbox_engines: bool = False

    # Recon execution plane marker (6C.4). True ONLY on the isolated recon worker, which holds no DB
    # credentials and runs `recon_collect` (probing). The DB-bound orchestrator `run_discovery` runs
    # where this is False. Each task refuses to run on the wrong plane, so a misroute fails loudly.
    recon_plane: bool = False

    # Tool execution plane marker (Security Tool Execution Framework). True ONLY on the isolated,
    # DB-less tool worker running `run_tool` (sandboxed providers). The trusted `dispatch_tool_job`
    # (authorize/scope/policy/persist) runs where this is False. A misroute fails loudly.
    tool_plane: bool = False

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

        Job-signing key boundary (P1-3) is enforced FIRST and in ALL environments: the tool plane
        verifies with the public key only and must NEVER hold the private key, so a compromised or
        mis-templated tool plane can never mint jobs. Outside local/dev we additionally require a
        distinct RLS app-role URL (so requests never fall back to the RLS-bypassing owner), a real
        encryption key, and the public signing key on the tool plane so it can verify. Staging
        counts as production-grade (mirrors the JWT rule)."""
        # Unconditional: the tool plane must never be configured with the private signing key.
        # (Dev/test/ci leave both keys empty and derive a fixed dev keypair in-process, so this
        # never trips there; it fires only when a private key is configured on the tool plane.)
        if self.tool_plane and self.job_signing_private_key:
            raise ValueError(
                "GUARDIAN_JOB_SIGNING_PRIVATE_KEY must NEVER be set on the tool plane "
                "(GUARDIAN_TOOL_PLANE=true): it verifies with the public key only and must be "
                "unable to mint jobs"
            )
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
        # Production tool plane must carry the public key: there is no dev keypair fallback outside
        # local/dev, so verification would otherwise fail-closed on the first job. Fail at startup.
        if self.tool_plane and not self.job_signing_public_key:
            raise ValueError(
                "GUARDIAN_JOB_SIGNING_PUBLIC_KEY must be set on the tool plane outside local/dev "
                "so it can verify signed jobs"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
