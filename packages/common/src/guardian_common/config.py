"""Typed, environment-driven settings (12-factor). Validated once at startup and cached.

All variables are prefixed ``GUARDIAN_`` so they can't collide with unrelated env. Secrets have
NO real defaults — the JWT secret default is a dev-only sentinel and refused outside `local`.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_JWT_SENTINEL = "change-me-dev-only-do-not-use-in-production"
_DEV_ENCRYPTION_SENTINEL = "dev-only-encryption-key-change-me"
_DEV_SEAL_SENTINEL = "dev-only-broker-seal-key-change-me"
_DEFAULT_BOOTSTRAP_PASSWORD = "ChangeMe123!"  # noqa: S105 - dev bootstrap default only
_LOCAL_ENVS = {"local", "dev", "development", "test", "ci"}
# Celery's Redis backend demands this parameter on a `rediss://` URL and raises without it.
# `required` is the setting that actually verifies the server certificate.
_CELERY_TLS_PARAM = "ssl_cert_reqs"
_CELERY_TLS_REQUIRED = "required"
# libpq/psycopg establishes an encrypted connection ONLY for these sslmodes; disable/allow/prefer
# either skip TLS or silently fall back to plaintext, so they are NOT accepted in production (P1-C).
_TLS_SSLMODES = {"require", "verify-ca", "verify-full"}


def _postgres_enforces_tls(dsn: str) -> bool:
    """True iff the Postgres DSN pins a TLS-enforcing sslmode in its query string (P1-C)."""
    from urllib.parse import parse_qs, urlsplit

    mode = (parse_qs(urlsplit(dsn).query).get("sslmode") or [""])[0].lower()
    return mode in _TLS_SSLMODES


def _redis_is_authenticated(url: str) -> bool:
    """True iff the Redis URL carries AUTH credentials — a non-empty password in userinfo (P1-δ).

    Covers both legacy password-only (``redis://:pw@host``) and ACL user+password
    (``redis://user:pw@host``); redis-py and kombu both consume the URL password for AUTH.
    """
    from urllib.parse import urlsplit

    return bool(urlsplit(url).password)


def celery_redis_url(url: str) -> str:
    """The broker/result-backend URL in the form Celery requires.

    Celery refuses to construct a Redis result backend for a ``rediss://`` URL that does not carry
    ``ssl_cert_reqs``, and raises at construction — before any network call. The effect is
    asymmetric and that is what makes it dangerous: the API only ever publishes, so it never touches
    the result backend and keeps working, while every worker dies at startup. A deployment can look
    healthy and be unable to execute a single scan.

    Normalising here rather than in the environment means a correct-but-incomplete secret cannot
    take the workers down, wherever it is set. It does not lower the bar: ``required`` is the
    verifying setting, and the production validator's own TLS and AUTH checks read
    ``settings.redis_url``, which this never modifies.

    A URL that already states its own ``ssl_cert_reqs`` is returned untouched — the operator made
    that choice, and quietly rewriting it would hide a misconfiguration instead of surfacing it. So
    is anything that is not ``rediss://``, and so is a URL that will not parse, which Celery should
    report rather than this function swallow.
    """
    from urllib.parse import parse_qsl, urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.scheme != "rediss":
        return url
    if _CELERY_TLS_PARAM in {key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}:
        return url
    # Appended as text rather than re-encoding the parsed query, so an existing parameter is
    # returned byte-for-byte as the operator wrote it.
    separator = "&" if parts.query else ""
    return urlunsplit(parts._replace(
        query=f"{parts.query}{separator}{_CELERY_TLS_PARAM}={_CELERY_TLS_REQUIRED}"))


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

    # Pepper for API-key digests (WP-G1). Separate from the JWT secret when set, so rotating one
    # does not invalidate the other; falls back to the JWT secret so a deployment that has not set
    # it still peppers rather than storing a bare SHA-256 that a stolen database could be brute
    # forced against offline.
    api_key_pepper: str = ""

    # Shared token for Prometheus to scrape /metrics without a human session (WP-G4). Empty means
    # the endpoint is closed: an unset secret must never mean "no authentication required".
    metrics_token: str = ""

    # Emergency stop for active scanning, platform-wide (WP-H3). Set it and every engine that
    # touches a customer's network refuses, whatever their authorization says.
    active_scanning_paused: bool = False

    # Per-tenant ceilings (WP-G2). Platform defaults; a tenant may lower or raise them within the
    # hard ceiling via `tenants.settings["quota"]`. 0 disables that limit entirely, which is a
    # deliberate operational choice and not the effect of leaving a value unset.
    # Whether a stranger may create an organization (WP-P0 sign-up). On a managed deployment an
    # operator provisions tenants and this is turned off; the endpoint then refuses rather than
    # quietly existing.
    self_serve_signup: bool = True

    tenant_rate_limit_per_minute: int = 600
    tenant_concurrent_scans: int = 10
    tenant_max_page_size: int = 200

    @property
    def apikey_pepper(self) -> str:
        return self.api_key_pepper or self.jwt_secret

    # Login rate limit (P1-γ): max /auth/login attempts per source IP and per account within a
    # 60s sliding window. Bounds password guessing and Argon2 CPU-exhaustion from a single source
    # BEFORE the hash runs. Raise it for shared-NAT deployments; a global limit across replicas is a
    # gateway concern (this in-app limiter is per-process). 0 disables the limiter.
    auth_rate_limit_per_minute: int = 10

    # Trusted reverse-proxy hop count (P1-①). X-Forwarded-For is client-spoofable, so by default (0)
    # the client IP used for audit + rate limiting is the SOCKET PEER and XFF is ignored entirely.
    # When the app runs behind N trusted proxies that append XFF, set this to N: the real client is
    # then the XFF entry just before those N trusted hops, which an attacker cannot forge by
    # prepending spoofed entries. Must match the actual proxy topology (enforced, not a convention).
    trusted_proxy_count: int = 0

    # Envelope-encryption key for credential references (5A). Generate: openssl rand -hex 32.
    # Empty falls back to a dev-only key (refused outside local/dev, like the JWT secret). This is
    # the credential KMS master — it decrypts tenant secrets and must live ONLY on the trusted
    # DB-bound planes (API, default worker), NEVER on the DB-less execution planes (P1-A).
    encryption_key: str = ""

    # Broker-seal key (P1-A): a SEPARATE symmetric key encrypting sensitive job/result payloads on
    # the Redis broker + result backend (P1-4). Deliberately DISTINCT from `encryption_key` so the
    # execution plane — which runs untrusted external binaries — holds only this lower-value payload
    # key and never the credential KMS master. Generate: openssl rand -hex 32. Empty falls back to a
    # dev-only key (refused, and required to differ from encryption_key, outside local/dev).
    broker_seal_key: str = ""

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
    bootstrap_admin_password: str = _DEFAULT_BOOTSTRAP_PASSWORD

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

    @model_validator(mode="after")
    def _enforce_production_invariants(self) -> Settings:
        """Fail fast at startup on misconfigurations that would silently weaken security.

        Job-signing key boundary (P1-3) is enforced FIRST and in ALL environments: the tool plane
        verifies with the public key only and must NEVER hold the private key, so a compromised or
        mis-templated tool plane can never mint jobs. Outside local/dev we additionally enforce the
        secret-boundary between trusted DB-bound planes and the DB-less execution planes (P1-A): the
        execution planes (tool/recon) must NOT carry the JWT secret or the credential KMS master,
        and the broker-seal key must be set and DISTINCT from that master. Staging counts as
        production-grade."""
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

        # The execution planes (tool/recon) run untrusted external binaries and hold NO DB. They
        # must be secret-minimal: no token-forging JWT secret, no credential KMS master (P1-A).
        is_execution_plane = self.tool_plane or self.recon_plane

        # JWT secret boundary (P1-A): token-minting/verifying planes require a real secret; the
        # execution planes never sign or verify tokens and must NOT hold a real one, so a hostile
        # binary can never exfiltrate a key that forges platform JWTs.
        if is_execution_plane:
            if self.jwt_secret and self.jwt_secret != _DEV_JWT_SENTINEL:
                raise ValueError(
                    "GUARDIAN_JWT_SECRET must NOT be set on the tool/recon execution plane "
                    "(GUARDIAN_TOOL_PLANE/GUARDIAN_RECON_PLANE=true): it never signs or verifies "
                    "tokens, so holding it only creates a JWT-forgery exfiltration risk"
                )
        elif self.jwt_secret == _DEV_JWT_SENTINEL:
            raise ValueError("GUARDIAN_JWT_SECRET must be set to a strong value outside local/dev")

        # RLS app-role: only the DB-bound control plane needs it; execution planes are DB-less.
        if not is_execution_plane and (
            not self.app_database_url or self.app_database_url == self.database_url
        ):
            raise ValueError(
                "GUARDIAN_APP_DATABASE_URL must be set to the non-owner guardian_app role "
                "(distinct from GUARDIAN_DATABASE_URL) outside local/dev — otherwise RLS is inert"
            )

        # Credential KMS master (encryption_key) boundary (P1-A): required where credentials are
        # encrypted/decrypted (API, default worker); FORBIDDEN on the execution planes so a tool
        # compromise never yields the key that decrypts stored tenant credentials.
        if is_execution_plane:
            if self.encryption_key and self.encryption_key != _DEV_ENCRYPTION_SENTINEL:
                raise ValueError(
                    "GUARDIAN_ENCRYPTION_KEY (credential KMS master) must NOT be set on the "
                    "tool/recon execution plane — it decrypts stored tenant credentials and must "
                    "stay on the trusted DB-bound planes; the execution plane uses "
                    "GUARDIAN_BROKER_SEAL_KEY for payload sealing"
                )
        elif not self.encryption_key or self.encryption_key == _DEV_ENCRYPTION_SENTINEL:
            raise ValueError(
                "GUARDIAN_ENCRYPTION_KEY must be set to a strong value outside local/dev"
            )

        # Broker-seal key (P1-A): the payload-seal key is separate from the credential KMS master
        # and required on every plane that seals/unseals broker payloads — the tool plane (unseals a
        # job, seals its evidence) and the control plane (seals a job, unseals results). The recon
        # plane never seals. It MUST differ from encryption_key so the domains use distinct keys.
        if not self.recon_plane:
            if not self.broker_seal_key or self.broker_seal_key == _DEV_SEAL_SENTINEL:
                raise ValueError(
                    "GUARDIAN_BROKER_SEAL_KEY must be set to a strong value outside local/dev"
                )
            if self.broker_seal_key == self.encryption_key:
                raise ValueError(
                    "GUARDIAN_BROKER_SEAL_KEY must differ from GUARDIAN_ENCRYPTION_KEY — the "
                    "broker payload-seal key and the credential KMS master must be separate keys"
                )

        # Production tool plane must carry the public key: there is no dev keypair fallback outside
        # local/dev, so verification would otherwise fail-closed on the first job. Fail at startup.
        if self.tool_plane and not self.job_signing_public_key:
            raise ValueError(
                "GUARDIAN_JOB_SIGNING_PUBLIC_KEY must be set on the tool plane outside local/dev "
                "so it can verify signed jobs"
            )
        # Broker/result-backend confidentiality (P1-4): the broker carries signed jobs (sealed
        # artifacts) and the result backend carries evidence; require TLS in transit off local/dev.
        if not self.redis_url.startswith("rediss://"):
            raise ValueError(
                "GUARDIAN_REDIS_URL must use TLS (rediss://) outside local/dev — the broker and "
                "result backend carry jobs and evidence"
            )
        # Redis authentication (P1-δ): an unauthenticated broker lets a compromised execution-plane
        # worker read/tamper the queue, result backend, and replay-nonce store. Require AUTH/ACL
        # credentials in the URL outside local/dev — all three clients derive from this one URL.
        if not _redis_is_authenticated(self.redis_url):
            raise ValueError(
                "GUARDIAN_REDIS_URL must carry AUTH credentials (rediss://:PASSWORD@host or "
                "user:PASSWORD@host) outside local/dev — an unauthenticated broker/replay store "
                "lets a compromised execution-plane worker tamper the queue and defeat replay"
            )
        # Bootstrap-admin credential (P1-B): never boot production with the publicly-documented
        # default owner password — the seed would otherwise create a known-credential owner.
        if self.bootstrap_admin_password == _DEFAULT_BOOTSTRAP_PASSWORD:
            raise ValueError(
                "GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD must be changed from the default "
                "outside local/dev"
            )
        # PostgreSQL TLS (P1-C): the DB carries encrypted credentials, PII, and the evidence chain —
        # require TLS in transit outside local/dev, symmetric with the Redis rediss:// rule. libpq
        # honours the DSN's sslmode. Execution planes are DB-less (empty DSN) and skip the check.
        for label, dsn in (("GUARDIAN_DATABASE_URL", self.database_url),
                           ("GUARDIAN_APP_DATABASE_URL", self.app_database_url)):
            if dsn and not _postgres_enforces_tls(dsn):
                raise ValueError(
                    f"{label} must enforce TLS (sslmode=require|verify-ca|verify-full) outside "
                    "local/dev — the database connection carries credentials, PII, and evidence"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
