"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from guardian_common.config import Settings, get_settings
from guardian_common.logging import configure_logging, get_logger
from sqlalchemy import text

from guardian_api.observability import MetricsMiddleware
from guardian_api.routes import api_router

log = get_logger("guardian.api")


def _verify_rls_app_role(settings: Settings) -> None:
    """Fail fast in production if the API's DB session is NOT the RLS-enforced non-owner role.

    Pointing GUARDIAN_APP_DATABASE_URL at the owner (or a superuser/BYPASSRLS role) silently makes
    tenant-isolation RLS inert. Refuse to start rather than serve without the backstop."""
    if settings.is_local_or_dev:
        return
    from guardian_db.session import get_app_session

    session = get_app_session()
    try:
        row = session.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
        if row.rolsuper or row.rolbypassrls:
            raise RuntimeError(
                "API app session connects as an RLS-bypassing role — set GUARDIAN_APP_DATABASE_URL "
                "to the non-owner guardian_app role so tenant-isolation RLS is enforced"
            )
    finally:
        session.close()


@asynccontextmanager
async def _lifespan(app: FastAPI):  # noqa: ANN202
    _verify_rls_app_role(get_settings())
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Security Guardian Platform API",
        version="0.1.0",
        description="AI Security Operations Platform — control plane (Phase 1 Foundation)",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=_lifespan,
    )

    # Never combine a wildcard origin with credentials — that would let any site make
    # credentialed cross-origin requests. If "*" is configured, credentials are disabled.
    origins = settings.cors_origin_list
    allow_credentials = "*" not in origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Added after CORS so it wraps every request including the preflight ones, and records the
    # failures: a request that raises is exactly the one worth graphing.
    app.add_middleware(MetricsMiddleware)

    app.include_router(api_router)

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {"name": "Security Guardian Platform", "status": "ok", "docs": "/docs"}

    return app


app = create_app()
