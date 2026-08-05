"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from guardian_common.config import get_settings
from guardian_common.logging import configure_logging

from guardian_api.routes import api_router


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Security Guardian Platform API",
        version="0.1.0",
        description="AI Security Operations Platform — control plane (Phase 1 Foundation)",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {"name": "Security Guardian Platform", "status": "ok", "docs": "/docs"}

    return app


app = create_app()
