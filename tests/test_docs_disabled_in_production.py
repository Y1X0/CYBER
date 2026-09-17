"""The interactive docs + OpenAPI schema are served only off production (Item 3).

/docs, /redoc and /openapi.json enumerate every route and auth scheme — recon surface that a
production control plane should not publish. They stay available in local/dev/test so the API is
still explorable there. create_app() is inspected directly (no TestClient) so the production
lifespan's DB-role check is not triggered.
"""

from __future__ import annotations

from guardian_api import main
from guardian_common.config import get_settings


def _app_with_env(monkeypatch, env: str):
    settings = get_settings()
    monkeypatch.setattr(settings, "env", env)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    return main.create_app()


def test_docs_disabled_in_production(monkeypatch):
    app = _app_with_env(monkeypatch, "production")
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_docs_disabled_in_staging(monkeypatch):
    # Staging is production-grade throughout the config; it hides the docs too.
    app = _app_with_env(monkeypatch, "staging")
    assert app.openapi_url is None


def test_docs_enabled_in_dev(monkeypatch):
    app = _app_with_env(monkeypatch, "local")
    assert app.docs_url == "/docs"
    assert app.openapi_url == "/openapi.json"
