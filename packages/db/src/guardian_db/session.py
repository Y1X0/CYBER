"""Engines + session factories.

Two engines for tenant isolation (Phase 5A):
  * ADMIN engine (table owner) — used by workers, migrations, seed, and the identity bootstrap.
    Bypasses RLS because those operate legitimately across tenants (a worker scans one tenant's
    asset; a feed sync updates the shared KB).
  * APP engine (a non-owner, RLS-enforced role) — used by API request handlers. Every query is
    filtered by Postgres RLS to `app.current_tenant`, a hard backstop under the app-level scoping.

In dev/tests where `app_database_url` is unset, the app engine falls back to the admin engine, so
RLS is inert (owner bypasses) but app-level tenant scoping still applies. Production points the app
URL at the `guardian_app` role to activate RLS.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from guardian_common.config import get_settings
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker


@lru_cache
def _admin_engine():  # noqa: ANN202
    return create_engine(get_settings().database_url, pool_pre_ping=True, future=True)


@lru_cache
def _app_engine():  # noqa: ANN202
    settings = get_settings()
    url = settings.app_database_url or settings.database_url
    return create_engine(url, pool_pre_ping=True, future=True)


@lru_cache
def _admin_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=_admin_engine(), autoflush=False, expire_on_commit=False, future=True)


@lru_cache
def _app_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=_app_engine(), autoflush=False, expire_on_commit=False, future=True)


def get_session() -> Session:
    """A privileged (admin) session — for workers, scripts, seed, and identity bootstrap."""
    return _admin_factory()()


def get_app_session() -> Session:
    """An RLS-enforced (app-role) session — for API request handlers."""
    return _app_factory()()


def set_tenant(session: Session, tenant_id) -> None:  # noqa: ANN001
    """Bind the session's connection to a tenant for RLS. No-op-safe (owner bypasses RLS)."""
    session.execute(text("SELECT set_config('app.current_tenant', :t, false)"),
                    {"t": str(tenant_id)})


def reset_tenant(session: Session) -> None:
    session.execute(text("SELECT set_config('app.current_tenant', '', false)"))


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional admin scope for scripts and workers: commit on success, rollback on error."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
