"""Engines + session factories, with transaction-local tenant binding for RLS.

Two engines:
  * ADMIN engine (table owner) — workers, migrations, seed. Bypasses RLS because those operate
    legitimately across tenants (a worker scans one tenant's asset; a feed sync updates the KB).
  * APP engine (non-owner, RLS-enforced role) — every API request. Queries are filtered by Postgres
    RLS to `app.current_tenant`, a hard backstop under the app-level scoping.

Tenant/user context is bound **transaction-locally**. `set_tenant`/`set_user` record the ids on the
Session and issue `set_config(..., is_local => true)` for the active transaction; an `after_begin`
listener re-applies them at the start of every subsequent transaction (so a handler that commits
mid-request keeps its binding). Because the GUCs are transaction-local they auto-clear when the
connection returns to the pool — no cross-tenant bleed, and compatible with PgBouncer transaction
pooling. In dev/tests where `app_database_url` is unset the app engine falls back to the owner, so
RLS is inert (owner bypasses) but the binding still applies harmlessly.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from guardian_common.config import get_settings
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

_TENANT_KEY = "app_tenant"


def _make_engine(url: str):  # noqa: ANN202
    s = get_settings()
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        pool_timeout=s.db_pool_timeout,
        future=True,
    )


@lru_cache
def _admin_engine():  # noqa: ANN202
    return _make_engine(get_settings().database_url)


@lru_cache
def _app_engine():  # noqa: ANN202
    settings = get_settings()
    return _make_engine(settings.app_database_url or settings.database_url)


@lru_cache
def _admin_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=_admin_engine(), autoflush=False, expire_on_commit=False, future=True)


@lru_cache
def _app_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=_app_engine(), autoflush=False, expire_on_commit=False, future=True)


@event.listens_for(Session, "after_begin")
def _apply_rls_context(session: Session, transaction, connection) -> None:  # noqa: ANN001
    """Re-apply the session's tenant/user binding (transaction-local) at each transaction start.

    No-op for admin/worker sessions, which never set these keys. Keeps the binding alive across the
    commits a request handler may issue, without leaving anything on the connection after it closes.
    """
    tenant_id = session.info.get(_TENANT_KEY)
    if tenant_id is not None:
        connection.exec_driver_sql(
            "SELECT set_config('app.current_tenant', %s, true)", (str(tenant_id),)
        )


def get_session() -> Session:
    """A privileged (admin) session — for workers, scripts, and seed."""
    return _admin_factory()()


def get_app_session() -> Session:
    """An RLS-enforced (app-role) session — for API request handlers."""
    return _app_factory()()


def set_tenant(session: Session, tenant_id) -> None:  # noqa: ANN001
    """Bind the session to a tenant for RLS (transaction-local, re-applied per transaction)."""
    session.info[_TENANT_KEY] = str(tenant_id)
    session.execute(
        text("SELECT set_config('app.current_tenant', :t, true)"), {"t": str(tenant_id)}
    )


def reset_tenant(session: Session) -> None:
    """Clear the binding. Transaction-local GUCs also self-clear on connection checkin."""
    session.info.pop(_TENANT_KEY, None)
    try:
        session.execute(text("SELECT set_config('app.current_tenant', '', true)"))
    except Exception:  # noqa: BLE001, S110 - connection may already be closing; nothing to clear
        pass


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
