"""A database can be built from nothing (WP-G1b).

Every migration in this repository was written against a database that already existed, and every
one of them was exercised that way. Nothing ever ran `alembic upgrade head` against an *empty*
database except CI — where it had been failing, in the "Migrate database" step, on every commit for
seven migrations, with the rest of the pipeline skipped behind it.

The cause: `0001_baseline` builds the schema from `Base.metadata`, so on an empty database it
creates every model registered *today*, including tables whose own migrations come later. The first
of those then failed with `relation "schedules" already exists`. Anywhere the schema had been built
incrementally — every developer machine, the deployed database — the baseline had run long before
those models existed, so the breakage was invisible. It would have appeared for the first time on a
disaster-recovery restore or a new environment.

These tests are the guard. They build a throwaway database from zero, and then check that what
comes out matches the models exactly — tables, columns, nullability, defaults, indexes,
constraints — and that every tenant-scoped table carries RLS. Schema drift between "migrated" and
"declared" is how a fresh environment ends up subtly different from production; naming it here
means it fails a test instead of a restore.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import text

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
# Tables that exist in the database but are nobody's model. Alembic's bookkeeping is the only one.
NON_MODEL_TABLES = {"alembic_version"}
# Columns migration 0010 adds deliberately without mapping them — a nullable link from an execution
# to its campaign that nothing in the ORM reads. Listed rather than ignored, so it stays a decision
# somebody made instead of drift nobody noticed.
UNMAPPED_COLUMNS = {("authorizations", "campaign_id"), ("scans", "campaign_id")}


def _admin_url() -> sa.URL:
    from guardian_common.config import get_settings

    return sa.make_url(get_settings().database_url)


@pytest.fixture(scope="module")
def fresh_database():
    """A database built by running the migrations, in order, against nothing."""
    base = _admin_url()
    name = f"guardian_migrate_{uuid.uuid4().hex[:10]}"
    maintenance = sa.create_engine(base.set(database="postgres"),
                                   isolation_level="AUTOCOMMIT")
    with maintenance.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))

    url = base.set(database=name)
    app_url = _app_url_for(name)
    # A subprocess, because `migrations/env.py` reads the URL from cached settings — and because it
    # is exactly what CI and a deploy run.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
        env={**os.environ,
             "GUARDIAN_DATABASE_URL": url.render_as_string(hide_password=False),
             "GUARDIAN_APP_DATABASE_URL": app_url},
        check=False,
    )
    engine = sa.create_engine(url)
    try:
        # The failure this file exists for prints its cause; do not swallow it into an assert.
        assert result.returncode == 0, (
            f"alembic upgrade head failed on an empty database:\n{result.stdout}\n{result.stderr}"
        )
        yield engine
    finally:
        engine.dispose()
        with maintenance.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        maintenance.dispose()


def _app_url_for(name: str) -> str:
    from guardian_common.config import get_settings

    configured = get_settings().app_database_url
    if not configured:
        return ""
    return sa.make_url(configured).set(database=name).render_as_string(hide_password=False)


def _metadata():
    import guardian_db.models  # noqa: F401
    from guardian_db.base import Base

    return Base.metadata


# ── the failure this file exists for ──────────────────────────────────────────────────────────────
def test_a_database_can_be_built_from_nothing(fresh_database):
    """`alembic upgrade head` on an empty database reaches head. This is the step CI was failing."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(REPO_ROOT / "alembic.ini"))
    heads = ScriptDirectory.from_config(config).get_heads()

    with fresh_database.connect() as conn:
        applied = conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()

    assert sorted(applied) == sorted(heads)


def test_the_migration_chain_has_exactly_one_head():
    """Two heads mean two people's migrations both claim to be last, and `upgrade head` refuses."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(REPO_ROOT / "alembic.ini"))
    assert len(ScriptDirectory.from_config(config).get_heads()) == 1


# ── the migrated schema is the declared schema ────────────────────────────────────────────────────
def test_every_model_has_a_table_and_every_table_has_a_model(fresh_database):
    declared = set(_metadata().tables)
    built = set(sa.inspect(fresh_database).get_table_names())

    assert declared - built == set(), "a model has no table: its migration is missing"
    assert built - declared - NON_MODEL_TABLES == set(), "a table nothing declares"


def test_columns_match_the_models(fresh_database):
    """Names, nullability and — the drift that started this — whether the database supplies a
    default. A column the migration gives `DEFAULT 0` and the model does not is a raw INSERT that
    works on one deployment and fails on the next."""
    inspector = sa.inspect(fresh_database)
    problems = []
    for name, table in sorted(_metadata().tables.items()):
        actual = {c["name"]: c for c in inspector.get_columns(name)
                  if (name, c["name"]) not in UNMAPPED_COLUMNS}
        declared = {c.name: c for c in table.columns}
        if set(actual) != set(declared):
            problems.append(f"{name}: columns differ "
                            f"(db-only {sorted(set(actual) - set(declared))}, "
                            f"model-only {sorted(set(declared) - set(actual))})")
            continue
        for column, spec in sorted(declared.items()):
            if actual[column]["nullable"] != spec.nullable:
                problems.append(f"{name}.{column}: nullable "
                                f"{actual[column]['nullable']} vs model {spec.nullable}")
            if bool(actual[column].get("default")) != bool(spec.server_default):
                problems.append(f"{name}.{column}: server default "
                                f"{actual[column].get('default')!r} vs model "
                                f"{bool(spec.server_default)}")
    assert not problems, "migrated schema differs from the models:\n  " + "\n  ".join(problems)


def test_declared_indexes_and_constraints_exist(fresh_database):
    inspector = sa.inspect(fresh_database)
    missing = []
    for name, table in sorted(_metadata().tables.items()):
        present = {i["name"] for i in inspector.get_indexes(name)}
        present |= {u["name"] for u in inspector.get_unique_constraints(name)}
        present |= {c["name"] for c in inspector.get_check_constraints(name)}
        for index in table.indexes:
            if index.name not in present:
                missing.append(f"{name}: index {index.name}")
        for constraint in table.constraints:
            if isinstance(constraint, sa.UniqueConstraint | sa.CheckConstraint):
                if constraint.name and constraint.name not in present:
                    missing.append(f"{name}: constraint {constraint.name}")
    assert not missing, "declared but not built:\n  " + "\n  ".join(missing)


# ── the control that must survive a rebuild ───────────────────────────────────────────────────────
def test_every_tenant_scoped_table_enforces_rls(fresh_database):
    """Tenant isolation is a property of the database, not of the queries the application happens
    to write. A table with a `tenant_id` and no policy is a cross-tenant read away from a raw query
    somebody adds later — and a rebuilt environment is exactly where such a gap would appear
    unnoticed."""
    inspector = sa.inspect(fresh_database)
    tenant_scoped = [
        name for name in inspector.get_table_names()
        if any(c["name"] == "tenant_id" for c in inspector.get_columns(name))
    ]
    assert tenant_scoped, "no tenant-scoped tables found — the check is not looking at anything"

    with fresh_database.connect() as conn:
        enforcing = set(conn.execute(text(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity"
        )).scalars())
        policed = set(conn.execute(text(
            "SELECT tablename FROM pg_policies WHERE schemaname = 'public'"
        )).scalars())

    unprotected = sorted(t for t in tenant_scoped if t not in enforcing or t not in policed)
    assert not unprotected, f"tenant-scoped tables without RLS: {unprotected}"


def test_the_app_role_exists_and_cannot_bypass_rls(fresh_database):
    """RLS that the application's own role is exempt from is decoration."""
    with fresh_database.connect() as conn:
        row = conn.execute(text(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'guardian_app'"
        )).first()

    assert row is not None, "guardian_app was not created"
    assert row.rolsuper is False
    assert row.rolbypassrls is False


def test_the_api_key_authentication_lookup_is_reachable_by_the_app_role(fresh_database):
    """WP-G1b: the key path needs this function, and needs it granted — without it a valid API key
    is refused as invalid under RLS."""
    with fresh_database.connect() as conn:
        secdef = conn.execute(text(
            "SELECT prosecdef FROM pg_proc WHERE proname = 'auth_api_key'"
        )).scalar()
        granted = conn.execute(text(
            "SELECT has_function_privilege('guardian_app', 'auth_api_key(uuid)', 'execute')"
        )).scalar()

    assert secdef is True
    assert granted is True
