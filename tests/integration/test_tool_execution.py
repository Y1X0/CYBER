"""Tool execution pipeline, end-to-end (Framework Phase 1). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves the governed rail: authorize → scope → policy → DB-less sandboxed run_tool → hash-chained
evidence. And the boundaries: deny outside authorization, human approval for active tools, tenant
isolation, and secrets never persisted in evidence.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest
from guardian_core.tool import RawEvidence, ToolCapabilities

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


class _EchoProvider:
    key, name, version = "echo", "echo", "1"
    _caps = ToolCapabilities(category="test", network=False, active=False)

    @property
    def capabilities(self):  # noqa: ANN201
        return self._caps

    def validate(self, job):  # noqa: ANN001, ANN201
        return None

    def execute(self, job):  # noqa: ANN001, ANN201
        for t in job.scope.targets:
            yield RawEvidence(tool="echo", execution_id=job.job_id, target=t, kind="echo",
                              data={"ok": True, "password": "SECRET"})  # secret must be scrubbed

    def normalize(self, evidence):  # noqa: ANN001, ANN201
        return None


def _install_echo(monkeypatch, caps=None):
    from guardian_scanner.tools import registry
    prov = _EchoProvider()
    if caps is not None:
        prov._caps = caps
    monkeypatch.setattr(registry, "tool_for", lambda k: prov if k == "echo" else None)
    monkeypatch.setattr(registry, "capabilities_for",
                        lambda k: prov.capabilities if k == "echo" else None)


def _tenant_with_authz(targets):
    from guardian_db.models import Authorization, Customer, Tenant, User
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        t = Tenant(name=f"tf-{m}", slug=f"tf-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"tf-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        if targets:
            db.add(Authorization(
                tenant_id=t.id, customer_id=c.id, asset_id=None, scope="s",
                authorized_targets=[{"type": "domain", "value": v} for v in targets],
                method="active_recon", authorized_by=u.id,
                valid_from=now - dt.timedelta(hours=1), valid_until=now + dt.timedelta(hours=1),
            ))
        return str(t.id)


def _evidence_rows(tid):
    from guardian_db.models import EvidenceItem
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(EvidenceItem).filter(EvidenceItem.tenant_id == uuid.UUID(tid)).all()


def test_pipeline_authorized_tool_persists_hash_chained_evidence(monkeypatch):
    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain
    from guardian_scanner.tools.tasks import dispatch_tool_job

    _install_echo(monkeypatch)
    tid = _tenant_with_authz(["example.com"])
    res = dispatch_tool_job.apply(args=[tid, "echo", ["example.com"]]).get()
    assert res["status"] == "completed" and res["evidence"] == 1

    rows = _evidence_rows(tid)
    assert len(rows) == 1
    assert rows[0].content_sha256 and rows[0].kind == "echo"
    assert "password" not in (rows[0].detail.get("data") or {})   # secret scrubbed from evidence
    with session_scope() as db:
        assert verify_chain(db, uuid.UUID(tid)) is True            # tamper-evident chain verifies


def test_pipeline_denies_target_outside_authorization(monkeypatch):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    _install_echo(monkeypatch)
    tid = _tenant_with_authz(["example.com"])
    res = dispatch_tool_job.apply(args=[tid, "echo", ["evil.com"]]).get()   # not authorized
    assert res["status"] == "denied"
    assert _evidence_rows(tid) == []                                        # nothing ran/persisted


def test_pipeline_requires_human_approval_for_active_tool(monkeypatch):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    _install_echo(monkeypatch, caps=ToolCapabilities(
        category="net", network=True, active=True, requires_human_approval=True))
    tid = _tenant_with_authz(["example.com"])

    denied = dispatch_tool_job.apply(args=[tid, "echo", ["example.com"], False]).get()
    assert denied["status"] == "denied" and denied["requires_human_approval"] is True
    assert _evidence_rows(tid) == []

    ok = dispatch_tool_job.apply(args=[tid, "echo", ["example.com"], True]).get()  # approved
    assert ok["status"] == "completed"


def test_evidence_is_tenant_isolated(monkeypatch):
    from guardian_db.session import get_app_session, set_tenant
    from guardian_scanner.tools.tasks import dispatch_tool_job
    from sqlalchemy import text

    _install_echo(monkeypatch)
    a = _tenant_with_authz(["example.com"])
    b = _tenant_with_authz(["example.com"])
    dispatch_tool_job.apply(args=[a, "echo", ["example.com"]]).get()
    dispatch_tool_job.apply(args=[b, "echo", ["example.com"]]).get()

    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        if row.rolbypassrls or row.rolsuper:
            pytest.skip("app session is not RLS-enforced")
        set_tenant(s, a)
        seen = s.execute(
            text("SELECT DISTINCT tenant_id::text FROM evidence_items")).scalars().all()
        assert seen == [a]
    finally:
        s.close()
