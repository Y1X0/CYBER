"""SBOM persistence + the scan-pipeline hook that fills it.

No database: SbomRecord constructs in memory and the store/pipeline logic is exercised with a small
fake session, so the mapping (inventory + findings -> stored CycloneDX) and the guarantees (one SBOM
per scan, replace-not-accumulate, never fatal) are testable without Postgres.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.sbom import Component, Vulnerability, build_sbom
from guardian_db.sbom_store import load_sbom, store_sbom


class _Query:
    def __init__(self, result):
        self._result = result

    def filter(self, *a, **k):  # noqa: ANN002, ANN003
        return self

    def first(self):
        return self._result


class _Session:
    """Just enough Session for the store: a canned query result and an add-list."""

    def __init__(self, existing=None):
        self.existing = existing
        self.added = []

    def query(self, _model):  # noqa: ANN001
        return _Query(self.existing)

    def add(self, obj):  # noqa: ANN001
        self.added.append(obj)


_TID = uuid.uuid4()
_CID = uuid.uuid4()
_SID = uuid.uuid4()
_AID = uuid.uuid4()


def _sbom():
    return build_sbom(
        [Component("Flask", "2.0.1", "pypi", "requirements.txt")],
        [Vulnerability("CVE-2020-1", "high", "Flask", "2.0.1", "pypi")],
        subject_name="acme/app",
    )


# ── store ─────────────────────────────────────────────────────────────────────────────────────────
def test_store_sbom_inserts_a_scoped_record():
    session = _Session(existing=None)
    rec = store_sbom(session, tenant_id=_TID, customer_id=_CID, scan_id=_SID, asset_id=_AID,
                     sbom=_sbom())
    assert rec in session.added
    assert rec.tenant_id == _TID and rec.scan_id == _SID
    assert rec.component_count == 1 and rec.vulnerable_count == 1
    assert rec.document["bomFormat"] == "CycloneDX"


def test_store_sbom_replaces_rather_than_accumulates():
    existing = SimpleNamespace(document={}, component_count=0, vulnerable_count=0,
                               bom_format="", spec_version="")
    session = _Session(existing=existing)
    rec = store_sbom(session, tenant_id=_TID, customer_id=_CID, scan_id=_SID, asset_id=_AID,
                     sbom=_sbom())
    assert rec is existing            # updated in place
    assert session.added == []        # nothing new inserted
    assert existing.component_count == 1
    assert existing.document["specVersion"] == "1.5"


def test_load_sbom_uses_the_scoped_query():
    marker = object()
    assert load_sbom(_Session(existing=marker), scan_id=_SID, tenant_id=_TID) is marker


# ── pipeline hook (_maybe_store_sbom) ──────────────────────────────────────────────────────────────
class _StubSca:
    key = EngineKey.SCA

    def __init__(self, inventory):
        self._inv = inventory

    def collect_inventory(self, _ctx):  # noqa: ANN001
        return self._inv


def _raw(pkg, ver, eco, cve):
    return RawFinding(
        engine=EngineKey.SCA, title=f"{pkg}@{ver}", category="vuln-dep",
        description="vuln", base_severity=Severity.HIGH, cve_ids=[cve],
        location={"package": pkg, "version": ver, "ecosystem": eco},
    )


def test_maybe_store_sbom_builds_from_inventory_and_findings(monkeypatch):
    from guardian_scanner import tasks

    captured = {}

    def _fake_store(session, *, tenant_id, customer_id, scan_id, asset_id, sbom):  # noqa: ANN001
        captured["sbom"] = sbom
        captured["scan_id"] = scan_id

    monkeypatch.setattr(tasks, "store_sbom", _fake_store)
    engine = _StubSca([("flask", "2.0.1", "pypi", "requirements.txt"),
                       ("requests", "2.25.0", "pypi", "requirements.txt")])
    scan = SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID)
    asset = SimpleNamespace(id=_AID, identifier="acme/app", name="app")
    raws = [_raw("flask", "2.0.1", "pypi", "CVE-2020-1")]

    tasks._maybe_store_sbom(object(), engine, object(), scan, asset, raws)

    sbom = captured["sbom"]
    assert captured["scan_id"] == _SID
    assert sbom.component_count == 2      # both dependencies inventoried
    assert sbom.vulnerable_count == 1     # only flask has a finding
    ids = [v["id"] for v in sbom.document["vulnerabilities"]]
    assert ids == ["CVE-2020-1"]


def test_maybe_store_sbom_is_a_noop_without_inventory(monkeypatch):
    from guardian_scanner import tasks

    called = {"n": 0}
    monkeypatch.setattr(tasks, "store_sbom", lambda *a, **k: called.__setitem__("n", 1))
    engine = _StubSca([])
    scan = SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID)
    asset = SimpleNamespace(id=_AID, identifier="x", name="x")
    tasks._maybe_store_sbom(object(), engine, object(), scan, asset, [])
    assert called["n"] == 0               # nothing to store, store not called


def test_maybe_store_sbom_never_raises(monkeypatch):
    from guardian_scanner import tasks

    def _boom(*a, **k):  # noqa: ANN002, ANN003
        raise RuntimeError("db down")

    monkeypatch.setattr(tasks, "store_sbom", _boom)
    engine = _StubSca([("flask", "2.0.1", "pypi", "requirements.txt")])
    scan = SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID)
    asset = SimpleNamespace(id=_AID, identifier="x", name="x")
    # A storage failure must never propagate out of the scan pipeline.
    tasks._maybe_store_sbom(object(), engine, object(), scan, asset, [])
