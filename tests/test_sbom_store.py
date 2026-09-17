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


# ── pipeline hooks (_accumulate_sbom + _finalize_sbom) ──────────────────────────────────────────────
def _raw(pkg, ver, eco, cve):
    return RawFinding(
        engine=EngineKey.SCA, title=f"{pkg}@{ver}", category="vuln-dep",
        description="vuln", base_severity=Severity.HIGH, cve_ids=[cve],
        location={"package": pkg, "version": ver, "ecosystem": eco},
    )


def test_sbom_merges_inventory_from_multiple_engines(monkeypatch):
    """The load-bearing new behaviour: one SBOM per scan, merged across engines."""
    from guardian_scanner import tasks

    captured = {}
    monkeypatch.setattr(tasks, "store_sbom",
                        lambda session, **kw: captured.update(kw))  # noqa: ANN001

    inv: list = []
    vulns: list = []
    # An SCA engine (repo deps) and a container engine (image packages) in the same scan. The
    # engine already collected its inventory (in-process, or on the scan plane) — _accumulate_sbom
    # merges those lists, it no longer re-runs collect_inventory.
    sca_inv = [("flask", "2.0.1", "pypi", "requirements.txt")]
    container_inv = [("openssl", "3.0.2", "Debian", "dpkg")]
    tasks._accumulate_sbom(sca_inv, [_raw("flask", "2.0.1", "pypi", "CVE-2020-1")], inv, vulns)
    tasks._accumulate_sbom(container_inv, [], inv, vulns)

    scan = SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID)
    asset = SimpleNamespace(id=_AID, identifier="acme/app", name="app")
    tasks._finalize_sbom(object(), scan, asset, inv, vulns)

    sbom = captured["sbom"]
    assert sbom.component_count == 2          # flask (pypi) + openssl (deb), merged
    assert sbom.vulnerable_count == 1         # only flask carries a finding
    purls = {c["purl"] for c in sbom.document["components"]}
    assert "pkg:pypi/flask@2.0.1" in purls and "pkg:deb/openssl@3.0.2" in purls


def test_a_versionless_component_is_included(monkeypatch):
    """Android native libs / iOS dylibs have no version — they still belong in the inventory."""
    from guardian_scanner import tasks

    captured = {}
    monkeypatch.setattr(tasks, "store_sbom", lambda session, **kw: captured.update(kw))  # noqa: ANN001
    inv: list = []
    tasks._accumulate_sbom([("libssl.so", "", "android-native", "lib/arm64/libssl.so")],
                           [], inv, [])
    tasks._finalize_sbom(object(), SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID),
                         SimpleNamespace(id=_AID, identifier="app", name="app"), inv, [])
    comp = captured["sbom"].document["components"][0]
    assert comp["purl"] == "pkg:generic/libssl.so" and "version" not in comp


def test_finalize_is_a_noop_without_inventory(monkeypatch):
    from guardian_scanner import tasks

    called = {"n": 0}
    monkeypatch.setattr(tasks, "store_sbom", lambda *a, **k: called.__setitem__("n", 1))
    tasks._finalize_sbom(object(), SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID),
                         SimpleNamespace(id=_AID, identifier="x", name="x"), [], [])
    assert called["n"] == 0               # nothing to store, store not called


def test_collect_inventory_never_raises_on_a_bad_engine():
    # The "never fatal" guarantee for collect_inventory now lives in _collect_inventory (which runs
    # where the engine runs — the scan plane when offloaded), not in _accumulate_sbom.
    from guardian_scanner.scan_plane import _collect_inventory

    class _Boom:
        def collect_inventory(self, _ctx):  # noqa: ANN001
            raise RuntimeError("walk failed")

    assert _collect_inventory(_Boom(), object()) == []


def test_accumulate_never_raises_on_a_bad_inventory_row():
    from guardian_scanner import tasks

    inv: list = []
    # A malformed inventory row (wrong arity) must not propagate out of the scan pipeline.
    tasks._accumulate_sbom([("only", "three", "cols")], [], inv, [])
    assert inv == []


def test_finalize_never_raises(monkeypatch):
    from guardian_scanner import tasks

    def _boom(*a, **k):  # noqa: ANN002, ANN003
        raise RuntimeError("db down")

    monkeypatch.setattr(tasks, "store_sbom", _boom)
    inv = [Component("flask", "2.0.1", "pypi", "requirements.txt")]
    # A storage failure must never propagate out of the scan pipeline.
    tasks._finalize_sbom(object(), SimpleNamespace(id=_SID, tenant_id=_TID, customer_id=_CID),
                         SimpleNamespace(id=_AID, identifier="x", name="x"), inv, [])
