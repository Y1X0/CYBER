"""SBOM builder + SCA inventory hook.

The SBOM is a view over data the SCA engine already resolves, serialized to CycloneDX. The
load-bearing properties: PURLs are correct per ecosystem, the document is deterministic (so two
SBOMs of the same inventory diff cleanly), vulnerabilities reference the components they affect and
group by advisory id, and nothing is silently dropped or unbounded.
"""

from __future__ import annotations

import json

from guardian_core.sbom import (
    Component,
    Vulnerability,
    build_sbom,
    purl,
)
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.sca_engine import ScaEngine


# ── PURL mapping ──────────────────────────────────────────────────────────────────────────────────
def test_purl_maps_ecosystems_to_purl_types():
    assert purl("Flask", "2.0.1", "pypi") == "pkg:pypi/Flask@2.0.1"
    assert purl("lodash", "4.17.19", "npm") == "pkg:npm/lodash@4.17.19"
    assert purl("golang.org/x/net", "0.1.0", "go") == "pkg:golang/golang.org/x/net@0.1.0"
    assert purl("rails", "7.0.0", "rubygems") == "pkg:gem/rails@7.0.0"
    assert purl("serde", "1.0.0", "cargo") == "pkg:cargo/serde@1.0.0"
    assert purl("monolog/monolog", "2.0", "packagist") == "pkg:composer/monolog/monolog@2.0"


def test_purl_unknown_ecosystem_falls_back_to_its_own_label():
    assert purl("thing", "1.0", "weirdlang") == "pkg:weirdlang/thing@1.0"
    assert purl("thing", "1.0", "") == "pkg:generic/thing@1.0"


# ── document shape ──────────────────────────────────────────────────────────────────────────────
def test_build_sbom_is_cyclonedx_15_with_root_component():
    s = build_sbom([Component("Flask", "2.0.1", "pypi")], subject_name="acme/app")
    d = s.document
    assert d["bomFormat"] == "CycloneDX"
    assert d["specVersion"] == "1.5"
    assert d["metadata"]["component"]["name"] == "acme/app"
    assert d["components"][0]["purl"] == "pkg:pypi/Flask@2.0.1"
    assert d["components"][0]["bom-ref"] == "pkg:pypi/Flask@2.0.1"
    assert s.component_count == 1


def test_components_are_deduped_and_counted():
    comps = [Component("a", "1", "pypi"), Component("A", "1", "pypi"), Component("b", "2", "npm")]
    s = build_sbom(comps, subject_name="x")
    assert s.component_count == 2


def test_build_is_deterministic_regardless_of_input_order():
    comps = [Component("z", "1", "pypi"), Component("a", "2", "npm"), Component("m", "3", "pypi")]
    a = build_sbom(comps, subject_name="x")
    b = build_sbom(list(reversed(comps)), subject_name="x")
    assert json.dumps(a.document, sort_keys=True) == json.dumps(b.document, sort_keys=True)


def test_source_is_recorded_as_evidence_not_identity():
    s = build_sbom([Component("Flask", "2.0.1", "pypi", "requirements.txt")], subject_name="x")
    comp = s.document["components"][0]
    assert comp["evidence"]["identity"]["concludedValue"] == "requirements.txt"
    # source never leaks into the component's identity fields
    assert comp["name"] == "Flask" and comp["version"] == "2.0.1"


# ── vulnerabilities ─────────────────────────────────────────────────────────────────────────────
def test_vulnerability_references_the_component_it_affects():
    comps = [Component("lodash", "4.17.19", "npm")]
    vulns = [Vulnerability("CVE-2021-1", "high", "lodash", "4.17.19", "npm", "proto pollution")]
    s = build_sbom(comps, vulns, subject_name="x")
    v = s.document["vulnerabilities"][0]
    assert v["id"] == "CVE-2021-1"
    assert v["ratings"][0]["severity"] == "high"
    assert v["affects"] == [{"ref": "pkg:npm/lodash@4.17.19"}]
    assert s.vulnerable_count == 1


def test_one_advisory_affecting_two_components_is_one_entry():
    comps = [Component("a", "1", "pypi"), Component("b", "1", "pypi")]
    vulns = [
        Vulnerability("CVE-X", "medium", "a", "1", "pypi"),
        Vulnerability("CVE-X", "medium", "b", "1", "pypi"),
    ]
    s = build_sbom(comps, vulns, subject_name="x")
    entries = s.document["vulnerabilities"]
    assert len(entries) == 1
    assert {a["ref"] for a in entries[0]["affects"]} == {"pkg:pypi/a@1", "pkg:pypi/b@1"}
    assert s.vulnerable_count == 2


def test_no_vulnerabilities_section_when_there_are_none():
    s = build_sbom([Component("a", "1", "pypi")], subject_name="x")
    assert "vulnerabilities" not in s.document
    assert s.vulnerable_count == 0


def test_empty_inventory_yields_zero_components():
    s = build_sbom([], subject_name="x")
    assert s.component_count == 0
    assert s.document["components"] == []


# ── SCA inventory hook (the source of the SBOM) ─────────────────────────────────────────────────
def test_collect_inventory_returns_full_deduped_inventory():
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      inline_content="Flask==2.0.1\nrequests==2.25.0\nFlask==2.0.1\n")
    inv = ScaEngine().collect_inventory(ctx)
    names = sorted(n for (n, _v, _e, _s) in inv)
    assert names == ["flask", "requests"]
    assert all(eco == "pypi" for (_n, _v, eco, _s) in inv)


def test_collect_inventory_is_empty_without_dependencies():
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content="")
    assert ScaEngine().collect_inventory(ctx) == []
