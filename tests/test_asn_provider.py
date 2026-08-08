"""Passive ASN/RIR provider tests (Phase 6F-b) — offline, deterministic, fail-safe. No network."""

from __future__ import annotations

from guardian_core.discovery import DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType
from guardian_scanner.discovery.providers.asn_provider import AsnRirProvider


def _ctx(ips, asn_snapshot, allow_live=False):
    settings = {"asn": asn_snapshot}
    if allow_live:
        settings["allow_live"] = True
    return DiscoveryContext(tenant_id="t", run_id="r", seeds={"ips": ips}, settings=settings)


def test_offline_snapshot_produces_netblock_and_contains():
    ctx = _ctx(["1.2.3.4"], {"1.2.3.4": {"netblock": "1.2.3.0/24", "asn": 64500}})
    out = list(AsnRirProvider().collect(ctx))
    assert len(out) == 1
    a = out[0]
    assert a.node_type is NodeType.NETBLOCK
    assert a.canonical_key == "1.2.3.0/24"
    assert a.source is DiscoverySource.ASN_RIR
    assert a.attributes.get("asn") == 64500
    assert a.edges[0].relation is EdgeRelation.CONTAINS
    assert a.edges[0].dst_type is NodeType.IP_ADDRESS
    assert a.edges[0].dst_key == "1.2.3.4"


def test_provider_is_passive():
    assert AsnRirProvider().requires_authorization is False


def test_duplicate_ip_inputs_are_collapsed():
    ctx = _ctx(["1.2.3.4", "1.2.3.4", "1.2.3.4"], {"1.2.3.4": {"netblock": "1.2.3.0/24"}})
    assert len(list(AsnRirProvider().collect(ctx))) == 1


def test_malformed_cidr_is_skipped_failsafe():
    ctx = _ctx(["9.9.9.9"], {"9.9.9.9": {"netblock": "NOT-A-CIDR"}})
    assert list(AsnRirProvider().collect(ctx)) == []


def test_no_snapshot_yields_nothing_offline():
    ctx = _ctx(["1.2.3.4"], {})  # no snapshot, allow_live off → no live lookup, nothing
    assert list(AsnRirProvider().collect(ctx)) == []


def test_empty_ip_input_yields_nothing():
    assert list(AsnRirProvider().collect(_ctx([], {"1.2.3.4": {"netblock": "1.2.3.0/24"}}))) == []
