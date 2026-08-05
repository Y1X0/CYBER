"""Canonicalization unit tests (Phase 6B) — the rule that collapses duplicates before the graph."""

from __future__ import annotations

from guardian_core.canonicalize import canonical_key
from guardian_core.enums import NodeType


def test_domain_case_trailing_dot_and_wildcard():
    assert canonical_key(NodeType.SUBDOMAIN, "API.EXAMPLE.com.") == "api.example.com"
    assert canonical_key(NodeType.SUBDOMAIN, "  api.example.com  ") == "api.example.com"
    assert canonical_key(NodeType.DOMAIN, "*.example.com") == "example.com"


def test_ip_normalization():
    # IPv6 forms collapse to the compressed canonical form.
    assert canonical_key(NodeType.IP_ADDRESS, "2001:0DB8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert canonical_key(NodeType.IP_ADDRESS, " 203.0.113.10 ") == "203.0.113.10"


def test_netblock_normalization():
    assert canonical_key(NodeType.NETBLOCK, "203.0.113.5/24") == "203.0.113.0/24"


def test_service_host_and_port():
    assert canonical_key(NodeType.SERVICE, "API.example.com:443") == "api.example.com:443"
    assert canonical_key(NodeType.SERVICE, "[2001:db8::1]:8080") == "2001:db8::1:8080"


def test_cloud_resource_preserves_case():
    arn = "arn:aws:s3:::My-Bucket"
    assert canonical_key(NodeType.CLOUD_RESOURCE, f"  {arn} ") == arn  # trimmed, not lowercased


def test_canonicalization_is_idempotent():
    for nt, raw in [
        (NodeType.SUBDOMAIN, "API.example.com."),
        (NodeType.IP_ADDRESS, "01.02.03.04"),
        (NodeType.SERVICE, "Host.example.com:8443"),
    ]:
        once = canonical_key(nt, raw)
        assert canonical_key(nt, once) == once


def test_unparseable_input_is_kept_not_dropped():
    assert canonical_key(NodeType.IP_ADDRESS, "not-an-ip") == "not-an-ip"
