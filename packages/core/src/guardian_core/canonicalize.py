"""Canonicalization — the single, deterministic rule for a node's identity key (Phase 6B).

This runs BEFORE any dedup or graph write: two observations of the same thing must collapse to the
same `canonical_key`, or the graph fills with phantom duplicates. `API.EXAMPLE.com.` and
`api.example.com` are the same subdomain; `1.2.3.4` and `01.2.3.004` the same IP; `[2001:db8::1]`
and `2001:0db8:0000::1` the same address. Pure and dependency-light so it's identical everywhere and
trivially testable.

Not a validator: unparseable input is lowered/stripped and returned as-is rather than rejected — a
collector may surface something odd, and losing it is worse than keeping a slightly-noisy key.
"""

from __future__ import annotations

import ipaddress

from guardian_core.enums import NodeType


def _canon_host(host: str) -> str:
    """Lowercase, strip a trailing dot and a leading wildcard, IDNA-normalize where possible."""
    h = host.strip().rstrip(".").lower()
    if h.startswith("*."):
        h = h[2:]
    if not h:
        return h
    try:
        # Normalize internationalized domains to punycode so unicode/ascii forms collapse.
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    return h


def _canon_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return raw.strip().lower()


def _canon_netblock(raw: str) -> str:
    try:
        return str(ipaddress.ip_network(raw.strip(), strict=False))
    except ValueError:
        return raw.strip().lower()


def _canon_service(raw: str) -> str:
    """`host:port` → canonical host + ':' + port. Host is normalized as an IP or a domain."""
    s = raw.strip()
    host, sep, port = s.rpartition(":")
    if not sep or not port.isdigit():
        return _canon_host(s)
    host = host.strip("[]")  # bracketed IPv6
    try:
        host_c = str(ipaddress.ip_address(host))
    except ValueError:
        host_c = _canon_host(host)
    return f"{host_c}:{int(port)}"


def canonical_key(node_type: NodeType | str, raw: str) -> str:
    """Deterministic identity key for a node of `node_type`. Idempotent: f(f(x)) == f(x)."""
    nt = node_type.value if isinstance(node_type, NodeType) else str(node_type)
    if nt in (NodeType.DOMAIN.value, NodeType.SUBDOMAIN.value):
        return _canon_host(raw)
    if nt == NodeType.IP_ADDRESS.value:
        return _canon_ip(raw)
    if nt == NodeType.NETBLOCK.value:
        return _canon_netblock(raw)
    if nt == NodeType.SERVICE.value:
        return _canon_service(raw)
    if nt == NodeType.CLOUD_RESOURCE.value:
        # ARNs/resource ids are case-sensitive in parts — only trim, don't lowercase.
        return raw.strip()
    return raw.strip().lower()
