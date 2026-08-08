"""Recon result-return + execution hardening tests (Phase 6C.4) — mostly pure, no live DB.

Proves the security guarantees of the split: the recon plane touches no DB, an inherited DB FD is
unusable inside the sandbox child, the plane pinning fails a misroute, the egress allowlist cannot
leak across contexts, the process limit is applied, and the evidence wire format round-trips.
"""

from __future__ import annotations

import os
import socket
import threading

import pytest
from guardian_core.discovery import (
    DiscoveredAsset,
    DiscoveredEdge,
    asset_from_wire,
    asset_to_wire,
)
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType
from guardian_scanner import egress, sandbox

fork_only = pytest.mark.skipif(
    not sandbox.supported(), reason="fork-based sandbox is POSIX-only"
)


# ── A. the recon plane touches no database ──
def test_recon_collect_uses_no_database(monkeypatch):
    """recon_collect produces evidence WITHOUT any DB access — even if the DB session would explode."""
    from guardian_scanner.discovery import tasks

    def _boom(*_a, **_k):
        raise AssertionError("recon_collect must not open a DB session")

    monkeypatch.setattr(tasks, "session_scope", _boom)

    payload = {
        "tenant_id": "t", "run_id": "r", "customer_id": None,
        "providers": ["dns"], "seeds": {"domains": ["example.com"]},
        "authorized_targets": [],
        "settings": {"dns": {"example.com": ["93.184.216.34"]}},
    }
    evidence = tasks.recon_collect.apply(args=[payload]).get()
    assert evidence and all("node_type" in e for e in evidence)  # real evidence, no DB touched


# ── B. an inherited DB/socket FD is unusable inside the sandbox child ──
@fork_only
def test_inherited_fd_is_closed_in_sandbox_child():
    """A file descriptor open in the parent (stands in for a DB connection) is closed in the child,
    so untrusted probe code cannot reuse the parent's connection."""
    a, b = socket.socketpair()
    hi = 250
    os.dup2(a.fileno(), hi)  # force a high fd number so the child cannot accidentally reuse it
    try:
        def use_inherited():
            os.write(hi, b"x")  # EBADF if the child closed the inherited fd
            return "used"

        with pytest.raises(sandbox.SandboxViolation) as ei:
            sandbox.run_in_sandbox(use_inherited, sandbox.SandboxPolicy(allow_network=False))
        assert "Bad file descriptor" in str(ei.value) or "Errno 9" in str(ei.value)
    finally:
        os.close(hi)
        a.close()
        b.close()


# ── C. plane pinning: a misroute fails loudly (distributed mode) ──
def test_plane_pinning_rejects_misroute(monkeypatch):
    from guardian_scanner.celery_app import celery_app
    from guardian_scanner.discovery import tasks

    monkeypatch.setattr(celery_app.conf, "task_always_eager", False)  # simulate distributed mode

    class _S:
        recon_plane = False

    monkeypatch.setattr(tasks, "get_settings", lambda: _S())
    tasks._enforce_plane(expect_recon=False)                 # run_discovery on the DB plane: OK
    with pytest.raises(RuntimeError):
        tasks._enforce_plane(expect_recon=True)              # recon_collect on the DB plane: refuse

    class _S2:
        recon_plane = True

    monkeypatch.setattr(tasks, "get_settings", lambda: _S2())
    tasks._enforce_plane(expect_recon=True)                  # recon_collect on the recon plane: OK
    with pytest.raises(RuntimeError):
        tasks._enforce_plane(expect_recon=False)             # run_discovery on the recon plane: refuse


# ── D. egress allowlist is isolated per context (no cross-thread leak) ──
def test_egress_allowlist_does_not_leak_across_threads():
    seen: dict = {}

    def worker():
        seen["value"] = egress.current_allowlist()

    with egress.allowlist({"a.example.com"}):
        assert egress.current_allowlist() == frozenset({"a.example.com"})
        t = threading.Thread(target=worker)
        t.start()
        t.join()
    assert seen["value"] is None                # the other context never saw this allowlist
    assert egress.current_allowlist() is None   # restored after the context


# ── E. process limit is applied and the parent survives a fork-heavy child ──
@fork_only
def test_process_limit_applied_and_parent_survives():
    def read_cap():
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NPROC)
        return soft

    assert sandbox.run_in_sandbox(
        read_cap, sandbox.SandboxPolicy(max_processes=7, allow_network=False)
    ) == 7  # the cap is applied inside the child

    def forky():
        for _ in range(40):
            try:
                if os.fork() == 0:
                    os._exit(0)
            except OSError:
                break
        return "survived"

    sandbox.run_in_sandbox(
        forky, sandbox.SandboxPolicy(max_processes=8, wall_seconds=5, allow_network=False)
    )
    # the parent test process is undestabilized — a subsequent sandbox call still works
    assert sandbox.run_in_sandbox(lambda: 42, sandbox.SandboxPolicy(allow_network=False)) == 42


# ── evidence wire format round-trips (result-return serialization parity) ──
def test_evidence_wire_roundtrip():
    a = DiscoveredAsset(
        node_type=NodeType.SUBDOMAIN, canonical_key="api.example.com",
        source=DiscoverySource.DNS_RESOLVER, confidence=90, ownership_confidence=85,
        attributes={"public_dns": True, "internet_reachable": True},
        edges=[DiscoveredEdge(relation=EdgeRelation.RESOLVES_TO,
                              dst_type=NodeType.IP_ADDRESS, dst_key="1.2.3.4", confidence=90)],
    )
    back = asset_from_wire(asset_to_wire(a))
    assert back.node_type is NodeType.SUBDOMAIN
    assert back.canonical_key == "api.example.com"
    assert back.source is DiscoverySource.DNS_RESOLVER
    assert back.confidence == 90 and back.ownership_confidence == 85
    assert back.attributes == {"public_dns": True, "internet_reachable": True}
    assert back.edges[0].relation is EdgeRelation.RESOLVES_TO
    assert back.edges[0].dst_type is NodeType.IP_ADDRESS
    assert back.edges[0].dst_key == "1.2.3.4" and back.edges[0].confidence == 90
