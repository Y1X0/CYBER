"""Recon egress-allowlist tests (Phase 6C.3) — the second, independent egress defense layer.

These prove the CTO's 6C.3 guarantee at the *runtime* layer, with NO authorization gate and NO
database in the loop: a sandboxed probe can only reach a host on the run's allowlist, and any other
destination — an unauthorized target, or an internal service (DB/cache/metadata) — is blocked at the
socket layer. The allowlist is derived only from gate-cleared targets and never leaks past a run.
"""

from __future__ import annotations

import socket

import pytest
from guardian_scanner import egress, sandbox
from guardian_scanner.discovery.tasks import _egress_hosts

fork_only = pytest.mark.skipif(
    not sandbox.supported(), reason="fork-based sandbox is POSIX-only"
)


# ── the guard decision, in-process, deterministic (no fork, no network) ──────────────────────────
def test_allowlist_permits_only_listed_hosts(monkeypatch):
    """The guard delegates to the real connector for a listed host and blocks every other host.

    Independent of the authorization gate: enforcement is a re-check at socket.create_connection.
    """
    calls: list = []

    def fake_create_connection(address, *a, **k):  # stands in for the real connector
        calls.append(address)
        return "SOCK"

    # Monkeypatch first so the guard captures this stub as the "real" connector; monkeypatch also
    # restores the original create_connection at teardown, undoing the guard install below.
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    sandbox._install_egress_allowlist(frozenset({"93.184.216.34"}))

    assert socket.create_connection(("93.184.216.34", 443)) == "SOCK"  # listed → delegated
    assert calls == [("93.184.216.34", 443)]

    with pytest.raises(PermissionError, match="not in the recon allowlist"):
        socket.create_connection(("10.0.0.5", 443))  # unlisted → blocked before any connect
    assert calls == [("93.184.216.34", 443)]  # the blocked host never reached the real connector


def test_empty_allowlist_denies_everything(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: "SOCK")
    sandbox._install_egress_allowlist(frozenset())
    with pytest.raises(PermissionError):
        socket.create_connection(("93.184.216.34", 443))


# ── end-to-end enforcement inside the real forked sandbox ────────────────────────────────────────
@fork_only
def test_unauthorized_egress_blocked_in_sandbox():
    """A probe to a host outside the allowlist is contained by the sandbox — gate not involved."""
    with egress.allowlist({"93.184.216.34"}):
        def reach_unauthorized():
            import socket as s
            s.create_connection(("10.0.0.5", 443), timeout=1)
            return "connected"

        with pytest.raises(sandbox.SandboxViolation) as ei:
            sandbox.run_in_sandbox(reach_unauthorized, sandbox.SandboxPolicy(allow_network=True))
    assert "allowlist" in str(ei.value).lower()


@fork_only
def test_recon_cannot_reach_internal_services():
    """With only an external target allowed, internal services stay unreachable from a probe."""
    with egress.allowlist({"93.184.216.34"}):
        for internal in ("db", "redis", "127.0.0.1", "169.254.169.254"):
            def reach(host=internal):
                import socket as s
                s.create_connection((host, 5432), timeout=1)
                return "connected"

            with pytest.raises(sandbox.SandboxViolation) as ei:
                sandbox.run_in_sandbox(reach, sandbox.SandboxPolicy(allow_network=True))
            assert "allowlist" in str(ei.value).lower()


@fork_only
def test_resource_containment_holds_with_allowlist():
    """The egress layer does not weaken resource containment: a runaway is still hard-killed."""
    with egress.allowlist({"93.184.216.34"}):
        def spin():
            while True:
                pass

        with pytest.raises(sandbox.SandboxViolation) as ei:
            sandbox.run_in_sandbox(spin, sandbox.SandboxPolicy(
                cpu_seconds=1, wall_seconds=3, allow_network=True))
    assert "signal" in str(ei.value).lower()


@fork_only
def test_no_allowlist_leaves_network_engines_unrestricted():
    """No recon allowlist active (None) → network-permitted work is unchanged (DAST/API path)."""
    assert egress.current_allowlist() is None

    def make_socket():
        import socket as s
        sk = s.socket(s.AF_INET, s.SOCK_STREAM)
        sk.close()
        return "ok"

    assert sandbox.run_in_sandbox(make_socket, sandbox.SandboxPolicy(allow_network=True)) == "ok"


# ── derivation + no-leak (the allowlist is bound to the gate's cleared targets, per run) ──────────
def test_egress_hosts_derived_from_gate_cleared_targets():
    assert _egress_hosts(["93.184.216.34:443", "example.com", "10.0.0.1:80"]) == frozenset(
        {"93.184.216.34", "example.com", "10.0.0.1"}
    )
    assert _egress_hosts([]) == frozenset()


def test_allowlist_restored_after_context():
    assert egress.current_allowlist() is None
    with egress.allowlist({"a"}):
        assert egress.current_allowlist() == frozenset({"a"})
        with egress.allowlist({"b"}):
            assert egress.current_allowlist() == frozenset({"b"})
        assert egress.current_allowlist() == frozenset({"a"})
    assert egress.current_allowlist() is None


def test_allowlist_restored_even_on_error():
    assert egress.current_allowlist() is None
    with pytest.raises(ValueError, match="boom"), egress.allowlist({"a"}):
        raise ValueError("boom")
    assert egress.current_allowlist() is None  # restored despite the exception
