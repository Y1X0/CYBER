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


# ── SSRF / DNS-rebinding guard (6C.3.1): a listed hostname that resolves to an internal IP ─────────
def _install_with_resolver(monkeypatch, allowlist_hosts, resolved_ip):
    """Install the guard with a stubbed connector + resolver, returning the connection call log.

    The stub resolver makes the (authorized) hostname resolve to `resolved_ip`, so the test controls
    DNS deterministically and no real network is touched.
    """
    connected: list = []

    def fake_create_connection(address, *a, **k):
        connected.append(address)
        return "SOCK"

    def fake_getaddrinfo(host, port, *a, **k):
        fam = socket.AF_INET6 if ":" in resolved_ip else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 6, "", (resolved_ip, port or 0))]

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    sandbox._install_egress_allowlist(frozenset(allowlist_hosts))
    return connected


def test_authorized_domain_resolving_to_private_ip_is_blocked(monkeypatch):
    """THE 6C.3.1 proof: an authorized hostname that resolves to a private IP is blocked, and the
    real connection is NEVER attempted."""
    connected = _install_with_resolver(monkeypatch, {"evil.example.com"}, "10.0.0.7")
    with pytest.raises(PermissionError, match="internal address"):
        socket.create_connection(("evil.example.com", 443))
    assert connected == []  # fail-closed BEFORE any socket to the internal address


def test_authorized_domain_resolving_to_metadata_endpoint_is_blocked(monkeypatch):
    """The cloud metadata endpoint (link-local) is rejected even for an authorized hostname."""
    connected = _install_with_resolver(monkeypatch, {"cloud.example.com"}, "169.254.169.254")
    with pytest.raises(PermissionError, match="internal address"):
        socket.create_connection(("cloud.example.com", 80))
    assert connected == []


def test_authorized_domain_resolving_to_loopback_is_blocked(monkeypatch):
    connected = _install_with_resolver(monkeypatch, {"local.example.com"}, "127.0.0.1")
    with pytest.raises(PermissionError, match="internal address"):
        socket.create_connection(("local.example.com", 8000))
    assert connected == []


def test_ipv4_mapped_ipv6_internal_is_blocked(monkeypatch):
    """An IPv4-mapped IPv6 resolution to an internal address cannot slip past the guard."""
    connected = _install_with_resolver(monkeypatch, {"mapped.example.com"}, "::ffff:169.254.169.254")
    with pytest.raises(PermissionError, match="internal address"):
        socket.create_connection(("mapped.example.com", 80))
    assert connected == []


def test_public_authorized_domain_is_allowed_and_pinned(monkeypatch):
    """A public authorized hostname still works — and is pinned to the validated IP (TOCTOU-safe)."""
    connected = _install_with_resolver(monkeypatch, {"example.com"}, "93.184.216.34")
    assert socket.create_connection(("example.com", 443)) == "SOCK"
    assert connected == [("93.184.216.34", 443)]  # connected to the validated IP, not the hostname


def test_explicitly_authorized_internal_ip_is_allowed(monkeypatch):
    """An IP literal that is itself on the allowlist is honored as-is — a deliberate operator choice,
    not a rebind — so it is never resolved nor blocked."""
    connected: list = []
    monkeypatch.setattr(socket, "create_connection",
                        lambda address, *a, **k: connected.append(address) or "SOCK")

    def _boom(*_a, **_k):  # resolution must NOT happen for an IP literal
        raise AssertionError("an authorized IP literal must not be resolved")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    sandbox._install_egress_allowlist(frozenset({"10.0.0.9"}))
    assert socket.create_connection(("10.0.0.9", 22)) == "SOCK"
    assert connected == [("10.0.0.9", 22)]


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
