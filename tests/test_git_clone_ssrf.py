"""git-clone SSRF + secret-scrub guards (P1-Ⓐ) — no network, no real clone.

`_prepare_workspace` clones a tenant-controlled repo URL on the DB/KMS-bearing scanner plane. Before
cloning it must refuse any host resolving to a private/loopback/link-local/metadata (incl.
IPv4-mapped-IPv6) address, disable redirects, and run git with a scrubbed, secret-free environment.
"""

from __future__ import annotations

import socket
import types

import pytest
from guardian_scanner import tasks


def _asset(identifier, config=None):
    return types.SimpleNamespace(kind="repo", identifier=identifier, config=config or {})


def _addrinfo(*ips):
    return [(0, socket.SOCK_STREAM, 0, "", (ip, 443)) for ip in ips]


class _RunSpy:
    def __init__(self):
        self.argv = None
        self.env = None

    def __call__(self, argv, *a, **k):
        self.argv = argv
        self.env = k.get("env")
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


@pytest.fixture()
def spy(monkeypatch):
    s = _RunSpy()
    monkeypatch.setattr(tasks.subprocess, "run", s)
    monkeypatch.setattr(tasks.tempfile, "mkdtemp", lambda *a, **k: "/tmp/guardian_ws_test")  # noqa: S108
    return s


# ── public target is allowed and actually clones ────────────────────────────────────────────────
def test_public_target_is_cloned(monkeypatch, spy):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    ws, inline, cleanup = tasks._prepare_workspace(_asset("https://github.com/acme/app.git"))
    assert ws == "/tmp/guardian_ws_test" and inline is None                 # noqa: S108
    assert spy.argv[0] == "git" and "clone" in spy.argv                     # git was invoked


# ── internal targets are refused, and git is NEVER invoked ───────────────────────────────────────
@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1",
                                "::1", "fe80::1", "::ffff:169.254.169.254"])
def test_internal_targets_are_refused(monkeypatch, spy, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
    with pytest.raises(RuntimeError, match="refused"):
        tasks._prepare_workspace(_asset("http://internal.example/repo.git"))
    assert spy.argv is None                                                 # clone never ran


def test_rebinding_multi_record_is_refused(monkeypatch, spy):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: _addrinfo("93.184.216.34", "10.1.2.3"))
    with pytest.raises(RuntimeError, match="refused"):
        tasks._prepare_workspace(_asset("https://rebind.example/repo.git"))
    assert spy.argv is None


def test_ssh_host_is_validated(monkeypatch, spy):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("127.0.0.1"))
    with pytest.raises(RuntimeError, match="refused"):
        tasks._prepare_workspace(_asset("git@169.254.169.254:acme/app.git"))
    assert spy.argv is None


# ── the git subprocess inherits NO secret, and follows no redirect ───────────────────────────────
def test_git_env_has_no_worker_secrets(monkeypatch, spy):
    for k in ("GUARDIAN_ENCRYPTION_KEY", "GUARDIAN_JWT_SECRET", "GUARDIAN_BROKER_SEAL_KEY",
              "GUARDIAN_DATABASE_URL", "GUARDIAN_REDIS_URL"):
        monkeypatch.setenv(k, "super-secret-value")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    tasks._prepare_workspace(_asset("https://github.com/acme/app.git"))
    assert spy.env is not None
    assert not any(k.startswith("GUARDIAN_") for k in spy.env)              # no GUARDIAN_* inherited
    assert "super-secret-value" not in spy.env.values()                     # no secret VALUE leaked
    assert spy.env.get("GIT_TERMINAL_PROMPT") == "0"                        # no credential prompt
    assert spy.env.get("GIT_CONFIG_NOSYSTEM") == "1"                        # host config ignored


def test_redirects_are_disabled(monkeypatch, spy):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    tasks._prepare_workspace(_asset("https://github.com/acme/app.git"))
    assert "http.followRedirects=false" in spy.argv                        # a redirect can't bounce
    assert "credential.helper=" in spy.argv                                # no credential helper


# ── non-clone paths are unaffected ───────────────────────────────────────────────────────────────
def test_inline_content_bypasses_clone(spy):
    ws, inline, cleanup = tasks._prepare_workspace(
        _asset("https://github.com/acme/app.git", config={"inline_content": "x=1"}))
    assert inline == "x=1" and ws is None and spy.argv is None             # never resolves or clones


def test_unparseable_host_is_refused(spy):
    with pytest.raises(RuntimeError, match="unparseable"):
        tasks._prepare_workspace(_asset("http:///no-host/repo.git"))
    assert spy.argv is None
