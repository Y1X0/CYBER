"""Worker-sandbox unit tests (Phase 5A hard gate). POSIX-only (fork); skipped elsewhere."""

from __future__ import annotations

import os
import socket

import pytest
from guardian_core.enums import EngineKey

sandbox = pytest.importorskip("guardian_scanner.sandbox")

pytestmark = pytest.mark.skipif(not sandbox.supported(), reason="fork-based sandbox is POSIX-only")


def test_returns_value_from_child():
    result = sandbox.run_in_sandbox(lambda: sum(range(1000)), sandbox.SandboxPolicy())
    assert result == sum(range(1000))


def test_child_exception_becomes_violation_not_crash():
    def boom():
        raise ValueError("engine blew up on hostile input")

    with pytest.raises(sandbox.SandboxViolation) as ei:
        sandbox.run_in_sandbox(boom, sandbox.SandboxPolicy())
    assert "ValueError" in str(ei.value)


def test_cpu_limit_kills_runaway_work():
    """A CPU-bound infinite loop is hard-killed by RLIMIT_CPU / the wall-clock alarm."""
    def spin():
        while True:
            pass

    policy = sandbox.SandboxPolicy(cpu_seconds=1, wall_seconds=3)
    with pytest.raises(sandbox.SandboxViolation) as ei:
        sandbox.run_in_sandbox(spin, policy)
    assert "signal" in str(ei.value).lower()


def test_egress_denied_by_default():
    def open_inet_socket():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        return "opened"

    with pytest.raises(sandbox.SandboxViolation) as ei:
        sandbox.run_in_sandbox(open_inet_socket, sandbox.SandboxPolicy(allow_network=False))
    assert "egress" in str(ei.value).lower() or "PermissionError" in str(ei.value)


def test_egress_allowed_for_network_engines():
    def open_inet_socket():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        return "opened"

    assert sandbox.run_in_sandbox(open_inet_socket, sandbox.SandboxPolicy(allow_network=True)) == "opened"


def test_runs_in_isolated_scratch_dir():
    parent_cwd = os.getcwd()
    child_cwd = sandbox.run_in_sandbox(os.getcwd, sandbox.SandboxPolicy())
    assert child_cwd != parent_cwd
    assert "guardian-sbx-" in child_cwd
    assert not os.path.exists(child_cwd)  # cleaned up after the child exits
    assert os.getcwd() == parent_cwd  # parent's cwd is untouched


def test_policy_grants_network_only_to_active_target_engines():
    assert sandbox.policy_for(EngineKey.DAST).allow_network is True
    assert sandbox.policy_for(EngineKey.API).allow_network is True
    for k in (EngineKey.SAST, EngineKey.SECRETS, EngineKey.SCA, EngineKey.CSPM,
              EngineKey.CONTAINER, EngineKey.K8S):
        assert sandbox.policy_for(k).allow_network is False
