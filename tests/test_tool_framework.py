"""Security Tool Execution Framework — pure contracts (Framework Phase 1). No DB.

Proves the security rails: EffectiveScope never widens beyond an authorization; the policy gate denies
(or requires approval) BEFORE execution; the execution primitive is sandboxed + egress-scoped; and
evidence content is scrubbed of secrets.
"""

from __future__ import annotations

import pytest
from guardian_common.ports import NullToolProvider, ToolProvider
from guardian_core.tool import (
    RawEvidence,
    ToolCapabilities,
    ToolJob,
    derive_effective_scope,
    evaluate_tool_policy,
)
from guardian_scanner import sandbox
from guardian_scanner.tools.evidence import _scrub

fork_only = pytest.mark.skipif(
    not sandbox.supported(), reason="fork-based sandbox is POSIX-only"
)


# ── EffectiveScope never widens beyond the authorization ──
def test_scope_is_intersection_never_wider_than_authorization():
    caps = ToolCapabilities(category="net", network=True, active=True, ports=(80, 443, 22))
    scope = derive_effective_scope(
        requested_targets=["example.com", "evil.com"],           # evil.com is NOT authorized
        authorized_targets=["example.com", "api.example.com"],
        capabilities=caps,
        policy={"ports": [443]},                                  # policy narrows ports
    )
    assert scope.targets == ("example.com",)                     # only the authorized ∩ requested
    assert "evil.com" not in scope.targets
    assert scope.ports == (443,)                                  # policy narrowed 80/443/22 → 443
    assert scope.network_allowed is True
    assert scope.read_only is True                               # non-destructive


def test_scope_defaults_to_full_authorization_when_nothing_requested():
    caps = ToolCapabilities(category="net")
    scope = derive_effective_scope([], ["a.example.com", "b.example.com"], caps)
    assert scope.targets == ("a.example.com", "b.example.com")


def test_policy_denies_without_in_scope_target():
    caps = ToolCapabilities(category="net", requires_authorization=True)
    scope = derive_effective_scope(["x.com"], ["y.com"], caps)   # no overlap → empty
    d = evaluate_tool_policy(caps, scope)
    assert d.allowed is False and "no in-scope authorized target" in d.reasons


def test_policy_requires_human_approval_for_active_tool():
    caps = ToolCapabilities(category="net", network=True, active=True,
                            requires_human_approval=True)
    scope = derive_effective_scope(["a.com"], ["a.com"], caps)
    assert evaluate_tool_policy(caps, scope, human_approved=False).allowed is False
    ok = evaluate_tool_policy(caps, scope, human_approved=True)
    assert ok.allowed is True and ok.requires_human_approval is True


def test_policy_denies_destructive_without_approval():
    caps = ToolCapabilities(category="net", destructive=True)
    scope = derive_effective_scope(["a.com"], ["a.com"], caps, {"allow_destructive": True})
    assert scope.read_only is False
    assert evaluate_tool_policy(caps, scope, human_approved=False).allowed is False
    assert evaluate_tool_policy(caps, scope, human_approved=True).allowed is True


def test_passive_in_scope_tool_is_allowed():
    caps = ToolCapabilities(category="analysis", network=False, active=False)
    scope = derive_effective_scope(["a.com"], ["a.com"], caps)
    d = evaluate_tool_policy(caps, scope)
    assert d.allowed is True and d.requires_human_approval is False


# ── the provider never authorizes itself; Null default is structural ──
def test_null_tool_provider_satisfies_contract():
    assert isinstance(NullToolProvider(), ToolProvider)
    assert not hasattr(NullToolProvider, "authorize")  # a provider cannot grant itself authorization


# ── execution primitive: sandboxed, DB-less, egress bound to scope ──
class _EchoProvider:
    key, name, version = "echo", "echo", "1"

    @property
    def capabilities(self):  # noqa: ANN201
        return ToolCapabilities(category="test", network=False, active=False)

    def validate(self, job):  # noqa: ANN001, ANN201
        return None

    def execute(self, job):  # noqa: ANN001, ANN201
        for t in job.scope.targets:
            yield RawEvidence(tool="echo", execution_id=job.job_id, target=t, kind="echo",
                              data={"ok": True})

    def normalize(self, evidence):  # noqa: ANN001, ANN201
        return None


def _job(scope_targets, network=False):
    from guardian_core.tool import EffectiveScope
    scope = EffectiveScope(targets=tuple(scope_targets), ports=(), protocols=(),
                           network_allowed=network, read_only=True)
    return ToolJob(tenant_id="t", job_id="j1", tool_key="echo", scope=scope)


@fork_only
def test_execute_tool_runs_sandboxed_and_returns_evidence():
    from guardian_scanner.tools.execution import execute_tool
    ev = execute_tool(_EchoProvider(), _job(["a.example.com"]))
    assert len(ev) == 1 and ev[0].target == "a.example.com" and ev[0].data == {"ok": True}


@fork_only
def test_execute_tool_egress_bound_to_scope():
    """A network tool reaching an OUT-OF-SCOPE host is blocked by the scope's egress allowlist."""
    from guardian_core.tool import EffectiveScope
    from guardian_scanner.tools.execution import execute_tool

    class _OutOfScope(_EchoProvider):
        @property
        def capabilities(self):  # noqa: ANN201
            return ToolCapabilities(category="net", network=True, active=True)

        def execute(self, job):  # noqa: ANN001, ANN201
            import socket
            socket.create_connection(("9.9.9.9", 443), timeout=1)  # NOT in scope
            yield RawEvidence(tool="x", execution_id="j", target="9.9.9.9", kind="x")

    scope = EffectiveScope(targets=("1.2.3.4",), ports=(), protocols=(),
                           network_allowed=True, read_only=True)
    job = ToolJob(tenant_id="t", job_id="j", tool_key="x", scope=scope)
    assert execute_tool(_OutOfScope(), job) == []  # contained: out-of-scope egress denied


# ── plane pinning: a misroute fails loudly (distributed mode) ──
def test_tool_plane_pinning_rejects_misroute(monkeypatch):
    from guardian_scanner.celery_app import celery_app
    from guardian_scanner.tools import tasks

    monkeypatch.setattr(celery_app.conf, "task_always_eager", False)

    class _S:
        tool_plane = False

    monkeypatch.setattr(tasks, "get_settings", lambda: _S())
    tasks._enforce_tool_plane(expect_tool=False)                 # dispatcher on Control Plane: OK
    with pytest.raises(RuntimeError):
        tasks._enforce_tool_plane(expect_tool=True)              # run_tool on Control Plane: refuse

    class _S2:
        tool_plane = True

    monkeypatch.setattr(tasks, "get_settings", lambda: _S2())
    tasks._enforce_tool_plane(expect_tool=True)                  # run_tool on tools plane: OK
    with pytest.raises(RuntimeError):
        tasks._enforce_tool_plane(expect_tool=False)            # dispatcher on tools plane: refuse


# ── evidence scrub: a secret is never evidence ──
def test_scrub_removes_sensitive_keys():
    scrubbed = _scrub({"ok": 1, "password": "p", "nested": {"api_key": "k", "host": "h"}})
    assert scrubbed == {"ok": 1, "nested": {"host": "h"}}
