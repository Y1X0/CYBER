"""Execution-plane trust (Phase C) — run_tool authenticity + non-downgradable isolation backend.

No DB, no network. Proves a forged/tampered run_tool message is refused BEFORE any provider runs or
backend is built, that a valid signed job still executes, and that an external-binary provider is
forced onto the uid+nft backend regardless of what the job settings say.
"""

from __future__ import annotations

from guardian_common import replay
from guardian_common.job_signing import sign_job
from guardian_core.tool import EffectiveScope, RawEvidence, ToolJob, job_to_wire


class _Spy:
    key = "spy"
    version = "1"
    external_binary = False
    ran = False

    @property
    def capabilities(self):  # noqa: ANN201
        from guardian_core.tool import ToolCapabilities
        return ToolCapabilities(category="test", network=False, active=False)

    def validate(self, job):  # noqa: ANN001, ANN201
        return None

    def execute(self, job):  # noqa: ANN001, ANN201
        type(self).ran = True
        yield RawEvidence(tool="spy", execution_id=job.job_id, target="x", kind="spy", data={})

    def normalize(self, evidence):  # noqa: ANN001, ANN201
        return None


def _wire(backend="inproc", tool="spy"):
    job = ToolJob(tenant_id="t", job_id="j1", tool_key=tool,
                  scope=EffectiveScope(targets=("1.2.3.4",), ports=(80,), protocols=("tcp",),
                                       network_allowed=False, read_only=True),
                  settings={"_execution_backend": backend})
    return job_to_wire(job)


def _install_spy(monkeypatch, external=False):
    from guardian_scanner.tools import registry
    spy = _Spy()
    spy.external_binary = external
    _Spy.ran = False
    monkeypatch.setattr(registry, "tool_for", lambda k: spy if k == "spy" else None)
    return spy


def test_forged_unsigned_message_rejected_before_provider(monkeypatch):
    from guardian_scanner.tools.tasks import run_tool
    replay.reset_local_for_tests()
    _install_spy(monkeypatch)
    forged = {"job": _wire(), "issued_at": "x", "expires_at": "x", "nonce": "n", "sig": "AA=="}
    result = run_tool.apply(args=[forged]).get()
    assert result == []                                  # refused
    assert _Spy.ran is False                             # provider NEVER ran


def test_tampered_scope_message_rejected_before_provider(monkeypatch):
    from guardian_scanner.tools.tasks import run_tool
    replay.reset_local_for_tests()
    _install_spy(monkeypatch)
    signed = sign_job(_wire())
    signed["job"]["scope"]["targets"] = ["9.9.9.9"]      # attacker rewrites the scope after signing
    result = run_tool.apply(args=[signed]).get()
    assert result == [] and _Spy.ran is False            # kernel allowlist never built from this


def test_valid_signed_message_executes(monkeypatch):
    from guardian_scanner.tools.tasks import run_tool
    replay.reset_local_for_tests()
    _install_spy(monkeypatch)
    # The provider runs in the sandbox fork, so its evidence (not a parent-side flag) proves it ran.
    result = run_tool.apply(args=[sign_job(_wire())]).get()
    assert len(result) == 1 and result[0]["kind"] == "spy"   # authenticated ⇒ runs normally


def _record_backend(chosen):
    def _get(name):
        chosen["name"] = name
        return _NullBackend()
    return _get


def test_external_binary_backend_cannot_be_downgraded(monkeypatch):
    # Even with settings _execution_backend="inproc", an external-binary provider is forced to uid_nft.
    import guardian_scanner.tools.execution as ex
    chosen = {}
    monkeypatch.setattr(ex, "get_backend", _record_backend(chosen))
    spy = _install_spy(monkeypatch, external=True)
    job = ToolJob(tenant_id="t", job_id="j", tool_key="spy",
                  scope=EffectiveScope(targets=("1.2.3.4",), ports=(80,), protocols=("tcp",),
                                       network_allowed=True, read_only=True),
                  settings={"_execution_backend": "inproc"})   # attacker asks for inproc
    ex.execute_tool(spy, job)
    assert chosen["name"] == "uid_nft"                    # forced by trusted provider code


def test_non_external_provider_uses_job_backend(monkeypatch):
    import guardian_scanner.tools.execution as ex
    chosen = {}
    monkeypatch.setattr(ex, "get_backend", _record_backend(chosen))
    spy = _install_spy(monkeypatch, external=False)
    job = ToolJob(tenant_id="t", job_id="j", tool_key="spy",
                  scope=EffectiveScope(targets=(), ports=(), protocols=(),
                                       network_allowed=False, read_only=True),
                  settings={"_execution_backend": "inproc"})
    ex.execute_tool(spy, job)
    assert chosen["name"] == "inproc"


class _NullBackend:
    def run(self, job, fn):  # noqa: ANN001, ANN201
        return []
