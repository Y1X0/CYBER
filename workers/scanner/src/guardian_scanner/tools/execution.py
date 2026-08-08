"""Tool execution primitive (Framework Phase 1) — DB-less, sandboxed, egress-scoped.

Generalizes the 6C.4 recon result-return to arbitrary tools: a provider's `execute` runs inside the
Phase-5 sandbox (mandatory) with NO database and its egress bound to the job's EffectiveScope — the
exact same allowlist + SSRF/DNS-rebinding + IP-pinning guards recon uses. A non-network tool gets
the full egress block; a network tool reaches ONLY its in-scope targets. The plane never sees
a DB, KMS, RLS, or another tenant — it returns RawEvidence and nothing else.
"""

from __future__ import annotations

from guardian_common.ports import ToolProvider
from guardian_core.tool import RawEvidence, ToolJob

from guardian_scanner import egress, sandbox

_CPU_SECONDS = 30
_WALL_SECONDS = 60


def execute_tool(provider: ToolProvider, job: ToolJob) -> list[RawEvidence]:
    """Run `provider.execute(job)` in the sandbox with egress bound to the job's scope. No DB.

    Returns the collected RawEvidence. Sandbox violations are contained (empty result), so a tool
    crash never destabilizes the worker or corrupts graph state.
    """
    provider.validate(job)  # validation is NOT authorization — the gate already ran upstream

    policy = sandbox.SandboxPolicy(
        cpu_seconds=_CPU_SECONDS, wall_seconds=_WALL_SECONDS,
        allow_network=job.scope.network_allowed,
    )

    def _run() -> list[RawEvidence]:
        return list(provider.execute(job))

    try:
        if job.scope.network_allowed:
            # Egress bound to the in-scope targets (reuses the 6C.3/6C.4 allowlist + guards).
            hosts = frozenset(t.split(":")[0] for t in job.scope.targets if t)
            with egress.allowlist(hosts):
                return sandbox.run_in_sandbox(_run, policy)
        # Non-network tool: the sandbox denies all outbound sockets.
        return sandbox.run_in_sandbox(_run, policy)
    except sandbox.SandboxViolation:
        return []  # contained — no result, never a crash
