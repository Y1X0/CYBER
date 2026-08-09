"""In-process sandbox backend — the Phase-5 sandbox + Python-socket egress guard.

Unchanged behavior from the original `execute_tool`: runs the provider's callable inside the fork
sandbox (rlimits, FD-close, temp isolation), and for a network-permitted tool binds the Python-level
egress allowlist to the in-scope targets. Sufficient for in-process Python tools and offline tools;
it does NOT confine an external binary's egress (that is `uid_nft`'s job).
"""

from __future__ import annotations

from collections.abc import Callable

from guardian_core.tool import RawEvidence, ToolJob

from guardian_scanner import egress, sandbox

_CPU_SECONDS = 30
_WALL_SECONDS = 60


class InprocSandboxBackend:
    def run(self, job: ToolJob, fn: Callable[[], list[RawEvidence]]) -> list[RawEvidence]:
        policy = sandbox.SandboxPolicy(
            cpu_seconds=_CPU_SECONDS, wall_seconds=_WALL_SECONDS,
            allow_network=job.scope.network_allowed,
        )
        try:
            if job.scope.network_allowed:
                hosts = frozenset(t.split(":")[0] for t in job.scope.targets if t)
                with egress.allowlist(hosts):
                    return sandbox.run_in_sandbox(fn, policy)
            return sandbox.run_in_sandbox(fn, policy)
        except sandbox.SandboxViolation:
            return []  # contained — no result, never a crash
