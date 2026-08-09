"""Tool execution primitive (Framework Phase 1) — backend-selected, DB-less isolation.

`execute_tool` selects an execution backend (chosen by the Control Plane and carried on the ToolJob)
and runs the provider's callable inside it. The backend enforces isolation according to the job's
EffectiveScope — the provider never sees it:

  * `inproc`  — Phase-5 sandbox + Python egress guard (in-process/offline tools).
  * `uid_nft` — per-run uid + kernel nftables egress allowlist for external binaries (nmap).

The plane never sees a DB, KMS, RLS, tenant, finding, or asset — it returns RawEvidence and nothing
else.
"""

from __future__ import annotations

from guardian_common.ports import ToolProvider
from guardian_core.tool import RawEvidence, ToolJob

from guardian_scanner.tools.backends import get_backend


def execute_tool(provider: ToolProvider, job: ToolJob) -> list[RawEvidence]:
    """Run `provider.execute(job)` inside the scope-isolating backend chosen for the job. No DB."""
    provider.validate(job)  # validation is NOT authorization — the gate already ran upstream

    # The isolation backend is NOT downgradable from the job. An external-binary provider is FORCED
    # onto the kernel-isolating uid+nft backend by the trusted provider code, regardless of what the
    # (now-authenticated) job settings say — defense in depth so isolation can never be lowered.
    if getattr(provider, "external_binary", False):
        backend_name = "uid_nft"
    else:
        backend_name = (job.settings or {}).get("_execution_backend")
    backend = get_backend(backend_name)

    def _run() -> list[RawEvidence]:
        return list(provider.execute(job))

    return backend.run(job, _run)
