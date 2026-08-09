"""Execution backends — the seam that isolates a tool run according to its EffectiveScope.

The Control Plane picks a backend name (from `tool_catalog.metadata["execution_backend"]`, or a code
default) and passes it on the ToolJob; `execute_tool` selects the backend here. The provider never
knows which backend runs it, never builds firewall rules, and never decides authorization.

  * `inproc`  — the Phase-5 sandbox + Python egress guard. Enough for in-process Python tools
    (web_tls) and offline tools (pcap, dns_posture).
  * `uid_nft` — for EXTERNAL binaries (nmap): a per-run unprivileged uid whose egress is confined at
    the Linux kernel by host nftables rules derived deterministically from the EffectiveScope.
"""

from __future__ import annotations


def get_backend(name: str | None):  # noqa: ANN201
    """Resolve a backend by name; unknown/None ⇒ the default in-process sandbox backend."""
    if name == "uid_nft":
        from guardian_scanner.tools.backends.uid_nft import UidNftBackend
        return UidNftBackend()
    from guardian_scanner.tools.backends.inproc import InprocSandboxBackend
    return InprocSandboxBackend()
