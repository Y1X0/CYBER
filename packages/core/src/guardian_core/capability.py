"""Capability classification (Phase A governance) — derive a tool's level from its primitives.

A tool never declares its own governance level or who may run it. The Control Plane derives a
`CapabilityLevel` deterministically from the `ToolCapabilities` primitives the provider declares,
and the governance policy is a function of that level. Adding a new tool = declaring primitives; the
governance (role ceiling, approval, campaign) then applies automatically — there is no per-tool
`if role == owner` anywhere, and no capability is ever "banned": the level only decides what it
takes to be allowed to run it.

Levels (governance framework, all architecturally supported):
  L0 PASSIVE_ANALYSIS   — offline, no network (pcap, dns_posture)
  L1 PASSIVE_NETWORK    — reads public/third-party data, non-active
  L2 ACTIVE_RECON       — actively touches a target, non-destructive (web_tls, nmap)
  L3 SENSITIVE          — higher-impact active / credential-adjacent testing
  L4 EXPLOIT_VALIDATION — payload used to prove, not to damage
  L5 DESTRUCTIVE        — can change target state

L3+ additionally require the campaign + approval machinery (Phase B); until that exists they are
recognized but not yet grantable — recognized, not forbidden.
"""

from __future__ import annotations

from enum import IntEnum

from guardian_core.tool import ToolCapabilities


class CapabilityLevel(IntEnum):
    PASSIVE_ANALYSIS = 0
    PASSIVE_NETWORK = 1
    ACTIVE_RECON = 2
    SENSITIVE = 3
    EXPLOIT_VALIDATION = 4
    DESTRUCTIVE = 5


# category hints that raise a tool above its primitive-derived floor (for future providers).
_EXPLOIT_CATEGORIES = frozenset({"exploit", "exploit_validation"})
# Active, higher-impact web checks (templated detection of exposed/sensitive resources) are L3:
# more intrusive than L2 recon, credential-adjacent, and gated by campaign + approval.
_SENSITIVE_CATEGORIES = frozenset(
    {"credential", "auth_testing", "credential_testing", "web_checks"}
)


def derive_capability_level(caps: ToolCapabilities) -> CapabilityLevel:
    """Deterministically map a provider's declared primitives to a governance level."""
    if caps.destructive:
        return CapabilityLevel.DESTRUCTIVE
    category = (caps.category or "").lower()
    if category in _EXPLOIT_CATEGORIES:
        return CapabilityLevel.EXPLOIT_VALIDATION
    if category in _SENSITIVE_CATEGORIES:
        return CapabilityLevel.SENSITIVE
    if caps.active:
        return CapabilityLevel.ACTIVE_RECON
    if caps.network:
        return CapabilityLevel.PASSIVE_NETWORK
    return CapabilityLevel.PASSIVE_ANALYSIS


def level_requires_campaign(level: CapabilityLevel) -> bool:
    """L3+ need the campaign + approval machinery (Phase B); L0–L2 do not."""
    return level >= CapabilityLevel.SENSITIVE
