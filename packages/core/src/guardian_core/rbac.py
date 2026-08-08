"""Role → capability ceilings (Phase A governance) — pure policy, no DB, no identity resolution.

The highest `CapabilityLevel` each staff role may run *without* an explicit per-user grant. This is
policy data the Control Plane consults; a provider never sees it. Raising a specific user above
their role ceiling (per-user grants) and platform-owner / service-account handling live in the
Control-Plane resolver, not here.

Phase A ceilings stop at ACTIVE_RECON (L2): L3+ need the campaign + approval machinery (Phase B), so
no role can yet run them — recognized, not forbidden.
"""

from __future__ import annotations

from guardian_core.capability import CapabilityLevel
from guardian_core.enums import StaffRole

# role value → max level runnable without an explicit grant; None ⇒ the role may not execute tools.
STAFF_ROLE_CEILING: dict[str, CapabilityLevel | None] = {
    StaffRole.OWNER.value: CapabilityLevel.ACTIVE_RECON,
    StaffRole.ADMIN.value: CapabilityLevel.ACTIVE_RECON,
    StaffRole.PENTESTER.value: CapabilityLevel.ACTIVE_RECON,
    StaffRole.ANALYST.value: CapabilityLevel.PASSIVE_ANALYSIS,
    StaffRole.REVIEWER.value: None,
}


def role_ceiling(role: str) -> CapabilityLevel | None:
    """The capability ceiling for a staff role, or None (unknown role or no-execute role)."""
    return STAFF_ROLE_CEILING.get(role)
