"""Capability classification + RBAC ceilings (no DB) — pure governance policy.

Proves the level is derived deterministically from a provider's declared primitives (not hardcoded
per tool) and that role ceilings are pure policy data the Control Plane consults.
"""

from __future__ import annotations

from guardian_core.capability import (
    CapabilityLevel,
    derive_capability_level,
    level_requires_campaign,
)
from guardian_core.enums import StaffRole
from guardian_core.rbac import role_ceiling
from guardian_core.tool import ToolCapabilities


def _caps(**kw):
    base = {"category": "x", "network": False, "active": False, "destructive": False}
    base.update(kw)
    return ToolCapabilities(**base)


def test_offline_tool_is_passive_analysis_l0():
    assert derive_capability_level(_caps()) == CapabilityLevel.PASSIVE_ANALYSIS


def test_passive_network_is_l1():
    assert derive_capability_level(_caps(network=True)) == CapabilityLevel.PASSIVE_NETWORK


def test_active_tool_is_active_recon_l2():
    assert derive_capability_level(_caps(network=True, active=True)) == CapabilityLevel.ACTIVE_RECON


def test_destructive_is_l5_regardless_of_others():
    assert derive_capability_level(_caps(destructive=True)) == CapabilityLevel.DESTRUCTIVE


def test_category_hints_raise_sensitive_and_exploit():
    assert derive_capability_level(_caps(category="credential", active=True)) == \
        CapabilityLevel.SENSITIVE
    assert derive_capability_level(_caps(category="exploit", active=True)) == \
        CapabilityLevel.EXPLOIT_VALIDATION


def test_real_providers_land_where_expected():
    from guardian_scanner.tools.providers.dns_posture_provider import DnsPostureProvider
    from guardian_scanner.tools.providers.pcap_provider import PcapMetaProvider
    from guardian_scanner.tools.providers.web_tls_provider import WebTlsProvider
    assert derive_capability_level(PcapMetaProvider().capabilities) == \
        CapabilityLevel.PASSIVE_ANALYSIS
    assert derive_capability_level(DnsPostureProvider().capabilities) == \
        CapabilityLevel.PASSIVE_ANALYSIS
    assert derive_capability_level(WebTlsProvider().capabilities) == CapabilityLevel.ACTIVE_RECON


def test_l3_plus_requires_campaign_l0_l2_do_not():
    assert not level_requires_campaign(CapabilityLevel.PASSIVE_ANALYSIS)
    assert not level_requires_campaign(CapabilityLevel.ACTIVE_RECON)
    assert level_requires_campaign(CapabilityLevel.SENSITIVE)
    assert level_requires_campaign(CapabilityLevel.DESTRUCTIVE)


def test_role_ceilings():
    assert role_ceiling(StaffRole.PENTESTER.value) == CapabilityLevel.ACTIVE_RECON
    assert role_ceiling(StaffRole.ANALYST.value) == CapabilityLevel.PASSIVE_ANALYSIS
    assert role_ceiling(StaffRole.REVIEWER.value) is None       # reviewer may not execute tools
    assert role_ceiling("nonexistent") is None
