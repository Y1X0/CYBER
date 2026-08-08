"""Security Tool Execution Framework — core contracts (Framework Phase 1).

The rails every future security tool (Nmap, PCAP, web/TLS, …) rides on, so a tool is a *Provider*
behind one security boundary — never a script wired to a button. Pure and deterministic: no DB, no
network, no AI. The provider NEVER grants itself authorization; the Control Plane decides.

Flow (see ADR-016):
  Authorization → EffectiveScope → Policy/Gate → ToolJob → (DB-less sandbox) → RawEvidence
  → hash-chained EvidenceItem → RawFinding → Finding → Graph.

Key invariant: `EffectiveScope` can only *narrow* what an Authorization permits — a tool
can never widen its reach (e.g. it can never turn "example.com" into "0.0.0.0/0").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCapabilities:
    """What a tool *is* — read by the Capability Registry + Policy engine BEFORE any execution."""

    category: str                     # network_discovery | web_assessment | packet_analysis | ...
    network: bool = False                          # opens outbound network
    active: bool = False              # actively touches a target (vs passive/analytical)
    destructive: bool = False         # can change target state (never allowed w/o approval)
    requires_authorization: bool = True            # needs a DB-backed authorization to run
    requires_human_approval: bool = False          # needs an explicit human approval before running
    supported_targets: tuple[str, ...] = ()        # target types it accepts (e.g. "domain", "ip")
    ports: tuple[int, ...] = ()                     # ports it may touch (policy can only narrow)
    protocols: tuple[str, ...] = ()                 # protocols it may speak


@dataclass(frozen=True)
class EffectiveScope:
    """The deterministic narrowing of an Authorization by policy + tool capabilities. Source of the
    tool's egress allowlist and the ONLY targets it may act on."""

    targets: tuple[str, ...]        # authorized targets the tool may act on (⊆ authorization)
    ports: tuple[int, ...]
    protocols: tuple[str, ...]
    network_allowed: bool
    read_only: bool                 # True unless the tool is destructive AND approved


@dataclass(frozen=True)
class ToolJob:
    """A unit of tool work handed to the execution plane. Carries NO secrets and NO DB handles."""

    tenant_id: str
    job_id: str
    tool_key: str
    scope: EffectiveScope
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawEvidence:
    """The structured, sanitized output of a tool run — proof of WHAT happened, never a secret.

    Ignorant of DB/graph (the trusted plane turns it into hash-chained EvidenceItems + findings).
    A credential the tool used is NEVER placed here (see ADR-016 secrets boundary)."""

    tool: str
    execution_id: str
    target: str
    kind: str
    data: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    confidence: int = 90
    occurred_at: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    requires_human_approval: bool
    reasons: tuple[str, ...] = ()


# ── deterministic control-plane logic (no DB/network/AI) ──────────────────────────────────────────
def derive_effective_scope(
    requested_targets: list[str],
    authorized_targets: list[str],
    capabilities: ToolCapabilities,
    policy: dict | None = None,
) -> EffectiveScope:
    """Narrow an authorization by requested targets, tool capabilities, and policy — never widen.

    `authorized_targets` are the targets an Authorization already cleared (the legal/security source
    of truth). The result's `targets` are the intersection of requested ∩ authorized, so a tool can
    never reach anything the Authorization did not permit. Ports/protocols/network are the tool's
    capabilities further narrowed by policy; a destructive tool is read-only unless policy allows.
    """
    policy = policy or {}
    authz = set(authorized_targets)
    # If nothing specific was requested, default to the full authorized set (still ⊆ authorization).
    requested = set(requested_targets) if requested_targets else authz
    targets = tuple(sorted(requested & authz))  # deterministic; never beyond authorization

    ports = tuple(sorted(_narrow(capabilities.ports, policy.get("ports"))))
    protocols = tuple(sorted(_narrow(capabilities.protocols, policy.get("protocols"))))
    network_allowed = bool(capabilities.network) and policy.get("network", True) is not False
    read_only = not (capabilities.destructive and policy.get("allow_destructive", False))
    return EffectiveScope(
        targets=targets, ports=ports, protocols=protocols,
        network_allowed=network_allowed, read_only=read_only,
    )


def _narrow(cap_values: tuple, policy_values) -> set:  # noqa: ANN001
    """Policy can only narrow a capability's values, never add new ones."""
    allowed = set(cap_values)
    if policy_values is not None:
        allowed &= set(policy_values)
    return allowed


def evaluate_tool_policy(
    capabilities: ToolCapabilities, scope: EffectiveScope, *, human_approved: bool = False
) -> PolicyDecision:
    """Deterministic pre-execution gate. Denies (or requires approval) BEFORE the tool runs.

    - A tool that requires authorization with no in-scope targets is denied.
    - A destructive tool is denied unless it is read-only in scope OR a human approved it.
    - An active/network tool that requires human approval is denied until approved.
    Nothing here trusts the provider — capabilities + scope + approval decide, in the Control Plane.
    """
    reasons: list[str] = []
    allowed = True
    requires_approval = False

    if capabilities.requires_authorization and not scope.targets:
        allowed = False
        reasons.append("no in-scope authorized target")

    if capabilities.destructive and not scope.read_only:
        requires_approval = True
        if not human_approved:
            allowed = False
            reasons.append("destructive tool requires human approval")

    if (capabilities.active or capabilities.network) and capabilities.requires_human_approval:
        requires_approval = True
        if not human_approved:
            allowed = False
            reasons.append("active/high-risk tool requires human approval")

    return PolicyDecision(allowed=allowed, requires_human_approval=requires_approval,
                          reasons=tuple(reasons))


# ── wire (de)serialization for the DB-less execution plane (result-return) ──
def scope_to_wire(s: EffectiveScope) -> dict:
    return {"targets": list(s.targets), "ports": list(s.ports), "protocols": list(s.protocols),
            "network_allowed": s.network_allowed, "read_only": s.read_only}


def scope_from_wire(d: dict) -> EffectiveScope:
    return EffectiveScope(
        targets=tuple(d.get("targets") or []), ports=tuple(d.get("ports") or []),
        protocols=tuple(d.get("protocols") or []),
        network_allowed=bool(d.get("network_allowed")), read_only=bool(d.get("read_only", True)),
    )


def job_to_wire(j: ToolJob) -> dict:
    return {"tenant_id": j.tenant_id, "job_id": j.job_id, "tool_key": j.tool_key,
            "scope": scope_to_wire(j.scope), "settings": j.settings}


def job_from_wire(d: dict) -> ToolJob:
    return ToolJob(tenant_id=d["tenant_id"], job_id=d["job_id"], tool_key=d["tool_key"],
                   scope=scope_from_wire(d["scope"]), settings=dict(d.get("settings") or {}))


def evidence_to_wire(e: RawEvidence) -> dict:
    return {"tool": e.tool, "execution_id": e.execution_id, "target": e.target, "kind": e.kind,
            "data": e.data, "provenance": e.provenance, "confidence": e.confidence,
            "occurred_at": e.occurred_at}


def evidence_from_wire(d: dict) -> RawEvidence:
    return RawEvidence(
        tool=d["tool"], execution_id=d["execution_id"], target=d["target"], kind=d["kind"],
        data=dict(d.get("data") or {}), provenance=dict(d.get("provenance") or {}),
        confidence=d.get("confidence", 90), occurred_at=d.get("occurred_at", ""),
    )
