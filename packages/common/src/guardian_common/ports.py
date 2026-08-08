"""Interface ports for future subsystems (Phase 5B) — definitions + no-op defaults only.

Same pattern as the existing `LLMProvider` / `JobQueue` / `ScanEngine` ports: declare the seam now
so later phases (EASM, SOAR, enterprise, BYOK) plug in without touching the core. Each port ships a
safe no-op default; **no real behavior is implemented in Phase 5.**
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:  # avoid a runtime guardian_common -> guardian_core coupling; annotations only
    from collections.abc import Iterable

    from guardian_core.discovery import DiscoveredAsset, DiscoveryContext
    from guardian_core.probe import ProbeEvidence


# ── SOAR: outbound notifications (Slack/PagerDuty/email...) — Phase 7 ──
@runtime_checkable
class Notifier(Protocol):
    def notify(
        self, *, channel: str, subject: str, body: str, meta: dict | None = None
    ) -> None: ...


class NullNotifier:
    """Default: does nothing. Real Notifiers arrive with SOAR (Phase 7)."""

    def notify(self, *, channel: str, subject: str, body: str, meta: dict | None = None) -> None:
        return None


# ── SOAR: ticketing/connectors (Jira/ServiceNow/GitHub Issues) — Phase 7 ──
@runtime_checkable
class Connector(Protocol):
    kind: str

    def create_ticket(self, *, title: str, body: str, meta: dict | None = None) -> str | None: ...


class NullConnector:
    kind = "null"

    def create_ticket(self, *, title: str, body: str, meta: dict | None = None) -> str | None:
        return None


# ── Attack-graph read side — deterministic, read-only projection over the graph (Phase 6D) ──
@runtime_checkable
class GraphProjector(Protocol):
    """Read-only, deterministic analysis over graph_nodes/graph_edges. Never writes, never reaches a
    network. Every method is tenant-scoped and depth/count-bounded; results are reproducible."""

    # Depth-bounded, ordered exposure paths from an internet-facing entry to a specific node.
    def paths_to(
        self, *, tenant_id: str, target_type: str, target_id: str, max_depth: int = 6
    ) -> list[list[dict]]: ...

    def reachable_from(
        self, *, tenant_id: str, src_type: str, src_id: str, max_depth: int = 6
    ) -> list[dict]: ...

    # Every internet-exposure path (entry → exposed/sensitive node) for the tenant.
    def exposure_paths(
        self, *, tenant_id: str, max_depth: int = 6, limit: int = 100
    ) -> dict: ...

    # Every real attack path (entry → finding, over reachability + serves + exposes) — 6E.
    def attack_paths(
        self, *, tenant_id: str, max_depth: int = 6, limit: int = 100
    ) -> dict: ...

    # Deterministic blast radius of one node (affected/sensitive counts, paths-through, weighted).
    def blast_radius(
        self, *, tenant_id: str, node_type: str, node_id: str, max_depth: int = 6
    ) -> dict: ...

    # Nodes ranked by how many exposure paths their remediation would cut (with evidence).
    def chokepoints(self, *, tenant_id: str, top: int = 10, max_depth: int = 6) -> dict: ...

    # Exposure drift classified from already-emitted node history within a time window.
    def exposure_drift(self, *, tenant_id: str, since: str, until: str) -> dict: ...


class NullGraphProjector:
    def paths_to(self, *, tenant_id, target_type, target_id, max_depth=6):  # noqa: ANN001, ANN201
        return []

    def reachable_from(self, *, tenant_id, src_type, src_id, max_depth=6):  # noqa: ANN001, ANN201
        return []

    def exposure_paths(self, *, tenant_id, max_depth=6, limit=100):  # noqa: ANN001, ANN201
        return {"paths": [], "truncated": False}

    def attack_paths(self, *, tenant_id, max_depth=6, limit=100):  # noqa: ANN001, ANN201
        return {"paths": [], "truncated": False}

    def blast_radius(self, *, tenant_id, node_type, node_id, max_depth=6):  # noqa: ANN001, ANN201
        return {}

    def chokepoints(self, *, tenant_id, top=10, max_depth=6):  # noqa: ANN001, ANN201
        return {"chokepoints": [], "total_paths": 0, "truncated": False}

    def exposure_drift(self, *, tenant_id, since, until):  # noqa: ANN001, ANN201
        return {"items": []}


# ── Attack-graph write side — edge/node ingestion from collectors (Phase 6B/6C) ──
@runtime_checkable
class GraphIngestor(Protocol):
    """Upserts nodes and edges from a discovery run. Split from the projector so collectors write
    without depending on query logic (closes the review's 'no graph-write seam' gap)."""

    def upsert_node(self, *, tenant_id: str, node: DiscoveredAsset, run_id: str) -> str: ...
    def link(
        self, *, tenant_id: str, src_id: str, relation: str, dst_id: str, run_id: str
    ) -> None: ...


class NullGraphIngestor:
    def upsert_node(self, *, tenant_id, node, run_id):  # noqa: ANN001, ANN201
        return ""

    def link(self, *, tenant_id, src_id, relation, dst_id, run_id):  # noqa: ANN001, ANN201
        return None


# ── KMS / secrets provider for envelope encryption + BYOK — Phase 9 (local default now) ──
@runtime_checkable
class KMSProvider(Protocol):
    def encrypt(self, plaintext: bytes, *, context: dict | None = None) -> bytes: ...
    def decrypt(self, ciphertext: bytes, *, context: dict | None = None) -> bytes: ...


# ── EASM discovery collectors (domains/subdomains/IPs/cloud) — Phase 6 ──
@runtime_checkable
class DiscoveryProvider(Protocol):
    """A pluggable EASM collector. Emits typed `DiscoveredAsset`s (with per-result confidence), so
    upsert/dedup/provenance is uniform across sources. `requires_authorization` marks active methods
    (port/service scan) that must be gated; passive collectors leave it False."""

    key: str
    requires_authorization: bool

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]: ...


class NullDiscoveryProvider:
    key = "null"
    requires_authorization = False

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:  # noqa: ARG002
        return []


# ── Protocol probes — one low-impact service-identification plugin per protocol (Phase 6C.2) ──
@runtime_checkable
class ProtocolProbe(Protocol):
    """Talks to ONE protocol on an authorized target and returns evidence. Ignorant of the graph.

    `probe` reads a snapshot when offline (deterministic CI) and runs live network work inside the
    worker sandbox otherwise. It NEVER exploits or sends payloads — identification/fingerprinting
    only, and only for a target the authorization gate already cleared (orchestrator-enforced)."""

    key: str
    ports: tuple[int, ...]

    def probe(
        self, host: str, port: int, *, timeout: int, allow_live: bool, snapshot: dict | None
    ) -> ProbeEvidence | None: ...


# ── Enterprise identity (SAML/OIDC/SCIM) — Phase 9 ──
@runtime_checkable
class IdentityProvider(Protocol):
    kind: str

    def authenticate(self, assertion: str) -> dict | None: ...


class NullIdentityProvider:
    kind = "null"

    def authenticate(self, assertion: str) -> dict | None:
        return None
