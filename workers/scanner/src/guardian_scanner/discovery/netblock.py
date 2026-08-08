"""Authorized-netblock enrichment (Phase 6F-a) — trusted plane, deterministic, no network.

Turns the netblocks an operator EXPLICITLY authorized (`Authorization.authorized_targets` entries of
type "netblock") into `netblock` graph nodes, and links each to the already-discovered `ip_address`
nodes it contains — by exact CIDR containment only. No fuzzy matching, no reverse inference, no
network. Source is limited to authorizations (NOT DiscoveryScope.seeds), tenant/customer scoped.

Runs in the persist phase after a discovery run (the IP nodes exist by then). Idempotent: netblock
nodes dedupe on `(tenant, "netblock", canonical CIDR)` and `contains` edges on their identity, so it
converges with the passive ASN/RIR provider (6F-b) onto one node per canonical CIDR. `contains` is
GROUPING ONLY — never a reachability/attack hop.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import uuid

from guardian_core.canonicalize import canonical_key
from guardian_core.enums import EdgeRelation, NodeType
from guardian_db.models import Authorization, GraphEdge, GraphNode
from sqlalchemy import select
from sqlalchemy.orm import Session


class NetblockEnricher:
    """Create netblock nodes + contains edges from authorized CIDRs. DB read+write, no network."""

    def __init__(
        self, session: Session, *, tenant_id: uuid.UUID, customer_id: uuid.UUID | None = None
    ) -> None:
        self._s = session
        self._tenant = tenant_id
        self._customer = customer_id
        self.stats = {"netblock_nodes": 0, "contains_edges": 0}

    def _now(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC)

    def _authorized_cidrs(self) -> list[str]:
        """Distinct netblock CIDRs from valid, non-revoked authorizations (deterministic order)."""
        now = self._now()
        stmt = (
            select(Authorization)
            .where(Authorization.tenant_id == self._tenant)
            .where(Authorization.revoked_at.is_(None))
            .where(Authorization.valid_from <= now)
            .where(Authorization.valid_until >= now)
        )
        if self._customer is not None:
            stmt = stmt.where(Authorization.customer_id == self._customer)
        cidrs: set[str] = set()
        for a in self._s.execute(stmt).scalars():
            for t in a.authorized_targets or []:
                if str(t.get("type", "")).lower() == "netblock" and t.get("value"):
                    cidrs.add(str(t["value"]))
        return sorted(cidrs)

    def _ip_nodes(self) -> list[tuple[uuid.UUID, str]]:
        rows = self._s.execute(
            select(GraphNode.id, GraphNode.canonical_key).where(
                GraphNode.tenant_id == self._tenant,
                GraphNode.node_type == NodeType.IP_ADDRESS.value,
            )
        ).all()
        return [(r.id, r.canonical_key) for r in rows]

    def _upsert_netblock(self, key: str) -> uuid.UUID:
        existing = self._s.execute(
            select(GraphNode).where(
                GraphNode.tenant_id == self._tenant,
                GraphNode.node_type == NodeType.NETBLOCK.value, GraphNode.canonical_key == key,
            )
        ).scalar_one_or_none()
        now = self._now()
        if existing is not None:
            existing.last_seen_at = now
            return existing.id
        row = GraphNode(
            tenant_id=self._tenant, node_type=NodeType.NETBLOCK.value, canonical_key=key,
            metadata_={"source": "authorized"}, confidence=100, ownership_confidence=100,
            exposure_score=0, exposure_rationale=[], state="active",
            first_seen_at=now, last_seen_at=now,
        )
        self._s.add(row)
        self._s.flush()
        self.stats["netblock_nodes"] += 1
        return row.id

    def _upsert_contains(self, nb_id: uuid.UUID, ip_id: uuid.UUID, cidr: str) -> None:
        existing = self._s.execute(
            select(GraphEdge).where(
                GraphEdge.tenant_id == self._tenant,
                GraphEdge.src_type == NodeType.NETBLOCK.value, GraphEdge.src_id == str(nb_id),
                GraphEdge.relation == EdgeRelation.CONTAINS.value,
                GraphEdge.dst_type == NodeType.IP_ADDRESS.value, GraphEdge.dst_id == str(ip_id),
            )
        ).scalar_one_or_none()
        now = self._now()
        if existing is not None:
            existing.state = "active"
            existing.last_seen_at = now
            return
        self._s.add(GraphEdge(
            tenant_id=self._tenant, src_type=NodeType.NETBLOCK.value, src_id=str(nb_id),
            relation=EdgeRelation.CONTAINS.value, dst_type=NodeType.IP_ADDRESS.value,
            dst_id=str(ip_id), state="active", source="inferred", confidence=100,
            first_seen_at=now, last_seen_at=now,
            meta={"link": "cidr_containment", "netblock": cidr},
        ))
        self._s.flush()
        self.stats["contains_edges"] += 1

    def enrich(self) -> dict:
        cidrs = self._authorized_cidrs()
        if not cidrs:
            return self.stats
        ip_nodes = self._ip_nodes()
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue  # malformed authorized CIDR → skip (fail-safe)
            nb_id = self._upsert_netblock(canonical_key(NodeType.NETBLOCK, cidr))
            for ip_id, ip_key in ip_nodes:
                try:
                    if ipaddress.ip_address(ip_key) in net:
                        self._upsert_contains(nb_id, ip_id, str(net))
                except ValueError:
                    continue  # non-IP key → skip
        return self.stats
