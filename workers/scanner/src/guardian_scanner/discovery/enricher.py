"""Graph enrichment (Phase 6E) — project managed assets + findings into the attack graph.

Trusted, DB-side, deterministic, idempotent. Reads the assets/findings a scan already produced and
writes two node kinds and two evidence-backed edges:

  * `asset`  --exposes--> `finding`          (evidence: findings.asset_id → assets.id)
  * subdomain/service --serves--> `asset`    (ONLY on an EXACT canonical-host identity between
    a web/api asset's URL host and a discovered topology node — no fuzzy / name / IP guessing)

It invents nothing: `enables` is NOT created (no evidence for what a finding enables beyond its own
asset); an asset with neither a host-derivable identifier nor findings produces no node/edge; no
match ⇒ no `serves` edge. Severity/risk/exposure are reused as-is — finding nodes carry
`exposure_score = 0` (exposure ≠ risk) and `state = Finding.status`. No AI, no re-scoring.

Runs on the trusted plane only (never recon). Idempotent: nodes dedupe on
`(tenant, node_type, canonical_key)` and edges on their identity, so re-running updates in place.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import uuid
from urllib.parse import urlparse

from guardian_core.canonicalize import canonical_key
from guardian_core.enums import EdgeRelation, NodeType
from guardian_db.models import Asset, Finding, GraphEdge, GraphNode
from sqlalchemy import select
from sqlalchemy.orm import Session

# Asset kinds whose identifier is a service URL with a host (so a `serves` link is meaningful).
_HOST_ASSET_KINDS = ("web", "api")


def _asset_host(asset: Asset) -> str | None:
    """The exact canonical host of a web/api asset's URL, or None when not reliably host-derived.

    Strict: only a scheme://host URL yields a host; a bare/opaque identifier, a non-host kind, or an
    IP-literal host returns None (no auto-link — deterministic identity only, never a guess).
    """
    if asset.kind not in _HOST_ASSET_KINDS:
        return None
    host = urlparse(asset.identifier or "").hostname
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # IP-literal host: not linked (conservative — no IP identity match in 6E)
    except ValueError:
        return canonical_key(NodeType.SUBDOMAIN, host)  # canonical domain host


class GraphEnricher:
    """Enrich the graph for one tenant (optionally one customer). DB read+write, no network."""

    def __init__(
        self, session: Session, *, tenant_id: uuid.UUID, customer_id: uuid.UUID | None = None
    ) -> None:
        self._s = session
        self._tenant = tenant_id
        self._customer = customer_id
        self.stats = {"asset_nodes": 0, "finding_nodes": 0, "exposes_edges": 0, "serves_edges": 0}

    def _now(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC)

    # ── node/edge upserts (idempotent) ──
    def _upsert_node(
        self, *, node_type: str, key: str, asset_id: uuid.UUID | None,
        customer_id: uuid.UUID | None, metadata: dict, state: str,
    ) -> uuid.UUID:
        existing = self._s.execute(
            select(GraphNode).where(
                GraphNode.tenant_id == self._tenant,
                GraphNode.node_type == node_type, GraphNode.canonical_key == key,
            )
        ).scalar_one_or_none()
        now = self._now()
        if existing is None:
            row = GraphNode(
                tenant_id=self._tenant, node_type=node_type, canonical_key=key,
                asset_id=asset_id, customer_id=customer_id, metadata_=metadata,
                confidence=100, ownership_confidence=100, exposure_score=0,
                exposure_rationale=[], state=state, first_seen_at=now, last_seen_at=now,
            )
            self._s.add(row)
            self._s.flush()
            return row.id
        existing.metadata_ = metadata          # deterministic refresh (no re-scoring)
        existing.state = state
        existing.asset_id = asset_id
        existing.last_seen_at = now
        return existing.id

    def _upsert_edge(
        self, *, src_id: uuid.UUID, src_type: str, relation: str,
        dst_id: uuid.UUID, dst_type: str, meta: dict,
    ) -> bool:
        existing = self._s.execute(
            select(GraphEdge).where(
                GraphEdge.tenant_id == self._tenant,
                GraphEdge.src_type == src_type, GraphEdge.src_id == str(src_id),
                GraphEdge.relation == relation,
                GraphEdge.dst_type == dst_type, GraphEdge.dst_id == str(dst_id),
            )
        ).scalar_one_or_none()
        now = self._now()
        if existing is not None:
            existing.state = "active"
            existing.last_seen_at = now
            existing.meta = meta
            return False
        self._s.add(GraphEdge(
            tenant_id=self._tenant, src_type=src_type, src_id=str(src_id), relation=relation,
            dst_type=dst_type, dst_id=str(dst_id), state="active",
            source="inferred", confidence=100, first_seen_at=now, last_seen_at=now, meta=meta,
        ))
        self._s.flush()
        return True

    # ── data loading (tenant/customer-scoped) ──
    def _assets(self) -> list[Asset]:
        stmt = select(Asset).where(Asset.tenant_id == self._tenant)
        if self._customer is not None:
            stmt = stmt.where(Asset.customer_id == self._customer)
        return list(self._s.execute(stmt.order_by(Asset.id)).scalars())

    def _findings_by_asset(self) -> dict[uuid.UUID, list[Finding]]:
        stmt = select(Finding).where(Finding.tenant_id == self._tenant)
        if self._customer is not None:
            stmt = stmt.where(Finding.customer_id == self._customer)
        out: dict[uuid.UUID, list[Finding]] = {}
        for f in self._s.execute(stmt.order_by(Finding.id)).scalars():
            out.setdefault(f.asset_id, []).append(f)
        return out

    def _host_index(self) -> dict[str, list[tuple[uuid.UUID, str]]]:
        """canonical host -> [(topology node id, node_type)] for subdomain/service nodes."""
        idx: dict[str, list[tuple[uuid.UUID, str]]] = {}
        rows = self._s.execute(
            select(GraphNode).where(
                GraphNode.tenant_id == self._tenant,
                GraphNode.node_type.in_((NodeType.SUBDOMAIN.value, NodeType.SERVICE.value)),
            )
        ).scalars()
        for n in rows:
            host = (n.canonical_key.rsplit(":", 1)[0]
                    if n.node_type == NodeType.SERVICE.value else n.canonical_key)
            idx.setdefault(host, []).append((n.id, n.node_type))
        return idx

    @staticmethod
    def _finding_meta(f: Finding) -> dict:
        return {
            "severity": f.severity, "risk_score": f.risk_score, "category": f.category,
            "status": f.status, "kev": f.kev, "cve_ids": list(f.cve_ids or []),
            "fingerprint": f.fingerprint,
        }

    def enrich(self) -> dict:
        """Create/refresh asset+finding nodes and exposes/serves edges. Returns delta stats."""
        findings_by_asset = self._findings_by_asset()
        host_index = self._host_index()

        for asset in self._assets():
            asset_findings = findings_by_asset.get(asset.id, [])
            host = _asset_host(asset)
            matches = host_index.get(host, []) if host else []

            if not asset_findings and not matches:
                continue  # no edge would attach → don't create an orphan asset node

            asset_node = self._upsert_node(
                node_type=NodeType.ASSET.value, key=str(asset.id), asset_id=asset.id,
                customer_id=asset.customer_id,
                metadata={"kind": asset.kind, "identifier": asset.identifier,
                          "exposure": asset.exposure, "name": asset.name},
                state=asset.state,
            )
            self.stats["asset_nodes"] += 1

            # asset --exposes--> finding  (evidence: findings.asset_id)
            for f in asset_findings:
                finding_node = self._upsert_node(
                    node_type=NodeType.FINDING.value, key=str(f.id), asset_id=f.asset_id,
                    customer_id=f.customer_id, metadata=self._finding_meta(f), state=f.status,
                )
                self.stats["finding_nodes"] += 1
                if self._upsert_edge(
                    src_id=asset_node, src_type=NodeType.ASSET.value,
                    relation=EdgeRelation.EXPOSES.value,
                    dst_id=finding_node, dst_type=NodeType.FINDING.value,
                    meta={"evidence": "findings.asset_id"},
                ):
                    self.stats["exposes_edges"] += 1

            # subdomain/service --serves--> asset  (deterministic exact host identity only)
            for node_id, node_type in matches:
                if self._upsert_edge(
                    src_id=node_id, src_type=node_type, relation=EdgeRelation.SERVES.value,
                    dst_id=asset_node, dst_type=NodeType.ASSET.value,
                    meta={"link": "deterministic_host_identity", "host": host},
                ):
                    self.stats["serves_edges"] += 1

        return self.stats
