"""Read-only attack-graph projector (Phase 6D) — the DB adapter behind the GraphProjector port.

Loads a tenant's subgraph from graph_nodes/graph_edges and runs the deterministic algorithms in
`guardian_core.attack_graph`. It is strictly READ-ONLY: it never writes a node, edge, event, score,
or snapshot. Tenant isolation is defense-in-depth — it runs on the RLS-enforced app session
filters every row to `app.current_tenant`) AND filters every query by `tenant_id` explicitly, so a
missed binding still cannot cross tenants.

Vulnerability severity is *enrichment* carried onto a node via a read-only join
(graph node → asset_id → findings), not a synthetic `finding` node or `exposes` edge. The exposure
paths themselves are built only from the real reachability edges the pipeline produced.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_core import attack_graph as ag
from guardian_core.enums import FindingStatus, Severity
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_db.models import Customer, Finding, GraphEdge, GraphNode, NodeEvent

_SEV_RANK: dict[str, int] = {s.value: s.rank for s in Severity}
# Findings that still represent live exposure (excludes false_positive / accepted_risk / resolved).
_OPEN_FINDING_STATUSES = (
    FindingStatus.OPEN.value, FindingStatus.TRIAGED.value, FindingStatus.CONFIRMED.value,
)


def _parse(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts)


class DbGraphProjector:
    """GraphProjector bound to a (RLS-enforced) session. Read-only + deterministic."""

    def __init__(self, session: Session, *, max_nodes: int = ag.DEFAULT_MAX_NODES) -> None:
        self._s = session
        self._max_nodes = max_nodes

    # ── subgraph loading (RLS + explicit tenant filter) ──
    def _load(self, tenant_id: str) -> tuple[list[ag.NodeView], list[ag.EdgeView], bool]:
        tid = uuid.UUID(str(tenant_id))
        rows = list(self._s.execute(
            select(GraphNode).where(GraphNode.tenant_id == tid).limit(self._max_nodes + 1)
        ).scalars())
        truncated = len(rows) > self._max_nodes
        rows = rows[: self._max_nodes]

        crit = self._criticality({r.customer_id for r in rows if r.customer_id}, tid)
        findings = self._findings({r.asset_id for r in rows if r.asset_id}, tid)

        views: list[ag.NodeView] = []
        for r in rows:
            counts = findings.get(r.asset_id, {}) if r.asset_id else {}
            max_rank = max((_SEV_RANK.get(s, 0) for s in counts), default=0)
            views.append(ag.NodeView(
                id=str(r.id), node_type=r.node_type, canonical_key=r.canonical_key,
                exposure_score=r.exposure_score or 0, state=r.state,
                internet_reachable=bool((r.metadata_ or {}).get("internet_reachable")),
                customer_criticality=crit.get(r.customer_id),
                has_asset=r.asset_id is not None,
                finding_max_rank=max_rank, finding_counts=counts,
            ))

        edges = [
            ag.EdgeView(src_id=e.src_id, relation=e.relation, dst_id=e.dst_id)
            for e in self._s.execute(
                select(GraphEdge).where(
                    GraphEdge.tenant_id == tid, GraphEdge.state == "active"
                )
            ).scalars()
        ]
        return views, edges, truncated

    def _criticality(self, customer_ids: set, tid: uuid.UUID) -> dict:
        if not customer_ids:
            return {}
        return {
            cid: c for cid, c in self._s.execute(
                select(Customer.id, Customer.criticality).where(
                    Customer.tenant_id == tid, Customer.id.in_(customer_ids)
                )
            ).all()
        }

    def _findings(self, asset_ids: set, tid: uuid.UUID) -> dict[uuid.UUID, dict[str, int]]:
        """Read-only enrichment: open findings per asset, counted by severity. No graph edges."""
        if not asset_ids:
            return {}
        out: dict[uuid.UUID, dict[str, int]] = {}
        for aid, sev in self._s.execute(
            select(Finding.asset_id, Finding.severity).where(
                Finding.tenant_id == tid, Finding.asset_id.in_(asset_ids),
                Finding.status.in_(_OPEN_FINDING_STATUSES),
            )
        ).all():
            out.setdefault(aid, {})[sev] = out.setdefault(aid, {}).get(sev, 0) + 1
        return out

    # ── helpers ──
    @staticmethod
    def _ref(n: ag.NodeView) -> dict:
        return {"id": n.id, "node_type": n.node_type, "canonical_key": n.canonical_key}

    def _path(self, p: ag.Path, by_id: dict[str, ag.NodeView]) -> list[dict]:
        return [self._ref(by_id[i]) for i in p.node_ids]

    # ── GraphProjector surface (read-only) ──
    def paths_to(
        self, *, tenant_id: str, target_type: str, target_id: str, max_depth: int = 6
    ) -> list[list[dict]]:
        nodes, edges, _ = self._load(tenant_id)
        by_id = {n.id: n for n in nodes}
        res = ag.paths_to(nodes, edges, str(target_id),
                          ag.Limits(max_depth=max_depth, max_nodes=self._max_nodes))
        return [self._path(p, by_id) for p in res.paths]

    def reachable_from(
        self, *, tenant_id: str, src_type: str, src_id: str, max_depth: int = 6
    ) -> list[dict]:
        nodes, edges, _ = self._load(tenant_id)
        by_id = {n.id: n for n in nodes}
        res = ag.reachable_from(nodes, edges, str(src_id),
                                ag.Limits(max_depth=max_depth, max_nodes=self._max_nodes))
        return [self._ref(by_id[i]) for i in res.node_ids]

    def exposure_paths(self, *, tenant_id: str, max_depth: int = 6, limit: int = 100) -> dict:
        nodes, edges, truncated = self._load(tenant_id)
        by_id = {n.id: n for n in nodes}
        res = ag.exposure_paths(
            nodes, edges, ag.Limits(max_depth=max_depth, max_paths=limit, max_nodes=self._max_nodes)
        )
        return {"paths": [self._path(p, by_id) for p in res.paths],
                "truncated": res.truncated or truncated}

    def blast_radius(
        self, *, tenant_id: str, node_type: str, node_id: str, max_depth: int = 6
    ) -> dict:
        nodes, edges, truncated = self._load(tenant_id)
        b = ag.blast_radius(nodes, edges, str(node_id),
                            ag.Limits(max_depth=max_depth, max_nodes=self._max_nodes))
        return {
            "root_id": b.root_id, "root_key": b.root_key,
            "affected_nodes": b.affected_nodes, "sensitive_nodes": b.sensitive_nodes,
            "exposure_paths": b.exposure_paths, "weighted_impact": b.weighted_impact,
            "truncated": b.truncated or truncated,
        }

    def chokepoints(self, *, tenant_id: str, top: int = 10, max_depth: int = 6) -> dict:
        nodes, edges, truncated = self._load(tenant_id)
        by_id = {n.id: n for n in nodes}
        res = ag.chokepoints(
            nodes, edges, ag.Limits(max_depth=max_depth, max_nodes=self._max_nodes), top=top
        )
        return {
            "total_paths": res.total_paths, "truncated": res.truncated or truncated,
            "chokepoints": [
                {
                    "node_id": c.node_id, "node_key": c.node_key, "node_type": c.node_type,
                    "paths_cut": c.paths_cut, "total_paths": c.total_paths, "fraction": c.fraction,
                    "evidence_paths": [self._path(p, by_id) for p in c.evidence_paths],
                }
                for c in res.chokepoints
            ],
        }

    def exposure_drift(self, *, tenant_id: str, since: str, until: str) -> dict:
        tid = uuid.UUID(str(tenant_id))
        since_dt, until_dt = _parse(since), _parse(until)
        events = [
            {"node_id": str(r.node_id), "node_key": r.canonical_key, "event_type": r.event_type,
             "detail": r.detail, "occurred_at": r.occurred_at.isoformat()}
            for r in self._s.execute(
                select(NodeEvent.node_id, NodeEvent.event_type, NodeEvent.detail,
                       NodeEvent.occurred_at, GraphNode.canonical_key)
                .join(GraphNode, GraphNode.id == NodeEvent.node_id)
                .where(NodeEvent.tenant_id == tid,
                       NodeEvent.occurred_at >= since_dt, NodeEvent.occurred_at <= until_dt)
            ).all()
        ]
        stale = [
            {"node_id": r.src_id, "node_key": r.src_id,
             "detail": {"relation": r.relation, "dst_id": r.dst_id},
             "occurred_at": r.last_seen_at.isoformat() if r.last_seen_at else ""}
            for r in self._s.execute(
                select(GraphEdge.src_id, GraphEdge.relation,
                       GraphEdge.dst_id, GraphEdge.last_seen_at)
                .where(GraphEdge.tenant_id == tid, GraphEdge.state == "stale",
                       GraphEdge.last_seen_at >= since_dt, GraphEdge.last_seen_at <= until_dt)
            ).all()
        ]
        report = ag.classify_drift(events, stale)
        return {"items": [
            {"node_id": i.node_id, "node_key": i.node_key, "kind": i.kind,
             "detail": i.detail, "occurred_at": i.occurred_at}
            for i in report.items
        ]}
