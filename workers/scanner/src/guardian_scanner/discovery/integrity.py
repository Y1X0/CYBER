"""Graph integrity validator (Phase 6B guardrail).

A polymorphic edge table has no FK to enforce that both endpoints exist and belong to the same
tenant — so we enforce it explicitly, runnable in CI or as a periodic job. Catches the three ways a
polymorphic graph rots: an edge to a missing node (orphan), a src/dst that resolves to another
tenant (the isolation violation that RLS can't catch across the polymorphic boundary), and a
self-loop. Endpoints whose type isn't a `graph_nodes` kind (finding/asset) are checked against their
own tables.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

# node_type -> table holding that node's rows (by uuid). Types not here live in graph_nodes.
_EXTERNAL_TABLES = {"finding": "findings", "asset": "assets"}


@dataclass
class IntegrityViolation:
    edge_id: str
    kind: str      # orphan_src | orphan_dst | cross_tenant | self_loop
    detail: str


def _endpoint_table(node_type: str) -> str:
    return _EXTERNAL_TABLES.get(node_type, "graph_nodes")


def validate_graph_integrity(
    session: Session, *, tenant_id: str | None = None, limit: int = 1000
) -> list[IntegrityViolation]:
    """Return integrity violations (empty = healthy). Runs on an admin session (all tenants)."""
    where = "WHERE e.tenant_id = :tid" if tenant_id else ""
    params = {"tid": tenant_id, "lim": limit} if tenant_id else {"lim": limit}
    rows = session.execute(
        # `where` is a fixed literal (empty or a parameterized clause), not user input.
        text("SELECT id, tenant_id, src_type, src_id, relation, dst_type, dst_id "  # noqa: S608
             f"FROM graph_edges e {where} ORDER BY created_at DESC LIMIT :lim"),
        params,
    ).all()

    violations: list[IntegrityViolation] = []
    for r in rows:
        eid = str(r.id)
        if r.src_type == r.dst_type and r.src_id == r.dst_id:
            violations.append(IntegrityViolation(eid, "self_loop", f"{r.src_type}:{r.src_id}"))
            continue
        for side, ntype, nid in (("src", r.src_type, r.src_id), ("dst", r.dst_type, r.dst_id)):
            table = _endpoint_table(ntype)
            row = session.execute(
                text(f"SELECT tenant_id FROM {table} WHERE id = :nid"),  # noqa: S608 - fixed table set
                {"nid": nid},
            ).first()
            if row is None:
                violations.append(
                    IntegrityViolation(eid, f"orphan_{side}", f"{ntype}:{nid} not found")
                )
            elif str(row.tenant_id) != str(r.tenant_id):
                violations.append(
                    IntegrityViolation(
                        eid, "cross_tenant",
                        f"{side} {ntype}:{nid} in tenant {row.tenant_id}, not {r.tenant_id}",
                    )
                )
    return violations
