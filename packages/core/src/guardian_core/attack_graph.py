"""Deterministic attack-graph analysis (Phase 6D) — pure algorithms, no DB / network / AI.

The read-side analysis over the topology the discovery pipeline already built. It answers, from the
data alone and reproducibly:

  * exposure paths — internet-facing entry → an exposed service/asset, over reachability
    edges only (`resolves_to`, `hosts`). `subdomain_of` is grouping, not a reachability hop, so it
    never forms a path. There are no synthetic `finding` nodes or `exposes` edges — vulnerability
    severity is enrichment carried on a node (see `NodeView.finding_max_rank`), never a path hop.
  * blast radius — what a node can reach, quantified deterministically.
  * chokepoints — which node, if remediated, cuts the most exposure paths; `paths_cut(node)`
    exact count of enumerated paths that traverse it, with the cut paths returned as evidence.
  * exposure drift — classifying already-emitted node history into appeared / newly-exposed /
    changed / disappeared.

Everything is deterministic: neighbours and results are ordered by a stable key, traversal is
depth/count-bounded, and cycles are handled with a per-path visited set. No AI decides sensitivity,
criticality, or impact — those come only from fields the deterministic pipeline already produced.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

# The relations that form an exposure path (forward reachability). `subdomain_of` is a grouping
# relation (a subdomain belongs to a domain), NOT a reachability hop, so it is excluded.
REACHABILITY_RELATIONS: frozenset[str] = frozenset({"resolves_to", "hosts"})

# The relations that form an ATTACK path (6E): reachability, then `serves` (topology → asset)
# and `exposes` (asset → finding). This is DISTINCT from exposure paths and never touches `enables`
# (not produced) so a real "internet → vulnerability" path is only the edges the data actually has.
ATTACK_RELATIONS: frozenset[str] = frozenset({"resolves_to", "hosts", "serves", "exposes"})

DEFAULT_MAX_DEPTH = 6
DEFAULT_MAX_PATHS = 100
DEFAULT_MAX_NODES = 10_000

# A node counts as an exposed/sensitive endpoint when the deterministic pipeline already says so:
EXPOSURE_SENSITIVE_THRESHOLD = 50  # exposure_score (0–100) at/above this
_HIGH_SEVERITY_RANK = 3            # Severity.HIGH.rank — a linked finding at/above adds it
_EVIDENCE_SAMPLE = 3              # cut-path samples returned per chokepoint


@dataclass(frozen=True)
class Limits:
    max_depth: int = DEFAULT_MAX_DEPTH
    max_paths: int = DEFAULT_MAX_PATHS
    max_nodes: int = DEFAULT_MAX_NODES


@dataclass(frozen=True)
class NodeView:
    """A node as the analysis sees it — only deterministic, pipeline-produced fields."""

    id: str
    node_type: str
    canonical_key: str
    exposure_score: int = 0
    state: str = "active"
    internet_reachable: bool = False
    customer_criticality: str | None = None
    has_asset: bool = False
    finding_max_rank: int = 0            # 0 = none; else Severity.rank of the worst finding
    finding_counts: dict[str, int] = field(default_factory=dict)  # severity -> count (enrichment)

    def sort_key(self) -> tuple[str, str, str]:
        return (self.node_type, self.canonical_key, self.id)


@dataclass(frozen=True)
class EdgeView:
    src_id: str
    relation: str
    dst_id: str


@dataclass(frozen=True)
class Path:
    node_ids: tuple[str, ...]
    node_keys: tuple[str, ...]


@dataclass(frozen=True)
class PathResult:
    paths: tuple[Path, ...]
    truncated: bool = False


@dataclass(frozen=True)
class ReachResult:
    node_ids: tuple[str, ...]
    truncated: bool = False


@dataclass(frozen=True)
class BlastRadius:
    root_id: str
    root_key: str
    affected_nodes: int
    sensitive_nodes: int
    exposure_paths: int
    weighted_impact: int
    affected_ids: tuple[str, ...]
    sensitive_ids: tuple[str, ...]
    truncated: bool = False


@dataclass(frozen=True)
class Chokepoint:
    node_id: str
    node_key: str
    node_type: str
    paths_cut: int
    total_paths: int
    fraction: float
    evidence_paths: tuple[Path, ...]


@dataclass(frozen=True)
class ChokepointResult:
    chokepoints: tuple[Chokepoint, ...]
    total_paths: int
    truncated: bool = False


@dataclass(frozen=True)
class DriftItem:
    node_id: str
    node_key: str
    kind: str      # appeared | newly_exposed | tls_changed | service_changed | state_changed
    detail: dict   #                         | changed | disappeared
    occurred_at: str


@dataclass(frozen=True)
class DriftReport:
    items: tuple[DriftItem, ...]


# ── sensitivity + adjacency ──
def is_sensitive(n: NodeView) -> bool:
    """Deterministic 'exposed endpoint' test — all inputs are pipeline-produced facts."""
    return (
        n.exposure_score >= EXPOSURE_SENSITIVE_THRESHOLD
        or n.state == "shadow"
        or n.customer_criticality == "high"
        or n.finding_max_rank >= _HIGH_SEVERITY_RANK
    )


def _index(nodes: list[NodeView]) -> dict[str, NodeView]:
    return {n.id: n for n in nodes}


def build_adjacency(
    nodes: list[NodeView], edges: list[EdgeView],
    relations: frozenset[str] = REACHABILITY_RELATIONS,
) -> dict[str, list[str]]:
    """Forward adjacency over the given relation set; deterministic, de-duplicated.

    Defaults to reachability relations so exposure-path/blast/chokepoint behaviour is unchanged;
    attack-path analysis passes ATTACK_RELATIONS.
    """
    by_id = _index(nodes)
    adj: dict[str, list[str]] = {n.id: [] for n in nodes}
    for e in edges:
        if e.relation in relations and e.src_id in by_id and e.dst_id in by_id:
            adj[e.src_id].append(e.dst_id)
    for k, neighbours in adj.items():
        adj[k] = sorted(set(neighbours), key=lambda i: by_id[i].sort_key())
    return adj


def entry_ids(nodes: list[NodeView]) -> list[str]:
    """Internet-facing nodes — the start of every exposure path."""
    return [n.id for n in sorted(nodes, key=lambda n: n.sort_key()) if n.internet_reachable]


def sensitive_ids(nodes: list[NodeView]) -> list[str]:
    return [n.id for n in sorted(nodes, key=lambda n: n.sort_key()) if is_sensitive(n)]


def finding_ids(nodes: list[NodeView]) -> list[str]:
    """`finding` nodes — the endpoints of an attack path (a real vulnerability, 6E)."""
    return [n.id for n in sorted(nodes, key=lambda n: n.sort_key()) if n.node_type == "finding"]


def _mk_path(path: tuple[str, ...], by_id: dict[str, NodeView]) -> Path:
    return Path(node_ids=path, node_keys=tuple(by_id[i].canonical_key for i in path))


def _enumerate(
    adj: dict[str, list[str]], by_id: dict[str, NodeView],
    sources: list[str], targets: set[str], limits: Limits,
) -> PathResult:
    """Bounded, deterministic DFS enumerating simple paths from any source to any target.

    Cycle-safe (a node never repeats within a path). Stops at `max_paths` or after visiting
    `max_nodes` frontier entries, marking the result `truncated`. Results are ordered by
    (length, node keys) so the output is reproducible regardless of traversal interleaving.
    """
    results: list[Path] = []
    seen: set[tuple[str, ...]] = set()
    budget = 0
    truncated = False

    for s in sorted(set(sources), key=lambda i: by_id[i].sort_key()):
        if truncated or len(results) >= limits.max_paths:
            break
        stack: list[tuple[str, tuple[str, ...]]] = [(s, (s,))]
        while stack:
            if len(results) >= limits.max_paths:
                truncated = True
                break
            node, path = stack.pop()
            budget += 1
            if budget > limits.max_nodes:
                truncated = True
                break
            if node in targets and path not in seen:
                seen.add(path)
                results.append(_mk_path(path, by_id))
                if len(results) >= limits.max_paths:
                    truncated = True
                    break
            if len(path) - 1 >= limits.max_depth:
                continue
            for nb in reversed(adj.get(node, [])):  # reversed → pop() yields sorted order
                if nb not in path:                  # per-path visited = cycle protection
                    stack.append((nb, (*path, nb)))

    results.sort(key=lambda p: (len(p.node_ids), p.node_keys))
    return PathResult(tuple(results), truncated)


# ── public analysis surface (all deterministic) ──
def exposure_paths(
    nodes: list[NodeView], edges: list[EdgeView], limits: Limits | None = None
) -> PathResult:
    """Every internet-exposure path: an internet-facing entry → an exposed/sensitive node."""
    limits = limits or Limits()
    by_id = _index(nodes)
    adj = build_adjacency(nodes, edges)
    return _enumerate(adj, by_id, entry_ids(nodes), set(sensitive_ids(nodes)), limits)


def attack_paths(
    nodes: list[NodeView], edges: list[EdgeView], limits: Limits | None = None
) -> PathResult:
    """Every real attack path (6E): an internet-facing entry → a `finding`, over ATTACK_RELATIONS
    only (reachability + `serves` + `exposes`). Distinct from `exposure_paths`, which is unchanged;
    this never uses `enables` (not produced), so a path exists only where the data's edges do."""
    limits = limits or Limits()
    by_id = _index(nodes)
    adj = build_adjacency(nodes, edges, ATTACK_RELATIONS)
    return _enumerate(adj, by_id, entry_ids(nodes), set(finding_ids(nodes)), limits)


def paths_to(
    nodes: list[NodeView], edges: list[EdgeView], target_id: str, limits: Limits | None = None
) -> PathResult:
    """Exposure paths from any internet-facing entry to a specific target node."""
    limits = limits or Limits()
    by_id = _index(nodes)
    if target_id not in by_id:
        return PathResult((), False)
    adj = build_adjacency(nodes, edges)
    return _enumerate(adj, by_id, entry_ids(nodes), {target_id}, limits)


def reachable_from(
    nodes: list[NodeView], edges: list[EdgeView], src_id: str, limits: Limits | None = None
) -> ReachResult:
    """Nodes reachable from `src_id` over reachability edges, bounded by depth and count."""
    limits = limits or Limits()
    by_id = _index(nodes)
    if src_id not in by_id:
        return ReachResult((), False)
    adj = build_adjacency(nodes, edges)
    visited = {src_id}
    order: list[str] = []
    q: deque[tuple[str, int]] = deque([(src_id, 0)])
    truncated = False
    budget = 0
    while q:
        node, depth = q.popleft()
        budget += 1
        if budget > limits.max_nodes:
            truncated = True
            break
        if depth >= limits.max_depth:
            continue
        for nb in adj.get(node, []):
            if nb not in visited:
                visited.add(nb)
                order.append(nb)
                q.append((nb, depth + 1))
                if len(order) >= limits.max_nodes:
                    truncated = True
                    break
        if truncated:
            break
    ids = tuple(sorted(order, key=lambda i: by_id[i].sort_key()))
    return ReachResult(ids, truncated)


def blast_radius(
    nodes: list[NodeView], edges: list[EdgeView], root_id: str, limits: Limits | None = None
) -> BlastRadius:
    """Deterministic blast radius of a node: what it reaches, how much of it is sensitive, how many
    exposure paths run through it, and a weighted impact — all from pipeline-produced fields."""
    limits = limits or Limits()
    by_id = _index(nodes)
    if root_id not in by_id:
        return BlastRadius(root_id, "", 0, 0, 0, 0, (), (), False)

    reach = reachable_from(nodes, edges, root_id, limits)
    affected = reach.node_ids
    sensitive = tuple(i for i in affected if is_sensitive(by_id[i]))
    weighted = sum(by_id[i].exposure_score for i in affected)

    paths = exposure_paths(nodes, edges, limits)
    through_root = sum(1 for p in paths.paths if root_id in p.node_ids)

    return BlastRadius(
        root_id=root_id, root_key=by_id[root_id].canonical_key,
        affected_nodes=len(affected), sensitive_nodes=len(sensitive),
        exposure_paths=through_root, weighted_impact=weighted,
        affected_ids=affected, sensitive_ids=sensitive,
        truncated=reach.truncated or paths.truncated,
    )


def chokepoints(
    nodes: list[NodeView], edges: list[EdgeView],
    limits: Limits | None = None, top: int = 10,
) -> ChokepointResult:
    """Rank nodes by how many exposure paths their removal would cut.

    `paths_cut(node)` is the exact number of enumerated exposure paths that traverse `node`:
    removing it removes exactly those paths. `fraction` = paths_cut / total,
    so a result like 0.8 is an exact count ("cuts 4 of 5 paths"), never an estimate. The cut paths
    are returned as evidence, making the ranking explainable and reproducible.
    """
    limits = limits or Limits()
    by_id = _index(nodes)
    paths = exposure_paths(nodes, edges, limits)
    total = len(paths.paths)

    on_paths: dict[str, list[Path]] = {}
    for p in paths.paths:
        for nid in set(p.node_ids):
            on_paths.setdefault(nid, []).append(p)

    ranked = sorted(
        on_paths.items(),
        key=lambda kv: (-len(kv[1]), by_id[kv[0]].sort_key()),
    )[: max(0, top)]

    out = tuple(
        Chokepoint(
            node_id=nid, node_key=by_id[nid].canonical_key, node_type=by_id[nid].node_type,
            paths_cut=len(hits), total_paths=total,
            fraction=(len(hits) / total) if total else 0.0,
            evidence_paths=tuple(hits[:_EVIDENCE_SAMPLE]),
        )
        for nid, hits in ranked
    )
    return ChokepointResult(out, total, paths.truncated)


# ── exposure drift (classification of already-emitted history) ──
def _exposure_rose(changes: list) -> bool:
    """True if a 'changed' detail records an exposure increase (e.g. 'exposure 30->60')."""
    for c in changes or []:
        text = str(c)
        if text.startswith("exposure ") and "->" in text:
            try:
                old_s, new_s = text[len("exposure "):].split("->", 1)
                if int(new_s.strip()) > int(old_s.strip()):
                    return True
            except ValueError:
                continue
    return False


def _became_shadow(changes: list) -> bool:
    return any("->shadow" in str(c) for c in changes or [])


def classify_drift(events: list[dict], stale_edges: list[dict]) -> DriftReport:
    """Turn already-emitted node_events (+ stale edges) into a deterministic drift report.

    Uses ONLY event types the ingestor actually emits today — observed / tls_changed /
    service_changed / state_changed / changed — plus edges that transitioned to `stale`. It never
    assumes aspirational event types (port_opened, certificate_changed, ...) exist in history.

    `events`: dicts with node_id, node_key, event_type, detail, occurred_at (ISO str).
    `stale_edges`: dicts with node_id, node_key, occurred_at, detail.
    """
    items: list[DriftItem] = []
    for e in events:
        et = e.get("event_type", "")
        changes = (e.get("detail") or {}).get("changes", [])
        if et == "observed":
            kind = "appeared"
        elif et == "tls_changed":
            kind = "tls_changed"
        elif et == "service_changed":
            kind = "service_changed"
        elif et == "state_changed":
            kind = "newly_exposed" if _became_shadow(changes) else "state_changed"
        elif et == "changed":
            rose = _exposure_rose(changes) or _became_shadow(changes)
            kind = "newly_exposed" if rose else "changed"
        else:
            continue  # unknown/aspirational event types are ignored, not invented
        items.append(DriftItem(
            node_id=str(e.get("node_id", "")), node_key=str(e.get("node_key", "")),
            kind=kind, detail=dict(e.get("detail") or {}),
            occurred_at=str(e.get("occurred_at", "")),
        ))
    for s in stale_edges:
        items.append(DriftItem(
            node_id=str(s.get("node_id", "")), node_key=str(s.get("node_key", "")),
            kind="disappeared", detail=dict(s.get("detail") or {}),
            occurred_at=str(s.get("occurred_at", "")),
        ))
    items.sort(key=lambda d: (d.occurred_at, d.node_key, d.kind))
    return DriftReport(tuple(items))
