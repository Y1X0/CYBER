"""Deterministic attack-graph analysis tests (Phase 6D) — pure, no DB/network/AI.

Covers the closure criteria: path correctness, cycle handling, deterministic ordering, dedup,
depth/paths/nodes bounds + truncation, empty/disconnected graphs, duplicate edges, blast radius,
chokepoint math, the provable "cuts 80% of paths" result, and drift classification.
"""

from __future__ import annotations

from guardian_core import attack_graph as ag


def _n(nid, *, node_type="service", key=None, exposure=0, internet=False,
       state="active", crit=None, rank=0):
    return ag.NodeView(
        id=nid, node_type=node_type, canonical_key=key or nid, exposure_score=exposure,
        state=state, internet_reachable=internet, customer_criticality=crit, finding_max_rank=rank,
    )


def _e(src, dst, relation="resolves_to"):
    return ag.EdgeView(src_id=src, relation=relation, dst_id=dst)


# ── path correctness ──
def test_exposure_path_internet_to_exposed_service():
    nodes = [
        _n("sub", node_type="subdomain", key="a.example.com", internet=True),
        _n("ip", node_type="ip_address", key="1.2.3.4"),
        _n("svc", node_type="service", key="1.2.3.4:443", exposure=70),
    ]
    edges = [_e("sub", "ip", "resolves_to"), _e("ip", "svc", "hosts")]
    res = ag.exposure_paths(nodes, edges)
    assert [p.node_ids for p in res.paths] == [("sub", "ip", "svc")]
    assert res.truncated is False


def test_subdomain_of_is_not_a_reachability_hop():
    # subdomain_of is grouping — it must never form an exposure path.
    nodes = [
        _n("sub", node_type="subdomain", key="a.example.com", internet=True),
        _n("dom", node_type="domain", key="example.com", exposure=90),
    ]
    edges = [_e("sub", "dom", "subdomain_of")]
    assert ag.exposure_paths(nodes, edges).paths == ()


# ── cycle handling + dedup + duplicate edges ──
def test_cycle_is_handled_without_infinite_loop():
    nodes = [
        _n("a", node_type="subdomain", key="a", internet=True),
        _n("b", node_type="ip_address", key="b", exposure=60),
    ]
    edges = [_e("a", "b", "resolves_to"), _e("b", "a", "resolves_to")]  # cycle
    res = ag.exposure_paths(nodes, edges)
    assert [p.node_ids for p in res.paths] == [("a", "b")]  # terminates, no revisit


def test_duplicate_edges_do_not_duplicate_paths():
    nodes = [_n("a", node_type="subdomain", internet=True), _n("b", exposure=60)]
    edges = [_e("a", "b"), _e("a", "b"), _e("a", "b")]  # same edge thrice
    assert len(ag.exposure_paths(nodes, edges).paths) == 1


# ── deterministic ordering ──
def test_deterministic_ordering_is_reproducible():
    nodes = [_n("a", node_type="subdomain", internet=True),
             _n("t2", key="z", exposure=60), _n("t1", key="a", exposure=60)]
    edges = [_e("a", "t2", "hosts"), _e("a", "t1", "hosts")]
    r1 = ag.exposure_paths(nodes, edges)
    r2 = ag.exposure_paths(nodes, edges)
    assert [p.node_ids for p in r1.paths] == [p.node_ids for p in r2.paths]
    # ordered by (length, node_keys) → the 'a'-keyed target sorts before 'z'
    assert [p.node_ids for p in r1.paths] == [("a", "t1"), ("a", "t2")]


# ── bounds + truncation ──
def test_max_depth_prevents_deep_paths():
    nodes = [_n("e", node_type="subdomain", internet=True)]
    prev = "e"
    for i in range(6):
        nodes.append(_n(f"n{i}", exposure=60 if i == 5 else 0))
    edges = []
    for i in range(6):
        edges.append(_e(prev, f"n{i}", "resolves_to"))
        prev = f"n{i}"
    # target n5 is 6 hops deep; max_depth=3 cannot reach it
    res = ag.exposure_paths(nodes, edges, ag.Limits(max_depth=3))
    assert res.paths == ()


def test_max_paths_truncates():
    nodes = [_n("e", node_type="subdomain", internet=True), _n("hub")]
    edges = [_e("e", "hub", "resolves_to")]
    for i in range(150):
        nodes.append(_n(f"t{i:03d}", exposure=60))
        edges.append(_e("hub", f"t{i:03d}", "hosts"))
    res = ag.exposure_paths(nodes, edges, ag.Limits(max_paths=100))
    assert len(res.paths) == 100
    assert res.truncated is True


def test_max_nodes_truncates():
    nodes = [_n("e", node_type="subdomain", internet=True)]
    for i in range(50):
        nodes.append(_n(f"n{i}", exposure=60))
    edges = [_e("e", f"n{i}", "resolves_to") for i in range(50)]
    res = ag.exposure_paths(nodes, edges, ag.Limits(max_nodes=3))
    assert res.truncated is True


# ── empty / disconnected ──
def test_empty_graph():
    res = ag.exposure_paths([], [])
    assert res.paths == () and res.truncated is False


def test_disconnected_graph_has_no_paths():
    nodes = [_n("e", node_type="subdomain", internet=True), _n("s", exposure=90)]
    assert ag.exposure_paths(nodes, []).paths == ()  # no edge → no path


# ── the synthetic 5-path graph: 4 through X → provable 0.8 ──
def _five_path_graph():
    nodes = [
        _n("E", node_type="subdomain", key="e1", internet=True),
        _n("E2", node_type="subdomain", key="e2", internet=True),
        _n("X", node_type="ip_address", key="x"),
        _n("Y", node_type="ip_address", key="y"),
    ]
    for i in range(1, 5):
        nodes.append(_n(f"T{i}", key=f"t{i}", exposure=60))
    nodes.append(_n("T5", key="t5", exposure=60))
    edges = [_e("E", "X", "resolves_to"), _e("E2", "Y", "resolves_to"), _e("Y", "T5", "hosts")]
    for i in range(1, 5):
        edges.append(_e("X", f"T{i}", "hosts"))
    return nodes, edges


def test_blast_radius_counts():
    nodes, edges = _five_path_graph()
    b = ag.blast_radius(nodes, edges, "E")
    assert b.affected_nodes == 5           # X, T1..T4
    assert b.sensitive_nodes == 4          # T1..T4
    assert b.exposure_paths == 4           # 4 exposure paths run through E
    assert b.weighted_impact == 240        # 4×60 + X(0)


def test_chokepoint_cuts_eighty_percent():
    nodes, edges = _five_path_graph()
    res = ag.chokepoints(nodes, edges, top=10)
    assert res.total_paths == 5
    x = next(c for c in res.chokepoints if c.node_id == "X")
    assert x.paths_cut == 4
    assert x.fraction == 0.8               # exact count, not an estimate: cuts 4 of 5
    assert len(x.evidence_paths) >= 1      # the cut paths are returned as evidence
    for p in x.evidence_paths:
        assert "X" in p.node_ids


# ── drift classification (only real emitted event types) ──
def test_classify_drift_maps_real_events_only():
    events = [
        {"node_id": "1", "node_key": "a", "event_type": "observed", "detail": {},
         "occurred_at": "2026-01-01T00:00:00+00:00"},
        {"node_id": "2", "node_key": "b", "event_type": "tls_changed",
         "detail": {"changes": ["tls changed"]}, "occurred_at": "2026-01-02T00:00:00+00:00"},
        {"node_id": "3", "node_key": "c", "event_type": "changed",
         "detail": {"changes": ["exposure 30->60"]}, "occurred_at": "2026-01-03T00:00:00+00:00"},
        {"node_id": "4", "node_key": "d", "event_type": "state_changed",
         "detail": {"changes": ["state active->shadow"]}, "occurred_at": "2026-01-04T00:00:00+00:00"},
        {"node_id": "5", "node_key": "e", "event_type": "changed",
         "detail": {"changes": ["banner changed"]}, "occurred_at": "2026-01-05T00:00:00+00:00"},
        {"node_id": "6", "node_key": "f", "event_type": "port_opened",  # aspirational → ignored
         "detail": {}, "occurred_at": "2026-01-06T00:00:00+00:00"},
    ]
    stale = [{"node_id": "7", "node_key": "g", "detail": {"relation": "hosts"},
              "occurred_at": "2026-01-07T00:00:00+00:00"}]
    report = ag.classify_drift(events, stale)
    kinds = {i.node_key: i.kind for i in report.items}
    assert kinds == {
        "a": "appeared", "b": "tls_changed", "c": "newly_exposed",
        "d": "newly_exposed", "e": "changed", "g": "disappeared",
    }
    assert "f" not in kinds  # port_opened is not invented
    # deterministic order by occurred_at
    assert [i.node_key for i in report.items] == ["a", "b", "c", "d", "e", "g"]
