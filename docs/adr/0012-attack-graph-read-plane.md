# ADR-012 — Phase 6D: deterministic, read-only attack-graph analysis plane

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

The discovery pipeline (6A–6C) builds a provenance-carrying graph of `domain / subdomain /
ip_address / service` nodes joined by `subdomain_of / resolves_to / hosts` edges, with a
deterministic `exposure_score` per node. The platform now needs to *answer questions* over that
graph — where is exposure, what is the blast radius of a node, which node is the chokepoint — without
adding any network capability and without letting AI decide severity or impact.

A read of the actual schema settled the scope honestly:

- There are **no `finding` nodes and no `exposes`/`enables` edges** — no provider emits them. So an
  "Internet → Vulnerability → Asset" attack path does not exist in the data and must not be claimed.
- What *does* exist is a real internet-exposure topology (`resolves_to`, `hosts`) plus a deterministic
  exposure score, customer criticality, and findings joinable by `asset_id`.

## Decision

**Build 6D as a deterministic, strictly read-only analysis plane over the graph that exists (option
A), naming results honestly.**

1. **Naming.** A path is an **internet exposure path** to an **exposed service/asset** — never
   "internet → vulnerability". Vulnerability severity is **enrichment** carried on a node (via a
   read-only `graph node → asset_id → findings` join), never a hop in the path and never a synthetic
   graph edge/node.

2. **Reachability semantics.** Exposure paths are built only from forward reachability edges
   (`resolves_to`, `hosts`). `subdomain_of` is grouping, not a reachability hop, so it never forms a
   path. Only `state='active'` edges are traversed.

3. **Determinism.** All algorithms live in `guardian_core.attack_graph` (pure — no DB, network, or
   AI). Neighbours and results are ordered by a stable key; traversal is depth/count-bounded; cycles
   are handled with a per-path visited set. Sensitivity, blast radius, and chokepoint impact are
   computed only from pipeline-produced fields (`exposure_score`, `state`, `customer_criticality`,
   joined finding severity) — never an AI judgment.

4. **Chokepoints are provable.** `paths_cut(node)` is the exact count of enumerated exposure paths
   that traverse a node (removing it removes exactly those paths); `fraction = paths_cut / total`, so
   "cuts 80% of paths" is a real count with the cut paths returned as evidence.

5. **Bounds.** `max_depth=6`, `max_paths=100`, `max_nodes_traversed=10_000`; exceeding any bound
   returns a partial result flagged `truncated=true` — never an unbounded traversal or a hang.

6. **Read-only + Control Plane.** The `DbGraphProjector` runs in the Control Plane (API) on the
   RLS-enforced app session and never writes a node, edge, event, score, or snapshot. It never runs
   on the recon worker and opens no socket.

7. **Tenant isolation (non-negotiable).** Defense-in-depth: every query runs under RLS
   (`app.current_tenant`) **and** filters `tenant_id` explicitly, so a tenant can never analyse
   another tenant's graph.

8. **No migration.** Everything is computed from existing tables; the `idx_graph_src` / `idx_graph_dst`
   indexes already back both traversal directions.

## Alternatives considered

- **Option B — wait for `finding` nodes and `exposes`/`enables` edges, then model true
  internet→vulnerability paths.** Deeper, but it widens scope and delays 6D behind a producer that
  does not exist. Rejected for now: 6D delivers real value over the existing topology, and the graph
  can be extended later without rebuilding the foundation.
- **Persisting computed paths/chokepoints as snapshots.** Rejected: writing analysis results would
  break the read-only guarantee. Compute on demand; a persisted snapshot store is a separate, later
  decision.
- **Enforcing the allowlist / running analysis in a worker.** Rejected: read-only analytics is a
  Control-Plane concern; keeping it there preserves the Control/Execution-Plane split.

## Consequences

- The platform can answer exposure-path, blast-radius, chokepoint, and drift questions deterministically
  and reproducibly, with evidence, over real data — and says exactly what the data supports, no more.
- Vulnerability severity enriches a node only where it is linked to a managed asset (`asset_id`);
  pure-topology service nodes carry no finding enrichment until they are linked. This is honest and
  expected, not a bug.
- Exposure drift uses only the node-event types the ingestor actually emits today (`observed`,
  `tls_changed`, `service_changed`, `state_changed`, `changed`) plus edge `stale` transitions —
  aspirational event types (`port_opened`, `certificate_changed`, …) are never assumed.

### Deferred / technical debt (documented, not in 6D)

- **`finding` nodes + `exposes`/`enables` edges** so true internet→vulnerability paths can be modelled;
  the graph extends without rebuilding this plane.
- **`netblock`/`cloud_resource` nodes and `contains`/`routes_to`/`trusts` edges** when providers emit
  them.
- **Richer node-event producers** (`port_opened`/`closed`, `certificate_changed`) to sharpen drift.
- **Persisted analysis snapshots** (a write concern) if historical path/chokepoint diffing is wanted.
- **Subgraph load cap** (`max_nodes` on the node load) is a coarse guard; a windowed/streaming loader
  is a later performance item for very large tenants.
