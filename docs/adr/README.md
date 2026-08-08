# Architecture Decision Records (ADRs)

This directory holds **incremental** architecture decisions made *after* the initial design package.
Each ADR is an immutable record: once accepted, it is superseded by a new ADR rather than edited.

## Format

Create `NNNN-short-title.md` using this template:

```markdown
# ADR-NNNN — <title>

- **Status:** Proposed | Accepted | Superseded by ADR-XXXX
- **Date:** YYYY-MM-DD
- **Deciders:** <names/roles>

## Context
What forces are at play? What problem needs a decision?

## Decision
The choice made, stated plainly.

## Alternatives considered
Options weighed and why they lost.

## Consequences
What becomes easier/harder. Follow-ups and risks.
```

## Foundational decisions

The nine foundational decisions (ADR-001 … ADR-009) that anchor the initial build are recorded in
[`../architecture/04-technology-decisions.md`](../architecture/04-technology-decisions.md):

| ADR | Decision |
|---|---|
| 001 | Backend: Python + FastAPI |
| 002 | Database: PostgreSQL (JSONB + arrays + RLS + pgvector) |
| 003 | Async: Celery + Redis behind a `JobQueue` port |
| 004 | Frontend: React + TypeScript + Vite |
| 005 | Scanning: wrap best-in-class OSS, don't reinvent |
| 006 | AI: Claude via Anthropic API, provider-abstracted, retrieval-grounded |
| 007 | Packaging: Docker-first, cloud-ready |
| 008 | Observability: OpenTelemetry-native |
| 009 | License: Apache-2.0 |

## Incremental decisions

| ADR | Decision |
|---|---|
| [010](0010-phase5-rls-and-foundational-seams.md) | Phase 5: two-role RLS tenant isolation + Tier-1 foundational seams |
| [011](0011-recon-execution-plane-isolation.md) | Phase 6C.3: Recon execution-plane isolation (network isolation + egress allowlist) |
| [012](0012-attack-graph-read-plane.md) | Phase 6D: deterministic, read-only attack-graph analysis plane (exposure paths / blast radius / chokepoints / drift) |
| [013](0013-recon-result-return.md) | Phase 6C.4: Recon result-return — no DB credentials in the network-facing execution plane + execution hardening |
| [014](0014-graph-enrichment-attack-paths.md) | Phase 6E: graph enrichment (finding/asset nodes, exposes/serves edges) + read-only attack-path analysis |
| [015](0015-netblock-world-model.md) | Phase 6F: netblock world-model (authorized-CIDR enrichment + passive ASN/RIR provider, `contains` grouping only) |
| [016](0016-tool-execution-framework.md) | Security Tool Execution Framework (Phase 1): governed rail (ToolProvider, EffectiveScope, policy gate, DB-less tool plane, evidence hash-chain) — no tools |
| [017](0017-web-tls-read-only-provider.md) | Provider #1: read-only Web/TLS tool (Evidence-first, exact canonical-host asset binding, reuses Scan/ScanEngineRun/to_finding/enrich_graph) |

New ADRs start at **ADR-018**.
