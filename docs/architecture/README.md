# Security Guardian Platform — Architecture Package

This directory is the **complete design specification** for the Security Guardian Platform.
It exists to be reviewed and approved *before* implementation begins.

## How to read this package

1. **[01 — System Architecture](01-architecture.md)**
   The heart of the design. High-level context, container/component views, request & scan
   data flows, the six scanner engines, the AI analyst pipeline, and the deployment topology.

2. **[02 — Folder Structure](02-folder-structure.md)**
   The physical monorepo layout: apps, services, workers, packages, infra, and how the pieces map
   onto the architecture in doc 01.

3. **[03 — Database Schema](03-database-schema.md)**
   The relational data model — organizations, projects, scans, findings, the vulnerability
   knowledge base, reports, and audit trail — with indexing, retention, and migration strategy.

4. **[04 — Technology Decisions](04-technology-decisions.md)**
   Every major stack choice (backend, DB, queue, workers, frontend, AI, scanning tools) with the
   trade-offs weighed and the reason for the pick. ADR-style.

5. **[05 — Development Roadmap](05-development-roadmap.md)**
   Phase 1–5 delivery plan with scope, exit criteria, and dependencies for each phase.

6. **[06 — Security Model](06-security-model.md)**
   How the platform secures *itself*: threat model, trust boundaries, tenant isolation, secrets
   handling, authorization enforcement, and safe-scanning guarantees.

Architecture Decision Records live in [`../adr/`](../adr/).

## Design principles

| Principle | What it means here |
|---|---|
| **Defensive by construction** | The system detects and reports; it never exploits. Safe-scanning is enforced in code, not policy alone. |
| **Multi-tenant & isolated** | Every row is scoped to an organization. Scan workloads run sandboxed and network-restricted. |
| **Normalize everything** | Every scanner emits findings into one canonical schema keyed to CWE/CVE/OWASP so scoring, dedup, and reporting are engine-agnostic. |
| **Pluggable engines** | Scanners are adapters behind a stable interface. Adding a tool never touches the core. |
| **Explainable AI, grounded** | The AI analyst augments — it explains, prioritizes, and drafts. Findings and severities remain traceable to deterministic scanner evidence. |
| **Shift-left & gate** | Results are actionable inside the PR; policy decides what blocks a deployment. |
| **Standards-mapped** | Findings carry ASVS / Top 10 / CWE / CIS / NIST references for audit and compliance. |

## One-paragraph summary

A FastAPI control plane fronts a PostgreSQL system-of-record and a Redis-backed job queue. Scan
requests are dispatched to a pool of sandboxed Celery workers, each hosting pluggable engine
adapters (SAST, SCA, DAST-lite, API, CSPM, container). Engines emit findings in a canonical,
standards-mapped schema; a normalization + dedup + risk-scoring pipeline persists them. An AI
analyst service (Claude via the Anthropic API, retrieval-grounded on the vulnerability knowledge
base) explains findings, scores risk, drafts remediation, and assembles reports. A React dashboard
and a GitHub App / CI integration expose everything to users and pipelines. The whole system runs
in Docker, is cloud-deployment-ready, and is designed for observability and multi-tenant isolation
from day one.
