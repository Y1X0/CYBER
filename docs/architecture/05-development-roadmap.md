# 05 — Development Roadmap

Five phases, each shippable and independently valuable. Every phase lists **scope**, **exit
criteria**, and **dependencies**. Nothing here is built until this architecture package is approved.

```mermaid
graph LR
    P1["Phase 1<br/>Foundation"] --> P2["Phase 2<br/>Code + Deps + KB"]
    P2 --> P3["Phase 3<br/>AI + Reports + Dashboard"]
    P3 --> P4["Phase 4<br/>Cloud + CI/CD"]
    P4 --> P5["Phase 5<br/>Production Hardening"]
```

---

## Phase 1 — Foundation

**Goal:** a running skeleton that can authenticate a user, register a project, and execute a trivial
scan end-to-end through the real pipeline.

**Scope**
- Monorepo scaffolding, tooling (ruff/mypy/pytest, pre-commit), `docker-compose` full-stack up.
- Database: core tables (orgs, users, memberships, projects, targets, scans, scan_engine_runs,
  findings, audit_log) + Alembic + RLS + seed script.
- Control plane: FastAPI app factory, layered structure, OAuth2/OIDC + JWT auth, RBAC, API keys.
- Async backbone: Celery + Redis, `JobQueue` port, one **reference engine** (secrets scan) proving
  trigger → queue → worker → canonical finding → persist.
- Canonical finding schema + severity model in `packages/core`.
- CI: lint, type-check, test, build images.

**Exit criteria**
- `docker compose up` → create account → create project → run a secrets scan → see a normalized
  finding in the DB and via the API. Green CI. Auth + tenant isolation covered by tests.

**Dependencies:** none (bootstraps the repo).

---

## Phase 2 — Code Analysis, Dependencies & Vulnerability Database  🚧 *in progress*

**Goal:** real, valuable static findings and a live vulnerability knowledge base.

**Delivered so far:** builtin SAST engine (insecure-code patterns, optional Semgrep wrap) and SCA
engine (manifest parse → KB match), both as plugins; the vulnerability KB models + offline seed
(CWE + sample CVEs) + OSV/EPSS/KEV feed clients + a graceful feed-sync task; the **Risk Engine**
(0–100 business-risk score with transparent rationale + business-impact input); structured
**evidence**; and the human-pentester **triage** (audited) + **report-approval** workflow. All
verified end-to-end against PostgreSQL. *Remaining:* dedup/trend across repeat scans, license/SBOM,
and scheduled feed beat.

**Scope**
- **SAST engine**: Semgrep + Bandit + ESLint-security adapters → canonical findings, CWE/OWASP mapping.
- **SCA engine**: OSV-Scanner + Trivy + Syft (SBOM) → vulnerable/outdated deps, supply-chain/license.
- **Secrets engine** hardened (history scanning, entropy tuning, allowlist/false-positive handling).
- **Vulnerability KB**: `vulnerabilities`, `weaknesses`, `advisories`, `kb_entries`, `feed_syncs`;
  scheduled sync jobs for NVD, OSV, GHSA, EPSS, KEV; CWE catalog + OWASP/CIS/ASVS seed mappings.
- **Normalization + dedup + risk scoring** pipeline (CVSS + EPSS + KEV + exposure + asset criticality).
- Sandbox hardening for workers (egress allowlist, resource/time limits, isolation).

**Exit criteria**
- Scanning a real repo yields deduplicated, standards-mapped, severity-scored findings for code +
  dependencies. Feed syncs run on schedule and enrich findings with CVSS/EPSS/KEV. Trend tracking
  (first-seen / still-open) works across repeat scans.

**Dependencies:** Phase 1 (schema, queue, engine interface, scoring contracts).

---

## Phase 3 — AI Security Analyst, Reporting & Dashboard  🚧 *in progress*

**Goal:** turn findings into human-grade, prioritized reports and give users a UI to work them.

**Delivered so far:** `LLMProvider` port with a Claude (Anthropic SDK, structured-output) provider
and a **deterministic offline stub** default; RAG grounding over the KB (CWE/OWASP/CVE mapping —
pgvector is a later upgrade behind the same call); the AI analyst (explanation, impact, non-actionable
attack summary, remediation) with grounding guardrails; a 0–100 **security score**; **executive
summaries**; professional **HTML + PDF reports** (reportlab) with an export endpoint; a **grounded AI
chat** (answers only from the customer's findings); and a **React dashboard** (score, severity mix,
scan/findings views, chat). Verified end-to-end against PostgreSQL offline via the stub provider.
*Remaining:* pgvector embeddings retrieval, SSE live scan progress, and object-storage report archival.

**Scope**
- **AI analyst service**: `LLMProvider` (Claude) + RAG over `kb_entries` (pgvector); explanation,
  remediation drafting, prioritization; **schema-validated** structured output; injection-hardened,
  versioned prompts; guardrail + golden-output tests.
- **Reporting**: executive summary + vulnerability list (severity, evidence, impact, fix, references)
  + standards appendix + remediation plan; HTML render + PDF export to object storage.
- **Dashboard (React)**: auth, project management, scan history, live scan progress (SSE), finding
  triage (status workflow), report viewer, severity/trend visualizations.

**Exit criteria**
- A completed scan produces a full report with AI explanations grounded in real findings + KB
  references, viewable and exportable in the dashboard; users can triage findings and see trends.
  AI never emits a severity or CVE not backed by a finding (verified by guardrail tests).

**Dependencies:** Phase 2 (findings, KB, scoring).

---

## Phase 4 — Cloud Security & CI/CD Integration  ✅ *complete*

**Goal:** extend coverage to cloud + containers and embed the platform in the developer workflow.

**Delivered so far:** five new plugin engines (zero core changes) — **CSPM** (AWS/Azure/GCP config
audit, CIS-mapped: public storage, IAM over-permission, open networking, encryption, audit logging),
**container** (Dockerfile CIS rules), **Kubernetes** (manifest CIS rules), **DAST-lite**
(headers/TLS/cookies) and **API** (OpenAPI review) — the last three authorization-gated. Plus a
deterministic **deployment-gate policy engine** + `GET /scans/{id}/gate`, a **`guardian` CLI** and
reusable **GitHub Action** for CI blocking, and an HMAC-verified **GitHub webhook** that auto-triggers
scans. All offline-testable via config snapshots; the safe-scanning authorization gate is verified
end-to-end. *Remaining:* live cloud collectors (boto3/az/gcloud), Trivy image-CVE wrap, GitHub App
PR annotations.

**Scope**
- **CSPM engine**: AWS/Azure/GCP read-only, least-privilege config audits (IAM risk, public storage,
  open networking, unencrypted resources); mapped to CIS Benchmarks.
- **Container engine**: Trivy image scan, Hadolint Dockerfile, kube-linter/Checkov manifests.
- **DAST-lite + API engines**: header/TLS/session probes and OpenAPI-driven safe API checks — all
  gated by the `authorizations` table (no active probing without a valid authorization record).
- **DevSecOps**: GitHub App (Check Runs, inline PR annotations, comments), reusable GitHub Action,
  `guardian` CLI, and the **declarative policy engine** driving deployment gates.

**Exit criteria**
- A push/PR triggers a scan via the GitHub App; findings post to the PR; the policy engine passes or
  blocks the check per rules. Cloud and container targets produce CIS-mapped findings. Active web/API
  scans run only with authorization on record.

**Dependencies:** Phase 3 (reports/UI to surface results), Phase 2 (scoring/normalization).

---

## Phase 5 — Production Hardening  🚧 *in progress*

**Goal:** make it safe, reliable, and operable at scale — commercial-grade.

**Delivered so far (5A hardening + 5B foundational seams):**
- **Tenant isolation at the database (hard gate).** The API connects as a non-owner, RLS-enforced
  role (`guardian_app`); every request binds its connection to `app.current_tenant`, and PostgreSQL
  Row-Level Security policies reject any cross-tenant read or write — direct-`tenant_id` tables,
  parent-scoped child tables, the tenant's own row, and org-scoped policies alike. Workers and
  migrations keep a privileged (owner) connection for legitimate cross-tenant work. Verified by
  cross-tenant isolation, fail-closed (no context → zero rows), and negative-authorization
  (`WITH CHECK` rejects) tests.
- **Worker sandbox (hard gate, MVP).** Untrusted-input engines can run in a forked child with
  OS-enforced resource limits (CPU/memory/file-size/open-files/no-core), a wall-clock deadline,
  private temp isolation, and network-egress restriction (only DAST/API reach an authorized target).
  Opt-in via `sandbox_engines`; the container-per-run backend for external scanning at scale plugs in
  behind the same interface later.
- **No plaintext secrets.** Asset credentials are envelope-encrypted (`LocalKMSProvider`, Fernet)
  into `asset.secret_ref` and decrypted only in-memory at scan time; a cloud-KMS/BYOK provider
  implements the same port later.
- **Supply-chain self-scan.** A dependency-free **self-SBOM** generator (CycloneDX-lite) plus a
  **pip-audit** dependency-vulnerability scan run in CI (the platform inventorying and checking its
  own supply chain).
- **Foundational seams (storage only, no feature logic):** a polymorphic **graph edge**, a
  **domain-event outbox**, first-class **evidence** with a hash-chain integrity foundation, and
  **asset provenance** columns — the irreversible schema decisions that later phases (attack-path
  graph, SOAR, evidence workflow, EASM) build on without a core rewrite. Schema-integrity and
  backward-compatibility tests guard them.

*Remaining:* full threat-model closure, secrets-manager/BYOK integration, image signing + SBOM
publishing, reliability (autoscaling, DLQ, DR runbooks), observability (OTel/SLOs), compliance
(ASVS L2, NIST CSF), and packaging (Helm/Terraform).

**Scope**
- Security: full threat-model closure, secrets manager integration, dependency + container signing,
  SBOM publishing, the platform **self-scanning** in CI, pen-test remediation, rate limiting & abuse
  controls, data retention/erasure workflows.
- Reliability: autoscaling worker pools, backpressure, DLQ handling, graceful degradation, DR/backup
  runbooks, load testing.
- Observability: complete OTel coverage, SLOs + alerting, audit dashboards.
- Compliance: OWASP ASVS L2 verification, NIST CSF mapping documented, evidence exports.
- Ops: Helm chart, Terraform modules, upgrade/migration runbooks, admin docs.

**Exit criteria**
- Documented SLOs met under load; ASVS L2 checklist satisfied; self-scan green; DR restore verified;
  one-command install for both dev (compose) and prod (Helm). Ready for real users on their own
  authorized assets.

**Dependencies:** all prior phases.

---

## Sequencing principles

- **Vertical slices first.** Phase 1 proves the *entire* pipeline with one trivial engine before
  breadth is added — architecture risk is retired early.
- **Schema before engines.** The canonical finding model and scoring contracts (Phase 1) are frozen
  early so every later engine conforms.
- **Safety gates precede active scanning.** The `authorizations` mechanism ships with/before the DAST,
  API, and cloud engines (Phase 4), never after.
- **Each phase is demoable and useful on its own** — no phase is purely internal plumbing.
