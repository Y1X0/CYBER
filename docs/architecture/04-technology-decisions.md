# 04 — Technology Decisions

Each major choice below states the **decision**, the **alternatives weighed**, and the **rationale**.
These are the ADRs that anchor the build. Individual future decisions live in [`../adr/`](../adr/).

## Summary stack

| Layer | Choice |
|---|---|
| Backend API | **Python 3.12 + FastAPI** |
| Async runtime | **Celery + Redis** (abstracted behind a `JobQueue` port) |
| Database | **PostgreSQL 16** (+ `pgvector`, `pgcrypto`) |
| ORM / migrations | **SQLAlchemy 2.0 + Alembic** |
| Object storage | **S3-compatible** (MinIO locally) |
| Frontend | **React 18 + TypeScript + Vite** |
| AI | **Claude via the Anthropic API**, behind an `LLMProvider` port |
| Packaging | **Docker + docker-compose**, K8s/Helm for prod |
| Observability | **OpenTelemetry + Prometheus + Grafana + Loki** |
| CI | **GitHub Actions** (incl. self-scan) |
| License | **Apache-2.0** |

---

## ADR-001 — Backend: Python + FastAPI (not Node.js)

**Decision:** Python 3.12 with FastAPI for the control plane and workers.

**Alternatives:** Node.js/NestJS; Go.

**Rationale.** The security-tooling ecosystem is Python-native — Semgrep, Bandit, Checkov, Prowler,
ScoutSuite, and most SBOM/vuln libraries are Python or ship Python bindings. Sharing one language
across API, workers, and the AI service means the **canonical finding schema and scoring logic live
in a single package** imported everywhere (no cross-language drift). FastAPI gives async I/O,
Pydantic validation at the edges, and first-class OpenAPI generation. Go was tempting for worker
performance, but scanners are subprocess-bound (I/O and external-binary time dominates), so Go's CPU
edge is marginal while it would split the codebase in two. Node was viable for the API but weaker for
the scanning/AI core.

---

## ADR-002 — Database: PostgreSQL

**Decision:** PostgreSQL 16 as the single system of record.

**Alternatives:** MySQL; MongoDB; a dedicated vector DB (Pinecone/Weaviate) alongside.

**Rationale.** The data is deeply relational (org → project → scan → finding → vuln) and needs
transactional integrity for triage and audit. Postgres uniquely combines: **JSONB** for
engine-shaped detail, **arrays + GIN** for CVE lists, **Row-Level Security** for tenant isolation,
and **`pgvector`** for KB embeddings — so we get relational, document, and vector needs in one engine
with no second datastore to operate in Phase 1–3. A dedicated vector DB is a Phase-5 option only if
KB scale demands it; the retrieval layer is abstracted so that swap is contained.

---

## ADR-003 — Async: Celery + Redis, behind a queue port

**Decision:** Celery workers with a Redis broker for Phase 1; all enqueue/consume goes through a
`JobQueue` interface.

**Alternatives:** RabbitMQ; AWS SQS; Temporal; Arq/Dramatiq.

**Rationale.** Scans are long-running, fan-out, retryable background jobs — a textbook queue+worker
problem. Celery is mature, supports the routing/retry/beat features we need, and Redis doubles as
cache and rate-limit store, keeping the Phase-1 footprint small. Redis's at-least-once delivery is
acceptable because engine jobs are **idempotent** on `(scan_id, engine)`. The `JobQueue` port means a
move to RabbitMQ (stronger delivery) or SQS (managed) at scale is a config swap, not a rewrite.
Temporal was considered for durable orchestration but is operationally heavy for the current scope.

---

## ADR-004 — Frontend: React + TypeScript + Vite

**Decision:** React 18 + TypeScript, built with Vite; a component library (e.g. shadcn/ui) + a charts
library for the security dashboard.

**Alternatives:** Vue; SvelteKit; server-rendered templates.

**Rationale.** A security dashboard is a rich, stateful SPA (live scan progress via SSE, finding
triage, filterable tables, severity/trend charts). React has the deepest ecosystem for exactly these
components and the largest contributor pool for an open-source project. TypeScript end-to-end pairs
with the API's generated OpenAPI types for a typed client.

---

## ADR-005 — Scanning: wrap best-in-class OSS, don't reinvent

**Decision:** Each engine wraps a hardened, **pinned** OSS scanner and normalizes its output into the
canonical schema. Custom detection is limited to correlation, scoring, and gap-filling rules.

**Wrapped tools (indicative):** Semgrep, Bandit, ESLint-security (SAST); Gitleaks/TruffleHog
(secrets); OSV-Scanner, Trivy, Syft (SCA/SBOM); Hadolint, Trivy, kube-linter/Checkov (containers/K8s);
Prowler/ScoutSuite-style read-only checks (cloud); custom header/TLS/session/API analyzers (web/API).

**Rationale.** These tools represent thousands of maintainer-hours and curated rule sets;
re-implementing them would be lower quality and unmaintainable. The platform's differentiated value
is **unifying** heterogeneous output into one standards-mapped model, correlating and deduping across
engines, scoring risk consistently, layering AI explanation, and wiring it all into DevSecOps
workflow. Tools are version-pinned and run in sandboxes for reproducibility and safety. License
compatibility is reviewed per tool (invoked as separate processes, not linked) to keep the platform
Apache-2.0-clean.

---

## ADR-006 — AI: Claude via Anthropic API, provider-abstracted, retrieval-grounded

**Decision:** The default analyst LLM is **Claude (Anthropic API)**, accessed through an
`LLMProvider` interface; all AI output is **retrieval-grounded** on the KB and **schema-validated**.

**Alternatives:** OpenAI; self-hosted open models; no-LLM templated reports.

**Rationale.** The analyst must produce accurate, well-structured, safe security guidance and follow
strict formatting/grounding constraints — a strong instruction-following, long-context model. Claude
fits and is the platform default. Abstraction keeps the platform vendor-neutral (self-hosted/OSS
models remain a deployment option for air-gapped users). Grounding + structured output + explicit
uncertainty flags keep the AI honest: it **explains and prioritizes deterministic findings**, it does
not originate severities or invent CVEs. Prompt-injection hardening treats all scanned content as
untrusted data.

---

## ADR-007 — Packaging & deployment: Docker-first, cloud-ready

**Decision:** Every service ships as a container; `docker-compose` runs the full stack locally; K8s
manifests / a Helm chart target production; optional Terraform provisions managed Postgres/Redis/
object storage/secrets.

**Rationale.** Reproducible environments, trivial onboarding (`docker compose up`), and a clean path
to any cloud. Stateless services scale horizontally; state is externalized to managed backing
services; config is 12-factor (env-driven, validated at startup); secrets come from a dedicated
manager, never images.

---

## ADR-008 — Observability: OpenTelemetry-native

**Decision:** OpenTelemetry traces across API → queue → worker → AI; Prometheus metrics; structured
JSON logs shipped to Loki; Grafana dashboards; per-scan audit trail in the DB.

**Rationale.** Distributed, async scan pipelines are hard to debug blind. End-to-end trace context
(carried through the queue) makes a slow or failing scan diagnosable. Vendor-neutral OTel avoids
lock-in and works with any backend the operator prefers.

---

## ADR-009 — License: Apache-2.0

**Decision:** Apache-2.0.

**Rationale.** Permissive enough to encourage adoption and contribution while providing an explicit
patent grant (valuable for a security product). Compatible with the OSS tools invoked as separate
processes. Enterprise-friendly.

## Cross-cutting standards

Findings and reports are mapped to **OWASP ASVS**, **OWASP Top 10**, **CWE**, **NIST CSF 2.0**, and
**CIS Benchmarks**, per the [Security Model](06-security-model.md) and the mapping tables in
`packages/core/standards/`.
