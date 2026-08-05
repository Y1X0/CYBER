# 02 — Folder Structure

A **monorepo** so the control plane, workers, AI service, shared packages, frontend, and infra evolve
together with atomic changes and one source of truth for the canonical schema.

## Top level

```
security-guardian/
├── README.md
├── LICENSE                       # Apache-2.0
├── SECURITY.md                   # coordinated disclosure policy
├── CONTRIBUTING.md
├── CODEOWNERS
├── .env.example                  # documented, non-secret defaults
├── docker-compose.yml            # full local stack (one command)
├── Makefile                      # dev shortcuts: make up / test / lint / migrate
├── pyproject.toml                # workspace tooling (ruff, mypy, pytest)
│
├── docs/                         # this architecture package + guides + ADRs
│   ├── architecture/
│   └── adr/
│
├── apps/
│   └── web/                      # React dashboard (frontend)
│
├── services/
│   ├── api/                      # FastAPI control plane
│   ├── github_app/               # GitHub App / webhook service
│   └── ai_analyst/               # AI analyst service (RAG + LLM)
│
├── workers/
│   └── scanner/                  # Celery workers + engine adapters
│
├── packages/
│   ├── core/                     # shared domain: canonical schema, scoring, standards maps
│   ├── db/                       # SQLAlchemy models, migrations, repositories
│   ├── clients/                  # external clients (github, cloud, feeds, llm)
│   └── common/                   # config, logging, telemetry, errors, security utils
│
├── cli/
│   └── guardian/                 # `guardian scan` CLI for CI/CD
│
├── integrations/
│   └── github-action/            # reusable GitHub Action
│
├── infra/
│   ├── docker/                   # Dockerfiles per service
│   ├── k8s/                      # manifests / Helm chart
│   ├── terraform/                # cloud provisioning (optional)
│   └── observability/            # dashboards, alert rules
│
├── knowledge_base/
│   ├── seeds/                    # curated best-practice & mapping seed data
│   └── rules/                    # custom SAST rules, policy templates
│
├── scripts/                      # ops scripts: seed KB, sync feeds, bootstrap
└── .github/
    └── workflows/                # CI: lint, type, test, build, self-scan
```

## `services/api/` — Control plane (FastAPI)

Layered: **routers → services → repositories**. Pydantic at the edges; models never leak upward.

```
services/api/
├── src/guardian_api/
│   ├── main.py                   # app factory, middleware, router mount, lifespan
│   ├── config.py                 # typed settings (Pydantic Settings)
│   ├── deps.py                   # DI: db session, current user, tenant
│   ├── api/v1/
│   │   ├── routes/
│   │   │   ├── auth.py
│   │   │   ├── organizations.py
│   │   │   ├── projects.py
│   │   │   ├── scans.py          # create/list/get, SSE progress
│   │   │   ├── findings.py       # list/triage/status
│   │   │   ├── reports.py        # generate/fetch/export
│   │   │   ├── policies.py       # gate rules
│   │   │   ├── knowledge_base.py
│   │   │   └── webhooks.py
│   │   └── schemas/              # request/response DTOs (Pydantic)
│   ├── services/                 # use-cases: scan_service, finding_service, report_service...
│   ├── security/                 # authn (oauth/jwt), rbac, api keys, rate limit
│   ├── policy/                   # gate evaluation engine
│   └── events/                   # job publisher, SSE hub
├── tests/                        # unit + integration (testcontainers)
├── Dockerfile
└── pyproject.toml
```

## `workers/scanner/` — Scan workers & engines

The plug-in point. Each engine is a self-contained adapter behind the shared `ScanEngine` interface.

```
workers/scanner/
├── src/guardian_scanner/
│   ├── celery_app.py             # Celery config (broker, queues, routing)
│   ├── orchestrator.py           # fan-out, per-engine dispatch, aggregation
│   ├── tasks.py                  # celery tasks (run_engine, normalize, finalize)
│   ├── sandbox/                  # egress allowlist, resource limits, isolation
│   ├── engines/
│   │   ├── base.py               # ScanEngine protocol, ScanContext, RawFinding
│   │   ├── sast/                 # Semgrep/Bandit/ESLint-security adapters
│   │   ├── secrets/              # Gitleaks/TruffleHog adapters
│   │   ├── sca/                  # OSV-Scanner/Trivy/Syft adapters
│   │   ├── dast/                 # headers/TLS/session probes
│   │   ├── api/                  # OpenAPI analyzer + safe probes
│   │   ├── cspm/                 # AWS/Azure/GCP read-only checks
│   │   └── container/            # Trivy/Hadolint/kube-linter adapters
│   ├── normalize/                # standards mapping, dedup/correlate, fingerprinting
│   └── scoring/                  # CVSS+EPSS+KEV+exposure → severity
├── tests/
├── Dockerfile                    # bundles pinned scanner binaries
└── pyproject.toml
```

## `services/ai_analyst/` — AI analyst

```
services/ai_analyst/
├── src/guardian_ai/
│   ├── worker.py                 # consumes analysis jobs
│   ├── rag/                      # retrieval over KB (pgvector), context assembly
│   ├── prompts/                  # versioned, injection-hardened templates
│   ├── providers/                # LLMProvider interface + Anthropic (Claude) impl
│   ├── analysts/                 # explain / remediate / prioritize
│   └── reporting/                # section builders, HTML + PDF renderers
├── tests/                        # incl. golden-output & guardrail tests
├── Dockerfile
└── pyproject.toml
```

## `packages/` — Shared libraries (the single source of truth)

```
packages/
├── core/src/guardian_core/
│   ├── findings.py               # canonical Finding model (schema shared everywhere)
│   ├── severity.py               # severity enum + scoring contracts
│   ├── standards/                # CWE/CVE/OWASP/CIS/ASVS mapping tables
│   └── domain.py                 # Project, Scan, Target value objects
├── db/src/guardian_db/
│   ├── models/                   # SQLAlchemy ORM models
│   ├── repositories/             # data-access, tenant-scoped
│   ├── migrations/               # Alembic
│   └── session.py
├── clients/src/guardian_clients/
│   ├── github.py · cloud/ · feeds/ (nvd, osv, ghsa, epss, kev) · llm/
├── common/src/guardian_common/
│   ├── config.py · logging.py · telemetry.py · errors.py · crypto.py (secret handling)
```

## `apps/web/` — Dashboard (React)

```
apps/web/
├── src/
│   ├── pages/                    # dashboard, projects, scan detail, findings, reports, policy
│   ├── features/                 # feature-scoped components + hooks + api
│   ├── components/               # shared UI (charts, severity badges, tables)
│   ├── lib/                      # api client, auth, sse
│   └── main.tsx
├── tests/
├── Dockerfile
└── package.json
```

## `cli/guardian/` & `integrations/github-action/`

```
cli/guardian/                     # `guardian scan --project X --fail-on critical`
integrations/github-action/       # action.yml wrapping the CLI for GitHub Actions
```

## Why this shape

- **`packages/core` is law.** The canonical finding schema, severity model, and standards mappings
  live in one place and are imported by API, workers, and AI — engines can never drift.
- **Services are independently deployable** but share code via workspace packages (no copy-paste,
  no version skew).
- **Engines are isolated folders** implementing one interface — adding a scanner is additive and
  never touches the core.
- **Infra, docs, and KB seeds are versioned with the code** they support, so a change and its
  deployment/config move together.
