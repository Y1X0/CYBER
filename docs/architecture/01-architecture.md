# 01 — System Architecture

> The complete architecture for the Security Guardian Platform: context, containers, components,
> data flows, the six scanner engines, the AI analyst pipeline, and deployment topology.

---

## 1. Context (C4 Level 1)

Who and what the platform interacts with.

```mermaid
graph TB
    dev["👤 Developer / Security Engineer"]
    lead["👤 Security Lead / CISO"]
    ci["⚙️ CI/CD Pipeline<br/>(GitHub Actions, GitLab CI)"]

    subgraph SG["Security Guardian Platform"]
        core["Control Plane + Scanners<br/>+ AI Analyst + Dashboard"]
    end

    repos["📦 Source Repositories<br/>(GitHub / GitLab)"]
    targets["🌐 Authorized Targets<br/>(web apps, APIs)"]
    cloud["☁️ Cloud Accounts<br/>(AWS / Azure / GCP — read-only)"]
    feeds["🛰️ Vuln Data Feeds<br/>(NVD, OSV, GHSA, EPSS, KEV)"]
    llm["🤖 Anthropic API<br/>(Claude)"]

    dev -->|configures projects,<br/>reviews findings| core
    lead -->|reads reports,<br/>sets policy| core
    ci -->|triggers scans,<br/>reads gate result| core

    core -->|clones / reads code| repos
    core -->|safe, rate-limited probing| targets
    core -->|read-only config audit| cloud
    core -->|pulls advisories| feeds
    core -->|grounded prompts| llm
```

**Trust posture:** the platform holds read-only or scoped credentials for the assets it audits.
It never receives write/deploy permissions on target systems. All target interaction is
non-destructive. See [06 — Security Model](06-security-model.md).

---

## 2. Container view (C4 Level 2)

The deployable pieces and how they talk.

```mermaid
graph TB
    subgraph edge["Edge"]
        gw["API Gateway / Reverse Proxy<br/>(Nginx / Traefik · TLS)"]
    end

    subgraph app["Application tier"]
        web["Web Dashboard<br/>(React SPA)"]
        api["API / Control Plane<br/>(FastAPI)"]
        ghapp["GitHub App / Webhook<br/>Service (FastAPI)"]
    end

    subgraph async["Async processing"]
        broker[("Redis<br/>broker + cache")]
        orch["Scan Orchestrator<br/>(Celery beat + dispatch)"]
        workers["Scan Worker Pool<br/>(Celery · sandboxed)"]
        ai["AI Analyst Service<br/>(worker + RAG)"]
    end

    subgraph data["Data tier"]
        pg[("PostgreSQL<br/>system of record")]
        obj[("Object Storage<br/>S3 / MinIO — raw artifacts")]
        vec[("Vector index<br/>pgvector — KB embeddings")]
    end

    subgraph ext["External"]
        feeds["Vuln feeds"]
        llm["Anthropic API"]
    end

    gw --> web
    gw --> api
    gw --> ghapp

    web -->|REST / SSE| api
    ghapp -->|enqueue scan| api
    api -->|read/write| pg
    api -->|enqueue jobs| broker
    api -->|presign| obj

    orch --> broker
    broker --> workers
    workers -->|write findings| pg
    workers -->|store raw output| obj
    workers -->|enqueue analysis| broker
    broker --> ai
    ai -->|read findings + KB| pg
    ai -->|similarity search| vec
    ai -->|grounded prompt| llm
    ai -->|write narrative + report| pg

    orch -->|scheduled sync| feeds
    feeds -->|advisories| pg
```

### Container responsibilities

| Container | Responsibility |
|---|---|
| **API / Control Plane** (FastAPI) | AuthN/Z, projects, scan lifecycle, findings API, policy, reports, SSE progress. The only writer of business rules. |
| **Web Dashboard** (React) | Project management, scan history, finding triage, report viewing, policy config. |
| **GitHub App / Webhook Service** | Receives push/PR events, verifies signatures, enqueues scans, writes PR checks & comments. |
| **Scan Orchestrator** (Celery beat) | Scheduled scans, feed syncs, retries, fan-out of multi-engine scans, timeout enforcement. |
| **Scan Worker Pool** (Celery) | Runs pluggable engine adapters inside sandboxes; emits canonical findings. Horizontally scalable. |
| **AI Analyst Service** | RAG over the knowledge base + findings; explanation, scoring assist, remediation, report drafting. |
| **PostgreSQL** | System of record: tenants, projects, scans, findings, KB, reports, audit. |
| **Redis** | Celery broker + result backend + cache + rate-limit counters. |
| **Object Storage** | Raw scanner output, SBOMs, generated report PDFs — large blobs kept out of the DB. |
| **Vector index** (pgvector) | Embeddings of KB entries and finding descriptions for retrieval-grounded AI. |

> **Queue note:** Redis + Celery is the Phase-1 default for velocity. The queue is abstracted behind
> a `JobQueue` interface so a swap to RabbitMQ or SQS (for stronger delivery guarantees at scale) is
> a config change, not a rewrite. See [04 — Technology Decisions](04-technology-decisions.md).

---

## 3. Component view — Control Plane

```mermaid
graph LR
    subgraph api["FastAPI Control Plane"]
        r["Routers<br/>(v1 REST)"]
        authm["Auth & RBAC<br/>middleware"]
        svc["Service layer<br/>(use-cases)"]
        repo["Repository layer<br/>(SQLAlchemy)"]
        dto["Schemas<br/>(Pydantic)"]
        pub["Job publisher"]
        pol["Policy engine"]
    end
    r --> authm --> svc
    svc --> repo
    svc --> pol
    svc --> pub
    r <--> dto
```

Clean layering: **routers** (transport) → **services** (use-cases, transactions) →
**repositories** (persistence). Pydantic schemas guard the edges; SQLAlchemy models never leak past
the repository layer. The **policy engine** evaluates gate rules; the **job publisher** is the only
component that enqueues work.

---

## 4. The scanning pipeline

The canonical lifecycle of a scan, from trigger to report.

```mermaid
sequenceDiagram
    participant T as Trigger<br/>(UI / CI / webhook / schedule)
    participant API as Control Plane
    participant Q as Queue (Redis)
    participant O as Orchestrator
    participant W as Worker (engine adapter)
    participant N as Normalizer + Scorer
    participant DB as PostgreSQL
    participant AI as AI Analyst
    participant G as Gate / Notifier

    T->>API: POST /scans (project, scan types)
    API->>DB: create scan (queued) + authz check
    API->>Q: enqueue scan job(s)
    API-->>T: 202 Accepted (scan_id)
    O->>Q: consume, fan out per engine
    Q->>W: dispatch engine job (sandboxed)
    W->>W: run engine (SAST/SCA/DAST/API/CSPM/container)
    W->>DB: write raw findings (canonical schema)
    W->>N: hand off findings
    N->>N: dedup · map CWE/CVE/OWASP · risk score
    N->>DB: persist normalized findings + severity
    N->>Q: enqueue analysis job
    Q->>AI: dispatch analysis
    AI->>DB: read findings + KB context (RAG)
    AI->>DB: write explanations · remediation · report
    AI->>G: publish result
    G->>T: PR check / gate decision / notification
```

**Idempotency & resumability:** each engine job is idempotent on `(scan_id, engine, target_hash)`.
Partial failures degrade gracefully — one failed engine does not fail the whole scan; the scan
record aggregates per-engine status.

---

## 5. Scanner engines

All engines implement one interface and emit the **canonical finding schema** (see
[03 — Database Schema §Findings](03-database-schema.md)). The core never knows engine internals.

```python
# Conceptual adapter contract (illustrative, not final code)
class ScanEngine(Protocol):
    key: str  # "sast", "sca", "dast", "api", "cspm", "container"

    def supports(self, target: Target) -> bool: ...
    def run(self, ctx: ScanContext) -> Iterable[RawFinding]: ...
    def health(self) -> EngineHealth: ...
```

| Engine | Class | Primary tools (wrapped) | Emits |
|---|---|---|---|
| **SAST** | Source code | Semgrep (rulesets), Bandit (Py), ESLint-security, plus custom rules | Insecure patterns, authN/Z flaws, injection, insecure config |
| **Secrets** | Source code | Gitleaks / TruffleHog + entropy heuristics | Hardcoded secrets, exposed API keys, tokens in history |
| **SCA** | Dependencies | OSV-Scanner, Trivy (fs), Syft (SBOM) | Vulnerable/outdated deps, supply-chain & license risk |
| **DAST-lite** | Web apps | Header/TLS analyzer, testssl-style checks, auth/session probes | Missing headers, weak TLS, cookie/session issues, common OWASP web risks |
| **API** | APIs | OpenAPI/Swagger analyzer + active safe probes | Missing authN, weak input validation, no rate limiting, verbose errors, misconfig |
| **CSPM** | Cloud | Prowler / ScoutSuite-style read-only checks (AWS/Azure/GCP) | IAM over-permission, public storage, open security groups, unencrypted resources |
| **Container** | Containers/K8s | Trivy (image), Hadolint (Dockerfile), kube-linter/Checkov (manifests) | Image CVEs, Dockerfile smells, risky K8s config |

**Engine principles**

- **Wrap, don't reinvent.** Each engine shells out to a hardened, pinned, well-tested OSS scanner in
  a sandbox, then maps output to the canonical schema. Proprietary value is in normalization,
  correlation, scoring, AI analysis, and workflow — not re-implementing scanners.
- **Safe & authorized.** Active engines (DAST, API) require a per-target authorization record and run
  read-only, rate-limited, non-destructive checks only. No exploitation, no fuzzing-to-crash, no DoS.
- **Sandboxed.** Every run is network-egress-restricted (target allowlist only), CPU/mem/time-bounded,
  and filesystem-isolated. Cloud audits use read-only, least-privilege roles.

### Normalization, dedup & risk scoring

```mermaid
graph LR
    raw["Raw findings<br/>(N engines)"] --> map["Standards mapping<br/>CWE · CVE · OWASP · CIS"]
    map --> dedup["Dedup & correlate<br/>(fingerprint + location)"]
    dedup --> score["Risk scoring"]
    score --> persist["Persist findings"]

    subgraph score_detail["Risk score inputs"]
        cvss["CVSS base"]
        epss["EPSS (exploit prob.)"]
        kev["CISA KEV flag"]
        reach["Reachability / exposure"]
        ctx["Asset criticality<br/>(project context)"]
    end
    score --- score_detail
```

Final **severity (Critical/High/Medium/Low)** is a deterministic function of CVSS + EPSS + KEV +
exposure + asset criticality. The score is transparent and reproducible; the AI **explains** it but
does not silently override it (any AI-suggested adjustment is recorded as a separate, auditable
signal).

---

## 6. AI Security Analyst

A **retrieval-grounded** layer that turns normalized findings into human-grade output. It augments
deterministic results; it never invents severities or fabricates evidence.

```mermaid
graph TB
    trigger["Analysis job<br/>(per scan)"] --> gather["Gather context"]
    gather --> f["Normalized findings<br/>+ evidence"]
    gather --> kb["KB retrieval<br/>(pgvector similarity)"]
    f --> prompt["Grounded prompt<br/>assembly"]
    kb --> prompt
    prompt --> llm["Claude<br/>(Anthropic API)"]
    llm --> out["Structured output<br/>(validated JSON)"]
    out --> explain["Plain-language<br/>explanation"]
    out --> remediate["Remediation steps"]
    out --> report["Report sections"]
    explain --> store["Persist + link to finding"]
    remediate --> store
    report --> store
```

**Grounding & guardrails**

- Every AI claim is tied to a specific finding ID and KB reference — no free-floating assertions.
- Output is **structured** (validated against a schema) so it slots cleanly into reports and the UI.
- Severity and CVSS come from the deterministic scorer; the AI provides *narrative, context,
  prioritization rationale, and fixes*, and flags uncertainty explicitly.
- Prompt-injection defense: repo/scan content is treated as untrusted data, never as instructions
  (delimited, role-separated). See [06 — Security Model](06-security-model.md).
- The model is configurable and the platform stays LLM-agnostic behind an `LLMProvider` interface;
  the default is Claude via the Anthropic API.

### Report structure (generated per scan)

1. **Executive summary** — posture, top risks, trend vs. previous scan (business language).
2. **Vulnerability list** — each with **Severity**, **Evidence**, **Impact**, **Recommended fix**,
   **References** (CWE/CVE/OWASP/CIS/ASVS).
3. **Standards mapping appendix** — OWASP Top 10 / ASVS / CIS coverage.
4. **Remediation plan** — prioritized, effort-tagged.

Reports render as HTML in-app and export to **PDF** (stored in object storage).

---

## 7. DevSecOps integration

```mermaid
graph LR
    push["git push / PR"] --> gha["GitHub Actions<br/>step / GitHub App"]
    gha --> api["Security Guardian API"]
    api --> scan["Scan runs"]
    scan --> policy["Policy engine<br/>evaluates gate"]
    policy -->|pass| ok["✅ Check passes"]
    policy -->|fail| block["❌ Block merge/deploy<br/>+ PR annotations"]
    scan --> comment["PR comment:<br/>findings summary + links"]
```

- **GitHub App** posts a **Check Run** and inline PR annotations; policy decides pass/fail.
- **Reusable GitHub Action** + **CLI** (`guardian scan`) for any CI/CD system; exit code drives gates.
- **Policy engine** is declarative (e.g. *"fail on any Critical, or High with EPSS > 0.5, or a KEV
  match"*), versioned per project, with documented break-glass overrides recorded in the audit log.

---

## 8. Deployment topology

```mermaid
graph TB
    subgraph dev_env["Local / Dev"]
        dc["docker compose up<br/>(all services + Postgres + Redis + MinIO)"]
    end

    subgraph prod["Production (cloud-ready)"]
        lb["Load Balancer / TLS"]
        subgraph k8s["Container platform (K8s / ECS)"]
            apip["API (N replicas)"]
            webp["Web (static / CDN)"]
            ghp["GitHub App svc"]
            wpool["Worker pool<br/>(autoscaled, sandboxed)"]
            aip["AI Analyst svc"]
        end
        rds[("Managed PostgreSQL")]
        redis[("Managed Redis")]
        s3[("Object storage")]
        secrets["Secrets manager<br/>(Vault / KMS / SM)"]
        obs["Observability<br/>(OTel · Prometheus · Loki · Grafana)"]
    end

    lb --> apip & webp & ghp
    apip --> rds & redis & s3
    wpool --> rds & s3
    aip --> rds
    apip -. reads secrets .-> secrets
    wpool -. reads secrets .-> secrets
    k8s -. telemetry .-> obs
```

- **Single command for dev:** `docker compose up` brings up the whole stack.
- **Cloud-ready:** stateless services scale horizontally; state lives in managed Postgres/Redis/object
  storage; secrets in a dedicated manager; full observability (traces, metrics, structured logs).
- **12-factor config** via environment; no secrets in images or repos.

---

## 9. Cross-cutting concerns

| Concern | Approach |
|---|---|
| **AuthN** | OAuth2 / OIDC + JWT sessions; GitHub OAuth for repo access; API keys for CI. |
| **AuthZ** | RBAC scoped to organization → project; every query is tenant-filtered. |
| **Observability** | OpenTelemetry traces end-to-end; Prometheus metrics; structured JSON logs; scan-level audit trail. |
| **Reliability** | Idempotent jobs, retries with backoff, per-engine timeouts, graceful partial-failure. |
| **Data lifecycle** | Configurable retention for raw artifacts; findings and reports kept per policy; PII-minimizing. |
| **Extensibility** | New engine = new adapter implementing `ScanEngine`; new LLM = new `LLMProvider`; new feed = new sync job. |
| **Configuration** | Central typed settings (Pydantic Settings); environment-driven; validated at startup. |

See the remaining docs for the physical layout ([02](02-folder-structure.md)), data model
([03](03-database-schema.md)), stack rationale ([04](04-technology-decisions.md)), delivery plan
([05](05-development-roadmap.md)), and self-security ([06](06-security-model.md)).
