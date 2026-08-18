# Guardian — Controlled End-to-End Pilot Run

**One run, executed 2026-08-18 at commit `6c6dd64`.** Not a test suite. Every request crossed real
HTTP to a real uvicorn process; every scan crossed Redis into a **separate `celery worker` OS
process**; every row was written to a PostgreSQL database built from an empty schema, through the
RLS-enforced non-superuser `guardian_app` role.

Nothing in this document comes from `task_always_eager`, a `TestClient`, or an in-process call to
the orchestrator. Where a stage could not be verified it says UNVERIFIED and why.

---

## 1. What was standing up

| Component | How it ran | Evidence |
|---|---|---|
| Database | `guardian_pilot`, created empty, `alembic upgrade head` → 53 tables, **41 RLS policies** | `select count(*) from pg_policies` → 41 |
| API | `uvicorn guardian_api.main:app` on 127.0.0.1:8099, request path bound to `guardian_app` | `rolsuper=false rolbypassrls=false`; 2 live `guardian_app` backends during the run |
| Broker | Redis db 3, flushed before the run | `Connected to redis://localhost:6379/3` |
| Worker (default plane) | `celery -A guardian_scanner.celery_app.celery_app worker --queues default --concurrency 1` | `celery@vm ready.` |
| Worker (recon plane) | same binary, `--queues recon`, `GUARDIAN_RECON_PLANE=true`, **launched with the DB, JWT and encryption variables removed from its environment** | `/proc/<pid>/environ` contains only `GUARDIAN_RECON_PLANE=true` — no DB, no JWT, no KMS key |
| Engine health at start | 9 engines loaded, 8 fully healthy, `sast` degraded (`semgrep` absent from this host) | `health_report()` |

**Target:** a deliberately vulnerable repository created for this run and owned by us — hardcoded
AWS credentials, `subprocess(shell=True)` and SQL string concatenation, four outdated Python
dependencies, a public-read S3 bucket and an all-ports security group in Terraform, a privileged
`hostNetwork` Kubernetes deployment, and a root Dockerfile on `ubuntu:18.04`. Scanning material we
created and own is authorized by construction, and the authorization was recorded through the API
as `written_consent` (artifact plane only).

---

## 2. Stage-by-stage result

25 PASS · 0 FAIL · 1 UNVERIFIED.

| # | Stage | Result | Evidence |
|---|---|---|---|
| 1 | signup | **PASS** | `POST /auth/signup` → 201, tenant created over the wire |
| 2 | organization | **PASS** | `/auth/me` resolves to that tenant; 1 business unit |
| 3a | ownership challenge | **PASS** | `_guardian-challenge.<domain>` TXT + token returned |
| 3b | ownership refusal | **PASS** | real DNS lookup, record not published → status ≠ verified |
| 3c | network authorization refused | **PASS** | `active_recon` for an unproved domain → **409**, naming the domain |
| 4 | asset | **PASS** | `POST /assets` → 201 |
| 4b | authorization recorded | **PASS** | `written_consent`, `permits_network=false`, responsible identity on the row |
| 5 | scan creation | **PASS** | `POST /scans` → **202**, 6 engines requested |
| 6 | queued | **PASS** | API reports `queued` at creation |
| 7 | **worker receives task** | **PASS** | `Task guardian.run_scan[2a90e644…] received` in the worker process log |
| 8 | running → terminal | **PASS** | `started_at=20:16:58.957`, `finished_at=20:16:59.066`, final `completed` |
| 9 | discovery | **PASS** | `run_discovery` on `default` dispatched `recon_collect` to the **DB-less recon worker**, which returned evidence over the broker: `Task guardian.recon_collect[a1c773c6…] succeeded` |
| 10 | scanner execution | **PASS** | 6 engine runs: `checked=[container, iac, k8s, sca, secrets]`, `inconclusive=[sast]` |
| 11 | finding | **PASS** | **16 findings** — 8 critical, 5 high, 3 medium |
| 12 | evidence | **PASS** | 16/16 carry evidence |
| 13 | deterministic risk | **PASS** | 16/16 scored > 0; repeated read returned 94 both times; rationale itemised |
| 13b | evidence redaction | **PASS** | the target's live-shaped secret is **absent** from the API response (`AK********LE (len=20)`) |
| 14 | report | **PASS** | 9,434 bytes of HTML, secret absent from the export |
| 15 | remediation | **PASS** | 14 items opened from 16 findings (2 grouped by correlation), each with a due date |
| 16 | retest | **PASS** | retest scan completed; 2 verdicts recorded, `still_present` with rationale |
| 17 | webhook delivery | **PASS** | 4 deliveries queued by the worker, signed, attempted, retry scheduled |
| 17b | webhook **2xx round trip** | **UNVERIFIED** | the receiver is `.invalid`, and the egress guard refuses loopback and private addresses by design. No reachable receiver exists here and none was manufactured. **(B-6)** |
| 18 | HMAC verification | **PASS** | signature over the exact recorded bytes verifies; a tampered body and a wrong key both fail |
| 19 | scan completed | **PASS** | terminal `completed`, stats match the findings |
| 20 | **no false-clean state** | **PASS** | see §3 |
| 20b | tenant isolation, live | **PASS** | a second organization sees 0 findings; `GET` our scan → **404**, our finding → **404** |

Zero `ERROR` or `Traceback` lines in either worker log for the whole run.

---

## 3. The false-clean property, proven on a live system

This is the single property the platform exists to protect, and the run exercised it twice.

**Within the scan.** `sast` ran without `semgrep`. The worker recorded the run as `completed` with
`degraded=true, missing=["semgrep"]`, and the customer-facing state is **`inconclusive`**, not
`checked`:

> *"This engine ran without semgrep, so it was looking with reduced coverage. Treat an empty result
> from it as unknown, not clean."*

**Across scans.** The retest ran **one** engine (`secrets`) against an asset carrying 16 findings
from six engines. Reconciliation's own output:

```
verification: {checked: 16, resolved: 0, still_present: 4, not_checked: 12, inconclusive: 0}
```

Twelve findings whose engines did not run in that scan were marked **`not_checked` — not
`resolved`**. A single-engine retest did not silently close five other engines' findings. Final
database state: **20 finding rows, 0 resolved.**

---

## 4. Defect found by this run

### 4.1 Finding rows accumulate per scan, so the open-finding count over-reports

`reconcile_scan` inserts a new `Finding` row for every scan and marks the *previous* scan's rows
`still_present`, which leaves both rows `open`. After one scan and one single-engine retest of the
same asset:

```
finding_rows | distinct_issues | open_rows
          20 |              14 |        20
```

Two fingerprints carry four rows each. The customer's dashboard would report **20 open findings for
14 distinct issues** — a 43% over-count after a single retest, growing linearly with every rescan.

* **Direction:** over-reports. It does **not** hide anything, does not resolve anything falsely, and
  does not touch authorization, RLS, evidence or scoring.
* **Where:** `workers/scanner/src/guardian_scanner/verification.py:103` `reconcile_scan` — the
  reconciliation matches by fingerprint for *verdicts* but never collapses the rows, and
  `GET /findings` has no per-fingerprint deduplication.
* **Impact on a pilot:** a design partner scanning weekly sees their open count climb while nothing
  gets worse. For a security product that is a credibility problem, not a safety one.
* **Not fixed here.** This phase was proof, not code.

---

## 5. What this run does *not* establish

| | Why |
|---|---|
| Production deployment | The worker ran on a development host, not a deployed environment. See §6. |
| Network-plane scanning (DAST/API engines against a live host) | Requires an authorization backed by a **verified domain**. We control no domain whose DNS we can publish to, and the ownership gate was not bypassed. **(B-5)** |
| Webhook 2xx round trip | No reachable receiver; the egress guard correctly refuses loopback. **(B-6)** |
| External tool coverage | `semgrep`, `trivy`, `gitleaks`, `osv-scanner`, `checkov` are absent from this host. The engines' builtin implementations produced every finding above; the packaged scanner image ships all five. |
| Transport TLS | `GUARDIAN_ENV=local`, so the `rediss://` and `sslmode=` invariants were not exercised. They are enforced by config validation outside local/dev and are unchanged. |

---

## 6. Worker infrastructure — requirement analysis and free-tier verdict

### 6.1 Requirements, by plane

The execution model splits into three roles. Only one of them needs kernel privileges, and the
queue the pilot ran (`default`) is not it.

| | **Artifact plane** (`-Q default`) | **Recon plane** (`-Q recon`) | **Tool plane** (`-Q tools`) |
|---|---|---|---|
| **1–2. What it runs** | `run_scan` and every artifact engine — secrets, SAST, SCA, IaC, K8s, container, CSPM — plus correlation, retest, remediation, service→CVE, webhooks, schedule sweep | `recon_collect` only: passive DNS/CT/ASN and the one active provider, limited to 80/443 | `run_tool` only — providers marked `external_binary` (nmap today) |
| **3. CAP_NET_ADMIN** | **No.** `uid_nft` is reached only via `execute_tool` when `provider.external_binary` is true, and that task is routed to `tools`. `GUARDIAN_TOOL_PLANE` is false here, so the uid_nft init hooks do not even load. | **No** | **Yes** — `external_binary` providers are *forced* onto the `uid_nft` backend, which fails closed without `nft` |
| **4. PostgreSQL** | **Required.** Owner DSN (`GUARDIAN_DATABASE_URL`); TLS enforced outside local/dev | **None.** Config validation *forbids* DB credentials here | **None** |
| **5. Redis** | Required — broker and result backend; `rediss://` with AUTH outside local/dev | Required | Required |
| **6. Secrets** | `JWT_SECRET`, `ENCRYPTION_KEY` (KMS master), `BROKER_SEAL_KEY`, `JOB_SIGNING_PRIVATE_KEY` | **Only** `BROKER_SEAL_KEY`. JWT and encryption keys are rejected at startup | `BROKER_SEAL_KEY` + `JOB_SIGNING_PUBLIC_KEY`; the **private** key is rejected in *all* environments |
| **7. Filesystem** | Writable temp for `git clone` / `local_path` workspaces; `git` on PATH; tool binaries on PATH | Ephemeral | Ephemeral |
| **8. CPU/RAM** | The pilot's six engines completed in **176 ms** on 1 CPU. Sizing is driven by the external tools, not the framework: semgrep and trivy want ~2 GB. `RLIMIT_AS` defaults to 2048 MB per sandboxed engine. | Minimal | Depends on the tool |
| **9. Outbound network** | HTTPS to clone repositories and sync feeds. **No inbound.** | DNS, CT logs, and ports 80/443 on gate-cleared targets only | Whatever the nft allowlist permits |
| **10. Isolation** | Long-lived process; `task_time_limit=1800`; `worker_max_tasks_per_child=50`; must not share a process with the request-serving API | Separate host/network from the DB; holds no DB credential | Kernel-level uid + nftables per run |

The artifact plane is **the entire code-security product** and needs no privileges: an unprivileged
container, `USER 10001`, is already built and published as `infra/docker/Dockerfile.scanner`, whose
`CMD` is exactly the command in question.

### 6.2 Can a free environment run it?

**No.** This is not an estimate — the platform refused it:

```
##[error]worker provisioning failed: Render API 402 on POST /services:
{"message":"Payment information is required to complete this request.
To add a card, visit https://dashboard.render.com/billing"}
```

`type=background_worker` is rejected with **402 before any resource is allocated**. Render offers no
free tier for background workers. Nothing was created and nothing was billed.

The operator's Render workspace, read today, confirms the shape of the gap:

| Resource | Plan | Note |
|---|---|---|
| `guardian-api` (web service) | **free** | live, `/health/ready` 200 |
| `guardian-web` (static site) | free | live |
| `guardian-redis` (Key Value) | **free** | `persistenceMode: off` — a broker that loses queued work on restart |
| **Guardian PostgreSQL** | **none** | the only Postgres in the workspace belongs to a different project and expires 2026-09-01 |
| Background worker | — | **cannot be created without payment** |

**The one workaround is refused, deliberately.** Running the consumer inside the existing free web
service would put unbounded scan work on the request-serving process, and Render's free web service
sleeps on idle — which silently stops the queue. It would also mean scanning from the API image,
which carries none of the five external tools, so every tool-backed engine would report degraded
while the customer believed they had a scan. Hiding a capacity limitation inside the API tier is
worse than an honest blocker.

**Infrastructure work stops here.** No further provisioning was attempted and no retries remain.

---

## 7. Reproducing this run

```bash
# 1. database, from empty
createdb guardian_pilot && GUARDIAN_DATABASE_URL=... alembic upgrade head

# 2. API on the RLS-enforced role
GUARDIAN_APP_DATABASE_URL=postgresql+psycopg://guardian_app:...@host/guardian_pilot \
  uvicorn guardian_api.main:app --port 8099

# 3. the worker under test
celery -A guardian_scanner.celery_app.celery_app worker --queues default --concurrency 1

# 4. the recon plane, with no database credentials at all
env -u GUARDIAN_DATABASE_URL -u GUARDIAN_APP_DATABASE_URL -u GUARDIAN_JWT_SECRET \
    -u GUARDIAN_ENCRYPTION_KEY GUARDIAN_RECON_PLANE=true \
  celery -A guardian_scanner.celery_app.celery_app worker --queues recon --concurrency 1

# 5. drive the journey
python pilot_run.py
```

The driver and its raw JSON evidence are in the session scratchpad (`pilot_run.py`,
`pilot_evidence.json`); the reproduction above is the whole of what it needs.
