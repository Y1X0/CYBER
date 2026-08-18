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
* **Fixed** in `normalize.merge_sighting` + `tasks.run_scan`; see §4b.

### 4.2 `queue-health` reports "stalled" on the first scan of a fresh deployment

At the moment the pilot's first scan was submitted — with a healthy worker running and about to
pick it up 200 ms later — `GET /scans/queue-health` returned:

```
state='stalled'  queued=1  running=0  scanner='degraded'
```

`_scanner_liveness` (`services/api/src/guardian_api/observability.py:298`) reads
`max(finished_at)` across all scans; on a deployment where **no scan has ever finished** that is
`NULL`, and any waiting scan is therefore reported as degraded. The console renders this as
*"Guardian has accepted your scan but nothing is executing it."*

So the first thing a new design partner is told about their first scan is that nothing is running
it — while it is being run. Once one scan had completed, the endpoint reported correctly (`idle` /
`unknown`) for the rest of the run.

* **Direction:** cries wolf. It errs toward alarm, never toward reassurance, so it cannot produce a
  false-clean. It is a first-impression defect, not a safety one.
* **Fixed** in `_scanner_liveness`: with nothing ever finished, the age of the oldest waiting scan
  is what separates a new deployment from a dead worker. See §4b.

---

## 4b. Second run, after both defects were fixed

Both defects in §4 were fixed and the run was repeated from an empty database with the same target
and the same stack. **27 PASS · 0 FAIL · 1 UNVERIFIED** (the webhook round trip, unchanged).

| Stage | Before | After |
|---|---|---|
| findings from one scan | **16 rows** for 14 distinct issues | **14 rows** — the within-scan duplicate is gone |
| after scan + retest | **20 rows** for 14 distinct issues | **14 rows for 14 distinct issues** |
| queue-health at submit | `state='stalled'`, scanner `degraded` | `state='working'`, scanner `unknown` — *"0 scan(s) running and 1 waiting. Scans are processed in order."* |

**The safety property survived the deduplication**, which was the risk. The retest's own reconcile
output, from the worker log:

```
verification: {checked: 14, resolved: 0, still_present: 3, not_checked: 11, inconclusive: 0}
```

A single-engine retest re-reported 3 findings and marked the other 11 **`not_checked`** — not
resolved. Three new tests drive the real `run_scan` path to hold this in place: a rescan folds
instead of duplicating, a scan that stops reporting an issue still resolves it, and an issue that
comes back reopens the original row rather than filing a new one.

Full suite after the fixes: **2164 passed, 0 failed, 0 skipped** under `guardian_app`.

---

## 4c. A third defect, found by testing the operator's own warning

The free Render Key Value instance runs with `persistenceMode: off`. The question that raises is
what happens to work the API has already accepted when the broker loses its data — so it was
measured rather than assumed.

**Method.** An API with no worker running. `POST /scans` → **202 Accepted**, and the task is visible
in Redis (`LLEN default` → 1). `FLUSHDB`, which is what a restart of a non-persistent Redis does to
the queue. Then start a healthy worker and wait.

**Result.** After 90 seconds with a worker connected and idle:

```
scan status: queued          (unchanged)
worker log:  celery@vm ready.    — no guardian.run_scan execution
```

The scan stays `queued` **forever**. Nothing re-dispatches it: `sweep_schedules` creates new scans
from schedules and never re-sends an existing one, and no other sweep looks for scans stranded in
`queued`. `grep` for a recovery path finds none.

**What the customer is told**, from the same run:

```
queue-health: state='working'  queued=1  running=0
detail: "0 scan(s) running and 1 waiting. Scans are processed in order."
```

That is reassuring and false — the scan will never be processed. After 45 minutes it becomes
`degraded` ("the worker has either never run or cannot reach the database"), which alarms correctly
but describes the wrong cause and still recovers nothing.

* **Direction:** the API's `202 Accepted` is a promise the platform can break silently and
  permanently. It does not produce a false-clean — no result is reported — but a customer waits on
  a scan that is gone.
* **Scope:** only bites when the broker loses data. A Redis with persistence on, or any managed
  Redis, does not hit it. It is one of the reasons the free instance is not suitable for a customer.
* **Fixed** in `guardian_scanner.recovery` — see §4d.

---

## 4d. Recovering the lost scan

The whole difficulty is telling **lost** from **waiting**: re-sending a message that is merely
queued behind other work runs one scan on two workers. Two facts make it decidable, and neither is
a guess.

**`run_scan` claims its scan atomically.** Its first database write is now a conditional
`UPDATE … WHERE status = 'queued'` that exactly one caller can win. So a scan still sitting at
`queued` has definitely not begun executing — whatever the broker holds — and a duplicate delivery
returns `claimed: False` instead of reaching `ScanEngineRun` and colliding on
`uq_engine_run_scan_engine`.

**The broker can be read.** Celery's Redis transport keeps pending messages in a list per queue and
delivered-but-unacknowledged ones in the `unacked` hash — verified against the running transport,
not assumed. A scan whose message is in neither is not going to be delivered by anybody.

So `guardian.sweep_stranded_scans` (beat, every 5 minutes) re-sends a scan only when it is `queued`,
older than a 40-minute grace period, and absent from the broker. Everything else is left alone, and
if the broker cannot be read — unreachable, too long to enumerate, a message that will not parse —
it recovers **nothing**. "I could not look" must never be read as "nothing is there", which is the
rule the scanners already follow about empty results.

**Proven live**, repeating the experiment that found the defect:

```
1. scan accepted: HTTP 202  status='queued'
2. broker holds: 1 message
3. FLUSHDB — broker holds: 0 messages
4. worker started and healthy → scan status: queued        ← the defect
5. guardian.sweep_stranded_scans dispatched over the real broker
   scan_requeued  waited_seconds=3629
   recovery_requeued_scans  candidates=1 requeued=1 waiting=0 skipped_unknown_broker=0
6. run_scan received and succeeded → status='completed'
7. final: scan status=completed  findings=2
```

The audit row the sweep leaves:

```json
{"reason": "the broker no longer holds this scan's message",
 "status": "queued", "waited_seconds": 3629}
```

**And queue-health stopped vouching for it.** Past the grace period the state is `delayed`, not
`working`, and the wording no longer promises anything about the future:

> *"A scan has been waiting 50 minutes, which is longer than one should. Guardian re-checks for work
> that never reached a scanner and re-submits it automatically. Nothing has been lost and no result
> has been produced — if this does not clear, the scanner needs attention rather than your target."*

Ten tests hold this in place, and most of them are about recovery doing **nothing**: a scan still in
the broker, a recently queued scan, a running scan, and an unreadable broker are all left alone; a
duplicate delivery neither re-runs the scan nor duplicates its findings.

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
python tools/production_golden_run.py --api http://127.0.0.1:8099 --repo <url> --inline
```

---

## 8. The production golden run — the last gate

Everything above proves the code. It does not prove a *deployment*, because the worker ran on a
development host. `tools/production_golden_run.py` is the same journey pointed at any base URL, so
the proof can be repeated against the deployed API the moment a worker consumes its queue. It goes
through the public API and touches no database — which is the point: if it passes against your
deployment, a customer can do the same thing.

**Step 1 — a worker.** Any host that runs one long-lived process. No privileges, no code change:

```bash
docker compose -f docker-compose.prod.yml up -d worker-default
# or, from a checkout:
GUARDIAN_DATABASE_URL=... GUARDIAN_REDIS_URL=... \
  celery -A guardian_scanner.celery_app.celery_app worker --queues default --concurrency 1
```

**Step 2 — a target you are authorized to scan.** `--make-target` writes the same deliberately
vulnerable estate the controlled run used; commit and push it to a repository you own:

```bash
python tools/production_golden_run.py --make-target ./vulnerable-sample
```

**Step 3 — the run.**

```bash
python tools/production_golden_run.py \
    --api https://your-guardian-api \
    --repo https://github.com/you/vulnerable-sample.git \
    --webhook https://your-receiver/guardian     # optional; closes B-6 if it 2xxs
```

It exits non-zero if any stage fails, and prints UNVERIFIED for anything it could not establish. If
the deployed worker never picks the scan up, it says so and names A1 rather than timing out
silently.

Two flags exist for the blockers this environment could not clear. `--domain-is-ours` expects a
*passing* ownership check, so publishing the TXT record and passing it closes **B-5**; `--webhook`
with a reachable receiver closes **B-6** when a delivery reaches `delivered`.

`--inline` supplies the vulnerable content directly instead of cloning, for a run before the
repository is published. Fewer engines have anything to read — IaC, Kubernetes and container
manifests need a workspace — and the ones that do not read anything say so rather than reporting
clean. Proven end to end against a live stack in this configuration: **21 PASS, 0 FAIL, 1
UNVERIFIED** (the webhook, with no receiver given).
