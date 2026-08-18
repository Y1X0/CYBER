# Guardian — Production / Commercial Readiness Audit

Audited at commit `59b191f` · 36 packages · 63,622 Python LOC · 141 test files · 2051 Python +
15 web tests · CI green (run 32104995687).

Method: the golden path was **executed**, not read. Two throwaway probes drove the real FastAPI app
and the real orchestrator against the live PostgreSQL under the **RLS-enforced `guardian_app`
role**, and every claim below is either a probe result, a code location, or a CI run. "Tests pass"
was not accepted as evidence of production operation anywhere in this document.

---

## 1. Executive verdict

| Dimension | Score | Why |
|---|---|---|
| **Engineering completeness** | **85%** | The code exists, is tested, migrates from nothing, and enforces its own invariants. Deductions are entirely for capabilities that were built and never connected to the orchestrator — see §4 RED-1…RED-4. |
| **Product completeness** | **45%** | The API can drive most of the path. The console cannot: it calls 7 read-only endpoints out of 25 mutating operations. There is no signup, no tenant creation, no asset/scan/report/remediation/webhook UI, and no API at all for recording a non-machine-proved authorization. |
| **Commercial readiness** | **25%** | A paying customer today would receive nothing. No worker exists (A1), so every scan sits at `queued` forever; and three capabilities they would be sold on — service→CVE, correlation, webhooks — are unreachable code even once a worker exists. |
| **Operational readiness** | **40%** | Deployment docs, backup/restore scripts, probes, `/health/slo` and API metrics are real and thought-through. But nothing is deployed, the worker exports no metrics at all, and the one counter about scan execution is declared and never emitted. |
| **Security assurance** | **80%** | The strongest dimension by a wide margin, and the one the platform was actually built around. RLS verified under the non-bypassing role; one unified authorization gate; licence gate live-verified in CI; egress pinned and redirects refused; evidence redacted at every boundary; append-only audit; fail-closed kill switch; and a consistent, tested refusal to let silence read as "clean". Deductions: two divergent redaction implementations, and no security testing of a deployed surface because there isn't one. |

**One-sentence verdict:** the security engineering is genuinely good and the packages are individually
sound, but several were finished in isolation and never wired into the orchestrator — so the product
is closer to a well-built parts bin than a running system.

---

## 2. Golden-path matrix

Probe evidence: `PASS`/`FAIL` lines are actual output from driving the live API + orchestrator.

| # | Stage | Status | Evidence | Missing |
|---|---|---|---|---|
| 1 | Customer signup | **RED** | Probe: tenant + owner had to be inserted directly into the database | No signup route, no tenant-creation API. Only `guardian_api.seed` (a dev bootstrap) creates a tenant |
| 2 | Organization / customer | **GREEN** | `POST /api/v1/customers` → 201 | — |
| 3 | Ownership verification | **GREEN** | `POST /verifications` → 201 with `instructions.record_value = guardian-site-verification=…`; `POST /{id}/check` → 200, `status=pending` (no TXT published — correct) | Live DNS round trip unverified (no controlled domain) |
| 4 | Asset onboarding | **GREEN** | `POST /assets` → 201 for `web` and `repo` | No UI |
| 5 | Authorization / scope | **YELLOW** | Probe: `Authorization` row had to be inserted directly | No API creates an authorization. The only programmatic path is a passing ownership check, so a signed written-consent engagement cannot be represented at all |
| 6 | Discovery | **GREEN** | `POST /discovery/runs` → 202 | Execution needs a worker (A1) |
| 7 | Service / technology identification | **GREEN (collect)** / **RED (use)** | Providers exist and are tested | See RED-2: the identified service never becomes a finding |
| 8 | Vulnerability intelligence | **YELLOW** | Feed clients + `feed_state` watermarks tested; beat entry `sync-vulnerability-feeds` exists | Never run against live feeds (egress blocked); needs a worker |
| 9 | Scan engine execution | **GREEN (code)** / **RED (production)** | Probe: `run_scan` inline → `completed`, stats `{high:1, medium:1, total:2}` | `POST /scans` only *enqueues*. With no worker (A1) the scan never runs |
| 10 | Findings | **GREEN** | `GET /findings?scan_id=…` → 200, n=2 | — |
| 11 | Evidence | **GREEN** | Finding carried `evidence.match`, scrubbed at the API boundary | — |
| 12 | Deterministic risk | **GREEN** | `severity=high risk=79`, computed by `guardian_core.scoring`, AI never overrides | — |
| 13 | Attack-path analysis | **GREEN** | `GET /graph/attack-chains` → 200 `{chains: [], unchainable_findings: 0}` — honest empty | — |
| 14 | Findings workbench | **GREEN** | `/findings/summary` → 200; `bulk-triage` → 200 `{updated:[…], refused:[]}` | — |
| 15 | Report | **GREEN** | `POST /reports` → 201; HTML export 2,472 B; PDF export 2,704 B | — |
| 16 | Compliance | **GREEN** | `GET /compliance` → 200, `overall_coverage=13` (three-state, honest) | — |
| 17 | Remediation | **YELLOW** | `POST /remediation` → 201 `{opened:2}` on open findings | Returns 201 `{opened:0}` with **no reason** when every finding was already triaged — a success response that created nothing |
| 18 | Retest | **GREEN** | Re-scan → `verification={checked:2, still_present:2}`, `remediation={verified:0, reopened:0}` | Per-finding `retest_finding` task is dead (RED-4) |
| 19 | Notification / webhook | **RED** | Endpoint registered (201); deliveries after a completed scan = **0** | RED-1: nothing in the platform emits an event |

---

## 3. Capability matrix

`API` = reachable HTTP route · `UI` = reachable in the console · `Orch` = invoked by the platform
without a human running a Celery command · `Live` = exercised against a real external dependency.

| WP | Capability | API | UI | Orch | Tests | Live | Status |
|---|---|---|---|---|---|---|---|
| A1/A1b | Worker fleet | n/a | n/a | — | n/a | ✗ | **BLOCKED_EXTERNAL** |
| A2 | Scanner runtime image | n/a | n/a | n/a | 36 | ✓ | GREEN |
| A3 | Scheduler | ✗ | ✗ | ✓ beat | 10 | ✗ | YELLOW |
| B1 | Passive discovery | ✓ | ✗ | ✓ | 39 | ✓ DNS / ✗ CT | YELLOW |
| B2 | Port/service discovery | ✓ | ✗ | ✓ | 41 | ✓ sockets | YELLOW |
| B3 | HTTP fingerprinting | ✓ | ✗ | ✓ | 40 | ✓ sockets | YELLOW |
| C1 | Feed ingestion | ✗ | ✗ | ✓ beat | 49 | ✗ | YELLOW |
| C2 | Version range matching | n/a | n/a | ✓ | 56 | n/a | GREEN |
| C3 | **Service version → CVE** | ✗ | ✗ | **✗** | 28 | ✗ | **RED** |
| C4 | Exploit intelligence | ✗ | ✗ | ✓ | 27 | ✗ | YELLOW |
| D1 | Nuclei templates | ✓ | ✗ | ✓ | 65 | ✓ | GREEN |
| D2 | DAST | ✓ | ✗ | ✓ | ~60 | ✓ fixture | YELLOW |
| D3–D10 | Secrets/SAST/SCA/IaC/K8s/CSPM/container/API engines | ✓ | ✗ | ✓ | high | partial | YELLOW |
| E1 | **Correlation** | ✗ | ✗ | **✗** | ✓ | ✗ | **RED** |
| E2 | Verification / retest | ✓ | ✗ | ✓ bulk / ✗ single | ✓ | ✗ | YELLOW |
| E3 | AI analyst | ✓ | ✓ chat | ✓ | ✓ | ✗ no key | YELLOW |
| E4 | Attack paths | ✓ | ✓ | ✓ | ✓ | n/a | GREEN |
| F1 | Ownership verification | ✓ | ✗ | ✓ | ✓ | ✗ no domain | YELLOW |
| F2 | Findings workbench | ✓ | partial | ✓ | ✓ | n/a | GREEN |
| F3/F4 | Console + compliance | ✓ | ✓ | n/a | 15 web | n/a | YELLOW |
| F5 | Remediation | ✓ | ✗ | ✓ | ✓ | n/a | YELLOW |
| G1 | API keys + SSO | ✓ | ✗ | ✓ | 64 | ✗ no IdP | YELLOW |
| G1b | RLS auth + clean-DB migration | n/a | n/a | ✓ | 23 | ✓ | GREEN |
| G2 | Scale hardening | ✓ | ✗ | ✓ | 49 | ✓ | GREEN |
| G3 | **Outbound webhooks** | ✓ | ✗ | **✗** | 82 | ✓ sockets | **RED** |
| G4 | Observability + SLOs | ✓ | ✗ | partial | 31 | ✗ | YELLOW |
| H1 | Authorization enforcement | n/a | n/a | ✓ | 35 | n/a | GREEN |
| H2 | Licence registry | n/a | n/a | ✓ CI | gate | ✓ | GREEN |
| H3 | Safe-scanning controls | ✗ | ✗ | ✓ | 25 | n/a | YELLOW |

---

## 4. Critical defects

### RED-1 — Outbound webhooks are never triggered (P0)

* **File:** `workers/scanner/src/guardian_scanner/webhooks.py:41` (`enqueue`) — zero callers outside
  `tests/`. `workers/scanner/src/guardian_scanner/tasks.py:398` records `scan.completed` to the
  *audit log* and stops there.
* **Impact:** WP-G3 is fully unreachable. A customer registers an endpoint, Guardian stores it, and
  it never receives anything. All seven event types in `guardian_core/webhooks.py:44` are dead
  letters. The failure is silent in the worst direction — an integration that never fires looks
  exactly like "you have no critical findings".
* **Reproduction:** register an endpoint, run a scan to completion, `GET
  /api/v1/webhook-endpoints/{id}/deliveries` → `[]`. Probe output: `deliveries=0`.
* **Fix:** call `enqueue(session, tenant_id=…, event_type="scan.completed", …)` in `tasks.py`
  after the scan commits, and at the three other points that already know the fact
  (`ownership.py` on verified, `verification.py` on reopened, `remediation` on overdue), then
  dispatch `deliver_webhook` for each returned id. ~20 lines.

### RED-2 — Service version → CVE never runs (P0)

* **File:** `workers/scanner/src/guardian_scanner/service_cve.py:113`
  (`guardian.match_service_versions`) — zero callers. Not in `beat_schedule`
  (`celery_app.py:117`), not called by `run_scan`, not chained from `enrich_graph`
  (`discovery/tasks.py:72`).
* **Impact:** WP-C3 is the *only* path by which a host with no repository gets a vulnerability
  finding. B2/B3 collect banners, versions and CPEs; C1 ingests CPE applicability; nothing joins
  them. Infrastructure scanning produces posture findings only. This is a headline capability that
  a buyer would assume works.
* **Reproduction:** discover a service, complete a scan, query findings — no `vuln-service`
  category ever appears.
* **Fix:** chain it after `enrich_graph` in `tasks.py`, or add a beat entry. ~5 lines.

### RED-3 — Findings are never correlated (P1)

* **File:** `workers/scanner/src/guardian_scanner/correlation.py:381`
  (`guardian.correlate_findings` → `correlate_tenant`) — zero callers.
* **Impact:** WP-E1's promise (one issue instead of three criticals; corroborated findings
  escalated) never happens in production. `Finding.correlation_id` stays null, so
  `remediation.open_items` degrades from "one item per underlying issue" to one per finding — the
  probe shows `grouped: 0` — and the workbench's `correlated` counter is permanently 0.
* **Reproduction:** run two engines that find the same secret; two separate criticals, no group.
* **Fix:** chain after reconciliation in `tasks.py`. ~5 lines.

### RED-4 — Single-finding retest task is dead (P2)

* **File:** `workers/scanner/src/guardian_scanner/verification.py:216` — zero callers, no API route.
* **Impact:** bulk reconciliation after a re-scan *is* wired and works (probe stage 18), so the
  capability is not lost; but "retest this one finding" cannot be invoked by a customer.

### RED-5 — No scan-execution telemetry (P1)

* **File:** `packages/common/src/guardian_common/metrics.py:180` declares
  `guardian_scan_engine_runs_total`; **zero emit sites**, and `workers/` never imports the registry
  at all. The registry is in-process, so worker counters could not reach the API's `/metrics`
  anyway.
* **Impact:** an operator scraping Prometheus has no signal about whether scans are running,
  failing or being skipped. Partially compensated by `GET /health/slo`, which derives
  `engine_success_rate` and stuck-scan counts from the database — that is what keeps this at P1
  rather than P0. The counter renders as `HELP`/`TYPE` with no samples, so it is *absent*, not
  falsely zero.

### RED-6 — Silent no-op on remediation open (P2)

* **File:** `services/api/src/guardian_api/routes/remediation.py:114`
* **Impact:** opening remediation for findings that were already triaged returns `201
  {"opened":0,"existing":0,"grouped":0}` with no reason. The refusal is *correct* (work should not
  be opened for an accepted risk) but it is indistinguishable from a bug.

### YELLOW-1 — Two divergent redaction implementations (P2)

`packages/common/src/guardian_common/logging.py:12` scrubs logs with **one** regex; WP-F2's
`guardian_core/redaction.py` has **12** and is used at every data boundary. A credential shape the
newer module catches (AWS, GitHub, Stripe, JWT, private keys) can still reach a log line.

---

## 5. Audit categories

| | Finding |
|---|---|
| **A. Dead code** | RED-1…RED-5. Also `dispatch_tool_job` / `dispatch_artifact_job` (`tools/tasks.py:179,563`) — no callers, consistent with A4 `NOT_STARTED` |
| **B. Built, not exposed** | Safe-scanning controls (H3) are configured only by writing `customers.settings` JSON directly; no API. Scheduling (A3) likewise — no route creates a `Schedule` |
| **C. Routes that cannot complete a workflow** | `POST /scans` returns 202 and, without a worker, the scan never leaves `queued`. Honest at the API layer; fatal at the product layer |
| **D. Engines registered but never invoked** | None — all 9 entry points are selectable and validated at `scans.py:49`. Engines needing absent binaries report `degraded` rather than running silently |
| **E. Silent failure** | RED-1 (no event), RED-6 (no-op 201). Otherwise strong: per-engine failures are isolated and recorded, and a failure outside the per-engine guard still lands the scan in `FAILED` with the cause (`tasks.py:349`) |
| **F. False-clean** | Well defended. `verification.py:91` reads `tool_versions.degraded` → `inconclusive`; a missing/failed engine → `not_checked`; neither resolves a finding. Compliance has `not_assessed`; SLOs have `unknown`; DAST/K8s emit coverage findings |
| **G. False-positive** | Bounded by design: verdicts require evidence rather than echo; version comparison uses real comparators; C3 refuses to fire without product *and* release |
| **H. Missing provenance** | None found. Findings carry engine, run, tool version, evidence and rationale; risk carries its rationale; audit log is append-only and DB-enforced |
| **I. Authorization bypass** | None found. All 25 mutating operations are authenticated except `/auth/login` and the HMAC-verified `/webhooks/github`. Machines cannot use human-role endpoints |
| **J. RLS / tenant isolation** | Verified under `guardian_app` (non-super, non-BYPASSRLS): 41 policies, every `tenant_id` table covered, cross-tenant read and write both refused. Full suite passes with **0 skipped** under the enforced role |
| **K. Secrets in logs** | No secret-bearing log statement found; `evidence=` fields are counts. Secrets decrypt only for engines declaring `wants_secrets` (`tasks.py:313`). Weakened by YELLOW-1 |
| **L. Licensing** | Gate live in CI: 50 tools, 5 not approved, exits non-zero on a prohibited tool. GREEN |
| **M. Migrations / clean DB** | Fixed and now tested from zero on every CI run; both build paths produce byte-identical DDL |
| **N. Disaster recovery** | `docs/deployment/05-backup-and-dr.md` + `infra/scripts/pg_backup.sh`/`pg_restore.sh` exist with RPO ≤ 5 min stated. Never rehearsed. The clean-database defect that would have broken a restore is now fixed and guarded |
| **O. Scan observability** | RED-5 |
| **P. Product UX** | The console is a read-only demo: login, dashboard, findings, attack graph, compliance, chat. Every write action a customer needs is API-only |
| **Q. Blocks measurable value** | No worker (A1) → nothing executes. Then RED-1/2/3 → three sold capabilities produce nothing |

---

## 6. Top 10 risks

| # | Risk | Sev |
|---|---|---|
| 1 | No worker: every scan queues forever. Nothing the platform does reaches a customer | **P0** (BLOCKED_EXTERNAL) |
| 2 | RED-1 webhooks never fire — a silent integration that reads as "all clear" | **P0** |
| 3 | RED-2 service→CVE never runs — infrastructure scanning yields no vulnerability findings | **P0** |
| 4 | RED-3 correlation never runs — duplicate criticals, no escalation, remediation ungrouped | **P1** |
| 5 | RED-5 no scan telemetry — an operator cannot see the scanner stop working | **P1** |
| 6 | No signup / tenant-creation API — no self-serve onboarding is possible | **P1** |
| 7 | No API for written-consent authorization — the managed/pentest motion cannot be represented | **P1** |
| 8 | Console cannot perform any write action — every customer workflow needs curl | **P1** |
| 9 | DR never rehearsed; backup scripts unexercised | **P2** |
| 10 | Two redaction implementations; logs use the weaker one | **P2** |

---

## 7. Can we sell this today?

**NO.**

Minimum exact conditions to change it to YES (pilot-grade, one design-partner customer):

1. **A worker executes tasks.** Any host that runs `celery -A guardian_scanner worker -Q default`
   against the same Postgres and Redis. Until then nothing else on this list matters.
   *(External/commercial decision — not an engineering task, and explicitly out of scope here.)*
2. **Wire RED-1, RED-2, RED-3** — approximately 30 lines in `tasks.py` plus one beat entry, using
   functions that already exist and are already tested.
3. **One authorization path an operator can use** — either an API to record written consent, or a
   documented, supported procedure for the ownership flow with a real domain.
4. **One live end-to-end run against a controlled vulnerable target**, producing a finding, a
   report, a remediation item, a retest and a webhook delivery — observed, not simulated.
5. **A scan-execution metric or an alert on `/health/slo`**, so a stalled scanner is noticed by the
   operator rather than by the customer.

Items 2–5 are days of work. Item 1 is a purchasing decision.

---

## 8. Single highest-leverage next action

**Wire the four orchestration gaps in `workers/scanner/src/guardian_scanner/tasks.py`.**

Roughly thirty lines converts three fully-built, fully-tested packages (C3, E1, G3) from unreachable
code into working product. Nothing else in this audit offers a comparable ratio of value to effort —
every other gap requires building something, and this one requires connecting things that already
exist and already have tests waiting for them.

It is second in *sequence* to having a worker, but first in *leverage*, and it is the only one of
the two that is within engineering's control.

---

## 9. What should NEVER be built next

- **More scanner engines.** Nine exist; several already can't reach a customer. A tenth adds
  nothing but surface.
- **More vulnerability taxonomy.** CWE, OWASP, CPE, EPSS, KEV and exploit maturity are already
  modelled more thoroughly than anything currently consumes.
- **More compliance frameworks.** SOC 2, ISO 27001 and PCI DSS assess at 13% coverage; a fourth
  framework deepens a hole rather than filling one.
- **AI/ML risk scoring.** Deterministic scoring is a stated product invariant and a differentiator.
- **More integrations** (Jira, Slack, Teams) while the webhook that would carry them is dead.
- **A console redesign.** The console's problem is that it cannot write, not that it looks wrong.
- **New work packages of any kind.** The correct next unit of work is *connection and verification*,
  not construction.

---

## 10. Final recommendation

### `BLOCKED_EXTERNAL`

Production operation is blocked on a background worker that cannot be provisioned within the stated
constraints, and no amount of engineering removes that.

But the label should not be read as "nothing to do". Even with a worker provisioned tomorrow, the
platform would ship with three sold capabilities silently producing nothing. The honest sequence is:

**WIRE** (RED-1/2/3, ~30 lines) → **VERIFY** (one live run against a controlled target) →
**READY_FOR_PILOT** → *(worker)* → **PRODUCTION**

The security engineering underneath this is the part that is hard to buy and hard to retrofit, and
it is in good shape. What is missing is the last inch of assembly, and the proof that the assembled
thing runs.
