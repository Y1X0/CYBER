# Guardian — Production / Commercial Readiness Audit

**Re-audited at `7909782`** after the WIRE → VERIFY gate. The original audit at `59b191f`
(commit `83edbda`) is summarised in §0; every finding it raised is tracked to a new status in §4.

Method, unchanged: the golden path is **executed**, not read. It now runs as a committed test
(`tests/integration/test_golden_path.py`) against the real API and the real orchestrator, on a
database built from zero, under the RLS-enforced `guardian_app` role. "Tests pass" is still not
accepted as evidence of production operation anywhere in this document.

---

## 0. What the first audit found

Three capabilities were complete, tested, and **unreachable**: outbound webhooks, service→CVE
matching, and cross-engine correlation had no caller anywhere outside their own tests. A fourth
(per-finding retest) had no API. Scan-execution telemetry was a declared metric that was never
emitted. The conclusion was that the packages had each been finished in isolation and several were
never connected — "a well-built parts bin rather than a running system".

That is what this pass fixed.

---

## 1. Executive verdict

| Dimension | Was | Now | Why |
|---|---|---|---|
| **Engineering completeness** | 85% | **95%** | Every capability the platform ships is now reachable from the path that should reach it. Remaining 5%: per-run engine health (a degraded tool still completes cleanly), and the tool-execution framework which belongs to the un-started A4. |
| **Product completeness** | 45% | **60%** | The API now drives the whole journey including retest and notification. Unchanged and still the ceiling: the console cannot perform a single write action, there is no signup or tenant-creation API, and no route records a written-consent authorization. |
| **Commercial readiness** | 25% | **45%** | A customer would now receive real value from every stage *once work executes*. It still does not execute: no worker (A1), so `POST /scans` queues forever in production. |
| **Operational readiness** | 40% | **70%** | Scan execution is observable for the first time — queue depth, scans by status, engine runs by engine and status, duration quantiles, and the age of the last completion, all read from the database at scrape time. `scanner_liveness` alerts when work is waiting and nothing is finishing. Still not deployed, and DR is still unrehearsed. |
| **Security assurance** | 80% | **88%** | Five engines could report clean when they had read nothing; they now refuse with a reason. Logs and data boundaries agree on what a secret looks like. A false-correlation defect that merged unrelated credentials is fixed. |

**One-sentence verdict:** the assembly is done and the product now works end to end in a test
harness; what remains between here and a pilot is an execution environment and a customer-facing
way to drive it.

---

## 2. Evidence

| | |
|---|---|
| Commit | `7909782` (from `59b191f`) |
| Tests | **2051 → 2131**, 0 skipped, 0 failed |
| Clean-database run | `alembic upgrade head` from zero, `guardian_app` (`rolsuper=f`, `rolbypassrls=f`), 41 RLS policies, no test-only authorization shortcuts → **2131 passed** |
| CI | green at `4c602fc` (run 32104995687 lineage); lint, migrate, seed, tests, web typecheck/test/build, licence gate, SBOM, pip-audit |
| Golden path | 19 stages, all asserted, 4 explicitly UNVERIFIED |
| New tests | `test_wired_pipeline` (21), `test_golden_path` (19), `test_false_clean_matrix` (14), `test_scan_telemetry` (10), `test_log_scrubbing` (16) |

---

## 3. Golden-path matrix

Executed by `tests/integration/test_golden_path.py`. Status is what the run demonstrates, not what
the code contains.

| # | Stage | Status | Evidence |
|---|---|---|---|
| 1 | Tenant + owner | **RED** | Written directly to the database. No signup or tenant-creation API exists. |
| 2 | Authentication | **GREEN** | `GET /auth/me` → 200 |
| 3 | Customer | **GREEN** | `POST /customers` → 201 |
| 4 | Ownership challenge | **GREEN** | 201 with a publishable `_guardian-challenge.<domain>` TXT record and token |
| 5 | Ownership check (refusal) | **GREEN** | Real DNS lookup, no record published → not verified |
| 5b | Ownership check (pass) | **UNVERIFIED** | Needs a domain we control |
| 6 | Asset onboarding | **GREEN** | `POST /assets` → 201 |
| 7 | Authorization | **YELLOW** | Written directly; no API creates one |
| 8 | Discovery | **GREEN** | `POST /discovery/runs` → 202 |
| 9 | Scan accepted | **GREEN** | `POST /scans` → 202 |
| 9b | Scan executes in production | **BLOCKED_EXTERNAL** | No worker (A1/A1b). Orchestrator invoked in-process. |
| 10 | Findings | **GREEN** | Returned with severity and category |
| 11 | Evidence | **GREEN** | Present, and the credential is absent from the API response |
| 12 | Deterministic risk | **GREEN** | Integer score > 0 from `guardian_core.scoring` |
| 13 | Service → CVE | **GREEN** | Controlled fixture: advisory + affected version → `vuln-service` finding with provenance; patched version → none |
| 14 | Correlation | **GREEN** | Runs on the scan path; groups one credential across two engines; refuses to merge three credentials on one line |
| 15 | Attack paths | **GREEN** | `chains` and `unchainable_findings` both reported |
| 16 | Workbench | **GREEN** | Summary + triage |
| 17 | Compliance | **GREEN** | Three-state with coverage |
| 18 | Report | **GREEN** | Created, exported, credential absent from the export |
| 19 | Remediation | **GREEN** | Opened; truthful 200 + reason when nothing is created |
| 20 | Retest | **GREEN** | `POST /findings/{id}/retest` → 202, verdict recorded, resolves after the fix |
| 21 | Webhook delivery | **GREEN** | Queued, signed, attempted over a real socket, retry scheduled |
| 21b | Webhook 2xx round trip | **UNVERIFIED** | Needs a reachable receiver |

---

## 4. Every previously RED item

| ID | Item | Was | Now | Evidence |
|---|---|---|---|---|
| RED-1 | Outbound webhooks never fire | RED | **GREEN** | `tasks.py` emits `scan.completed`/`scan.failed`/`finding.critical`; delivery persisted, signed, attempted, retried. 8 tests. |
| RED-2 | Service version → CVE never runs | RED | **GREEN** | Wired after `enrich_graph`; controlled advisory fixture produces a finding, patched version does not, unversioned service counted not guessed. |
| RED-3 | Findings never correlated | RED | **GREEN** | Wired after reconciliation. Fixing the wiring exposed a real defect in the rule — see §5. |
| RED-4 | Per-finding retest unreachable | RED | **GREEN** | `POST /findings/{id}/retest`; still-present leaves open, fixed resolves, other tenants 404. |
| RED-5 | No scan telemetry | RED | **GREEN** | DB-derived gauges + `scanner_liveness` SLO. The dead counter is deleted. |
| RED-6 | Remediation silent no-op | RED | **GREEN** | 201 only when created; otherwise 200 with a machine-readable reason. |
| YELLOW-1 | Two redaction implementations | YELLOW | **GREEN** | Logs use the 12-pattern boundary scrubber recursively; a test fails if a pattern is added to one and not the other. |
| Phase 4 | Engines returning `[]` on no input | (new) | **GREEN** | `secrets`, `k8s`, `iac`, `cspm`, `api` now refuse with a reason → `not_checked`. |

---

## 5. Defects found *by* this work

Wiring a capability is the first time anyone runs it. Three real defects surfaced:

### 5.1 Correlation merged unrelated credentials (fixed)

`correlation.py::_secret_identity` read the redacted value from `evidence["detail"]`, and the
secrets engine writes it at `evidence["match"]` — top level. The redacted branch therefore never
fired on a real finding, and every identity fell through to `path:line`. The rule was wrong in both
directions: three different credentials on one line of a `.env` were reported as *"one credential
reported by several engines"*, while the same credential found by two engines in two places never
grouped at all. Invisible because correlation had no caller. Both directions are now tested.

### 5.2 A notification bug could fail a committed scan (fixed)

The first version of the webhook emitter used `event=` as a structlog keyword — which is reserved —
so it raised *after* the deliveries were queued and took the whole completed scan down with it. The
emitter is now guarded as a unit: the blast radius of the notification path stops at a log line.

### 5.3 Five engines could report clean having read nothing (fixed)

`engine_outcome` is the platform's single safety property: only a failed, non-completed or degraded
run avoids `RESOLVED`. So an engine that returns `[]` because its input was missing hands
reconciliation permission to resolve that asset's existing findings. A missing collector export
would have quietly closed every cloud finding a customer had. This overturned a documented decision
in `test_cspm_engine` — *"an asset with no collector export has not failed; it has nothing to
assess"* — which is true about the engine and false about the platform.

---

## 6. Remaining YELLOW

| # | Item | Why it is not GREEN |
|---|---|---|
| Y1 | No signup / tenant-creation API | A tenant is created by `guardian_api.seed` or by hand. No self-serve onboarding is possible. |
| Y2 | No API records a written-consent authorization | The only programmatic path to an `Authorization` is a passing ownership check. A signed pentest engagement cannot be represented, which blocks the managed-services motion. |
| Y3 | Console is read-only | 7 read endpoints against 25 mutating operations. Every customer workflow needs curl. |
| Y4 | Per-run engine health | A tool that crashes mid-run (semgrep, git history) is now *logged*, but the run still completes non-degraded, so reconciliation treats it as clean. Fixing it properly changes the engine contract — assembly cannot reach it. |
| Y5 | DR unrehearsed | Backup and restore scripts exist and are documented; nobody has restored from them. The clean-database defect that would have broken a restore is fixed and guarded. |
| Y6 | Feeds never synced live | Egress to NVD/OSV/KEV/EPSS is blocked here. The KB is seeded, so CVE matching is verified against a controlled advisory, not a live feed. |
| Y7 | No live IdP / AI provider / AWS | SSO, AI narrative and cloud collection are verified against real tokens/stubs, never a live dependency. |

---

## 7. Remaining RED

| # | Item | Impact |
|---|---|---|
| R1 | Nothing executes in production | `POST /scans` enqueues to Celery; no worker consumes it. Every stage downstream of "accepted" is theoretical in a deployment. This is A1/A1b — see §8. |

That is the only RED left. Every other previously-RED item is GREEN.

---

## 8. External blockers

| ID | Blocker | Consequence | What would clear it |
|---|---|---|---|
| **A1** | No background worker. Render Free provides none and no money may be spent. | Scans, discovery, feed sync, webhook retries and scheduled work never run. | Any host running `celery -A guardian_scanner worker -Q default`. A purchasing decision, not an engineering one. |
| **A1b** | Network plane needs `CAP_NET_ADMIN` for `uid_nft`. | `nmap_provider` / `nmap_service_provider` cannot run. Only these two set `external_binary=True`. | A container runtime that grants the capability. |
| B-1 | CT log egress blocked | Certificate-transparency discovery unverified live |
| B-2 | Feed egress blocked | Intelligence freshness unverified live |
| B-3 | No AI provider key | Narrative generation runs on the deterministic stub |
| B-4 | No IdP | OIDC verified against real signed tokens, never a live provider |
| B-5 | No controlled domain | A *passing* ownership check is unverified |
| B-6 | No reachable webhook receiver | A 2xx delivery round trip is unverified |

---

## 9. Can we sell this today?

**NO — but the reason has changed, and that matters.**

Before: three capabilities a buyer would be sold on produced nothing, silently.
Now: everything works, and nothing runs.

Minimum conditions for a controlled design-partner pilot:

1. **A worker executes tasks.** Everything else is downstream of this. *(External.)*
2. **A way for the customer to act.** Either a console that can write, or an operator running the
   API on their behalf as a managed service — which is a legitimate pilot shape and needs Y2 (an
   authorization the operator can record) more than it needs Y3.
3. **One live end-to-end run against a controlled vulnerable target**, observed: finding → report →
   remediation → retest → webhook received with a verifying signature.
4. **An alert wired to `scanner_liveness`**, so a stalled scanner is noticed by the operator.

Items 2–4 are days of work. Item 1 is a purchase.

---

## 10. Verdict

### `BLOCKED_EXTERNAL` — with the engineering gate cleared

The WIRE and VERIFY phases are complete. What was a parts bin is now an assembled machine with a
test harness proving it turns over. It has no power supply.

**Pilot readiness: NO**, on one external blocker and one product gap (a customer-facing way to
drive it). Neither is a defect in what was built.
