# Guardian — Production / Commercial Readiness Audit

**Re-audited at `de4aa1e`** after the productization phase. The WIRE → VERIFY re-audit at `7909782`
is carried forward in §4 and §6; the original audit at `83edbda` is summarised in §0.

Method, unchanged: the golden path is **executed**, not read. It runs as a committed test
(`tests/integration/test_golden_path.py`) against the real API and the real orchestrator, on a
database built from zero, under the RLS-enforced `guardian_app` role. It now also runs through the
product UI (`apps/web/src/Journey.test.tsx`), against the real shell, router and screens. "Tests
pass" is still not accepted as evidence of production operation anywhere in this document.

---

## 0. What the earlier audits found

The first audit found three capabilities complete, tested, and **unreachable** — outbound webhooks,
service→CVE matching and cross-engine correlation had no caller anywhere outside their own tests.
The WIRE phase connected them, and connecting them exposed three real defects (§5.1–5.3).

The second audit found the resulting machine assembled and unusable: the console could not perform
a single write, there was no way to create a tenant, and no route could record an authorization. A
customer could not reach any of it without curl. That is what this pass fixed.

---

## 1. Executive verdict

| Dimension | Audit 1 | Audit 2 | **Now** | Why |
|---|---|---|---|---|
| **Engineering completeness** | 85% | 95% | **96%** | Unchanged in substance: no new engine, no new vulnerability class, no architectural change. The four new routes are seams onto existing domain logic. Remaining 4%: per-run engine health at the *reconciliation* boundary (Y4), and the un-started A4 tool framework. |
| **Product completeness** | 45% | 60% | **90%** | The whole journey — sign up, organization, domain proof, asset, authorization, scan, findings, dossier, report, remediation, retest, notifications — is operable from the console with no API knowledge. Remaining 10%: no user administration, no per-customer branding, no saved views, and remediation ownership is take/release rather than assignment to a named colleague (no directory endpoint exists). |
| **Commercial readiness** | 25% | 45% | **60%** | A prospect can be shown the product and can drive it themselves. It still does not execute work: no worker (A1), so `POST /scans` queues forever in a deployment. That single fact is the ceiling on this number. |
| **Operational readiness** | 40% | 70% | **72%** | Unchanged apart from `GET /scans/queue-health`, which puts the operator's own `scanner_liveness` judgement in front of the customer. Still not deployed; DR still unrehearsed. |
| **Security assurance** | 80% | 88% | **90%** | The new consent endpoint does not weaken the ownership gate — `active_recon` is refused without a verified domain — and sign-up now writes under RLS with the tenant bound before the first insert, which is a tighter rule than the code it replaced. |

**One-sentence verdict:** the product is now usable by the customer it was built for, and it still
has nothing to execute their work.

---

## 2. Evidence

| | |
|---|---|
| Commit | `de4aa1e` (from `ca5812b`) |
| Backend tests | **2131 → 2160**, 0 skipped, 0 failed |
| Web tests | **13 → 42**, 0 failed |
| Clean-database run | `alembic upgrade head` from an empty database (53 tables, 41 RLS policies), `guardian_app` (`rolsuper=f`, `rolbypassrls=f`), no test-only shortcuts → **2160 passed** |
| CI | green at `1fe2fe5` (run 32170951294); lint, migrate, seed, tests, web typecheck/test/build, licence gate, SBOM, pip-audit |
| Golden path | 22 stages, all asserted, **3** explicitly UNVERIFIED (was 4) |
| UI journey | 4 tests driving the real `App`: empty account → asset → domain → authorization → scan → findings → dossier → retest → report → remediation |
| New tests | `test_product_seams` (26), `Journey.test.tsx` (4), `Screens.test.tsx` (16), `Scans.test.tsx` (7) |

---

## 3. Golden-path matrix

Executed by `tests/integration/test_golden_path.py` (API) and `apps/web/src/Journey.test.tsx` (UI).
Status is what the run demonstrates, not what the code contains.

| # | Stage | API | UI | Evidence |
|---|---|---|---|---|
| 1 | Organization created | **GREEN** | **GREEN** | `POST /auth/signup` → 201; creates tenant, owner, membership, first customer and nothing else |
| 2 | Authentication | **GREEN** | **GREEN** | `GET /auth/me` → 200 |
| 3 | Business unit | **GREEN** | **GREEN** | `POST /customers` → 201; Organization screen |
| 4 | Ownership challenge | **GREEN** | **GREEN** | Publishable `_guardian-challenge.<domain>` TXT record and token, shown to the customer |
| 5 | Ownership check (refusal) | **GREEN** | **GREEN** | Real DNS lookup, no record published → not verified |
| 5b | Ownership check (pass) | **UNVERIFIED** | — | Needs a domain we control |
| 6 | Asset onboarding | **GREEN** | **GREEN** | `POST /assets` → 201 |
| 7 | Authorization recorded | **GREEN** | **GREEN** | `POST /authorizations` → 201; artifact plane only, responsible identity on the row |
| 7b | Active testing refused unverified | **GREEN** | **GREEN** | 409 naming the unverified domain |
| 8 | Discovery | **GREEN** | **GREEN** | `POST /discovery/runs` → 202 |
| 9 | Scan accepted | **GREEN** | **GREEN** | `POST /scans` → 202 |
| 9b | Scan executes in production | **BLOCKED_EXTERNAL** | **GREEN (blocked state)** | No worker (A1/A1b). The API test invokes the orchestrator in-process; the UI test asserts the customer is told the scan is waiting, with no fabricated progress and no result. |
| 10–12 | Findings, evidence, deterministic risk | **GREEN** | **GREEN** | Returned with evidence; credential absent from the response; integer score from `guardian_core.scoring`; rationale shown on the dossier |
| 13 | Service → CVE | **GREEN** | n/a | Controlled fixture: advisory + affected version → finding with provenance; patched version → none |
| 14 | Correlation | **GREEN** | **GREEN** | Grouped on the scan path; shown on the dossier as one issue seen several ways |
| 15 | Attack paths | **GREEN** | **GREEN** | `chains` and `unchainable_findings` both reported |
| 16 | Workbench | **GREEN** | **GREEN** | Filter, sort, triage with a required justification for false-positive / accepted-risk |
| 17 | Compliance | **GREEN** | **GREEN** | Three-state with coverage |
| 18 | Report | **GREEN** | **GREEN** | Created, exported, credential absent; downloaded from the UI with the bearer token |
| 19 | Remediation | **GREEN** | **GREEN** | Opened; truthful 200 + reason when nothing is created; SLA, owner, due date, ticket body |
| 20 | Retest | **GREEN** | **GREEN** | 202, verdict recorded, resolves after the fix |
| 21 | Webhook delivery | **GREEN** | **GREEN** | Queued, signed, attempted over a real socket, retry scheduled |
| 21b | Webhook 2xx round trip | **UNVERIFIED** | — | Needs a reachable receiver |

---

## 4. Previously RED and YELLOW items

| ID | Item | Was | Now | Evidence |
|---|---|---|---|---|
| RED-1…RED-6, YELLOW-1 | Wiring gaps from audit 1 | RED | **GREEN** | Unchanged since `7909782`; see git history for the per-item evidence |
| Y1 | No signup / tenant-creation API | YELLOW | **GREEN** | `POST /auth/signup`, rate-limited, non-enumerating, grants nothing |
| Y2 | No API records a written-consent authorization | YELLOW | **GREEN** | `POST /authorizations`; `written_consent` free, `active_recon` gated on a verified domain |
| Y3 | Console is read-only | YELLOW | **GREEN** | 13 screens covering every customer workflow; every write operation a customer needs is reachable |

---

## 5. Defects found *by* this work

Wiring a capability is the first time anyone runs it. Two more surfaced in this phase, both of
which would have been live defects.

### 5.1 `GET /scans/queue-health` was unreachable (fixed)

It was declared after `GET /scans/{scan_id}`. Starlette matches routes in declaration order and
`{scan_id}` compiles to `[^/]+`, so the literal path matched the parameterised route first and the
UUID coercion rejected it with a 422 — the handler never ran. The endpoint the console uses to
explain a waiting scan answered nothing but a validation error. Moved above `/{scan_id}`; a test
now asserts the literal route resolves.

### 5.2 Sign-up could not write under RLS (fixed)

`get_db` hands out an RLS-enforced session. The policies on `tenants`, `tenant_memberships` and
`customers` check each row against `app.current_tenant`, and sign-up is the one request where the
row being inserted *is* the tenant — so with nothing bound, PostgreSQL refused the insert and the
whole front door returned a 500. Invisible on a developer database, where the app role is the owner
and RLS is inert; CI sets `GUARDIAN_APP_DATABASE_URL` to `guardian_app`, so this would have been red
on the first push. It now chooses the tenant id and binds it before writing, which is also the
tighter rule: for the length of that transaction sign-up can write **only** rows belonging to the
organization it is creating. The slug pre-flight check was deleted with it — under RLS that session
can never see another tenant's slug, so the check always found it free and then failed on the unique
index. Uniqueness is left to the database, with one suffixed retry.

### 5.3 The console's empty state never fired (fixed)

`Async` decided "empty" with `Array.isArray(data) && data.length === 0`, but every paginated loader
returns `{rows, hasMore, nextCursor}`. The `empty` branch was therefore unreachable on every
paginated screen, and each would have rendered a bare table header where the explanation belongs.
Caught by the scan-screen tests before any of it shipped.

Carried forward from audit 2: §5.1 correlation merged unrelated credentials, §5.2 a structlog
keyword collision could fail a committed scan, §5.3 five engines could report clean having read
nothing. All three remain fixed and guarded.

---

## 6. Remaining YELLOW

| # | Item | Why it is not GREEN |
|---|---|---|
| Y4 | Per-run engine health at the reconciliation boundary | The customer is now told: `GET /scans/{id}/engines` downgrades a degraded completed run to `inconclusive`, and the scan screen refuses to call an empty result clean when any engine did not fully answer. **Reconciliation still does not know.** A tool that crashes mid-run still completes non-degraded internally, so resolution treats it as clean. Fixing that changes the engine contract. |
| Y5 | DR unrehearsed | Backup and restore scripts exist and are documented; nobody has restored from them. |
| Y6 | Feeds never synced live | Egress to NVD/OSV/KEV/EPSS is blocked here. CVE matching is verified against a controlled advisory, not a live feed. |
| Y7 | No live IdP / AI provider / AWS | SSO, AI narrative and cloud collection are verified against real tokens and stubs, never a live dependency. |
| Y8 | No user administration | An organization has exactly one member — the owner created at sign-up. There is no invite flow and no directory endpoint, which is also why remediation ownership is take/release rather than assignment to a named colleague. |

---

## 7. Remaining RED

| # | Item | Impact |
|---|---|---|
| R1 | Nothing executes in production | `POST /scans` enqueues to Celery; no worker consumes it. Every stage downstream of "accepted" is theoretical in a deployment. This is A1/A1b — see §8. The product now states this to the customer rather than spinning: a queued scan with a stalled scanner is shown as waiting, with the reason, and no result is implied. |

That is the only RED.

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

**NO — and exactly one thing stands in the way.**

Audit 1: three capabilities a buyer would be sold on produced nothing, silently.
Audit 2: everything worked and nothing ran, and a customer could not touch any of it.
Now: a customer can sign up, onboard, authorize, ask for a scan, and be told — accurately — that
Guardian has accepted it and has nothing to run it with.

Minimum conditions for a controlled design-partner pilot:

1. **A worker executes tasks.** Everything else is downstream of this. *(External — a purchase.)*
2. ~~A way for the customer to act.~~ **Done.**
3. **One live end-to-end run against a controlled vulnerable target**, observed: finding → report →
   remediation → retest → webhook received with a verifying signature. *(Needs 1.)*
4. **An alert wired to `scanner_liveness`**, so a stalled scanner is noticed by the operator before
   the customer sees the queued-and-nothing-running banner. *(Hours of work.)*

---

## 10. Verdict

### `BLOCKED_EXTERNAL` — engineering and product gates both cleared

The machine is assembled, it has a control panel, and the control panel tells the truth about a
machine with no power supply. The remaining work between here and a pilot is a purchase and one
observed live run.

**Pilot readiness: NO**, on one external blocker. Nothing left on the critical path is a defect in
what was built.
