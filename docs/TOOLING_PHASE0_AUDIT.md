# Phase-0 architecture audit — is the framework ready for providers?

> A strict, skeptical audit run **before** any new tool is implemented, to answer one question:
> can Guardian add tool providers without rebuilding the architecture, and without a governance
> bypass or an evidence-integrity hole? This is a verification pass, not a design pass. Nothing was
> refactored; no provider was implemented.

Method: direct source reading of the critical paths (governance, job-signing, execution, evidence,
redaction) plus two independent code-trace passes (resource controls + licence CI; engine_outcome +
evidence/AI boundary), plus running the safety-critical unit tests. Every claim below cites the file
and line it was verified against.

---

## Executive verdict: **READY WITH BLOCKERS**

The architecture is genuinely sound. The three invariants the whole product rests on are **real and
enforced in code, not by convention**:

1. **No governance bypass.** Running a provider requires an Ed25519-signed job; only the
   governance-passing Control Plane can sign; the execution plane holds the public key alone. This
   is a cryptographic boundary, not a called-in-the-right-place convention.
2. **The AI cannot inject a finding.** The findings table gives the AI exactly one nullable column
   (`ai_explanation`) plus a `remediation` annotation. There is no insert path in the AI service.
   Severity is owned by the deterministic engine; the model has no channel to return one.
3. **"Did not run" can never render as "clean."** The `is_evidence` gate makes a `not_checked` /
   `inconclusive` verdict physically incapable of resolving a finding, and the scan/dashboard/report
   layers each refuse to present a non-completed engine as a clean result.

So the answer to "is Claude quietly rubber-stamping while a governance bypass or evidence hole
hides?" is **no** — those are the strongest parts of the codebase, and they hold up under a hostile
read.

**But three real blockers must close before the first secret-emitting or binary-installed provider
(gitleaks is both-adjacent) ships.** None is an architecture flaw; each is a bounded, isolated fix.
The headline: two of the safety mechanisms the tooling plan leans on are **narrower than they
appear** — secret redaction at persistence is key-name-based only (a value in a benignly-named field
leaks to the DB and UI), and the licence gate is blind to the `curl | tar` install pattern the repo
actually uses for its main tools.

---

## Architecture map

```
 Control Plane (trusted, has DB + KMS + Ed25519 PRIVATE key)
   dispatch_tool_job / dispatch_artifact_job        tasks.py:180, 564
     │  1. registry.capabilities_for(tool_key)      registry.py:38  → derive_capability_level  capability.py:47
     │  2. evaluate_governance(...)                  governance.py:201   ← deny-by-default gate
     │  3. derive_effective_scope + evaluate_tool_policy
     │  4. consume single-use approval (L3+)         tasks.py:229
     │  5. sign_job(job)                             job_signing.py:80   ← PRIVATE key
     ▼
 [ Celery "tools" queue — untrusted transport ]
     ▼
 Execution Plane (DB-less, has PUBLIC key only)
   run_tool(signed)                                  tasks.py:132
     │  verify_job(signed)  ── forged/expired/replayed → refused (returns [])   job_signing.py:93
     │  execute_tool(provider, job)                  execution.py:22   ← ONLY provider-execution entry
     │     backend: inproc (free host)  |  uid_nft (worker, CAP_NET_ADMIN)
     │       sandbox.run_in_sandbox — rlimits, SIGALRM, forked child          sandbox.py
     ▼  RawEvidence (sealed)
 Control Plane
   persist_evidence_chain (hash-chained, key-scrubbed)   evidence.py:64
   _bind_and_derive_findings → normalize.to_finding      tasks.py:274 / normalize.py:42
   [ optional ] AI analyst → ai_explanation + remediation ONLY   analysis.py:35
```

---

## 1. Provider seam — READY

- Providers register as `guardian.tool_providers` entry points (`pyproject.toml:87-100`); the
  registry loads them by entry point, `lru_cache`s them, and rejects anything not implementing
  `ToolProvider` (`tools/registry.py:15-41`).
- The contract is four methods (`validate` / `execute` / `normalize` + `capabilities`) on
  `ToolProvider` (`packages/common/.../ports.py:178-200`), with `NullToolProvider` as the safe
  default.
- **Adding a provider requires no change to unrelated framework code** — confirmed: a new provider
  is a class + an entry-point line + a licence row + tests. The four in-tree providers
  (`dns_posture`, `pcap_meta`, `web_tls`, `ct_surface`, `web_checks`, `nmap*`) are all this shape.

Verdict: the seam is real and cheap. This part is ready as claimed.

## 2. Capability model — READY

- L0–L5 (`PASSIVE_ANALYSIS … DESTRUCTIVE`) exist as `CapabilityLevel` (`capability.py:29-35`).
- The level is **derived deterministically** from a provider's declared primitives by
  `derive_capability_level` (`capability.py:47-60`) — `destructive → L5`, exploit category → L4,
  sensitive category → L3, `active → L2`, `network → L1`, else L0.
- **A provider cannot self-authorize.** Governance calls `derive_capability_level(caps)` on the
  provider's *declared* capabilities (`governance.py:206`), and the provider "is never consulted and
  never sees identity, role, grant, campaign, or approval" (`governance.py:16`). A provider that
  under-declares its capability is a licence/registry review concern, not a bypass — it still cannot
  see or influence the identity decision.

## 3. Governance — READY (strongest area; no bypass found)

`evaluate_governance` (`governance.py:201-278`) is deny-by-default and layered:
- principal resolution → base ceiling (platform owner L5 / staff role-ceiling / service capped at
  **L2**, `governance.py:42, 260-261`);
- tool-catalog enablement (disabled → refused; unregistered L3+ → refused, `governance.py:137-146`);
- capability grants can *raise* a ceiling but never lift a service past L2 (`governance.py:257-258`);
- L3+ additionally require an **active, in-window campaign** the actor operates
  (`governance.py:149-172`) and a **valid, unconsumed, scope/provider/campaign-matched approval**,
  with an **independent approver required at L4+** (`governance.py:196-197`);
- the approval is **consumed only after the whole gate passes** (`tasks.py:229-238`), single-use via
  a conditional `UPDATE ... WHERE consumed_at IS NULL`.

**The bypass question — traced end to end, no bypass exists:**
- The only code that executes a provider is `execute_tool` (`execution.py:22`), called **only** from
  `run_tool` (`tasks.py:157`) — verified by grep across `workers/` and `services/`.
- `run_tool` calls `verify_job(signed)` **before** any reconstruction, backend choice, or provider
  call (`tasks.py:147`). A forged / tampered / expired / replayed job is refused and returns `[]`
  (`tasks.py:148-150`).
- The signature is Ed25519 (`job_signing.py:26-27, 86`); the Control Plane holds the **private** key
  and the execution plane verifies with the **public** key alone — "it can never mint a valid job"
  (`job_signing.py:6-7`). Signing happens only in the two Control-Plane dispatchers, **after**
  governance + policy pass.
- Execution backend is **not downgradable from the job**: an external-binary provider is forced onto
  `uid_nft` regardless of what the (authenticated) job settings say (`execution.py:30-34`).

So an attacker who can enqueue a raw `run_tool` message to the tools queue still cannot run anything
— they cannot produce a valid signature. **This is a cryptographic boundary, not a convention.**

Minor caveat (not a bypass): the replay-nonce cache is bounded and in-memory (`job_signing.py:9`),
so across multiple execution-plane processes or a restart, replay protection is best-effort — but
signature + expiry still bound the window. Worth noting, not blocking.

Tests run: `tests/test_job_signing.py` (valid roundtrip, and the forge/tamper/expiry cases) — pass.

## 4. Execution planes — READY

- **inproc** (free host, offline/fixed-endpoint) and **uid_nft** (worker, external binaries) —
  `execution.py:5-9`.
- The **tool** path sandboxes **unconditionally** (`backends/inproc.py:25-35` calls
  `run_in_sandbox` every time), unlike the *engine* path which sandboxes only under
  `sandbox_engines` — so every provider run is confined on a POSIX host.
- **What specifically prevents L2+ on the free host today:** the `uid_nft` backend needs
  `CAP_NET_ADMIN` + kernel nftables to build the per-run egress table, and fails closed if isolation
  cannot be established — "an external binary is never executed unconfined" (`backends/uid_nft.py`
  header). The free Render host has neither capability. This is BLOCKER-1, and it is not solved here
  (out of scope, as instructed).

## 5. engine_outcome() — READY on the invariant, NOT on six-way granularity

- Defined in `workers/scanner/.../verification.py:76-100`, returning a `Verdict`. States are
  **module-level string constants, not a `packages/core` enum** as the plan hypothesized:
  `still_present` / `resolved` / `not_checked` / `inconclusive` (`verification.py:48-51`).
- **The core invariant is enforced in code**, not convention: `is_evidence` is true only for
  `still_present` / `resolved` (`verification.py:71-73`), and `_apply` returns without changing a
  finding when `not verdict.is_evidence` (`verification.py:192-195`). A failed / degraded / missing
  run therefore **physically cannot** resolve a finding. Backed by
  `test_a_failed_run_can_never_resolve_a_finding`, `test_a_degraded_run_is_inconclusive_not_resolved`,
  `test_a_missing_run_is_not_checked`, `test_an_engine_with_no_input_does_not_look_clean` — all pass.
- Scan aggregation: a scan is `completed` only when **no** engine failed or was skipped, else
  `partial` / `failed` (`tasks.py:423-428`). Dashboard surfaces failed/skipped/deferred as
  `engine_runs_unresolved` — "these are the states that must never read as 'clean'"
  (`dashboard.py:94`). Reports/compliance filter to `status == "completed"` and mark unrun controls
  `not_assessed`, never `passing`.

**Where it does not meet the request:** the six conceptual outcomes the user asked for
(NOT_CHECKED / NO_FINDINGS / FINDING / ERROR / UNSUPPORTED / BLOCKED) are **not** six-way distinct at
the verdict layer. ERROR (`failed`), UNSUPPORTED (no input), and BLOCKED (policy `skipped`) all
collapse into `not_checked`. The collapse is **safe** — all three correctly refuse to license a
"resolved" — but a customer cannot tell *why* an engine did not run from the verdict alone. The
distinction survives only at the lower `ScanEngineRun.status` (`failed` / `skipped` / `deferred`),
which the dashboard does surface. See P2-2.

Minor: `deferred` is not in the `{failed, skipped}` set that degrades a scan to `partial`
(`tasks.py:425`), so a scan whose only anomaly is a deferred engine is labelled `completed` (still
surfaced as unresolved on the dashboard). And `FindingSource.AI_ASSISTED` is defined
(`enums.py:145`) but never assigned — dead. See P3.

## 6. Evidence integrity / AI analyst — READY (strong)

- `RawEvidence` (`packages/core/.../tool.py:59-73`) and `RawFinding`
  (`packages/core/.../findings.py:18-61`) are produced by deterministic engines/providers — **34
  construction sites, all under `workers/scanner/`, none in `services/ai_analyst/`.**
- **The AI cannot create a customer-visible finding.** The `Finding` model exposes one AI-writable
  column, `ai_explanation` (`models/scanning.py:132`); the only place AI output touches the table is
  `analysis.py:35-58`, which iterates **already-persisted** findings and writes `ai_explanation` +
  `remediation` only. There is **no `session.add(Finding(...))`** in the AI service. Findings are
  created solely by `normalize.to_finding()` with `source="automated"` hardcoded.
- **Severity is never taken from the model.** The explain schema has no severity field
  (`analyst.py:34-45`); the executive-summary path overwrites any model-returned risk facts with
  deterministic values (`analyst.py:166-170`, "Deterministic values are authoritative").
- `guard.py` does all three of: scrub-secrets-first before the prompt (`sanitize_for_model`, calling
  `guardian_core.redaction.scrub`), neutralize prompt-injection from scanned content (delimiters +
  known injection shapes, **counted**), and record when the model contradicts a finding
  (surfaced, not silently corrected). Tests `test_known_injection_shapes_are_caught[*]`,
  `test_prose_that_assigns_a_different_severity_is_recorded` — pass.

Caveat (cosmetic, not a hole): contradiction detection is regex-based and gated to `critical`/`high`
findings. Because severity is never read from the model, an undetected downplay changes prose tone
only, never the stored severity/score/status.

This directly satisfies the plan's central rule — **"the AI may direct the search and explain the
result, but a finding requires tool-produced evidence"** — at the data-model level, which is the
strongest possible place to enforce it.

## 7. Licence enforcement — READY WITH BLOCKERS (narrower than it appears)

`tools/check_tool_licenses.py` is a **real gate**, not formatting validation: it reads a runtime
Dockerfile, extracts installed tools, and exits 1 if any is unlisted or in a blocked state
(`APPROVED_STATES` vs `BLOCKED_STATES = {LEGAL_REVIEW, PROHIBITED, NOT_ADOPTED}`,
`check_tool_licenses.py:27-30, 111-122`). It is wired into CI (`ci.yml:103-104`,
`guardian-deploy-worker.yml:53`); a non-zero exit fails the job. An unknown state token is a fatal
error, so a typo can't slip the gate.

**But its enforcement surface is materially smaller than the plan assumes — this is P1-2:**
1. It only recognizes `apt-get / apk / go install / pip / npm` installs (`_INSTALL`,
   `check_tool_licenses.py:40-42`). The repo's **main tools — trivy, gitleaks, syft, grype,
   osv-scanner — are installed via `curl … | tar`** (`infra/docker/Dockerfile.scanner:53-61`), which
   the regex never matches. A `curl`-downloaded **prohibited or unlisted binary would pass the gate
   silently** — the exact false-negative the tool exists to prevent.
2. Only the Dockerfile passed via `--image` is checked; `infra/docker/Dockerfile` (the worker-tools
   image with `nftables`) is **never gated** by any workflow.
3. A missing `--image` path makes `main()` return **0** ("nothing to enforce") — a renamed Dockerfile
   turns the gate green.
4. **No coupling between provider entry points and the registry.** The gate never reads
   `pyproject.toml`; adding a provider for an unlisted tool is not caught. (Live example of the
   decoupling: `nmap`/`nmap_service` providers are registered while the nmap binary is
   `LEGAL_REVIEW`.)

Also a doc/code drift: `NOT_ADOPTED` is enforced as blocked in code but omitted from the
"Approval states" table in `docs/TOOL_LICENSES.md`.

## 8. Sandbox / resource controls — READY WITH ONE GAP

Framework-enforced (in `sandbox.py`, applied to every tool run via the unconditional inproc path):

| Control | Value | Where |
|---|---|---|
| Wall-clock | 60s inproc / 180s uid_nft (SIGALRM→terminate) | `inproc.py:20`, `uid_nft.py:40`, `sandbox.py:209-210` |
| CPU | 30s (`RLIMIT_CPU`) | `inproc.py:21`, `sandbox.py` |
| Memory | ~2 GB (`RLIMIT_AS`) in a forked child | `sandbox.py:198-59` |
| Single-file disk | 256 MB (`RLIMIT_FSIZE`) + private tempdir | `sandbox.py:199, 241-242` |
| Processes / FDs | 64 (`RLIMIT_NPROC`) / 256 (`RLIMIT_NOFILE`), inherited FDs closed | `sandbox.py:200-205` |
| Core dumps | 0 | `sandbox.py:206` |
| Dispatch ceiling | Celery `.get(timeout=300)` | `tasks.py:247` |

A misbehaving in-process provider **cannot run forever** (SIGALRM + CPU limit kill it, contained to
`[]` and logged as `tool_contained`, never as "clean") and **cannot exhaust host memory** (per-run
2 GB in a forked child; host insulated).

**The gap (P2-1): no framework cap on returned evidence size.** The child's result crosses an
`os.pipe()` (`sandbox.py:245, 252-261`) — `RLIMIT_FSIZE` does not apply to pipe writes, and the
parent read is unbounded. Output bounding is left to each provider (e.g. `web_checks` caps
`_MAX_BYTES=200_000` / `_MAX_DETECTIONS=500`; `pcap` caps packets/endpoints). A provider that ignores
its own caps could return an evidence blob up to the 2 GB address-space limit. And `RLIMIT_FSIZE`
bounds a single file, not aggregate disk — no total-disk quota.

## 9. Secret redaction — READY WITH ONE GAP (gitleaks-critical) — P1-1

Two layers, and they cover **different** surfaces:

- **Egress to AI / webhooks** — **value/pattern-based** (`guardian_core/redaction.py:30-60`): catches
  `AKIA…`, `ghp_…`, JWTs, PEM private keys, `password=…` shapes, inline URL credentials. So a secret
  value reaching the model or a webhook is masked even in a benignly-named field. Good.
- **Persistence to the DB + UI** — **key-name-based only** (`tools/evidence.py:24-35`): it drops
  dict keys whose *name* matches `secret/token/password/...`, but does **not** inspect values. The
  design intent is that "a secret is never evidence" because the **provider** must not emit the value
  (`evidence.py:8-9`); the key-scrub is defense-in-depth, not a safety net.

**Why this blocks gitleaks specifically:** gitleaks output places the secret **value** in fields like
`Match` / `Secret` / `Line`. The `Secret` key would be dropped by name; `Match` would **not** — it is
a benign name carrying the raw credential. So a naive gitleaks provider that passed gitleaks' JSON
through would **persist the secret to `evidence_items` and render it in the UI**, because the
pattern-based scrub runs only on egress, not at persistence. The provider's own value-redaction is
therefore **load-bearing**, and it must be reviewed before it ships — exactly the gate flagged in the
tooling study.

Minimal fix options (either, ideally both): (a) route evidence content through
`guardian_core.redaction.scrub` at `persist_evidence_chain` time, not only on egress; and/or (b)
make the gitleaks provider mask values itself (fingerprint like `AK****EY (len=20)`, never the raw
match) and add a test that asserts no raw secret survives into an `EvidenceItem`.

## 10. AI analyst readiness

- Integration point exists: `services/ai_analyst/.../providers/anthropic_provider.py` (official SDK,
  structured outputs, refusal handling), selected when `anthropic_api_key` is set.
- **What is missing to enable it:** only `GUARDIAN_ANTHROPIC_API_KEY` (BLOCKER-3). The guardrails run
  today against a recording/stub provider.
- **Can the AI request governed tool calls rather than executing shell?** Today the analyst does not
  call tools at all — it annotates findings. There is no `shell()` and no direct tool execution in
  the AI service. The *agentic* capability described in the tooling study (§6.3) does not yet exist;
  when built, it must route through the same `dispatch_tool_job` governance path as any other
  principal. This is future work, correctly not present yet.

---

## Blockers, ranked

**P1 — close before the first secret-emitting or binary provider ships:**

- **P1-1 · Secret redaction at persistence/UI is key-name-based only.** A secret value in a
  benignly-named field (gitleaks' `Match`) is persisted and rendered. Fix: pattern-scrub at
  `persist_evidence_chain` and/or provider-level value redaction + a "no raw secret in EvidenceItem"
  test. Files: `tools/evidence.py:24-42`, `packages/core/.../redaction.py:98`.
- **P1-2 · Licence gate is blind to `curl | tar` installs, skips the second Dockerfile, and passes
  on a missing image.** A prohibited binary could ship undetected. Fix: extend `_INSTALL` to
  `curl`/`wget`/`tar` release fetches, gate **both** Dockerfiles in CI, and make a missing `--image`
  a hard failure. Files: `tools/check_tool_licenses.py:40-42, 152-154`, `ci.yml`,
  `guardian-deploy-worker.yml`.

**P2 — close before relying on the mechanism at scale:**

- **P2-1 · No framework cap on returned evidence size.** A provider could return up to ~2 GB. Fix: a
  size ceiling on the sandbox pipe result and a declared per-provider evidence cap in the contract.
  Files: `sandbox.py:245-261`, `tools/execution.py`.
- **P2-2 · engine_outcome does not distinguish ERROR / UNSUPPORTED / BLOCKED** from `not_checked` at
  the verdict layer. Safe, but a customer cannot see *why* an engine did not run. Fix (product
  decision): carry the `ScanEngineRun.status` reason through to the finding/dashboard verdict, or add
  distinct outcome states. Files: `verification.py:48-100`, `dashboard.py`.

**P3 — hygiene, non-blocking:**

- `deferred` does not degrade a scan to `partial` (`tasks.py:425`).
- `FindingSource.AI_ASSISTED` is dead (`enums.py:145`) — either assign it on AI-annotated findings or
  remove it.
- Replay-nonce cache is in-memory/per-process (`job_signing.py:9`).
- `NOT_ADOPTED` doc/code drift in `docs/TOOL_LICENSES.md`.

---

## Things that must NOT be changed

These are the invariants the product's credibility rests on. Do not "clean them up":

1. The **job-signing boundary** — asymmetric Ed25519, private key on the Control Plane only,
   `verify_job` before any execution work. Do not add an unsigned execution path or move signing to
   the tool plane.
2. The **`evaluate_governance` gate** and its deny-by-default ordering — do not add a fast path that
   skips it, and do not let a provider influence its own level.
3. The **`is_evidence` gate** in `verification.py` — do not let a `not_checked`/`inconclusive`
   verdict change a finding's status.
4. The **plane separation** (`_enforce_tool_plane`) and the DB-less execution plane — do not give the
   execution plane a DB, KMS, or the private signing key.
5. **Deterministic severity ownership** — do not let the model return or change severity/risk/status;
   keep the executive-summary overwrite.
6. The **AI annotation-only boundary** — the AI writes `ai_explanation` + `remediation` and never
   inserts a `Finding`. Do not give it an insert path.

---

## Evidence appendix

**Files inspected (critical path, read directly or via trace):**
`tools/governance.py`, `tools/tasks.py`, `tools/execution.py`, `tools/evidence.py`,
`tools/registry.py`, `tools/backends/inproc.py`, `tools/backends/uid_nft.py`, `sandbox.py`,
`packages/common/.../job_signing.py`, `packages/common/.../ports.py`, `packages/core/.../capability.py`,
`packages/core/.../tool.py`, `packages/core/.../findings.py`, `packages/core/.../redaction.py`,
`packages/core/.../enums.py`, `workers/scanner/.../verification.py`, `workers/scanner/.../analysis.py`,
`workers/scanner/.../normalize.py`, `packages/db/.../models/scanning.py`,
`services/ai_analyst/.../analyst.py`, `services/ai_analyst/.../guard.py`,
`services/ai_analyst/.../providers/anthropic_provider.py`, `services/api/.../routes/dashboard.py`,
`tools/check_tool_licenses.py`, `.github/workflows/ci.yml`,
`.github/workflows/guardian-deploy-worker.yml`, `infra/docker/Dockerfile.scanner`,
`docs/TOOL_LICENSES.md`, `pyproject.toml`.

**Tests run:** `.venv/bin/pytest tests/ -k "false_clean or governance or ai_guard or redaction or
verification or evidence_chain or job_sign"` → **87 passed, 61 skipped** (skips require a live
database; they are the integration tier). The passing set includes the load-bearing safety tests:
`test_a_failed_run_can_never_resolve_a_finding`, `test_a_degraded_run_is_inconclusive_not_resolved`,
`test_a_missing_run_is_not_checked`, `test_an_engine_with_no_input_does_not_look_clean[iac|k8s|secrets]`,
`test_the_engines_that_need_an_export_refuse_rather_than_reporting_clean`,
`test_known_injection_shapes_are_caught[*]`,
`test_prose_that_assigns_a_different_severity_is_recorded`, `test_valid_signed_job_roundtrips`.

**Git diff summary:** this commit adds only `docs/TOOLING_PHASE0_AUDIT.md`. No source file was
changed; no provider was implemented; no production behavior was altered.

**Final verdict: READY WITH BLOCKERS.** The framework can carry providers without an architecture
rebuild, and the core safety invariants are real and enforced. Close P1-1 (secret redaction at
persistence) and P1-2 (licence gate coverage) before the first provider that emits secrets or
installs a binary — i.e. before gitleaks. P2 items should close before the mechanism is relied on at
scale. Then Phase 1 (the gitleaks golden-reference provider) can proceed.
