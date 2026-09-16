# CYBER Full Product Audit

**Scope:** production-readiness / sellability audit of the real repository at milestone `ccb76f7`,
branch `claude/security-guardian-architecture-p1315d`. Evidence is `file:line`. This is an audit
document only — **no code, schema, or deployment was changed.** Findings are classified as
*confirmed defect*, *architectural risk*, *needs measurement*, *product gap*, or *documentation gap*;
anything not confirmable from the repo is marked **UNVERIFIED**.

Method: the whole tree was inspected across auth/RBAC/RLS/tenancy, SSRF/scan-safety/uploads/sandbox,
every scanner engine + orchestrator, the finding→risk→evidence→report→remediation pipeline, the AI
analyst + RAG, reliability/Celery/DB, deployment (render.yaml, compose, Dockerfiles, CI), tests,
performance architecture, the frontend console, and documentation.

---

## Executive Summary

CYBER is an unusually disciplined codebase for its stage. The **security foundation is real and
verified**, not aspirational: PostgreSQL Row-Level Security is present on every one of the ~47
tenant-owned tables with the tenant GUC set per request and re-applied per transaction; production
boot **refuses** to start with weak/misplaced secrets or a superuser/BYPASSRLS app role; SSRF egress
is pinned to a validated public IP in a DNS-rebinding-safe way; the sandbox applies real rlimits and
closes inherited sockets; the AI analyst is genuinely *advisory* (no tools, no secrets, no DB, no
ability to write or resolve findings, deterministic severity, tenant-scoped retrieval); and the
finding pipeline is honest about "not looked for ≠ clean." DB-gated tenant-isolation and
authorization tests **actually run in CI** against the non-owner `guardian_app` role.

The blockers to putting paying customers on it are **not** the security core. They are:

1. **Operational:** the periodic scheduler (Celery **beat**) is not present in any standing
   deployment, so stranded-scan recovery, vulnerability-feed refresh, webhook retries, and scheduled
   scans never run — a security platform silently aging its CVE intelligence and never recovering
   lost scans. (P0)
2. **Scanner transparency & finding quality:** active engines that are gated off produce *no*
   finding in the exported report; the capability matrix overstates a few things (server
   Package→CVE, "taint-based SAST"); and several static "indicators" are emitted at HIGH severity
   from byte-substring matches (false-positive risk). (P1)
3. **Onboarding & commercial:** there is no file-upload path (the console says "Upload the .apk"
   but the platform has no upload endpoint), no team invitations / account deletion / data export,
   and no billing/entitlement enforcement (plans are cosmetic). (P1 / commercial gaps)

None of the five parallel audits found a **P0 security breach, cross-tenant data exposure,
unauthorized/destructive scanning path, or RCE.** The confirmed security issues are all bounded
(staff-authenticated, same-tenant, or availability-only) and land at P1/P2.

## Production Readiness

**READY WITH CONDITIONS.**

Concrete reasons it is *not* NOT-READY: the multi-tenant security model (RLS + app filters + boot
guards), SSRF/sandbox controls, active-scan authorization gate, AI safety, and CI-run isolation
tests are implemented and verified. A security-conscious operator could run a controlled pilot
today.

Concrete conditions that must be met before charging self-serve customers:
- **P0-1** (scheduler) fixed — otherwise CVE intelligence silently ages and lost scans never
  recover.
- The scanner-transparency P1s addressed so a customer cannot read a report as "clean" when active
  testing never ran, and the capability matrix matches the code.
- The onboarding gap (no upload path / no invitations / no lifecycle) closed for the asset types the
  UI advertises.
- Commercial primitives (entitlement enforcement, or removal of the cosmetic plan tables) decided.

No overall numeric score is given, per the brief.

---

## P0 — Must Fix Before Selling

### AUD-P0-1 — Periodic scheduler (Celery beat) runs in no standing deployment
- **Area:** Reliability / Operations · *confirmed defect*
- **Evidence:** `celery_app.py` defines `beat_schedule` (`sweep-schedules`, `recover-stranded-scans`,
  `retry-webhook-deliveries`, `sync-vulnerability-feeds`). But `infra/render/start.sh` runs
  `celery … worker --queues default --concurrency 1` with **no `--beat`**; `docker-compose.prod.yml`
  has db/redis/migrate/seed/api/ingress/worker services but **no beat service**;
  `infra/docker/Dockerfile.scanner:142` CMD is worker-only. Beat exists only as an opt-in flag on a
  manual workflow (`guardian-burst-worker.yml:188`). `docs/PRODUCTION_AUDIT.md:165` (A1) itself
  admits "Scans, discovery, feed sync, webhook retries and scheduled work never run" — which
  **contradicts** `docs/PILOT_RUN.md:228` presenting recovery as "beat, every 5 minutes."
- **Impact:** Broken production operation with security-correctness consequences: (a) vulnerability
  feeds never refresh → CVE matching silently ages against a frozen KB; (b) `recovery.py`
  stranded-scan recovery is dead → a scan lost to a Redis restart stays `queued` forever; (c)
  scheduled/recurring scans never run; (d) failed webhook deliveries never retry. For a security
  product, silently stale vulnerability intelligence trends toward materially misleading results.
- **Verification:** VERIFIED by exhaustive grep across infra/compose/render/workflows; corroborated
  by the platform's own PRODUCTION_AUDIT.md.
- **Required fix:** Add a `celery … beat` process (a dedicated service in compose/render, or
  `worker --beat` on the single-instance node) wherever the sweeps are relied on.
- **Acceptance criteria:** In the deployed topology, `recover_stranded_scans`, `sweep_schedules`,
  `sync_vulnerability_feeds`, and `retry_webhook_deliveries` are observed to run on schedule (metric
  or log); a scan stranded by a broker restart returns to terminal state within one recovery
  interval; `feed_freshness` SLO stays green.

*(Deliberately the only P0: every other confirmed issue is bounded to P1/P2. See the calibration
notes in each P1 for why the "silent active-engine skip" and "server Package→CVE" items are P1, not
P0 — both have on-screen honesty mechanisms and human-in-the-loop mitigations.)*

---

## P1 — Should Fix Before Serious Customer Usage

### AUD-P1-1 — Gated active engines produce no "not tested" record in the exported report/dashboard findings
- **Area:** Finding transparency / customer trust · *confirmed defect (bounded)*
- **Evidence:** `tasks.py:359-378` — when an active engine (DAST/API/CSPM; `ACTIVE_ENGINES`,
  `enums.py:74`) lacks a valid authorization the run is set `deferred`/`skipped`, an audit row is
  written, and the loop `continue`s with **no Finding**. The honest "not tested" findings
  (`api_engine.py:260`, `dast_engine.py:271`) exist only when the engine actually runs.
- **Impact:** A `web`/`api` asset scanned without a verified-domain authorization yields zero active
  findings; the PDF/HTML report's findings section does not state "active testing did not run," so an
  auditor could read it as clean.
- **Mitigations (verified, why this is P1 not P0):** the scan-detail "what was actually checked"
  table surfaces each engine's `not_checked`/`deferred` state with the reason (`scans.py`
  `ENGINE_STATE_MEANING`); the dashboard surfaces `engine_runs_unresolved` with "did not answer /
  unknown, not clean" (Screens.test asserts this); the report compliance table prints `not assessed`
  as its own column; reports pass a human draft→approve→publish gate.
- **Required fix:** Render a "scope of testing / engines that did not run" section in the PDF/HTML
  report and reflect deferred-active-engines on the dashboard posture, so the omission is impossible
  to miss in the artifact, not only on one screen.
- **Acceptance:** A report generated for a scan where DAST was deferred explicitly lists DAST as not
  run, with the reason.

### AUD-P1-2 — Capability matrix overstates real scanner behavior
- **Area:** UX honesty / documentation · *documentation gap + missing capability*
- **Evidence:** `docs/SCANNER_CAPABILITY_MATRIX.md` claims server "Package→CVE reuse of SCA" — but
  `host_posture_engine.py:69-89` `collect_inventory` only feeds the SBOM component list and never
  calls a vuln matcher; `sbom.py` cross-references vulns solely from package-shaped *findings*, so a
  submitted server package inventory yields an SBOM with **zero vulnerabilities**. The matrix's
  "Taint-based SAST" is Python-only + intra-file (`taint.py:22`, `sast_engine.py:290-295`); all other
  languages are regex-presence rules. `web_checks`/`web_tls` are listed as website "engines" but are
  governed L3 tools requiring authorization **and human approval** and default to an offline snapshot
  (`web_checks_provider.py:146,198-219`). The matrix's "skipped ⇒ INCONCLUSIVE" for active engines is
  contradicted by AUD-P1-1 (skipped ⇒ *no finding*).
- **Impact:** Customers (and our own reports) infer coverage the code does not provide.
- **Required fix:** Correct the matrix to match code; where a capability is inventory-only or
  static-indicator-only, say so in the customer-facing surface, not just docs.
- **Acceptance:** Each matrix row is verifiable against an engine's actual output; no row promises
  CVE matching, dynamic analysis, or dataflow the code does not perform.

### AUD-P1-3 — High-severity findings from byte-substring "indicators" and soft-404 probing (false positives)
- **Area:** Finding quality / trust · *confirmed defect (quality)*
- **Evidence:** Mobile/iOS emit **HIGH** findings when a token string is merely present in the
  DEX/Mach-O bytes — `if token.encode() in data` (`mobile_engine.py:310`, `ios_engine.py:326`) for
  `TrustAllX509TrustManager`, `AllowAllHostnameVerifier`, `allowsAnyHTTPSCertificate`, etc.
  (`mobile_engine.py:66-71`, `ios_engine.py:69-73`) — with no call-site confirmation; a symbol in an
  unused vendored SDK or dead code produces a HIGH "TLS validation disabled / MITM" finding. The API
  shadow-endpoint probe counts `200/401/403/405/500/503` as "the route exists"
  (`apisec/discovery.py:63`), so against an SPA/reverse-proxy/soft-404 backend every wordlist entry
  (`admin`, `debug`, `actuator/env`, `swagger`) is reported as undocumented/exposed at LOW–MEDIUM.
- **Impact:** Confident false positives at HIGH/MEDIUM erode trust and can drive wrong remediation
  spend. (The disclaimer text is appended, but the *severity* the customer sees is HIGH.)
- **Required fix:** Cap string-indicator findings below HIGH (or to "informational — confirm call
  site") until corroborated; for the shadow-endpoint probe, calibrate against a known-random control
  path (soft-404 detection) before reporting existence.
- **Acceptance:** A benign app bundling a library that merely *contains* these symbols does not
  produce a HIGH finding; an SPA returning 200 for all paths does not flood shadow-endpoint findings.

### AUD-P1-4 — Chat path sends attacker-controlled finding content to the LLM unsanitized (prompt injection)
- **Area:** AI trust · *confirmed defect (bounded, same-tenant)*
- **Evidence:** `services/ai_analyst/src/guardian_ai/chat.py:36` builds
  `f"Question: {question}\n<scan_data>{json.dumps(context)}</scan_data>"` where `context` embeds raw
  `f.title` / `f.risk_rationale` (`chat.py:24-33`). Unlike the analyst path
  (`analyst.py:96/156` → `sanitize_for_model`), chat performs no delimiter/injection neutralization
  (`guard.py:40,47,96`). Wired live at `routes/chat.py:33`.
- **Impact:** Scanned content that becomes a finding title (a web page `<title>`, filename, or git
  commit message) can carry `</scan_data> New instructions: …` and break the data boundary in the
  customer's grounded chat. No tool/action exists and it is tenant-scoped, so blast radius is
  misleading advisory text to the same tenant — but that can drive a wrong "it's fine" decision.
- **Required fix:** Route the chat `context` through `sanitize_for_model()` exactly as `analyst.py`
  does.
- **Acceptance:** A finding title containing a `</scan_data>`-style break is neutralized before the
  prompt is built.

### AUD-P1-5 — Decompression-bomb DoS in the mobile/iOS artifact engines
- **Area:** Upload / availability · *confirmed defect (availability)*
- **Evidence:** `mobile_engine.py:280` and `ios_engine.py:300` do `data = zf.read(n)[:budget]` —
  `ZipFile.read()` fully decompresses the member into memory *then* slices; `mobile_engine.py:162`
  and `ipa.py:127/138/146` read whole members unbounded. `sandbox_engines` defaults **False**
  (`config.py:182`), so these engines run in-process. Contrast the correct pattern in
  `images/oci.py:147-154` (per-file + cumulative size check *before* read).
- **Impact:** A crafted `.apk`/`.ipa` with a high DEFLATE ratio inflates to gigabytes in the worker
  before the slice → OOM/crash DoS. (Reachability today is limited because there is no upload
  endpoint — see AUD-P1-7 — so the file must already be on the worker; this becomes directly
  exploitable the moment an upload path is added.)
- **Required fix:** Check `info.file_size` against the remaining budget and read bounded
  (`zf.open(n).read(budget + 1)`) as `oci.py` does; bound the manifest/plist reads too.
- **Acceptance:** A zip-bomb `.apk`/`.ipa` is rejected with a bounded read, no unbounded memory
  growth, with or without `sandbox_engines`.

### AUD-P1-6 — Arbitrary worker-filesystem read via asset `config.local_path` / `apk_path`
- **Area:** Authorization / tenant isolation · *confirmed defect (staff-auth, same-tenant)*
- **Evidence:** `routes/assets.py:45` stores `config=body.config` verbatim (`schemas.py:61`
  `config: dict`, free-form). Engines then open attacker-named paths: `tasks.py:204`
  (`cfg["local_path"]`), `mobile_engine.py:146-149` (`apk_path`/`local_path`/`artifact_path`),
  `container_engine.py` (`image_archive`). A `require_staff_write` user can point an asset at any
  path on the worker (`/etc`, mounted secrets, another tenant's ephemeral workspace) and have
  SAST/secrets/SCA surface its contents as findings.
- **Impact:** Local file disclosure / weak worker-plane isolation; requires an authenticated staff
  role and the data lands in the same tenant, so not unauthenticated and not cross-tenant, but it
  breaks the "the platform only reads what you gave it" contract.
- **Required fix:** Constrain path-bearing config keys to an allowlisted ingestion root; reject
  absolute/`..` paths.
- **Acceptance:** An asset config naming `/etc/passwd` (or any path outside the ingestion root) is
  refused before any engine opens it.

### AUD-P1-7 — No file-upload path; the console implies an upload the platform cannot perform
- **Area:** Onboarding / UX honesty · *product gap + UX honesty*
- **Evidence:** No `UploadFile`/multipart endpoint exists anywhere in `routes/` (grep). Assets are
  created with a text `identifier` + free-form `config`. Yet the guided scan hints say "Upload the
  .apk to the asset" / "Upload the .ipa" (`apps/web/src/scanCatalog.ts:42,50`), and the engines read
  the artifact from `asset_config[apk_path]`/`workspace` only (`mobile_engine._locate_apk`).
- **Impact:** A self-serve customer can create a `mobile_app`/`ios_app`/`container_image`/
  `cloud_account`/`server_host`/`network_host` asset and start a scan that then has nothing to read;
  the UI advertises an action the backend cannot complete. `repo`/`web`/`api` work (git clone / URL).
- **Required fix:** Either add an authenticated upload → object-storage → `asset_config` ingestion
  path, or gate these asset types in the console as "provide via API/agent" and remove the "Upload"
  wording until the path exists.
- **Acceptance:** No console flow claims an action (upload) it cannot complete; every advertised
  asset type is completable end-to-end from the console or is clearly marked otherwise.

### AUD-P1-8 — Dashboard security posture is computed from a capped 5000-finding subset
- **Area:** Performance / correctness · *confirmed defect (KNOWN PROBLEM)*
- **Evidence:** `routes/dashboard.py` loads `findings = fq.limit(5000).all()` then computes
  `total_findings=len(findings)`, severity/open counts, and `security_score(findings)` from that
  Python list.
- **Impact:** A tenant with >5000 findings gets `total_findings`, severity counts, and the headline
  security score from an arbitrary 5000-row subset — the exact "invents a plausible figure" failure
  the module docstring warns against — plus an O(5000) in-memory load per view.
- **Required fix:** Replace the row load with SQL `GROUP BY severity/status` aggregates for counts
  and score inputs.
- **Acceptance:** Dashboard counts/score match a direct DB aggregate for a tenant with >5000
  findings.

### AUD-P1-9 — Whole scan runs in one long transaction; `RUNNING` never externally visible
- **Area:** Reliability / observability · *confirmed defect + needs measurement*
- **Evidence:** `tasks.py:294` wraps the entire engine loop in one `session_scope()`; the
  `queued→running` claim (`tasks.py:310`) is flushed but not committed until scope exit (`:526`+).
- **Impact:** Under READ COMMITTED, dashboards / `queue-health` / SLO readers never observe `running`
  (uncommitted); a duplicate delivery's conditional UPDATE blocks on the Scan row lock for up to the
  1800s task limit; a pooled DB connection is held for the whole scan; long-open transactions defer
  VACUUM. Lock/vacuum pressure at concurrency is NEEDS MEASUREMENT.
- **Required fix:** Commit the `queued→running` claim in its own short transaction before running
  engines.
- **Acceptance:** `guardian_scan_queue_depth{state=running}` reflects in-flight scans; a duplicate
  delivery returns fast rather than blocking.

### AUD-P1-10 — Tool-dependent coverage may silently degrade on the Render image (NEEDS VERIFICATION)
- **Area:** Scanner coverage / deployment · *architectural risk / needs verification*
- **Evidence:** `infra/docker/Dockerfile.scanner:55-119` installs semgrep, checkov, modelscan,
  gitleaks, osv-scanner (full coverage). But `infra/render/build.sh:38-39` fetches only trivy +
  gitleaks. `ml_model_engine.py:75-82` has no built-in detector → INCONCLUSIVE without modelscan;
  semgrep/osv/checkov only widen coverage when present.
- **Impact:** If Render is the production target, ML-model scanning is inert and SAST/SCA silently
  run at reduced coverage — the "fewer findings looks like a cleaner codebase" failure the engines'
  own comments warn about.
- **Verification:** UNVERIFIED which image is production (Dockerfile.scanner vs Render build.sh).
  Determine the prod scanner image; if Render, this is a confirmed silent coverage loss.
- **Required fix:** Make the prod scanner image install the full tool set, or surface a per-engine
  "tool absent → reduced coverage" state to the customer (the `degraded`/INCONCLUSIVE machinery
  already exists — wire the absent tools into it visibly).
- **Acceptance:** The production scanner image runs every wrapped tool, or the console/report states
  which tool-backed engines ran degraded.

---

## P2 — Important Product Hardening

Each is confirmed and bounded; fix after P0/P1.

- **AUD-P2-1 Worker plane bypasses RLS with no GUC backstop.** `session.py:78-116` worker sessions
  use the owner engine and never `set_tenant`; isolation depends 100% on every worker query
  filtering `tenant_id` (spot-checked correct in `tasks.py`, but enrichment modules
  correlation/verification/service_cve/discovery UNVERIFIED line-by-line). *Fix:* set
  `app.current_tenant` per-tenant in the worker as defense-in-depth.
- **AUD-P2-2 No JWT revocation / password-change invalidation.** `security.py:49-65` stateless HS256,
  no `jti`/token-version; TTL ≤60m; mitigated by per-request account/membership checks
  (`deps.py:181-207`). *Fix:* token-version claim bumped on disable/rotate.
- **AUD-P2-3 Brute-force + rate limiter is per-process in-memory.** `ratelimit.py:20-82` (its own
  docstring notes N× under N replicas); resets on restart. *Fix:* back with Redis / gateway limit.
- **AUD-P2-4 No email verification on self-serve signup.** `auth.py:62-161` activates + issues a
  token immediately; anyone can create a tenant under an unowned email. *Fix:* gate scanning on a
  verification link. (`self_serve_signup` can be disabled today.)
- **AUD-P2-5 No application security headers.** `main.py` adds only CORS + metrics; no
  nosniff/CSP/frame; `/docs` Swagger HTML served with none; compose nginx sets HSTS only and Render
  has no nginx. *Fix:* headers middleware in `main.py` (holds on every deploy path).
- **AUD-P2-6 Finding fingerprint includes version-bearing `title`.** `findings.py:52-61` keys on
  `title`; SCA/container/service-CVE titles embed `@version` (`sca_engine.py:164`). Upgrading to a
  still-vulnerable version splits history and marks the old finding `resolved` while a new one opens.
  *Fix:* drop `title` from the fingerprint; identify by engine+category+normalized location+rule/CVE.
- **AUD-P2-7 AI-discovery severity taken from the model.** `ai_discovery_engine.py:221,276` →
  `base_severity` floors the deterministic band (`scoring.py:101,171`); an unverified LLM
  "critical" persists at risk≈90 and can fire the `finding.critical` webhook. *Fix:* clamp
  AI-discovery severity until the verifier confirms.
- **AUD-P2-8 Explanation/title not scrubbed at export boundary.** `routes/remediation.py:261-263`
  passes `ex.what_it_means/what_to_do` unscrubbed; `reporting/html.py:108` + `pdf.py:83,114` +
  `generator.py:67-73` write `f.title` only HTML-escaped, not `scrub_text`'d. *Fix:* `scrub_text`
  over title + all `explain_finding`-derived fields on every export/ticket path. (Low likelihood a
  raw secret lands in a 300-char title, but this is the boundary scrubber's stated purpose.)
- **AUD-P2-9 Report remediation precedence bug prints `None`.** `reporting/generator.py:67-73` — a
  `remediation` dict lacking `summary` renders `- [HIGH] <title>: None`. *Fix:* compute
  `summary = (f.remediation or {}).get("summary") or "<fallback>"` before the f-string.
- **AUD-P2-10 Within-tenant integrity gaps.** `remediation.py:301` assigns to any global user id (no
  tenant-membership check); `webhook_endpoints.py:99-103` stores `customer_id` without
  `_assert_customer_in_tenant`. Low impact (no access granted; events just never match). *Fix:*
  validate both against `identity.tenant_id`.
- **AUD-P2-11 Scan cancellation unimplemented.** `enums.py:158` `CANCELED` is defined but never
  written; no cancel endpoint. Only the platform kill-switch + 1800s timeout stop a runaway scan.
  *Fix:* `POST /scans/{id}/cancel` + cooperative revoke.
- **AUD-P2-12 Git-clone DNS-rebinding.** `tasks.py:211` validates the resolved IP then `:225` clones
  by hostname (git re-resolves) — resolve-then-reconnect, unlike the socket-pinned DAST path.
  Staff-gated, blind. *Fix:* pin git to the validated IP.
- **AUD-P2-13 Spec parse has no size cap.** `api_engine.py:329` `yaml.safe_load`/JSON on
  `openapi_spec` with no length bound (safe_load blocks code exec; anchor fan-out CPU/mem risk).
  *Fix:* cap spec byte length.
- **AUD-P2-14 Non-constant-time metrics-token compare.** `health.py:38-40` plain `==` (fails closed
  when unset). *Fix:* `hmac.compare_digest`.
- **AUD-P2-15 Global GitHub webhook secret + cross-tenant asset lookup.** `webhooks.py:40-59` one
  platform secret; asset lookup runs RLS-bypassed across all tenants and takes `.first()` on repo-URL
  collision. *Fix:* per-tenant/per-endpoint secrets + collision disambiguation.
- **AUD-P2-16 No JSON report export.** Only PDF/HTML (`routes/reports.py:214-220`); the SBOM is the
  only machine-readable artifact. *Fix:* add a JSON report export for programmatic consumers.
- **AUD-P2-17 Exotic IPv6 (6to4/NAT64) not decoded by the internal-IP guard.** `sandbox.py:90-114`
  decodes IPv4-mapped IPv6 but not 6to4/NAT64 embedded IPv4. Theoretical (requires such a routable
  path). *Fix:* decode 6to4/NAT64 before classification.
- **AUD-P2-18 `scans:write` API scope is unusable.** `apikeys.py` defines `SCANS_WRITE` but
  `scans.py:41` requires `require_staff_write` which rejects machine principals — a declared scope
  with no wired path (fails closed; note so it isn't "fixed" by loosening the human gate).

---

## Capability Matrix (verified against code)

`Production-ready`: **yes** = deterministic, evidence-backed, works in the cloud as-is · **partial**
= real but gated/limited/heuristic · **no** = advertised but not implemented as findings.

| Asset | Capability | Real implementation | Prod-ready | Key limitation | FP risk | FN risk | Priority |
|---|---|---|---|---|---|---|---|
| Website | DAST passive+active | headers/cookies/HSTS/TLS/banner + GET-only injection probes, egress-pinned (`dast_engine.py`) | partial | whole engine `requires_authorization` → **skipped ⇒ no finding** without a verified domain | low | high if skipped | P1 (AUD-P1-1) |
| Website | web_checks / web_tls | governed L3 tools, `requires_human_approval`, snapshot unless `allow_live` (`web_checks_provider.py`) | partial | not the pipeline engine the matrix implies; no live output w/o campaign+approval | low | offline-only default | P1 (AUD-P1-2) |
| API | contract + deep spec audit | static OpenAPI + scheme/exposure/pagination audit (`api_engine.py`, `spec_audit.py`) | yes | needs `openapi_spec`; raises if absent (honest) | low | only what the spec declares | P2 |
| API | BOLA/BFLA/auth (active) | GET/HEAD, two principals; honest `_not_tested` when absent (`api_engine.py`) | partial | `requires_authorization` + principals; skipped in cloud default | issue-confidence | untested classes w/o principals | P1 (AUD-P1-1) |
| API | shadow-endpoint probe | GET wordlist + secured-GET-no-creds (`apisec/discovery.py`) | partial | 200/401/403/500/503 ⇒ "exists" | **high** on soft-404/SPA | tiny 23-entry list | P1 (AUD-P1-3) |
| Android | static APK | zip + AXML decode + manifest posture + DEX string/secret scan | partial | no dynamic/emulator (honest) | **high** — HIGH-sev string indicators | reachability, packed code | P1 (AUD-P1-3) |
| iOS | static IPA | zip + plist + mobileprovision entitlements + Mach-O strings | partial | FairPlay store binaries unreadable (INFO'd); entitlements only from `.mobileprovision` | **high** — same indicators | store builds: no strings | P1 (AUD-P1-3) |
| Home Network | host_posture (network) | assesses authorized local-agent JSON; refuses w/o `authorized` | partial | never scans; agent is a **reference collector** | low | agent-coverage-bound | P1 (agent maturity) |
| Server | host_posture (server) | SSH/firewall/EOL/sudo/Docker rules on agent report | partial | config posture only; `os.eol` trusted from agent | low | posture-only | P1 |
| Server | Package → CVE | inventory feeds SBOM only; **no vuln match / no finding** (`host_posture_engine.py:69-89`) | **no** | advertised in matrix but not implemented | — | **all server package CVEs** | P1 (AUD-P1-2) |
| Cloud | CSPM (AWS) | real AWS API-shape rules; raises on bad export (`cspm_engine.py`) | partial | AWS-only; `requires_authorization` (skip risk); collector-dependent | low | non-AWS; uncovered resources | P1 |
| Container | image + Dockerfile | Dockerfile rules + layer reader + dpkg/apk/pypi/npm → matcher; deleted-layer secrets | yes | RPM DB explicitly flagged unparsed (honest) | naive `FROM` tag parse | RPM pkgs; KB coverage | P2 |
| Kubernetes | manifest posture | rules over manifests/export; coverage finding for unparsed | yes | passive; export must be supplied | low | only supplied manifests | P2 |
| Source | SAST | Python intra-file **taint** + multi-lang regex + optional semgrep | partial | taint = Python-only intra-file; others = presence-regex | med (presence) | **high** JS/Java/Go dataflow | P1 (AUD-P1-2) |
| Source | SCA | npm/pip/poetry/pipfile/gem/go/cargo/composer + optional osv-scanner | yes | no repo-level system-pkg parsing | low | ecosystems needing osv when tool absent | P2 |
| Source | secrets | patterns + entropy + git-history diff + optional gitleaks | yes | history bounded (1000 commits/400k lines/120s) | med (entropy) | secrets beyond bounds | P2 |
| Source | ml_model | **modelscan-only** wrapper; degraded→INCONCLUSIVE if absent | partial | zero coverage if binary missing (see AUD-P1-10) | low | everything if absent | P1 (AUD-P1-10) |
| Source | ai_discovery | LLM hypotheses, `ai_assisted`, always degraded, line-verified | partial | needs LLM key; 12-file cap; "verified"=line exists | overstates sev (AUD-P2-7) | non-exhaustive by design | P2 |

---

## Security Findings (confirmed weaknesses, separate from product gaps)

- **No P0 security breach / cross-tenant exposure / unauthorized-or-destructive scanning / RCE** was
  found. Tenant isolation (RLS on all tenant tables + app filters + boot guards), SSRF egress
  pinning (DNS-rebind-safe), active-scan authorization, and sandbox isolation are VERIFIED.
- Bounded, staff-authenticated / same-tenant / availability-class issues: AUD-P1-4 (chat prompt
  injection), AUD-P1-5 (zip-bomb DoS), AUD-P1-6 (worker file read via config path); AUD-P2-2/3/4/5
  (session/rate/verification/headers), AUD-P2-12 (git DNS-rebind), AUD-P2-13 (spec size),
  AUD-P2-14/15/17 (metrics token, webhook secret, IPv6).

## Reliability Findings (confirmed)

- AUD-P0-1 (scheduler dead), AUD-P1-9 (single long transaction / `running` invisible), AUD-P2-11
  (no cancellation). VERIFIED-STRONG: atomic `queued→running` claim, per-engine failure isolation →
  `partial`, terminal `FAILED` for non-engine failures, fail-closed safe-scan kill-switch, recovery
  logic distinguishing broker-unreadable from empty.

## UX Findings (confirmed)

- AUD-P1-7 (no upload path; "Upload the .apk" implies capability the platform lacks) — the biggest UX
  honesty gap. AUD-P1-1/P1-2 (scope-of-testing & matrix honesty) are UX-visible too. VERIFIED-STRONG:
  honest loading/error/empty states (`Async`), per-engine "what was actually checked", first-run
  welcome, guided scan, journey strip, plain-language findings shared with reports/tickets.

## Performance Findings

- **Measured / KNOWN PROBLEM:** AUD-P1-8 (dashboard 5000-cap miscount). VERIFIED-STRONG: cursor
  pagination, `page_size` refuses `limit<1`, report rendering bounded with a truncation banner,
  DB-global scan admission, evidence stored in Postgres (not ephemeral disk).
- **Inferred architectural bottleneck:** single shared `default` queue + concurrency-1 worker
  (Render) = throughput ceiling; DB connection math `(pool 5 + overflow 10) × engines × processes`
  approaches `max_connections` without PgBouncer around ~100 tenants; per-replica in-memory rate
  limiter.
- **Needs measurement:** JSONB evidence/SBOM bloat; `percentile_cont` duration queries;
  `generator.py:41` loads all findings for report content (HTTP path is bounded).
- **Speculative:** no retention/partitioning on findings/evidence/audit/usage (state it as a
  measurement task, not a defect).

## Product / Commercial Gaps (separate from engineering defects)

- **No billing/payment; entitlements unenforced.** `models/billing.py:1` "SCHEMA ONLY";
  `Plan`/`PlanEntitlement`/`Subscription` seeded (`seed.py:35`) but `PlanEntitlement` is read nowhere
  — `max_assets`/`scans_per_month`/`seats` enforced nowhere; only live scan-concurrency is capped via
  `tenants.settings["quota"]`. Plans are cosmetic. *Commercial gap.*
- **No team invitations, account deletion, or data export.** No users/members router
  (`routes/__init__.py`); signup creates a single owner. Compliance/portability blocker.
- **Pilot data is disposable:** free Render Postgres deleted after 30 days (`render.yaml`).

## Documentation Gaps (stale / contradictory, verified)

- `billing.py:3` claims entitlements ENFORCE limits — no enforcement exists.
- `docs/PILOT_RUN.md:228` presents recovery as live ("beat, every 5 minutes") vs
  `docs/PRODUCTION_AUDIT.md:165` "scheduled work / recovery / feed sync never run" (AUD-P0-1).
- `README.md:53` "Vulnerability Intelligence … refreshed on a schedule" — untrue on the deployed
  pilot (no beat).
- `docker-compose.prod.yml:104` "converges to head `0011_web_checks_catalog`" — actual head is
  `0021_sbom`.
- `docs/SCANNER_CAPABILITY_MATRIX.md` overstates server Package→CVE, taint-SAST breadth, web_checks
  as pipeline engines, and "skipped ⇒ INCONCLUSIVE" (AUD-P1-2).

## Test Coverage Gaps

VERIFIED-STRONG: DB-gated integration tests **run in CI** (`.github/workflows/ci.yml` provisions
Postgres+Redis, sets the non-owner role, `GUARDIAN_RUN_DB_TESTS=1`); `test_rls_isolation`,
`test_scan_authorization`, `test_recon_isolation`, `test_false_clean_matrix`, `test_scan_recovery`,
`test_scale_limits`, `test_apikey_auth`, control-plane/broker-confidentiality all execute. Gaps:
- No deployment-topology test asserting a **beat** process exists where the sweeps are relied on
  (would have caught AUD-P0-1).
- Enrichment-module worker queries (correlation/verification/service_cve/discovery) not line-audited
  for tenant-filter correctness under RLS-bypass (AUD-P2-1).
- No test for the dashboard >5000-finding aggregate correctness (AUD-P1-8).

## Deployment / Operations Gaps

- AUD-P0-1 (beat), AUD-P2-5 (headers). Render single-instance + concurrency-1; `/health/ready`
  checks DB only, not the broker (dead Redis ⇒ API "ready" while nothing dispatches). VERIFIED-STRONG:
  boot config validator (weak/misplaced secrets, non-TLS Redis/PG, unauth Redis, plane-secret
  boundary), RLS app-role verified at boot, no committed secrets, migrate-once-before-replicas,
  restore-verification backup workflow, CORS refuses wildcard+credentials.

## What Is Already Strong (verified, not marketing)

- RLS on all ~47 tenant tables + tenant GUC per request/transaction (`session.py:64-93`); boot
  refuses superuser/BYPASSRLS app role and dev-sentinel secrets (`main.py`, `config.py`).
- SSRF egress pinned to a validated public IP, DNS-rebinding-safe, no redirect-follow
  (`dast_engine.py:56-81`, `sandbox.py:100-124`); the new API discovery probes reuse the same pinned
  transport.
- Sandbox with CPU/AS/FSIZE/NOFILE/NPROC rlimits + inherited-FD close; no `shell=True`; external
  tools use fixed argv; uploads are static-only (no unpickling/execution).
- Active-scan authorization gate + fail-closed safe-scan kill-switch, per-asset concurrency=1,
  intensity profiles default to `safe`.
- AI is safely advisory: no tools/secrets/DB, deterministic severity, credential-scrubbed egress,
  reference-filtered output, tenant-scoped (global-only) RAG, deterministic stub fallback.
- Finding honesty: dedup/one-row-per-issue, triage never overturned by a rescan, "not looked for ≠
  clean" (INCONCLUSIVE), regression reopen, human-only accepted-risk/false-positive.
- Auth: Argon2id, rate-limit-before-hash + dummy-verify (non-enumerating), JWT alg allowlist,
  immediate account-disable enforcement.
- CI runs the isolation/authz tests against the real non-owner role; report/PDF evidence redaction;
  cursor pagination; bounded reports with truncation banner.

---

## Recommended Execution Order

**P0 → P1 → P2**, strictly technical/product sequencing:

1. **P0:** AUD-P0-1 (deploy beat) — smallest fix, largest correctness impact.
2. **P1, in this order:** AUD-P1-7 (upload path / stop implying it) → AUD-P1-1 + AUD-P1-2 (report
   scope-of-testing + correct the matrix) → AUD-P1-3 (severity of string-indicator + soft-404 FPs) →
   AUD-P1-4 (chat sanitize) → AUD-P1-5 (zip-bomb bound) → AUD-P1-6 (config path allowlist) →
   AUD-P1-8 (dashboard SQL aggregate) → AUD-P1-9 (commit the claim) → AUD-P1-10 (verify prod scanner
   image / surface degraded tools).
3. **Commercial (parallel track before charging):** entitlement enforcement or remove plan tables;
   invitations / deletion / data export; managed Postgres.
4. **P2:** the hardening list, in the order above.

---

## Final Sellability Checklist

- [x] **Security** — core verified (RLS, SSRF, sandbox, authz); residual issues are P1/P2, none P0.
- [x] **Tenant isolation** — RLS on all tenant tables + per-request GUC + boot guard (worker-plane
  defense-in-depth is AUD-P2-1).
- [x] **Authorization** — route-level tenant scoping + object ownership verified; within-tenant
  integrity nits AUD-P2-10.
- [ ] **Scanner correctness** — AUD-P1-2 (matrix overstates), AUD-P1-3 (FP severity), AUD-P1-10
  (tool coverage).
- [x] **Evidence integrity** — redacted at API/report; boundary-scrub gap AUD-P2-8.
- [ ] **Reports** — AUD-P1-1 (scope-of-testing omission), AUD-P2-9 (`None` bug), AUD-P2-16 (no JSON).
- [x] **AI safety** — safely advisory; one gap AUD-P1-4 (chat sanitize).
- [ ] **Deployment** — AUD-P0-1 (beat), AUD-P2-5 (headers), broker not in readiness.
- [ ] **Reliability** — AUD-P0-1, AUD-P1-9, AUD-P2-11 (cancellation).
- [ ] **UX** — AUD-P1-7 (implied upload), AUD-P1-1/P1-2 (scope/matrix honesty).
- [ ] **Documentation** — stale claims (billing, feeds, migration head, matrix): AUD-P1-2 + Docs
  Gaps.
- [x] **Testing** — isolation/authz run in CI; gaps AUD-P0-1 topology test, AUD-P1-8, AUD-P2-1.
- [ ] **Operations** — AUD-P0-1; retention/partitioning NEEDS MEASUREMENT; readiness lacks broker.
- [ ] **Customer onboarding** — AUD-P1-7 (no upload path); no invitations/deletion/export.
- [ ] **Usage controls** — per-tenant rate limit + DB-global scan admission exist; plan
  entitlements unenforced (commercial gap).
- [ ] **Billing / entitlements** — none (commercial gap; schema-only).

*Checked = demonstrably implemented and verified. Unchecked = see the referenced finding IDs.*
