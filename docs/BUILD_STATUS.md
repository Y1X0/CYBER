# Guardian Build Status

Machine-readable progress against the Engineering Work Order v1.0. One row per work package.

**States:** `NOT_STARTED` · `IN_PROGRESS` · `IMPLEMENTED` · `TESTED` · `DEPLOYED` · `LIVE_VERIFIED` ·
`BLOCKED_EXTERNAL`

A package is never marked beyond `TESTED` without recorded evidence. `LIVE_VERIFIED` means it ran
against a real system and the output was inspected — not that a test double returned the right shape.

Baseline: commit `8e4338b` · 26,465 lines · 552 tests · 34% code-complete · 0% operable.

**Current: 2160 Python tests + 42 web tests passing** (+1650), 37 work packages delivered, 0 skipped on a database built from zero under the RLS-enforced role.

The productization phase (`de4aa1e`) turned the platform into a product a customer can operate: a console covering the whole journey, plus the four API seams it needed — `POST /auth/signup`, `POST /authorizations`, `GET /scans/{id}/engines` and `GET /scans/queue-health`. No new engine, no new vulnerability class, no architectural change. Wiring it exposed two live defects: `queue-health` was shadowed by `GET /scans/{scan_id}` and unreachable, and `POST /auth/signup` could not write under the RLS-enforced role. See `docs/PRODUCTION_AUDIT.md`.

The WIRE → VERIFY gate (`7909782`) connected the capabilities the readiness audit found built and unreachable — outbound webhooks, service→CVE matching, correlation and per-finding retest — and closed the false-clean paths in five engines. See `docs/PRODUCTION_AUDIT.md`.

Run two ways, because the difference between them was hiding a production defect:
`GUARDIAN_APP_DATABASE_URL` pointed at the owner role by default, and the full suite passes with
**0 skipped** only when it is pointed at the real RLS-enforced `guardian_app` role — the
configuration production runs. With the owner default, 15 RLS assertions skip and the API-key tests
pass for the wrong reason. See WP-G1b.

**Correction to earlier entries: CI had not been green, on any commit of this branch.** It failed at
*"Migrate database"* — `alembic upgrade head` could not build a database from nothing — with the
entire rest of the pipeline skipped behind it, so the "CI green" claims in the rows below were wrong
when they were written. Clearing that one unmasked two more, each hidden behind the last:

1. `pytest` (the console script CI runs) does not put the repository root on `sys.path`, while
   `python -m pytest` does — so `tests/test_tool_licenses.py` collected 1,972 tests and then aborted
   the whole run on `ModuleNotFoundError: No module named 'tools'`. Fixed with `pythonpath = ["."]`.
2. jsdom 30 requires Node `^22.22.2 || ^24.15.0 || >=26` and the workflow pinned Node 20, so the web
   tests crashed in under a second. Fixed by moving CI to Node 22 and declaring `engines`.

**CI is now green end to end** — run
[32104995687](https://github.com/Y1X0/CYBER/actions/runs/32104995687) on `db7b288`: lint, migrate,
seed, 2051 Python tests, web typecheck/test/build, the tool licence gate, the self-SBOM and
pip-audit. The last four steps had never executed on this branch before.

---

## Track A — Execution platform

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| A1 | Worker fleet — artifact plane | `BLOCKED_EXTERNAL` | `9017610` | — | Image builds and pushes; provisioning is refused by the platform. A worker started against the production broker and reached `ready.` in run 32621666688 (23 Aug 2026), so the code path is live-verified and what is missing is a host, not a fix. Partially mitigated by `.github/workflows/guardian-burst-worker.yml`, an operator-triggered one-shot drain of the `default` queue. It is not scheduled and must not be: nothing consumes the queue unless a human runs it, so the status stays `BLOCKED_EXTERNAL`. See BLOCKER-1. |
| A1b | Worker fleet — network plane | `BLOCKED_EXTERNAL` | — | — | Only `nmap_provider` and `nmap_service_provider` set `external_binary=True` and are forced onto `uid_nft`. That plane alone needs `CAP_NET_ADMIN`. |
| A2 | Scanner runtime image | `LIVE_VERIFIED` | `a959396` | 28 (`test_tool_licenses`) + 8 (`test_engine_health`) | Built and pushed: `ghcr.io/y1x0/cyber-scanner@sha256:80037347e22ee4574bc9ebfe5a557cfb0399d178049cf57a0c20be81102e61ac`. Step 8 of run 32039299600 executed each tool inside the image; licence gate passed first. Release asset URLs are resolved from the GitHub API on the runner, not written from memory. |
| A3 | Scheduler + notifications | `TESTED` | `96b73a6` | 10 (`test_scheduling`) | `schedules` table + migration `0012`, RLS live-verified (`rls_enabled=true`, `policy=tenant_isolation roles=guardian_app`). Sweep claims the slot before dispatch; a six-hour outage produces one run, not six. Beat entries `sweep-schedules` (300s) and `sync-vulnerability-feeds` (86400s). Cannot reach `DEPLOYED` while A1 is blocked — beat needs a worker. |
| A4 | Tool execution API | `NOT_STARTED` | — | — | |

## Track B — Discovery

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| B1 | Live passive discovery | `LIVE_VERIFIED` (DNS) / `IMPLEMENTED` (CT) | `eb40a5c` | 39 new (`test_dns_source_unit`, `test_ct_source_unit`) | DNS resolved `example.com` → `104.20.23.154`, `2606:4700:10::ac42:93f3`; wildcard probe returned `present=False`; nonexistent name → `unresolved=True, takeover=False`. CT egress denied by this environment's gateway (403 on CONNECT) — code path exercised, live fetch `BLOCKED_EXTERNAL`. |
| B2 | Active port/service discovery | `TESTED` | `aa1c13a` | 41 (`test_port_discovery`) | Concurrent TCP connect sweep over a 60-port reviewed catalogue (was: ports 80 and 443 only, because those were the two a probe registered). Banner + read-only identification probes yield product, version and **CPE** — the key WP-C3 looks a CVE up by. No privileges needed, so it runs in the artifact plane. Live-verified against real loopback listeners over real sockets: open vs closed vs filtered, concurrency, rate limit, deadline truncation. Public-address guard refuses a target resolving to a private/metadata address, including a mixed rebinding answer. |
| B3 | HTTP probing / tech fingerprinting | `TESTED` | `7050e28` | 40 (`test_web_fingerprint`) | 48 technology signatures across servers, languages, frameworks, CMS, CDN, WAF and client-side libraries, graded by evidence strength (header > cookie > HTML marker) and emitting CPEs. HTTP probe records status, title, redirect chain, TLS posture, security headers and cookie flags. Redirects are followed manually and one that leaves the authorized host is recorded, not followed. Live-verified against a real HTTP server over real sockets, including the off-site redirect refusal. |
| B4 | Cloud asset discovery | `NOT_STARTED` | — | — | |
| B5 | Continuous discovery + drift | `NOT_STARTED` | — | — | Depends on A3. |

## Track C — Vulnerability intelligence

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| C1 | Feed ingestion pipeline | `TESTED` | `e04c09f` | 49 (`test_feed_clients`, `integration/test_feed_ingestion`) | The KB was empty and nothing filled it — the old sync only *enriched* rows that did not exist, and reported `completed`. Now: NVD (with **CPE applicability**, the field that makes a service version matchable), OSV bulk per ecosystem, KEV records, EPSS bulk CSV. Migration `0013` adds `feed_state` watermarks + `cpe_configurations` + a GIN index, verified live. Failures raise, are recorded as failures, and **never advance the watermark**. |
| C2 | Version range matching | `TESTED` | `cb47daa` | 56 (`test_versioning`) | Replaces exact-string matching. Verified against SemVer §11, PEP 440, Debian policy and rpmvercmp published orderings, and end-to-end on a Debian backport where only the release field separates patched from vulnerable. |
| C3 | Service version → CVE | `TESTED` | `7be0e32` | 28 (`test_cpe_match`, `integration/test_service_cve`) | Joins WP-B2/B3 fingerprints to WP-C1's CPE applicability: the only path by which a host with no repository gets a vulnerability finding. Version bounds evaluated with a real comparator (lexically `"10.0" < "9.0"`, which would clear a vulnerable host). Refuses to fire without a product and without a release. Findings carry the whole chain — banner, fingerprint, advisory row — are idempotent across re-runs, and belong to a recorded scan. |
| C4 | Exploit intelligence | `TESTED` | `4f8c689` | 27 (`test_exploit_intelligence`, `integration/test_feed_ingestion`) | Exploit-DB index + Metasploit module metadata → CVSS temporal maturity (`high`/`functional`/`poc`/`unproven`), plus CISA ransomware linkage. **Only the existence of exploit code is stored, never the code.** Migration `0014` verified live. Fixed a real scoring defect found here: the additive model saturated at 100 for an ordinary public finding, so a weaponized critical scored identically to a theoretical one — signals now scale into the band's headroom. |

## Track D — Scanning engines

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| D1 | Nuclei | `LIVE_VERIFIED` | `55bed4a` | 65 (`test_template_loader`, `test_template_runner`, `test_web_checks_provider_unit`) | Nuclei's **template format** is executed natively — no binary, so it stays in the artifact plane and off `uid_nft`. `templates/loader.py` denies by default (http+GET/HEAD only; no DSL, payloads, raw, redirects, or OOB callbacks); 17 templates ship. Verified over a real socket against a local HTTP fixture: 8 exposures detected, a present-but-harmless `/phpinfo.php` correctly silent, every 404 route silent. Adding a check is now a reviewed YAML file. |
| D2 | Dynamic application security testing | `LIVE_VERIFIED` | `2d8aad1` | 80 (`test_dast_checks`, `test_dast_scanner`, `integration/test_dast_live`, `test_dast_ssrf`) | The engine was a header/cookie/TLS inspector on one response — worth having, not DAST, and unable to find an injection by construction. Now: a bounded in-scope crawler that discovers parameters and GET forms, plus 8 active checks (reflected XSS, SQL injection error- and boolean-based, path traversal, SSTI, OS command injection, open redirect, CORS-with-credentials). Following WP-D1's precedent, no external binary — so no ZAP process, JVM, or privilege footprint, and it stays in the artifact plane. **Every payload is read-only**: no stacked SQL, no DDL, no timing probes (a check whose signal is "the server got slower" is indistinguishable from one that caused an outage), command probes `echo` a marker and nothing else, and the redirect probe targets an RFC 2606 `.invalid` host that cannot resolve. GET only — a POST form is inventoried and never requested at all. State-changing paths (`/logout`, `/delete/…`) are refused before the request. Scope is re-checked in the single function that can open a socket. Live-verified over real TCP against a purpose-built vulnerable fixture: **8/8 planted flaws found, 0 findings on the 4 correct implementations of the same features** — and the scanner caught a genuine `//evil` scheme-relative bypass in the fixture's own "safe" redirect. An unreachable target now **raises** instead of returning an empty result, and a scan stopped by its budget emits an explicit coverage finding. |
| D3 | SCA v2 | `TESTED` | `def7df6` | 30 (`test_sca_lockfiles`) | 9 lockfile formats incl. transitive deps; `OsvVulnMatcher` connects the client that had zero call sites; `CompositeVulnMatcher` merges sources by advisory id; CVSS v3.x base scoring. Live OSV query needs egress (see BLOCKER-4). |
| D4 | SAST v2 | `LIVE_VERIFIED` | `2aadc76` | 54 (`test_sast_taint`, `test_sast_engine`) | AST taint analysis: 11 sink classes, class-specific sanitizers, import-alias resolution, inter-procedural summaries, comment/string masking. Against an 11-route vulnerable fixture: **8/8 planted flaws found, 0 false positives on the 3 safe variants**. Against Guardian's own 26k lines: 40 findings → 4 after fixing the noise the first run exposed, all true positives. |
| D5 | Secrets v2 (git history) | `TESTED` | `1ed0e35` | 8 (`test_secrets_history`) | Scans lines added by past commits against the existing patterns and entropy heuristic; clone fetches history (bounded, blobless at depth 0). Verified on a real repository where the secret was deleted in a later commit: working tree clean, finding still raised, raw value never persisted, one report per credential rather than per commit. |
| D6 | Container / image | `TESTED` | `d355d30` | 31 (`test_container_image`) | Reads a `docker save`/OCI archive in-process — no binary, no daemon, no registry. Detects **a secret deleted in a later layer but still in the image**, the finding a flattened-filesystem scan cannot see; sensitive files and key material by path and by content; config issues (root, ENV secrets, mutable tag, SSH, no healthcheck, `curl \| sh` in history). Packages from dpkg/apk/dist-info/node_modules go through the existing `VulnMatcher` seam rather than a second matcher. An unreadable archive and an unparsed RPM database are reported as findings, not silence. A well-built image produces zero findings. |
| D7 | Kubernetes posture | `LIVE_VERIFIED` | `66ac798` | 46 (`test_k8s_posture`, `integration/test_k8s_engine_repo`) | The engine checked seven pod-spec fields on workload manifests and had **no tests at all**. Everything that decides what a compromised pod can reach was invisible: RBAC roles and bindings (`cluster-admin`, wildcard verbs, `system:unauthenticated`, the default service account), Secrets and ConfigMaps carrying committed credentials, NodePort Services, TLS-less Ingresses, permissive NetworkPolicies. Three real defects fixed: a **Helm chart never parsed** — `{{ .Values.x }}` is not YAML, the loader raised, and the engine returned silently, so a whole chart looked clean (templates are now rendered to a placeholder and analysed); pod-level `securityContext` was ignored, so a correctly-hardened workload was reported three times per container while a **privileged initContainer** was reported not at all; and an unparseable file is now a coverage finding rather than silence. Credential findings carry the key and the length, never the value. Live-verified over this repository's own `infra/k8s/` manifests: **9 objects, 1 true positive** (the ingress policy that accepts from anywhere, as its own comment admits), **0 findings on the 8 correct policies**. |
| D8 | Cloud CSPM | `TESTED` | `3122ebc` | 55 (`test_cloud_posture`, `test_cspm_engine`) | The engine consumed a snapshot schema Guardian invented — `{"storage": [{"public": true}]}` — which nothing produces and in which the only interesting judgement had already been made by whoever wrote the fixture. It now reads the **AWS API's own response shapes** (`Buckets`, `SecurityGroups`, `UserDetailList`, the credential report, `DBInstances`, `trailList`), so a collector is a script that calls read-only APIs and writes the responses down. Real IAM policy evaluation: statements, wildcards, `NotAction` (which grants everything it does not name), explicit Deny beating Allow, and the documented privilege-escalation actions — counted only when the resource is unconstrained, because `iam:PassRole` scoped to one role is how a correct deployment policy is written. S3 publicness is decided from **policy + ACL + public access block**, three sources that routinely disagree. Security groups are evaluated by **port range**: the old rule compared `port == 22`, so `FromPort: 0, ToPort: 65535` — which exposes SSH along with everything else — matched nothing. Plus RDS, CloudTrail multi-region and log validation, and KMS rotation (customer keys only). An unparseable export now **raises** instead of reporting a clean account. The legacy snapshot path is kept working for existing assets. |
| D9 | IaC | `TESTED` | `cbb4b75` | 40 (`test_iac_engine`) | New `iac` engine: a purpose-built HCL2 reader, a CloudFormation loader that keeps `!Ref`-style intrinsics as data (a plain `safe_load` refuses those documents outright), and a Terraform-plan loader. 20 rules across AWS/Azure/GCP — open admin ports graded by service, public buckets, unencrypted/public RDS, IAM wildcards, hardcoded credentials, CloudTrail, EKS. **Silence on the unknown is enforced**: `storage_encrypted = var.encrypt` produces nothing, and the plan loader exists so CI can turn that unknown into an answer. |
| D10 | API security | `LIVE_VERIFIED` | `f02d4ea` | 62 (`test_apisec`, `integration/test_apisec_live`) | The engine reviewed an OpenAPI document and complained about what the document did not say. **Broken object level authorization — the top entry on the OWASP API list — is invisible to that by construction**: `GET /invoices/{id}` reads identically whether the handler checks ownership or not. Now four dynamic checks: BOLA (principal A's credential against principal B's object), BFLA (an unprivileged credential on an administrative operation), missing authentication (the spec requires a credential, the service does not), and excessive data exposure (sensitive fields matched by **name**, values never recorded). The proof standard is a comparison, not a 200: the conclusive BOLA verdict is a body byte-identical to what the object's owner receives, with a control request against a nonexistent id so an API that answers generically for every identifier is not reported on every endpoint. Refusals are recognized however spelled — including an error document served with HTTP 200. **Identifiers are never enumerated**: only the objects the customer named are requested, because walking `id+1` through a production API means reading real people's records. GET/HEAD only, credentials from `secret_config` and never persisted. When fewer than two principals are configured the engine says BOLA was *not tested* rather than reporting the API clean of a class it never looked for. Live-verified over real TCP against a two-tenant API: 4/4 broken endpoints found, **0 findings on the three correctly-authorized twins** that differ by a single ownership or role check. |

## Track E — Correlation & intelligence

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| E1 | Cross-engine correlation | `TESTED` | `fc1adf1` | 36 (`test_correlation`, `integration/test_correlation_persistence`) | Five deterministic rules producing three kinds of group: **duplicate** (one credential seen by three engines is one problem), **corroboration** (a SAST taint path plus a DAST observation of the same CWE), **chain** (a vulnerable dependency that is also answering on a port; an exposed `.git` plus a committed secret). Escalations are recorded in the group's rationale. **No member is ever deleted or hidden** — the evidence trail is the product. Migration `0015`, RLS live-verified on both tables. |
| E2 | Validation & retest | `TESTED` | `0df3bd5` | 15 (`integration/test_verification`) | Four verdicts, not two: `resolved` only when the engine **completed cleanly**; `not_checked` when it failed or never ran; `inconclusive` when it ran degraded. Every check is recorded with its rationale, so "resolved on the 3rd, back on the 10th" survives. A returning finding reopens the original with a `reopened_count` rather than filing a new one. Human decisions (accepted risk, false positive) are never overturned by a scanner. Wired into `run_scan`; migration `0016`, RLS live-verified. |
| E3 | AI analyst v2 | `TESTED` (guardrails) / `BLOCKED_EXTERNAL` (live model) | `c46ac2b` | 33 (`test_ai_guard`, `integration/test_ai_analysis_guard`) | The analyst already refused to take severity from the model and filtered references to the ones the finding carries. Three gaps that only matter once a **real** provider is configured are now closed. **Outbound:** findings were sent verbatim to a third party's API — `evidence` and `location` included — so a credential an engine did not redact at write time left the platform; WP-F2's scrubber now runs before the request, and it is proved on the real path that the key never reaches the prompt. **Delimiter:** `<scan_data>…</scan_data>` is a convention the content can close, and scanned content is written by the customer's attacker — the closing tag and known instruction shapes are neutralized inside the data and counted. **Inbound:** operational exploit content (shell commands with arguments, reverse shells, SQL and script payloads, Metasploit modules) is removed from the explanatory fields — but deliberately **not** from `remediation`, which is supposed to carry commands — and prose that downplays or re-grades a critical finding is recorded as a contradiction rather than silently accepted. Analysis failures are now counted and returned (`failed`/`partial`), because `completed` with `analyzed: 0` reads as "nothing needed explaining". Live model still `BLOCKED_EXTERNAL`: needs `ANTHROPIC_API_KEY` in production; the guardrails are verified against a recording provider that answers the way a badly-behaved model would. |
| E4 | Attack path v2 | `TESTED` | `630c034` | 36 (`test_attack_paths`, `integration/test_attack_chains`) | `attack_paths` answered "can the internet reach a host that has a finding" — a real answer, one hop long. What a defender is afraid of is the part after it: RCE on the public host, then the credential committed in its repository, then the over-permissioned principal that credential belongs to. Chaining needs the thing the platform never modelled — what a finding **grants**. 25 CWE profiles plus category fallbacks map each finding class to the capabilities it requires and confers (`code_execution`, `credential_access`, `data_access`, `privilege_escalation`, `lateral_movement`, `network_access`), and a chain is a sequence where every step's precondition is met by the one before. Two rules keep it from becoming fiction, and both are tested directly: **movement between assets happens only along edges the discovery graph actually has** (with no edge, the chain stops at the asset boundary), and **every hop names the finding it rests on**, so a reader who doubts a step can go read its evidence. A finding class that maps to no capability is never given one — it is counted as unchainable and reported, because "no attack path" and "we could not reason about half your findings" are different statements. Deterministic scoring: likelihood multiplies across steps (every link has to hold), impact is the worst capability held, raised by the terminal asset's criticality, and a shorter route to the same capability outranks a longer one. `GET /api/v1/graph/attack-chains`, staff-only, tenant-scoped, verified against the live database. |

## Track F — Product surface

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| F1 | Onboarding + assets — domain ownership verification | `TESTED` | `f77368b` | 57 (`test_ownership`, `integration/test_ownership_flow`) | `Authorization.method` has always had the value `ownership_verified` and nothing verified ownership — a human asserted it and the platform believed them. Now a customer is issued a per-verification high-entropy token, publishes it as a DNS TXT record or a `/.well-known/` file, and the worker goes and reads it; only then is the `Authorization` created, scoped to that domain and its subdomains and expiring with the proof. **A redirect never verifies** (it proves the redirect target's owner published something), a record that merely *contains* the token never verifies, and a subdomain proof never claims the apex. The active-discovery gate now honours `ownership_verified` alongside `active_recon` — before this, a machine-checked proof cleared nothing while a checkbox cleared everything — and `written_consent` still clears no network target. Revoking the proof revokes the permission and the gate denies from that moment. Migration `0017`, RLS live-verified on `domain_verifications` (`rowsecurity = t`, `tenant_isolation`). |
| F2 | Findings workbench | `TESTED` | `7a41b62` | 82 (`test_workbench`, `test_redaction`, `integration/test_workbench_api`) | Ordering and paging moved into SQL: the list took up to 1000 rows in **unspecified order** and sorted that page in Python, so a customer with more findings than that was shown a "worst first" list whose criticals the database had already discarded. Keyset pagination on the full sort key `(severity, risk, created_at, id)` — proved to walk every finding exactly once and to stay stable while a scan writes rows mid-scroll. Fourteen filters incl. engine, CVE, exploitability and free text (`%` searched literally, not as a pattern); an unrecognized filter value is **refused, not dropped**, because dropping widens the query the caller asked to narrow. A dossier endpoint returns the whole chain — asset, scan, engine, risk rationale, exploit intel, correlation group with its other members, verification history, triage timeline. Bulk triage records one event and one audit row per finding, keeps the justification requirement, and **names every id it could not apply** instead of silently skipping. New `guardian_core.redaction` scrubs credential shapes at the boundary and logs each hit, so an engine that persisted one stays findable; digests, CPEs, versions and paths are deliberately left readable. |
| F3 | Attack graph UI | `TESTED` | `a746879` | 7 (`apps/web/src/AttackGraph.test.tsx`) | The console now renders WP-E4's chains: each hop with the finding it rests on, its CWE and reliability, the deterministic score/likelihood/impact, and a plain-language statement of what the attacker ends up able to do. Three properties are load-bearing because this is the one screen where a presentation mistake is a security problem — a customer who reads "no attack paths" walks away believing something. **A failed request never renders as an empty graph** (it renders an alert saying so, and explicitly that it is not a statement that there are none); **an empty result is qualified** with the count of findings the analysis could not reason about; and **a truncated result says so** rather than presenting itself as complete. Each has its own test. The web suite now runs in CI (typecheck, vitest, production build) — it was previously untested and unbuilt by any pipeline. |
| F4 | Reports + compliance | `TESTED` | `b7d8d5a` | 44 (`test_compliance`, `integration/test_compliance_report`, `apps/web/src/Compliance.test.tsx`) | Findings mapped to SOC 2, ISO/IEC 27001:2022 and PCI DSS v4.0 controls — with **three statuses, not two**. A control with no findings is `passing` only if an engine that can assess it actually completed; otherwise it is `not_assessed`. That distinction is the package: reporting an unexamined control as passing manufactures an assurance nobody earned, and it is the difference between a compliance feature and a compliance liability. A failed engine run assesses nothing (verified). Coverage percentage is printed beside every count, because a 100% pass rate over 20% coverage is the number that misleads an auditor. Mappings are deterministic (CWE → rule → category) and auditable; an accepted risk still fails its control, because accepting a risk is a decision about fixing it, not evidence the control works. Wired into report generation (a `compliance` section plus the full assessment in `report.summary`) and the exported HTML, and surfaced at `GET /api/v1/compliance`. **Report evidence is now scrubbed through WP-F2's redactor** — the report is emailed, attached to board packs and forwarded to prospects, so it is the worst place for the one credential an engine missed, and the copy nobody can recall. |
| F5 | Remediation workflow | `TESTED` | `d54024b` | 44 (`test_remediation`, `integration/test_remediation_flow`) | `remediation_items` had been a table with **no code behind it** since the first schema. The loop is now closed: finding → an owner and a deterministic due date (severity window, halved for an internet-facing asset) → a claimed fix → **a rescan that proves it** → verified. The design rule is that `verified` is not a status anybody can set — the API refuses it whatever the caller's role, and it is reachable only from `verify_after_scan`, which reads WP-E2's verification records: the engine that found the issue ran again, completed cleanly, and did not report it. A `not_checked` or `inconclusive` verification closes nothing, because an engine that failed proves nothing; a claimed fix the scanner still sees is **reopened**. One item per underlying issue via WP-E1's correlation groups, so three engines finding one credential produce one piece of work rather than three. Declining to fix requires a justification; accepting a stale backlog cannot improve the on-time rate. `GET /{id}/ticket` renders a Jira/GitHub-ready body with evidence scrubbed — Guardian holds no ticketing credential, which is the right side of that trade. Wired into `run_scan` after reconciliation. |

## Track G — Enterprise

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| G1 | API keys + SSO | `TESTED` (keys) / `TESTED` (SSO verification), live IdP `BLOCKED_EXTERNAL` | `a5974f8` | 64 (`test_apikeys`, `test_sso`, `integration/test_apikey_auth`) | `api_keys` had been a table with **no issuance and no authentication path** — the only credential that ever worked was a person's password, so a CI pipeline had no way in. Keys now work end to end: `gdn_<id>_<secret>` (a distinctive prefix a secret scanner can be taught, and an embedded id so authentication is one indexed lookup rather than a table scan), stored as an **HMAC digest under a server-side pepper** so a stolen database is not enough to check a guess offline, compared in constant time, returned exactly once. Scopes are least-privilege with no implicit hierarchy: a key with none can do nothing, `findings:write` does not confer `findings:read`, and **`assets:write` is deliberately absent from the CI preset** so a leaked build key cannot point the scanner at a target nobody authorized. A key cannot mint another key and cannot use any endpoint requiring a human staff role — opting an endpoint in is an explicit act, so everything written before keys existed stays closed to them. Revocation and expiry take effect on the next request; `last_used_at` is recorded. SSO: OIDC id-token verification tested against **real tokens signed with real keys**, refusing the attacks that actually break OIDC — a token signed with the attacker's key, `alg: none`, an HS256 token whose "secret" is the provider's published public key (hand-assembled, since PyJWT refuses to sign that), a valid token for another audience, one from another issuer, and an unverified email. Provisioning only from a domain the tenant declared, and an IdP group can never mint an owner or admin. A live IdP round trip is `BLOCKED_EXTERNAL` — none is available here. |
| G1b | API keys under RLS + a database that can be built from nothing | `TESTED` | `7a713b7` | 8 (`integration/test_migrations`) + the 15 in `integration/test_apikey_auth`, which now run RLS-enforced | Two defects that both hid in the same blind spot — everything was tested against a database that already existed, under a role RLS does not apply to. **(1) API-key authentication was dead in production.** The key lookup was a plain `SELECT ... FROM api_keys`, but a key's tenant is a property of the key, so nothing can be bound before it is read: under `guardian_app` the query returns no row and a perfectly valid key is refused as `401 invalid API key`. The JWT path had solved this in migration 0006 with `SECURITY DEFINER` functions; the key path had not. Migration `0019` adds `auth_api_key(uuid)` on the same narrow terms — one id the caller already presented, only the columns authentication needs, `EXECUTE` revoked from PUBLIC — and the constant-time digest comparison still decides. Two further bugs fell out of fixing it: the `last_used_at` write happened before any tenant was bound (so it too would have been refused by RLS), and `set_config(..., is_local => true)` is transaction-local, so the commit that saves it drops the binding — every query the request went on to make would have seen an empty database. **(2) `alembic upgrade head` could not build a database from nothing.** `0001_baseline` creates the schema from `Base.metadata`, so on an empty database it also creates tables whose migrations come later; `0012` then died on `relation "schedules" already exists`. Every developer machine and the deployed database had been built incrementally, so it never showed there — it would have appeared for the first time on a disaster-recovery restore or a new environment, and it is why **CI had been red on every commit of this branch**. Migrations `0012`–`0018` are now replay-safe (create the table only if absent; apply indexes, constraints, RLS and grants either way), and the schema drift this exposed is closed: the CHECK constraints that existed only in `0012` and ~40 server defaults that existed only in the migrations are now declared on the models too, so both paths produce byte-identical DDL — verified by diffing an incrementally-built database against one built from zero. The new tests build a throwaway database from nothing on every run and then assert the result matches the models column by column, that every tenant-scoped table carries RLS, and that `guardian_app` holds neither `SUPERUSER` nor `BYPASSRLS`. |
| G2 | Scale hardening | `TESTED` | `5eebc48` | 49 (`test_quota`, `integration/test_scale_limits`) | Every expensive thing in this platform is reachable from one authenticated request, and almost none of it was bounded. **Reads.** `GET /assets` returned the entire inventory — discovery is *designed* to find things, so an estate of 200,000 assets is a success, not an anomaly, and it was being assembled into a single JSON array in memory on every request. `GET /scans`, `/reports` and `/discovery/runs` stopped at a hard `LIMIT 200` with no way to reach row 201 and **no way to tell that they had stopped** — a page exactly `limit` long is indistinguishable from the end of the data. All of them now page by keyset on `(created_at, id)`: keyset rather than `OFFSET` because `OFFSET 10000` makes the database walk ten thousand rows to discard them, and because a row inserted between two requests shifts every later page by one, so a client walking an estate silently *skips* assets — proven here by inserting a row mid-walk. `limit=0` and `limit=-1` are refused rather than clamped: both mean "all of them" to the client that sent them, and answering with a default page is how a script processes fifty of nine thousand rows and reports a clean run. An unreadable cursor is refused rather than restarting from the top, which is the same failure with a longer tail. **Writes.** `POST /scans` accepted as many scans as anyone cared to send, onto a queue every tenant shares — WP-H3 caps concurrency per *asset* in the worker, which stops one host being hammered and does nothing about ten thousand scans of ten thousand assets, so admission control now lives where the work is accepted, counts only work in flight, and refuses with the numbers, a `Retry-After` and an audit row naming the reason. **Rate.** The only limiter in the codebase guarded the login endpoint, which protects the password hash and nothing else. Authenticated traffic is now limited per tenant, with an **API key given its own window inside the tenant's** — otherwise one CI pipeline retrying in a loop locks the console out from exactly the people trying to find out why. Every refusal carries a `Retry-After` of at least one second, because a 429 telling a client to wait zero seconds turns a rate limit into an amplifier. Per-process, like the login limiter, and the multiplication factor across replicas is stated rather than hidden; `guardian_rate_limited_total` and `guardian_scan_admission_refused_total` make it visible. **Quotas** are platform defaults a tenant may override, and an override that cannot be read leaves the default in place and is logged — read as "unlimited" it would be one typo away from removing the limit, and those two directions are not equally survivable. **Queries.** A report summary loaded every finding of a scan to produce eleven numbers (now `GROUP BY` + `ORDER BY … LIMIT 5`); a ticket body loaded a whole correlation group to take its length (now `count()`); and a PDF export rendered every finding there was. Exports are bounded **and say so in the document**, because silently dropping half the findings is worse than refusing to render: the reader cannot otherwise tell "nothing else was found" from "nothing else fitted". One more real defect fixed en route: the webhook retry sweep took `LIMIT 100` with no ordering, so Postgres could hand back the same arbitrary hundred rows forever and a delivery outside that set would never be retried at all. |
| G3 | Outbound webhooks | `TESTED` | `24f8a6f` | 82 (`test_webhooks`, `integration/test_webhook_delivery`) | Guardian could tell a customer something had happened only if they came and looked. A webhook is the platform making an HTTP request to an address a customer typed into a form, carrying their security posture, and both halves of that sentence are the risk. **The destination is attacker-influenced**, so it is refused unless it is `https`, has a host, carries no inline credentials and is not loopback — and the sender independently **pins to a validated public address at connect time** and **never follows a redirect**, because a customer endpoint answering `302 Location: http://169.254.169.254/…` would otherwise have Guardian fetch its own cloud credentials and do it carrying a signature the receiver can prove came from Guardian. **The payload is the customer's posture**, travelling to what is often a shared chat channel, so evidence/excerpt/match/raw/secret/token are dropped outright and what remains passes the WP-F2 boundary scrub — a finding's excerpt is the field most likely to contain the credential the finding is *about*. **The signature covers `timestamp.body`, not the body alone**: an HMAC over the body verifies forever, so a captured delivery replays perfectly a year later; the freshness window makes it expire, and the shipped `verify()` is the same code the sender uses so a customer's implementation cannot drift from it. The secret is returned once and by no endpoint afterwards, and reaches no listing and no audit row. Failure handling refuses to lie: a 4xx is **never** retried (it fails identically every time, and retrying it is how a misconfigured endpoint gets a denial of service from its own vendor) while 408/429/5xx/connection-failure back off 1/5/25 minutes and stop; an endpoint that fails 20 times in a row is disabled **with the reason and the last status recorded**; and every attempt keeps the exact signed bytes, because "the signature did not verify" is otherwise an unresolvable support conversation. Proven over real TCP against a local receiver — signature verified by the receiver with the stored secret, redirect refused rather than followed, the pin refusing loopback with its real cause, tenant isolation enforced by RLS on both tables. |
| G4 | Observability + SLOs | `TESTED` | `4d25083` | 31 (`test_metrics`, `integration/test_observability`) | The API emitted no metrics at all. Now: a dependency-free Prometheus registry (written rather than pulled in — a platform that ships a licence gate and a self-SBOM should not add a dependency for four counters, and the exposition format's escaping and cumulative buckets are exactly what a test can pin down), request/latency/status middleware labelled by the **route template rather than the path** so cardinality cannot grow with the number of findings, and `/metrics` closed unless the scrape token is set and presented — an unset secret never means "no authentication required". The valuable half is `GET /health/slo`: four SLOs about the ways this platform **fails quietly** — feeds that stopped syncing while every scan still reports `completed`, engine runs that failed (a failed engine reports no findings, which looks exactly like a clean scan), scans stuck `running` with nothing errored, and a remediation backlog past its own deadline. Each carries its reasoning, and each reports an explicit **`unknown`** when there is no data to judge from — `unknown` never collapses into `healthy`, because a dashboard that renders "nothing has run" green is how a platform lies quietly for a month. |

## Track H — Trust, safety, legal

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| H1 | Authorization enforcement | `TESTED` | `87d9df4` | 35 (`test_authorization_scope`, `integration/test_scan_authorization`) | Two gates existed and they disagreed. Discovery matched `authorized_targets` by domain/netblock/host; the scan gate matched `asset_id` **and nothing else**. Each was defensible alone, and together they meant a domain a customer had *proved they own* (WP-F1 issues its authorization scoped by target with no asset) cleared a discovery probe and **skipped every active engine on a scan of the same host**. Both gates now ask one evaluator in `guardian_core.authorization`. Its rules: the method decides the plane — `written_consent` covers an artifact the customer handed over and grants nothing on the network, while `active_recon` and `ownership_verified` permit sending packets; an authorization with neither an asset nor targets grants nothing (the safe reading of a half-filled record); expiry and revocation are absolute, so withdrawing an ownership proof actually stops scans; and **every refusal carries a reason naming the host and what would have covered it**, in the engine run and in the audit record — "blocked" with no cause is a support ticket. Verified end to end through `run_scan`. |
| H2 | Licence registry | `LIVE_VERIFIED` | `c5ed0b6` | CI gate | 40 tools registered; gate exits 1 on masscan (AGPL §13), 0 on an approved set. nmap `LEGAL_REVIEW`, masscan/TruffleHog/CodeQL `PROHIBITED`, substitutes named. Wired into CI. |
| H3 | Safe-scanning controls | `TESTED` | `3594fe0` | 25 (`test_safescan`, `integration/test_scan_authorization`) | Authorization decides *whether*; these decide *when*, *how hard*, and *at all* — the questions whose wrong answers turn a consented scan into the customer's incident. **Blackout windows** in the customer's own UTC offset (evaluating them in UTC is being wrong by the size of their timezone every day), including windows that wrap midnight; a scan inside one is **deferred with a retry time, never skipped**, because a skipped engine reads as a clean one. **Concurrency**: one active scan per asset by default — every engine had its own budget and nothing stopped five scans hitting one host, and budgets that only hold individually are not budgets. **Intensity profiles** (`safe`/`standard`/`thorough`) that actually cap the D2 and D10 request budgets, defaulting to the conservative one, with an unrecognized profile name falling back to `safe` rather than to fastest. **A kill switch** per customer and platform-wide, evaluated before everything else and **fail-closed**: an unreadable switch refuses, because a stop button that only works when the rest of the system is healthy is not a stop button. A malformed blackout window refuses rather than disappearing — a window the customer meant to have is not the same as no window. Every hold is audited with its reason and retry time; artifact scans are untouched. |

---

## Blockers

### BLOCKER-1 — Worker host — *scope corrected, previously overstated*

An earlier version of this record claimed the worker host blocked A2, B2, B3, B5 and all of D1–D10.
**That was wrong**, and the correction materially changes what is shippable.

`execute_tool` (`tools/execution.py:29`) forces the `uid_nft` backend only when a provider sets
`external_binary = True`. Exactly two do: `nmap_provider` and `nmap_service_provider`. Every
`ScanEngine` runs through the in-process sandbox instead (`tasks.py:62`), never touching `nft`.

So the planes split, and only one is blocked:

| Plane | Needs | Covers | Status |
|-------|-------|--------|--------|
| **Artifact** | any container host | SAST, SCA, secrets, container images, IaC, K8s manifests, CSPM — the whole code-security product | ready to deploy |
| **Network** | `CAP_NET_ADMIN` + `nft` | nmap today; nuclei, ZAP, naabu when added | blocked |

**Attempted and refused by the platform.** The image is built, pushed and verified; the worker
cannot be created. Run [32039299600](https://github.com/Y1X0/CYBER/actions/runs/32039299600),
step 9, verbatim:

```
  existing    : 0 service(s) matched name='guardian-worker'
##[error]worker provisioning failed: Render API 402 on POST /services:
{"message":"Payment information is required to complete this request.
To add a card, visit https://dashboard.render.com/billing"}
```

Render offers **no free tier for background workers** — `POST /v1/services` with
`type=background_worker` is rejected with `402` before any resource is allocated. The service list
in the same run returned `0 service(s) matched`, so nothing was created and nothing was billed on
any attempt. This is a platform pricing rule, not a defect in our provisioning code, and no amount
of retrying changes it. Retries have stopped.

The workaround that would "unblock" this — running the consumer inside the existing free web
service — is refused deliberately. It would put unbounded scan work on the request-serving process,
so a customer's scan would degrade the API for every other tenant, and Render's free web service
sleeps on idle, which silently stops the queue. Hiding a capacity limitation inside the API tier is
worse than an honest blocker.

**Live-verified on 23 Aug 2026 — the code half of this blocker is closed.** Run
[32621666688](https://github.com/Y1X0/CYBER/actions/runs/32621666688) started a worker against the
real production broker and it came up. From its `worker.log`, verbatim:

```
 -------------- celery@runnervm76f27 v5.6.3 (recovery)
 - ** ---------- .> transport:   ***ohio-keyvalue.render.com:6379//
 - ** ---------- .> results:     ***ohio-keyvalue.render.com:6379/
 -------------- [queues] .> default   exchange=default(direct) key=default
[05:58:11: INFO/MainProcess] Connected to ***ohio-keyvalue.render.com:6379//
[05:58:16: INFO/MainProcess] celery@runnervm76f27 ready.
```

Two things that were previously assumptions are now facts:

* **`celery_redis_url` works against Render Key Value.** Constructing a Redis *result backend* is
  where Celery raises on a `rediss://` URL with no `ssl_cert_reqs`, at construction and before any
  network call — the asymmetry that let the API stay green while every worker died. The banner shows
  a constructed backend and a connected transport, so the normalisation in `0317a86` is verified in
  production rather than only in unit tests. **What remains of BLOCKER-1 is a host, not a defect.**
* **The database is reachable from an arbitrary runner.** The connectivity probe opened `SELECT 1`
  on both DSNs and pinged the broker before the worker started:
  `GUARDIAN_DATABASE_URL` and `GUARDIAN_APP_DATABASE_URL` → `ep-crimson-haze-axj6kfh8-pooler.c-4.us-east-2.aws.neon.tech`,
  `GUARDIAN_REDIS_URL` → `ohio-keyvalue.render.com:6379`. The database is on Neon, not in the Render
  workspace, so its allowlist could not be read from the Render side; the probe settles it — no IP
  allowlist blocks a hosted runner.

The run still ended `failure` and **scored no stages**: its liveness gate was a Celery `inspect ping`
that never answered, so the journey was skipped. `inspect` travels the remote-control channel
(pidbox, a Redis pub/sub fanout), a different path from task delivery — a worker can consume while
remote control is unavailable. The gate was therefore stricter than what it guarded and discarded a
run without measuring what the run existed to measure. It now gates on the worker's own `ready.`
line and reports the ping as a warning. Whether the product completes a scan end to end remains
unmeasured — not failed, unmeasured.

**Interim mitigation — `.github/workflows/guardian-burst-worker.yml`.** The verified scanner image
(A2) is run as a short-lived consumer of the `default` queue, `workflow_dispatch` only, for as long
as the operator asks (default 25 minutes). Nothing is rebuilt: the image is pinned by digest and its
own `CMD` is already the worker command. `timeout --signal=TERM` ends the burst so Celery finishes
the task in flight rather than stranding it, which is what `task_acks_late` assumes. It exists so a
queue can be drained deliberately while a permanent host is chosen.

**It is deliberately not scheduled, and a schedule must never be added.** A `*/30 * * * *` cron was
briefly committed here and removed in the same session. `guardian-golden-run.yml` already states the
rule, and it binds this file too: keeping a queue drained for real customers is a service, a service
does not belong in CI, and the fix is a host, not a cron. Two things made it worse than a style
violation. This repository's default branch is the working branch, and `schedule:` fires from the
default branch — so the cron was live from the moment it was pushed, consuming a production queue
unattended with nobody reading the result. And running a service on Actions is the kind of use its
terms exclude regardless of the repository being public and the minutes free; the exposure is not a
bill but the account being restricted, which would take CI down with it.

Its limits, none of which are incidental:

* **Nothing is consumed unless a human runs it.** There is no latency property here at all — a scan
  sits `queued` until someone triggers a drain. That is honest rather than unfortunate: it keeps the
  gap visible instead of hiding it behind a cron. It cannot carry a scheduled-scan product (A3),
  whose whole value is running when it said it would.
* **It is not a host, and must not be allowed to become one.** It does not touch the network plane
  (A1b), which needs `CAP_NET_ADMIN`; a hosted runner is not that either. It also leaves the
  queue-health signal ambiguous while unrun — depth alone stops distinguishing "no drain has been
  triggered" from "nothing is consuming". Removing this file is part of the definition of done for
  BLOCKER-1.
* **It answers a narrower question than it looks like it does.** A drain reports queue depth before
  and after. Whether the product actually works end to end is what `guardian-golden-run.yml`
  answers, with a pass/fail criterion per stage.

**The pinned image predates the broker-URL fix, and the workflow compensates.** The digest was built
at `a959396` (17 Aug 2026); `celery_redis_url` landed in `0317a86` (21 Aug 2026), so that function
does not exist inside the image. Its `celery_app` hands `settings.redis_url` to the result backend
raw, and Celery raises on a `rediss://` URL carrying no `ssl_cert_reqs` at construction, before any
network call — unpatched, the worker would die at startup and the burst would consume nothing.

The workflow therefore normalises the URL itself, in a dedicated step, to the same contract as the
repository function: only a `rediss://` URL that does not already state `ssl_cert_reqs` is touched,
the parameter is appended as text rather than the query re-encoded, and a URL that already carries
the operator's own choice passes through untouched. The result is `::add-mask::`ed before use, since
it is derived from a secret but no longer equal to it and Actions will not mask it on its own, and
it is handed on through the environment rather than a step output. The queue-depth steps read that
value directly instead of importing from the image. No repository secret needs changing.

This is compensation, not a fix, and it is the second copy of a rule that already exists in the
code. **When the image is rebuilt from a commit containing `celery_redis_url`, delete the
`Normalise the broker URL for the pinned image` step** rather than leaving two copies to drift
apart.

**Operator action:** any container host that will run a long-lived process — a Render paid worker,
a Fly.io Machine, a single VPS, or a laptop running `celery -A guardian_scanner worker`. Nothing in
the artifact plane needs privileges. Separately, a privileged host when the network plane is built.

Everything downstream of the *engines themselves* remains buildable and testable without this host:
engines run in-process and are exercised directly by the test suite. What is blocked is production
execution, not development.

### BLOCKER-2 — CT egress in this build environment (limits B1 live verification only)

This session's network gateway answers `403` to `CONNECT crt.sh:443`. The CT code path is
implemented, unit-tested, and fails closed with a logged reason; live confirmation requires an
environment whose egress policy permits crt.sh. Does not block any dependent package.

### BLOCKER-4 — Outbound egress for feed queries (limits D3/C1 live verification)

The same gateway policy that denies crt.sh also governs OSV, NVD and GHSA. Matchers and parsers are
unit-tested against recorded response shapes; querying the live services needs an environment whose
egress policy permits them. Does not block implementation of any dependent package.

### BLOCKER-3 — AI provider key (blocks E3)

`ANTHROPIC_API_KEY` is not among the production environment variables, so the analyst runs the
deterministic stub. Adding the secret is the entire fix.

---

## Security & deployment debt

Tracked, not blocking, unless marked active risk.

| Item | Severity | Status |
|------|----------|--------|
| `guardian_app` password exposed in a public workflow log | **Active risk** | Not rotated, at operator's explicit direction. Rotation is a single `ALTER ROLE` plus a secret update. |
| `GUARDIAN_SECRETS_PAT` and `GHCR_PULL_TOKEN` still live | Medium | One-shot workflows that used them are deleted; token revocation is account-side. |
| Redis `persistenceMode: off` | Medium | Replay-nonce store loses state on restart. |
| Neon PITR retention window unconfirmed | Low | Restore drill passes daily; retention length is a console read. |
| No custom domain | Low | TLS verified on `*.onrender.com`. |
