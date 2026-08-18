# Guardian Build Status

Machine-readable progress against the Engineering Work Order v1.0. One row per work package.

**States:** `NOT_STARTED` · `IN_PROGRESS` · `IMPLEMENTED` · `TESTED` · `DEPLOYED` · `LIVE_VERIFIED` ·
`BLOCKED_EXTERNAL`

A package is never marked beyond `TESTED` without recorded evidence. `LIVE_VERIFIED` means it ran
against a real system and the output was inspected — not that a test double returned the right shape.

Baseline: commit `8e4338b` · 26,465 lines · 552 tests · 34% code-complete · 0% operable.

**Current: 953 tests passing** (+401), 10 work packages delivered, CI green.

---

## Track A — Execution platform

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| A1 | Worker fleet — artifact plane | `BLOCKED_EXTERNAL` | `9017610` | — | Image builds and pushes; provisioning is refused by the platform. See BLOCKER-1. |
| A1b | Worker fleet — network plane | `BLOCKED_EXTERNAL` | — | — | Only `nmap_provider` and `nmap_service_provider` set `external_binary=True` and are forced onto `uid_nft`. That plane alone needs `CAP_NET_ADMIN`. |
| A2 | Scanner runtime image | `LIVE_VERIFIED` | `a959396` | 28 (`test_tool_licenses`) + 8 (`test_engine_health`) | Built and pushed: `ghcr.io/y1x0/cyber-scanner@sha256:80037347e22ee4574bc9ebfe5a557cfb0399d178049cf57a0c20be81102e61ac`. Step 8 of run 32039299600 executed each tool inside the image; licence gate passed first. Release asset URLs are resolved from the GitHub API on the runner, not written from memory. |
| A3 | Scheduler + notifications | `TESTED` | `96b73a6` | 10 (`test_scheduling`) | `schedules` table + migration `0012`, RLS live-verified (`rls_enabled=true`, `policy=tenant_isolation roles=guardian_app`). Sweep claims the slot before dispatch; a six-hour outage produces one run, not six. Beat entries `sweep-schedules` (300s) and `sync-vulnerability-feeds` (86400s). Cannot reach `DEPLOYED` while A1 is blocked — beat needs a worker. |
| A4 | Tool execution API | `NOT_STARTED` | — | — | |

## Track B — Discovery

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| B1 | Live passive discovery | `LIVE_VERIFIED` (DNS) / `IMPLEMENTED` (CT) | `eb40a5c` | 39 new (`test_dns_source_unit`, `test_ct_source_unit`) | DNS resolved `example.com` → `104.20.23.154`, `2606:4700:10::ac42:93f3`; wildcard probe returned `present=False`; nonexistent name → `unresolved=True, takeover=False`. CT egress denied by this environment's gateway (403 on CONNECT) — code path exercised, live fetch `BLOCKED_EXTERNAL`. |
| B2 | Active port/service discovery | `NOT_STARTED` | — | — | Depends on A1/A2. |
| B3 | HTTP probing / tech fingerprinting | `NOT_STARTED` | — | — | |
| B4 | Cloud asset discovery | `NOT_STARTED` | — | — | |
| B5 | Continuous discovery + drift | `NOT_STARTED` | — | — | Depends on A3. |

## Track C — Vulnerability intelligence

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| C1 | Feed ingestion pipeline | `NOT_STARTED` | — | — | |
| C2 | Version range matching | `TESTED` | `cb47daa` | 56 (`test_versioning`) | Replaces exact-string matching. Verified against SemVer §11, PEP 440, Debian policy and rpmvercmp published orderings, and end-to-end on a Debian backport where only the release field separates patched from vulnerable. |
| C3 | Service version → CVE | `NOT_STARTED` | — | — | |
| C4 | Exploit intelligence | `NOT_STARTED` | — | — | |

## Track D — Scanning engines

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| D1 | Nuclei | `LIVE_VERIFIED` | `55bed4a` | 65 (`test_template_loader`, `test_template_runner`, `test_web_checks_provider_unit`) | Nuclei's **template format** is executed natively — no binary, so it stays in the artifact plane and off `uid_nft`. `templates/loader.py` denies by default (http+GET/HEAD only; no DSL, payloads, raw, redirects, or OOB callbacks); 17 templates ship. Verified over a real socket against a local HTTP fixture: 8 exposures detected, a present-but-harmless `/phpinfo.php` correctly silent, every 404 route silent. Adding a check is now a reviewed YAML file. |
| D2 | ZAP full DAST | `NOT_STARTED` | — | — | |
| D3 | SCA v2 | `TESTED` | `def7df6` | 30 (`test_sca_lockfiles`) | 9 lockfile formats incl. transitive deps; `OsvVulnMatcher` connects the client that had zero call sites; `CompositeVulnMatcher` merges sources by advisory id; CVSS v3.x base scoring. Live OSV query needs egress (see BLOCKER-4). |
| D4 | SAST v2 | `LIVE_VERIFIED` | `2aadc76` | 54 (`test_sast_taint`, `test_sast_engine`) | AST taint analysis: 11 sink classes, class-specific sanitizers, import-alias resolution, inter-procedural summaries, comment/string masking. Against an 11-route vulnerable fixture: **8/8 planted flaws found, 0 false positives on the 3 safe variants**. Against Guardian's own 26k lines: 40 findings → 4 after fixing the noise the first run exposed, all true positives. |
| D5 | Secrets v2 (git history) | `TESTED` | `1ed0e35` | 8 (`test_secrets_history`) | Scans lines added by past commits against the existing patterns and entropy heuristic; clone fetches history (bounded, blobless at depth 0). Verified on a real repository where the secret was deleted in a later commit: working tree clean, finding still raised, raw value never persisted, one report per credential rather than per commit. |
| D6 | Container / image | `TESTED` | `d355d30` | 31 (`test_container_image`) | Reads a `docker save`/OCI archive in-process — no binary, no daemon, no registry. Detects **a secret deleted in a later layer but still in the image**, the finding a flattened-filesystem scan cannot see; sensitive files and key material by path and by content; config issues (root, ENV secrets, mutable tag, SSH, no healthcheck, `curl \| sh` in history). Packages from dpkg/apk/dist-info/node_modules go through the existing `VulnMatcher` seam rather than a second matcher. An unreadable archive and an unparsed RPM database are reported as findings, not silence. A well-built image produces zero findings. |
| D7 | Kubernetes posture | `NOT_STARTED` | — | — | |
| D8 | Cloud CSPM | `NOT_STARTED` | — | — | |
| D9 | IaC | `NOT_STARTED` | — | — | |
| D10 | API security | `NOT_STARTED` | — | — | |

## Track E — Correlation & intelligence

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| E1 | Cross-engine correlation | `NOT_STARTED` | — | — | |
| E2 | Validation & retest | `NOT_STARTED` | — | — | |
| E3 | AI analyst v2 | `BLOCKED_EXTERNAL` | — | — | Needs `ANTHROPIC_API_KEY` in the production environment. Provider selection already implemented (`providers/__init__.py:19`); production currently runs the deterministic stub. |
| E4 | Attack path v2 | `NOT_STARTED` | — | — | |

## Track F — Product surface

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| F1 | Onboarding + assets | `NOT_STARTED` | — | — | |
| F2 | Findings workbench | `NOT_STARTED` | — | — | |
| F3 | Attack graph UI | `NOT_STARTED` | — | — | |
| F4 | Reports + compliance | `NOT_STARTED` | — | — | |
| F5 | Remediation workflow | `NOT_STARTED` | — | — | |

## Track G — Enterprise

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| G1 | API keys + SSO | `NOT_STARTED` | — | — | |
| G2 | Scale hardening | `NOT_STARTED` | — | — | |
| G3 | Outbound webhooks | `NOT_STARTED` | — | — | |
| G4 | Observability + SLOs | `NOT_STARTED` | — | — | |

## Track H — Trust, safety, legal

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| H1 | Authorization enforcement | `NOT_STARTED` | — | — | |
| H2 | Licence registry | `LIVE_VERIFIED` | `c5ed0b6` | CI gate | 40 tools registered; gate exits 1 on masscan (AGPL §13), 0 on an approved set. nmap `LEGAL_REVIEW`, masscan/TruffleHog/CodeQL `PROHIBITED`, substitutes named. Wired into CI. |
| H3 | Safe-scanning controls | `NOT_STARTED` | — | — | |

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
