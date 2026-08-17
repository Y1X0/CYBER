# Guardian Build Status

Machine-readable progress against the Engineering Work Order v1.0. One row per work package.

**States:** `NOT_STARTED` · `IN_PROGRESS` · `IMPLEMENTED` · `TESTED` · `DEPLOYED` · `LIVE_VERIFIED` ·
`BLOCKED_EXTERNAL`

A package is never marked beyond `TESTED` without recorded evidence. `LIVE_VERIFIED` means it ran
against a real system and the output was inspected — not that a test double returned the right shape.

Baseline: commit `8e4338b` · 26,465 lines · 552 tests · 34% code-complete · 0% operable.

---

## Track A — Execution platform

| WP | Title | Status | Commit | Tests | Evidence |
|----|-------|--------|--------|-------|----------|
| A1 | Worker fleet | `BLOCKED_EXTERNAL` | — | — | Needs a host granting `nftables` (CAP_NET_ADMIN) for the `uid_nft` execution backend, plus a paid worker plan. Render background workers have no free tier and cannot grant kernel egress control. See *Blockers*. |
| A2 | Scanner runtime image | `NOT_STARTED` | — | — | Gated on A1's host decision (image target differs for Fly/K8s vs Render). |
| A3 | Scheduler + notifications | `NOT_STARTED` | — | — | |
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
| D1 | Nuclei | `NOT_STARTED` | — | — | |
| D2 | ZAP full DAST | `NOT_STARTED` | — | — | |
| D3 | SCA v2 | `TESTED` | `def7df6` | 30 (`test_sca_lockfiles`) | 9 lockfile formats incl. transitive deps; `OsvVulnMatcher` connects the client that had zero call sites; `CompositeVulnMatcher` merges sources by advisory id; CVSS v3.x base scoring. Live OSV query needs egress (see BLOCKER-4). |
| D4 | SAST v2 | `NOT_STARTED` | — | — | |
| D5 | Secrets v2 (git history) | `NOT_STARTED` | — | — | |
| D6 | Container / image | `NOT_STARTED` | — | — | |
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

### BLOCKER-1 — Worker host (blocks A1, and transitively A2, B2, B3, B5, D1–D10)

The `uid_nft` execution backend confines an external binary's egress with kernel `nftables` rules
and fails closed when `nft` is unavailable — by design, it never runs a binary unconfined. Render's
platform does not grant `CAP_NET_ADMIN`, and its background workers have no free tier.

**Operator action:** choose a worker host. Fly.io Machines, Hetzner with Docker, or managed
Kubernetes all satisfy the requirement. Engines that need no external binary (SAST, secrets, SCA,
CSPM) can run on any host; only the tool plane needs the capability.

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
