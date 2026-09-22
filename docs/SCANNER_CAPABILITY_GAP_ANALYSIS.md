# Scanner capability gap analysis (Phase 0)

> Grounded in the actual repository, not README claims. Each capability is classified as one of:
> **FULLY IMPLEMENTED** · **PARTIALLY IMPLEMENTED** · **ENGINE EXISTS BUT PRODUCT CAPABILITY MISSING**
> · **NOT IMPLEMENTED**. The rule for this work is **add missing capabilities only** — reuse the
> existing finding / risk / evidence / AI / report / authorization / sandbox pipeline; never rebuild
> or duplicate a working engine.

## How the platform is wired (the shared spine every scanner must use)

- **Asset kinds** (`guardian_core.enums.AssetKind`): repo, web, api, cloud_account, container_image,
  k8s_manifest, domain, subdomain, ip_address, netblock, service, cloud_resource. *(No mobile_app,
  no host/server, no local_network — these are the missing product surfaces.)*
- **Engines** (entry point `guardian.scanner_plugins`): secrets, sast, sca, cspm, container, k8s,
  iac, dast, api, ml_model, cicd, ai_discovery. Adding an engine is purely additive (registry is
  entry-point driven; core is never edited).
- **Tool providers** (`guardian.tool_providers`): web_tls, pcap_meta, dns_posture, nmap,
  ct_surface, nmap_service, web_checks. Governed by capability level L0–L5 + authorization + the
  `uid_nft` sandbox for active/binary tools.
- **Finding spine**: `RawFinding` → `normalize.to_finding` → `Finding` (severity from the
  deterministic risk engine, `guardian_core.scoring`), `Evidence`, redaction at persistence + egress,
  AI analyst (`guardian_ai`), reporting, audit log, RLS tenant isolation.
- **Execution safety**: `_run_engine` runs untrusted-input engines in the resource-limited,
  egress-restricted sandbox; active engines require an authorization record (`ACTIVE_ENGINES`).

Everything added below flows through this spine. No new finding model, no second reporting system.

---

## PRODUCT AREA 1 — Website Scanner — **FULLY / PARTIALLY IMPLEMENTED**

**Existing implementation.** `engines/dast_engine.py` + `dast/` (in-proc HTTP checks), the
`web_checks` provider (`templates/library/*.yaml`, validated nuclei-format), and the `web_tls`
provider.

Coverage confirmed in-repo (grep): security headers (`missing-security-headers.yaml`), cookie
attributes Secure/HttpOnly/SameSite (`insecure-cookie-attributes.yaml` + dast engine), CORS incl.
wildcard-with-credentials (`cors-wildcard-with-credentials.yaml`), clickjacking/X-Frame,
X-Content-Type, Referrer-Policy, HSTS, HTTP→HTTPS redirect, server/version disclosure
(`server-version-disclosure.yaml`), certificate expiry / hostname / chain (`web_tls`), sensitive-file
& info disclosure (`.git`/`.env`/backup/`.DS_Store`/`.svn`/`phpinfo`/`swagger-ui`/directory-listing),
exposed admin/observability consoles (jenkins, spring-actuator, prometheus, elasticsearch, db admin).

**API/UI entry point.** Asset kind `web`; DAST engine + web_checks/web_tls providers; console
Scans/Findings screens.

**What is missing (small, additive only).** `security.txt` presence (RFC 9116), `Cache-Control`/
`Pragma` on sensitive responses, `Permissions-Policy` presence, explicit mixed-content indicator.
Reusable: **yes** — add as `web_checks` templates or dast-engine checks. **Recommended change:** add
2–4 templates; do **not** touch the engine core.

**Verdict: FULLY IMPLEMENTED** for the headline capabilities; a few low-value additive checks remain.

---

## PRODUCT AREA 2 — API Scanner — **FULLY IMPLEMENTED**

**Existing implementation.** `engines/api_engine.py` + `apisec/{spec,checks,scanner}.py`. Grep
confirms: OpenAPI/Swagger import + schema handling (`spec.py`), BOLA (object-level authz), BFLA
(function-level authz), excessive-data-exposure, HTTP method review, rate-limit indicators, security
schemes. Findings flow through the canonical pipeline; active probing is authorization-gated and
rate-limited.

**What is missing.** Marginal: JWT `alg`/config deep-analysis and mass-assignment indicators may be
partial. Reusable: **yes**. **Recommended change:** add checks inside `apisec/checks.py` only if a
concrete gap is confirmed; otherwise leave intact.

**Verdict: FULLY IMPLEMENTED.** Do not rebuild.

---

## PRODUCT AREA 3 — Mobile App Security — **NOT IMPLEMENTED**

**Existing implementation.** None for Android/iOS. The only `apk` references in-repo are the Alpine
Linux `apk` package manager (`images/packages.py`), unrelated to Android `.apk`. No `AssetKind` for
a mobile app, no manifest/DEX parsing, no mobile engine.

**What is missing.** The entire product area: APK ingestion + static analysis (manifest, permissions,
exported components, cleartext/network-security-config, WebView indicators, secrets, crypto misuse,
storage/logging indicators, dependency/SDK inventory).

**Reusable pieces.** Secrets detection/redaction (`guardian_core.redaction`), the SCA/vuln-intel
matcher for library CVEs, and the whole finding/risk/evidence/AI/report spine.

**Recommended change (this task, Phase 1).** New `AssetKind.MOBILE_APP` + new `EngineKey.MOBILE` +
`engines/mobile_engine.py` doing **static** APK analysis (APK = zip; a compact binary-AXML decoder
for `AndroidManifest.xml`; string extraction from DEX/resources for secrets; signing-cert metadata;
network-security-config parsing). Reuse `RawFinding`/redaction; register via entry point; asset config
carries the uploaded APK (base64/inline or workspace path). **Static only** — dynamic Android
instrumentation needs an emulator/host capability the cloud container lacks; documented, not faked.

**Verdict: NOT IMPLEMENTED → build static APK analysis now.**

---

## PRODUCT AREA 4 — Router / Home Network — **ENGINE EXISTS (active recon) BUT PRODUCT CAPABILITY MISSING**

**Existing implementation.** Active network recon exists as *providers*: `nmap`, `nmap_service`
(TCP-connect discovery, L2, authorization-gated, sandboxed) and the discovery pipeline
(`discovery/`), which already models `service` graph nodes (open ports) — now surfaced in the console
("Exposed services"). But this scans **reachable/remote** targets; **a cloud server cannot reach a
user's private LAN**, and there is no local-agent model.

**What is missing.** The authorized **local-agent** architecture: an agent runs inside the home
network, performs only allowlisted, non-destructive collection (interfaces, gateway, discovered
hosts, open ports, router identification, insecure-service indicators), and submits an inventory the
platform assesses. No Wi-Fi cracking / deauth / injection — ever.

**Recommended change (Phase 2).** A **local-agent ingestion seam**: a new asset kind + a
posture-assessment engine that consumes agent-submitted allowlisted JSON (no cloud-LAN scanning),
producing findings via the normal pipeline, plus a reference collector and documented deployment
requirement. The active-scan *logic* (service/port risk) is reused; only the *collection location*
moves to the agent.

**Verdict: PRODUCT CAPABILITY MISSING → build the agent ingestion seam + posture engine; document
the agent as the required deployment mode.**

---

## PRODUCT AREA 5 — Server Security — **NOT IMPLEMENTED (as host posture) / partially reusable**

**Existing implementation.** None for authenticated host posture (OS/SSH/users/packages/services).
Package parsing exists for *container images* (`images/packages.py` dpkg/apk) and can be reused for a
package inventory; the SCA/vuln-intel matcher can match host packages to CVEs.

**What is missing.** Authorized server assessment via a local agent / secure connector: OS + kernel +
patch state, listening ports/services, firewall status, SSH config posture (root login, password
auth, key auth), privileged users/sudo indicators, package inventory + CVEs, risky services, host
Docker exposure, hardening checks. **No password attacks, no arbitrary command execution** — an
allowlisted collector submits posture, the platform assesses it.

**Recommended change (Phase 3).** Same agent-ingestion seam as Product Area 4, with a **host-posture
engine** that consumes agent-submitted allowlisted posture JSON and emits findings (SSH config, OS
patch state via package CVEs reusing SCA intel, exposed services, hardening). Static/collector-based;
documented deployment requirement.

**Verdict: NOT IMPLEMENTED → build host-posture engine over the agent seam.**

---

## PRODUCT AREA 6 — Cloud Scanner (CSPM) — **FULLY IMPLEMENTED**

**Existing implementation.** `engines/cspm_engine.py` + `cloud/` providers for AWS/Azure/GCP.
Authorization-gated (`ACTIVE_ENGINES` includes CSPM), offline snapshots supported for tests. Covers
IAM, public storage (s3-public-*), network exposure / security groups (sg-*), unencrypted
data-at-rest (s3/rds-unencrypted, kms rotation), logging (cloudtrail-*), MFA/root posture (iam-*).
The compliance module already maps these to SOC2/ISO/PCI/NIST/CIS controls.

**What is missing.** Only breadth of individual checks (per-service). Reusable: **yes** — add rules
inside the existing `cloud/` providers. **Recommended change:** none required for completeness; add
specific rules only when a concrete high-value check is confirmed missing.

**Verdict: FULLY IMPLEMENTED.** Do not rebuild.

---

## PRODUCT AREA 7 — Docker / Kubernetes / Container — **FULLY IMPLEMENTED**

**Existing implementation.** `engines/container_engine.py` (image layers, dpkg/apk package CVEs,
Dockerfile hygiene) + `engines/k8s_engine.py` (manifest review: privileged, hostNetwork/PID/IPC,
capabilities, securityContext, RBAC wildcard/cluster-admin, host mounts, service exposure) +
`engines/iac_engine.py` (with checkov). The compliance module credits these controls.

**What is missing.** Marginal per-check breadth. The PSS-restricted / zero-trust batch has since
landed (seccomp, AppArmor-unconfined, capabilities `drop: ["ALL"]`, digest-pinning, and the first
cross-resource rule — `netpol-missing`, a namespace whose workloads are selected by no
NetworkPolicy); see [docs/K8S_SCANNER.md](K8S_SCANNER.md). Still open: RBAC binding→role reach
(bindings graded in isolation, not by the verbs the referenced role grants). Reusable: **yes**.

**Verdict: FULLY IMPLEMENTED.** Do not rebuild.

---

## PRODUCT AREA 8 — Source Code — **FULLY IMPLEMENTED**

**Existing implementation.** `engines/sast_engine.py` (taint + pattern rules + optional semgrep; the
Python taint engine now also covers log injection (CWE-117), NoSQL injection (CWE-943) and LDAP
injection (CWE-90) — see [docs/SAST_TAINT.md](SAST_TAINT.md)),
`engines/sca_engine.py` (built-in lockfile parser + optional osv-scanner + vuln intel),
`engines/secrets_engine.py` (patterns + entropy + git history + optional gitleaks), plus
`ai_discovery` (LLM-found leads, verified + labelled ai_assisted) and `cicd`/`iac`/`ml_model`.

**What is missing.** First-class **SBOM generation** as an output is thin (syft is fetched but not a
product feature); code-to-dependency correlation could be richer. **Supply-chain signals beyond
known-CVE have since landed**: malicious-package (`MAL-`) findings routed through the existing OSV
feed seam as CONFIRMED, and typosquat indicators over direct dependencies as POTENTIAL (bundled,
versioned popular lists; no registry calls at scan time) — see
[docs/SCA_SUPPLY_CHAIN.md](SCA_SUPPLY_CHAIN.md). Still open: reachability, and more ecosystems for the
typosquat list. Reusable: **yes**.

**Verdict: FULLY IMPLEMENTED.** Do not rebuild.

---

## Summary matrix

| Product area | Status | Action this task |
|---|---|---|
| 1. Website | FULLY IMPLEMENTED | preserve; optional tiny additive checks |
| 2. API | FULLY IMPLEMENTED | preserve |
| 3. **Mobile App** | **NOT IMPLEMENTED** | **build static APK engine (Phase 1)** |
| 4. **Router / Home Network** | PRODUCT CAP MISSING | **agent ingestion seam + network-posture engine (Phase 2)** |
| 5. **Server** | **NOT IMPLEMENTED** | **host-posture engine over the agent seam (Phase 3)** |
| 6. Cloud (CSPM) | FULLY IMPLEMENTED | preserve |
| 7. Container / K8s | FULLY IMPLEMENTED | preserve |
| 8. Source Code | FULLY IMPLEMENTED | preserve |

**Net:** three genuine gaps — Mobile (static, buildable now), and the local-agent model for
Home-Network and Server (build the ingestion seam + posture engines; the agent itself is the
documented deployment requirement, never fake cloud-LAN scanning). Everything else is preserved and
reused.
