# Scanner Capability Matrix

The honest, current inventory of what Guardian can assess, how it does it, and what it deliberately
does **not** do. Every capability runs through the one pipeline — Asset → Scan → Engine → RawFinding
→ `normalize.to_finding` → deterministic risk → Evidence → AI analyst → Report — under tenant RLS.
No engine bypasses it, and nothing here is UI-only.

Status legend:

- **IMPLEMENTED** — runs in the cloud worker today, no special host capability required.
- **STATIC ONLY** — implemented, but analysis is static/offline by design (no runtime/dynamic step).
- **REQUIRES LOCAL AGENT** — the cloud cannot legitimately reach the target; an authorized,
  allowlisted local agent collects posture and Guardian assesses the submission. This is the
  documented, required deployment mode, not a limitation to work around.
- **REQUIRES NETWORK AUTHORIZATION** — active network testing, gated on a verified domain +
  active authorization; skipped (findings INCONCLUSIVE) otherwise.
- **NOT SUPPORTED** — deliberately out of scope under the security model (below).

## By product area

| # | Product area | Asset kind(s) | Engine(s) | Status | Notes |
|---|---|---|---|---|---|
| 1 | Website | `web` | `dast`, `web_checks`, `web_tls` | IMPLEMENTED (passive) + REQUIRES NETWORK AUTHORIZATION (active DAST) | Headers, cookies, CORS, CSP/HSTS, TLS/cert, sensitive-file exposure, nuclei-format template library (30 templates incl. new `security-txt-missing`). |
| 2 | API | `api` | `api`, `web_checks` | IMPLEMENTED + REQUIRES NETWORK AUTHORIZATION (active) | OpenAPI/Swagger ingestion, BOLA/BFLA authorization checks, auth/transport hygiene, **deep spec-security audit** (scheme quality, unreferenced schemes, excessive-exposure by field name, unbounded collections) + **spec-vs-reality probing** (undocumented/shadow endpoints, unenforced authentication) — GET-only, bounded, authorized. See docs/API_DEEP_ANALYSIS.md. |
| 3 | Mobile app (Android) | `mobile_app` | `mobile` | **STATIC ONLY** | APK unzip + binary-AXML manifest decode + DEX string scan. Debuggable, allowBackup, cleartext, exported components, dangerous perms, hardcoded secrets, WebView/TLS-trust/crypto indicators. No emulator, no dynamic instrumentation — documented in docs/MOBILE_SCANNER.md. |
| 3b | Mobile app (iOS) | `ios_app` | `ios` | **STATIC ONLY** | IPA unzip + Info.plist (binary/XML via stdlib plistlib) + provisioning-profile entitlements + Mach-O string scan. ATS weakening, get-task-allow (debuggable), URL schemes, file sharing, privacy usage, hardcoded secrets, deprecated/weak-crypto/TLS-trust indicators; FairPlay encryption detected and reported. No device, no macOS/Xcode, no dynamic — documented in docs/MOBILE_SCANNER.md. |
| 4 | Router / Home network | `network_host` | `host_posture` | **REQUIRES LOCAL AGENT** | Cleartext HTTP mgmt, WAN-exposed mgmt (CRITICAL), UPnP, telnet/ftp on LAN hosts. Assessed from an authorized agent report; never cloud-to-LAN scanning. |
| 5 | Server (Linux) | `server_host` | `host_posture` | **REQUIRES LOCAL AGENT** | SSH root/password/protocol-1, host firewall, EOL OS, insecure services, passwordless sudo, exposed Docker daemon (CRITICAL), privileged containers. Package→CVE reuse of SCA when an inventory is submitted. |
| 6 | Cloud (CSPM) | `cloud` | `cspm` | IMPLEMENTED | Assessed from a collector export (no standing cloud creds in the platform). |
| 7 | Container / K8s | `repo`, `container` | `container`, `k8s`, `iac`, `cicd` | IMPLEMENTED | Image/Dockerfile, manifests, IaC, and GitHub Actions supply-chain (script injection, `pull_request_target`, unpinned actions, `write-all`, curl\|bash, self-hosted+public). |
| 8 | Source code | `repo` | `sast`, `sca`, `secrets`, `ml_model`, `ai_discovery` | IMPLEMENTED + STATIC (ai_discovery is `ai_assisted`) | Taint-based SAST, dependency CVEs, secret detection, ML-model malware (ModelScan), and AI-assisted discovery that verifies each cited line before it is allowed to stand. **SBOM (CycloneDX 1.5)** exported per scan from the SCA inventory — see docs/SBOM.md. |

## By engine

| Engine key | Added this task | Source | Determinism | Network | Authorization |
|---|---|---|---|---|---|
| `secrets`, `sast`, `sca`, `iac`, `k8s`, `container`, `cspm`, `dast`, `api`, `web_checks`, `web_tls` | no (preserved) | automated | deterministic | dast/api active | dast/api require auth |
| `ml_model` | earlier this session | automated | detector-only (health degrades when ModelScan absent → INCONCLUSIVE, never resolves) | no | no |
| `cicd` | earlier this session | automated | deterministic | no | no |
| `ai_discovery` | earlier this session | **ai_assisted** | non-deterministic → always `degraded` (empty ⇒ INCONCLUSIVE); every finding verified against source, unverified capped to low confidence | no (LLM call only) | no |
| `mobile` | earlier this session (Phase 1) | automated | deterministic, static | no | no |
| `ios` | **this task** | automated | deterministic, static | no | no |
| `host_posture` | **this task (Phase 2/3)** | automated | deterministic | no (assesses a submitted report) | **refuses a report that does not assert `authorized: true`** |

## Security model — what Guardian will NOT do (NOT SUPPORTED, by design)

Preserved across every engine added this session:

- No credential stuffing, password cracking/guessing, or brute force.
- No Wi-Fi attacks, deauthentication, or packet injection.
- No denial-of-service or destructive/weaponized exploitation.
- No arbitrary remote shell or command execution; the server never blindly runs user-supplied input.
- No unauthorized or cloud-to-LAN scanning; the local agent is read-only, allowlisted, and must
  assert authorization.
- The Verification Evidence Vault stores only **safe** reproductions (Proof-of-Vulnerability);
  `assess_reproduction_safety` refuses destructive/weaponized payloads even for admin-only use.
- Secret values are redacted before persistence, UI, logs, and any AI request.

## Deployment reality

The cloud worker has no raw sockets, no `CAP_NET_ADMIN`, no LAN route, and no Android emulator.
That is exactly why Mobile is **static only** and Router/Server go through a **local agent**: the
matrix reflects what actually runs, not what a demo could pretend to run.
