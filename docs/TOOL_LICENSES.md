# Tool licence registry

Every third-party binary Guardian ships or invokes, with its licence and whether it may be used in
a commercial product. **A tool that is not listed and approved here must not enter a runtime image.**
`tools/check_tool_licenses.py` enforces that in CI.

This is not paperwork. A licence violation discovered during due diligence can end an acquisition,
and two of the most obvious tools in this category — nmap and masscan — are exactly the ones that
cannot simply be bundled.

## Approval states

| State | Meaning |
|-------|---------|
| `APPROVED` | Permissive licence; ship freely, with attribution. |
| `APPROVED_SEPARATE_PROCESS` | Copyleft, but invoked as a separate process with no linking and no distribution of modified source. Commonly accepted; confirmed by counsel per deployment model. |
| `LEGAL_REVIEW` | Cannot ship until counsel signs off. Blocked in CI. |
| `PROHIBITED` | Incompatible with a commercial SaaS product. Never ship. |

## Registry

| Tool | Version | Licence | State | Notes |
|------|---------|---------|-------|-------|
| **Base runtime** | | | | |
| git | 2.39+ | GPL-2.0 | `APPROVED_SEPARATE_PROCESS` | Invoked as a subprocess to clone assets; never linked. |
| curl | 8.x | curl (MIT-like) | `APPROVED` | Build stage only. |
| ca-certificates | — | MPL-2.0 | `APPROVED` | Trust anchors. |
| tar | 1.35+ | GPL-3.0 | `APPROVED_SEPARATE_PROCESS` | Build stage only; extracts release archives. |
| pip | 24.x | MIT | `APPROVED` | Build stage only. |
| setuptools | 78+ | MIT | `APPROVED` | Build stage only. |
| **Discovery** | | | | |
| subfinder | 2.6.x | MIT | `APPROVED` | Passive subdomain enumeration. |
| dnsx | 1.2.x | MIT | `APPROVED` | Bulk DNS resolution. |
| httpx | 1.6.x | MIT | `APPROVED` | HTTP probing and fingerprinting. |
| katana | 1.1.x | MIT | `APPROVED` | Crawler. |
| amass | 4.2.x | Apache-2.0 | `APPROVED` | OWASP; deep enumeration. |
| dnspython | 2.8.x | ISC | `APPROVED` | In use — live DNS resolution (WP-B1). |
| **Network** | | | | |
| naabu | 2.3.x | MIT | `APPROVED` | Port discovery. **Preferred over nmap** for the discovery stage precisely because it carries no licence encumbrance. |
| fingerprintx | 1.1.x | MIT | `APPROVED` | Service fingerprinting without nmap. |
| nmap | 7.9x | NPSL | `LEGAL_REVIEW` | The Nmap Public Source License restricts redistribution in commercial products. A commercial OEM licence from Nmap Software LLC is required before shipping. Guardian's wrapper already exists; the binary must not enter an image until this clears. |
| masscan | 1.3.x | AGPL-3.0 | `PROHIBITED` | AGPL §13 covers network interaction, which is what a SaaS product is. Use ZMap instead. |
| ZMap | 4.x | Apache-2.0 | `APPROVED` | Permissive substitute for masscan. |
| **Web / API** | | | | |
| nuclei | 3.x | MIT | `APPROVED` | **Format adopted; binary not shipped.** WP-D1 reads the nuclei template format natively (`guardian_scanner/templates`) rather than shipping the binary. MIT permits either; the format was chosen because Guardian's own validator then decides what a template may do, and because an in-process check stays off the privileged `uid_nft` execution backend. |
| nuclei-templates | — | MIT | `APPROVED` | **Per-template review.** Adopted one reviewed template at a time into `templates/library`, never fetched at scan time. MIT requires the notice to travel with any template text we copy. |
| interactsh | 1.2.x | MIT | `NOT_ADOPTED` | Out-of-band detection. Licence is fine; the capability is not adopted — the template validator refuses any template referencing it, because an OOB callback sends customer data to a third host. Revisit only with a self-hosted server and an explicit customer agreement. |
| OWASP ZAP | 2.15.x | Apache-2.0 | `APPROVED` | Full DAST. |
| ffuf | 2.1.x | MIT | `APPROVED` | Content discovery. |
| dalfox | 2.9.x | MIT | `APPROVED` | XSS. |
| Schemathesis | 3.x | MIT | `APPROVED` | API property testing. |
| sqlmap | 1.8.x | GPL-2.0 | `APPROVED_SEPARATE_PROCESS` | Invoked as a subprocess, never linked. |
| Nikto | 2.5.x | GPL-2.0 | `APPROVED_SEPARATE_PROCESS` | Largely superseded by nuclei. |
| **Code / dependencies** | | | | |
| semgrep | 1.101.0 | LGPL-2.1 | `APPROVED_SEPARATE_PROCESS` | Engine is LGPL; the registry rules have their own terms. Review ruleset licensing separately from the binary. |
| opengrep | 1.x | LGPL-2.1 | `APPROVED_SEPARATE_PROCESS` | Community fork created after Semgrep's licence change. Evaluate as the primary. |
| CodeQL | 2.x | Proprietary | `PROHIBITED` | Free only for open-source projects. Commercial use requires a GitHub licence. |
| osv-scanner | 1.9.2 | Apache-2.0 | `APPROVED` | |
| trivy | 0.58.1 | Apache-2.0 | `APPROVED` | Images, OS packages, IaC, secrets, SBOM in one binary. |
| syft | 1.19.0 | Apache-2.0 | `APPROVED` | SBOM generation. |
| grype | 0.87.0 | Apache-2.0 | `APPROVED` | SBOM vulnerability matching. |
| gitleaks | 8.22.1 | MIT | `APPROVED` | Git history secret scanning. |
| TruffleHog | 3.x | AGPL-3.0 | `PROHIBITED` | Credential verification is valuable, but AGPL §13 applies to SaaS. Use Gitleaks plus a purpose-built verifier. |
| detect-secrets | 1.5.x | Apache-2.0 | `APPROVED` | Permissive alternative with a baseline model. |
| bandit | 1.8.x | Apache-2.0 | `APPROVED` | Python-native SAST. |
| gosec | 2.x | Apache-2.0 | `APPROVED` | Go-native SAST. |
| **Cloud / containers** | | | | |
| Prowler | 4.x | Apache-2.0 | `APPROVED` | 500+ checks with CIS/NIST/PCI mappings. |
| ScoutSuite | 5.x | GPL-2.0 | `APPROVED_SEPARATE_PROCESS` | Second opinion; not required. |
| Kubescape | 3.x | Apache-2.0 | `APPROVED` | Includes RBAC analysis. |
| kube-bench | 0.7.x | Apache-2.0 | `APPROVED` | |
| checkov | 3.2.334 | Apache-2.0 | `APPROVED` | IaC. |
| KICS | 2.x | Apache-2.0 | `APPROVED` | IaC. |
| PMapper | 1.1.x | Apache-2.0 | `APPROVED` | IAM privilege-escalation paths. |
| cartography | 0.9x | Apache-2.0 | `APPROVED` | Cloud asset graph. |
| Cosign | 2.x | Apache-2.0 | `APPROVED` | Signature and provenance verification. |
| Hadolint | 2.12.x | GPL-3.0 | `APPROVED_SEPARATE_PROCESS` | Guardian's builtin Dockerfile rules already cover much of this. |

## Data sources

Feed content carries its own terms, separate from any tool licence.

| Source | Terms | State | Notes |
|--------|-------|-------|-------|
| OSV.dev | CC-BY-4.0 | `APPROVED` | Attribution required. |
| NVD | Public domain (US Gov) | `APPROVED` | API key required for usable rate limits. |
| GitHub Advisory DB | CC-BY-4.0 | `APPROVED` | Attribution required. |
| CISA KEV | Public domain | `APPROVED` | |
| EPSS (FIRST) | Free for commercial use | `APPROVED` | Attribution requested. |
| MITRE CVE / CWE / CAPEC | MITRE terms | `APPROVED` | Attribution required. |
| ExploitDB | GPL-2.0 | `LEGAL_REVIEW` | Content licence differs from tool licences; review before redistributing exploit text to customers. |

## Version pinning

Versions here are the ones the runtime image installs. A scanner that silently changes version
changes its findings, and "the tool updated" is not an answer a customer accepts for why this
month's report differs from last month's. Bumping a tool is a deliberate commit that updates this
table and the image together.

## Attribution

Any deployment shipping these binaries must carry a NOTICE file listing each tool, its licence, and
a link to its source. `tools/check_tool_licenses.py --notice` generates it from this registry.
