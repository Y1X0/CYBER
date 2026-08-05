# Security Guardian Platform

> An open-source, defensive **AI Security Operations Platform** that connects to your own
> software projects — websites, mobile apps, APIs, backends, and cloud deployments — to
> manage assets, run automated + AI-assisted security assessments, produce expert-reviewed
> pentest reports, track remediation, and monitor posture continuously.

**Status:** 🚧 **Phase 1 — Foundation (in progress).** The architecture package is approved; the
commercial platform layer (hybrid tenancy, customer portal, plugin engines, billing-ready schema,
human-pentester approval workflow) is designed and being implemented.

**Not just a scanner — an operations loop:**

```
Asset Management → Security Assessment → AI + Human Pentest → Remediation Tracking → Compliance → Continuous Monitoring → ↺
```

---

## What it does

Security Guardian is a **defensive-only** security auditing platform for **authorized testing**
of assets you own or are explicitly permitted to assess. It combines a curated vulnerability
knowledge base, a multi-domain automated scanner, and an AI analyst that turns raw findings into
clear, prioritized, actionable security reports — wired directly into your CI/CD.

```
Developer pushes code
        │
        ▼
Security Guardian scans (code · deps · web · API · cloud · containers)
        │
        ▼
Findings normalized → risk-scored → AI-explained
        │
        ▼
Report generated · High-risk issues can block the deployment gate
```

## Core capabilities

| Domain | What is analyzed |
|---|---|
| **Vulnerability Intelligence** | CVE / OWASP Top 10 / CWE / best-practice knowledge base, refreshed on a schedule |
| **Source Code (SAST)** | Insecure patterns, hardcoded secrets, exposed keys, authN/authZ flaws, injection risks, insecure config |
| **Dependencies (SCA)** | Outdated packages, known-vulnerable libraries, supply-chain risk, license posture |
| **Web Applications (DAST-lite)** | Security headers, TLS config, auth flows, session management, common OWASP risks |
| **APIs** | Endpoint review, auth validation, input validation, rate-limiting, misconfiguration |
| **Cloud (CSPM)** | AWS/Azure/GCP config, IAM risk, storage exposure, insecure networking |
| **Containers** | Dockerfile hygiene, image CVEs, Kubernetes manifest review |
| **AI Analyst** | Plain-language explanations, risk scoring, remediation guidance, executive & technical reports |
| **DevSecOps** | GitHub Actions, CI/CD pipelines, PR checks, policy-driven security gates |

## Standards alignment

OWASP **ASVS** · OWASP **Top 10** · **CWE** · NIST **CSF 2.0** · **CIS Benchmarks** · Secure **SDLC**.

---

## 📐 The architecture package

Read these in order. This is the material to review before any implementation starts.

| # | Document | Purpose |
|---|---|---|
| 0 | [Architecture index](docs/architecture/README.md) | Reading guide & summary |
| 1 | [System Architecture](docs/architecture/01-architecture.md) | Components, data flow, scanners, AI layer, deployment topology |
| 2 | [Folder Structure](docs/architecture/02-folder-structure.md) | Monorepo layout for every service |
| 3 | [Database Schema](docs/architecture/03-database-schema.md) | Full relational model + migrations strategy |
| 4 | [Technology Decisions](docs/architecture/04-technology-decisions.md) | Stack choices with rationale (ADR-style) |
| 5 | [Development Roadmap](docs/architecture/05-development-roadmap.md) | Phase 1–5 delivery plan |
| 6 | [Security Model](docs/architecture/06-security-model.md) | Threat model, trust boundaries, self-hardening |

---

## ⚖️ Responsible-use policy

This platform is for **defensive security and authorized testing only**.

- Scan **only** assets you own or have **written authorization** to assess.
- No exploitation payloads, no denial-of-service tooling, no offensive/attack automation.
- Active web/API probing is **safe, non-destructive, and rate-limited**, and requires an
  explicit per-target authorization record before it runs.

Unauthorized scanning of third-party systems may be illegal. You are responsible for how you use it.

## License

Intended to be released under the **Apache-2.0** license (see [Technology Decisions](docs/architecture/04-technology-decisions.md)).
