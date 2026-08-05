# 08 — Strategic Product & Architecture Review (pre-Phase-5)

> Chief Security Architect review of the post-Phase-4 platform against eight proposed capability
> areas. Decides what lands **before Phase 5**, what becomes **Phase 6–9**, how **Phase 5 changes**,
> and — most importantly — which **schema/architecture seams must be added now** while they are cheap.
> **No implementation until this direction is approved.**

---

## 0. The one strategic insight

Everything proposed (EASM, SOAR, attack-path graph, AI agents, cloud/IaC, pentest workspace,
enterprise) rests on **two architectural bets** the current model does not yet make:

1. **A unified asset + identity + data graph** — attack paths, EASM inventory, IAM analysis, and
   "real impact" all need typed **nodes and edges**, not just findings.
2. **An event/automation backbone** — SOAR, notifications, ticketing, and agent triggers all need a
   reliable **domain-event stream**, not ad-hoc writes.

These two are the **expensive-to-retrofit** decisions. Adding an edge model or an event outbox after
hundreds of customers' data exists means backfilling history and rewriting every write path. Adding
them now — as **empty schema seams + interface ports, with no feature logic** — is cheap.

**Therefore Phase 5 changes from "production hardening" to "Hardening + Foundations": harden the
platform for scale AND lay the data-model seams, together, because both are one-time "before-scale"
work that touches the core.**

---

## 1. Capability-by-capability verdict

| # | Capability | Verdict | Why |
|---|---|---|---|
| 1 | **EASM** (asset discovery) | **Phase 6** feature; **seam now** | Active external discovery is a new subsystem *and* legally sensitive (must be authorization/scope-gated like all active scanning). But the **asset provenance + graph-edge** model it needs is a cheap seam to add in Phase 5. |
| 2 | **SOAR** (automation/orchestration) | **Phase 7** feature; **seam now** | Rule engine + connectors are substantial. But the **domain-event outbox** + **Notifier/Connector port** must exist before Phase 5 writes multiply, or eventing is a painful retrofit. |
| 3 | **Attack-path graph** | **Phase 6** feature; **seam now** | The differentiator ("real impact, not findings"). Needs the same node/edge model as EASM. Resist a graph DB — **materialize from Postgres edges**; revisit Neo4j only at proven scale. |
| 4 | **Advanced AI agents** | **Phase 6–7**; compliance **seam now** | Recon/Analysis/Threat-Model/Remediation agents evolve the existing `LLMProvider` + analyst. The **compliance framework/control** tables (for the Compliance agent + SOC2/ISO) are a cheap seam. Remediation-PR agent is the **highest-risk** item → last (Phase 9). AI stays non-authoritative throughout. |
| 5 | **Cloud/IaC/Supply-chain** | **Phase 6** | Natural extensions of CSPM/SCA. IaC (Terraform/CFN) ≈ existing engine pattern; SBOM (CycloneDX/SPDX) ≈ SCA extension; **live cloud connectors** expand credential blast radius → must land *with* the BYOK/Vault + least-privilege work seeded in Phase 5. |
| 6 | **Pentest workspace** | **Phase 8**; evidence-integrity **seam now** | Deepens what we have (engagements, findings, report approval). **First-class evidence with hash-chain integrity** can't be added retroactively to old evidence → seam now. Collaboration/UI later. |
| 7 | **Enterprise** (SSO/SCIM/BYOK/regional) | **Phase 9**; SSO **seam now** | Gates enterprise sales but not all urgent. **RLS + strong tenant isolation** are already Phase-5 and non-negotiable. SSO user-model seam is cheap now; SCIM/BYOK/regional/Trust-Center are Phase 9. |
| 8 | **Arch security before scaling** | **This IS Phase 5** | RLS, sandboxing, ephemeral workers, prompt-injection/RAG controls, self-SBOM, image signing — the security-of-the-security-product. Elevate to hard gates. |

---

## 2. What MUST land before Phase 5 (fold into Phase 5)

### 2A. Hardening (the original Phase 5 spine — keep, elevate to gates)
- **PostgreSQL RLS + connection-level tenant context** — isolation. Do first; retrofitting after data grows is painful.
- **Scanner sandboxing + ephemeral, egress-restricted worker containers** — before running untrusted customer code/targets at scale. Hard gate.
- **Prompt-injection & RAG security controls** — formalize the existing principle into enforced, tested guardrails (delimited untrusted data, output validation, allow-listed retrieval, no tool authority from model text).
- **Self-SBOM + signed, reproducible images + self-scan-in-CI (dogfood)** — our own supply chain.
- **Secrets manager integration + envelope encryption** for stored credential references (the honest gap flagged in the Phase-1 review) — and the prerequisite for live cloud connectors + BYOK.
- **Rate limiting / brute-force protection**, **audit tamper-evidence** (append-only + hash chain), **per-customer staff assignment** enforcement (the managed-service scoping gap).

### 2B. Foundational schema seams (schema + ports only — NO feature logic)
These are the cheap-now / expensive-later changes. **Tier-1 = add in Phase 5. Tier-2 = defer with the feature.**

| Seam | Tier | Unlocks | Retrofit cost if deferred |
|---|---|---|---|
| **Asset provenance** (`source` declared\|discovered, `state`, `first_seen`, `confidence`, `data_classification`) | **1** | EASM, shadow-asset, graph | High — touches every asset write |
| **`graph_edge`** (polymorphic: `src_type/src_id → dst_type/dst_id`, `relation`, `weight`, `metadata`) | **1** | Attack-path graph, EASM topology, IAM analysis | Very high — the core relationship model |
| **`domain_event` outbox** (append-only; `type`, `payload`, `occurred_at`, `processed_at`) | **1** | SOAR, notifications, agent triggers, reliable delivery | Very high — every write path |
| **`evidence_item`** (first-class; `kind`, `storage_ref`, `content_sha256`, `prev_hash` chain, `created_by`) | **1** | Defensible pentest evidence, chain-of-custody | High — integrity can't be added to past evidence |
| **`identity` + `data_store` nodes** (cloud/app principals, sensitive data assets) | **1** | Attack paths through IAM → data | High — graph completeness |
| **Compliance** (`framework`, `control`, `control_mapping`) | 2 | Compliance agent, SOC2/ISO posture | Medium — additive |
| **`integration` / `notification_channel`** config + `Notifier`/`Connector` port | 2 | SOAR connectors | Medium — port now is cheap, impl later |
| **SSO fields on `user`** (`idp`, `external_subject`, `sso_only`) + `identity_provider` | 2 | SAML/OIDC | Low-medium |
| **`discovery_job`** | 2 | EASM runs | Low |

### 2C. Interface ports to introduce now (definitions only, no implementations)
`Notifier` / `ConnectorProvider` (SOAR) · `GraphProjector` (materialize graph from edges) ·
`KMSProvider` / `SecretsProvider` (BYOK/Vault) · `DiscoveryProvider` (EASM collectors) ·
`IdentityProvider` (SSO). Same pattern as the existing `LLMProvider` / `JobQueue` / `ScanEngine`
ports — lets later phases plug in without touching the core.

---

## 3. Does Phase 5 change? — Yes

**Rename:** *Phase 5 — Production Hardening* → **Phase 5 — Production Hardening & Platform Foundations.**
**Two workstreams, run together:**

- **5A — Security hardening** (§2A). Hard gates: RLS, worker sandboxing, secrets-manager. This is the
  answer to capability #8 in full.
- **5B — Foundational seams** (§2B/§2C). Tier-1 schema + all ports. **No feature behavior** — just the
  seams so Phases 6–9 are additive, not migrations-under-load.

Exit criteria add: RLS enforced + tested cross-tenant; workers sandboxed + egress-restricted; self-scan
green in CI; Tier-1 seams migrated and covered by model tests; ports defined with stub/no-op defaults.

---

## 4. Required DB/architecture changes NOW (the expensive-later list)

Ranked by retrofit cost — this is the concrete "do these seams in 5B" list:

1. **`graph_edge`** (+ `identity`, `data_store` nodes; asset provenance fields) — the relationship spine.
2. **`domain_event` transactional outbox** — the eventing spine (SOAR + agents + notifications).
3. **`evidence_item` with hash-chain integrity** — the pentest-defensibility spine.
4. **RLS + `app.current_tenant` session context** — the isolation spine (also a 5A hardening item).
5. **Secrets-manager / envelope-encryption for credential references** — the credential spine (BYOK + live cloud later).

Everything else (compliance tables, connector configs, SSO fields, discovery jobs) can land **with its
feature** at low retrofit cost, so it stays in Phase 6–9.

---

## 5. Revised 12-month roadmap

| Window | Phase | Focus | Key data model added with the feature |
|---|---|---|---|
| **M1–2** | **5 — Hardening & Foundations** | RLS, sandboxing, ephemeral workers, prompt-injection/RAG controls, self-SBOM + image signing, secrets manager; **Tier-1 seams + ports** | graph_edge, identity, data_store, domain_event, evidence_item, asset provenance |
| **M3–5** | **6 — Attack Surface & Graph** | EASM (authorization-gated discovery), attack-path **graph projection + visualization**, **live cloud connectors + deep IAM** (shadow admins, trust relationships), **IaC** (Terraform/CFN/K8s-IaC) + **SBOM** (CycloneDX/SPDX) + malicious-package detection | discovery_job; edges populated |
| **M5–7** | **7 — Automation & Intelligence** | **SOAR** (event rules + Slack/Jira/PagerDuty/ServiceNow connectors), **advanced AI agents** (recon, analysis, threat-modeling), **compliance** mapping (SOC2/ISO/PCI/HIPAA) | automation_rule, integration, compliance_framework/control |
| **M7–9** | **8 — Pentest Operations** | Engagement workspace, evidence collection + chain-of-custody UI, client collaboration, report tiers (exec/technical/board) | evidence_item populated; comment/thread |
| **M9–12** | **9 — Enterprise & Trust** | **SSO/SAML/OIDC/SCIM**, **BYOK/Vault**, regional data isolation, Trust Center, **SOC2/ISO readiness**; **Remediation-PR agent** (opt-in, sandboxed, human-approved, never auto-merge) | identity_provider, region routing |

Sequencing rationale: **graph + events first** (they underpin EASM, SOAR, agents, impact); **cloud
depth + IaC** next (extends existing engines, feeds the graph); **automation + agents** once there are
events and a graph to reason over; **pentest workspace** once evidence integrity exists; **enterprise +
the riskiest AI (remediation PRs)** last, when isolation and trust controls are mature.

---

## 6. Risk register / guardrails (standing constraints for 6–9)

- **Active discovery & live cloud = legal + blast-radius exposure.** EASM active probing and cloud
  connectors are authorization/scope-gated (same gate as DAST/API/CSPM), read-only least-privilege,
  short-lived creds, per-tenant isolated. Distinguish passive/OSINT discovery from active probing.
- **AI stays non-authoritative — reaffirmed for every new agent.** Deterministic engines (severity,
  risk score, gate, graph edges) are the source of truth; agents explain, correlate, and draft.
- **Remediation-PR agent is the highest-risk feature** (write access to customer code) → Phase 9, opt-in,
  sandboxed, human-approved, never auto-merge; branch-only, signed, reversible.
- **No premature graph DB.** Materialize from `graph_edge` in Postgres; adopt a graph engine only if
  path-query scale demands it.
- **No connector sprawl.** Build the `Connector` port + two connectors (Slack, Jira) first; add others on demand.
- **Prompt-injection is a first-class threat now that agents act on more data** — untrusted-data framing,
  validated structured output, allow-listed retrieval, and no tool authority from model text are enforced,
  not aspirational.

---

## 7. Recommendation

Approve **Phase 5 = Hardening (5A) + Foundational Seams (5B)** as scoped above, adopt the revised
12-month roadmap (§5), and authorize the Tier-1 schema seams + interface ports (§2B/§2C) to be built in
Phase 5 **without feature logic**. This keeps the core clean, avoids expensive migrations under load,
and sequences the "Security Operations Platform" evolution so each phase is additive.

Await approval before implementation.
