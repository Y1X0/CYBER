# ADR-021 — Capability Governance (Phase A): identity-gated tool execution, no migration

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

The tool execution rail (ADR-016…019) enforced *target* authorization + policy + human approval, but
carried **no identity**: `dispatch_tool_job(tenant_id, tool_key, targets, human_approved: bool)` did
not know *who* was asking, and any caller that could enqueue the Celery task could run any tool. The
platform must instead be able to host every class of security tool — passive, active, sensitive,
exploit-validation, red-team — where *who may run what* is decided centrally by identity + role +
capability, never hardcoded inside a provider. The existing model already carried the substrate:
`TenantMembership.role` (owner/admin/pentester/analyst/reviewer), `ApiKey.scopes`, an append-only
`AuditLog`, and two-role RLS — but there was no platform-level owner, no capability abstraction, and
no enforcement on the worker path.

## Decision (CTO-locked) — Phase A only, no migration

Add a Control-Plane capability-governance layer that refuses a tool execution based on WHO is asking,
before anything runs, reusing existing identity with **no new tables**. DB head stays
`0009_phase6c_recon`.

1. **Capability level derived from primitives, not hardcoded per tool.** `derive_capability_level`
   maps a provider's declared `ToolCapabilities` to a level:
   L0 PASSIVE_ANALYSIS · L1 PASSIVE_NETWORK · L2 ACTIVE_RECON · L3 SENSITIVE · L4 EXPLOIT_VALIDATION
   · L5 DESTRUCTIVE. Adding a tool = declaring primitives; governance follows automatically. **No
   capability is banned** — the level only decides *what it takes* to be allowed to run it.
2. **Identity threaded into the execution path.** `dispatch_tool_job` and `dispatch_artifact_job`
   take an `actor_id`; a request with no valid identity in the tenant is **refused** (Celery cannot
   run a job anonymously).
3. **Single Control-Plane enforcement point.** `evaluate_governance` resolves the principal and
   decides, *before* the existing authorization/scope/policy gate and before any `run_tool`:
   - **Platform Owner** — a config allowlist (`GUARDIAN_PLATFORM_OWNER_IDS`), platform-level and
     tenant-independent, distinct from any per-tenant `owner` role. Still subject to authorization,
     scope, policy, approval, and audit.
   - **Tenant staff** — role resolved from `TenantMembership` *in this tenant*; a role ceiling
     (`STAFF_ROLE_CEILING`) caps the level they may run without an explicit grant. A principal with
     no membership in the target tenant is refused (**no cross-tenant execution**, no self-escalation).
   - **Service account** — `ApiKey.scopes` (`cap:<n>`) is an explicit allowlist; it cannot exceed it.
4. **Provider boundary unchanged.** A provider still declares only `capabilities`, still cannot
   `authorize` itself, and never sees a user, role, or identity. The decision is entirely in the
   Control Plane.
5. **Audit carries the actor.** Every capability decision and job decision is recorded via the
   append-only `AuditLog` with `actor_id` (null for service accounts, whose key id is in metadata) —
   who, when, tenant, capability level, provider, decision, reasons.
6. **L3+ recognized, not yet grantable.** SENSITIVE/EXPLOIT/DESTRUCTIVE need the campaign + approval
   machinery (Phase B). Until that exists they are refused with an explicit "requires campaign +
   approval governance (Phase B, not enabled)" reason — **recognized, not forbidden**. No L3+ provider
   exists yet, so nothing current is affected.

### The Tool Catalog schema (governance contract; no runtime catalog built)

Every provider is *described* by (already carried by `ToolCapabilities` + the derived level):
`provider_key, version, category, capability_level, network, active, destructive,
requires_authorization, requires_human_approval, requires_campaign, supported_targets, sandbox,
execution_backend, allowed_capability_levels_by_role`. It is metadata/policy *input* — it never makes
the security decision itself.

## Semantic reuse

Reuses unchanged: `Authorization`, `EffectiveScope`, the policy gate, human approval, the sandbox,
`ToolProvider`, evidence hash chain, findings, graph, RLS/tenant isolation, the DB-less execution
plane. The governance layer sits *in front of* the existing gates; it does not replace them.

## Alternatives considered

- **`can_use_<tool> = true` flags per tool / per role.** Rejected: the anti-pattern the platform must
  avoid; capability levels derived from primitives scale to any future tool without editing role sets.
- **Skip identity on the worker path (enforce only at the API).** Rejected: the Celery path is a
  second entry that must not bypass RBAC; the gate lives where the job is dispatched.
- **Build platform_roles / campaigns / approvals / capability_grants tables now (Phase B).**
  Deferred: they require migrations; Phase A reuses `TenantMembership` / `ApiKey.scopes` / a config
  allowlist and delivers real enforcement with no schema change.

## Consequences

- A tool execution is now refused centrally by identity before it runs; the worker plane stays
  identity-free and DB-less.
- The platform can host every capability class; *who* may run each is governed, not the provider.
- 6C.4/6D/6E/6F/Framework P1/Providers #1/#2/#3 behavior is unchanged; DB head stays `0009`.

### Deferred / technical debt (Phase B — needs migration, out of scope here)

- **Platform-owner as a table** (`platform_roles` / `user_platform_role`) instead of a config
  allowlist; **campaigns**; **approvals** as first-class revocable records (replacing the
  `human_approved` bool); **per-user capability grants**; a **persisted per-tenant tool catalog**.
- **`run_tool` direct-invocation hardening** — the RBAC gate is at dispatch; `run_tool` (DB-less,
  persists nothing) relies on queue isolation and the trusted-plane assumption. Plane authentication
  is a later hardening.
- **Hash-chained / WORM audit** so even a platform owner cannot silently delete sensitive audit
  (today: append-only + no DELETE grant to the app role).
- Reconcile `web_tls`'s eager binder (ADR-019 debt), unrelated but still open.
