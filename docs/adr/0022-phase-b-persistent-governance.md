# ADR-022 — Phase B: persistent authorization — platform roles, campaigns, approvals, grants, catalog

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Phase A (ADR-021) gated tool execution by identity, but its pillars were ephemeral: platform owner
was a config allowlist, approval was a `human_approved` bool, capability was a hardcoded role ceiling,
there was no campaign, and the tool catalog lived only in code. Turning "partial governance" into a
real permission system — where a platform owner can enable any capability, a normal user only runs
what they were granted, and every sensitive act has an owner, an approval, a scope, and a record —
requires persistence. This is the **first migration after `0009_phase6c_recon`**.

## Decision (CTO-locked) — one additive, reversible migration `0010_phase_b_governance`

Six tables + two nullable FKs + RLS + a SECURITY DEFINER reader + an audit-immutability trigger.
No migration 0001–0009 is touched; L0–L2 behavior is unchanged.

1. **Platform roles — `platform_grants`** (global). Real `platform_owner`/`platform_admin`, distinct
   from a per-tenant `owner`. Read via the SECURITY DEFINER `platform_role(uuid)` (fixed search_path,
   EXECUTE granted only to `guardian_app`). Seeded from the existing `platform_owner_ids` so the
   current owner survives the migration. Cross-tenant platform actions go through definer functions —
   **the tenant_isolation policies are never weakened**.
2. **Campaigns — `campaigns` + `campaign_members`** (tenant + child). The container for L3+ work:
   `status` (draft → active → suspended/completed/revoked), `max_capability_level`, time window,
   operators. Executions/authorizations link via nullable `scans.campaign_id` /
   `authorizations.campaign_id`. **Evidence-first is unchanged** — evidence stays tenant-keyed and
   independent; the campaign link is on the scan only.
3. **Approvals — `approvals`** (tenant). Replaces the bool for L3+: `approver_id`, `requested_by`,
   `capability_level`, `provider_key`, `campaign_id`, `scope_snapshot`, `granted_at`, `expires_at`,
   `revoked_at/by`, `consumed_at`. Validated live (expiry/revocation/consumption/scope/provider/
   campaign); **single-use** (consumed only after the whole gate passes); **independent approver for
   L4/L5** enforced both in the Control Plane and by a DB CHECK. **L2 keeps the bool** — untouched.
4. **Capability grants — `capability_grants`** (tenant). Raise a `user` / `role` / `api_key` above the
   role ceiling for specific tools, with expiry/revocation. A grant can never lift a service account
   past L2. The provider never sees grants.
5. **Tool catalog — `tool_catalog`** (global). **Primitives stay in code** (`ToolCapabilities` →
   derived level); the catalog owns only enablement, version, and campaign/approval overrides. A
   disabled tool is refused; an **unregistered L3+ provider is refused by default** (deny-by-default
   for sensitive capabilities); unregistered L0–L2 keeps working; the three shipped providers are
   seeded enabled — so #1/#2/#3 are unaffected.
6. **Service accounts.** `ApiKey.scopes` stays; effective level = scopes ∩ grant ∩ catalog ∩
   authorization, **hard-capped at L2** — no service account can run L3+.
7. **Audit.** `AuditLog` stays append-only; a `BEFORE UPDATE OR DELETE` trigger makes it immutable
   even to the owner via normal DML (break-glass = disabling the trigger as superuser, itself
   audit-worthy). Every capability decision records `actor_id` + context. No new audit table.

The decision chain, all in the Control Plane, refusing at the first failing stage:
`Identity → Platform/RBAC → Capability Grant → Level → Campaign (L3+) → Approval (L3+) →
Authorization → Effective Scope → Tool Catalog → Policy → Provider`. Both API and Celery funnel
through the dispatch gate; no path bypasses it; no anonymous execution.

## Boundaries preserved

Provider boundary unchanged (no provider knows user/role/grant/campaign/approval; none self-authorizes).
Execution plane unchanged (DB-less, identity-less — Phase B is entirely Control-Plane). Evidence hash
chain, World Model, Attack Graph, and the existing RLS policies are untouched.

## Alternatives considered

- **Keep platform owner in config.** Rejected: no provenance, grant/revoke, or audit; a table with a
  definer reader is the real model while leaving tenant RLS intact.
- **Fold approvals into `authorizations`.** Rejected: target-scope and capability-approval are
  different axes; overloading one loses the single-use/independent-approver semantics.
- **Weaken tenant RLS so a platform owner sees all tenants.** Rejected outright (a STOP condition):
  cross-tenant platform access is via SECURITY DEFINER functions, never by relaxing tenant_isolation.
- **Catalog as source of truth for primitives.** Rejected: primitives are a code property; the
  catalog is policy/enablement only.

## Consequences

- L3–L5 are now *executable* under campaign + approval + grant — recognized-not-forbidden realized —
  while L0–L2 (all current providers) are unchanged.
- The migration is additive and fully reversible (proved: upgrade → downgrade with live data →
  re-upgrade); DB head moves `0009_phase6c_recon → 0010_phase_b_governance`.
- **Nmap (L2) needs none of this to be governed** — Phase A already governs it; Nmap's real blocker
  stays the execution-plane egress isolation (Discovery 0020). Phase B unlocks the *higher-risk* tools.

### Deferred / technical debt

- **Management API** for platform grants, campaigns, approvals, grants, and catalog (creation-time
  rules: only admin/owner/platform may grant; a grant/approval cannot exceed the granter's authority).
  Phase B ships the enforcement + persistence; the CRUD surface is next.
- Approval is consumed only after the full gate passes; a wasteful edge (gate passes governance,
  later stage denies) does not consume — acceptable, but revisit with the management API.
- `run_tool` direct-invocation hardening; hash-chained/WORM audit beyond the trigger; per-user grant
  UI. Reconcile `web_tls`'s eager binder (ADR-019 debt). Everything already deferred by ADR-011…021.
