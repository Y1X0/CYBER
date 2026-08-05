# ADR-010 — Phase 5: two-role RLS tenant isolation + Tier-1 foundational seams

- **Status:** Accepted
- **Date:** 2026-08-05
- **Deciders:** Chief Security Architect, Platform Engineering

## Context

Phase 5 makes the platform safe to run for many tenants at once. Two of its decisions are
*irreversible* — expensive or impossible to retrofit later — so they are recorded here:

1. **How tenant isolation is enforced at the database.** Application-level scoping (routers filtering
   by `tenant_id`) is necessary but not sufficient for a commercial security product: a single missed
   filter is a cross-tenant breach. We want a backstop the database itself enforces.
2. **Which storage shapes must exist now.** Some relationships (a graph spine, an event outbox,
   evidence integrity) are near-impossible to add retroactively to data already captured without
   them. The rest of Phase 6–9's data model, however, should *not* be pulled forward — unused
   schema is liability, not value.

## Decision

**1. Two-role Row-Level Security.** The API connects as a non-owner role (`guardian_app`) that RLS
applies to; each request binds its connection to `app.current_tenant` (a GUC set after identity
resolution) and every tenant-scoped table carries an RLS policy that filters to it. Workers,
migrations, seeds, and the pre-tenant identity bootstrap keep a **privileged owner** connection that
bypasses RLS, because they operate legitimately across tenants. Tables isolate by their natural
shape: a direct `tenant_id`; a parent FK (child tables resolve through the parent the tenant owns);
the tenant's own row; or `organization_id`. Append-only tables (`audit_log`, `domain_events`) scope
reads by tenant but allow inserts (system/pre-auth events may carry a null tenant). With no tenant
bound, policies fail **closed** (zero rows). Dev/test without a configured app URL falls back to the
owner connection, leaving RLS inert but app-level scoping intact.

**2. Tier-1 seams only.** Land four storage foundations with no feature logic: a polymorphic
`graph_edges` (no FKs to node tables, so new node types need no schema change), a `domain_events`
outbox, an `evidence_items` table with a `content_sha256`/`prev_hash` integrity chain, and asset
**provenance** columns. Explicitly *defer* full compliance, integration-config, SSO, identity-graph,
and data-store-graph schemas to their feature phases.

## Alternatives considered

- **App-level tenant scoping only (no RLS).** Simplest, but one forgotten `WHERE tenant_id` is a
  breach with no backstop. Rejected for a product whose core promise is isolation.
- **Session-variable RLS on a single (owner) role.** The owner bypasses RLS regardless of policies,
  so isolation would depend entirely on always setting the GUC — no true enforcement. Rejected in
  favor of a genuinely unprivileged app role.
- **Per-tenant schemas or databases.** Strong isolation, but operationally heavy at the tenant counts
  we target and painful for cross-tenant platform queries. Revisit only for enterprise BYO-DB.
- **Build the full future schema now.** Rejected — premature complexity; unused tables are attack
  surface and migration weight. Seams are the minimum irreversible subset.

## Consequences

- **Easier:** a missed application-level filter can no longer leak across tenants; the guarantee is
  test-verified (cross-tenant, fail-closed, and negative-authorization `WITH CHECK` tests).
- **Harder / follow-ups:** request handlers must run on the app session with a bound tenant, and any
  genuinely cross-tenant read in a request path must be a deliberate, reviewed exception on the
  owner connection. New tenant-scoped tables must add an RLS policy in the same migration — enforced
  by review of `security-sensitive paths`.
- **Global reference data** (users, KB, plans, vulns) intentionally keeps no RLS; the app role reads
  it freely. `users` is global identity by design; identity resolution runs on the owner session.
- The seams carry a **backward-compatibility guarantee**: existing call sites that build an `Asset`
  without provenance fields keep working (safe defaults) — covered by a schema-integrity test.
