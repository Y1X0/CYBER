# ADR-016 — Security Tool Execution Framework (Phase 1: the governed rail, no tools)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

The platform must eventually run security tools (network discovery, web/TLS, PCAP, …). Building them
as "a button → a command" would make a toolbox, not a platform, and would let a compromised tool
reach the database, secrets, or another tenant. A read of the code showed most of a framework already
exists in fragments: the scanner-engine contract (`ScanEngine`/`ScanContext`/`RawFinding`→`Finding`),
the `EvidenceItem` hash-chain table, `Scan`/`ScanEngineRun`, the deterministic policy gate, the
sandbox, the plugin registries, and — crucially — the 6C.4 recon execution-plane isolation
(DB-less, result-return, egress-allowlisted). The right move is to **unify and generalize**, not
rebuild — and to build the security boundary FIRST, before any tool.

## Decision (CTO-locked)

**Build the rail every future tool rides on; ship no tool in Phase 1.** A tool becomes a *Provider*
behind: Authorization → EffectiveScope → Policy/Gate → ToolJob → (DB-less sandbox) → RawEvidence →
hash-chained EvidenceItem → Finding → Graph.

1. **Generalize 6C.4 isolation to all tool execution (the blocker, done first).** A DB-less `tools`
   execution plane (`worker-tools`, no DB URL, no DB route, no KMS, `GUARDIAN_TOOL_PLANE=true`) runs
   only `run_tool` — a provider inside the **mandatory** sandbox with egress bound to the job's scope
   (reusing the exact 6C.3/6C.4 allowlist + SSRF/DNS-rebinding + IP-pinning + FD-close + NPROC). The
   trusted `dispatch_tool_job` (authorize/scope/policy/persist) runs on `default`. Each task refuses
   the wrong plane; a misroute fails loudly. **The execution worker is dumber than the trusted plane
   — it never sees a DB, KMS, RLS, tenant, finding, or asset.**
2. **Reuse `Scan`/`ScanEngineRun` as the execution model** (no new `tool_jobs` table). If a state
   cannot be represented cleanly, STOP and report rather than migrate.
3. **Scope = Authorization + Policy + Capabilities → EffectiveScope** (deterministic, no `tool_scopes`
   table). `EffectiveScope` can only ever *narrow* an Authorization — a tool can never widen its reach
   (never turn `example.com` into `0.0.0.0/0`). Authorization is the source of truth; scope is a
   narrowing.
4. **The provider never authorizes itself.** The contract has `validate` (is the job well-formed?),
   never `authorize`. Authorization, scope, and the policy gate are decided in the Control Plane
   before a job reaches a provider.
5. **Capability Registry, not a plugin list.** `guardian.tool_providers` exposes each tool's
   `ToolCapabilities` (network / active / destructive / requires_authorization /
   requires_human_approval / category / ports / protocols), so the policy engine can reject a tool in
   a context *before* it reaches the execution plane.
6. **Human-approval boundary as a real gate.** Passive/analytical tools that are already within
   authorization+policy need no extra approval; **active/network tools and any destructive-capable
   tool require an explicit human approval** before dispatch. High-risk campaigns (phishing,
   auth-testing) are not `execute()` calls — they will need their own campaign-authorization workflow
   and are out of scope.
7. **Secrets are never evidence.** The execution plane holds no KMS and no long-lived credentials;
   the trusted plane would decrypt and pass minimal runtime material to the sandbox (not the general
   payload). A secret must never appear in evidence, logs, audit, findings, or results — evidence
   content is additionally scrubbed of sensitive-looking keys before hashing/storage.
8. **Evidence is the heart.** `RawEvidence` → tamper-evident `EvidenceItem` hash chain
   (`content_sha256 = sha256(prev_hash + canonical)`), verifiable, tenant-scoped — reusing the
   existing table (no migration). Findings and graph integration reuse the existing
   normalize → Finding → 6E enrich_graph path when a provider is bound to an asset.
9. **No migration.** Everything reuses existing schema; DB head stays `0009_phase6c_recon`.

## Alternatives considered

- **Add Nmap first, generalize later.** Rejected: running a network tool on a DB-credentialed worker
  is the exact escalation 6C.4 closed for recon; generalizing the isolation is the prerequisite.
- **New `tool_jobs`/`tool_scopes` tables.** Rejected: three parallel execution/scope systems instead
  of one; reuse Scan/ScanEngineRun + Authorization + Policy. (Migration only if truly forced — then
  stop and ask.)
- **Provider decides authorization.** Rejected outright: a tool must never grant itself permission.

## Consequences

- Any future capability enters as a governed, scoped, isolated, audited Provider whose results become
  Evidence → Finding → Attack Graph → Risk — dozens of tools without turning the project into a
  toolbox or a security hazard.
- 6C.4/6D/6E/6F are untouched; the tool plane reuses (does not modify) the recon isolation primitives.
- The execution plane is DB-incapable by construction, so a compromise inside any tool finds no crown
  jewels.

### Deferred / technical debt (not in Phase 1)

- **Any actual tool provider** (Nmap, PCAP, web/TLS, …) — a separate, scoped phase; the first should
  be non-destructive and narrow, to prove the rail.
- **Finding persistence from tools** (needs an asset/scan binding) and object-storage artifacts
  (`EvidenceItem.storage_ref`).
- **Minimal-secret runtime delivery** to the sandbox (contract + boundary defined; wiring lands with
  the first tool that needs a credential).
- **Campaign-authorization workflow** for high-risk categories (phishing, auth-testing).
- Everything already deferred by ADR-011…015 (cloud_resource, routes_to/trusts, seccomp, Phase 7).
