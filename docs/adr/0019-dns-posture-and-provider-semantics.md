# ADR-019 — Provider #3: DNS/Email-Security Posture + unified Provider semantics

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Providers #1 (active/network) and #2 (offline artifact) both derive a finding from a *single*
positive observation via `normalize(evidence) → RawFinding | None`. Much of security posture,
however, is inferred from the **aggregate** and — critically — the **absence** of data: no SPF, DMARC
`p=none`, no CAA, no DNSSEC. That inference pattern was unproven, and the deferred MX/TXT/CAA
capability from ADR-017 was still open. This provider closes both, read-only, without a live resolver.

Two governance items also needed to be settled platform-wide: the Evidence/Finding/Scan relationship
(after #1 created a Scan on binding while #2 did not), and a schema for describing every future tool.

## Decision (CTO-locked)

Ship **`dns_posture`**, an offline DNS/email-security posture assessor, on the ADR-016 rail; reuse
`ToolProvider`/`ToolJob`/sandbox/evidence-chain/authorization/scope/policy/host-binding/`to_finding`/
6E `enrich_graph`. No migration; DB head stays `0009_phase6c_recon`.

1. **Absence-as-evidence, contract unchanged.** The provider evaluates the full record set inside
   `execute()` and emits a POSITIVE evidence item for each weakness — *including a recorded absence*
   (`dns_spf_missing`, …). `normalize()` stays strictly per-evidence and the shared framework
   contract is **not** changed. An absence is a first-class recorded observation, not special-case
   logic. A chain-of-custody `dns_records` evidence item captures the full observed record set.
2. **Offline-first, hermetic.** The authoritative DNS record set arrives as a bounded snapshot in
   `ToolJob.settings`. No live resolver, **no new egress** (a live resolver mode is deferred behind a
   separate decision on resolver egress). The snapshot is authoritative: an omitted record key means
   "not observed" (absent). A structurally malformed snapshot entry **fails closed** for that target.
3. **Policy: passive.** `network=false, active=false, destructive=false, requires_authorization=true,
   requires_human_approval=false`. Authorization is required (the domain must be an authorized
   target); no human approval (mirrors #2). The execution plane runs with the network denied.
4. **Exact canonical-host binding (as #1).** Findings bind to the single tenant web/api asset whose
   exact canonical host matches the domain; zero or 2+ matches ⇒ **Evidence-only**. The provider
   never creates an asset.
5. **Conservative, deterministic findings only:** SPF missing, SPF permissive (`+all`), DMARC
   missing, DMARC `p=none`, CAA missing, DNSSEC not enabled, and MX-without-SPF (which supersedes the
   generic SPF-missing when mail is configured). Each is traceable to the observed record set. **No**
   inference of compromise, takeover, or intrusion; no AI; no new scoring.

## The unified Provider semantic contract (platform-wide, locked)

Documented here as the rule every current and future Provider follows:

- **Evidence = primary truth.** Every observation is persisted independently, hash-chained, and
  tenant-scoped — whether or not a finding results.
- **Finding = deterministic derived inference.** A finding is derived from evidence by a provider's
  `normalize()`; it is never the tool's own verdict, and it may be absent.
- **Scan/ScanEngineRun/Finding are created ONLY when ≥1 finding is derived.** A binding that yields
  no finding stays evidence-only (no empty Scan). `dns_posture` and `pcap_meta` honor this via the
  strict binder; **`web_tls` predates the rule and keeps its eager binder — reconciling it is tracked
  technical debt** (below), deliberately not changed here to keep this change minimal.
- **Graph = derived representation.** 6E enrichment projects derived findings; it invents nothing.

### Tool Catalog schema (governance only — no runtime catalog built now)

Every Provider is described by this schema (already carried by `ToolCapabilities` + policy). It is a
documentation/governance contract, not a new system:

| Field | Meaning |
|---|---|
| `passive/active/destructive` | how the tool touches a target (drives the policy gate) |
| `authorization` | whether a DB-backed authorization is required |
| `human_approval` | whether an explicit human approval is required before dispatch |
| `sandbox` | always mandatory; DB-less execution plane |
| `scope` | the EffectiveScope narrowing (never wider than authorization) |
| `evidence` | the RawEvidence kinds it emits (primary truth, hash-chained) |
| `finding` | the deterministic findings `normalize()` derives (or none) |

Registered providers today: `web_tls` (active/network, human-approval), `pcap_meta` (passive,
offline artifact), `dns_posture` (passive, offline posture).

## Fix folded in — `verify_chain` ordering (Framework P1 bug exposed by #3)

Provider #3 is the first to emit several evidence items in one transaction, which exposed a latent
bug: items share a transaction-constant `now()` `created_at`, so `verify_chain`'s
`(created_at, id)` ordering tiebroke on the random UUID and diverged from the build order, failing a
*valid* chain. Fix (read-only, approved, minimal): `verify_chain` now reconstructs order by walking
the self-describing `prev_hash` linked list (genesis = `prev_hash IS NULL`; successor = the item
whose `prev_hash` equals the current `content_sha256`), failing closed on a missing/duplicate genesis
link, a fork, a mid-chain break, or a tampered item. No `persist` change, no `EvidenceItem` contract
change, no schema, no migration. #1/#2 behavior is unchanged (single/short chains still verify).

## Alternatives considered

- **Change `normalize` to return a list / read an evidence set.** Rejected: absence-as-evidence keeps
  the per-evidence contract intact and is more honest (an absence is a real observation).
- **Live resolver now.** Rejected: it needs new egress semantics (a resolver is not the target);
  offline-first proves the capability hermetically, live is a later, separate decision.
- **Fix `verify_chain` by assigning synthetic increasing `created_at` in `persist`.** Rejected:
  touches the write path; the `prev_hash` walk fixes the reader where the bug actually is.
- **Retrofit `web_tls` to the strict binder now.** Deferred: not required for #3; tracked as debt.

## Consequences

- The rail now proves three inference shapes: single active observation (#1), single offline
  observation (#2), and **aggregate/absence** posture (#3) — plus a hardened, self-verifying evidence
  chain.
- The Provider semantic contract is explicit, so future tools cannot silently diverge.
- 6C.4/6D/6E/6F/Framework P1/Provider #1/#2 behavior is unchanged; DB head stays `0009_phase6c_recon`.

### Deferred / technical debt

- **Reconcile `web_tls` to the strict binder** (no empty Scan) — the one remaining semantic divergence.
- Live DNS resolver mode (needs a resolver-egress + rebinding decision); MX/TXT records beyond
  posture; per-record TTL/serial provenance.
- Everything already deferred by ADR-011…018.
