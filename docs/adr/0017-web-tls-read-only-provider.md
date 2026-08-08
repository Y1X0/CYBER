# ADR-017 — Provider #1: Web/TLS Read-only tool (Evidence-first, exact-binding)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Framework Phase 1 (ADR-016) built the governed rail but shipped no tool. The rail needs to be proven
by a first Provider that is narrow, non-destructive, and read-only — a tool that *observes* an
authorized host and produces evidence, never one that crawls, fuzzes, authenticates, or sends a
payload. The open question the rail deferred was how a tool's output becomes a Finding without the
tool inventing an asset: a Finding requires `asset_id`/`scan_id`/`engine_run_id` (all NOT NULL). The
answer must be deterministic and must never let a tool guess which asset it touched.

A second principle was locked during review: **Evidence is the primary truth; a Finding is a derived
inference.** The provider's success is not conditional on producing a Finding — evidence stands on
its own, and a Finding is only derived when the evidence binds cleanly to one managed asset.

## Decision (CTO-locked)

Ship **`web_tls`**, a read-only Web/TLS observer, on the ADR-016 rail. It reuses the 6C.2 TLS/HTTP
read logic and the existing `Scan`/`ScanEngineRun`/`to_finding`/6E `enrich_graph` path. No migration.

1. **Tiny, passive, read-only.** The provider observes only: the TLS certificate (issuer / subject /
   SAN / expiry / version / hostname verification) and a safe HTTP status + a small set of
   non-sensitive response headers, plus the verified IP of the connection it made. **Never**:
   crawling, directory/content discovery, forms, POST, authentication, fuzzing, payloads,
   open-redirect probing, or port discovery. HTTP uses `HEAD` only.
2. **Reuse the rail, add no self-sandbox.** `execute()` runs inside the framework's mandatory sandbox
   (`tools.execution`) with egress already bound to the job's `EffectiveScope`, so the provider does
   the raw observation without re-wrapping itself in a sandbox (unlike the standalone 6C.2 probes).
3. **Evidence-first.** `dispatch_tool_job` persists the hash-chained evidence **first** (primary
   truth), then derives findings. `execute()` yields `RawEvidence`; `normalize()` maps a single
   evidence item to a `RawFinding` deterministically (expired cert → CWE-298; hostname mismatch →
   CWE-297) or to nothing. A Finding is an inference from evidence — never the tool's own verdict.
4. **Exact canonical-host Asset Binding, or Evidence-only.** Evidence binds to a Finding only when
   its host matches **exactly one** tenant web/api asset by the same exact canonical-host rule 6E's
   `serves` edge uses (no fuzzy / brand / IP-literal match). Zero or two-plus matches → **Evidence
   persists, no Finding**. The provider NEVER creates an asset.
5. **Reuse Scan/ScanEngineRun.** On a unique binding, one `Scan(trigger="tool")` +
   `ScanEngineRun(engine="web_tls")` carry the derived findings through `to_finding` (deterministic
   scoring) and then 6E `enrich_graph`, yielding a real internet → serves → asset → exposes → finding
   attack path. `EngineKey.WEB_TLS` is added so the finding fingerprint and the engine-run label
   agree (additive enum; no behavior change to 6C.4/6D/6E/6F/Framework P1).
6. **Human approval + authorization required.** Capabilities are `network=True, active=True,
   requires_authorization=True, requires_human_approval=True, destructive=False`. The Control-Plane
   policy gate denies an unauthorized target (the provider never executes) and denies an unapproved
   active run.
7. **Offline-first, hermetic tests.** Absent `settings["allow_live"]`, the provider reads a snapshot
   and opens no socket, so CI is deterministic. Live work runs only behind `allow_live`, and only to
   the in-scope target the sandbox+egress permit.
8. **DNS is the verified IP only.** The only DNS fact recorded is the IP the connection actually
   resolved/used. MX/TXT/CAA and any resolver enumeration are deferred (the egress allowlist is bound
   to the target, so resolver traffic is out of scope here).

## Alternatives considered

- **Let the provider create/lookup the asset.** Rejected: a tool must never invent inventory or guess
  a binding. Ambiguity (0 or 2+) must degrade to Evidence-only, deterministically.
- **Make the Finding the success signal.** Rejected by the Evidence-first principle: evidence is the
  primary record; findings are derived and optional.
- **Reuse the self-sandboxing 6C.2 probe classes verbatim.** Rejected: nesting a fork-sandbox inside
  the framework's fork-sandbox; the rail already provides isolation, so the provider stays tiny.
- **Add MX/TXT/CAA / DNS enumeration now.** Deferred: outside a read-only web/TLS observer and in
  tension with the target-bound egress allowlist.

## Consequences

- The rail is proven end-to-end by a real, safe tool: authorize → scope → approval → DB-less sandbox
  → evidence → exact binding → Scan/ScanEngineRun → Finding → 6E graph → attack path.
- Evidence exists even when no asset binds, so an observation is never lost to a missing/ambiguous
  inventory — the platform can later reconcile it.
- 6C.4/6D/6E/6F/Framework Phase 1 are untouched; DB head stays `0009_phase6c_recon`.

### Deferred / technical debt

- Live network hardening for `allow_live` (rate limits, richer certificate chain facts).
- Backlinking an EvidenceItem to the Finding it justified (`EvidenceItem.finding_id` stays null in
  Phase 1 — evidence is persisted before, and independently of, any derived finding).
- MX/TXT/CAA / verified-DNS beyond the connection IP; object-storage artifacts for raw captures.
- Everything already deferred by ADR-011…016.
