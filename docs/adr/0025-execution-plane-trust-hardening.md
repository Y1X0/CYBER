# ADR-025 — Phase C: execution-plane trust hardening (signed jobs + non-downgradable backend)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Discovery 0025 found the P0 that made everything else bypassable: `run_tool(job_wire)` trusted the
queue message. Anyone able to enqueue on the `tools` queue could **skip all Phase A/B governance and
forge the scope** — and because the uid+nft egress allowlist is built FROM the job's scope, a forged
job could point the kernel isolation at any destination, or set `_execution_backend="inproc"` to run
an external binary with no confinement. Authenticity had to be established before any execution work.

## Decision (CTO-locked, P0 only)

1. **Asymmetric job signing (Ed25519, no new dependency — `cryptography` is already a dep).**
   - The **trusted dispatcher holds the private key only** and signs a canonical serialization of the
     **entire job wire** (tenant, actor, tool, scope, targets, ports, protocols, campaign/approval
     context, allow_live, backend, every setting) plus `issued_at` / `expires_at` / a unique `nonce`.
   - The **tool plane holds the public key only** and can never mint a valid job, even if fully
     compromised. Signing the *whole* wire means no security-relevant field lives outside the signed
     payload — any change flips the signature.
   - Keys are base64 raw Ed25519 via config (`GUARDIAN_JOB_SIGNING_PRIVATE_KEY` / `_PUBLIC_KEY`); a
     fixed dev keypair is derived only in local/dev, refused elsewhere. The private key must never
     reach the tool plane, the queue, a job, or logs.
2. **`run_tool` verifies first, executes never-before.** It authenticates the envelope (signature +
   expiry + replay) with the public key **before** reconstructing the job, choosing a backend,
   building nft rules, or running a provider. Any failure → refuse (return no evidence). A
   fabricated/tampered/expired/replayed message is rejected at the door.
3. **Replay protection without migration.** A bounded in-memory nonce cache (per process, entries
   expire at the job's `expires_at`) rejects a re-used nonce; combined with a short TTL (300 s) and
   Celery's single-delivery semantics. **No persistent storage, no schema.** (Limitation below.)
4. **Isolation backend is not downgradable from the job (P0-2).** An external-binary provider
   declares `external_binary = True` (trusted provider code); `execute_tool` **forces** it onto the
   `uid_nft` kernel-isolation backend regardless of `settings["_execution_backend"]`. Even a valid
   signed job cannot lower Nmap to `inproc`.

Security ordering (now enforced): untrusted message → authenticity → expiry/replay → trusted job
reconstruction → forced/trusted backend → kernel isolation → provider. **The kernel allowlist is
never built from an unverified wire scope.**

## Proven (tests, no DB/network)

Signed valid job → accepted & executes; unsigned, and any tampered field
(tenant/actor/scope/targets/ports/protocols/campaign/approval/allow_live/backend, and the
issued/expires/nonce envelope) → rejected; expired → rejected; replayed nonce → rejected; a
hand-fabricated `run_tool` message → **refused before the provider runs**; a public-key-only plane
**cannot sign**; an external-binary provider is **forced to uid_nft even when the job says inproc**.

## Alternatives considered

- **Shared HMAC secret.** Rejected (per the CTO): a tool plane holding the secret could mint jobs.
  Ed25519 gives the tool plane verify-only power.
- **A new crypto dependency.** Unnecessary — `cryptography>=42` (Ed25519) is already present.
- **Persistent (Redis/DB) nonce store.** Deferred: would add infra/schema; the bounded in-memory
  cache + short TTL + single-delivery queue is adequate for v1 (limitation documented).

## Consequences

- No execution path bypasses governance, and isolation can never be downgraded by a job. The
  governance (Phase A/B) and the kernel egress isolation (ADR-024) are now both actually enforceable.
- 6C.4/6D/6E/6F, Providers #1/#2/#3, Nmap, Phase A/B, Evidence chain, World Model, Attack Graph, RLS
  unchanged; DB head stays `0010_phase_b_governance`; no new dependency.

### Residual / deferred

- **Cross-process replay within the TTL window:** the nonce cache is per-process, so a replay to a
  *different* worker replica inside the ≤300 s window is bounded by expiry but not deduplicated across
  processes. A shared nonce store (Redis) would close it — deferred (no migration now). With
  `--concurrency=1` and Celery single-delivery, the practical window is small.
- **Key management / rotation** (KMS-backed signing key, rotation, per-environment keys) — operational
  hardening, deferred.
- Everything deferred by ADR-011…024 (P1: offline/live lane split, IP resolve-and-pin, periodic
  reaper; P2: NET_ADMIN sidecar, gVisor/microVM) stands.
