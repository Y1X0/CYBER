# ADR-013 — Phase 6C.4: Recon result-return (no DB in the execution plane)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

A read of the recon plane (ADR-011) surfaced a real, cross-tenant escalation concentration:

1. **The plane that touches untrusted network held owner DB credentials.** `worker-recon` used the
   `guardian` owner URL (RLS-bypassing) and `run_discovery` kept a DB session open across
   `provider.collect()` — the step that runs probes against attacker-influenced targets.
2. **The sandbox child inherited the parent's DB descriptor.** `run_in_sandbox` forks; the child only
   closed the result pipe's read end. A fork copies the descriptor table, so a probe child inherited
   the parent's open Postgres socket. `RLIMIT_NOFILE` caps only *new* descriptors and the egress
   guard only covers `create_connection`, so neither stopped a probe from reusing that connection.
   Chained with an RCE in probe code (e.g. parsing a hostile TLS certificate), this yields owner,
   cross-tenant DB read/write that bypasses both RLS and the egress allowlist.

Low probability (the probes are request-less), critical impact (cross-tenant). It became a
blocking hardening before expanding graph capability (6E), not a deferrable debt.

## Decision

**Split discovery into two tasks across two planes so the network-facing plane is architecturally
incapable of DB access (result-return).**

- **`run_discovery` — trusted orchestrator (`default` queue, DB).** Loads the run, runs the
  authorization gate (DB) and audits denials, dispatches collection, then persists the returned
  evidence via the existing ingestor. It holds **no open DB session while probes run** (auth commits
  and closes; collection runs; a fresh session persists).
- **`recon_collect` — recon plane (`recon` queue, NO DB).** Receives only gate-cleared targets +
  settings, runs providers/probes inside the sandbox + egress allowlist, and **returns structured
  evidence** (`DiscoveredAsset` wire dicts). It never imports or opens a DB session.

**Why authorization moved to the trusted plane (deviation from the literal 6C.4 scope diagram).** The
gate reads the `authorizations` table, so it cannot live on a plane that has no DB. The primary goal
("recon plane has no DB credentials") therefore *requires* authorization to run in the trusted
orchestrator, which then hands only cleared targets to the recon plane. Consequently the pinning
guard applies to **both** tasks: `recon_collect` refuses to run off the recon plane and
`run_discovery` refuses to run on it (`GUARDIAN_RECON_PLANE`), so a misroute in either direction fails
loudly. This preserved every existing 6C test unchanged (auth + denial audit still happen in
`run_discovery`).

**Trust boundary.** Untrusted network ↔ trusted DB is now a process/queue/network boundary:

```
API (control plane, DB)  --send_task-->  run_discovery (default, DB)
        │ authorize (DB) + audit denials
        │ dispatch cleared targets ─────►  recon_collect (recon, NO DB, no DB route)
        │                                     probes → ProbeEvidence → return
        └ persist evidence (DB) ◄──────────  evidence (result-return)
```

**Execution hardening (same plane):**
- **Inherited descriptors are closed in the sandbox child** (keep only stdio + result pipe), so an
  inherited connection is unusable regardless of credentials.
- **`RLIMIT_NPROC`** in the sandbox + **`pids_limit`** on the recon container contain a fork-bomb
  without destabilizing the parent worker.
- **Egress allowlist moved from a module global to a `ContextVar`**, so it cannot leak across
  concurrent tasks/threads; deny-all-when-empty, SSRF/DNS-rebinding protection, and IP pinning are
  unchanged.

**Deployment (Compose reference).** `worker-recon` holds no DB URL (`GUARDIAN_DATABASE_URL=""`) and
joins only `recon-cache` (the redis broker) — the database is on `backend` only, so the recon plane
has **no network route to the DB**. Credentials-absent + route-absent = architecturally DB-incapable.

**No migration.** Evidence flows over the Celery result backend (redis); no schema change. DB head
stays `0009_phase6c_recon`.

## Alternatives considered

- **Keep authorization in the recon task.** Impossible under the primary goal — the gate needs the DB.
- **Move authorization into the API request path.** Would work, but it breaks the 6C test suite (which
  drives `run_discovery` directly by `run_id`) and is a larger change; rejected for minimal churn.
- **Rely only on closing inherited FDs (keep DB creds in recon).** Rejected: defense-in-depth wants
  the plane to be DB-incapable, not merely to close one hole.
- **A Celery chord/chain instead of `apply_async().get()`.** The blocking orchestrator is simplest and
  parity-preserving; a non-blocking chord is a deferred refactor (the `.get()` is cross-queue, so no
  self-deadlock).

## Consequences

- The plane that touches untrusted network can reach neither the DB (no creds, no route) nor an
  inherited connection (closed) — the cross-tenant escalation path is removed.
- A misroute of either task fails loudly (`GUARDIAN_RECON_PLANE`), so the split can't silently
  degrade.
- Graph/node/edge/event semantics, RLS, provenance, scoring, exposure, the authorization gate, the
  probe contracts, and the 6D read plane are all unchanged — the same evidence, persisted the same
  way; only *where* the work runs changed.
- Under Celery eager mode (tests) both tasks run in one process, so the pinning guard is skipped and
  the FD-closing still runs (closing the pooled DB descriptor in probe children) — the guarantee is
  exercised even in tests.

### Deferred / technical debt (documented, not in 6C.4)

- **Raw-socket / native-code egress** that bypasses `create_connection` — closed by a per-run
  container/seccomp backend (parallel infra track), unchanged here.
- **Non-blocking orchestration** (chord/chain) instead of the orchestrator's blocking `get()`.
- Everything already deferred by ADR-011/012 (6E finding nodes + exposes/enables, netblock/cloud
  nodes, node-event enrichment, historical snapshots, graph-loader scalability).
