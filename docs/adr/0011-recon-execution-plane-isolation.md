# ADR-011 — Phase 6C.3: Recon execution-plane isolation

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Active discovery (Phase 6C) reaches the public internet from inside our infrastructure. Until now
the only thing standing between a discovery run and an arbitrary destination was the **Authorization
Gate** (`guardian_scanner.discovery.authorization`) — application logic that decides which targets a
run may probe. That gate is necessary but, on its own, insufficient for a security product:

1. **It is a single logical layer.** A bug that let an unauthorized target past the gate would open a
   socket to it, with nothing else to stop it. Evidence-grade defense wants a second, *independent*
   layer at the runtime.
2. **The recon worker shared a process and network with everything else.** One worker consumed both
   the `default` (scans/analysis) and `recon` (active discovery) queues, and sat on the same network
   as the control-plane API. Code that reaches untrusted external hosts should not also be able to
   reach our internal services (the database, the cache, the API, a cloud metadata endpoint).
3. **Resource limits were per-process only.** The Phase-5 sandbox applies `setrlimit` inside the
   forked child, but there was no container-level ceiling on the recon worker as a whole.

This is the Control Plane / Execution Plane separation principle made concrete for recon, without
touching the gate, the protocol-plugin architecture, RLS, provenance, scoring, or exposure.

## Decision

**Two independent layers of defense in depth, plus worker separation and resource ceilings.**

**C1 — Network isolation (infrastructure).** Split the single worker into two: `worker-default`
(consumes `default`) and `worker-recon` (consumes `recon`). The recon worker joins **only** an
internal `recon-data` network carrying the database and cache — the two *necessary* shared services
— and is **not** on the `backend` network. The control-plane API is on `edge` + `backend` and
**never** on `recon-data`. Consequences, structural (not code-enforced): the recon plane cannot
reach the API or the default worker, and the control plane cannot reach the recon plane; the only
overlap is the shared DB/cache. `docker-compose.yml` is the runnable reference; production maps it to
Kubernetes NetworkPolicy (see `docs/architecture/09-recon-execution-plane.md`).

**C2 — Egress allowlist (runtime).** A new `guardian_scanner.egress` module holds a process-wide
allowlist, bound by the recon task to *exactly* the hosts the Authorization Gate cleared for the run
(`_egress_hosts(allowed)`), for the duration of active providers only, and restored afterwards. The
Phase-5 sandbox, when network-permitted work runs and an allowlist is active, installs a guard at
`socket.create_connection` — the chokepoint the protocol probes use — that re-checks the destination
host against the allowlist and raises `PermissionError` for anything else. This is **independent of
the gate**: it does not trust the orchestrator's target selection; it re-derives the permitted set
and enforces it at the socket layer. An unauthorized target, or an attempt to reach an internal
service from a probe, is blocked here even if it slipped past the gate. Empty allowlist = deny-all,
never allow-all.

**Control plane stays socket-free.** The API enqueues by task **name** (`send_task`, ADR-003) and
never imports the worker package, so it neither runs a probe in-process nor reaches the recon plane.
This is now asserted by a test that imports the API in a clean subprocess.

**Resource ceilings.** Both workers get container-level `mem_limit` + `cpus` on top of the
per-process `setrlimit` and the Celery `task_time_limit`.

**Direct DB access is retained for 6C.3.** The recon worker still writes graph results to Postgres
directly, over the one necessary `recon-data` path. Removing direct DB access from the execution
plane (a result-return architecture) is deliberately deferred to 6C.4.

No database migration, and no change to: the Authorization Gate, `ProtocolProbe`/`ProbeEvidence`,
RLS, provenance, deterministic scoring, exposure scoring, `node_events`, or AI. Ports stay 80/443
(HTTP/TLS only).

## Alternatives considered

- **Rely on the Authorization Gate alone.** Rejected: a single logical layer is not defense in depth;
  a security product must contain a gate bug at the runtime, not just in code review.
- **Result-return execution plane now (no direct DB from recon).** The stronger end state — the recon
  worker returns structured evidence that a trusted in-network worker persists, so the execution
  plane needs no DB credentials or DB path at all. Deferred to 6C.4 to keep 6C.3 focused on isolation
  without reworking the ingestion path.
- **Per-probe container / seccomp / network namespace.** The production-grade containment the sandbox
  docstring already anticipates. Deferred: heavier operational surface; the create_connection guard
  plus network isolation is the right increment now. The residual (raw-socket egress that bypasses
  `create_connection` from hostile native code) is unchanged from the existing Python-level guard and
  is what the container backend closes.
- **Enforce the allowlist at the low-level `socket.connect` (resolved IP).** Rejected: an authorized
  *domain* resolves to an IP not in a host-string allowlist, so guarding the resolved address would
  break legitimate domain probes. The probes' sole egress path is `create_connection`, so that is the
  correct, non-breaking chokepoint.

## Consequences

- Discovery/active-recon now runs in a network-isolated worker whose external egress is constrained,
  at the socket layer, to the run's authorized hosts — independent of the gate.
- The control plane is provably worker-free and does not open external sockets.
- Tenant isolation (RLS), provenance, scoring/exposure, and all 6C behavior are unchanged; the egress
  wrapping is behavior-neutral (the full 6C active-discovery suite passes untouched).
- The allowlist is process-wide, so it assumes one active-recon task per process at a time — true
  under Celery prefork, where each worker child runs a single task. Documented; revisited if the
  recon worker ever moves to a threaded pool.

### Deferred debt (tracked for follow-up phases)

- **6C.4 — result-return / no direct DB from the execution plane.** Remove DB credentials and the DB
  path from the recon worker; it returns evidence that a trusted worker persists.
- **Per-probe / container isolation.** OS namespace + seccomp or a container per run behind the same
  sandbox seam, closing the raw-socket residual.
- **Dynamic per-run egress derived from discovered assets.** Today the allowlist is derived from the
  run's authorized targets; a future version derives it from the resolved discovered nodes.
- **Link active targets to 6B discovered nodes** instead of manual `active_targets` seeds.

## Update — 6C.3.1: SSRF / DNS-rebinding micro-fix (applied)

A read-only security review of this plane found an active gap the original decision did not cover:
the egress allowlist authorized a *hostname* and checked it *before* DNS resolution, so an authorized
domain could resolve — or be rebinded — to a private/loopback/link-local/reserved/metadata address
that C1's network isolation does not IP-filter (C1 gates service reachability by name, not egress by
IP). Impact was bounded (the current probes send no request, so this was internal-service enumeration
/ TLS-cert disclosure, not credential theft), but SSRF is foundational for a security product, so it
was closed before 6D.

The fix lives entirely inside the `create_connection` egress guard (`_resolve_public_address` in
`guardian_scanner.sandbox`): a listed *hostname* is resolved, the connection is rejected if **any**
resolved address is internal (defeating a multi-record rebind), and the connection is then **pinned**
to the validated public IP so the real connector cannot re-resolve to a different address
(TOCTOU-safe). An IP literal that is itself on the allowlist is honored as-is — a deliberately
authorized internal target is a valid operator choice. No change to the authorization gate,
`ProtocolProbe`/`ProbeEvidence`, the probes, RLS, provenance, scoring/exposure, the sandbox fork/limit
architecture, the Docker topology, or the Celery queues; no migration.

Still deferred (unchanged): raw-socket/native-code egress that bypasses `create_connection` (closed
by the per-probe container/seccomp backend), `RLIMIT_NPROC`/`pids_limit`, hard-binding
`run_discovery` to the recon worker, the ContextVar allowlist for non-prefork pools, and 6C.4
result-return.
