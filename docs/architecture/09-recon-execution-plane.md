# Recon Execution Plane — isolation and production mapping (Phase 6C.3)

Active discovery reaches the public internet from inside our infrastructure. It runs in an isolated
**recon execution plane**, separate from the control plane (the API) and from the default execution
plane (scans/analysis). This document records the isolation model and how the local Compose
reference maps to production (Kubernetes). See ADR-011 for the decision record.

## The two defense layers

| Layer | What it does | Where it lives | Independent of |
|---|---|---|---|
| **Authorization Gate** | Decides *which* targets a run may probe, from DB-stored authorizations. Denials are audited before any network. | `guardian_scanner.discovery.authorization` (application logic) | — |
| **C1 — Network isolation** | The recon worker can reach only the DB + cache; never the API or the default worker. The control plane can never reach the recon plane. | Container/pod network membership | The gate |
| **C2 — Egress allowlist** | At the socket layer, a probe may connect only to the run's gate-cleared hosts; any other host (unauthorized target, internal service, metadata endpoint) is denied. | `guardian_scanner.egress` + the sandbox `create_connection` guard | The gate |

C1 and C2 are **defense in depth**: a bug in the gate does not, by itself, let a probe reach an
unauthorized or internal destination — C2 re-checks at runtime, and C1 removes the network path to
internal services entirely.

## Compose reference (`docker-compose.yml`)

Networks:

- `edge` — user-facing; only the API.
- `backend` — control plane + default work reach DB/cache here. The recon worker is **not** on it.
- `recon-data` — the **only** internal network the recon worker joins: DB + cache, nothing else.

Placement:

| Service | Networks | Reaches | Cannot reach |
|---|---|---|---|
| `api` (control plane) | `edge`, `backend` | DB, cache, users | recon worker (not on `recon-data`) |
| `worker-default` | `backend` | DB, cache | recon worker |
| `worker-recon` | `recon-data` | DB, cache (necessary paths), public internet (authorized probes) | API, default worker |
| `db`, `redis` | `backend`, `recon-data` | — (shared necessary services) | — |

Each worker also carries a container-level `mem_limit` + `cpus` ceiling, on top of the per-process
`setrlimit` inside the sandbox and the Celery `task_time_limit`.

## Production mapping (Kubernetes) — reference, not shipped in 6C.3

No manifests are built in this phase. The intended mapping:

- **Namespaces / labels.** Run `worker-recon` under its own label/namespace (e.g.
  `plane=recon`), distinct from `plane=control` (API) and `plane=default`.
- **NetworkPolicy (C1).** Default-deny ingress and egress for the recon plane, then allow only:
  - egress to the Postgres and Redis services (the necessary paths), and
  - egress to the public internet on 80/443 for authorized probes (paired with C2 at the app layer).
  - **No** egress to the control-plane API service or the default worker.
  - Correspondingly, deny the control plane any path into the recon namespace.
  Block the cloud metadata endpoint (e.g. `169.254.169.254/32`) explicitly at the NetworkPolicy /
  egress-gateway level, in addition to the C2 allowlist.
- **Egress controls (C2 in prod).** The `guardian_scanner.egress` allowlist enforces per-run host
  restriction in-process; at the cluster edge, pair it with an egress gateway / firewall that limits
  the recon plane's outbound reach. The two are complementary (app-layer per-run + infra-layer
  coarse).
- **Resource limits.** Set pod `resources.requests`/`resources.limits` (CPU + memory) mirroring the
  Compose `cpus`/`mem_limit`. Keep the Celery `task_time_limit` as the per-task wall-clock ceiling.
- **Credentials scope (until 6C.4).** The recon worker still holds DB credentials in 6C.3. 6C.4
  removes direct DB access from the execution plane (result-return), after which the recon plane
  needs no DB credentials and its NetworkPolicy can drop the DB egress rule entirely.

## Boundaries (unchanged in 6C.3)

Ports stay 80/443 (HTTP/TLS only). No change to the Authorization Gate, `ProtocolProbe` /
`ProbeEvidence`, RLS, provenance, deterministic scoring, exposure scoring, `node_events`, or AI. No
database migration.
