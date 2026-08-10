# 06 — Redis / Celery Resilience

> Deployment Readiness · Phase 6. Fixes discovery finding **D-07** (no Redis persistence) and
> documents the durability + replay-nonce semantics. **The security rail is unchanged** — TLS + AUTH
> stay exactly as enforced by `config.py`; this phase only adds durability + operational clarity.

## 1. TLS + AUTH (unchanged, enforced)

Redis carries the broker, the result backend, and the **replay-nonce store**. Outside local/dev the
platform refuses to boot unless `GUARDIAN_REDIS_URL` is `rediss://` (TLS) **and** carries AUTH
credentials (`config.py:239-252`). All three clients (Celery broker, result backend, redis-py nonce
store) derive from that one URL.

- **Managed Redis (recommended):** terminates TLS + enforces AUTH/ACL for you.
- **Self-hosted (reference):** AUTH via the compose `--requirepass` (secret, not in the conf); TLS by
  uncommenting the `--tls-*` flags with operator certs in `./infra/tls/redis`.

## 2. Persistence (D-07)

`infra/redis/redis.conf` enables **AOF** (`appendonly yes`, `appendfsync everysec`) plus RDB
snapshots, on a persistent `redis-data` volume. Two consequences that matter:

| Without persistence | With AOF (this config) |
|---------------------|------------------------|
| A restart drops all queued jobs | Bounded loss (~1 s of writes); queued jobs survive |
| A restart **resets the replay-nonce store** | Nonces survive → single-use enforcement persists across restarts |
| Results/backends lost | Preserved within `result_expires` |

`maxmemory-policy noeviction`: a broker/nonce store must **fail loudly** rather than silently evict a
queued job or a live nonce under memory pressure. Provision `maxmemory` to the container headroom and
alert at ~80%.

## 3. Job durability semantics (at-least-once)

From `workers/scanner/src/guardian_scanner/celery_app.py:63-83`:

| Setting | Value | Effect |
|---------|-------|--------|
| `task_acks_late` | `True` | Ack only after completion → a worker crash redelivers the task |
| `task_reject_on_worker_lost` | `True` | A lost worker's task is requeued, not silently dropped |
| `task_track_started` | `True` | Started state is observable |
| `task_time_limit` / `soft` | 1800 / 1500 s | Hard/soft caps bound a stuck job |
| `worker_max_tasks_per_child` | 50 | Recycle children (bounds leaks) |
| `result_expires` | 3600 s | Results TTL |

**Delivery semantics: at-least-once.** Tasks are idempotent by design (scans keyed per
`(scan_id, engine)` unique constraint; seed idempotent), so a redelivery re-converges rather than
duplicating. `acks_late` covers a **worker** crash; AOF (§2) covers a **broker** restart — the two
together give end-to-end durability.

## 4. Replay-nonce behaviour after a Redis restart

The execution-plane trust model verifies each signed job's single-use nonce with a Redis
`SET NX EX` (fail-closed in prod). The nonce key expires with the job's signed validity window.

- **With AOF (this config):** the nonce set survives a restart, so a captured job cannot be replayed
  even across a Redis bounce.
- **Without persistence:** a restart clears the nonce set; replay protection then falls back to the
  job's own signed-timestamp validity window until nonces repopulate. AOF closes that gap — hence
  persistence is a **durability requirement for the security rail**, documented here, not a code
  change.

## 5. Task routing (unchanged)

Plane isolation depends on the routing in `celery_app.py:74-82`: `run_discovery` /
`dispatch_tool_job` / `dispatch_artifact_job` → `default` (trusted); `recon_collect` → `recon`;
`run_tool` → `tools`. The DB-less execution planes consume only their queue, which is what lets them
hold no DB credentials.

> **Stop point:** managed-Redis durability class, HA/replication, and TLS termination are provider
> choices requiring an account. The repo ships the self-hosted reference + the requirements; the
> managed provisioning is an operator step.

## 6. Verification

```bash
# redis.conf boots and enables AOF + noeviction (native, throwaway dir/port):
redis-server infra/redis/redis.conf --dir /tmp/rtest --port 63799 --requirepass t --daemonize no &
redis-cli -p 63799 -a t CONFIG GET appendonly        # → yes
redis-cli -p 63799 -a t CONFIG GET maxmemory-policy  # → noeviction
redis-cli -p 63799 -a t shutdown nosave
```
