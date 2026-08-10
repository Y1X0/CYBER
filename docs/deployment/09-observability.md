# 09 — Observability (Freeze-respecting)

> Deployment Readiness · Phase 9. Discovery finding **D-17** (no metrics/error-tracking) requires a
> new dependency + code (`/metrics`, Sentry, OTel) and is therefore **Freeze-gated** — deferred to a
> future, explicitly-approved change. This phase delivers everything achievable **without any code or
> dependency change**: structured logs, a log-shipping contract, health signals, audit logs, and an
> alerting runbook.

## 1. What already exists (use it)

| Signal | Where | Notes |
|--------|-------|-------|
| **Structured JSON logs** | `packages/common/src/guardian_common/logging.py` | structlog → JSON, ISO timestamps, log level, contextvars merge. Emitted to stdout (one JSON object per line). |
| **Health signals** | `/health`, `/health/ready` | liveness + DB-readiness (docs 08). |
| **Immutable audit log** | `audit_log` table + DB trigger `audit_log_no_mutation` (migration `0010`) | append-only; UPDATE/DELETE are blocked at the database. `record_audit()` writes scan, auth, and gate events. |
| **Usage records** | `usage_records` table | per-scan metering. |

## 2. Log-shipping contract (no code change)

> **Log hygiene (accurate scope).** The primary control is **not logging secret values** — the app
> logs safe structured keys, not raw credentials. `logging.py` additionally runs a *best-effort*
> scrub that redacts the single token immediately following a `authorization|api_key|token|password|
> secret` `=`/`:` inside a string message. It is a backstop, **not a guarantee**: it does not redact
> a structured secret kwarg (`log.info("x", password=…)`) or a space-separated token
> (`authorization=Bearer <token>` leaves `<token>`). Do not rely on it — rely on not logging
> secrets. Strengthening the scrubber is a code change (Freeze-gated, P3 future).

Logs go to **stdout as one JSON object per line** — the 12-factor contract. Ship them with an
infra-level collector, not application code:

- **Compose / VM:** a logging driver (`json-file` + a forwarder, or `fluent`/`journald`) or a
  sidecar (Vector / Fluent Bit) tailing container stdout → your log store.
- **Kubernetes:** the node log agent (Fluent Bit / Vector / the cloud provider's agent) collects pod
  stdout → your log store.

Required fields already present per line: `timestamp`, `level`, `event`, plus event-specific keys.
Recommended index fields: `level`, `event`, and any `tenant`/`scan_id`/`customer` present.

> **Stop point:** the destination log store + retention are an external service/provider decision
> (not in this repo). The contract (JSON stdout, scrubbed) is satisfied by the app today; wiring the
> collector is an operator step.

## 3. Deployment log expectations (what "healthy" looks like)

| Phase | Expected log evidence |
|-------|-----------------------|
| migrate job | alembic upgrade lines; exit 0 |
| seed job | `seed_complete` event; exit 0 |
| api start | uvicorn startup; RLS role check passes (no `RLS-bypassing role` error) |
| worker start | Celery `ready`; queue = `default`/`recon`/`tools` as expected |
| steady state | `scan.completed`, `scan.engine.*`, audit events; no repeated tracebacks |

A boot that violates a startup invariant (Phase 1) logs a `ValueError` from
`_enforce_production_invariants` and the process exits — that is the intended fail-fast, and your
alerting should treat a crash-looping api/worker as a config error first.

## 4. Alerting runbook (thresholds to wire in your platform)

| Alert | Signal source | Suggested threshold | First response |
|-------|---------------|---------------------|----------------|
| API down | `/health` failing / container unhealthy | 2 consecutive failures | check crash logs for a config `ValueError` (Phase 1) |
| API not ready | `/health/ready` failing | > 1 min | DB reachability / TLS / credentials |
| Migration/seed job failed | job exit ≠ 0 | any | inspect job logs; deploy is fail-closed (api won't start) |
| Worker not consuming | `celery inspect ping` failing | 2 consecutive | broker (Redis) reachability / AUTH |
| Redis memory pressure | Redis `used_memory` vs `maxmemory` | ≥ 80% | scale Redis; `noeviction` means writes will fail, not evict (docs 06) |
| Redis down | `redis-cli ping` | any | queued jobs pause; AOF preserves them (docs 06) |
| Auth abuse | repeated `429` / login-limit events in logs | spike | confirm `TRUSTED_PROXY_COUNT`; investigate source IP |
| Backup failure | `pg_backup.sh` exit ≠ 0 | any | DR risk — fix before it compounds (docs 05) |
| Cert expiry | ingress cert `notAfter` | < 14 days | renew + reload nginx (docs 03) |

## 5. Future (Freeze-gated — needs explicit approval)

Metrics (`/metrics` + prometheus-client), distributed tracing (OTel), and error tracking (Sentry)
each add a dependency and code. They are **out of scope** until the Freeze is lifted for that
specific addition. Until then, logs + health + audit + the alert table above are the observability
surface.

## 6. Verification

```bash
# Logs render as one JSON object per line (the shipping contract):
python -c "
from guardian_common.logging import configure_logging, get_logger
configure_logging('INFO'); get_logger('t').info('scan.completed', scan_id='abc', status='ok')
" | python -c "import sys,json; json.loads(sys.stdin.read()); print('JSON log line OK')"
# NOTE: the scrubber is a partial backstop (see §2) — the real control is not logging secrets.
```
