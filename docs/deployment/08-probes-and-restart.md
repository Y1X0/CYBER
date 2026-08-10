# 08 — Deployment Probes & Restart Policy

> Deployment Readiness · Phase 8. Fixes discovery finding **D-21** (no probes/restart wiring) and
> locks in the startup ordering from Phase 2.

## 1. Health endpoints (existing)

| Endpoint | Checks | Use as |
|----------|--------|--------|
| `GET /health` | process is up (no dependencies) | **liveness** — restart if it fails |
| `GET /health/ready` | process + `SELECT 1` on the DB | **readiness** — gate traffic; drop from LB if it fails |

Source: `services/api/src/guardian_api/routes/health.py:14-22`, mounted at the root
(`routes/__init__.py:24`).

## 2. Probe wiring (compose reference)

| Service | Restart | Healthcheck | Grace |
|---------|---------|-------------|-------|
| `api` | `unless-stopped` | `curl /health` (liveness — DB-independent) | 30 s |
| `worker-default` | `unless-stopped` | `celery inspect ping` | 120 s |
| `worker-recon` | `unless-stopped` | `celery inspect ping` | 120 s |
| `worker-tools` | `unless-stopped` | `celery inspect ping` | 120 s |
| `db` / `redis` | `unless-stopped` | `pg_isready` / `redis-cli ping` | — |
| `migrate` / `seed` | `no` (one-shot; must exit 0) | — | — |

Liveness uses `/health` (no DB) so a transient DB hiccup restarts nothing; **readiness** gating on
`/health/ready` belongs at the LB / orchestrator (the ingress and K8s probe below), so a DB-unready
replica is pulled from rotation without being killed.

## 3. Startup ordering & failure behaviour

```
db healthy ──▶ migrate (exit 0) ──▶ seed (exit 0) ──▶ api ×N + worker-default
                     │ nonzero            │ nonzero
                     ▼                     ▼
              deploy fails-closed:  api never starts (gates on service_completed_successfully)
```

- **API replicas never start before migrate+seed complete** — they `depends_on` the seed job's
  `service_completed_successfully` (Phase 2). No replica count can race migrations.
- **A failed migration fails the deploy closed:** `seed` won't run, `api` won't start, so no replica
  ever serves against a half-migrated schema. Fix forward or `alembic downgrade` (docs 05 §5), then
  redeploy.
- **Worker health:** `celery inspect ping` over the broker confirms the worker is consuming; a lost
  worker is safe because `task_acks_late` + `task_reject_on_worker_lost` redeliver its in-flight task
  (idempotent). `stop_grace_period` allows a warm drain; a hard stop is still safe.

## 4. Kubernetes probe mapping

```yaml
# API Deployment (readiness gates traffic; liveness restarts):
readinessProbe: { httpGet: { path: /health/ready, port: 8000 }, periodSeconds: 10 }
livenessProbe:  { httpGet: { path: /health,       port: 8000 }, periodSeconds: 10, failureThreshold: 3 }
startupProbe:   { httpGet: { path: /health,       port: 8000 }, failureThreshold: 30, periodSeconds: 2 }
# Ordering: migrate+seed as a Job (or Argo/Helm pre-install/pre-upgrade hook) that must reach
# Completed before the API Deployment rolls. Workers: exec `celery ... inspect ping` liveness.
terminationGracePeriodSeconds: 120   # workers; 30 for the API
```

## 5. Verification

```bash
docker compose --env-file <env> -f docker-compose.prod.yml config >/dev/null && echo "compose OK"
# after deploy:
docker inspect --format '{{.State.Health.Status}}' <api-container>   # healthy
curl -fsS https://<host>/health && curl -fsS https://<host>/health/ready
```
