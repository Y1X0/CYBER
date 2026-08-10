# Production Deployment & Operational Readiness

Turns the **Production Security GO** (baseline `0a3eb4f`) into a **Production Deployable** platform.
Provider-neutral: the runnable reference is Docker Compose (`docker-compose.prod.yml`); Kubernetes
and managed-service mappings are documented, never forced. **No real secrets live in Git.**

The **Security Foundation stays FROZEN** — nothing here modifies security code, adds a dependency,
or adds a migration. Two frozen preconditions hold throughout: semgrep is not installed, and
tool-execution is not wired to the API.

## Documents

| # | Doc | Covers | Fixes (discovery) |
|---|-----|--------|-------------------|
| 01 | [Secrets & Environment](01-secrets-and-environment.md) | `.env.production` contract, invariant matrix, per-plane vars | D-01 |
| 02 | [Database](02-database.md) | migrate/seed one-shot ordering, determinism, RLS role password | D-03, D-04 |
| 03 | [Ingress / TLS](03-ingress-tls.md) | nginx TLS termination, XFF, body cap, uvicorn not public | D-11, D-12, D-13 |
| 04 | [Network Topology](04-network-topology.md) | plane isolation, K8s NetworkPolicy reference, egress model | D-10 |
| 05 | [Backup & DR](05-backup-and-dr.md) | backups, PITR, RPO/RTO, restore, rollback | D-06, D-18, D-19 |
| 06 | [Redis / Celery](06-redis-celery.md) | AOF persistence, durability, replay-nonce-after-restart | D-07 |
| 07 | [Build & Release](07-build-release.md) | image pipeline, SBOM, scans, digest, configurable registry | D-20 |
| 08 | [Probes & Restart](08-probes-and-restart.md) | liveness/readiness, graceful stop, ordering | D-21 |
| 09 | [Observability](09-observability.md) | JSON logs, audit, alerting runbook (no new deps) | D-17 (partial; metrics Freeze-gated) |
| 10 | [Launch Runbook](10-launch-runbook.md) | the 15-step cutover procedure | — |

## Reference artifacts

| Path | What |
|------|------|
| `docker-compose.prod.yml` | Production topology (migrate→seed→api, ingress, plane isolation, probes) |
| `.env.production.example` | Configuration contract template (no secrets) |
| `infra/nginx/guardian.conf` | Ingress reverse-proxy config |
| `infra/redis/redis.conf` | Redis durability config |
| `infra/k8s/networkpolicies.yaml` | Portable K8s plane-isolation reference |
| `infra/scripts/pg_backup.sh` · `pg_restore.sh` | Backup / restore helpers |
| `infra/tls/README.md` | Operator cert-placement contract |
| `.github/workflows/release.yml` | Build/scan/publish pipeline |
| `.dockerignore` | Keeps secrets/junk out of image layers |

## External stop points (operator / provider decisions — not in repo scope)

Secrets-manager choice · managed DB/Redis provisioning + PITR · TLS certificate issuance · object
store for backups · container registry credentials · the K8s cluster + CIDRs. Each is called out in
its phase doc. The repo ships the contract and the provider-neutral reference; provisioning the
external service is the operator's step.
