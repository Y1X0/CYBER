# 10 — Production Launch Runbook

> Deployment Readiness · Phase 10. The end-to-end cutover procedure. Follow top-to-bottom; each step
> links to its detailed phase doc. **No secret appears in this document** — all values come from your
> git-ignored `.env.production` / secrets manager.

## Pre-flight (once)

- [ ] Security baseline confirmed at commit `0a3eb4f` (Production Security GO).
- [ ] **Frozen preconditions honoured:** semgrep NOT installed; tool-execution NOT wired to the API.
- [ ] A pinned application image exists: `GUARDIAN_IMAGE=<registry>/<name>@sha256:<digest>` (docs 07).

## 1. Secrets provisioning — docs 01
- [ ] `cp .env.production.example .env.production`; fill every `CHANGE_ME` with a CSPRNG value.
- [ ] `ENCRYPTION_KEY`, `BROKER_SEAL_KEY`, `JWT_SECRET` all distinct; `BROKER_SEAL_KEY ≠ ENCRYPTION_KEY`.
- [ ] Bootstrap admin password non-default (checked on **every** plane).
- [ ] Ed25519 job-signing keypair generated; private key ONLY on control plane.
- [ ] Dry-run: `set -a && . ./.env.production && set +a && python -c "from guardian_common.config import Settings; Settings()"` → no error.

## 2. Database provisioning — docs 02
- [ ] Managed Postgres (recommended) or self-hosted db with TLS certs (docs 02 §4).
- [ ] `sslmode=verify-full` in both DSNs.
- [ ] Set the RLS role password out of band: `ALTER ROLE guardian_app WITH PASSWORD '<…>';`.

## 3. Redis provisioning — docs 06
- [ ] Managed Redis (TLS+AUTH) or self-hosted redis with `infra/redis/redis.conf` + certs.
- [ ] `GUARDIAN_REDIS_URL` is `rediss://` with a password. AOF persistence on.

## 4. Network setup — docs 04
- [ ] Plane isolation applied: execution planes can't reach db/api; db/redis not internet-published.
- [ ] K8s: `kubectl apply -f infra/k8s/networkpolicies.yaml` (fill cluster CIDRs) OR compose networks.

## 5. TLS / Ingress — docs 03
- [ ] Ingress certs in `./infra/tls/nginx` (or managed LB cert).
- [ ] `GUARDIAN_TRUSTED_PROXY_COUNT` = real XFF-appending hop count.
- [ ] `GUARDIAN_CORS_ORIGINS` = production dashboard origin(s).

## 6. Image verification — docs 07
- [ ] `docker inspect --format '{{.Config.User}}' $GUARDIAN_IMAGE` → `guardian` (non-root).
- [ ] No `GUARDIAN_*` baked into the image env.
- [ ] Trivy/pip-audit reviewed for the release.

## 7. Migration job — docs 02 / 08
- [ ] `docker compose --env-file .env.production -f docker-compose.prod.yml run --rm migrate`
      (or the K8s migrate Job). Must exit 0. `alembic heads` → `0011_web_checks_catalog`.

## 8. Seed job — docs 02
- [ ] `... run --rm seed`. Must exit 0 (`seed_complete`). Idempotent — safe to re-run.

## 9. API deployment — docs 08
- [ ] `... up -d api` (replicas start only after seed completed).
- [ ] `... up -d ingress`.

## 10. Worker deployment — docs 04 / 08
- [ ] `... up -d worker-default worker-recon worker-tools`.
- [ ] Confirm each worker consumes its queue (`default` / `recon` / `tools`) and holds only its
      allowed secrets (recon: none; tools: seal + public key).

## 11. Health / readiness verification — docs 08
- [ ] `curl -fsS https://<host>/health` → ok; `.../health/ready` → database ok.
- [ ] All containers `healthy`; workers answer `celery inspect ping`.

## 12. Smoke tests
- [ ] Log in as the bootstrap admin; token issued.
- [ ] Audit log recorded the login with the **real client IP** (validates `TRUSTED_PROXY_COUNT`).
- [ ] Create a customer + asset; run a passive scan; findings appear; deployment gate evaluates.
- [ ] `/docs` reachable only as intended; HTTP→HTTPS redirect works.

## 13. Backup verification — docs 05
- [ ] `./infra/scripts/pg_backup.sh` produces a verified dump; schedule enabled.
- [ ] Restore drill into a scratch instance succeeded; measured RTO recorded.

## 14. Rollback procedure — docs 05 §5
- [ ] Bad app release → redeploy previous image digest.
- [ ] Bad migration → `alembic downgrade <prev>` (or restore from backup if data-lossy).
- [ ] Keep the last-good `GUARDIAN_IMAGE` digest + a fresh backup pointer handy before cutover.

## 15. Incident procedure — docs 09 §4
- [ ] Alerts wired (API/worker/Redis/backup/cert/auth). On-call knows the alert table.
- [ ] First response for a crash-loop: check logs for a Phase-1 config `ValueError` (fail-fast).
- [ ] Escalation + comms path documented for your org.

---

### Go / No-Go
**GO** when steps 1–13 are green and 14–15 are rehearsed. Any failed startup invariant (Phase 1) or a
red migrate/seed job is a **No-Go** — the deploy is fail-closed by design; fix the flagged config and
re-run. Never weaken a guardrail to force a launch.
