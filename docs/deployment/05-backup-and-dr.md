# 05 — Database Backup & Disaster Recovery

> Deployment Readiness · Phase 5. Fixes discovery findings **D-06 / D-18 / D-19** (no backups, no
> DR/rollback runbook). Provider-neutral: managed PITR is the recommended primary; the
> `infra/scripts/pg_backup.sh` / `pg_restore.sh` logical dumps are the portable baseline.

## 1. What must be protected

| Asset | Store | Recovery mechanism |
|-------|-------|--------------------|
| Relational state (tenants, findings, evidence chain, audit log, credentials-at-rest) | PostgreSQL | Backups + PITR (this doc) |
| Queue / results / replay-nonce store | Redis | Not a system of record — see `docs/deployment/06-redis-celery.md` (durability, not backup) |
| Generated reports / artifacts | See `docs/deployment/07` note + §6 below | Object store snapshot / re-generation |

## 2. Backup strategy (two tiers)

1. **Managed PITR (recommended primary).** Enable the managed Postgres provider's automated
   backups + continuous WAL archiving (point-in-time recovery). Target **RPO ≤ 5 min**.
2. **Logical dumps (portable baseline / second copy).** `infra/scripts/pg_backup.sh` writes a
   verified, compressed custom-format dump and prunes by `GUARDIAN_BACKUP_RETENTION_DAYS`
   (default 14). Schedule it (cron / systemd timer / K8s CronJob), e.g. every 6 h, and ship the
   dumps off-host to an object store with its own retention + encryption.

> **Stop point (external provisioning):** the object-store bucket, the managed-DB PITR toggle, and
> off-host retention require a provider account + credentials that are **not** in this repo. The repo
> ships the scripts + the runbook (the contract); provisioning the destination is an operator step.

## 3. Retention · RPO · RTO (targets — operator-tunable)

| Objective | Reference target | How it's met |
|-----------|------------------|--------------|
| **RPO** (max data loss) | ≤ 5 min | managed WAL/PITR; logical dumps bound the *baseline* RPO to the dump interval (6 h) |
| **RTO** (max downtime) | ≤ 60 min | restore latest base + replay WAL, or `pg_restore` the newest dump, then roll API |
| **Retention** | 14 days logical + provider PITR window | `GUARDIAN_BACKUP_RETENTION_DAYS`; provider policy |

Set the real numbers to your business requirement; the platform imposes no lower bound.

## 4. Restore procedure

```bash
# A. Managed PITR: use the provider console/CLI to restore to a timestamp (fastest, lowest RPO).

# B. Logical dump restore into a fresh/target instance:
export GUARDIAN_DATABASE_URL='postgresql+psycopg://guardian:<pw>@<host>:5432/guardian?sslmode=verify-full'
export GUARDIAN_RESTORE_CONFIRM=yes
./infra/scripts/pg_restore.sh /var/backups/guardian/guardian-<ts>.dump

# C. Post-restore checks (ALWAYS):
alembic current                       # → 0011_web_checks_catalog (schema head intact)
#   If restoring into a brand-new instance, (re)set the RLS role password (docs 02 §3):
#   ALTER ROLE guardian_app WITH PASSWORD '<GUARDIAN_APP_DB_PASSWORD>';
#   Then bring up API replicas; /health/ready must return database: ok.
```

**Restore drills are mandatory** — an untested backup is not a backup. Run a quarterly restore into a
scratch instance and record the measured RTO.

## 5. Rollback procedures

| Scenario | Action |
|----------|--------|
| Bad application release | Redeploy the previous pinned image digest (Phase 7). No DB change if the schema didn't move. |
| Bad **migration** | `alembic downgrade <prev_rev>` — every migration ships a real `downgrade()` (verified, docs 02 §2). **Caveat:** a downgrade that drops columns/tables is data-lossy; on a destructive migration, restore from backup (§4) instead of downgrading. |
| Data corruption | PITR to just before the corrupting event (§4A), or logical restore (§4B). |

**Migration rollback strategy:** deploy migrations as the one-shot `migrate` job (Phase 2) *before*
rolling the new API image. If the `migrate` job fails, the new API never starts (it gates on job
completion), so a failed migration cannot leave replicas serving against a half-migrated schema —
fix forward or `alembic downgrade` to the last-good revision, then redeploy.

## 6. Reports / artifacts (verify before launch — D-27)

Generated PDF reports (reportlab) and tool evidence are produced on the control plane. Confirm where
your deployment persists them (DB blob vs mounted volume vs object store) and include that store in
the backup scope, **or** rely on re-generation from the retained findings. This is a
per-deployment verification item, not a code gap.

## 7. Verification

```bash
bash -n infra/scripts/pg_backup.sh infra/scripts/pg_restore.sh   # shell syntax
# End-to-end drill (scratch db): pg_backup.sh → pg_restore.sh into a throwaway → alembic current.
```
