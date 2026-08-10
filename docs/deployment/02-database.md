# 02 — Database Production Deployment

> Deployment Readiness · Phase 2. Enforces the migrate/seed-as-one-shot-step separation that the
> design already anticipated (dev compose comment: *"Dev convenience; production separates these
> steps."*) and pins the `guardian_app` role production authentication contract. **No schema
> change** — migrations are frozen at head `0011_web_checks_catalog`.

## 1. The ordering problem it fixes (discovery finding D-04)

The dev compose runs `alembic upgrade head && python -m guardian_api.seed && uvicorn …` as the API
boot command. With N API replicas that races the migration and the seed on every rollout.

Production splits it into **one-shot jobs that run to completion first**:

```
migrate  (alembic upgrade head)            restart: "no"   depends_on db healthy
   │  service_completed_successfully
   ▼
seed     (python -m guardian_api.seed)     restart: "no"   depends_on migrate completed
   │  service_completed_successfully
   ▼
api ×N   (uvicorn only — no alembic/seed)  depends_on seed completed  + db/redis healthy
worker-default ×M                          depends_on seed completed
```

`docker-compose.prod.yml` encodes exactly this with Compose
`depends_on: { condition: service_completed_successfully }`. Every API replica and the default
worker start **only after** the seed job exits 0, so migrations run **once** regardless of replica
count.

**Kubernetes mapping:** `migrate` and `seed` become a `Job` (or an `initContainer` on a single
pre-deploy pod) that must reach `Completed` before the API `Deployment` rolls. See
`docs/deployment/08-probes-and-restart.md`.

## 2. Migration determinism

| Property | State | Evidence |
|----------|-------|----------|
| Chain | Linear `0001 → 0011`, single head | `alembic history` |
| Head | `0011_web_checks_catalog` | `packages/db/src/guardian_db/migrations/versions/0011_web_checks_catalog.py` |
| Downgrades | Every migration implements a real `downgrade()` (not a no-op) | all 11 `versions/*.py` |
| URL source | `env.py` sets `sqlalchemy.url = get_settings().database_url` (owner DSN); libpq honours the DSN `sslmode`, so the same TLS DSN works for alembic | `packages/db/src/guardian_db/migrations/env.py:15` |
| Isolation | `NullPool` (no lingering pool from the one-shot job) | `env.py:34` |

Verify determinism before a deploy:

```bash
alembic heads            # → 0011_web_checks_catalog (single head; a split head blocks deploy)
alembic history | head   # linear chain, no branches
alembic upgrade head     # idempotent: no-op when already at head
```

## 3. `guardian_app` role — production authentication contract (D-03)

Migration `0005_phase5_rls.py:78` creates the RLS role with **`CREATE ROLE guardian_app LOGIN;`** —
**no password**. The API connects as this non-owner, RLS-enforced role via
`GUARDIAN_APP_DATABASE_URL`. Before that DSN can authenticate you MUST set the role password in the
managed database (a one-time operator step, out of migration scope so the password never lands in
Git or migration history):

```sql
-- Run once as the DB owner/admin, out of band:
ALTER ROLE guardian_app WITH PASSWORD '<GUARDIAN_APP_DB_PASSWORD>';
-- Then GUARDIAN_APP_DATABASE_URL = postgresql+psycopg://guardian_app:<pw>@<host>:5432/guardian?sslmode=verify-full
```

The API refuses to start if this role turns out to be a superuser / `BYPASSRLS` role
(`services/api/src/guardian_api/main.py:18-38`), so RLS can never be silently inert.

## 4. Postgres TLS (P1-C)

Every non-empty DSN must carry `sslmode` ∈ {`require`, `verify-ca`, `verify-full`} or the platform
refuses to boot. `verify-full` (validates hostname + CA) is recommended.

- **Managed Postgres (recommended):** the provider terminates TLS; set `sslmode=verify-full` and
  supply the CA via `sslrootcert` per your provider.
- **Self-hosted db service (reference):** enable TLS on the `db` service by dropping
  `server.crt` / `server.key` (key `0600`, owned by uid 70) into `./infra/tls/postgres/` and
  uncommenting the `command:` + `volumes:` block in `docker-compose.prod.yml`. Certificates are
  operator-provided (external provisioning).

## 5. Backup, PITR, restore, rollback

Covered in `docs/deployment/05-backup-and-dr.md` (Phase 5). Migration rollback uses the intact
`downgrade()` paths, but **is not a substitute for a data backup** on a destructive event.

## 6. Verification

```bash
# Structure of the production topology (uses a throwaway env; never .env.production):
docker compose --env-file <your-env> -f docker-compose.prod.yml config >/dev/null && echo "compose OK"
alembic heads   # single head 0011_web_checks_catalog
```
