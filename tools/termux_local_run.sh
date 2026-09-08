#!/usr/bin/env bash
# Run Guardian locally on Termux (Android), for trying the product rather than for using it.
#
# WHAT YOU GET. The API, PostgreSQL with the RLS policies live, the Redis queue, one worker, and
# the 28 reviewed Nuclei templates. That is enough to drive the whole customer journey — sign up,
# prove ownership, authorize, scan, read the report, retest — against a real database with real
# tenant isolation.
#
# WHAT YOU DO NOT GET, AND WHY IT LOOKS LIKE THIS. Engines that shell out to Go binaries — SCA,
# container, IaC, CSPM — will report `not_checked`. Those tools (trivy, gitleaks, syft, grype) are
# built against glibc and Termux uses Bionic, so they are absent rather than broken. The report
# saying `not_checked` instead of "clean" IS the safety property working: an engine that could not
# look never claims it found nothing. See `engine_outcome()`.
#
# The network plane (nmap) needs CAP_NET_ADMIN and cannot run here at all.
#
# GUARDIAN_ENV=local is not a convenience. Outside local the settings validator refuses to boot
# without TLS on Redis, sslmode=verify-full on Postgres, and non-default secrets — correct for
# production, impossible on a phone. Nothing below weakens a control that would apply in
# production; it selects the local profile the code already ships.
set -euo pipefail

say() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

say "packages"
# clang and binutils are here because psycopg may need building: Termux is aarch64/Bionic and does
# not always have a prebuilt wheel.
pkg install -y python postgresql redis git clang binutils

say "database"
# Termux has no separate postgres system user, so the cluster runs as you.
mkdir -p "$PREFIX/var/lib/postgresql"
if [ ! -f "$PREFIX/var/lib/postgresql/PG_VERSION" ]; then
  initdb "$PREFIX/var/lib/postgresql"
fi
pg_ctl -D "$PREFIX/var/lib/postgresql" -l "$PREFIX/var/lib/postgresql/pg.log" start || true
sleep 3
createuser -s guardian 2>/dev/null || true
createdb -O guardian guardian 2>/dev/null || true
psql -d guardian -c "ALTER ROLE guardian WITH PASSWORD 'guardian';" >/dev/null

say "queue"
redis-server --daemonize yes --port 6379 || true

say "python environment"
cd "$(dirname "$0")/.."
python -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -e .

say "settings"
# These are local-profile values and are safe to commit precisely because the validator refuses
# them outside local/dev — a leaked dev secret cannot be used against a production deployment.
cat > .env <<'ENV'
GUARDIAN_ENV=local
GUARDIAN_DATABASE_URL=postgresql+psycopg://guardian:guardian@localhost:5432/guardian
GUARDIAN_APP_DATABASE_URL=postgresql+psycopg://guardian_app:guardian_app@localhost:5432/guardian
GUARDIAN_APP_DB_PASSWORD=guardian_app
GUARDIAN_REDIS_URL=redis://localhost:6379/0
GUARDIAN_JWT_SECRET=local-dev-jwt-secret-not-for-production
GUARDIAN_ENCRYPTION_KEY=local-dev-encryption-key-change-me-now
GUARDIAN_BROKER_SEAL_KEY=local-dev-broker-seal-key-different-one
GUARDIAN_SANDBOX_ENGINES=true
GUARDIAN_RECON_PLANE=false
ENV
set -a; . ./.env; set +a

say "schema and seed"
# Migration 0006 creates the RLS-enforced `guardian_app` role and takes its password from
# GUARDIAN_APP_DB_PASSWORD. The API connects as that role, not as the owner, which is what makes
# the tenant isolation real here rather than nominal.
alembic upgrade head
python -m guardian_api.seed

say "starting"
# TWO processes. The worker is what executes scans; without it a scan stays `queued` forever —
# which is BLOCKER-1 reproduced on your phone, and worth seeing once.
pkill -f 'guardian_scanner.celery_app' 2>/dev/null || true
pkill -f 'guardian_api.main:app' 2>/dev/null || true
celery -A guardian_scanner.celery_app.celery_app worker \
  --queues default --concurrency 1 --loglevel INFO > worker.log 2>&1 &
uvicorn guardian_api.main:app --host 127.0.0.1 --port 8000 > api.log 2>&1 &

sleep 6
if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
  printf '\n\033[1;32mGuardian is running.\033[0m\n\n'
  printf '  Console   http://127.0.0.1:8000/docs\n'
  printf '  Login     admin@example.com / ChangeMe123!\n'
  printf '  Logs      tail -f ~/CYBER/api.log ~/CYBER/worker.log\n\n'
  printf '  Stop      pkill -f guardian_api.main ; pkill -f guardian_scanner\n\n'
else
  printf '\n\033[1;31mThe API did not answer /health.\033[0m Read api.log — the settings validator\n'
  printf 'reports the exact missing or malformed value and refuses to start rather than\n'
  printf 'running half-configured:\n\n  tail -30 api.log\n\n'
  exit 1
fi
