#!/usr/bin/env bash
# Restore a Security Guardian logical backup into a TARGET database.
#
# DESTRUCTIVE to the target (drops+recreates objects). Requires an explicit confirmation to run.
# See docs/deployment/05-backup-and-dr.md for the full restore + verification procedure.
#
# Usage:  GUARDIAN_DATABASE_URL=<target-owner-dsn> GUARDIAN_RESTORE_CONFIRM=yes \
#         ./infra/scripts/pg_restore.sh /var/backups/guardian/guardian-<ts>.dump
set -euo pipefail

dump="${1:?usage: pg_restore.sh <backup.dump>}"
: "${GUARDIAN_DATABASE_URL:?set GUARDIAN_DATABASE_URL for the TARGET database}"
[ -f "$dump" ] || { echo "no such dump: $dump" >&2; exit 2; }

if [ "${GUARDIAN_RESTORE_CONFIRM:-}" != "yes" ]; then
  echo "refusing: this OVERWRITES the target db. Re-run with GUARDIAN_RESTORE_CONFIRM=yes" >&2
  exit 2
fi

PG_URL="${GUARDIAN_DATABASE_URL/+psycopg/}"

# --clean --if-exists → drop existing objects first; --no-owner/--no-privileges → map to the target's
# roles. After restore, run `alembic current` to confirm the schema head, then re-ALTER the
# guardian_app role password if restoring into a fresh instance (docs/deployment/02-database.md §3).
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="$PG_URL" "$dump"
echo "restore complete from: $dump"
