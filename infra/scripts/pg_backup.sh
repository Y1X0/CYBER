#!/usr/bin/env bash
# Logical PostgreSQL backup for Security Guardian (portable baseline).
#
# For production prefer the managed database's automated PITR (see docs/deployment/05-backup-and-dr.md);
# this script is the provider-neutral baseline and a belt-and-braces logical dump. It reads the DSN
# from GUARDIAN_DATABASE_URL, writes a timestamped custom-format dump, verifies it, and prunes old
# dumps. No secret is printed or committed.
#
# Usage:  GUARDIAN_DATABASE_URL=postgresql+psycopg://user:pw@host:5432/guardian?sslmode=verify-full \
#         GUARDIAN_BACKUP_DIR=/var/backups/guardian ./infra/scripts/pg_backup.sh
set -euo pipefail

: "${GUARDIAN_DATABASE_URL:?set GUARDIAN_DATABASE_URL}"
BACKUP_DIR="${GUARDIAN_BACKUP_DIR:-/var/backups/guardian}"
RETENTION_DAYS="${GUARDIAN_BACKUP_RETENTION_DAYS:-14}"

# pg_dump speaks libpq URLs; strip SQLAlchemy's "+psycopg" driver suffix.
PG_URL="${GUARDIAN_DATABASE_URL/+psycopg/}"

mkdir -p "$BACKUP_DIR"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/guardian-${ts}.dump"

# --format=custom → compressed, selective-restore-capable. --no-owner/--no-privileges → portable
# across a fresh role set (the guardian_app role is recreated by migration 0005, not the dump).
pg_dump --format=custom --no-owner --no-privileges --file="$out" "$PG_URL"

# Integrity: a readable TOC means the dump is not truncated.
pg_restore --list "$out" >/dev/null
echo "backup ok: $out ($(du -h "$out" | cut -f1))"

# Retention prune.
find "$BACKUP_DIR" -maxdepth 1 -name 'guardian-*.dump' -type f -mtime "+${RETENTION_DAYS}" -print -delete
