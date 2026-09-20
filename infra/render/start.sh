#!/usr/bin/env bash
# Start the control plane on a single Render instance: migrate, seed, then run the API and the
# default worker together.
#
# WHY BOTH IN ONE PROCESS GROUP. BLOCKER-1 is that scans sit `queued` forever with no worker
# running. Render bills Background Workers, and this deployment is deliberately on the free tier,
# so the worker runs beside the API instead of in its own service.
#
# That is a compromise in isolation, and it is worth being exact about which one. It does NOT cross
# the plane boundary the architecture maintains: docker-compose.prod.yml gives `api` and
# `worker-default` the same `*control-env` secret block, so the default worker is already a
# control-plane component holding the same JWT and KMS material. The planes that really are
# separated — recon and tools, which are DB-less and never see those secrets — are not deployed
# here at all. What is actually given up is resource isolation: a scan that pins the CPU will slow
# API requests on the same instance. On a free instance that is the honest trade for having a
# worker at all.
#
# WHAT THIS IS NOT. A single instance means `alembic upgrade head` cannot race itself, which is why
# running migrations in the start command is safe here and is NOT safe in the compose topology,
# where a separate one-shot job runs before N replicas start. If this service is ever scaled past
# one instance, the migration must move back out of this script first.
set -euo pipefail

log() { printf '[start] %s\n' "$1"; }

: "${PORT:=8000}"
export PATH="${PATH}:/opt/render/project/src/.tools"

log "schema"
# Not backgrounded and not tolerated: a service that starts with a half-migrated schema serves
# wrong answers rather than failing, and wrong answers from a security product are worse than an
# outage. `set -e` stops the container here, and Render reports it.
alembic upgrade head

log "seed"
# Idempotent — it creates the bootstrap tenant and knowledge base only when they are absent.
python -m guardian_api.seed

log "scan plane"
# ISSUE-3: untrusted engine execution runs on the `scan` queue, holding NEITHER the KMS master NOR
# the JWT secret — so a malicious customer file that reaches code execution inside an engine cannot
# read the key that decrypts every tenant's credentials. The control-plane worker below always sets
# GUARDIAN_SCAN_OFFLOAD=true, so run_scan hands each engine to the `scan` queue rather than running it
# next to the master key. WHERE that `scan` consumer runs is a deploy choice:
#
#   * default (GUARDIAN_EXTERNAL_SCAN_PLANE unset/false): run the scan worker IN-INSTANCE, beside the
#     API. Simplest, and correct for light scans. A heavy DAST scan then spends its RAM on this one
#     512 MB free instance and can OOM the API — the known free-tier limit.
#   * GUARDIAN_EXTERNAL_SCAN_PLANE=true: do NOT start an in-instance scan worker. Offloaded engines
#     wait on the `scan` queue for an OFF-INSTANCE consumer with real RAM — the GitHub Actions
#     scan-plane workflow (.github/workflows/guardian-scan-plane.yml), which holds only the broker
#     seal key + Redis. Engines then execute only while that workflow's window is open; a scan
#     created outside it waits until run_scan's offload timeout. This keeps heavy scans off the free
#     instance without paying for a Render worker. Set the flag on guardian-api + redeploy to use it.
#
# When in-instance, `env -u` strips both master secrets from the worker (config refuses a scan_plane
# that still carries either), GUARDIAN_SCAN_PLANE=true marks it, and the DB URLs are set EMPTY (not
# unset — the settings default is a non-empty localhost DSN that would fail the production TLS check).
SCAN_PID=""
if [ "${GUARDIAN_EXTERNAL_SCAN_PLANE:-false}" = "true" ]; then
  log "scan plane: EXTERNAL — engines offload to the 'scan' queue for an off-instance consumer (GitHub Actions); not starting an in-instance scan worker"
else
  log "scan plane: in-instance"
  env -u GUARDIAN_JWT_SECRET -u GUARDIAN_ENCRYPTION_KEY \
    GUARDIAN_DATABASE_URL="" GUARDIAN_APP_DATABASE_URL="" GUARDIAN_SCAN_PLANE=true \
    celery -A guardian_scanner.celery_app.celery_app worker \
    --queues scan --concurrency 1 --loglevel INFO &
  SCAN_PID=$!
fi

log "worker + beat"
# `--beat` embeds the periodic scheduler in THIS one worker process. It is the correct form here and
# only here: this deployment runs exactly one worker on one instance, so embedding beat yields
# exactly one scheduler with no coordination needed. (The compose topology can scale workers, so it
# runs beat as a separate single service instead — never `--beat` on a scalable worker, which would
# fire every periodic job N times.) Without this, stranded-scan recovery, feed sync, webhook retries
# and scheduled scans never run. The instance is kept awake by the /health keepalive
# (.github/workflows/guardian-keepalive.yml, every 10m); beat fires while the instance is awake.
# GUARDIAN_SCAN_OFFLOAD=true routes untrusted engine execution onto the `scan` queue — consumed by
# the in-instance scan worker above, or (GUARDIAN_EXTERNAL_SCAN_PLANE=true) by the off-instance
# GitHub Actions scan plane.
GUARDIAN_SCAN_OFFLOAD=true \
  celery -A guardian_scanner.celery_app.celery_app worker --beat \
  --queues default --concurrency 1 --loglevel INFO &
WORKER_PID=$!

log "api on :${PORT}"
uvicorn guardian_api.main:app --host 0.0.0.0 --port "${PORT}" &
API_PID=$!

# The whole point of this file is that the worker is running, so the container must die when it
# stops. Without this the API would keep answering health checks while scans silently queued
# forever — BLOCKER-1 reappearing as a green service, which is the failure mode this project
# treats as the worst kind: a system that cannot report that it stopped working.
#
# `wait -n` returns when ANY child (control worker, API, and the scan worker when it runs
# in-instance) exits; whichever it was, we tear the others down and exit non-zero so Render restarts
# the instance. In external-scan-plane mode SCAN_PID is empty and simply drops out of the list — the
# `${SCAN_PID:+...}` expansion contributes nothing when unset, so wait/kill act on the two remaining
# children. When the scan worker IS in-instance it is load-bearing (a scan blocks on it), so its
# death must restart the instance just like the control worker's.
# `|| code=$?` is required, not defensive. Under `set -e` a bare `wait -n` returning non-zero
# terminates the shell immediately — before the log line and before the sibling is killed. The
# container would still exit, but with no reason in the logs and a stray process behind it: a
# failure path that cannot describe itself. Caught by running it, not by reading it.
code=0
wait -n "${WORKER_PID}" "${API_PID}" ${SCAN_PID:+"${SCAN_PID}"} || code=$?
log "a child process exited (status ${code}) — stopping the container so Render restarts it"
kill "${WORKER_PID}" "${API_PID}" ${SCAN_PID:+"${SCAN_PID}"} 2>/dev/null || true
exit "${code:-1}"
