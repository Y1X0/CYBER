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

log "worker + beat"
# `--beat` embeds the periodic scheduler in THIS one worker process. It is the correct form here and
# only here: this deployment runs exactly one worker on one instance, so embedding beat yields
# exactly one scheduler with no coordination needed. (The compose topology can scale workers, so it
# runs beat as a separate single service instead — never `--beat` on a scalable worker, which would
# fire every periodic job N times.) Without this, stranded-scan recovery, feed sync, webhook retries
# and scheduled scans never run. The instance is kept awake by the /health keepalive
# (.github/workflows/guardian-keepalive.yml, every 10m); beat fires while the instance is awake.
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
# `wait -n` returns when EITHER child exits; whichever it was, we tear the other down and exit
# non-zero so Render restarts the instance.
# `|| code=$?` is required, not defensive. Under `set -e` a bare `wait -n` returning non-zero
# terminates the shell immediately — before the log line and before the sibling is killed. The
# container would still exit, but with no reason in the logs and a stray process behind it: a
# failure path that cannot describe itself. Caught by running it, not by reading it.
code=0
wait -n "${WORKER_PID}" "${API_PID}" || code=$?
log "a child process exited (status ${code}) — stopping the container so Render restarts it"
kill "${WORKER_PID}" "${API_PID}" 2>/dev/null || true
exit "${code:-1}"
