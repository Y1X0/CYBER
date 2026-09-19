#!/usr/bin/env bash
# Start the control plane on a single Render instance: migrate, seed, then run the API and the
# default (control-plane) worker together. Engine execution is OFFLOADED to a SEPARATE service.
#
# WHY THE API + CONTROL WORKER SHARE THIS INSTANCE, BUT THE SCAN WORKER NO LONGER DOES. BLOCKER-1 is
# that scans sit `queued` forever with no worker running. Render bills Background Workers, and this
# deployment is deliberately on the free tier, so the control worker runs beside the API rather than
# in its own paid service — that is a resource-isolation compromise, not a trust one: the API and the
# default worker already share `*control-env` (JWT + KMS) in docker-compose.prod.yml, so co-locating
# them crosses no plane boundary.
#
# What DID move off this instance is the untrusted-engine execution (the `scan` plane). It used to
# run here as a second worker, which meant a heavy DAST scan spent its RAM inside this 512 MB free
# instance alongside uvicorn + the control worker + beat and could OOM-kill the API. It now runs on
# its own free service (infra/render/start-scan-plane.sh, service `guardian-scan` in render.yaml),
# giving engine execution its own 512 MB. This instance sets GUARDIAN_SCAN_OFFLOAD=true on the
# control worker (below), so `run_scan` dispatches each engine over the `scan` queue to that service
# and blocks on the sealed result — the DB-bound orchestration stays here with the master key, the
# untrusted parsing runs there with neither the master key nor the JWT secret.
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

# ISSUE-3: untrusted engine execution (the `scan` plane) no longer runs on THIS instance — it is a
# separate free service (`guardian-scan`, infra/render/start-scan-plane.sh) so a heavy scan spends
# its RAM there, not next to the API. That worker holds NEITHER the KMS master NOR the JWT secret;
# this instance reaches it over the shared `scan` queue via GUARDIAN_SCAN_OFFLOAD=true below.

log "worker + beat"
# `--beat` embeds the periodic scheduler in THIS one worker process. It is the correct form here and
# only here: this deployment runs exactly one worker on one instance, so embedding beat yields
# exactly one scheduler with no coordination needed. (The compose topology can scale workers, so it
# runs beat as a separate single service instead — never `--beat` on a scalable worker, which would
# fire every periodic job N times.) Without this, stranded-scan recovery, feed sync, webhook retries
# and scheduled scans never run. The instance is kept awake by the /health keepalive
# (.github/workflows/guardian-keepalive.yml); beat fires while the instance is awake.
# GUARDIAN_SCAN_OFFLOAD=true routes untrusted engine execution over the `scan` queue to the separate
# guardian-scan service (infra/render/start-scan-plane.sh), off this instance.
GUARDIAN_SCAN_OFFLOAD=true \
  celery -A guardian_scanner.celery_app.celery_app worker --beat \
  --queues default --concurrency 1 --loglevel INFO &
WORKER_PID=$!

log "api on :${PORT}"
uvicorn guardian_api.main:app --host 0.0.0.0 --port "${PORT}" &
API_PID=$!

# The whole point of this file is that the control worker is running, so the container must die when
# it stops. Without this the API would keep answering health checks while scans silently queued
# forever — BLOCKER-1 reappearing as a green service, which is the failure mode this project
# treats as the worst kind: a system that cannot report that it stopped working.
#
# `wait -n` returns when EITHER child (control worker, API) exits; whichever it was, we tear the
# other down and exit non-zero so Render restarts the instance. (The scan worker is no longer a
# child of this process — it is the separate guardian-scan service, which restarts itself on its own
# instance; an offloaded engine whose plane is down degrades that one engine, it does not need to
# restart the API.)
# `|| code=$?` is required, not defensive. Under `set -e` a bare `wait -n` returning non-zero
# terminates the shell immediately — before the log line and before the sibling is killed. The
# container would still exit, but with no reason in the logs and a stray process behind it: a
# failure path that cannot describe itself. Caught by running it, not by reading it.
code=0
wait -n "${WORKER_PID}" "${API_PID}" || code=$?
log "a child process exited (status ${code}) — stopping the container so Render restarts it"
kill "${WORKER_PID}" "${API_PID}" 2>/dev/null || true
exit "${code:-1}"
