#!/usr/bin/env bash
# Start the ISOLATED scan-plane worker on its OWN Render free instance.
#
# WHY A SEPARATE SERVICE. A DAST (or any active) scan parses attacker-controlled bytes and can spend
# real RAM; run beside the API (infra/render/start.sh) it shares one 512 MB free instance with
# uvicorn + the control worker + beat, so a heavy scan risks OOM-killing the API. This service gives
# engine execution its OWN 512 MB. guardian-api keeps the API + control worker + beat and offloads
# engine execution here over the `scan` queue (GUARDIAN_SCAN_OFFLOAD=true on the control worker).
#
# THE SECRET BOUNDARY (ISSUE-3) — enforced by config, not by convention. This plane holds NEITHER the
# JWT secret NOR the credential KMS master (GUARDIAN_ENCRYPTION_KEY): Settings refuses to start a
# scan_plane that carries either. It holds only GUARDIAN_BROKER_SEAL_KEY — the SAME value as
# guardian-api — to unseal its per-job payload (creds sealed with that key, never the master) and
# seal its findings back. It is DB-less: the DB URLs are set EMPTY (not unset — the settings default
# is a non-empty localhost DSN that would fail the production TLS check). So a malicious file that
# reaches code execution inside an engine here cannot read the key that decrypts tenant credentials,
# forge a platform token, or touch the database.
#
# WHY A `web` SERVICE WITH A PORT. Render bills type=background_worker (HTTP 402 on free), so this is
# a `web` service; a web service must bind a port or Render fails the deploy and reaps it.
# scan_plane_health.py is that port — it answers /health while the worker is alive, and is also the
# keepalive target that stops this free instance sleeping. A free web service sleeps after 15 minutes
# with no inbound HTTP, and a scan offloaded to a sleeping plane would block until the offload
# timeout, so guardian-keepalive.yml pings THIS /health too.
#
# NOTE ON ARTIFACTS. Network engines (DAST/API) need no shared disk — the target is a URL and the job
# crosses sealed over the broker. Artifact engines (mobile/iOS) read uploaded bytes by path from a
# shared workspace; two separate free instances do NOT share disk, so those stay on the in-instance
# path until artifacts are delivered over object storage (the deferred follow-up). The workspace dir
# below is a LOCAL scratch dir for this instance only.
#
# WHAT THIS DOES NOT DO. No database migration and no bootstrap seed here: this plane is DB-less and
# never touches Postgres. Running either would need a DB URL this plane must not hold.
set -euo pipefail

log() { printf '[scan-plane] %s\n' "$1"; }

: "${PORT:=10000}"
export PATH="${PATH}:/opt/render/project/src/.tools"
export GUARDIAN_SCAN_WORKSPACE_DIR="${GUARDIAN_SCAN_WORKSPACE_DIR:-/tmp/guardian-scan}"
mkdir -p "${GUARDIAN_SCAN_WORKSPACE_DIR}"

log "scan worker (queue=scan, DB-less, no JWT/KMS master)"
# `env -u` strips the two forbidden secrets from THIS process even if the environment somehow carries
# them — belt-and-braces with the config check. GUARDIAN_SCAN_PLANE=true marks the plane; the empty
# DB URLs keep it DB-less past the production TLS validator. Same invocation the single-instance
# start.sh used for this worker, now on its own service.
env -u GUARDIAN_JWT_SECRET -u GUARDIAN_ENCRYPTION_KEY \
  GUARDIAN_DATABASE_URL="" GUARDIAN_APP_DATABASE_URL="" GUARDIAN_SCAN_PLANE=true \
  celery -A guardian_scanner.celery_app.celery_app worker \
  --queues scan --concurrency 1 --loglevel INFO &
SCAN_PID=$!
export GUARDIAN_SCAN_WORKER_PID="${SCAN_PID}"

log "health endpoint on :${PORT}"
# Binds the port Render requires and reports the worker's liveness (200 while the worker PID is
# alive, 503 if it died). Also the keepalive target for this instance.
python infra/render/scan_plane_health.py &
HEALTH_PID=$!

# If EITHER the worker or the health port dies, tear both down and exit non-zero so Render restarts
# the instance. A scan plane whose worker died but whose port stayed up would look healthy while
# every offloaded scan blocked on it — the "green service that stopped working" failure this project
# treats as the worst kind. `|| code=$?` is required under `set -e`: a bare failing `wait -n` would
# kill the shell before the teardown and the log line.
code=0
wait -n "${SCAN_PID}" "${HEALTH_PID}" || code=$?
log "a child process exited (status ${code}) — stopping the container so Render restarts it"
kill "${SCAN_PID}" "${HEALTH_PID}" 2>/dev/null || true
exit "${code:-1}"
