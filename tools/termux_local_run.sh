#!/usr/bin/env bash
# Run Guardian locally on Android, for trying the product rather than for using it.
#
# READ THIS FIRST: RUN IT INSIDE proot-distro, NOT ON BARE TERMUX.
#
# Bare Termux cannot install this project, and the reason is structural rather than a missing
# package. `cryptography` and `pydantic-core` are Rust extensions with no Android wheels, so pip
# falls back to building them — and rustup does not support `aarch64-unknown-linux-android` at all:
#
#     Computed rustc target triple: aarch64-unknown-linux-android
#     Target triple not supported by rustup
#
# The same wall then repeats for psycopg and argon2-cffi. Termux uses Bionic libc; the Python
# ecosystem ships manylinux wheels built against glibc.
#
# proot-distro gives you a real glibc Ubuntu inside Termux, where those wheels install normally.
# It is also strictly better for the demonstration: the Go security tools (trivy, gitleaks, syft,
# grype) ship linux/arm64 glibc binaries, so the SCA, container and IaC engines actually SCAN
# instead of reporting `not_checked`.
#
#   pkg install proot-distro
#   proot-distro install ubuntu
#   proot-distro login ubuntu
#   # then, inside:
#   apt update && apt install -y git curl
#   git clone https://github.com/Y1X0/CYBER.git && cd CYBER
#   git checkout claude/security-guardian-architecture-p1315d
#   bash tools/termux_local_run.sh
#
# WHAT STILL WILL NOT WORK, ANYWHERE ON A PHONE. The network plane (nmap) needs CAP_NET_ADMIN and
# the uid_nft egress backend needs kernel nftables; both are unavailable without root, so those
# providers stay off. Engines whose tool is genuinely absent report `not_checked` rather than
# "clean" — that is `engine_outcome()` working, not a broken install, and seeing it on your own
# device is a better demonstration of the safety property than reading about it.
#
# GUARDIAN_ENV=local is not a convenience. Outside local the settings validator refuses to boot
# without TLS on Redis, sslmode=verify-full on Postgres, and non-default secrets — correct for
# production, impossible here. Nothing below weakens a control that would apply in production; it
# selects the local profile the code already ships.
set -euo pipefail

say()  { printf '\n\033[1m── %s\033[0m\n' "$1"; }
fail() { printf '\n\033[1;31m%s\033[0m\n' "$1"; exit 1; }

# ── refuse bare Termux rather than failing halfway through pip ─────────────────────────────────
if [ -d /data/data/com.termux/files/usr ] && [ ! -f /etc/os-release ]; then
  cat <<'MSG'

This is bare Termux (Bionic libc). The install cannot succeed here — cryptography and
pydantic-core are Rust extensions with no Android wheels, and rustup does not support the
aarch64-unknown-linux-android target, so there is no build path either.

Use a glibc distribution inside Termux instead:

    pkg install proot-distro
    proot-distro install ubuntu
    proot-distro login ubuntu

    apt update && apt install -y git curl
    git clone https://github.com/Y1X0/CYBER.git && cd CYBER
    git checkout claude/security-guardian-architecture-p1315d
    bash tools/termux_local_run.sh

That path also lets the Go security tools run, so the SCA, container and IaC engines
scan for real instead of reporting `not_checked`.

MSG
  exit 1
fi

command -v apt-get >/dev/null || fail "This script expects a Debian/Ubuntu userland (apt-get)."

say "packages"
# noninteractive AND a null debconf frontend: proot has no dialog and the Readline fallback will
# sit waiting for input that never comes, which is what a hang here looks like.
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_FRONTEND=noninteractive
apt-get update -qq
# Two separate things hang a postgres install under proot, and both need disarming.
#
# 1. `dpkg-preconfigure` runs debconf BEFORE unpacking. postgresql's config script calls
#    `pg_lsclusters`, which does not exist yet at that point, and the frontend then waits on input
#    that never comes. Setting DEBIAN_FRONTEND is not enough and neither is
#    `-o Dpkg::Pre-Install-Pkgs::=` — the script is invoked by a different path. Diverting the
#    binary to /bin/true is what actually stops it.
# 2. The postinst then tries to create and START a cluster through systemd, which proot does not
#    have. A policy-rc.d returning 101 makes invoke-rc.d refuse, and the install continues. Seeing
#    "policy-rc.d denied execution of start" in the output is this working, not failing.
#
# The cluster is created and started by hand below, where a failure is visible.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d
if [ ! -L /usr/sbin/dpkg-preconfigure ]; then
  dpkg-divert --local --rename --add /usr/sbin/dpkg-preconfigure >/dev/null
  ln -sf /bin/true /usr/sbin/dpkg-preconfigure
fi
# The `postgresql` metapackage pulls in more cluster machinery than is wanted here; the versioned
# server package is the narrower dependency.
#
# This asks about five named packages rather than searching. `apt-cache search` reads the whole
# package-description index and regex-matches every entry; under proot, where each read crosses the
# syscall-translation boundary, that scan takes minutes and looks exactly like a hang. `apt-cache
# show` is a keyed lookup and answers immediately. Highest version first so the loop stops at the
# newest available.
#
# No pipe into `grep -q` here, deliberately: grep exits at the first match, the writer takes SIGPIPE,
# and `pipefail` then adopts that as the command's failure — a green check reported as a red one.
# That exact shape cost us a wrongly-diagnosed golden-run gate; a direct exit status has no race.
PGPKG=postgresql
for _v in 19 18 17 16 15; do
  if apt-cache show "postgresql-$_v" >/dev/null 2>&1; then PGPKG="postgresql-$_v"; break; fi
done
echo "  server package: $PGPKG"
apt-get install -y -qq --no-install-recommends \
    python3 python3-venv python3-dev build-essential \
    "$PGPKG" redis-server git curl ca-certificates

say "security tools (optional — engines report not_checked without them)"
# Installed best-effort. A missing tool is a correct `not_checked`, never a false "clean", so a
# failure here degrades the demo rather than breaking it.
ARCH="$(dpkg --print-architecture)"
install_tool() {  # name url
  command -v "$1" >/dev/null && { echo "  $1: already present"; return; }
  if curl -fsSL "$2" -o "/tmp/$1.tgz" 2>/dev/null \
     && tar -xzf "/tmp/$1.tgz" -C /usr/local/bin "$1" 2>/dev/null; then
    chmod +x "/usr/local/bin/$1"; echo "  $1: installed"
  else
    echo "  $1: unavailable — its engine will report not_checked"
  fi
}
if [ "$ARCH" = "arm64" ]; then
  install_tool trivy    "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-ARM64.tar.gz"
  install_tool gitleaks "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_arm64.tar.gz"
  install_tool syft     "https://github.com/anchore/syft/releases/download/v1.29.0/syft_1.29.0_linux_arm64.tar.gz"
  install_tool grype    "https://github.com/anchore/grype/releases/download/v0.98.0/grype_0.98.0_linux_arm64.tar.gz"
else
  echo "  architecture $ARCH — skipping (release URLs above are arm64)"
fi

say "database"
# Debian's cluster tooling (service / pg_ctlcluster) goes through systemd, so this drives pg_ctl
# directly against a data directory we own. An earlier version ended these lines with `|| true`,
# which swallowed the failure and left the migration to fail later with a confusing "connection
# refused" — a step that cannot report its own failure, which is the thing ADR-027 forbids. It
# now verifies with pg_isready and stops here, with the log, if the server is not actually up.
PGBIN="/usr/lib/postgresql/$(ls /usr/lib/postgresql | sort -V | tail -1)/bin"
PGDATA=/var/lib/postgresql/guardian
[ -x "$PGBIN/pg_ctl" ] || fail "PostgreSQL did not install: $PGBIN/pg_ctl is missing."

# ── reuse a server that is already listening, before trying to start one ──────────────────────
# On Android this is the only path that works, and it is not a workaround for proot. PostgreSQL
# needs one small System V shared-memory segment as a startup interlock — 56 bytes, not
# configurable away — and Android blocks SysV IPC at the sandbox level, so `shmget` fails with
# EIO. proot translates paths and permissions; it cannot supply a syscall the kernel refuses.
# Installing an older PostgreSQL does not help: the failure is in the kernel, not the version.
#
# Termux's own `postgresql` package is built for Android and uses mmap shared memory instead, so
# it starts where the Ubuntu build cannot. proot-distro does not create a network namespace, so a
# process inside the container reaches that server on the same 127.0.0.1. Verified end to end:
# psql from inside the container authenticates as `guardian` against the Termux server.
#
# The probe is a real query as the real role, not a port check. A port that accepts TCP proves
# something is listening, not that this application can log in — and "I could not check" must
# never be recorded as "it is fine".
#
# -w, </dev/null and PGCONNECT_TIMEOUT together are what stop this check hanging. psql writes its
# password prompt to /dev/tty, not to stderr, so redirecting stderr hides the question while psql
# waits on the answer forever. That is a check with no failure path, which is exactly what
# ADR-027 forbids — and it is the third time this file has grown one. -w makes psql fail instead
# of asking, </dev/null denies it a terminal to read from, and the timeout bounds the connect.
PG_EXTERNAL=0
if PGPASSWORD=guardian PGCONNECT_TIMEOUT=5 \
     "$PGBIN/psql" -w -h 127.0.0.1 -U guardian -d guardian -tAc 'SELECT 1' \
     </dev/null >/dev/null 2>&1; then
  PG_EXTERNAL=1
  echo "  using the PostgreSQL already answering on 127.0.0.1:5432"
fi

if [ "$PG_EXTERNAL" = 0 ]; then
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
if [ ! -f "$PGDATA/PG_VERSION" ]; then
  # --no-sync, and the reason is proot rather than impatience. initdb ends by fsync'ing every file
  # it just wrote; each fsync crosses proot's syscall-translation boundary onto phone storage, so
  # that final step alone runs for many minutes with nothing on screen. What --no-sync gives up is
  # durability of the *initial* cluster against a machine crash during initdb itself: if the phone
  # died mid-run the cluster could be corrupt and would need recreating. For a throwaway local
  # cluster that is the right trade; it would not be on a server, and this script only ever runs
  # under GUARDIAN_ENV=local.
  #
  # Output goes to a log rather than /dev/null. Silencing it is what made this look like a hang.
  echo "  creating cluster (first run only)"
  if ! su postgres -c "$PGBIN/initdb -D $PGDATA -A trust --no-sync" > /tmp/initdb.log 2>&1; then
    echo; tail -20 /tmp/initdb.log; echo
    # Name the one cause that has a different remedy from every other initdb failure, and name it
    # only when the log actually says so rather than assuming it from the platform.
    if grep -q shmget /tmp/initdb.log; then
      cat <<'MSG'
That is the Android sandbox refusing System V shared memory, which PostgreSQL requires for a
56-byte startup interlock. No PostgreSQL version and no setting avoids it. Run the server from
bare Termux instead, where the package is built against mmap shared memory, and leave Guardian
here — proot shares Termux's loopback, so the two reach each other on 127.0.0.1.

In a Termux shell, outside this container:

    pkg install -y postgresql
    initdb -D ~/pgdata -A trust
    pg_ctl -D ~/pgdata -l ~/pg.log -o "-c listen_addresses=127.0.0.1" start
    createuser -h 127.0.0.1 -s guardian
    createdb -h 127.0.0.1 -O guardian guardian
    psql -h 127.0.0.1 -d guardian -c "ALTER ROLE guardian WITH PASSWORD 'guardian';"

Then re-run this script. It detects that server and skips creating its own.
MSG
    fi
    fail "initdb failed."
  fi
fi
# pg_ctl's own failure is tolerated here only because "already running" is a normal re-run outcome
# that must not stop the script. Its output is kept, not discarded: if the server never comes up,
# the reason is often in what pg_ctl said rather than in the server log it never got to write.
su postgres -c "$PGBIN/pg_ctl -D $PGDATA -l /tmp/pg.log -o '-c listen_addresses=127.0.0.1' start" \
  > /tmp/pgctl.log 2>&1 || true
for _ in $(seq 1 20); do
  su postgres -c "$PGBIN/pg_isready -h 127.0.0.1" >/dev/null 2>&1 && break
  sleep 1
done
su postgres -c "$PGBIN/pg_isready -h 127.0.0.1" >/dev/null 2>&1 \
  || { echo; tail -20 /tmp/pgctl.log 2>/dev/null; tail -20 /tmp/pg.log 2>/dev/null
       fail "PostgreSQL did not start — logs above."; }
echo "  postgres up"

su postgres -c "$PGBIN/psql -h 127.0.0.1 -tAc \"SELECT 1 FROM pg_roles WHERE rolname='guardian'\"" \
  | grep -q 1 || su postgres -c "$PGBIN/createuser -h 127.0.0.1 -s guardian"
su postgres -c "$PGBIN/psql -h 127.0.0.1 -lqtA" | cut -d'|' -f1 | grep -qx guardian \
  || su postgres -c "$PGBIN/createdb -h 127.0.0.1 -O guardian guardian"
su postgres -c "$PGBIN/psql -h 127.0.0.1 -c \"ALTER ROLE guardian WITH PASSWORD 'guardian';\"" \
  >/dev/null
fi  # end of the locally-created cluster

# One assertion for both paths. The external branch has no role or database to create — it was
# reached precisely because logging in as `guardian` already worked — but it still has to prove
# the migration can write, and that is a stronger claim than "the login succeeded". A role with
# no CREATE right on the database would pass the probe above and fail on migration 0001.
PGPASSWORD=guardian PGCONNECT_TIMEOUT=5 "$PGBIN/psql" -w -h 127.0.0.1 -U guardian -d guardian -tAc \
  'CREATE TABLE IF NOT EXISTS guardian_local_preflight(x int); DROP TABLE guardian_local_preflight;' \
  </dev/null >/dev/null \
  || fail "Connected to PostgreSQL as 'guardian' but could not create a table in it."
echo "  database ready"

say "queue"
redis-server --daemonize yes --port 6379 --save '' >/dev/null 2>&1 || true
for _ in $(seq 1 10); do redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 1; done
redis-cli ping 2>/dev/null | grep -q PONG || fail "Redis did not start."
echo "  redis up"

say "python environment"
cd "$(dirname "$0")/.."
python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
pip install --upgrade pip -q
pip install -e . -q

say "settings"
# Local-profile values, safe to commit precisely because the validator refuses them outside
# local/dev — a leaked dev secret cannot be used against a production deployment.
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
# GUARDIAN_APP_DB_PASSWORD. The API connects as that role rather than as the owner, which is what
# makes the tenant isolation real here rather than nominal.
alembic upgrade head
python -m guardian_api.seed

say "starting"
# TWO processes. The worker is what executes scans; without it a scan stays `queued` forever —
# BLOCKER-1 reproduced on your phone, and worth seeing once.
pkill -f 'guardian_scanner.celery_app' 2>/dev/null || true
pkill -f 'guardian_api.main:app' 2>/dev/null || true
celery -A guardian_scanner.celery_app.celery_app worker \
  --queues default --concurrency 1 --loglevel INFO > worker.log 2>&1 &
uvicorn guardian_api.main:app --host 127.0.0.1 --port 8000 > api.log 2>&1 &

sleep 8
if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
  printf '\n\033[1;32mGuardian is running.\033[0m\n\n'
  printf '  Console   http://127.0.0.1:8000/docs\n'
  printf '  Login     admin@example.com / ChangeMe123!\n'
  printf '  Logs      tail -f api.log worker.log\n'
  printf '  Stop      pkill -f guardian_api.main ; pkill -f guardian_scanner\n\n'
else
  printf '\n\033[1;31mThe API did not answer /health.\033[0m The settings validator names the exact\n'
  printf 'malformed value and declines to run half-configured, so the reason is in the log:\n\n'
  printf '  tail -30 api.log\n\n'
  exit 1
fi
