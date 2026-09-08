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
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-dev build-essential \
                      postgresql redis-server git curl ca-certificates

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
service postgresql start || pg_ctlcluster "$(ls /etc/postgresql | head -1)" main start || true
sleep 3
su - postgres -c "psql -c \"SELECT 1 FROM pg_roles WHERE rolname='guardian'\"" | grep -q 1 \
  || su - postgres -c "createuser -s guardian"
su - postgres -c "psql -lqt" | cut -d'|' -f1 | grep -qw guardian \
  || su - postgres -c "createdb -O guardian guardian"
su - postgres -c "psql -c \"ALTER ROLE guardian WITH PASSWORD 'guardian';\"" >/dev/null

say "queue"
service redis-server start || redis-server --daemonize yes --port 6379 || true

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
