#!/usr/bin/env bash
# Build step for the Render deployment: install the application, then fetch the external security
# tools the engines shell out to.
#
# The tools are fetched rather than baked into an image because this service uses Render's native
# Python runtime, not the project Dockerfile. That is a deliberate narrowing: the Docker path needs
# a registry and a paid plan to be worth it, and the native runtime gets a working control plane
# onto the free tier today. What it costs is the Dockerfile's `nftables`, so the uid_nft egress
# backend is unavailable and any engine depending on it must report `not_checked` — which is the
# correct outcome for a missing tool and not a silent degradation.
set -euo pipefail

log() { printf '[build] %s\n' "$1"; }

log "application"
pip install --upgrade pip
pip install -e .

log "security tools"
# Best effort, and that is the point: a tool that fails to download makes its engine report
# `not_checked`, never a false "clean". Failing the whole build because one mirror is slow would
# trade a truthful partial result for no deployment at all.
TOOLS_DIR="$(pwd)/.tools"
mkdir -p "$TOOLS_DIR"

fetch() {  # name url
  if curl -fsSL --retry 3 --retry-delay 2 "$2" -o "/tmp/$1.tgz" \
     && tar -xzf "/tmp/$1.tgz" -C "$TOOLS_DIR" "$1" 2>/dev/null; then
    chmod +x "$TOOLS_DIR/$1"
    echo "  $1: $("$TOOLS_DIR/$1" --version 2>/dev/null | head -1 || echo installed)"
  else
    echo "  $1: unavailable — its engine will report not_checked"
  fi
  rm -f "/tmp/$1.tgz"
}

# Render's build hosts are linux/amd64.
fetch trivy    "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz"
fetch gitleaks "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz"
fetch syft     "https://github.com/anchore/syft/releases/download/v1.29.0/syft_1.29.0_linux_amd64.tar.gz"
fetch grype    "https://github.com/anchore/grype/releases/download/v0.98.0/grype_0.98.0_linux_amd64.tar.gz"

log "done"
