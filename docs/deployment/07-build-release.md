# 07 — Container Build & Release

> Deployment Readiness · Phase 7. Fixes discovery finding **D-20** (no image build/publish
> pipeline). Provider-neutral: the registry is configurable and publishing is opt-in — the repo
> picks no external registry.

## 1. What ships

| Artifact | Purpose |
|----------|---------|
| `.dockerignore` | Keeps the build context small and **secret-free** — `.env*`, `infra/tls`, `*.pem/*.key/*.crt`, `.git`, `.venv`, caches, `dump.rdb` can never enter an image layer. |
| `.github/workflows/release.yml` | Tag/dispatch-triggered: build → assert non-root + no baked secrets → SBOM → pip-audit → Trivy image scan → digest → opt-in push. |
| Existing `infra/docker/Dockerfile` | Unchanged: `python:3.12-slim`, non-root `guardian` (uid 10001), drops privileges, narrow COPYs. |

## 2. Release flow

```
git tag vX.Y.Z && git push --tags     # OR: Actions → Release → Run workflow (publish: true)
        │
        ▼  release.yml
  build (local)
   → assert User=guardian, no GUARDIAN_* baked in
   → SBOM (tools/generate_sbom.py)  → artifact
   → pip-audit (advisory)
   → Trivy HIGH,CRITICAL (advisory)
   → publish to ${REGISTRY}/${IMAGE_NAME}:tag   (opt-in)
   → record image@sha256:<digest>   → artifact + job summary
```

The build never runs on ordinary branch pushes (tag/dispatch only), so it does not interfere with
CI. `push` on a `v*` tag publishes; `workflow_dispatch` publishes only when `publish: true`.

## 3. Configurable registry (no provider chosen)

| Variable | Default | Meaning |
|----------|---------|---------|
| `vars.GUARDIAN_REGISTRY` | `ghcr.io` | Any OCI registry host |
| `vars.GUARDIAN_IMAGE_NAME` | `${{ github.repository }}` | Image path |

Defaults target **GHCR** (this repo's own home, using the built-in `GITHUB_TOKEN`) so nothing
external must be chosen to get a working pipeline. For another registry, set the two vars and provide
that registry's credentials as secrets in the login step.

> **Stop point:** pushing to a non-GHCR registry (Docker Hub, ECR, GAR, Harbor, …) needs an account
> + credentials that are **not** in this repo. The pipeline is registry-configurable and stops
> exactly there — it does not create or assume a registry.

## 4. Reproducibility & digest pinning

- **Deploy by digest, not tag.** Set `GUARDIAN_IMAGE=${REGISTRY}/${IMAGE_NAME}@sha256:<digest>` (the
  value `release.yml` records) in `docker-compose.prod.yml` / your orchestrator. This pins the exact
  bytes and is the reproducibility lever at the deployment boundary — no Dockerfile change required.
- **Base-image pinning (recommended, post-launch):** pin `python:3.12-slim` by digest and add a
  dependency lockfile (discovery D-23/D-24) for fully reproducible rebuilds. Left as a documented
  post-launch item to respect the current Freeze — the deploy-by-digest step above already gives
  artifact-level reproducibility.

## 5. Supply-chain posture (existing, retained)

- SBOM generated + uploaded (source deps) — `tools/generate_sbom.py`.
- `pip-audit` on the dependency tree (advisory, matching the project's gate tiering).
- Trivy image scan for HIGH/CRITICAL (advisory).
- Non-root runtime; least-privilege CI token.

## 6. Verification

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('release.yml OK')"
# Local build honouring .dockerignore (needs a docker daemon):
docker build -f infra/docker/Dockerfile -t security-guardian:local .
docker inspect --format '{{.Config.User}}' security-guardian:local     # → guardian
docker inspect --format '{{json .Config.Env}}' security-guardian:local  # no GUARDIAN_* entries
```
