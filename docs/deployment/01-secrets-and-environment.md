# 01 — Production Secrets & Environment Contract

> Deployment Readiness · Phase 1. Turns the startup fail-fast invariants
> (`packages/common/src/guardian_common/config.py`) into an explicit, provider-neutral configuration
> contract. **No real secrets live in Git.** The template is
> [`.env.production.example`](../../.env.production.example); the real file is `.env.production`
> (git-ignored via `.gitignore` `.env.*`, with `!.env.production.example` re-including only the
> template).

## 1. Where secrets come from

The platform is 12-factor: **all** configuration is read from `GUARDIAN_*` environment variables
(`config.py` `SettingsConfigDict(env_prefix="GUARDIAN_")`). There is **no** secrets-manager
integration in the codebase, by design — secrets are injected at runtime by the deployment
substrate. Two supported injection paths, both keeping secrets out of the image and out of Git:

| Path | How | When |
|------|-----|------|
| **Env file** (reference) | Operator creates `.env.production`, deployment runs `docker compose --env-file .env.production -f docker-compose.prod.yml …`. Compose interpolates values into per-plane `environment:` blocks. | Single-host / self-managed. |
| **External secrets manager** | Vault / AWS SSM / GCP Secret Manager / K8s Secrets inject the same `GUARDIAN_*` vars into each container's environment at start. `.env.production` is then unnecessary. | Orchestrated / multi-host. |

> **Stop point (external provisioning):** choosing and wiring a specific secrets manager requires a
> provider decision and real credentials that are **not** in this repo. The repo provides the
> **contract** (which variables, which plane, which invariant); the actual provisioning is an
> operator step. This is a documented boundary, not a code blocker.

## 2. Generating the secrets

```bash
# Symmetric keys / passwords — 256-bit hex
openssl rand -hex 32     # GUARDIAN_JWT_SECRET
openssl rand -hex 32     # GUARDIAN_ENCRYPTION_KEY        (distinct from all others)
openssl rand -hex 32     # GUARDIAN_BROKER_SEAL_KEY       (distinct from ENCRYPTION_KEY)
openssl rand -hex 32     # GUARDIAN_REDIS_PASSWORD
openssl rand -base64 24  # GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD

# Ed25519 job-signing keypair (raw 32-byte seed / public, base64)
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
import base64
sk = Ed25519PrivateKey.generate()
raw_priv = sk.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
raw_pub  = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
print("GUARDIAN_JOB_SIGNING_PRIVATE_KEY=", base64.b64encode(raw_priv).decode())
print("GUARDIAN_JOB_SIGNING_PUBLIC_KEY =", base64.b64encode(raw_pub).decode())
PY
```

## 3. The invariant matrix (enforced at startup)

`config.py::_enforce_production_invariants` runs on every process at import. Outside
`{local,dev,development,test,ci}` it refuses to boot unless **all** of these hold. `staging` counts
as production-grade.

| Requirement | Rule | Enforced at |
|-------------|------|-------------|
| Env engaged | `GUARDIAN_ENV` ∉ local set | `config.py:146-148` |
| JWT secret (control planes) | set, ≠ dev sentinel | `config.py:187` |
| JWT secret (execution planes) | **must NOT** be a real secret | `config.py:180-186` |
| App DB role (non-execution) | `APP_DATABASE_URL` set & ≠ `DATABASE_URL` | `config.py:191-197` |
| KMS master (control planes) | set, ≠ dev sentinel | `config.py:210-213` |
| KMS master (execution planes) | **forbidden** | `config.py:202-209` |
| Broker-seal key (non-recon) | set, ≠ dev sentinel, **≠ ENCRYPTION_KEY** | `config.py:219-228` |
| Tool-plane signing key | private key **never** on tool plane (all envs); public key **required** on tool plane in prod | `config.py:164-169, 232-236` |
| Redis TLS | URL starts `rediss://` | `config.py:239-243` |
| Redis AUTH | URL carries a password | `config.py:247-252` |
| Bootstrap password | ≠ default, **on every plane** (unconditional) | `config.py:255-259` |
| Postgres TLS | every non-empty DSN has `sslmode` ∈ {require, verify-ca, verify-full} | `config.py:263-269` |

## 4. Per-plane variable applicability

The **same** `.env.production` supplies raw values; `docker-compose.prod.yml` decides which reach
which plane. Two non-obvious rules, surfaced during discovery:

- **worker-default is not an execution plane** → it *also* requires `APP_DATABASE_URL` (distinct),
  even though it connects with the owner DSN.
- **`BOOTSTRAP_ADMIN_PASSWORD` is checked unconditionally** → it must be non-default on *every*
  plane, including `worker-recon` and `worker-tools`, or they will not boot.

| Variable | api | worker-default | worker-recon | worker-tools |
|----------|:---:|:---:|:---:|:---:|
| `GUARDIAN_ENV` | ✅ | ✅ | ✅ | ✅ |
| `GUARDIAN_JWT_SECRET` | ✅ | ✅ | ❌ forbidden | ❌ forbidden |
| `GUARDIAN_ENCRYPTION_KEY` | ✅ | ✅ | ❌ forbidden | ❌ forbidden |
| `GUARDIAN_BROKER_SEAL_KEY` | ✅ | ✅ | ❌ (never seals) | ✅ required |
| `GUARDIAN_JOB_SIGNING_PRIVATE_KEY` | ✅ | ✅ | ❌ | ❌ forbidden |
| `GUARDIAN_JOB_SIGNING_PUBLIC_KEY` | ✅ | ✅ | — | ✅ required |
| `GUARDIAN_DATABASE_URL` | ✅ owner | ✅ owner | `""` empty | `""` empty |
| `GUARDIAN_APP_DATABASE_URL` | ✅ app role | ✅ (distinct) | — | — |
| `GUARDIAN_REDIS_URL` (rediss+AUTH) | ✅ | ✅ | ✅ | ✅ |
| `GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD` (non-default) | ✅ | ✅ | ✅ | ✅ |
| `GUARDIAN_TRUSTED_PROXY_COUNT` | ✅ | — | — | — |
| `GUARDIAN_CORS_ORIGINS` | ✅ | — | — | — |
| `GUARDIAN_TOOL_PLANE` | — | — | — | `true` |
| `GUARDIAN_RECON_PLANE` | — | `false` | `true` | — |
| `GUARDIAN_SANDBOX_ENGINES` | — | per policy | `true` | `true` |

## 5. Verification

```bash
# The startup invariants are unit-tested; a misconfig raises ValueError before serving.
# Dry-run one plane's config resolution against a filled .env.production:
set -a && . ./.env.production && set +a
python -c "from guardian_common.config import Settings; Settings(); print('control-plane config OK')"
# Execution plane (must NOT carry JWT/KMS):
GUARDIAN_TOOL_PLANE=true GUARDIAN_DATABASE_URL='' GUARDIAN_JWT_SECRET='' GUARDIAN_ENCRYPTION_KEY='' \
  python -c "from guardian_common.config import Settings; Settings(); print('tool-plane config OK')"
```

A red result here is the platform doing its job — fix the flagged variable, never weaken the check.
