# 04 — Plane Network Topology (production contract)

> Deployment Readiness · Phase 4. Turns the compose network model into an explicit isolation
> contract (fixes discovery finding **D-10**). Enforcement already ships in
> `docker-compose.prod.yml` (network membership); the portable
> `infra/k8s/networkpolicies.yaml` reproduces it on Kubernetes. **No orchestrator is forced** — the
> Compose stack is runnable as-is; the K8s manifests are an optional reference.

## 1. Isolation invariants

| Invariant | Enforced by (Compose) | Enforced by (K8s reference) |
|-----------|-----------------------|-----------------------------|
| Execution planes (recon, tools) cannot reach the **database** | not on any network with `db` (`recon-cache` only) | `worker-recon` / `worker-tools` egress omits `db`; `db` ingress allows only api + worker-default |
| Execution planes cannot reach the **API** | API is on `backend`, not `recon-cache` | no egress rule to `plane: api` |
| Database / Redis are never **internet-published** | no `ports:` on `db`/`redis` | `default-deny-all` + no ingress from outside |
| API reachable only via the **ingress** | API on `backend`, no host port; only ingress publishes | `api` ingress allows only `plane: ingress` |
| Execution-plane **egress** to internet is allowed but private ranges blocked | in-process egress allowlist + tool-plane uid+nft (kernel) | `ipBlock` `except` RFC1918 + link-local |

## 2. Egress model (important nuance)

Network isolation here is **not** "no internet." The recon and tool planes must reach the public
internet to do authorized scanning/probing. What must be impossible is reaching **internal**
services (DB, API, metadata, RFC1918). That is enforced in **three** independent layers:

1. **Application** — `sandbox._resolve_public_address` refuses private/loopback/link-local/metadata
   (+ IPv4-mapped-IPv6) and pins connections (the frozen SSRF hardening).
2. **Kernel (tool plane)** — the uid+nft per-run egress allowlist confines external binaries
   (`CAP_NET_ADMIN`, P1-ε).
3. **Network** — the DB/API are simply not routable from the execution planes (compose membership /
   K8s NetworkPolicy `except` private CIDRs).

Defense in depth: a bypass of any one layer is still contained by the others.

## 3. Why shared-network workers are still isolated

`worker-recon` and `worker-tools` share the `recon-cache` network (both need Redis). They are still
mutually isolated in practice: **Celery workers open no inbound listener** — they connect *out* to
Redis and pull jobs. There is no service on another worker to reach. The material isolation is the
**absence of DB credentials and DB routes** on those planes, not port-level separation between them.
The K8s reference tightens this further (each plane's egress is scoped to Redis + internet only).

## 4. Data-store exposure

- Compose: `db` and `redis` declare **no** `ports:` — they are reachable only on the internal
  Docker networks, never from the host/internet. Only `ingress` publishes host ports.
- Managed data stores: keep them on a private subnet / VPC with security groups allowing only the
  API + worker-default (DB) and all four planes (Redis). This is the same contract, enforced by your
  cloud's network primitives.

> **Stop point:** applying the K8s reference requires an actual cluster + CNI and the two
> cluster-specific CIDRs (`<POD_CIDR>`/`<SERVICE_CIDR>`), plus pod labels on your workloads. That is
> an operator/infra decision; the repo ships the portable policy, not a chosen cluster.

## 5. Verification

```bash
# YAML well-formedness of the reference manifests:
python -c "import yaml,sys; list(yaml.safe_load_all(open('infra/k8s/networkpolicies.yaml'))); print('policies OK')"
# On a cluster (dry-run, no apply):
kubectl apply --dry-run=server -n guardian -f infra/k8s/networkpolicies.yaml
# Compose isolation — confirm db/redis publish no host port and recon/tools aren't on backend:
docker compose -f docker-compose.prod.yml --env-file <env> config | \
  python -c "import sys,yaml; s=yaml.safe_load(sys.stdin)['services']; \
print('db ports', s['db'].get('ports')); print('recon nets', list(s['worker-recon']['networks']))"
```
