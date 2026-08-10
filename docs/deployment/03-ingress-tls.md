# 03 — Production Ingress / TLS

> Deployment Readiness · Phase 3. Fixes discovery findings **D-11** (no ingress / TLS termination),
> **D-12** (trusted proxy count), **D-13** (no request-body limit). Provider-neutral: the reference
> uses **nginx** (self-hostable, not a cloud). The same contract maps to any L7 proxy / cloud LB /
> Kubernetes Ingress.

## 1. What the ingress provides

The API serves plain `uvicorn` on `:8000` and, by design, has **no** in-process TLS, HTTP→HTTPS
redirect, or request-body limit. The ingress supplies all of it and is the **only** internet-facing
service:

| Requirement | Where | Evidence |
|-------------|-------|----------|
| TLS termination | `listen 443 ssl; http2 on;` + operator certs | `infra/nginx/guardian.conf` |
| HTTP → HTTPS | `:80` returns `301 https://…` (ACME path excepted) | `infra/nginx/guardian.conf` |
| Correct `X-Forwarded-For` | `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` | `infra/nginx/guardian.conf` |
| Request-body cap | `client_max_body_size 10m` | `infra/nginx/guardian.conf` |
| `/health`, `/health/ready` | reachable through `location /` | `services/api/src/guardian_api/routes/__init__.py:24` |
| Uvicorn not exposed | API has no published port; on `backend` only | `docker-compose.prod.yml` (api `networks: [backend]`) |
| HSTS | `Strict-Transport-Security` header | `infra/nginx/guardian.conf` |

## 2. Trusted-proxy count (D-12) — must match the topology

`X-Forwarded-For` is client-spoofable, so the app trusts it **only** for the last
`GUARDIAN_TRUSTED_PROXY_COUNT` hops (`config.py:72-76`; client IP resolution in
`services/api/src/guardian_api/deps.py`). Set it to the number of proxies that append XFF in front
of the app:

```
internet ── [cloud LB?] ── nginx ingress ── api
                             └─ appends 1 hop
GUARDIAN_TRUSTED_PROXY_COUNT = 1  (nginx only)   ← reference default
                             = 2  (one cloud LB in front of nginx that also appends XFF)
```

Wrong count → audit logs and login rate-limiting see the proxy IP, not the client. It is **enforced,
not conventional**: a mismatch simply mis-attributes the IP, so validate it (§4).

## 3. Topology

```
            :80/:443 (host)
                │
         ┌──────▼───────┐   networks: edge + backend
         │  ingress     │   TLS term · HTTP→HTTPS · XFF · body cap
         │  (nginx)     │
         └──────┬───────┘
            backend │  http://api:8000  (re-resolved via Docker DNS across replicas)
         ┌──────▼───────┐   networks: backend only — NO published port
         │  api ×N      │   uvicorn, never internet-facing
         └──────────────┘
```

**Cloud / Kubernetes mapping:** replace the nginx service with your managed LB or an Ingress
resource (TLS via cert-manager). Keep the two invariants: (a) the API is never directly public, and
(b) `GUARDIAN_TRUSTED_PROXY_COUNT` equals the real number of XFF-appending hops.

> **Stop point:** choosing a specific cloud LB / ACME provider is an operator decision requiring
> external accounts/DNS. The repo ships the provider-neutral nginx reference + the contract; it does
> not pick a cloud.

## 4. Verification

```bash
# nginx config syntax (with any cert present):
docker run --rm -v "$PWD/infra/nginx/guardian.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$PWD/infra/tls/nginx:/etc/nginx/tls:ro" nginx:1.27-alpine nginx -t

# after deploy:
curl -sS -o /dev/null -w '%{http_code}\n' http://<host>/            # 301 → https
curl -sSk https://<host>/health                                     # {"status":"ok",...}
curl -sSk https://<host>/health/ready                               # {"status":"ready",...}
# client-IP attribution: log in from a known IP, confirm audit_log shows THAT IP, not the proxy.
```
