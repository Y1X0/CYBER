# TLS certificates (operator-provided — NOT in Git)

Certificate material is a deployment secret and an **external provisioning step**. Nothing here is
committed: `*.pem`, `*.key`, and `*.crt` are all git-ignored (see the `# Env & secrets` block in
`.gitignore`), so only this README and the directory layout are tracked — never a key or certificate.
This directory only documents what to place where.

```
infra/tls/
├── nginx/
│   ├── fullchain.pem     # server cert + intermediate chain (ingress, Phase 3)
│   └── privkey.pem        # server private key (0600)
├── postgres/             # ONLY if self-hosting the db service (Phase 2/6); managed DB terminates TLS
│   ├── server.crt
│   └── server.key         # 0600, owned by uid 70 (alpine postgres)
└── redis/                # ONLY if self-hosting redis with TLS (Phase 6); managed Redis terminates TLS
    ├── redis.crt
    ├── redis.key          # 0600
    └── ca.crt
```

## Obtaining certificates

- **Public dashboard host:** Let's Encrypt via the ACME HTTP-01 path the ingress already exposes
  (`/.well-known/acme-challenge/`), or your CA of choice. Renew and reload nginx (`nginx -s reload`).
- **Internal service TLS (db/redis):** issue from your internal CA / cert-manager and mount here.

## Verify

```bash
openssl x509 -in infra/tls/nginx/fullchain.pem -noout -subject -enddate
# key/cert must match:
diff <(openssl x509 -in infra/tls/nginx/fullchain.pem -noout -modulus) \
     <(openssl rsa  -in infra/tls/nginx/privkey.pem   -noout -modulus)
```
