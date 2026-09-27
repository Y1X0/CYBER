# Recon plane — owner-direct active port scanning (nmap)

The recon plane is Guardian's **network plane**: the one privileged execution surface that runs
`nmap` inside a kernel egress cage to actively probe a target's open ports. It is deliberately kept
apart from the artifact/scan plane and locked behind an owner-only, feature-flagged, per-target
affirmation, mirroring owner-direct scanning exactly.

## Authority model (owner-direct-recon)

Recon is gated identically to owner-direct scanning, and every layer is re-checked server-side:

1. **Owner-only.** `POST /api/v1/recon` requires the tenant **OWNER** role, resolved server-side from
   the authenticated principal — never a client flag, a borrowed role, or an API key. A non-owner is
   refused (403) and audited, **even if they hold a verified-ownership authorization** for the target.
2. **Off by default.** The capability does not exist until an operator sets
   `GUARDIAN_OWNER_DIRECT_RECON=true`. While unset, even the owner is refused.
3. **Per-target legal affirmation.** The first recon of a target returns `409` with the exact text
   *"I affirm that I have the legal right and authority to run an active port scan against &lt;target&gt;…"*.
   Re-send with `affirm=true` to record it. The affirmation is stored immutably (`recon_affirmations`,
   unique per tenant+target, RLS-isolated) **and** written to the audit log (`recon.affirmed`).
   Subsequent scans of the same target skip the prompt.
4. **Audited dispatch.** Every dispatch writes `recon.dispatch` with the authority note and the
   `owner-direct-recon` basis. Denials write `recon.owner_direct.denied`.
5. **Re-checked at dispatch.** The trusted `dispatch_tool_job` (default queue, DB) RE-CHECKS the owner
   role and the enable flag before owner-direct can widen scope — it never trusts the caller's flag.
6. **Reported honestly.** A Scan produced under this authority carries
   `authorization_basis = "owner-direct-recon"`.

Owner-direct authority augments the authorized set for that one dispatch (bypassing the ownership
requirement, exactly like owner-direct scanning). It does **not** bypass the two deeper defenses:

- the **DB-authorization gate** is left intact for every non-owner-direct tool dispatch (defense in
  depth); and
- the **uid+nftables egress cage** is MANDATORY and fail-closed — it confines nmap to exactly the
  affirmed target IP and the capability's port allowlist. It is never bypassed.

## Execution path (Route B — the governance-gated tool path)

```
POST /api/v1/recon (owner + flag + affirmation)         → guardian-api (control plane)
  → guardian.dispatch_tool_job  (default queue, DB)      → owner re-check, governance, scope, policy,
                                                            signs the job
    → guardian.run_tool         (tools queue, recon plane) → verifies the signed job, runs nmap in the
                                                            uid+nftables cage, seals evidence back
```

nmap is an `external_binary` provider, so the execution primitive **forces** the `uid_nft` backend
regardless of job settings: each run gets a dedicated unprivileged run-uid and a private nftables
table whose `meta skuid` rules permit egress only to the authorized destination IP + ports; every
other packet from that uid is dropped by the kernel. Without `nft`, or without a proven single
allocator (concurrency 1), the run **fails closed** — nmap is never executed unconfined.

## The two planes and the NET_ADMIN boundary

| | Artifact / scan plane | Recon (network) plane |
|---|---|---|
| Image | `Dockerfile.scanner` | `Dockerfile.recon` |
| Runs as | `USER guardian` (uid 10001) | **root** (needs setuid + nft) |
| Capability | none | **CAP_NET_ADMIN** (recon workflow only) |
| Tools | trivy/gitleaks/syft/grype/osv-scanner/semgrep/checkov | nmap + nftables |
| Queues | `scan` / `default` | `recon,tools` |
| Parses customer artifacts | yes | **never** |

`--cap-add=NET_ADMIN` appears in **`guardian-recon-plane.yml` only**. A CI guard
(`tests/test_recon_plane_isolation.py`) fails the build if the capability ever appears on the
scan/artifact plane. Both planes are DB-less on the execution side and hold no JWT secret and no KMS
master; the recon plane additionally holds no job-signing **private** key (verify-only public key).

### Blast-radius note

CAP_NET_ADMIN lets a process manipulate the container's network namespace. It is granted only to the
recon image, which carries **no customer-artifact parser** — the surface most likely to meet hostile
input stays on the unprivileged plane. Within the recon plane, nmap still drops to an unprivileged
run-uid before exec (root unrecoverable) and every packet is confined by the kernel egress allowlist.
The trade-off is acceptable precisely because the privilege and the untrusted-byte parsing never sit
in the same image.

## Licence

nmap ships under the NPSL, recorded in `docs/TOOL_LICENSES.md` as **`APPROVED_PERSONAL_USE`** — the
NPSL permits personal/educational/non-commercial use but restricts commercial redistribution, and
this deployment has accepted those terms. **Before any commercial use, that row must return to
`LEGAL_REVIEW` and a commercial OEM licence obtained.** The scanner is isolated behind the tool
provider interface, so **naabu (MIT, `APPROVED`)** can replace nmap without re-architecting.

## Operating it

1. Build + push the recon image: run **Guardian Deploy Recon** (`mode: publish`), read the printed
   `@sha256` digest, and repin it in `guardian-recon-plane.yml` (the "Pull the verified recon image"
   step).
2. Set `GUARDIAN_OWNER_DIRECT_RECON=true` on guardian-api and ensure a `default`-queue worker is
   running (it runs `dispatch_tool_job`, which needs the DB + the job-signing private key).
3. Open a recon window: run **Guardian Recon Plane** (workflow_dispatch). It requires the `production`
   environment secrets `GUARDIAN_REDIS_URL`, `GUARDIAN_BROKER_SEAL_KEY`, and the **public**
   `GUARDIAN_JOB_SIGNING_PUBLIC_KEY`.
4. As the owner, `POST /api/v1/recon` with the target IP and `affirm=true`.
