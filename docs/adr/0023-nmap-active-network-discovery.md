# ADR-023 — Nmap active network discovery provider (L2, argv-isolated, no root)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Nmap is the first tool to run an **external binary that opens its own sockets** — the case the whole
Framework was built to govern rather than trust. Governance-wise it is L2 ACTIVE_RECON (like web_tls),
so Phase A/B already govern it: authorization + human approval + capability level. The open question
was execution safety: the current backend's egress guard is a Python-socket monkeypatch that does
**not** constrain an external process, and true kernel-level egress isolation (netns/nftables) is a
future execution backend (Discovery 0020, deferred). The locked scope: TCP connect scan only, no root,
no NSE/UDP/OS/raw, no free-form args, no sweep — implemented within the current backend.

## Decision (CTO-locked)

Ship **`nmap`** as a narrow, offline-first-testable L2 provider. No migration; DB head stays
`0010_phase_b_governance`. No python-nmap dependency (stdlib XML). No new backend.

1. **Scope is the argv.** `build_nmap_argv` builds the ENTIRE command from validated authorized **IP**
   targets and an integer port list on a fixed template: `nmap -sT -Pn -n --host-timeout 60s
   -oX - -p <ports> <ips>`. Every target must parse as an IP (a value can never smuggle a flag);
   every port is an int in the capability allowlist (policy can only narrow). **No shell, no
   free-form args, no `--script`/NSE, no `-sS/-sU/-O` (raw/UDP/OS), no host-discovery sweep, no
   CIDR.** nmap physically scans only what the Control Plane put in its argv.
2. **No root.** `-sT` connect scan uses the normal TCP stack — no `CAP_NET_RAW`, no privilege.
   `-n` disables DNS/reverse-DNS (IP-only, no resolution ambiguity / rebinding).
3. **Bounded, contained subprocess.** `run_nmap` launches `shell=False` in its own process group
   (`start_new_session=True`), bounds wall time and total output (4 MB), and kills the whole process
   group on timeout/overflow. It never raises; it returns a typed result. The sandbox's rlimits
   (CPU/mem/NPROC) are inherited by nmap; FD hygiene and temp isolation apply.
4. **Offline-first, hermetic.** Without `allow_live` the provider parses a provided nmap XML snapshot
   (CI needs no nmap and no network). XML is parsed with stdlib after **rejecting any DTD/entity**
   (XXE / billion-laughs defense with no dependency) and under the size cap. Malformed/oversized/
   timed-out/erroring ⇒ a `failed`/`timeout` scan-evidence, **no service evidence, no finding**.
5. **Assessment, not discovery.** Open services are recorded as `nmap_service` evidence; a small set
   of sensitive exposed services (Telnet/FTP/SMB/RDP/MySQL/PostgreSQL/SMTP) is derived into
   conservative findings. The provider **never creates IP/Service graph nodes**; findings bind to an
   **existing** asset via the target IP's `Authorization.asset_id` (Control Plane), else Evidence-only.
   No exploitation/brute/fuzzing/vuln inference — an open port is exposure, not a vulnerability.
6. **Governance reused unchanged.** L2 ⇒ authorization + human approval; a normal analyst (L0) cannot
   run it; a service account (≤ L2) can within its grant. The provider declares only capabilities and
   never self-authorizes; the execution plane stays DB-less and identity-less.

## Alternatives considered

- **Kernel-level egress isolation now (netns/nftables/container).** Deferred (not required by the
  locked scope): v1's network-scope control is the argv + `-n` + IP-only + no-root, consistent with
  the platform's existing trusted-binary precedent (`sast_engine` runs `semgrep` via subprocess).
- **SYN/UDP/OS/NSE or `--script`.** Rejected: raw sockets need root and NSE is an arbitrary-code /
  policy-bypass channel — the exact things the argv template forbids.
- **python-nmap dependency.** Rejected: stdlib `-oX -` parsing with DTD rejection is enough.
- **Auto-create IP/Service nodes from results.** Rejected: that is world-model discovery, out of
  scope; nmap observes, binding to an existing asset only.

## Consequences

- The Framework now runs a real active network tool, fully governed, with scope enforced at the argv
  boundary and the process bounded/killable — proving the rail on an external binary.
- 6C.4/6D/6E/6F, Framework P1, Providers #1/#2/#3, Phase A/B, Evidence chain, World Model, Attack
  Graph, RLS are unchanged; DB head stays `0010_phase_b_governance`.

### Deferred / technical debt (documented, NOT a workaround)

- **OS-level network-egress isolation for the external binary** (netns + nftables bound to the
  authorized IPs). **KNOWN SECURITY LIMITATION of Nmap v1 — explicitly accepted, CTO-signed-off.**
  v1 does **NOT** provide kernel-level network isolation for the nmap process: its network-scope
  control is the argv (validated authorized IPs) + `-n` + IP-only + no-root, plus the trusted-binary
  assumption. There is **no guarantee at the network layer** that a compromised or misbehaving nmap
  binary could not reach beyond its argv targets — nothing at the kernel/socket layer stops it today
  (the Python egress guard does not constrain an external process). Treat v1 accordingly: run it only
  against authorized scope, on trusted infrastructure, with the trusted nmap binary. **A real
  kernel-enforced egress boundary (per-run network namespace + nftables allowlist bound to the
  authorized IPs) will land later as part of a dedicated execution backend (Discovery 0020); until
  then this gap stands.** This is the key item any future review of Nmap must re-examine.
- Domain targets (resolve-and-pin to authorized IPs) — v1 is IP-only; hostname authorizations are
  not scanned.
- Streaming output cap (v1 caps after `communicate`); richer service/CPE facts; version-detection
  (`-sV`) behind a flag. Everything already deferred by ADR-011…022.
