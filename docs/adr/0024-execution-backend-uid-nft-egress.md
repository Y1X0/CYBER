# ADR-024 — Execution backend seam + uid+nftables kernel-level egress isolation

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

ADR-023 shipped Nmap with a documented gap: the Python-socket egress guard cannot confine an external
binary, so Nmap v1's network scope was enforced only by the argv (trusted-binary assumption).
Discovery 0024 evaluated real isolation. The locked netns+veth design was blocked in the current
environment (no `iproute2`). A verified alternative — **per-run uid + host nftables egress allowlist,
matched by `meta skuid`** — achieves kernel-level egress confinement without netns, veth, iproute2, a
nested runtime, or a Docker image change, using only `CAP_NET_ADMIN`.

## Decision (CTO-locked, Option B)

Introduce an **execution-backend seam** and a **uid+nft backend** that confines an external binary's
egress at the Linux kernel, per run, from the EffectiveScope. No migration; DB head stays
`0010_phase_b_governance`.

1. **Backend seam.** `execute_tool` selects an `ExecutionBackend` by a name the Control Plane put on
   the ToolJob (`settings["_execution_backend"]`), then runs the provider callable inside it. The
   provider never sees the backend, never builds firewall rules, never decides authorization —
   **Provider boundary unchanged**.
   - `inproc` — the Phase-5 sandbox + Python egress guard (web_tls, pcap, dns_posture, and all offline
     runs). **Behavior unchanged.**
   - `uid_nft` — for external binaries (nmap).
2. **Backend selection.** From `tool_catalog.metadata["execution_backend"]` (admin-overridable, no
   migration), else a code default (`{"nmap": "uid_nft"}`). Everything else stays `inproc`.
3. **Kernel egress confinement (uid_nft), per live run:**
   - a **dedicated unprivileged run-uid** (process-local unique allocator ⇒ concurrent runs never
     share a uid); the binary `setuid`s to it before exec and **cannot regain root**;
   - a private nftables table `guardian_run_<job_id>`, output hook, whose rules are derived
     **deterministically from the EffectiveScope**: `meta skuid <uid>` may reach ONLY the authorized
     destination IPs (IP-pinned, never a runtime hostname) on the authorized TCP ports; **every other
     packet from that uid is DROPPED by the kernel**. DNS (53) is allowed only if a target+53 is
     explicitly in scope.
   - The argv is no longer the security boundary — the kernel is. A fully compromised binary cannot
     send a packet outside its EffectiveScope.
4. **Lifecycle.** Process group + `killpg(SIGTERM→SIGKILL)` on timeout (unchanged runner); **teardown
   deletes the table and frees the uid in a `finally`**; a **startup reaper** removes `guardian_run_*`
   tables orphaned by a crash. Fail-closed: if isolation cannot be established, the external binary is
   **not run** (returns no evidence).
5. **No cross-run / cross-tenant leakage.** Unique uid + unique table per run, rules scoped to the
   run's own uid. The worker-tools container has its own netns, so its rules never touch the host or
   other workers. Tool-plane worker runs `--concurrency=1` (serialized) so uids are unique in-process;
   scale out with more replicas (each its own netns).
6. **Privilege.** `CAP_NET_ADMIN` added to **worker-tools only** (not privileged, no `CAP_NET_RAW` —
   `nmap -sT` needs none). The tool plane already holds no DB/KMS/secrets, so the capability's blast
   radius is a network-isolation manager over its own netns.

## Proven (real, not mocked)

Kernel-level tests (gated on root+nftables, skipped where absent) install the rules and demonstrate,
via a real unprivileged child and live listeners: authorized IP+port → **connected**; unauthorized
port, unauthorized IP, and DNS → **kernel DROP (timeout)**; DNS allowed only when explicitly scoped;
teardown removes the table; the reaper cleans orphans; run A's uid cannot use run B's allowlist.

## Alternatives considered

- **netns + veth + NAT (the originally-locked mechanism).** Blocked: `iproute2` absent → would need a
  Docker image change (a STOP condition). Re-locked to uid+nft (Discovery 0024).
- **gVisor / microVM per run.** Deferred as future defense-in-depth for L4/L5 (documented, not built).
- **slirp4netns.** Rejected: adds a dependency; uid+nft needs none.

## Consequences

- Every external binary now rides one isolated execution rail: kernel-enforced egress ≤ EffectiveScope,
  regardless of the tool's behavior. Nmap's ADR-023 gap is closed within the current environment.
- inproc tools (web_tls/pcap/dns) and all offline runs are unchanged; DB head stays `0010`.
- 6C.4/6D/6E/6F, Framework P1, Phase A/B, Evidence chain, World Model, Attack Graph, RLS unchanged.

### Residual risks / deferred

- **Kernel/nft bug escaping the uid filter** — mitigated by future gVisor/microVM (defense-in-depth).
- **Multi-process concurrency** on one container would need uid-range partitioning; addressed by
  `--concurrency=1` + replica-per-netns. Documented.
- **CAP_NET_ADMIN on worker-tools** — a compromised worker could alter its own netns firewall; blast
  radius limited (no secrets/DB), accepted and documented.
- Domain targets still IP-only (resolve-and-pin deferred); `-sV` behind a flag. Everything deferred by
  ADR-011…023 stands.
