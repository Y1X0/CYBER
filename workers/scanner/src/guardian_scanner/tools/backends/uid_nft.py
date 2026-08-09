"""uid+nft execution backend — kernel-level egress confinement for external binaries.

For a live external-binary run (e.g. nmap), the security boundary is NOT the argv — it is the Linux
kernel. Each run gets:

  * a dedicated, unprivileged **run-uid** (the binary drops to it before exec; root unrecoverable);
  * a private nftables table `guardian_run_<job_id>` whose output-hook rules are derived
    deterministically from the EffectiveScope: `meta skuid <uid>` may reach ONLY the authorized
    destination IPs on the authorized TCP ports; every other packet from that uid is DROPPED.

So even a fully compromised binary cannot send a packet outside the run's EffectiveScope — the
kernel drops it. Rules match only the run's own uid, so runs never affect each other or the worker.
Teardown deletes the table and frees the uid in a finally; a startup reaper removes tables orphaned
by a crash. DNS (port 53) is allowed only if a target+53 is explicitly in scope.

Requires the worker to hold CAP_NET_ADMIN (worker-tools only). If isolation cannot be established,
the run fails closed — an external binary is never executed unconfined. Offline runs (no process)
need no confinement and are delegated to the in-process backend.
"""

from __future__ import annotations

import ipaddress
import subprocess  # noqa: S404 - fixed argv, shell=False, values validated (uid int, IP, int port)
import threading
from collections.abc import Callable
from contextlib import contextmanager

from guardian_common.logging import get_logger
from guardian_core.tool import RawEvidence, ToolJob

from guardian_scanner import sandbox
from guardian_scanner.tools.backends.inproc import InprocSandboxBackend
from guardian_scanner.tools.nmap_runner import run_as_uid

log = get_logger("guardian.tools.uid_nft")

_TABLE_PREFIX = "guardian_run_"
_UID_BASE, _UID_TOP = 61000, 62000
_WALL_SECONDS = 180

_lock = threading.Lock()
_used_uids: set[int] = set()


class IsolationError(RuntimeError):
    """Raised when kernel egress confinement cannot be established — the run must fail closed."""


# ── uid allocation (process-local, unique per concurrent run ⇒ no cross-run rule interference) ──
def _alloc_uid() -> int:
    with _lock:
        for uid in range(_UID_BASE, _UID_TOP):
            if uid not in _used_uids:
                _used_uids.add(uid)
                return uid
    raise IsolationError("no free isolation uid")


def _free_uid(uid: int) -> None:
    with _lock:
        _used_uids.discard(uid)


# ── nftables helpers ──
def _nft(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["nft", *args], capture_output=True, text=True, check=False)  # noqa: S603,S607

def _table(job_id: str) -> str:
    safe = "".join(c for c in job_id if c.isalnum() or c == "_")[:48]
    return f"{_TABLE_PREFIX}{safe}"


def _install_rules(table: str, uid: int, job: ToolJob) -> None:
    """Build the run's egress allowlist from EffectiveScope. Fail closed on any error."""
    ports = [int(p) for p in job.scope.ports]
    pins: list[tuple[str, str]] = []
    for target in job.scope.targets:
        host = str(target).split(":")[0]
        try:
            ip = ipaddress.ip_address(host)  # IP-pinned only — never a hostname/DNS at runtime
        except ValueError as exc:
            raise IsolationError(f"non-IP target cannot be confined: {host!r}") from exc
        pins.append(("ip" if ip.version == 4 else "ip6", str(ip)))
    if not pins or not ports:
        raise IsolationError("empty scope: nothing to authorize")

    _delete_table(table)  # idempotent: clear any stale table of the same name
    if _nft("add", "table", "inet", table).returncode != 0:
        raise IsolationError("cannot create nft table (CAP_NET_ADMIN?)")
    chain = "{ type filter hook output priority 0 ; policy accept ; }"
    if _nft("add", "chain", "inet", table, "out", chain).returncode != 0:
        _delete_table(table)
        raise IsolationError("cannot create nft chain")
    for fam, ip in pins:
        for port in ports:
            r = _nft("add", "rule", "inet", table, "out", "meta", "skuid", str(uid),
                     fam, "daddr", ip, "tcp", "dport", str(port), "accept")
            if r.returncode != 0:
                _delete_table(table)
                raise IsolationError("cannot add allow rule")
    # Everything else from this uid is dropped by the kernel — the real boundary.
    if _nft("add", "rule", "inet", table, "out", "meta", "skuid", str(uid), "drop").returncode != 0:
        _delete_table(table)
        raise IsolationError("cannot add drop rule")


def _delete_table(table: str) -> None:
    _nft("delete", "table", "inet", table)  # ignore errors (may not exist)


@contextmanager
def isolate(job: ToolJob):  # noqa: ANN201
    """Allocate a run-uid + install its kernel egress allowlist; tear both down on exit."""
    uid = _alloc_uid()
    table = _table(job.job_id)
    try:
        _install_rules(table, uid, job)
        with run_as_uid(uid):
            yield uid
    finally:
        _delete_table(table)
        _free_uid(uid)


def reap_orphans() -> int:
    """Delete any `guardian_run_*` tables left by a crashed run. Call at worker startup."""
    listing = _nft("list", "tables", "inet")
    removed = 0
    for line in (listing.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "table" and parts[2].startswith(_TABLE_PREFIX):
            _delete_table(parts[2])
            removed += 1
    if removed:
        log.info("reaped_orphan_isolation_tables", count=removed)
    return removed


class UidNftBackend:
    def run(self, job: ToolJob, fn: Callable[[], list[RawEvidence]]) -> list[RawEvidence]:
        # Offline / no live external process ⇒ nothing to confine at the network layer.
        if not (job.settings or {}).get("allow_live"):
            return InprocSandboxBackend().run(job, fn)

        policy = sandbox.SandboxPolicy(
            cpu_seconds=30, wall_seconds=_WALL_SECONDS, allow_network=True)
        try:
            with isolate(job):
                return sandbox.run_in_sandbox(fn, policy)
        except IsolationError as exc:
            log.warning("isolation_unavailable_run_refused", tool=job.tool_key, reason=str(exc))
            return []  # fail closed — never run an external binary unconfined
        except sandbox.SandboxViolation:
            return []
