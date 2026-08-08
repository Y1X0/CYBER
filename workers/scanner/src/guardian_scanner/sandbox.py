"""Worker sandboxing (Phase 5A hard gate) — contain a scanner engine's execution.

Scanner engines process untrusted input (a customer's repository, a crafted HTTP response, a
malicious dependency's metadata). A bug or a hostile payload must not be able to exhaust the host,
write outside a scratch dir, or exfiltrate data over the network. This module runs an engine's work
in a **forked child** with:

  * **Resource limits** (OS-enforced via setrlimit): CPU seconds, address space, output file size,
    open files, and no core dumps. A runaway loop or a fork-bomb-ish allocation is killed by the
    kernel, not merely by cooperative code.
  * **Wall-clock deadline** (SIGALRM in the child): covers sleeps/blocking that CPU time doesn't.
  * **Temp isolation**: the child runs in a fresh, private scratch directory, removed afterwards.
  * **Egress restriction**: for passive engines (SAST/secrets/SCA) all INET socket creation is
    denied inside the child; only engines that legitimately reach an authorized target
    (DAST/API) are allowed network.

Honesty about the boundary: the egress guard is a Python-level block — it stops accidental and
most-real egress, but a determined attacker with native-code execution could bypass a pure-Python
guard. Full isolation of *hostile* code needs OS namespaces/seccomp or a container per run; that is
the production upgrade this seam is built for. The rlimits and the process boundary, by contrast,
are hard kernel guarantees. This MVP suffices for internal/authorized scanning; enabling external
untrusted scanning at scale should turn on the container-per-run backend behind the same interface.

Opt-in: `run_scan` sandboxes engines only when `settings.sandbox_engines` is true, so the in-process
test path is unaffected. The primitive itself is tested directly.
"""

from __future__ import annotations

import ipaddress
import os
import pickle
import resource
import signal
import socket
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from guardian_core.enums import EngineKey

# Engines permitted outbound network — they intentionally contact an authorized target. Everything
# else runs network-denied. (Authorization for active scanning is enforced separately, upstream.)
_NETWORK_ENGINES: frozenset[EngineKey] = frozenset({EngineKey.DAST, EngineKey.API})

_MB = 1024 * 1024


class SandboxViolation(RuntimeError):
    """Raised in the parent when the sandboxed child breached a limit, was killed, or errored."""


@dataclass(frozen=True)
class SandboxPolicy:
    cpu_seconds: int = 60          # RLIMIT_CPU — CPU time, hard-killed by the kernel (SIGXCPU/KILL)
    wall_seconds: int = 120        # SIGALRM deadline — also bounds blocking/sleeping work
    memory_mb: int = 2048          # RLIMIT_AS — total virtual address space (counts mapped libs)
    fsize_mb: int = 256            # RLIMIT_FSIZE — largest file the child may write
    open_files: int = 256          # RLIMIT_NOFILE
    max_processes: int = 64        # RLIMIT_NPROC — caps fork() in the child (fork-bomb containment)
    allow_network: bool = False    # INET socket creation permitted inside the child


def policy_for(engine_key: EngineKey, **overrides: Any) -> SandboxPolicy:
    """Default policy for an engine: network only for engines that reach an authorized target."""
    base = SandboxPolicy(allow_network=engine_key in _NETWORK_ENGINES)
    return SandboxPolicy(**{**base.__dict__, **overrides}) if overrides else base


def _install_egress_guard() -> None:
    """Block creation of INET/INET6 sockets in this process (deny outbound network)."""
    real_socket = socket.socket

    class _BlockedSocket(real_socket):  # type: ignore[misc,valid-type]
        def __init__(self, family=socket.AF_INET, *args, **kwargs):  # noqa: ANN002, ANN003
            if family in (socket.AF_INET, socket.AF_INET6):
                raise PermissionError("network egress is disabled in this sandbox")
            super().__init__(family, *args, **kwargs)

    socket.socket = _BlockedSocket  # type: ignore[assignment]

    def _blocked(*_args: Any, **_kwargs: Any):  # noqa: ANN202
        raise PermissionError("network egress is disabled in this sandbox")

    socket.create_connection = _blocked  # type: ignore[assignment]


def _is_internal_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for addresses a recon probe must never reach: RFC1918/ULA private, loopback, link-local
    (which includes the cloud metadata endpoint 169.254.169.254), reserved, multicast, unspecified.
    """
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _resolve_public_address(host: str, port: int) -> str:
    """Resolve `host` and return one validated public IP, or raise if it maps to an internal one.

    SSRF / DNS-rebinding guard (Phase 6C.3.1): the egress allowlist authorizes a *hostname*, but a
    hostname can resolve — or be rebinded — to a private/loopback/link-local/reserved/metadata
    address that C1's network isolation does not IP-filter. We resolve here and fail closed if ANY
    resolved address is internal (which defeats a multi-record rebind), then return the validated IP
    so the caller can pin the connection to it and the real connector cannot re-resolve to a
    different address (TOCTOU-safe).
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    public: str | None = None
    for *_meta, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # an IPv4-mapped IPv6 literal is judged by its embedded IPv4 value
        if _is_internal_ip(ip):
            raise PermissionError(
                f"egress to {host!r} denied: resolves to internal address {ip}"
            )
        if public is None:
            public = sockaddr[0]
    if public is None:
        raise PermissionError(f"egress to {host!r} denied: no resolvable address")
    return public


def _install_egress_allowlist(allowed_hosts: frozenset[str]) -> None:
    """Permit outbound connections only to `allowed_hosts` (the Phase-6C.3 recon egress allowlist).

    Enforced at `socket.create_connection` — the chokepoint the protocol probes use — independently
    of the authorization gate: the host is re-checked here against the allowlist, so a connection to
    any other destination (an unauthorized target, or an internal service like the DB/cache/metadata
    endpoint) raises PermissionError and is contained by the sandbox as a violation. A connection is
    allowed only for a host the allowlist explicitly lists; an empty allowlist denies everything.

    A hostname on the allowlist is additionally resolved and blocked if it maps to an internal
    address, then pinned to the validated public IP (SSRF / DNS-rebinding guard, 6C.3.1). An IP that
    is *itself* on the allowlist is honored as-is — a deliberately authorized internal target is a
    valid choice the operator made explicitly.

    (Raw-socket egress that bypasses `create_connection` is the same residual gap already disclosed
    for the Python-level egress guard, closed by the per-run container/seccomp backend this seam is
    built for — see the module docstring and ADR-011.)
    """
    real_create_connection = socket.create_connection

    def _guarded(address, *args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        host = address[0] if isinstance(address, (tuple, list)) and address else None
        if host not in allowed_hosts:
            raise PermissionError(
                f"egress to {host!r} denied: host is not in the recon allowlist"
            )
        try:
            ipaddress.ip_address(host)  # an explicitly authorized IP literal is honored as-is
        except ValueError:
            # A hostname: resolve, block internal resolutions, and pin to the validated IP so the
            # real connector cannot re-resolve to a rebinded address.
            port = address[1] if isinstance(address, (tuple, list)) and len(address) > 1 else 0
            safe_ip = _resolve_public_address(host, port)
            address = (safe_ip, *tuple(address[1:]))
        return real_create_connection(address, *args, **kwargs)

    socket.create_connection = _guarded  # type: ignore[assignment]


def _close_inherited_fds(keep: set[int]) -> None:
    """Close file descriptors inherited from the parent (except `keep`) inside the forked child.

    A fork copies the parent's descriptor table, so the child would otherwise inherit the parent's
    open sockets — including a Postgres/Redis connection. RLIMIT_NOFILE only caps *new* descriptors,
    and the egress guard only covers `create_connection`, so neither stops a probe from reusing an
    inherited DB connection. Closing them here (6C.4) makes an inherited connection unusable in the
    child; closing the child's own copy never affects the parent's descriptor.
    """
    try:
        max_fd = os.sysconf("SC_OPEN_MAX")
    except (ValueError, OSError, AttributeError):
        max_fd = 4096
    max_fd = min(max_fd, 65536)  # bound the scan; the real table is tiny
    for fd in range(3, max_fd):
        if fd in keep:
            continue
        try:
            os.close(fd)
        except OSError:
            pass  # not open — nothing to close


def _apply_limits(policy: SandboxPolicy) -> None:
    """Apply OS resource limits + the wall-clock alarm inside the child. Best-effort per limit."""
    def _set(res: int, soft: int, hard: int | None = None) -> None:
        try:
            resource.setrlimit(res, (soft, hard if hard is not None else soft))
        except (ValueError, OSError):
            pass  # a limit we can't tighten (e.g. below the current hard cap) is skipped, not fatal

    _set(resource.RLIMIT_CPU, policy.cpu_seconds)
    _set(resource.RLIMIT_AS, policy.memory_mb * _MB)
    _set(resource.RLIMIT_FSIZE, policy.fsize_mb * _MB)
    _set(resource.RLIMIT_NOFILE, policy.open_files)
    if hasattr(resource, "RLIMIT_NPROC"):
        # Cap process creation so a fork-bomb in the child cannot exhaust the host. Per-uid and not
        # enforced for privileged (root) processes — the container `pids_limit` is the production
        # backstop (6C.4); this is the in-process layer.
        _set(resource.RLIMIT_NPROC, policy.max_processes)
    _set(resource.RLIMIT_CORE, 0)  # no core dumps (may contain secrets from memory)

    # Wall-clock deadline: SIGALRM's default action terminates the process.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(policy.wall_seconds)


def run_in_sandbox(func: Callable[[], Any], policy: SandboxPolicy) -> Any:
    """Run `func()` in a resource-limited, temp-isolated, egress-restricted child process.

    Returns the pickled return value of `func`. Raises SandboxViolation if the child breached a
    limit, was killed by a signal, exited non-zero, or raised — the parent is never destabilized.
    """
    read_fd, write_fd = os.pipe()
    pid = os.fork()

    if pid == 0:  # ── child ──
        exit_code = 0
        try:
            os.close(read_fd)
            # Neutralize inherited descriptors (e.g. the parent's DB/cache sockets) before running
            # untrusted work — keep only stdio and the result pipe (6C.4).
            _close_inherited_fds(keep={0, 1, 2, write_fd})
            if not policy.allow_network:
                _install_egress_guard()
            else:
                # Network-permitted work (a probe reaching an authorized target): if a recon egress
                # allowlist is active, enforce it here at the socket layer — a second defense that
                # does not trust the orchestrator's target selection. No allowlist (None) → the
                # existing DAST/API behavior (unrestricted egress for network engines) is unchanged.
                from guardian_scanner import egress

                _recon_allowlist = egress.current_allowlist()
                if _recon_allowlist is not None:
                    _install_egress_allowlist(_recon_allowlist)
            with tempfile.TemporaryDirectory(prefix="guardian-sbx-") as scratch:
                os.chdir(scratch)
                _apply_limits(policy)  # limits last, so setup isn't charged against them
                result = func()
                payload = pickle.dumps({"ok": True, "value": result})
        except BaseException as exc:  # noqa: BLE001 - marshal any failure back to the parent
            try:
                payload = pickle.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            except Exception:  # noqa: BLE001 - unpicklable error; send a plain marker
                payload = pickle.dumps({"ok": False, "error": "unpicklable sandbox error"})
            exit_code = 1
        try:
            with os.fdopen(write_fd, "wb") as w:
                w.write(payload)
        finally:
            os._exit(exit_code)

    # ── parent ──
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as r:
        raw = r.read()
    _, status = os.waitpid(pid, 0)

    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        raise SandboxViolation(
            f"sandboxed work killed by signal {sig} ({signal.Signals(sig).name}) — "
            "resource limit or deadline exceeded"
        )
    if not raw:
        raise SandboxViolation("sandboxed work produced no result (crashed before responding)")
    try:
        # Trusted source: `raw` is produced only by our own child via the private pipe.
        message = pickle.loads(raw)  # noqa: S301
    except (pickle.PickleError, EOFError) as exc:
        raise SandboxViolation(f"could not decode sandbox result: {exc}") from exc
    if not message.get("ok"):
        raise SandboxViolation(message.get("error", "unknown sandbox failure"))
    return message["value"]


def supported() -> bool:
    """True where the fork-based sandbox can run (POSIX). Windows falls back to in-process."""
    return hasattr(os, "fork") and sys.platform != "win32"
