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
            if not policy.allow_network:
                _install_egress_guard()
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
