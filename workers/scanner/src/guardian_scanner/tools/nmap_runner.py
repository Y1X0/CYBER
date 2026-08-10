"""Safe argv construction + subprocess execution for the Nmap provider.

Two hard security properties live here:

  * **Scope is the argv.** `build_nmap_argv` builds the ENTIRE command from validated, authorized IP
    targets and an integer port list — a fixed flag template, no shell, no free-form user arguments,
    no NSE (`--script`), no `-sS/-sU/-O` (raw/UDP/OS), no host-discovery sweep. Every target must
    parse as an IP address (so a value can never smuggle a flag); every port is an int in scope.
    nmap physically scans only what is in its argv; the argv is 100% Control-Plane-built.
  * **The process is contained.** `run_nmap` launches with `shell=False` in its own process group
    (`start_new_session=True`), bounds wall time and total output, and kills the WHOLE process group
    on timeout or overflow. It never raises into the caller; it returns a typed result.

Note (documented, deferred): the current execution backend gives nmap no OS-level network-egress
isolation (the Python socket guard does not constrain an external binary). v1's network scope
is the argv + `-n` (no DNS) + IP-only targets + no-root `-sT`; kernel-level egress isolation
(netns/nftables) is deferred to a future execution backend.
"""

from __future__ import annotations

import ipaddress
import os
import signal
import subprocess  # noqa: S404 - fixed argv, shell=False, process-group bounded
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

# The per-run unprivileged uid the external binary must drop to (set by the uid+nft backend). When
# set, the binary runs as this uid so host nftables can confine its egress at the kernel by skuid.
_run_uid: ContextVar[int | None] = ContextVar("guardian_run_uid", default=None)


@contextmanager
def run_as_uid(uid: int):
    """Bind the ambient run-uid so a subsequently spawned binary drops to it before exec."""
    token = _run_uid.set(uid)
    try:
        yield
    finally:
        _run_uid.reset(token)


def _drop_privs(uid: int):  # pragma: no cover - runs in the forked child before exec
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)          # real=eff=saved=uid ⇒ root cannot be regained


_HOST_TIMEOUT = "60s"
_DEFAULT_WALL = 120          # seconds — outer kill deadline
_MAX_OUTPUT = 4 * 1024 * 1024  # 4 MB XML cap; overflow ⇒ killed + failed
# Service/version detection (Provider #5): a fixed, conservative intensity — never --version-all,
# never NSE. Capped so version probing stays well inside the locked "no fuzzing" boundary.
_VERSION_INTENSITY = 2


def build_nmap_argv(targets: list[str], ports: tuple[int, ...], *,
                    version_detection: bool = False) -> list[str]:
    """Build the full nmap argv from authorized IP targets + in-scope ports. Raises on bad input.

    TCP connect scan (`-sT`, no root), no host discovery (`-Pn`), no DNS (`-n`), XML to stdout.
    With `version_detection`, adds `-sV --version-intensity 2` (Provider #5) — a bounded service
    probe, still no NSE / UDP / OS / free-form args.
    """
    ip_targets: list[str] = []
    for t in targets:
        ip_targets.append(str(ipaddress.ip_address(str(t))))  # rejects hostnames/flags/garbage
    port_list = sorted({int(p) for p in ports})
    if not ip_targets:
        raise ValueError("nmap: no valid IP target in scope")
    if not port_list:
        raise ValueError("nmap: no in-scope port")
    if any(p < 1 or p > 65535 for p in port_list):
        raise ValueError("nmap: port out of range")
    version_flags = ["-sV", "--version-intensity", str(_VERSION_INTENSITY)] if version_detection \
        else []
    return [
        "nmap", "-sT", *version_flags, "-Pn", "-n", "--host-timeout", _HOST_TIMEOUT,
        "-oX", "-", "-p", ",".join(str(p) for p in port_list), *ip_targets,
    ]


@dataclass(frozen=True)
class NmapResult:
    status: str            # ok | timeout | overflow | failed | not_installed
    xml: bytes = b""
    returncode: int | None = None


def _killpg(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def run_nmap(argv: list[str], *, wall_seconds: int = _DEFAULT_WALL,
             max_output: int = _MAX_OUTPUT) -> NmapResult:  # pragma: no cover - exercised via fakes
    """Run nmap in its own process group, bounded by wall time and output size. Never raises."""
    uid = _run_uid.get()
    preexec = (lambda: _drop_privs(uid)) if uid is not None else None
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is validated/fixed, shell=False
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=preexec,
        )
    except FileNotFoundError:
        return NmapResult(status="not_installed")
    except OSError:
        return NmapResult(status="failed")

    try:
        out, _ = proc.communicate(timeout=wall_seconds)
    except subprocess.TimeoutExpired:
        _killpg(proc)
        return NmapResult(status="timeout")
    except OSError:
        _killpg(proc)
        return NmapResult(status="failed")

    if out is not None and len(out) > max_output:
        return NmapResult(status="overflow", returncode=proc.returncode)
    if proc.returncode != 0:
        return NmapResult(status="failed", returncode=proc.returncode, xml=out or b"")
    return NmapResult(status="ok", returncode=0, xml=out or b"")
