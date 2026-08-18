"""Concurrent TCP connect sweep (WP-B2).

Before this, "active discovery" meant connecting to 80 and 443 because those were the two ports a
protocol probe happened to register. That answers "is the website up", not "what is exposed" — and
the services that actually get an organization compromised are the ones nobody meant to publish: a
database on 5432, a Redis with no password on 6379, an SSH daemon on a forgotten jump box.

A TCP connect scan needs no privileges — it is an ordinary `connect()` — so this runs in the
artifact plane alongside every other engine. SYN scanning would need `CAP_NET_ADMIN` and is
deliberately not attempted.

Three safety properties, all enforced here rather than left to the caller:

* **Bounded work.** Ports come from a fixed catalogue, concurrency is capped, and the whole sweep of
  one host has a wall-clock deadline. A scanner that can be pointed at 65535 ports × 10000 hosts is
  a denial-of-service tool with a friendlier name.
* **Bounded rate.** Connections per second are limited, so a sweep degrades nothing on the target.
* **No payloads.** This module opens a connection and reads whatever the service volunteers. It
  never writes. Protocol-specific identification that requires sending a byte lives in
  `fingerprint`, where each probe is a fixed, reviewed string.
"""

from __future__ import annotations

import errno
import selectors
import socket
import time
from dataclasses import dataclass, field

MAX_CONCURRENCY = 128
MAX_PORTS = 2_048
DEFAULT_TIMEOUT = 2.0
DEFAULT_HOST_DEADLINE = 120.0
DEFAULT_RATE = 200.0          # new connections per second
BANNER_BYTES = 512
BANNER_WAIT = 1.5


@dataclass
class OpenPort:
    """One port observed accepting connections."""

    port: int
    banner: str = ""
    latency_ms: int = 0
    attributes: dict = field(default_factory=dict)


@dataclass
class SweepResult:
    """What a sweep saw, including what it could not finish.

    `truncated` and `error` exist so the caller can tell an empty result apart from a host that was
    unreachable or a sweep that ran out of time. Those look identical in a report and only one of
    them means the host is clean.
    """

    host: str
    open_ports: list[OpenPort] = field(default_factory=list)
    scanned: int = 0
    truncated: bool = False
    error: str = ""

    @property
    def complete(self) -> bool:
        return not self.truncated and not self.error


class _RateLimiter:
    """A simple token bucket over wall-clock time."""

    def __init__(self, per_second: float) -> None:
        self._interval = 1.0 / per_second if per_second > 0 else 0.0
        self._next = 0.0

    def wait(self) -> None:
        if self._interval <= 0:
            return
        now = time.monotonic()
        if now < self._next:
            time.sleep(self._next - now)
            now = time.monotonic()
        self._next = max(now, self._next) + self._interval


def sweep(
    host: str,
    ports: list[int] | tuple[int, ...],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = 64,
    rate: float = DEFAULT_RATE,
    deadline: float = DEFAULT_HOST_DEADLINE,
    read_banner: bool = True,
) -> SweepResult:
    """Connect to each port and report the ones that accept.

    A refused connection is a closed port, and a timeout is a filtered one; neither is an error.
    A failure to resolve the host is, and it is returned rather than swallowed.
    """
    result = SweepResult(host=host)
    unique = sorted({int(p) for p in ports if 0 < int(p) < 65536})[:MAX_PORTS]
    if not unique:
        return result

    try:
        family = _family_for(host)
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"[:200]
        return result

    limiter = _RateLimiter(rate)
    selector = selectors.DefaultSelector()
    pending: dict[int, tuple[socket.socket, int, float]] = {}   # fd -> (sock, port, started)
    queue = list(unique)
    started_at = time.monotonic()
    slots = max(1, min(int(concurrency), MAX_CONCURRENCY))

    try:
        while (queue or pending):
            if time.monotonic() - started_at > deadline:
                result.truncated = True
                break

            while queue and len(pending) < slots:
                limiter.wait()
                port = queue.pop(0)
                sock = _start_connect(host, port, family)
                if sock is None:
                    result.scanned += 1
                    continue
                pending[sock.fileno()] = (sock, port, time.monotonic())
                selector.register(sock, selectors.EVENT_WRITE)

            if not pending:
                continue

            for key, _events in selector.select(timeout=0.2):
                sock, port, began = pending.pop(key.fd)
                selector.unregister(sock)
                result.scanned += 1
                if _connected(sock):
                    latency = int((time.monotonic() - began) * 1000)
                    banner = _read_banner(sock) if read_banner else ""
                    result.open_ports.append(
                        OpenPort(port=port, banner=banner, latency_ms=latency)
                    )
                sock.close()

            # A port that never becomes writable inside the timeout is filtered, not open.
            now = time.monotonic()
            for fd in [fd for fd, (_s, _p, began) in pending.items() if now - began > timeout]:
                sock, _port, _began = pending.pop(fd)
                selector.unregister(sock)
                result.scanned += 1
                sock.close()
    finally:
        for sock, _port, _began in pending.values():
            try:
                selector.unregister(sock)
            except (KeyError, ValueError):
                pass
            sock.close()
        selector.close()

    result.open_ports.sort(key=lambda p: p.port)
    return result


def _family_for(host: str) -> int:
    """Resolve once, so the sweep does not repeat a DNS lookup per port."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"no address for {host!r}")
    return infos[0][0]


def _start_connect(host: str, port: int, family: int) -> socket.socket | None:
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        return None
    sock.setblocking(False)
    try:
        sock.connect((host, port))
    except BlockingIOError:
        pass
    except OSError as exc:
        if exc.errno not in {errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK}:
            sock.close()
            return None
    return sock


def _connected(sock: socket.socket) -> bool:
    """A writable socket is not necessarily a connected one — a refused connect is also writable."""
    try:
        return sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
    except OSError:
        return False


def _read_banner(sock: socket.socket) -> str:
    """Read whatever the service volunteers on connect. Nothing is sent.

    Many services announce themselves unprompted — SSH, SMTP, FTP, MySQL, Redis on some builds — and
    that greeting usually carries the exact product and version, which is what turns a port number
    into a vulnerability lookup.
    """
    sock.setblocking(True)
    sock.settimeout(BANNER_WAIT)
    try:
        data = sock.recv(BANNER_BYTES)
    except OSError:
        return ""
    return data.decode("latin-1", "replace").strip()
