"""Recon egress allowlist (Phase 6C.3) — the second, independent egress defense layer.

The Authorization Gate (`guardian_scanner.discovery.authorization`) decides, in application logic,
*which* targets a run may probe. This module enforces, at the socket layer inside the sandbox, that
a probe can only connect to a host on that allowlist. The two are deliberately independent: a bug
that leaked an unauthorized target past the gate, or a probe that tried to reach an internal service
(the database, the cache, a cloud metadata endpoint), is still blocked at execution time — without
trusting the orchestrator's decision. Defense in depth: gate (logic) + allowlist (runtime).

The allowlist is a process-wide value, established by the recon task for the duration of active
providers (`allowlist(...)`) and read by the sandbox's egress guard (`current_allowlist()`). Because
the sandbox forks, the child inherits the allowlist in memory and re-checks every outbound
connection against it. It is scoped to one active-recon task at a time — true under Celery prefork,
where each worker child runs a single task — and restored on exit, so it never bleeds into the next
run or tenant.

Empty allowlist means deny-all, never allow-all: an active run with zero cleared targets must not
fall back to unrestricted egress.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager

# None  => no recon allowlist active (non-recon sandbox work is unaffected — allow per policy).
# frozenset => the exact hosts a sandboxed probe may connect to (possibly empty = deny-all).
_allowlist: frozenset[str] | None = None


def current_allowlist() -> frozenset[str] | None:
    """The hosts a sandboxed probe may connect to, or None when no recon allowlist is active."""
    return _allowlist


@contextmanager
def allowlist(hosts: Iterable[str]) -> Iterator[None]:
    """Bind the egress allowlist for the enclosed active-provider work, then restore the previous.

    Restores on exit even on error, so an exception mid-run never leaves the allowlist installed for
    the next run or tenant.
    """
    global _allowlist
    previous = _allowlist
    _allowlist = frozenset(hosts)
    try:
        yield
    finally:
        _allowlist = previous
