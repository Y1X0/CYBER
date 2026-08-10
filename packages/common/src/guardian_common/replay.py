"""Shared single-use nonce reservation for signed-job replay protection (P1-1).

`verify_job` must guarantee a signed job envelope executes AT MOST ONCE across ALL tool-plane
workers and hosts — not merely once per process. The tool plane is DB-less by design, but every
worker already shares the Redis broker, so an atomic Redis `SET key val NX EX ttl` reserves a nonce
cluster-wide with no new dependency and no database access on the execution plane. This closes the
cross-process / cross-host replay a per-process cache could not (a captured envelope replayed to a
*different* worker would otherwise re-execute and re-trigger an already-consumed approval).

Fallback: when no shared store is reachable, a process-local set is used — the cross-worker
guarantee then holds only within one process. That fallback is permitted ONLY in local/dev/test/ci
(CI runs a real Redis; unit tests are single-process). In production a shared-store failure is
FAIL-CLOSED: the job is refused rather than trusted as single-use.
"""

from __future__ import annotations

import threading
import time

from guardian_common.config import get_settings

_KEY_PREFIX = "guardian:jobnonce:"
_LOCAL_MAX = 20_000

_local_seen: dict[str, float] = {}
_local_lock = threading.Lock()

_redis_client = None
_redis_lock = threading.Lock()


class ReplayStoreUnavailable(RuntimeError):
    """The shared single-use store is unreachable and local fallback is barred (production)."""


def _client():  # noqa: ANN202
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            if _redis_client is None:
                import redis
                _redis_client = redis.Redis.from_url(
                    get_settings().redis_url, socket_timeout=2, socket_connect_timeout=2)
    return _redis_client


def _reserve_local(nonce: str, ttl: int, now: float) -> bool:
    with _local_lock:
        if len(_local_seen) > _LOCAL_MAX:
            for k, v in list(_local_seen.items()):
                if v <= now:
                    del _local_seen[k]
        prior = _local_seen.get(nonce)
        if prior is not None and prior > now:
            return False
        _local_seen[nonce] = now + ttl
        return True


def reserve_nonce(nonce: str, ttl_seconds: int) -> bool:
    """Atomically reserve `nonce` cluster-wide: True on first use, False on replay.

    Uses Redis `SET NX EX` (the shared broker) as the authoritative single-use gate. On a store
    error, falls back to a process-local set in local/dev/test/ci, but FAILS CLOSED in production
    (`ReplayStoreUnavailable`) so a job is never trusted as single-use without the shared store.
    """
    import redis

    ttl = max(1, int(ttl_seconds))
    now = time.time()
    try:
        return bool(_client().set(f"{_KEY_PREFIX}{nonce}", "1", nx=True, ex=ttl))
    except (redis.RedisError, OSError) as exc:
        if get_settings().is_local_or_dev:
            return _reserve_local(nonce, ttl, now)
        raise ReplayStoreUnavailable("shared replay store unavailable") from exc


def reset_local_for_tests() -> None:
    """Reset the process-local fallback + cached client (test helper only; no production path)."""
    global _redis_client
    with _local_lock:
        _local_seen.clear()
    with _redis_lock:
        _redis_client = None
