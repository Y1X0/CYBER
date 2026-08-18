"""In-process sliding-window rate limiter for the auth endpoint (P1-γ).

No new dependency: a per-process, thread-safe sliding-window counter. It bounds password guessing
and Argon2 CPU-exhaustion from a single source (IP or account) BEFORE the hash runs. It is
per-process by design — a limit shared across replicas is a gateway/infrastructure concern,
deliberately out of the app's scope; this layer protects each process against single-source attacks.
"""

from __future__ import annotations

import threading
import time
from functools import lru_cache

from guardian_common.config import get_settings

_MAX_KEYS = 50_000  # crude memory bound: distinct keys tracked in a window before a hard reset


class SlidingWindowLimiter:
    """Allow at most ``max_hits`` events per ``window_seconds`` per key. Thread-safe."""

    def __init__(self, max_hits: int, window_seconds: float, *, clock=time.monotonic) -> None:  # noqa: ANN001
        self._max = max_hits
        self._window = window_seconds
        self._clock = clock
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, *, max_hits: int | None = None) -> tuple[bool, float]:
        """Record an attempt for ``key``. Returns (allowed, retry_after_seconds).

        ``max_hits`` overrides the limiter's ceiling for this key only, so one shared window can
        serve callers with different limits (WP-G2: a tenant may be allowed fewer requests than the
        platform default). It is passed per call rather than stored, because a ceiling mutated on a
        shared object is a race between two tenants' requests.
        """
        ceiling = self._max if max_hits is None else max_hits
        if ceiling <= 0:
            return True, 0.0                          # limiter disabled
        now = self._clock()
        with self._lock:
            if len(self._hits) > _MAX_KEYS:
                self._hits.clear()                    # bound memory; brief accuracy loss is fine
            recent = [t for t in self._hits.get(key, ()) if now - t < self._window]
            if len(recent) >= ceiling:
                self._hits[key] = recent
                return False, max(0.0, self._window - (now - recent[0]))
            recent.append(now)
            self._hits[key] = recent
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


@lru_cache
def login_limiter() -> SlidingWindowLimiter:
    """Process-wide login limiter, sized from settings (60s window)."""
    return SlidingWindowLimiter(get_settings().auth_rate_limit_per_minute, 60.0)


def reset_login_limiter() -> None:
    """Drop the cached limiter (tests / config reload)."""
    login_limiter.cache_clear()


@lru_cache
def tenant_limiter() -> SlidingWindowLimiter:
    """Process-wide limiter for authenticated traffic, keyed by tenant (WP-G2).

    Sized generously here and narrowed per key at the call site, because a tenant's own limit may be
    lower than the platform's; `hit_limited` applies the caller's ceiling against this window.

    Per-process, like the login limiter and for the same reason: a limit shared across replicas is a
    gateway concern. What that means in practice is stated rather than hidden — with N replicas a
    tenant can reach roughly N× its configured rate before every replica refuses. That is a ceiling
    on damage, not an exact quota, and `guardian_rate_limited_total` is what makes the difference
    visible.
    """
    return SlidingWindowLimiter(0, 60.0)  # the ceiling is supplied per call by `hit_limited`


def hit_limited(key: str, *, limit: int) -> tuple[bool, float]:
    """Record a request for ``key`` and apply ``limit`` to the shared 60-second window.

    A limit of 0 disables the check for that caller — an explicit operational choice, and the only
    way to switch it off.
    """
    if limit <= 0:
        return True, 0.0
    return tenant_limiter().hit(key, max_hits=limit)


def reset_tenant_limiter() -> None:
    tenant_limiter.cache_clear()
