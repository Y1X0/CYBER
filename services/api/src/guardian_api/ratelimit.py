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

    def hit(self, key: str) -> tuple[bool, float]:
        """Record an attempt for ``key``. Returns (allowed, retry_after_seconds)."""
        if self._max <= 0:
            return True, 0.0                          # limiter disabled
        now = self._clock()
        with self._lock:
            if len(self._hits) > _MAX_KEYS:
                self._hits.clear()                    # bound memory; brief accuracy loss is fine
            recent = [t for t in self._hits.get(key, ()) if now - t < self._window]
            if len(recent) >= self._max:
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
