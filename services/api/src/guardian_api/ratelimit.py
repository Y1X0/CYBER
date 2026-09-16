"""In-process sliding-window rate limiter for the auth endpoint (P1-γ).

No new dependency: a per-process, thread-safe sliding-window counter. It bounds password guessing
and Argon2 CPU-exhaustion from a single source (IP or account) BEFORE the hash runs. It is
per-process by design — a limit shared across replicas is a gateway/infrastructure concern,
deliberately out of the app's scope; this layer protects each process against single-source attacks.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_common.metrics import REGISTRY

log = get_logger("guardian.ratelimit")

_MAX_KEYS = 50_000  # soft cap on distinct keys tracked; eviction removes only EXPIRED entries


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
            if len(self._hits) >= _MAX_KEYS and key not in self._hits:
                # Memory pressure. NEVER clear the whole map: that would erase active IP/account
                # blocks and let an attacker reset every lockout by churning arbitrary keys. Evict
                # only entries whose entire window has expired — those hold no live limit.
                self._evict_expired(now)
                if len(self._hits) >= _MAX_KEYS:
                    # Still full — every remaining key is an ACTIVE block. Admit this brand-new key
                    # WITHOUT tracking it rather than evict a live block: existing limits stay
                    # intact and memory stays bounded. Fail-open applies only to a never-seen key
                    # under a table full of active blocks, a state made near-unreachable by the
                    # login flow no longer creating account keys once an IP is already blocked.
                    return True, 0.0
            recent = [t for t in self._hits.get(key, ()) if now - t < self._window]
            if len(recent) >= ceiling:
                self._hits[key] = recent
                return False, max(0.0, self._window - (now - recent[0]))
            recent.append(now)
            self._hits[key] = recent
            return True, 0.0

    def _evict_expired(self, now: float) -> None:
        """Drop keys whose every timestamp is older than the window. Caller holds the lock.

        Removes only stale entries, so an active IP/account block is never evicted by capacity
        pressure driven by unrelated key churn.
        """
        stale = [k for k, ts in self._hits.items()
                 if not ts or now - ts[-1] >= self._window]
        for k in stale:
            del self._hits[k]

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


# ── Argon2 concurrency limiter (CPU protection that never blocks a specific user) ────────────────
@lru_cache
def _argon2_gate() -> threading.BoundedSemaphore:
    """Process-wide cap on concurrent Argon2 verifications, sized from settings."""
    return threading.BoundedSemaphore(max(get_settings().login_argon2_max_concurrency, 0) or 1)


def reset_argon2_gate() -> None:
    """Drop the cached semaphore (tests / config reload)."""
    _argon2_gate.cache_clear()


@contextmanager
def argon2_verification_slot() -> Iterator[bool]:
    """Acquire a slot for one Argon2 verification, or yield False if the process is saturated.

    Bounds CPU exhaustion from a login flood WITHOUT blocking by source, so a correct password is
    never denied beyond a short queue and no single client can lock others out. A caller that gets
    False should shed the request with a retryable 503 rather than run the hash. Concurrency 0 in
    settings means "unbounded" — the gate then always yields True.
    """
    if get_settings().login_argon2_max_concurrency <= 0:
        yield True
        return
    timeout = get_settings().login_argon2_acquire_timeout_seconds
    acquired = _argon2_gate().acquire(timeout=timeout)
    try:
        yield acquired
    finally:
        if acquired:
            _argon2_gate().release()


# ── alert-only failed-login breaker (detection, never blocking) ──────────────────────────────────
@lru_cache
def _failed_login_breaker() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(0, 60.0)  # ceiling supplied per call from settings


def reset_failed_login_breaker() -> None:
    _failed_login_breaker.cache_clear()


def record_failed_login() -> None:
    """Count one failed login; if the process-wide 60s threshold is crossed, alert (never block).

    This exists purely for detection — it emits a metric and, on the rising edge of the threshold, a
    log line. It MUST NOT gate the request: a global block would let one attacker deny login to
    everyone, including users with the correct password.
    """
    REGISTRY.inc("guardian_login_failed_total")
    ceiling = get_settings().global_login_breaker_per_minute
    if ceiling <= 0:
        return
    allowed, _ = _failed_login_breaker().hit("global:login:failed", max_hits=ceiling)
    if not allowed:
        REGISTRY.inc("guardian_login_breaker_tripped_total")
        # Rate the alert to once per window so a sustained flood does not flood the log too.
        now = time.monotonic()
        with _alert_lock:
            global _last_breaker_alert  # noqa: PLW0603 - module-level throttle timestamp
            if now - _last_breaker_alert >= 60.0:
                _last_breaker_alert = now
                log.warning("login_global_breaker_tripped", threshold_per_minute=ceiling)


_alert_lock = threading.Lock()
_last_breaker_alert = 0.0
