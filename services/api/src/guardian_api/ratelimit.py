"""In-process sliding-window rate limiter for the auth endpoint (P1-γ).

No new dependency: a per-process, thread-safe sliding-window counter. It bounds password guessing
and Argon2 CPU-exhaustion from a single source (IP or account) BEFORE the hash runs. It is
per-process by design — a limit shared across replicas is a gateway/infrastructure concern,
deliberately out of the app's scope; this layer protects each process against single-source attacks.
"""

from __future__ import annotations

import ipaddress
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


def client_bucket_key(ip: str | None) -> str | None:
    """A rate-limit bucket key for a resolved client IP, or None when there is no reliable key.

    Returns None for a missing or unparseable value: the caller must then SKIP the per-client bucket
    (and rely on the account bucket) rather than key on a shared placeholder, which would let every
    such request share one bucket and lock each other out.

    An IPv6 address that actually carries an IPv4 client is unwrapped to that IPv4 and keyed on it —
    IPv4-mapped (``::ffff:a.b.c.d``), 6to4 (``2002::/16``) and Teredo all collapse to ``::/64``
    otherwise, which would put every IPv4 client behind a single global bucket. Only a real global
    IPv6 address is keyed by its /64 (a single client is routinely handed a whole /64, so keying on
    the full address would let one host rotate through 2^64 addresses to dodge the limit). IPv4 is
    keyed as-is.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 6:
        embedded = addr.ipv4_mapped or addr.sixtofour
        if embedded is None and addr.teredo is not None:
            embedded = addr.teredo[1]          # Teredo: (server, CLIENT) — key on the client IPv4
        if embedded is not None:
            addr = embedded
        else:
            return str(ipaddress.ip_network(f"{addr}/64", strict=False).network_address) + "/64"
    return str(addr)


def per_client_limiting_enabled(settings) -> bool:  # noqa: ANN001
    """True when the resolved client IP is a trustworthy per-client value to key a limit on.

    Enabled when a proxy hop count is configured (client_ip is then the real client) or on a
    local/dev direct connection. Disabled behind a shared proxy with the count unset
    (production/staging, trusted_proxy_count == 0), where client_ip would be one shared address —
    keying a login limit there could lock everyone out. That misconfiguration is surfaced as a
    startup error and in /health/details rather than silently keying on a shared IP.
    """
    return settings.trusted_proxy_count > 0 or settings.is_local_or_dev


def deployment_warnings(settings) -> list[dict]:  # noqa: ANN001
    """Operational misconfigurations worth surfacing at startup and in /health/details."""
    warnings: list[dict] = []
    if not per_client_limiting_enabled(settings):
        warnings.append({
            "code": "per_client_login_limiting_disabled",
            "severity": "error",
            "detail": (
                "GUARDIAN_TRUSTED_PROXY_COUNT is 0 outside local/dev, so the client IP is an "
                "untrusted shared value and per-client login rate limiting is DISABLED. Password "
                "spraying is only bounded per-account until the proxy hop count is set. Confirm it "
                "via GET /api/v1/auth/proxy-diagnostic and set GUARDIAN_TRUSTED_PROXY_COUNT."
            ),
        })
    return warnings


class SlidingWindowLimiter:
    """Allow at most ``max_hits`` events per ``window_seconds`` per key. Thread-safe."""

    def __init__(self, max_hits: int, window_seconds: float, *, clock=time.monotonic) -> None:  # noqa: ANN001
        self._max = max_hits
        self._window = window_seconds
        self._clock = clock
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, *, max_hits: int | None = None,
            fail_closed: bool = False) -> tuple[bool, float]:
        """Record an attempt for ``key``. Returns (allowed, retry_after_seconds).

        ``max_hits`` overrides the limiter's ceiling for this key only, so one shared window can
        serve callers with different limits (WP-G2: a tenant may be allowed fewer requests than the
        platform default). It is passed per call rather than stored, because a ceiling mutated on a
        shared object is a race between two tenants' requests.

        ``fail_closed`` decides what happens to a brand-new key when the table is full of ACTIVE
        blocks: an authentication key (``acct:`` / ``client:``) must be REFUSED there (Issue 4 —
        an attacker who fills the table must not thereby win an unlimited-guessing window), while a
        best-effort quota key stays fail-open so a full table never denies legitimate traffic.
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
                if len(self._hits) >= _MAX_KEYS and key not in self._hits:
                    # Still full — every remaining key is an ACTIVE block. An auth key fails CLOSED
                    # (refuse this untracked attempt) so a saturated table cannot become an
                    # unlimited-guessing bypass; a best-effort quota key stays fail-open so a full
                    # table never denies legitimate traffic.
                    return (False, self._window) if fail_closed else (True, 0.0)
            recent = [t for t in self._hits.get(key, ()) if now - t < self._window]
            if len(recent) >= ceiling:
                self._hits[key] = recent
                return False, max(0.0, self._window - (now - recent[0]))
            recent.append(now)
            self._hits[key] = recent
            return True, 0.0

    def check(self, key: str, *, max_hits: int | None = None,
              fail_closed: bool = False) -> tuple[bool, float]:
        """Peek whether ``key`` is currently allowed WITHOUT recording an attempt.

        Used to refuse an already-blocked client before spending an expensive Argon2 verification on
        it, while the attempt itself is recorded only on failure. Same fail-open/closed rule as
        ``hit`` for a brand-new key under a saturated table.
        """
        ceiling = self._max if max_hits is None else max_hits
        if ceiling <= 0:
            return True, 0.0
        now = self._clock()
        with self._lock:
            if len(self._hits) >= _MAX_KEYS and key not in self._hits:
                self._evict_expired(now)
                if len(self._hits) >= _MAX_KEYS and key not in self._hits:
                    return (False, self._window) if fail_closed else (True, 0.0)
            recent = [t for t in self._hits.get(key, ()) if now - t < self._window]
            if len(recent) >= ceiling:
                return False, max(0.0, self._window - (now - recent[0]))
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


# ── alert-only untrusted-signup counter (detection, never blocking) ──────────────────────────────
@lru_cache
def _untrusted_signup_breaker() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(0, 60.0)


def reset_untrusted_signup_breaker() -> None:
    _untrusted_signup_breaker.cache_clear()


def record_untrusted_signup() -> None:
    """Count one sign-up from an untrusted client IP; alert (never block) if the flood threshold is
    crossed. A per-client sign-up limit cannot be keyed on an untrusted/shared IP without risking a
    global lockout, so the shared-IP case is made visible here instead of enforced."""
    REGISTRY.inc("guardian_signup_untrusted_ip_total")
    ceiling = get_settings().global_signup_breaker_per_minute
    if ceiling <= 0:
        return
    allowed, _ = _untrusted_signup_breaker().hit("global:signup:untrusted", max_hits=ceiling)
    if not allowed:
        REGISTRY.inc("guardian_signup_breaker_tripped_total")
        now = time.monotonic()
        with _alert_lock:
            global _last_signup_alert  # noqa: PLW0603 - module-level throttle timestamp
            if now - _last_signup_alert >= 60.0:
                _last_signup_alert = now
                log.warning("signup_global_breaker_tripped", threshold_per_minute=ceiling)


_last_signup_alert = 0.0
