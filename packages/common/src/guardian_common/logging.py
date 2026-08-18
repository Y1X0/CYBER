"""Structured JSON logging with secret scrubbing (doc 06 §6 — logs must never leak secrets).

Every process — API, worker, CLI — configures logging through here, so this is the single place a
credential can be caught on its way to a log line.

It used to catch them with one regex, matching `key=value` for five key names, while the data
boundaries (findings, reports, AI prompts, webhooks, tickets) used WP-F2's `guardian_core.redaction`
with twelve patterns covering AWS, GitHub, Slack, Stripe, Google, npm, PyPI, JWTs, private keys and
inline URL credentials. A platform with two different ideas of what a secret looks like will leak
through whichever one is weaker, and the weaker one was guarding the logs — the artefact most likely
to be shipped to a third-party aggregator (readiness audit YELLOW-1).

Both now apply. `guardian_core.redaction` is imported lazily because `guardian_common` deliberately
holds no runtime dependency on `guardian_core` (see `ports.py`); if it cannot be imported the local
pattern still runs, so this is strictly additive and never a downgrade.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog

# The original assignment matcher. Kept as a floor: it fires on key *names* (`password=…`) where the
# shape-based patterns below fire on credential *values*, and the two catch different mistakes.
_SCRUB_PATTERNS = [
    re.compile(r"(?i)(authorization|api[_-]?key|token|password|secret)\"?\s*[:=]\s*\"?[^\s\"',}]+"),
]

_CORE_SCRUB: Any = None
_CORE_RESOLVED = False


def _core_scrub():  # noqa: ANN202
    """Resolve `guardian_core.redaction.scrub` once, or None if the package is not installed."""
    global _CORE_SCRUB, _CORE_RESOLVED  # noqa: PLW0603 - one-time memo for a hot path
    if not _CORE_RESOLVED:
        _CORE_RESOLVED = True
        try:
            from guardian_core.redaction import scrub  # noqa: PLC0415

            _CORE_SCRUB = scrub
        except Exception:  # noqa: BLE001 - the local pattern still applies; logging must not fail
            _CORE_SCRUB = None
    return _CORE_SCRUB


def _scrub(_logger, _method, event_dict):  # noqa: ANN001, ANN202
    core = _core_scrub()
    for key, val in list(event_dict.items()):
        value = val
        if core is not None:
            # Recursive: a credential nested in a dict or list argument is still a credential, and
            # the old top-level-strings-only pass walked straight past it.
            try:
                value, _hits = core(value)
            except Exception:  # noqa: BLE001 - never let redaction turn a log line into a crash
                value = val
        if isinstance(value, str):
            for pat in _SCRUB_PATTERNS:
                value = pat.sub(r"\1=***REDACTED***", value)
        event_dict[key] = value
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", level=getattr(logging, level.upper(), logging.INFO))
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _scrub,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "guardian"):  # noqa: ANN201
    return structlog.get_logger(name)
