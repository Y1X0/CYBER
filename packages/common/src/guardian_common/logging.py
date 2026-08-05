"""Structured JSON logging with secret scrubbing (doc 06 §6 — logs must never leak secrets)."""

from __future__ import annotations

import logging
import re

import structlog

# Patterns that must never appear in logs. Best-effort defense-in-depth on top of not logging
# secrets in the first place.
_SCRUB_PATTERNS = [
    re.compile(r"(?i)(authorization|api[_-]?key|token|password|secret)\"?\s*[:=]\s*\"?[^\s\"',}]+"),
]


def _scrub(_logger, _method, event_dict):  # noqa: ANN001, ANN202
    for key, val in list(event_dict.items()):
        if isinstance(val, str):
            for pat in _SCRUB_PATTERNS:
                val = pat.sub(r"\1=***REDACTED***", val)
            event_dict[key] = val
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
