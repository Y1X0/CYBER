"""A minimal Prometheus registry (WP-G4).

Written rather than pulled in, for two reasons that both matter more than the hundred lines.

A scanner platform ships a licence gate and a self-SBOM; adding a dependency to emit four counters
is a poor trade against that. And the exposition format is a text format with a specification — the
part that is easy to get wrong is escaping and label ordering, which is exactly what a test can
pin down.

Deliberately small: counters, gauges, and histograms with fixed buckets. No pushgateway, no
multiprocess mode, no collectors that shell out. Everything is in-process and thread-safe, because
the alternative — a metric that is occasionally wrong under load — is worse than no metric, and an
alert nobody trusts is one that gets muted.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field

# Latency buckets in seconds. Chosen for an API where the interesting question is "did this take
# longer than a person will wait", not microbenchmarking.
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_NAME_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:")


def _valid_name(name: str) -> str:
    if not name or not set(name) <= _NAME_OK:
        raise ValueError(f"invalid metric name: {name!r}")
    return name


def escape_label(value: str) -> str:
    """Escape a label value per the exposition format.

    Backslash first — escaping it after the others would double-escape what they inserted, which
    produces a file Prometheus rejects and nobody notices until an alert does not fire.
    """
    return (str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n"))


def _labels_key(labels: dict | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))


def _render_labels(key: tuple[tuple[str, str], ...], extra: tuple | None = None) -> str:
    pairs = list(key) + list(extra or ())
    if not pairs:
        return ""
    return "{" + ",".join(f'{k}="{escape_label(v)}"' for k, v in pairs) + "}"


@dataclass
class _Metric:
    name: str
    help: str
    kind: str
    buckets: tuple[float, ...] = DEFAULT_BUCKETS
    values: dict = field(default_factory=dict)
    # histogram only: per-label-set bucket counts and sum
    hist: dict = field(default_factory=dict)


class Registry:
    """Everything the process is willing to say about itself."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metrics: dict[str, _Metric] = {}

    # ── declaration ──────────────────────────────────────────────────────────────────────────────
    def counter(self, name: str, help_text: str) -> None:
        self._declare(name, help_text, "counter")

    def gauge(self, name: str, help_text: str) -> None:
        self._declare(name, help_text, "gauge")

    def histogram(self, name: str, help_text: str,
                  buckets: tuple[float, ...] = DEFAULT_BUCKETS) -> None:
        self._declare(name, help_text, "histogram", buckets=tuple(sorted(buckets)))

    def _declare(self, name: str, help_text: str, kind: str,
                 buckets: tuple[float, ...] = DEFAULT_BUCKETS) -> None:
        _valid_name(name)
        with self._lock:
            existing = self._metrics.get(name)
            if existing is not None:
                if existing.kind != kind:
                    raise ValueError(f"{name} is already declared as a {existing.kind}")
                return
            self._metrics[name] = _Metric(name=name, help=help_text, kind=kind, buckets=buckets)

    # ── recording ────────────────────────────────────────────────────────────────────────────────
    def inc(self, name: str, labels: dict | None = None, amount: float = 1.0) -> None:
        if amount < 0:
            # A counter that can go down is a counter whose rate() is meaningless.
            raise ValueError("a counter cannot decrease")
        with self._lock:
            metric = self._require(name, "counter")
            key = _labels_key(labels)
            metric.values[key] = metric.values.get(key, 0.0) + amount

    def set(self, name: str, value: float, labels: dict | None = None) -> None:
        with self._lock:
            metric = self._require(name, "gauge")
            metric.values[_labels_key(labels)] = float(value)

    def observe(self, name: str, value: float, labels: dict | None = None) -> None:
        if math.isnan(value) or math.isinf(value):
            return
        with self._lock:
            metric = self._require(name, "histogram")
            key = _labels_key(labels)
            counts, total, seen = metric.hist.get(key, ([0] * len(metric.buckets), 0.0, 0))
            counts = list(counts)
            for index, bound in enumerate(metric.buckets):
                if value <= bound:
                    counts[index] += 1
            metric.hist[key] = (counts, total + value, seen + 1)

    def _require(self, name: str, kind: str) -> _Metric:
        metric = self._metrics.get(name)
        if metric is None:
            raise KeyError(f"metric {name!r} was never declared")
        if metric.kind != kind:
            raise ValueError(f"{name} is a {metric.kind}, not a {kind}")
        return metric

    # ── exposition ───────────────────────────────────────────────────────────────────────────────
    def render(self) -> str:
        """The text exposition format, deterministically ordered.

        Ordered because a diff between two scrapes should show what changed, not what moved.
        """
        lines: list[str] = []
        with self._lock:
            for name in sorted(self._metrics):
                metric = self._metrics[name]
                lines.append(f"# HELP {name} {metric.help}")
                lines.append(f"# TYPE {name} {metric.kind}")
                if metric.kind == "histogram":
                    for key in sorted(metric.hist):
                        counts, total, seen = metric.hist[key]
                        # `counts` is already cumulative: `observe` increments every bucket whose
                        # bound the value falls under, which is what `le` means.
                        for bound, count in zip(metric.buckets, counts, strict=True):
                            labels = _render_labels(key, (("le", _format(bound)),))
                            lines.append(f"{name}_bucket{labels} {count}")
                        inf = _render_labels(key, (("le", "+Inf"),))
                        lines.append(f"{name}_bucket{inf} {seen}")
                        lines.append(f"{name}_sum{_render_labels(key)} {_format(total)}")
                        lines.append(f"{name}_count{_render_labels(key)} {seen}")
                else:
                    for key in sorted(metric.values):
                        lines.append(f"{name}{_render_labels(key)} {_format(metric.values[key])}")
        return "\n".join(lines) + "\n"


def _format(value: float) -> str:
    if value == int(value):
        return str(int(value))
    return repr(round(value, 6))


# The process-wide registry. One per process, because a metric split across two registries is a
# metric that reads low and an alert that does not fire.
REGISTRY = Registry()

# ── the metrics this platform actually cares about ────────────────────────────────────────────────
# Deliberately few, and each one answers a question somebody would page on. Request rate and latency
# are table stakes; the rest are about whether the *security* function is working, which is the
# thing a generic dashboard never tells you.
REGISTRY.counter("guardian_http_requests_total", "API requests by method, route and status.")
REGISTRY.histogram("guardian_http_request_seconds", "API request duration in seconds.")
REGISTRY.counter("guardian_auth_failures_total", "Rejected credentials, by reason.")
REGISTRY.counter("guardian_authorization_denied_total",
                 "Requests refused by an authorization check, by reason.")
REGISTRY.counter("guardian_scan_engine_runs_total", "Engine runs by engine and status.")
REGISTRY.gauge("guardian_feed_age_seconds", "Age of the newest record from each intelligence feed.")
REGISTRY.gauge("guardian_slo_healthy", "1 when a named SLO is met, 0 when it is not.")
# WP-G2. A quota nobody can see is a quota nobody knows they are hitting: the first sign
# should be a graph, not a customer asking why their pipeline started failing.
REGISTRY.counter("guardian_rate_limited_total", "Requests refused by the per-tenant rate limit.")
REGISTRY.counter("guardian_scan_admission_refused_total",
                 "Scans refused at submission because the tenant was at its concurrency limit.")


__all__ = ["DEFAULT_BUCKETS", "REGISTRY", "Registry", "escape_label"]
