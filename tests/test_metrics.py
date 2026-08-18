"""The metrics registry and its exposition format (WP-G4).

Written rather than pulled in as a dependency, so its correctness is this repository's problem. The
part that is easy to get wrong is the text format: escaping, label ordering, and cumulative
histogram buckets. Prometheus rejects a malformed scrape, and nobody notices until an alert does not
fire — which is the failure mode the whole package exists to prevent.
"""

from __future__ import annotations

import threading

import pytest
from guardian_common.metrics import Registry, escape_label


def _registry() -> Registry:
    registry = Registry()
    registry.counter("requests_total", "Requests.")
    registry.gauge("queue_depth", "Queued items.")
    registry.histogram("latency_seconds", "Latency.", buckets=(0.1, 1.0))
    return registry


# ── counters ──────────────────────────────────────────────────────────────────────────────────────
def test_a_counter_accumulates_per_label_set():
    registry = _registry()
    registry.inc("requests_total", {"code": "200"})
    registry.inc("requests_total", {"code": "200"})
    registry.inc("requests_total", {"code": "500"})

    rendered = registry.render()
    assert 'requests_total{code="200"} 2' in rendered
    assert 'requests_total{code="500"} 1' in rendered


def test_a_counter_cannot_go_down():
    """A counter that decreases makes every rate() over it meaningless."""
    registry = _registry()
    with pytest.raises(ValueError, match="cannot decrease"):
        registry.inc("requests_total", {}, amount=-1)


def test_an_undeclared_metric_is_an_error_not_a_silent_no_op():
    """A metric that silently does nothing is worse than a missing one: the dashboard shows a flat
    line and everyone reads it as calm."""
    registry = _registry()
    with pytest.raises(KeyError):
        registry.inc("never_declared_total", {})


def test_using_a_metric_as_the_wrong_type_is_refused():
    registry = _registry()
    with pytest.raises(ValueError, match="not a gauge"):
        registry.set("requests_total", 1.0)


def test_redeclaring_with_a_different_type_is_refused():
    registry = _registry()
    with pytest.raises(ValueError, match="already declared"):
        registry.gauge("requests_total", "Requests.")


# ── gauges ────────────────────────────────────────────────────────────────────────────────────────
def test_a_gauge_holds_the_last_value():
    registry = _registry()
    registry.set("queue_depth", 5, {"queue": "scans"})
    registry.set("queue_depth", 2, {"queue": "scans"})
    assert 'queue_depth{queue="scans"} 2' in registry.render()


# ── histograms ────────────────────────────────────────────────────────────────────────────────────
def test_histogram_buckets_are_cumulative():
    """`le` means "less than or equal", so each bucket counts everything below it. A non-cumulative
    histogram renders a p99 that is quietly wrong."""
    registry = _registry()
    registry.observe("latency_seconds", 0.05)
    registry.observe("latency_seconds", 0.5)
    registry.observe("latency_seconds", 5.0)

    rendered = registry.render()
    assert 'latency_seconds_bucket{le="0.1"} 1' in rendered
    assert 'latency_seconds_bucket{le="1"} 2' in rendered
    assert 'latency_seconds_bucket{le="+Inf"} 3' in rendered
    assert "latency_seconds_count 3" in rendered
    assert "latency_seconds_sum 5.55" in rendered


def test_a_non_finite_observation_is_ignored_rather_than_poisoning_the_sum():
    registry = _registry()
    registry.observe("latency_seconds", float("nan"))
    registry.observe("latency_seconds", float("inf"))
    registry.observe("latency_seconds", 0.5)

    assert "latency_seconds_count 1" in registry.render()


# ── exposition ────────────────────────────────────────────────────────────────────────────────────
def test_every_metric_declares_its_help_and_type():
    rendered = _registry().render()
    assert "# HELP requests_total Requests." in rendered
    assert "# TYPE requests_total counter" in rendered
    assert "# TYPE latency_seconds histogram" in rendered


def test_the_output_is_deterministically_ordered():
    """A diff between two scrapes should show what changed, not what moved."""
    registry = _registry()
    for code in ("500", "200", "404"):
        registry.inc("requests_total", {"code": code})
    assert registry.render() == registry.render()
    lines = [line for line in registry.render().splitlines() if line.startswith("requests_total{")]
    assert lines == sorted(lines)


def test_labels_are_ordered_within_a_series():
    registry = _registry()
    registry.inc("requests_total", {"route": "/a", "code": "200"})
    assert 'requests_total{code="200",route="/a"} 1' in registry.render()


@pytest.mark.parametrize(("raw", "expected"), [
    ('a"b', 'a\\"b'),
    ("a\\b", "a\\\\b"),
    ("a\nb", "a\\nb"),
])
def test_label_values_are_escaped(raw, expected):
    """A malformed scrape is rejected wholesale, so one unescaped quote in one label silences every
    metric in the process."""
    assert escape_label(raw) == expected


def test_a_backslash_is_escaped_before_the_characters_that_introduce_one():
    """Escaping in the other order double-escapes what the later replacements inserted."""
    assert escape_label('\\"') == '\\\\\\"'


def test_an_invalid_metric_name_is_refused():
    registry = Registry()
    with pytest.raises(ValueError, match="invalid metric name"):
        registry.counter("has spaces", "x")


# ── concurrency ───────────────────────────────────────────────────────────────────────────────────
def test_counting_from_several_threads_loses_nothing():
    """A metric that is occasionally wrong under load is one that gets muted, and a muted alert is
    the same as no alert."""
    registry = _registry()

    def work() -> None:
        for _ in range(500):
            registry.inc("requests_total", {"code": "200"})

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert 'requests_total{code="200"} 2000' in registry.render()
