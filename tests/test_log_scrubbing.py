"""Logs and data boundaries must agree on what a secret looks like (audit YELLOW-1).

The log processor used one regex matching `key=value` for five key names. The data boundaries —
findings, reports, AI prompts, webhooks, ticket bodies — used WP-F2's twelve shape-based patterns.
A platform with two definitions of "secret" leaks through the weaker one, and the weaker one was
guarding the artefact most likely to be shipped to a third-party log aggregator.

Every credential shape the boundary redaction knows is asserted here against the *log* path.
"""

from __future__ import annotations

import pytest
from guardian_common.logging import _scrub

# Assembled at runtime so this file contains no literal that a secret scanner would flag — the same
# reason the WP-F2 tests do it.
SAMPLES = {
    "aws_access_key_id": "AKIA" + "IOSFODNN7EXAMPLE",
    "github_token": "ghp_" + "a" * 36,
    "slack_token": "xoxb-" + "1234567890-1234567890-" + "b" * 24,
    "stripe_key": "sk_" + "live_" + "c" * 24,
    "google_api_key": "AIza" + "d" * 35,
    "npm_token": "npm_" + "e" * 36,
    "pypi_token": "pypi-" + "AgEIcHlwaS5vcmc" + "f" * 20,
    "jwt": "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxIn0." + "g" * 20,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    "url_credentials": "postgresql://guardian:s3cret@db.internal:5432/guardian",
}


def _line(value: str) -> dict:
    return _scrub(None, None, {"event": "something_happened", "detail": value})


@pytest.mark.parametrize(("name", "secret"), sorted(SAMPLES.items()))
def test_every_boundary_pattern_is_also_scrubbed_from_logs(name, secret):
    out = _line(f"observed {secret} while working")["detail"]
    assert secret not in out, f"{name} reached a log line intact"


def test_the_original_assignment_pattern_still_applies():
    """Kept as a floor: it fires on key *names* where the shape patterns fire on values."""
    out = _line('config: password="hunter2" loaded')["detail"]
    assert "hunter2" not in out


def test_a_credential_nested_in_a_structure_is_scrubbed():
    """The old processor only walked top-level strings, so a dict argument sailed straight past."""
    event = _scrub(None, None, {
        "event": "engine_finished",
        "context": {"env": {"AWS_SECRET_ACCESS_KEY": SAMPLES["aws_access_key_id"]}},
        "items": [{"token": SAMPLES["github_token"]}],
    })
    blob = str(event)
    assert SAMPLES["aws_access_key_id"] not in blob
    assert SAMPLES["github_token"] not in blob


def test_ordinary_text_is_left_alone():
    """A scrubber that mangles normal logs gets turned off, which is the real failure mode."""
    message = "scan 4f2a completed: 12 findings, 3 critical, engine=secrets duration=4.2s"
    assert _line(message)["detail"] == message


def test_non_string_values_survive():
    event = _scrub(None, None, {"event": "x", "count": 12, "ratio": 0.5, "ok": True, "none": None})
    assert event["count"] == 12
    assert event["ratio"] == 0.5
    assert event["ok"] is True
    assert event["none"] is None


def test_scrubbing_never_raises_and_never_drops_the_line(monkeypatch):
    """A redaction bug must not silence a log line — that would hide the incident it was written
    for. The value falls back to the local pattern rather than disappearing."""
    import guardian_common.logging as mod

    monkeypatch.setattr(mod, "_CORE_RESOLVED", True)
    monkeypatch.setattr(mod, "_CORE_SCRUB",
                        lambda _v: (_ for _ in ()).throw(RuntimeError("redaction exploded")))

    out = _scrub(None, None, {"event": "still_logged", "detail": 'password="hunter2"'})

    assert out["event"] == "still_logged"
    assert "hunter2" not in out["detail"]


def test_the_logger_and_the_boundary_use_the_same_pattern_set():
    """The invariant, stated directly: if WP-F2 learns a new credential shape, logs learn it too."""
    from guardian_core.redaction import _PATTERNS

    for name, _pattern in _PATTERNS:
        if name == "assigned_secret":  # covered by the local floor pattern, tested above
            continue
        assert name in SAMPLES, (
            f"redaction pattern {name!r} has no log-scrubbing regression test — add a sample so a "
            f"new credential shape cannot be taught to the boundary and not to the logs"
        )
