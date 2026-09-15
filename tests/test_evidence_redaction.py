"""Evidence redaction at the persistence boundary (Phase-0 audit fix P1-1).

The evidence key-scrub drops fields whose NAME is sensitive, but a provider can put a credential
VALUE in a benignly-named field. gitleaks is the motivating case: it reports the secret itself in a
`Match` field, and the DB and console read straight from the persisted evidence content. These tests
pin that a credential-shaped value cannot survive into the canonical evidence, whatever field it
sits in — so no future provider can leak a secret to `evidence_items` or the UI by naming a field
innocently.
"""

from __future__ import annotations

import json

from guardian_core.tool import RawEvidence
from guardian_scanner.tools.evidence import _canonical


def _evidence(data: dict) -> RawEvidence:
    return RawEvidence(
        tool="gitleaks", execution_id="job-1", target="repo:example/app",
        kind="secret_leak", data=data,
        provenance={"mode": "offline", "source": "gitleaks"}, occurred_at="",
    )


def test_secret_value_in_a_benignly_named_field_is_masked() -> None:
    # gitleaks' real shape: the raw secret lands in `Match`, not in a field named "secret".
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    ev = _evidence({
        "RuleID": "aws-access-key", "File": "config/prod.py", "Line": 42,
        "Match": f"aws_key = {aws_key}", "Description": "AWS Access Key",
    })
    canonical, hits = _canonical(ev)

    assert aws_key not in canonical, "raw AWS key survived into persisted evidence"
    assert "[redacted]" in canonical
    assert hits, "a credential value at persistence must be reported as a defect, not swallowed"
    # The non-secret metadata that makes the finding useful must be preserved.
    body = json.loads(canonical)
    assert body["data"]["RuleID"] == "aws-access-key"
    assert body["data"]["File"] == "config/prod.py"
    assert body["data"]["Line"] == 42


def test_sensitively_named_key_is_dropped_entirely() -> None:
    # The existing key-scrub still applies: a field literally named `secret` is removed, not masked.
    ev = _evidence({"RuleID": "generic", "secret": "hunter2-not-a-pattern", "File": "a.py"})
    canonical, _hits = _canonical(ev)
    assert "hunter2" not in canonical
    assert "secret" not in json.loads(canonical)["data"]


def test_clean_evidence_is_untouched_and_reports_no_hit() -> None:
    ev = _evidence({"RuleID": "none", "File": "README.md", "Line": 1, "Match": "hello world"})
    canonical, hits = _canonical(ev)
    assert hits == []
    body = json.loads(canonical)
    assert body["data"]["Match"] == "hello world"


def test_a_pem_private_key_never_survives() -> None:
    pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
           "-----END RSA PRIVATE KEY-----")
    ev = _evidence({"RuleID": "private-key", "File": "id_rsa", "Match": pem})
    canonical, hits = _canonical(ev)
    assert "BEGIN RSA PRIVATE KEY" not in canonical
    assert "MIIEowIBAAKCAQEA" not in canonical
    assert hits


def test_canonical_is_deterministic() -> None:
    # The hash chain depends on this: the same evidence must canonicalize identically every time.
    ev = _evidence({"RuleID": "x", "File": "b.py", "Match": "token=ghp_" + "a" * 30})
    first, _ = _canonical(ev)
    second, _ = _canonical(ev)
    assert first == second
