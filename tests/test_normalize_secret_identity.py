"""normalize relocates the keyed secret identity out of evidence (WP-E1 same-secret fix).

This is the security guarantee that lets the identity be persisted at all: it must land in the
dedicated `Finding.secret_correlation_id` column and NOT in `Finding.evidence`, which is serialized
to customers through several paths. A pure `to_finding` call is enough to prove it — no database.
"""

from __future__ import annotations

import uuid

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_scanner.normalize import to_finding

_IDS = dict(
    tenant_id=uuid.uuid4(), customer_id=uuid.uuid4(), scan_id=uuid.uuid4(),
    engine_run_id=uuid.uuid4(), asset_id=uuid.uuid4(),
)


def _raw(evidence: dict) -> RawFinding:
    return RawFinding(
        engine=EngineKey.SECRETS, title="Hardcoded secret", category="secret",
        description="", base_severity=Severity.HIGH, confidence="medium",
        cwe_id="CWE-798", owasp_ref="A07:2021",
        location={"path": "app.py", "line": 3, "rule": "aws-key"},
        evidence=evidence, references={},
    )


def _finding(evidence: dict):
    return to_finding(_raw(evidence), exposure="public", asset_criticality="medium", **_IDS)


def test_the_identity_is_relocated_into_its_own_column_and_stripped_from_evidence():
    finding = _finding({"match": "AK********EY (len=40)", "secret_id_hmac": "deadbeef" * 8})
    # Landed in the dedicated column...
    assert finding.secret_correlation_id == "deadbeef" * 8
    # ...and is GONE from evidence (which is what customer-facing serializers read).
    assert "secret_id_hmac" not in finding.evidence
    # The human-visible redaction is untouched.
    assert finding.evidence["match"] == "AK********EY (len=40)"


def test_a_finding_without_an_identity_has_a_null_column_and_untouched_evidence():
    finding = _finding({"match": "AK********EY (len=40)"})
    assert finding.secret_correlation_id is None
    assert finding.evidence == {"match": "AK********EY (len=40)"}


def test_a_blank_identity_is_treated_as_absent():
    finding = _finding({"match": "x", "secret_id_hmac": ""})
    assert finding.secret_correlation_id is None
    assert "secret_id_hmac" not in finding.evidence


def test_relocation_does_not_mutate_the_raw_findings_evidence():
    raw = _raw({"match": "x", "secret_id_hmac": "abc"})
    to_finding(raw, exposure="public", asset_criticality="medium", **_IDS)
    # The engine's RawFinding is left intact (to_finding copies before stripping).
    assert raw.evidence.get("secret_id_hmac") == "abc"
