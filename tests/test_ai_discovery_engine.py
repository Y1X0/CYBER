"""AI vulnerability-discovery engine — the analyst as a hunter.

The LLM is faked here (a canned complete_json), so no key or network is needed in CI. The properties
under test are the safety rules that make AI discovery trustworthy rather than a hallucination feed:
its findings are ai_assisted hypotheses, labelled unverified, with capped confidence; secrets are
scrubbed before code leaves the process; and — the load-bearing one — the engine is ALWAYS degraded,
so its non-deterministic silence is INCONCLUSIVE and can never resolve a finding.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines import ai_discovery_engine as ade
from guardian_scanner.engines.ai_discovery_engine import AiDiscoveryEngine
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.verification import INCONCLUSIVE, engine_outcome


class _FakeProvider:
    name = "openai_compatible"

    def __init__(self, payload=None, raises=None):
        self._payload = payload if payload is not None else {"findings": []}
        self._raises = raises

    def complete_json(self, *, system, prompt, schema, context=None):  # noqa: ANN001
        if self._raises is not None:
            raise self._raises
        self.last_prompt = prompt
        return self._payload


class _StubProvider:
    name = "stub"

    def complete_json(self, **_):  # noqa: ANN003
        return {}


_ITEM = {
    "title": "Unsanitized input in query", "vuln_type": "SQL injection", "cwe": "CWE-89",
    "severity": "critical", "line": 42, "confidence": "high",
    "explanation": "The username parameter is concatenated into the SQL string at line 42.",
}
_CODE = 'q = "SELECT * FROM users WHERE n=\'" + name + "\'"\n'


def _use_provider(monkeypatch, provider):
    monkeypatch.setattr(ade, "get_provider", lambda: provider)


def _discover(code=_CODE):
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=code)
    return list(AiDiscoveryEngine().run(ctx))


def test_no_op_when_only_the_stub_is_available(monkeypatch):
    _use_provider(monkeypatch, _StubProvider())
    assert _discover() == []


def test_health_is_degraded_and_missing_a_provider_with_the_stub(monkeypatch):
    _use_provider(monkeypatch, _StubProvider())
    h = AiDiscoveryEngine().health()
    assert h.ok is True
    assert h.degraded is True
    assert h.missing == ("ai_provider",)


def test_health_is_still_degraded_even_with_a_real_provider(monkeypatch):
    # The crux: even with a working model, the engine is non-exhaustive, so its silence must never
    # resolve a finding. Degraded is how that is enforced downstream.
    _use_provider(monkeypatch, _FakeProvider())
    h = AiDiscoveryEngine().health()
    assert h.ok is True
    assert h.degraded is True
    assert h.missing == ()
    assert "non-exhaustive" in h.detail


def test_a_completed_run_is_inconclusive_never_resolves():
    class _Run:
        status = "completed"
        engine = EngineKey.AI_DISCOVERY.value
        error = None
        tool_versions = {"ai_discovery": "1.0.0", "degraded": True, "missing": []}

    verdict = engine_outcome(_Run())
    assert verdict.verdict == INCONCLUSIVE
    assert not verdict.is_evidence


def test_a_candidate_becomes_an_ai_assisted_hypothesis(monkeypatch):
    _use_provider(monkeypatch, _FakeProvider({"findings": [_ITEM]}))
    findings = _discover()
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == EngineKey.AI_DISCOVERY
    assert f.category == "ai-suspected"
    assert f.base_severity == Severity.CRITICAL
    assert f.cwe_id == "CWE-89"
    assert f.location["line"] == 42
    assert f.evidence["detector"] == "ai-discovery"
    assert f.evidence["unverified"] is True
    assert "AI-suspected" in f.title
    assert "UNVERIFIED" in f.description


def test_the_engine_declares_ai_assisted_provenance():
    assert AiDiscoveryEngine().finding_source == "ai_assisted"


def test_confidence_is_capped_so_an_ai_lead_is_never_high(monkeypatch):
    _use_provider(monkeypatch, _FakeProvider({"findings": [dict(_ITEM, confidence="high")]}))
    assert _discover()[0].confidence == "medium"      # high -> medium
    _use_provider(monkeypatch, _FakeProvider({"findings": [dict(_ITEM, confidence="medium")]}))
    assert _discover()[0].confidence == "low"          # anything else -> low


def test_secrets_in_code_are_scrubbed_before_reaching_the_model(monkeypatch):
    provider = _FakeProvider({"findings": []})
    _use_provider(monkeypatch, provider)
    secret = "AKIA" + "I" * 16
    _discover(code=f'aws_key = "{secret}"\n')
    assert secret not in provider.last_prompt, "a live secret was shipped to the model"


def test_missing_severity_defaults_to_medium(monkeypatch):
    item = dict(_ITEM)
    item.pop("severity")
    _use_provider(monkeypatch, _FakeProvider({"findings": [item]}))
    assert _discover()[0].base_severity == Severity.MEDIUM


def test_a_bad_cwe_is_dropped_not_propagated(monkeypatch):
    _use_provider(monkeypatch, _FakeProvider({"findings": [dict(_ITEM, cwe="not-a-cwe")]}))
    assert _discover()[0].cwe_id is None


def test_an_item_without_a_title_or_explanation_is_skipped(monkeypatch):
    _use_provider(monkeypatch, _FakeProvider({"findings": [
        {"vuln_type": "x", "severity": "low", "line": 1},
        {"title": "t", "severity": "low", "line": 1},
    ]}))
    assert _discover() == []


def test_a_model_error_does_not_break_the_scan(monkeypatch):
    from guardian_ai.providers.base import LLMError
    _use_provider(monkeypatch, _FakeProvider(raises=LLMError("rate limited")))
    assert _discover() == []


def test_malformed_model_output_is_handled(monkeypatch):
    _use_provider(monkeypatch, _FakeProvider({"not_findings": 1}))
    assert _discover() == []


def test_duplicate_candidates_collapse(monkeypatch):
    _use_provider(monkeypatch, _FakeProvider({"findings": [_ITEM, dict(_ITEM)]}))
    assert len(_discover()) == 1


def test_only_risky_files_are_sent_to_the_model(monkeypatch, tmp_path):
    captured = {"prompts": 0}

    class _Counting(_FakeProvider):
        def complete_json(self, *, system, prompt, schema, context=None):  # noqa: ANN001
            captured["prompts"] += 1
            return {"findings": []}

    _use_provider(monkeypatch, _Counting())
    (tmp_path / "boring.py").write_text("x = 1 + 1\nprint(x)\n")          # nothing security-relevant
    (tmp_path / "risky.py").write_text('run("SELECT * FROM t WHERE x=" + i)\n')  # SQL-ish
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      workspace_path=str(tmp_path))
    list(AiDiscoveryEngine().run(ctx))
    assert captured["prompts"] == 1, "only the risky file should cost an LLM call"
