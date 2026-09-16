"""ApiEngine wiring — the deep static audit flows through run(), additively.

Confirms the deep spec audit reaches the canonical finding stream via ApiEngine.run(), that it did
not disturb the engine's existing static review, and that no live probing happens when there is no
base URL to probe (so this test makes no network call).
"""

from __future__ import annotations

import json

from guardian_core.enums import EngineKey
from guardian_scanner.engines.api_engine import ApiEngine
from guardian_scanner.engines.base import ScanContext

# A deliberately weak contract: api-key-in-query, a sensitive response field, no servers (so the
# engine has no base URL and performs no live probing).
_SPEC = {
    "openapi": "3.0.0", "info": {"title": "t"},
    "components": {
        "securitySchemes": {"K": {"type": "apiKey", "in": "query", "name": "api_key"}},
        "schemas": {"U": {"type": "object", "properties": {
            "id": {"type": "string"}, "password": {"type": "string"}}}}},
    "security": [{"K": []}],
    "paths": {"/users": {"get": {"responses": {"200": {"content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/U"}}}}}}}},
}


def _run():
    ctx = ScanContext(scan_id="t", asset_kind="api", asset_identifier="offline-spec",
                      inline_content=json.dumps(_SPEC))
    return list(ApiEngine().run(ctx))


def test_deep_audit_findings_reach_the_engine_output():
    findings = _run()
    titles = " | ".join(f.title for f in findings)
    assert "API key passed in the URL" in titles          # deep scheme audit
    assert "sensitive field 'password'" in titles          # deep exposure audit
    assert all(f.engine == EngineKey.API for f in findings)


def test_existing_static_review_still_runs():
    # The pre-existing contract review (no 429 documented) must still fire — audit is additive.
    assert any("rate limiting" in f.title.lower() for f in _run())


def test_no_base_url_means_no_live_probe_and_a_coverage_note():
    findings = _run()
    # With no base URL the engine cannot probe or test authorization; it says so, and no
    # surface-probe finding exists.
    assert any(f.category == "scan-coverage" for f in findings)
    assert not any((f.location or {}).get("rule") == "api-surface-probe" for f in findings)
