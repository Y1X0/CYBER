"""The knowledge base is the analyst's grounding surface — validate its shape and its safety rules.

No database here: these assert the seed DATA is well-formed, retrievable, and — the load-bearing
rule — knowledge, not weapons. The retriever matches a KB entry to a finding by `standards.cwe`,
`standards.owasp`, or a `tags` membership on the finding category, so every entry must carry at
least one of those or it can never be retrieved.
"""

from __future__ import annotations

import re

from guardian_db.kb_seed import _CWE_SEED, _KB_SEED, _VULN_SEED

_CWE_RE = re.compile(r"^CWE-\d+$")

# Categories the detection engines actually emit — every one should have knowledge behind it, or a
# finding of that class reaches the analyst with nothing to ground on.
_ENGINE_CATEGORIES = {
    "injection", "secret", "vuln-dep", "ml-model-malware",
    "cicd-injection", "cicd-supply-chain", "cicd-permissions",
    "api-authorization", "insecure-code", "iac-misconfig",
}


def test_every_cwe_seed_row_is_well_formed():
    seen = set()
    for row in _CWE_SEED:
        assert len(row) == 3, row
        ext_id, name, description = row
        assert _CWE_RE.match(ext_id), ext_id
        assert name and len(name) > 5, ext_id
        assert description and len(description) > 30, f"{ext_id} has a thin description"
        assert ext_id not in seen, f"duplicate {ext_id}"
        seen.add(ext_id)


def test_every_kb_entry_is_well_formed_and_retrievable():
    titles = set()
    for e in _KB_SEED:
        assert set(e) >= {"kind", "title", "body", "standards", "tags"}, e
        assert e["title"] and e["title"] not in titles, e["title"]
        titles.add(e["title"])
        assert len(e["body"]) > 80, f"{e['title']}: body too thin to ground on"
        # Retrievable: it must carry a CWE, an OWASP ref, or at least one tag.
        assert e["standards"].get("cwe") or e["standards"].get("owasp") or e["tags"], e["title"]
        for cwe in [e["standards"].get("cwe")] if e["standards"].get("cwe") else []:
            assert _CWE_RE.match(cwe), cwe


def test_the_kb_is_knowledge_not_weapons():
    """The safety rule this table exists under: describe detection and remediation, never ship a
    working exploit. Every entry earns its place by carrying remediation guidance, and none carries
    an obvious weaponized payload."""
    for e in _KB_SEED:
        body = e["body"].lower()
        assert ("remediat" in body or "remediation" in body or e["kind"] == "remediation"), \
            f"{e['title']} has no remediation guidance"
        # No raw exploit payloads: a stored SQLi/XSS/shell payload would make this table a liability.
        for marker in ("' or 1=1", "<script>alert", "; drop table", "$(curl", "rm -rf /"):
            assert marker not in body, f"{e['title']} looks like it embeds a payload: {marker!r}"


def test_the_new_domain_categories_are_covered():
    tagged = {t for e in _KB_SEED for t in e["tags"]}
    missing = _ENGINE_CATEGORIES - tagged
    assert not missing, f"engine categories with no knowledge behind them: {sorted(missing)}"


def test_the_new_engine_cwes_have_a_weakness_definition():
    # CWEs the CI/CD and ML-model engines emit must exist as weaknesses so the analyst can define
    # them, not just as tags.
    defined = {row[0] for row in _CWE_SEED}
    for cwe in ("CWE-94", "CWE-502", "CWE-1357", "CWE-272", "CWE-494", "CWE-668"):
        assert cwe in defined, f"{cwe} (a new-engine CWE) has no weakness definition"


def test_advisory_seed_still_well_formed():
    for v in _VULN_SEED:
        assert v["external_id"].startswith("CVE-")
        assert v["cwe_ids"] and all(_CWE_RE.match(c) for c in v["cwe_ids"])
        assert 0 <= float(v["cvss_base"]) <= 10
