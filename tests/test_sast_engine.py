"""The SAST engine must catch common insecure patterns and map them to CWE/OWASP.

This file is the v1 contract, kept as a regression guard across the v2 upgrade: everything v1
caught must still be caught. What changed is *how*. Three of the lines below carry attacker-
controlled data into a dangerous call, so v2 reports them as proven flows (`taint-*`) instead of
pattern matches (`py-*`) — a stronger claim about the same line, with a data-flow trace attached.
The lines where no input is involved are still pattern matches, because that is all that can
honestly be said about them.

Detection depth lives in `test_sast_taint.py`.
"""

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.sast_engine import SastEngine

PY_SAMPLE = """
import os, subprocess, hashlib, yaml
def handler(req):
    eval(req.body)
    os.system("ls " + req.path)
    subprocess.run("echo hi", shell=True)
    hashlib.md5(req.data).hexdigest()
    yaml.load(req.body)
    requests.get(url, verify=False)
"""


def _run(content: str):
    return list(
        SastEngine().run(
            ScanContext(
                scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=content
            )
        )
    )


def test_every_v1_issue_is_still_detected():
    findings = _run(PY_SAMPLE)
    rules = {f.location["rule"] for f in findings}
    assert {
        "taint-code-exec",       # was py-eval
        "taint-shell-command",   # was py-os-system
        "taint-deserialization", # was py-yaml-load
        "py-shell-true",
        "py-weak-hash",
        "py-tls-verify-off",
    } <= rules
    assert all(f.engine == EngineKey.SAST for f in findings)


def test_a_line_is_reported_once():
    """v1's rules overlapped; a customer must not see the same line twice under two names."""
    findings = _run(PY_SAMPLE)
    lines = [f.location["line"] for f in findings]
    assert len(lines) == len(set(lines))


def test_proven_flows_outrank_pattern_matches():
    findings = {f.location["rule"]: f for f in _run(PY_SAMPLE)}
    assert findings["taint-code-exec"].base_severity is Severity.CRITICAL
    assert findings["taint-code-exec"].confidence == "high"
    assert findings["py-weak-hash"].confidence == "medium"


def test_findings_have_cwe_and_owasp():
    findings = _run("eval(x)\n")
    assert findings and findings[0].cwe_id == "CWE-95"
    assert findings[0].owasp_ref == "A03:2021"


def test_clean_code_is_quiet():
    assert _run("def add(a, b):\n    return a + b\n") == []
