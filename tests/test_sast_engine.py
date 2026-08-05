"""Builtin SAST rules must catch common insecure patterns and map to CWE/OWASP."""

from guardian_core.enums import EngineKey
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


def test_detects_multiple_insecure_patterns():
    findings = _run(PY_SAMPLE)
    rules = {f.location["rule"] for f in findings}
    assert {
        "py-eval",
        "py-os-system",
        "py-shell-true",
        "py-weak-hash",
        "py-yaml-load",
        "py-tls-verify-off",
    } <= rules
    assert all(f.engine == EngineKey.SAST for f in findings)


def test_findings_have_cwe_and_owasp():
    findings = _run("eval(x)\n")
    assert findings and findings[0].cwe_id == "CWE-95"
    assert findings[0].owasp_ref == "A03:2021"


def test_clean_code_is_quiet():
    assert _run("def add(a, b):\n    return a + b\n") == []
