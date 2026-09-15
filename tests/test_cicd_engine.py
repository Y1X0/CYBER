"""CI/CD & supply-chain security engine — GitHub Actions workflow analysis (Phase A).

A self-contained built-in detector: no external binary, no network, parses the workflow YAML the
customer already provided. So unlike the tool-augmented engines there is nothing to mock — these
tests feed real (deliberately vulnerable) workflow snippets and assert the finding. The load-bearing
properties: the canonical Actions attack classes are caught, the documented mitigation is NOT flagged
(low false positives), and no untrusted value survives into a finding unredacted.
"""

from __future__ import annotations

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.cicd_engine import CicdEngine, CicdInputError


def _scan(text: str) -> list:
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=text)
    return list(CicdEngine().run(ctx))


def _rules(text: str) -> set[str]:
    return {f.location["rule"] for f in _scan(text)}


def _one(text: str, rule: str):
    hits = [f for f in _scan(text) if f.location["rule"] == rule]
    assert len(hits) == 1, f"expected exactly one {rule}, got {[f.location['rule'] for f in _scan(text)]}"
    return hits[0]


def test_script_injection_in_run_is_critical():
    wf = """
on: issues
jobs:
  j:
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""
    f = _one(wf, "CICD-INJECTION")
    assert f.engine == EngineKey.CICD
    assert f.base_severity == Severity.CRITICAL
    assert f.cwe_id == "CWE-94"
    assert f.location["line"] == 6


def test_the_env_var_mitigation_is_not_flagged():
    # The documented fix: route the untrusted value through env and reference $VAR in the script.
    # Flagging this would punish the correct pattern — the engine must stay silent here.
    wf = """
on: issues
jobs:
  j:
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
"""
    assert "CICD-INJECTION" not in _rules(wf)


def test_a_safe_context_in_run_is_not_flagged():
    wf = """
on: push
jobs:
  j:
    steps:
      - run: echo "sha is ${{ github.sha }} on ${{ github.repository }}"
"""
    assert "CICD-INJECTION" not in _rules(wf)


def test_pull_request_target_checking_out_pr_head_is_critical():
    wf = """
on: pull_request_target
jobs:
  j:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build
"""
    f = _one(wf, "CICD-PR-TARGET-CHECKOUT")
    assert f.base_severity == Severity.CRITICAL
    assert f.cwe_id == "CWE-269"


def test_pull_request_target_default_checkout_is_safe():
    # Under pull_request_target a checkout with no ref takes the BASE (trusted) — not flagged.
    wf = """
on: pull_request_target
jobs:
  j:
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
"""
    assert "CICD-PR-TARGET-CHECKOUT" not in _rules(wf)


def test_checkout_of_pr_head_without_pr_target_is_not_this_finding():
    # On a plain `pull_request` trigger the job has no secrets in scope, so head checkout is normal.
    wf = """
on: pull_request
jobs:
  j:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert "CICD-PR-TARGET-CHECKOUT" not in _rules(wf)


def test_third_party_action_pinned_to_a_tag_is_medium():
    wf = """
on: push
jobs:
  j:
    steps:
      - uses: tj-actions/changed-files@v35
"""
    f = _one(wf, "CICD-UNPINNED-ACTION")
    assert f.base_severity == Severity.MEDIUM
    assert "tj-actions/changed-files" in f.title


def test_first_party_action_pinned_to_a_tag_is_low():
    f = _one("on: push\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n",
             "CICD-UNPINNED-ACTION")
    assert f.base_severity == Severity.LOW


def test_a_sha_pinned_action_is_not_flagged():
    sha = "a" * 40
    wf = f"on: push\njobs:\n  j:\n    steps:\n      - uses: tj-actions/changed-files@{sha}\n"
    assert "CICD-UNPINNED-ACTION" not in _rules(wf)


def test_a_local_composite_action_is_not_flagged():
    assert "CICD-UNPINNED-ACTION" not in _rules(
        "on: push\njobs:\n  j:\n    steps:\n      - uses: ./.github/actions/build\n")


def test_write_all_permissions_is_flagged():
    f = _one("on: push\npermissions: write-all\njobs:\n  j:\n    steps:\n      - run: true\n",
             "CICD-WRITE-ALL")
    assert f.base_severity == Severity.MEDIUM
    assert f.cwe_id == "CWE-272"


def test_scoped_permissions_are_not_flagged():
    wf = """
on: push
permissions:
  contents: read
jobs:
  j:
    steps:
      - run: true
"""
    assert "CICD-WRITE-ALL" not in _rules(wf)


def test_curl_piped_to_shell_is_flagged():
    wf = """
on: push
jobs:
  j:
    steps:
      - run: curl -sSL https://example.com/install.sh | bash
"""
    f = _one(wf, "CICD-CURL-BASH")
    assert f.base_severity == Severity.MEDIUM
    assert f.cwe_id == "CWE-494"


def test_a_plain_curl_without_a_pipe_to_shell_is_not_flagged():
    wf = """
on: push
jobs:
  j:
    steps:
      - run: curl -sSL https://example.com/file.tar.gz -o file.tgz
"""
    assert "CICD-CURL-BASH" not in _rules(wf)


def test_self_hosted_runner_on_a_public_trigger_is_high():
    wf = """
on: pull_request
jobs:
  j:
    runs-on: self-hosted
    steps:
      - run: true
"""
    f = _one(wf, "CICD-SELFHOSTED-PUBLIC")
    assert f.base_severity == Severity.HIGH


def test_self_hosted_runner_on_a_private_trigger_is_not_flagged():
    wf = """
on: push
jobs:
  j:
    runs-on: [self-hosted, linux]
    steps:
      - run: true
"""
    assert "CICD-SELFHOSTED-PUBLIC" not in _rules(wf)


def test_the_yaml_on_true_gotcha_is_handled():
    # PyYAML parses the bare key `on` as the boolean True. The trigger set must still resolve, or
    # every trigger-dependent rule silently misfires.
    wf = """
on: pull_request_target
jobs:
  j:
    runs-on: self-hosted
    steps:
      - run: true
"""
    assert "CICD-SELFHOSTED-PUBLIC" in _rules(wf)


def test_an_untrusted_value_never_survives_unredacted():
    wf = ('on: issues\njobs:\n  j:\n    steps:\n      - run: echo '
          '"${{ github.event.issue.title }} tok=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n')
    f = _one(wf, "CICD-INJECTION")
    blob = f"{f.title} {f.description} {f.evidence} {f.location}"
    assert "ghp_AAAA" not in blob, "a token embedded in the run line leaked into the finding"


def test_a_clean_workflow_yields_nothing():
    sha = "b" * 40
    wf = f"""
on: push
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha}
      - run: make test
"""
    assert _scan(wf) == []


def test_malformed_yaml_is_handled_not_crashed():
    assert _scan("this: : : not valid yaml\n  - [\n") == []


def test_a_non_workflow_document_is_ignored():
    assert _scan("just a list\n- a\n- b\n") == []


def test_no_workspace_raises_rather_than_completing_clean():
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", workspace_path=None)
    with pytest.raises(CicdInputError):
        list(CicdEngine().run(ctx))


def test_reads_workflows_from_a_real_workspace(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: issues\njobs:\n  j:\n    steps:\n      - run: echo ${{ github.event.issue.body }}\n")
    (wf_dir / "notes.txt").write_text("not a workflow")   # non-YAML ignored
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      workspace_path=str(tmp_path))
    rules = {f.location["rule"] for f in CicdEngine().run(ctx)}
    assert "CICD-INJECTION" in rules


def test_a_repo_with_no_workflows_is_clean_not_an_error(tmp_path):
    (tmp_path / "README.md").write_text("hi")
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      workspace_path=str(tmp_path))
    assert list(CicdEngine().run(ctx)) == []


def test_health_is_ok_and_never_degraded():
    h = CicdEngine().health()
    assert h.ok is True
    assert h.degraded is False    # self-contained: no binary to be missing
