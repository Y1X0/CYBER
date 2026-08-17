"""Secret scanning across git history.

Removing a key in a later commit does not remove it from the repository — anyone who can clone can
still read it, while the working tree shows nothing. A scanner that only reads the checkout reports
the repository as clean and the credential stays live. These tests build real repositories and
assert the engine finds what a `git log` would.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.secrets_engine import SecretsEngine

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

_KEY = "AKIAIOSFODNN7EXAMPLE"          # AWS's own documentation example, not a live credential


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(repo),
                        "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"})


def _repo_with_removed_secret(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "config.py").write_text(f'AWS_ACCESS_KEY = "{_KEY}"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add config")
    # The fix everyone believes is sufficient.
    (repo / "config.py").write_text('AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "remove hardcoded key")
    return repo


def _ctx(repo, **settings):
    return ScanContext(scan_id="s", asset_kind="repo", asset_identifier=str(repo),
                       workspace_path=str(repo), settings=settings)


def test_working_tree_alone_shows_nothing(tmp_path):
    """The premise: after the 'fix', the checkout really is clean."""
    repo = _repo_with_removed_secret(tmp_path)
    assert _KEY not in (repo / "config.py").read_text()


def test_secret_removed_in_a_later_commit_is_still_found(tmp_path):
    repo = _repo_with_removed_secret(tmp_path)
    findings = list(SecretsEngine().run(_ctx(repo)))
    history = [f for f in findings if f.location.get("source") == "git-history"]
    assert history, "a secret deleted in a later commit must still be reported"
    assert history[0].location["path"] == "config.py"
    assert len(history[0].location["commit"]) == 12


def test_history_finding_says_rotation_is_required(tmp_path):
    """Deleting the file is the wrong remediation, so the finding must not imply otherwise."""
    repo = _repo_with_removed_secret(tmp_path)
    history = [f for f in SecretsEngine().run(_ctx(repo))
               if f.location.get("source") == "git-history"]
    assert "rotation is required" in history[0].description


def test_raw_secret_is_never_persisted(tmp_path):
    repo = _repo_with_removed_secret(tmp_path)
    for finding in SecretsEngine().run(_ctx(repo)):
        assert _KEY not in str(finding.evidence)
        assert _KEY not in finding.description
        assert _KEY not in str(finding.location)


def test_history_scanning_can_be_disabled(tmp_path):
    repo = _repo_with_removed_secret(tmp_path)
    findings = list(SecretsEngine().run(_ctx(repo, scan_history=False)))
    assert not [f for f in findings if f.location.get("source") == "git-history"]


def test_repeated_commits_of_one_secret_report_once(tmp_path):
    """The same key re-committed is one exposed credential, not one finding per commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    for i in range(4):
        (repo / "config.py").write_text(f'AWS_ACCESS_KEY = "{_KEY}"\n# revision {i}\n')
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"commit {i}")

    history = [f for f in SecretsEngine().run(_ctx(repo))
               if f.location.get("source") == "git-history"]
    aws = [f for f in history if "AWS Access Key" in f.title]
    assert len(aws) == 1


def test_a_directory_that_is_not_a_repository_is_handled(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text('KEY = "not-a-secret"\n')
    assert list(SecretsEngine().run(_ctx(plain))) == []


def test_current_tree_secret_is_still_reported_from_the_working_copy(tmp_path):
    """History scanning must not replace the checkout scan."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "live.py").write_text(f'AWS_ACCESS_KEY = "{_KEY}"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add")

    findings = list(SecretsEngine().run(_ctx(repo)))
    assert [f for f in findings if f.location.get("source") != "git-history"]
