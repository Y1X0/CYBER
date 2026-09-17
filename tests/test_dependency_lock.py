"""Python dependencies are pinned in a hashed lock, installed everywhere, and audited in CI (Item 2).

Static checks over the repo: the lock exists and is hash-pinned with the required floors; build.sh
and both Dockerfiles install it with --require-hashes; and CI pip-audits the lock and fails on
findings (no continue-on-error).
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_LOCK = (_ROOT / "requirements.lock").read_text()


def _pinned(name: str) -> tuple[int, ...]:
    m = re.search(rf"(?mi)^{re.escape(name)}==([0-9][0-9.]*)", _LOCK)
    assert m, f"{name} is not pinned in requirements.lock"
    return tuple(int(p) for p in m.group(1).split("."))


def test_lock_exists_and_is_hash_pinned():
    assert "--hash=sha256:" in _LOCK, "the lock must be generated with --generate-hashes"
    # Every requirement line (name==version) is followed by at least one hash.
    pins = re.findall(r"(?m)^[A-Za-z0-9._-]+==", _LOCK)
    assert len(pins) >= 20, f"expected a full dependency set, found {len(pins)} pins"


def test_required_floors_are_met():
    assert _pinned("cryptography") >= (50,), "cryptography floor is >= 50"
    assert _pinned("urllib3") >= (2, 7), "urllib3 floor is >= 2.7"
    assert _pinned("idna") >= (3, 15), "idna floor is >= 3.15"


def test_build_and_dockerfiles_install_from_the_lock_with_hashes():
    for rel in ("infra/render/build.sh", "infra/docker/Dockerfile", "infra/docker/Dockerfile.scanner"):
        text = (_ROOT / rel).read_text()
        assert "--require-hashes -r requirements.lock" in text, f"{rel} must install from the lock"
    # The Dockerfiles must COPY the lock into the image so the install can read it.
    for rel in ("infra/docker/Dockerfile", "infra/docker/Dockerfile.scanner"):
        text = (_ROOT / rel).read_text()
        assert any("COPY" in ln and "requirements.lock" in ln for ln in text.splitlines()), \
            f"{rel} must COPY requirements.lock into the image"


def test_ci_pip_audit_targets_the_lock_and_fails_on_findings():
    ci = (_ROOT / ".github/workflows/ci.yml").read_text()
    # The pip-audit step audits the lock…
    assert "pip-audit" in ci and "-r requirements.lock" in ci
    # …and is a hard gate: the audit step must not be marked continue-on-error.
    audit_block = ci.split("pip-audit against the lock")[1]
    assert "continue-on-error" not in audit_block, "the pip-audit gate must fail the build"
