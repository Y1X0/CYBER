"""Scanner image supply-chain invariants (security follow-up).

The burst worker runs the scanner from a pre-built GHCR image. Two supply-chain properties must hold
and stay held:

  * the runtime image reference is IMMUTABLE — pinned by `@sha256:` digest, never a mutable tag
    (`:latest`, `:main`, `:sha-<ref>`, or a bare tag) that could drift under a fixed reference; and
  * the workflow's broker-URL "normalise" step is a bounded, secret-safe shim that only appends
    `ssl_cert_reqs=required` — it exists ONLY because the currently-pinned image predates
    `celery_redis_url`. Current source normalises the broker URL in-process, so a scanner image
    rebuilt from HEAD makes that step removable. This test encodes that removal condition so the
    shim cannot silently become permanent.

These are static checks over the real workflow YAML + source — they do not build or pull an image.
Rebuilding + repinning to a current digest is a release-pipeline action (it needs GHCR push
credentials) and is intentionally NOT done here; these tests guard the invariants that remain.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_BURST = _ROOT / ".github/workflows/guardian-burst-worker.yml"
_DEPLOY = _ROOT / ".github/workflows/guardian-deploy-worker.yml"

_SCANNER_REPO = "ghcr.io/y1x0/cyber-scanner"
_DIGEST_RE = re.compile(rf"{re.escape(_SCANNER_REPO)}@sha256:[0-9a-f]{{64}}")
# A mutable reference: the repo followed by ':<tag>' (and NOT '@sha256:').
_MUTABLE_TAG_RE = re.compile(rf"{re.escape(_SCANNER_REPO)}:[A-Za-z0-9._-]+")


def _steps(workflow: Path) -> list[dict]:
    wf = yaml.safe_load(workflow.read_text())
    steps: list[dict] = []
    for job in (wf.get("jobs") or {}).values():
        steps.extend(job.get("steps") or [])
    return steps


def _step(workflow: Path, name: str) -> dict:
    for step in _steps(workflow):
        if step.get("name") == name:
            return step
    raise AssertionError(f"step {name!r} not found in {workflow.name}")


# ── A. immutability ──────────────────────────────────────────────────────────────────────────────
def test_burst_worker_pins_scanner_image_by_digest():
    run = _step(_BURST, "Pull the verified scanner image")["run"]
    refs = re.findall(rf"{re.escape(_SCANNER_REPO)}\S*", run)
    assert refs, "no scanner image reference found in the pull step"
    for ref in refs:
        ref = ref.strip('"').rstrip('"\\')
        assert _DIGEST_RE.fullmatch(ref), f"scanner image is not digest-pinned: {ref!r}"


def test_burst_worker_uses_no_mutable_scanner_tag_anywhere():
    text = _BURST.read_text()
    # Any `ghcr.io/y1x0/cyber-scanner:<tag>` (a mutable reference) is forbidden as a RUNTIME pin.
    mutable = [m for m in _MUTABLE_TAG_RE.findall(text)]
    assert mutable == [], f"burst worker references the scanner by a mutable tag: {mutable}"


def test_deploy_worker_provisions_by_digest_not_tag():
    # The build/publish workflow pushes a :sha-<ref> tag to build, but the RUNTIME pin it provisions
    # onto Render must be the immutable digest form `@{digest}`.
    text = _DEPLOY.read_text()
    assert "cyber-scanner@{digest}" in text, "deploy worker must provision the image by digest"


# ── B. the broker-URL shim is bounded, secret-safe, and removable ────────────────────────────────
def test_broker_normaliser_only_appends_ssl_cert_reqs_and_leaks_no_secret():
    run = _step(_BURST, "Normalise the broker URL for the pinned image")["run"]
    # Only that one query parameter is ever added…
    assert "ssl_cert_reqs=required" in run
    assert run.count("_replace(query=") <= 1
    # …the derived value is masked before it can be emitted…
    assert "::add-mask::" in run
    # …and no NEW secret is introduced into the scanner environment by this step.
    forbidden = ("JWT_SECRET", "ENCRYPTION_KEY", "PASSWORD", "PRIVATE_KEY")
    for name in forbidden:
        assert f"{name}=" not in run, f"the normalise step must not set {name}"


def test_current_source_normalises_broker_url_in_process():
    # The removal condition for the shim above: a scanner image built from current source normalises
    # the broker URL itself (celery_redis_url), so once the pinned image is rebuilt the workflow step
    # is redundant and must be deleted. If this ever stops being true, the shim is load-bearing and
    # this test tells us so.
    config = (_ROOT / "packages/common/src/guardian_common/config.py").read_text()
    celery_app = (_ROOT / "workers/scanner/src/guardian_scanner/celery_app.py").read_text()
    assert "def celery_redis_url(" in config
    assert "celery_redis_url(settings.redis_url)" in celery_app


# ── C. no fragile image/config runtime patching ──────────────────────────────────────────────────
def test_no_sed_or_perl_rewrites_image_or_config_files():
    text = _BURST.read_text()
    # The only in-place edits in this workflow are `sed -i` de-indenting a throwaway, read-only
    # queue-depth OBSERVATION script under /tmp — never the scanner image, its config, or its
    # runtime files. Assert every `sed -i` targets exactly that throwaway path.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("sed -i"):
            assert stripped.endswith("/tmp/qdepth.py"), f"unexpected in-place edit: {stripped!r}"
    assert "perl -i" not in text and "perl -pi" not in text
