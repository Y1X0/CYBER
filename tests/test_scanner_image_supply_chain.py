"""Scanner image supply-chain invariants (security follow-up).

The burst worker runs the scanner from a pre-built GHCR image. Two supply-chain properties must hold
and stay held:

  * the runtime image reference is IMMUTABLE — pinned by `@sha256:` digest, never a mutable tag
    (`:latest`, `:main`, `:sha-<ref>`, or a bare tag) that could drift under a fixed reference; and
  * the broker URL is normalised by the image itself (`celery_redis_url`), NOT by a workflow-level
    shim. The pinned image now postdates that function, so the old "Normalise the broker URL" step
    was removed; this test asserts it stays removed and that the image still contains the function it
    was replaced by, so the shim cannot silently creep back in.

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


# ── B. the broker-URL shim is gone; the image normalises the URL itself ──────────────────────────
def test_broker_normalise_shim_is_removed_from_the_burst_worker():
    # The pinned image now contains celery_redis_url, so the workflow-level normalisation shim was
    # removed with the repin. It must not creep back: two copies of one rule are exactly what drifts.
    names = [s.get("name") for s in _steps(_BURST)]
    assert "Normalise the broker URL for the pinned image" not in names
    text = _BURST.read_text()
    # The shim's tell-tale mechanics must be gone too: it rewrote the broker URL into GITHUB_ENV and
    # masked the derived value. Neither belongs in the workflow now that the image normalises it.
    assert "GUARDIAN_REDIS_URL=" not in text, "workflow must not rewrite the broker URL via GITHUB_ENV"
    assert "_replace(query=" not in text, "query-string rewriting belongs in the image, not the workflow"
    assert "::add-mask::" not in text, "no derived-secret masking should remain once the shim is gone"


def test_current_source_normalises_broker_url_in_process():
    # The image (built from source at or after the celery_redis_url commit) normalises the broker URL
    # itself, which is what makes the workflow shim above unnecessary. If this ever stops being true,
    # the removed shim was load-bearing and this test tells us so.
    config = (_ROOT / "packages/common/src/guardian_common/config.py").read_text()
    celery_app = (_ROOT / "workers/scanner/src/guardian_scanner/celery_app.py").read_text()
    assert "def celery_redis_url(" in config
    assert "celery_redis_url(settings.redis_url)" in celery_app


def test_queue_depth_reads_normalise_via_the_image_function():
    # The read-only queue-depth observations run inside the image and must normalise the URL the same
    # way the worker does — via celery_redis_url — rather than a second inline copy of that rule.
    for name in ("Report queue depth before the burst", "Report queue depth after the burst"):
        run = _step(_BURST, name)["run"]
        assert "from guardian_common.config import celery_redis_url" in run
        assert "celery_redis_url(os.environ[" in run


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


# ── D. the burst worker refuses an image that predates the AUD-P1-6 worker file-read fix ──────────
_MIN_REVISION = "f65c09fc03ee1ee0ff34d6dafaf9822baa195465"  # AUD-P1-6 fix commit


def test_burst_worker_guards_image_revision_against_audp1_6():
    text = _BURST.read_text()
    # A guard step must read the image's source revision and prove, against the checked-out history,
    # that it is at or after the AUD-P1-6 fix — otherwise a stale image honouring a tenant-controlled
    # local_path could drain the queue.
    assert "org.opencontainers.image.revision" in text
    assert _MIN_REVISION in text, "guard must pin the AUD-P1-6 minimum revision"
    assert "git merge-base --is-ancestor" in text, "ancestry must be proved, not string-compared"
    # The guard needs history, so the workflow checks the repo out with full depth.
    assert "actions/checkout@" in text and "fetch-depth: 0" in text


def test_deploy_worker_labels_image_with_source_revision():
    text = _DEPLOY.read_text()
    # The build must stamp the source commit so the burst-worker guard has something to verify.
    assert "org.opencontainers.image.revision=${{ github.sha }}" in text
