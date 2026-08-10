"""nftables runtime dependency for uid_nft (P1-ε).

The uid_nft backend builds a per-run kernel egress allowlist with `nft`. Two guarantees:
  * the reference image SHIPS nftables (so worker-tools can confine external binaries);
  * if `nft` is EVER absent, execution fails closed and clear — the external binary never runs
    unconfined, and worker startup (the reaper) is not aborted.
"""

from __future__ import annotations

import pathlib
import re
import shutil

import pytest
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.backends import uid_nft
from guardian_scanner.tools.backends.uid_nft import IsolationError, UidNftBackend

_REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolate_state():
    saved = uid_nft._worker_concurrency
    uid_nft._used_uids.clear()
    yield
    uid_nft._worker_concurrency = saved
    uid_nft._used_uids.clear()


def _live_job():
    return ToolJob(tenant_id="t", job_id="j1", tool_key="nmap",
                   scope=EffectiveScope(targets=("1.2.3.4",), ports=(80,), protocols=("tcp",),
                                        network_allowed=True, read_only=True),
                   settings={"allow_live": True})


# ── the image ships nftables ─────────────────────────────────────────────────────────────────────
def test_reference_image_installs_nftables():
    dockerfile = (_REPO / "infra/docker/Dockerfile").read_text()
    apt = re.search(r"apt-get install[^\n]*", dockerfile)
    assert apt and "nftables" in apt.group(0), "Dockerfile must apt-install nftables for uid_nft"


# ── missing nft ⇒ clear IsolationError from _nft (fail-closed, never unconfined) ─────────────────
def test_nft_missing_raises_isolation_error(monkeypatch):
    def _boom(*_a, **_k):
        raise FileNotFoundError(2, "No such file or directory", "nft")

    monkeypatch.setattr(uid_nft.subprocess, "run", _boom)
    with pytest.raises(IsolationError, match="nftables .* not installed"):
        uid_nft._nft("list", "tables", "inet")


def test_live_run_fails_closed_when_nft_absent(monkeypatch):
    # With nft unavailable, a LIVE external-binary run must return [] and NEVER invoke the runner.
    uid_nft.set_worker_concurrency(1)                    # pass the single-allocator guard first
    monkeypatch.setattr(uid_nft, "_nft",
                        lambda *a: (_ for _ in ()).throw(IsolationError("nft missing")))
    ran = {"called": False}

    def _fn():
        ran["called"] = True                             # the confined binary runner — must NOT run
        return ["evidence"]

    out = UidNftBackend().run(_live_job(), _fn)
    assert out == []                                     # fail closed
    assert ran["called"] is False                        # binary never executed unconfined
    assert uid_nft._used_uids == set()                   # uid freed even though rules failed


def test_reaper_is_resilient_when_nft_absent(monkeypatch):
    # A missing nft at startup must not abort the worker: the reaper logs and returns 0.
    monkeypatch.setattr(uid_nft, "_nft",
                        lambda *a: (_ for _ in ()).throw(IsolationError("nft missing")))
    assert uid_nft.reap_orphans() == 0


# ── runtime sanity: where nft IS present, the backend can reach it ───────────────────────────────
@pytest.mark.skipif(shutil.which("nft") is None, reason="nft not on PATH in this runtime")
def test_nft_binary_is_reachable_when_present():
    # Non-privileged `list tables` may return non-zero without CAP_NET_ADMIN, but it must not raise
    # (the binary resolves) — proving the runtime has the dependency the backend needs.
    res = uid_nft._nft("list", "tables", "inet")
    assert res.returncode is not None
