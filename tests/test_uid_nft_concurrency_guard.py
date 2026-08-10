"""uid+nft single-allocator hard guard (P1-2) — no DB, no network, no nft.

Per-run uid uniqueness relies on the process-local allocator being the SOLE allocator (concurrency=1).
These tests prove the RUNTIME guard — not the compose flag — refuses to establish isolation when that
is not provable, BEFORE any uid is allocated or any nft rule is created, and that offline runs (which
never touch the kernel isolation) are unaffected.
"""

from __future__ import annotations

import pytest
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.backends import uid_nft
from guardian_scanner.tools.backends.uid_nft import IsolationError


@pytest.fixture(autouse=True)
def _reset_state():
    saved = uid_nft._worker_concurrency
    uid_nft._used_uids.clear()
    yield
    uid_nft._worker_concurrency = saved
    uid_nft._used_uids.clear()


def _job():
    return ToolJob(tenant_id="t", job_id="j1", tool_key="nmap",
                   scope=EffectiveScope(targets=("1.2.3.4",), ports=(80,), protocols=("tcp",),
                                        network_allowed=True, read_only=True),
                   settings={"allow_live": True})


# ── the guard itself ───────────────────────────────────────────────────────────────────────────────
def test_concurrency_1_is_allowed():
    uid_nft.set_worker_concurrency(1)
    uid_nft._assert_single_allocator()          # no raise


@pytest.mark.parametrize("conc", [2, 4, 8])
def test_concurrency_gt_1_is_rejected(conc):
    uid_nft.set_worker_concurrency(conc)
    with pytest.raises(IsolationError, match="concurrency=1"):
        uid_nft._assert_single_allocator()


def test_unknown_concurrency_fails_closed():
    uid_nft._worker_concurrency = None
    with pytest.raises(IsolationError, match="concurrency unknown"):
        uid_nft._assert_single_allocator()


# ── isolate() refuses BEFORE any uid / nft rule ─────────────────────────────────────────────────────
def test_isolate_creates_no_nft_rules_before_rejecting(monkeypatch):
    calls = []
    monkeypatch.setattr(uid_nft, "_nft", lambda *a: calls.append(a))   # spy: any nft call is recorded
    uid_nft.set_worker_concurrency(2)
    with pytest.raises(IsolationError):
        with uid_nft.isolate(_job()):
            pass
    assert calls == []                          # no nft table/chain/rule was ever created
    assert uid_nft._used_uids == set()          # no uid leaked either


def test_isolate_unknown_concurrency_also_fails_closed(monkeypatch):
    calls = []
    monkeypatch.setattr(uid_nft, "_nft", lambda *a: calls.append(a))
    uid_nft._worker_concurrency = None
    with pytest.raises(IsolationError):
        with uid_nft.isolate(_job()):
            pass
    assert calls == [] and uid_nft._used_uids == set()


# ── uid uniqueness (no collision within the single allowed allocator) ───────────────────────────────
def test_alloc_uid_is_unique_within_the_single_allocator():
    uids = {uid_nft._alloc_uid() for _ in range(200)}
    assert len(uids) == 200                     # every concurrent run gets a distinct uid
    assert all(uid_nft._UID_BASE <= u < uid_nft._UID_TOP for u in uids)


# ── offline path is unaffected (no guard, delegates to in-proc) — Nmap/nmap_service regression ──────
def test_offline_run_bypasses_guard_and_isolation(monkeypatch):
    # allow_live absent ⇒ UidNftBackend delegates to the in-proc backend; the guard never runs, so a
    # (hypothetically) unsafe concurrency does not block offline scans.
    uid_nft.set_worker_concurrency(4)           # would reject a LIVE run
    called = {}
    monkeypatch.setattr(uid_nft, "_assert_single_allocator",
                        lambda: called.setdefault("guard", True))
    job = ToolJob(tenant_id="t", job_id="j", tool_key="nmap",
                  scope=EffectiveScope(targets=(), ports=(), protocols=(),
                                       network_allowed=False, read_only=True), settings={})
    out = uid_nft.UidNftBackend().run(job, lambda: [])
    assert out == [] and "guard" not in called  # guard not invoked on the offline path


# ── concurrency detection (what worker_ready feeds the guard) ───────────────────────────────────────
def test_detect_concurrency_prefers_actual_pool_size():
    class _Pool:
        num_processes = 1

    class _Sender:
        pool = _Pool()
        concurrency = 8            # a stale/config value must NOT win over the real pool size

    assert uid_nft.detect_concurrency(_Sender(), 8) == 1


def test_detect_concurrency_falls_back_then_none():
    assert uid_nft.detect_concurrency(object(), 4) == 4
    assert uid_nft.detect_concurrency(object(), None) is None
