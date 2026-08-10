"""Shared single-use nonce reservation — process-local fallback + production fail-closed (no DB/redis).

Proves the dev/test fallback works single-process, and that production REFUSES to fall back when the
shared store is unreachable (fail-closed), which verify_job surfaces as a rejection.
"""

from __future__ import annotations

import secrets

import pytest
from guardian_common import replay
from guardian_common.job_signing import JobVerificationError, sign_job, verify_job


@pytest.fixture(autouse=True)
def _fresh():
    replay.reset_local_for_tests()
    yield
    replay.reset_local_for_tests()


def test_local_fallback_is_single_use_in_dev(monkeypatch):
    # Force the fallback path (unreachable store, dev env) so this is deterministic with or without a
    # real Redis running: the process-local store must still enforce single-use.
    class _Dev:
        redis_url = "redis://127.0.0.1:6390/0"         # unreachable ⇒ fall back to local
        is_local_or_dev = True

    monkeypatch.setattr(replay, "get_settings", lambda: _Dev())
    replay.reset_local_for_tests()
    nonce = "local-" + secrets.token_hex(8)
    assert replay.reserve_nonce(nonce, 300) is True    # first use
    assert replay.reserve_nonce(nonce, 300) is False   # replay


def test_production_fails_closed_when_shared_store_unreachable(monkeypatch):
    class _Prod:
        redis_url = "redis://127.0.0.1:6390/0"         # nothing listening ⇒ connection refused
        is_local_or_dev = False

    monkeypatch.setattr(replay, "get_settings", lambda: _Prod())
    replay.reset_local_for_tests()
    with pytest.raises(replay.ReplayStoreUnavailable):
        replay.reserve_nonce("n2", 300)                # prod must NOT fall back to local


def test_verify_job_refuses_when_store_unavailable(monkeypatch):
    signed = sign_job({"tenant_id": "t", "job_id": "j", "tool_key": "nmap",
                       "scope": {"targets": ["1.2.3.4"], "ports": [80], "protocols": ["tcp"],
                                 "network_allowed": True, "read_only": True}, "settings": {}})

    def _boom(_nonce, _ttl):
        raise replay.ReplayStoreUnavailable("down")

    # verify_job imports reserve_nonce locally from guardian_common.replay, so patch it there.
    monkeypatch.setattr(replay, "reserve_nonce", _boom)
    with pytest.raises(JobVerificationError, match="replay store unavailable"):
        verify_job(signed)
