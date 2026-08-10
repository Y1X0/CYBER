"""Cross-worker single-use replay protection via the shared Redis store (P1-1). Requires a live Redis.

Proves the guarantee a per-process cache could not: the SAME signed envelope, replayed to a different
worker process (fresh process-local cache), is rejected by the shared store — at verify_job and at
run_tool — and that concurrent reservations of one nonce yield exactly one winner.
"""

from __future__ import annotations

import secrets
import threading

import pytest
from guardian_common import replay
from guardian_common.config import get_settings
from guardian_common.job_signing import JobVerificationError, sign_job, verify_job
from guardian_core.tool import EffectiveScope, RawEvidence, ToolJob, job_to_wire


def _redis_up() -> bool:
    try:
        import redis
        redis.Redis.from_url(get_settings().redis_url, socket_connect_timeout=1).ping()
        return True
    except Exception:  # noqa: BLE001 - any connection failure ⇒ skip
        return False


pytestmark = pytest.mark.skipif(not _redis_up(), reason="requires a live Redis")

_JOB = {"tenant_id": "t", "job_id": "j", "tool_key": "nmap",
        "scope": {"targets": ["1.2.3.4"], "ports": [80], "protocols": ["tcp"],
                  "network_allowed": True, "read_only": True}, "settings": {}}


def test_replay_rejected_on_a_different_worker_process():
    replay.reset_local_for_tests()
    signed = sign_job(_JOB)
    assert verify_job(signed) == _JOB               # worker A reserves the nonce in shared Redis
    replay._local_seen.clear()                      # a DIFFERENT worker process: empty local cache
    with pytest.raises(JobVerificationError, match="replay"):
        verify_job(signed)                          # worker B: the SHARED store rejects the replay


class _Spy:
    key, name, version, external_binary, ran = "spy", "spy", "1", False, False

    @property
    def capabilities(self):  # noqa: ANN201
        from guardian_core.tool import ToolCapabilities
        return ToolCapabilities(category="test", network=False, active=False)

    def validate(self, job):  # noqa: ANN001, ANN201
        return None

    def execute(self, job):  # noqa: ANN001, ANN201
        yield RawEvidence(tool="spy", execution_id=job.job_id, target="x", kind="spy", data={})

    def normalize(self, evidence):  # noqa: ANN001, ANN201
        return None


def test_replayed_run_tool_envelope_refused_on_second_worker(monkeypatch):
    from guardian_scanner.tools import registry
    from guardian_scanner.tools.tasks import run_tool
    monkeypatch.setattr(registry, "tool_for", lambda k: _Spy() if k == "spy" else None)
    replay.reset_local_for_tests()

    job = ToolJob(tenant_id="t", job_id="j1", tool_key="spy",
                  scope=EffectiveScope(targets=("1.2.3.4",), ports=(80,), protocols=("tcp",),
                                       network_allowed=False, read_only=True), settings={})
    signed = sign_job(job_to_wire(job))
    assert run_tool.apply(args=[signed]).get() != []    # first execution (worker A)
    replay._local_seen.clear()                          # different worker process
    assert run_tool.apply(args=[signed]).get() == []    # replay refused at run_tool ⇒ no re-run


def test_concurrent_reservation_has_exactly_one_winner():
    replay.reset_local_for_tests()
    nonce = "race-" + secrets.token_hex(8)
    results: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        r = replay.reserve_nonce(nonce, 60)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for r in results if r) == 1            # atomic single-use across 20 concurrent
