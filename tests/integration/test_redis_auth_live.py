"""Redis authentication — REAL authenticated Redis (P1-δ). Gated by GUARDIAN_RUN_DB_TESTS=1.

Spins a password-protected `redis-server` and proves: an unauthenticated client is rejected; an
authenticated client works; the replay-nonce store (P1-1) functions over AUTH; and Celery's broker +
result backend both connect with the password in the URL — so authentication does not break Celery.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1" or shutil.which("redis-server") is None,
    reason="requires redis-server binary + GUARDIAN_RUN_DB_TESTS=1",
)

_PW = "test-redis-pass-9f2a"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def authed_redis():
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603
        ["redis-server", "--port", str(port), "--requirepass", _PW, "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    import redis

    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            redis.Redis(host="127.0.0.1", port=port, password=_PW).ping()
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.skip("authed redis did not come up")
    try:
        yield port, f"redis://:{_PW}@127.0.0.1:{port}/0"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_unauthenticated_client_is_rejected(authed_redis):
    port, _url = authed_redis
    import redis

    with pytest.raises(redis.exceptions.AuthenticationError):
        redis.Redis(host="127.0.0.1", port=port).ping()      # no password → NOAUTH


def test_authenticated_client_works(authed_redis):
    port, _url = authed_redis
    import redis

    assert redis.Redis(host="127.0.0.1", port=port, password=_PW).ping() is True


def test_replay_nonce_store_works_over_auth(authed_redis, monkeypatch):
    # P1-1 replay store (redis-py SET NX EX) must function against an authenticated broker.
    _port, url = authed_redis
    from guardian_common import config, replay

    monkeypatch.setattr(replay, "get_settings", lambda: config.Settings(env="ci", redis_url=url))
    replay.reset_local_for_tests()
    nonce = "n-" + _PW
    assert replay.reserve_nonce(nonce, 60) is True           # first use reserved
    assert replay.reserve_nonce(nonce, 60) is False          # replay refused (single-use holds)
    replay.reset_local_for_tests()


def test_celery_broker_and_backend_connect_over_auth(authed_redis):
    # Celery must not break under Redis AUTH: both broker and result backend connect with the URL pw.
    _port, url = authed_redis
    from celery import Celery

    app = Celery("authcheck", broker=url, backend=url)
    app.connection().ensure_connection(max_retries=2)        # broker AUTH ok
    assert app.backend.client.ping() is True                 # result-backend AUTH ok
