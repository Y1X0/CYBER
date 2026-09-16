"""Request-body size limit at the ASGI layer (Issue 3).

Proves the protection sits BELOW FastAPI's dependency/endpoint layer — where the reviewer showed the
existing Content-Length dependency and read cap run only after Starlette has already spooled the
multipart body. These drive the middleware's raw ASGI interface directly (so the no-Content-Length /
chunked case is exercised, which a normal client cannot easily send) and then confirm the behaviour
end to end through the real app.
"""

from __future__ import annotations

import asyncio

from guardian_api.bodylimit import _ENVELOPE_ALLOWANCE, RequestBodySizeLimitMiddleware
from guardian_common.config import get_settings


def _run(coro):
    return asyncio.run(coro)


class _Send:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)

    @property
    def status(self):  # noqa: ANN201
        for m in self.messages:
            if m["type"] == "http.response.start":
                return m["status"]
        return None


def _scope(headers: dict | None = None) -> dict:
    return {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
    }


def _receiver(chunks):
    """chunks: list of (body_bytes, more_body). Yields ASGI http.request messages then disconnect."""
    it = iter(chunks)

    async def receive():
        try:
            body, more = next(it)
            return {"type": "http.request", "body": body, "more_body": more}
        except StopIteration:
            return {"type": "http.disconnect"}

    return receive


# ── Content-Length fast path ─────────────────────────────────────────────────────────────────────
def test_oversized_content_length_is_rejected_before_the_body_is_read(monkeypatch):
    monkeypatch.setattr(get_settings(), "artifact_max_bytes", 1000)
    inner_ran = {"v": False}

    async def inner(scope, receive, send):  # noqa: ANN001
        inner_ran["v"] = True

    send = _Send()
    over = 1000 + _ENVELOPE_ALLOWANCE + 1
    _run(RequestBodySizeLimitMiddleware(inner)(
        _scope({"content-length": str(over)}), _receiver([(b"x" * 10, False)]), send))
    assert send.status == 413
    assert inner_ran["v"] is False           # never handed downstream — body not parsed/spooled


# ── streamed body with NO Content-Length (chunked) ───────────────────────────────────────────────
def test_streamed_body_without_content_length_is_capped(monkeypatch):
    monkeypatch.setattr(get_settings(), "artifact_max_bytes", 1000)
    limit = 1000 + _ENVELOPE_ALLOWANCE
    consumed = {"n": 0}

    async def inner(scope, receive, send):  # noqa: ANN001
        # A stand-in for Starlette's multipart parser: pull the whole body from `receive`.
        while True:
            m = await receive()
            if m["type"] != "http.request":
                break
            consumed["n"] += len(m.get("body", b""))
            if not m.get("more_body"):
                break

    send = _Send()
    # ~200 KiB in 20 KiB chunks, no content-length header at all.
    chunks = [(b"x" * 20_000, True) for _ in range(9)] + [(b"x" * 20_000, False)]
    _run(RequestBodySizeLimitMiddleware(inner)(_scope({}), _receiver(chunks), send))
    assert send.status == 413
    # The downstream parser never received more than the limit — the whole hostile body was never
    # buffered (this is the DoS the Content-Length dependency could not prevent).
    assert consumed["n"] <= limit


def test_small_body_passes_through(monkeypatch):
    monkeypatch.setattr(get_settings(), "artifact_max_bytes", 100 * 1024 * 1024)
    ran = {"v": False}

    async def inner(scope, receive, send):  # noqa: ANN001
        await receive()
        ran["v"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    send = _Send()
    _run(RequestBodySizeLimitMiddleware(inner)(
        _scope({"content-length": "5"}), _receiver([(b"hello", False)]), send))
    assert ran["v"] is True and send.status == 200


def test_non_http_scope_is_passed_through():
    ran = {"v": False}

    async def inner(scope, receive, send):  # noqa: ANN001
        ran["v"] = True

    _run(RequestBodySizeLimitMiddleware(inner)({"type": "lifespan"}, None, None))
    assert ran["v"] is True


# ── end to end through the real app (no DB needed: rejected before routing/auth) ─────────────────
def test_app_rejects_oversized_content_length_before_routing(monkeypatch):
    from fastapi.testclient import TestClient
    from guardian_api.main import app

    monkeypatch.setattr(get_settings(), "artifact_max_bytes", 1000)
    client = TestClient(app)
    # A 200 KiB body to an unauthenticated JSON route: the middleware rejects on Content-Length
    # before CORS, routing, or auth — so this needs no DB and never reaches the handler.
    resp = client.post("/api/v1/auth/login", content=b"x" * 200_000,
                       headers={"content-type": "application/json"})
    assert resp.status_code == 413


def test_app_allows_a_normal_small_request():
    from fastapi.testclient import TestClient
    from guardian_api.main import app

    client = TestClient(app)
    assert client.get("/").status_code == 200        # small request is unaffected by the limit
