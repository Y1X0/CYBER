"""ASGI request-body size limit — reject an oversized body BEFORE it is buffered.

The artifact-upload endpoint validates size in two application-level places: a Content-Length
pre-check dependency and a hard `file.file.read(max+1)` cap. Both run only AFTER Starlette has
already parsed the multipart body and spooled every part to a temp file (FastAPI resolves body
params, which consumes the request stream, before the endpoint and its dependencies run). So a
client that streams a multi-gigabyte body — or a chunked body with no Content-Length at all — can
force Starlette to write the whole thing to the worker's temp disk before any application check
fires: a resource-exhaustion DoS that the later 100 MiB cap cannot prevent.

This middleware runs at the ASGI layer, before routing and multipart parsing. It:
  * rejects immediately on an oversized `Content-Length` (the body is never read); and
  * for a chunked / absent-Content-Length body, counts bytes as they arrive on the ASGI `receive`
    channel and aborts the moment the running total crosses the limit — so at most the limit (plus
    one in-flight chunk) is ever buffered downstream, never the whole hostile body.

The limit is read live from `artifact_max_bytes` (+ a small multipart-envelope allowance), so it is
the SAME single source of truth as the endpoint's own cap — no second, drifting limit. It is a
global cap: every other endpoint's body is far below it, so legitimate non-upload requests pass.
"""

from __future__ import annotations

from guardian_common.config import get_settings
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Headroom over the artifact byte cap for the multipart envelope (boundaries + part headers), to
# match the upload endpoint's own Content-Length allowance so the two limits stay consistent.
_ENVELOPE_ALLOWANCE = 64 * 1024


class _BodyTooLarge(Exception):
    """Raised inside the wrapped receive when the streamed body exceeds the cap."""


class RequestBodySizeLimitMiddleware:
    """Reject request bodies larger than `artifact_max_bytes` (+ envelope) at the ASGI layer."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def _limit(self) -> int:
        return get_settings().artifact_max_bytes + _ENVELOPE_ALLOWANCE

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self._limit()

        # Fast path: a truthful oversized Content-Length is refused before the body is read at all.
        raw_len = Headers(scope=scope).get("content-length")
        if raw_len is not None:
            try:
                if int(raw_len) > limit:
                    await self._reject(send)
                    return
            except ValueError:
                pass  # malformed header → fall through to the streaming counter

        received = 0
        response_started = False

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Stop before the downstream parser can buffer more than `limit` (+ this chunk).
                    raise _BodyTooLarge
            return message

        async def watching_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, watching_send)
        except _BodyTooLarge:
            # The body is consumed during request/form parsing, before the endpoint produces a
            # response, so we can still emit a clean 413. If a response had already begun (it should
            # not on the upload path), re-raise rather than corrupt the stream.
            if response_started:
                raise
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
