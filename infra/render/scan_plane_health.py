#!/usr/bin/env python3
"""Minimal HTTP health endpoint for the scan-plane Render service.

Render's free tier bills background workers (HTTP 402), so the isolated scan-plane worker runs on a
``web`` service — and a web service must bind a port or Render marks the deploy failed and reaps it.
This is that port: a standard-library HTTP server that answers 200 on ``/health`` while the celery
scan worker it rides with is alive, and 503 if that worker has died (so Render's health check
restarts the instance rather than leaving a service that is up but consuming nothing).

It is deliberately dependency-free and imports NO guardian modules: the scan plane is DB-less and
secret-minimal, and this responder must boot in well under a second and hold no key. The only thing
it knows about the worker is its PID, passed in ``GUARDIAN_SCAN_WORKER_PID``; liveness is
``os.kill(pid, 0)``. It also doubles as the keepalive target that stops this free instance sleeping
(a free web service sleeps after 15 minutes with no inbound HTTP, and a scan offloaded to a sleeping
plane would block until the offload timeout — so guardian-keepalive.yml pings this ``/health`` too).
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _worker_alive() -> bool:
    """True if the scan worker process is alive (or if we were handed no PID to check).

    With no ``GUARDIAN_SCAN_WORKER_PID`` we do NOT claim the worker is dead — the start script's
    ``wait -n`` is the authoritative liveness guard, and reporting the port up keeps Render from
    reaping a healthy instance over a missing hint.
    """
    raw = os.environ.get("GUARDIAN_SCAN_WORKER_PID", "")
    if not raw.isdigit():
        return True
    try:
        os.kill(int(raw), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another uid — alive enough
    return True


class _Handler(BaseHTTPRequestHandler):
    def _respond(self) -> None:
        alive = _worker_alive()
        body = b'{"status":"ok","plane":"scan"}\n' if alive else b'{"status":"worker_down"}\n'
        self.send_response(200 if alive else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._respond()

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond()

    def log_message(self, *_args) -> None:  # noqa: ANN002
        # Silence the default stderr access log — a health probe every few minutes would otherwise
        # bury the celery worker's log, which is the signal that matters on this instance.
        return


def main() -> None:
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)  # noqa: S104
    print(f"[scan-plane-health] listening on :{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
