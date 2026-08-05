"""`guardian` CLI — trigger a scan and enforce the deployment gate from CI/CD.

Usage:
    guardian scan --asset <asset_id> [--engines secrets,sast,sca] [--timeout 300]

Config via env: GUARDIAN_API_URL (default http://localhost:8000), GUARDIAN_TOKEN (bearer).
Exit code 0 = gate passed; 1 = gate failed (block deploy); 2 = usage/transport error.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import httpx


def _client() -> httpx.Client:
    base = os.environ.get("GUARDIAN_API_URL", "http://localhost:8000").rstrip("/")
    token = os.environ.get("GUARDIAN_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.Client(base_url=base, headers=headers, timeout=30.0)


def _cmd_scan(args: argparse.Namespace) -> int:
    engines = [e.strip() for e in args.engines.split(",") if e.strip()]
    with _client() as c:
        r = c.post(
            "/api/v1/scans", json={"asset_id": args.asset, "engines": engines, "trigger": "ci"}
        )
        if r.status_code != 202:
            print(f"error: could not start scan: {r.status_code} {r.text}", file=sys.stderr)
            return 2
        scan_id = r.json()["id"]
        print(f"scan {scan_id} started ({', '.join(engines)})")

        deadline = time.monotonic() + args.timeout
        status = "queued"
        while time.monotonic() < deadline:
            s = c.get(f"/api/v1/scans/{scan_id}").json()
            status = s["status"]
            if status in {"completed", "partial", "failed", "canceled"}:
                break
            time.sleep(3)
        print(f"scan status: {status}")

        gate = c.get(f"/api/v1/scans/{scan_id}/gate").json()
        if gate.get("passed"):
            print("✅ security gate PASSED")
            return 0
        print(f"❌ security gate FAILED — {gate.get('blocking_count', 0)} blocking finding(s):")
        for b in gate.get("blocking", [])[:20]:
            print(f"   [{b['severity'].upper()}] {b['title']}")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian", description="Security Guardian CI gate")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("scan", help="run a scan and enforce the deployment gate")
    ps.add_argument("--asset", required=True, help="asset id to scan")
    ps.add_argument("--engines", default="secrets,sast,sca", help="comma-separated engine keys")
    ps.add_argument("--timeout", type=int, default=300, help="max seconds to wait for completion")
    ps.set_defaults(func=_cmd_scan)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except httpx.HTTPError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
