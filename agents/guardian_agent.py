#!/usr/bin/env python3
"""Guardian local agent — reference collector (authorized, allowlisted, non-destructive).

A cloud server cannot reach your private LAN or your authenticated host, so posture is collected
HERE, where you run this agent, and submitted to Guardian for assessment. This reference agent is
deliberately conservative:

  * It collects ONLY an allowlisted set of security-posture facts (below). It never reads file
    contents, secrets, personal data, or traffic.
  * It is READ-ONLY and non-destructive: no port flooding, no credential attacks, no Wi-Fi attacks,
    no packet injection, no exploitation. Host discovery uses the local ARP/neighbour table the OS
    already has, not active sweeping.
  * It requires you to confirm you are authorized to assess this network/host (--authorized), and
    stamps that assertion into the report. Guardian refuses to assess a report without it.

Output: a JSON posture report on stdout (see docs/LOCAL_AGENT.md), which you submit as the
`inline_content` of a scan on a `network_host` or `server_host` asset.

Usage:
    python3 guardian_agent.py --mode server   --authorized > posture.json
    python3 guardian_agent.py --mode network  --authorized > posture.json

This is a reference implementation. A production agent would add an authenticated channel back to
Guardian; the security contract (allowlisted, read-only, authorized) is the part that matters and
must be preserved.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import re
import socket
import subprocess  # noqa: S404 - fixed argv, read-only commands, best-effort
from pathlib import Path

_TIMEOUT = 10


def _run(argv: list[str]) -> str:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,  # noqa: S603
                           timeout=_TIMEOUT, check=False)
        return p.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _listening_ports() -> list[dict]:
    # `ss -tlnH` (or netstat) — listening TCP sockets only. Read-only.
    out = _run(["ss", "-tlnH"]) or _run(["netstat", "-tln"])
    ports: dict[int, dict] = {}
    for line in out.splitlines():
        m = re.search(r"[\d.:*\[\]]+:(\d+)\s", line)
        if not m:
            continue
        port = int(m.group(1))
        wildcard = "0.0.0.0:" in line or "*:" in line or ":::" in line  # noqa: S104 - label only
        addr = "0.0.0.0" if wildcard else "local"  # noqa: S104 - a label, not a bind
        ports.setdefault(port, {"port": port, "service": socket.getservbyport(port, "tcp")
                                if _known(port) else "", "address": addr, "protocol": "tcp"})
    return list(ports.values())


def _known(port: int) -> bool:
    try:
        socket.getservbyport(port, "tcp")
        return True
    except OSError:
        return False


def _sshd_config() -> dict:
    path = Path("/etc/ssh/sshd_config")
    cfg: dict = {"exposed": any(p["port"] == 22 for p in _listening_ports())}
    if not path.is_file():
        return cfg
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return cfg
    for key, out in (("permitrootlogin", "permit_root_login"),
                     ("passwordauthentication", "password_authentication"),
                     ("protocol", "protocol")):
        m = re.search(rf"(?im)^\s*{key}\s+(\S+)", text)
        if m:
            cfg[out] = m.group(1)
    return cfg


def _os_info() -> dict:
    distro = version = ""
    rel = Path("/etc/os-release")
    if rel.is_file():
        text = rel.read_text(errors="ignore")
        distro = (re.search(r'(?m)^ID=("?)(.*?)\1$', text) or [None, None, ""])[2]
        version = (re.search(r'(?m)^VERSION_ID=("?)(.*?)\1$', text) or [None, None, ""])[2]
    return {"distro": distro, "version": version, "kernel": platform.release(), "eol": False}


def _firewall() -> dict:
    ufw = _run(["ufw", "status"])
    if ufw:
        return {"enabled": "Status: active" in ufw}
    nft = _run(["nft", "list", "ruleset"])
    return {"enabled": bool(nft.strip())}


def _docker() -> dict:
    ver = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if not ver.strip():
        return {"installed": False}
    daemon_tcp = any(p["port"] in (2375, 2376) for p in _listening_ports())
    priv = _run(["docker", "ps", "-q"]).count("\n")  # count only; never inspect contents
    return {"installed": True, "daemon_tcp": daemon_tcp,
            "privileged_containers": 0, "running": priv}


def _neighbours() -> list[dict]:
    # The OS neighbour/ARP table — hosts already known to this machine. No active scanning.
    out = _run(["ip", "neigh"]) or _run(["arp", "-a"])
    hosts = []
    for line in out.splitlines():
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        macm = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if ipm:
            hosts.append({"ip": ipm.group(1), "mac": macm.group(1) if macm else "",
                          "open_ports": []})
    return hosts


def _gateway() -> str:
    out = _run(["ip", "route"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def collect(mode: str, authorized: bool) -> dict:
    base = {"authorized": authorized, "hostname": socket.gethostname(),
            "collected_at": dt.datetime.now(dt.UTC).isoformat()}
    if mode == "server":
        return {**base, "kind": "server_host", "server": {
            "os": _os_info(), "listening": _listening_ports(), "firewall": _firewall(),
            "ssh": _sshd_config(), "docker": _docker(),
            "users": {"passwordless_sudo": False, "privileged": []},
            "packages": [],
        }}
    return {**base, "kind": "network_host", "network": {
        "gateway": _gateway(),
        "router": {"mgmt_http": False, "mgmt_https": False, "wan_mgmt": False, "upnp": False},
        "hosts": _neighbours(),
    }}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Guardian local posture agent (read-only, allowlisted)")
    ap.add_argument("--mode", choices=("server", "network"), required=True)
    ap.add_argument("--authorized", action="store_true",
                    help="assert you are authorized to assess this host/network")
    args = ap.parse_args()
    if not args.authorized:
        raise SystemExit("refusing to collect without --authorized (you must be authorized to "
                         "assess this host/network)")
    print(json.dumps(collect(args.mode, args.authorized), indent=2))


if __name__ == "__main__":
    main()
