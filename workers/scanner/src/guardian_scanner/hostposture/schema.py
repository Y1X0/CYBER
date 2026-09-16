"""Allowlist normalizer for agent-submitted posture reports.

The agent runs on the user's own network/host, so its report must be treated as data, and only the
*allowlisted* fields are read — anything else the agent sent (a stray token, a file's contents) is
dropped, never stored. String values are scrubbed for credential shapes as defence in depth. The
result is a small, typed dict the posture engine evaluates.
"""

from __future__ import annotations

from guardian_core.redaction import scrub

_MAX_HOSTS = 4_000
_MAX_PORTS = 200
_MAX_PACKAGES = 20_000


def _s(v: object, limit: int = 200) -> str:
    return scrub(str(v))[0][:limit] if v is not None else ""


def _b(v: object) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() in ("true", "yes", "1", "on"))


def _i(v: object) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return None


def _ports(raw: object) -> list[dict]:
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for p in raw[:_MAX_PORTS]:
        if not isinstance(p, dict):
            continue
        port = _i(p.get("port"))
        if port is None:
            continue
        out.append({"port": port, "service": _s(p.get("service"), 40),
                    "tls": _b(p.get("tls")), "address": _s(p.get("address"), 60),
                    "protocol": _s(p.get("protocol"), 8) or "tcp"})
    return out


def normalize(report: object) -> dict:
    """Coerce an agent report to the allowlisted posture shape. Unknown keys are dropped."""
    r = report if isinstance(report, dict) else {}
    kind = _s(r.get("kind"), 20)
    out: dict = {
        "kind": kind if kind in ("network_host", "server_host") else "",
        "authorized": _b(r.get("authorized")),
        "collected_at": _s(r.get("collected_at"), 40),
        "hostname": _s(r.get("hostname"), 120),
    }

    net = r.get("network") if isinstance(r.get("network"), dict) else {}
    router = net.get("router") if isinstance(net.get("router"), dict) else {}
    hosts = []
    for h in (net.get("hosts") or [])[:_MAX_HOSTS] if isinstance(net.get("hosts"), list) else []:
        if not isinstance(h, dict):
            continue
        hosts.append({
            "ip": _s(h.get("ip"), 45), "mac": _s(h.get("mac"), 20),
            "vendor": _s(h.get("vendor"), 80), "hostname": _s(h.get("hostname"), 120),
            "open_ports": _ports(h.get("open_ports")),
        })
    out["network"] = {
        "gateway": _s(net.get("gateway"), 45),
        "router": {
            "vendor": _s(router.get("vendor"), 80), "model": _s(router.get("model"), 80),
            "firmware": _s(router.get("firmware"), 80),
            "mgmt_http": _b(router.get("mgmt_http")), "mgmt_https": _b(router.get("mgmt_https")),
            "wan_mgmt": _b(router.get("wan_mgmt")), "upnp": _b(router.get("upnp")),
        },
        "hosts": hosts,
    }

    srv = r.get("server") if isinstance(r.get("server"), dict) else {}
    os_ = srv.get("os") if isinstance(srv.get("os"), dict) else {}
    ssh = srv.get("ssh") if isinstance(srv.get("ssh"), dict) else {}
    fw = srv.get("firewall") if isinstance(srv.get("firewall"), dict) else {}
    users = srv.get("users") if isinstance(srv.get("users"), dict) else {}
    docker = srv.get("docker") if isinstance(srv.get("docker"), dict) else {}
    packages = []
    for p in (srv.get("packages") or [])[:_MAX_PACKAGES] \
            if isinstance(srv.get("packages"), list) else []:
        if isinstance(p, dict) and p.get("name"):
            packages.append({"name": _s(p.get("name"), 120), "version": _s(p.get("version"), 60)})
    out["server"] = {
        "os": {"distro": _s(os_.get("distro"), 40), "version": _s(os_.get("version"), 40),
               "kernel": _s(os_.get("kernel"), 60), "eol": _b(os_.get("eol"))},
        "listening": _ports(srv.get("listening")),
        "firewall": {"enabled": _b(fw.get("enabled"))} if fw else {"enabled": None},
        "ssh": {
            "exposed": _b(ssh.get("exposed")),
            "permit_root_login": _s(ssh.get("permit_root_login"), 20).lower(),
            "password_authentication": _s(ssh.get("password_authentication"), 20).lower(),
            "protocol": _s(ssh.get("protocol"), 8),
        } if ssh else {},
        "users": {"passwordless_sudo": _b(users.get("passwordless_sudo")),
                  "privileged": [_s(u, 60) for u in (users.get("privileged") or [])[:200]
                                 if isinstance(users.get("privileged"), list)]},
        "packages": packages,
        "docker": {"installed": _b(docker.get("installed")),
                   "daemon_tcp": _b(docker.get("daemon_tcp")),
                   "privileged_containers": _i(docker.get("privileged_containers")) or 0} if docker
        else {},
    }
    return out
