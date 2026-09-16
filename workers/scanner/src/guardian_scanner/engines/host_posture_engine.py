"""Host / home-network posture engine (Phase 2/3) — evaluates an authorized agent's submission.

A cloud host cannot reach a private LAN or an authenticated server, so this engine never scans
anything: an agent the user installs performs allowlisted, non-destructive collection on their own
network/host and submits a posture report, and this engine assesses that report through the normal
finding pipeline. It refuses to assess a report that does not assert authorization — collection
authorization lives at the agent, and a report that omits it is not evaluated.

Covers the two agent asset kinds:
  * `network_host` — home router / device posture (insecure management, exposed admin, UPnP,
    telnet/ftp, WAN-exposed management).
  * `server_host` — Linux server posture (SSH config, firewall, EOL OS, insecure services,
    passwordless sudo, exposed Docker daemon, privileged containers).

See docs/LOCAL_AGENT.md for the agent protocol and the reference collector.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.hostposture.schema import normalize

log = get_logger("guardian.engine.host_posture")

# Cleartext / legacy services that should not be exposed.
_INSECURE_SERVICES = {23: "telnet", 21: "ftp", 512: "rexec", 513: "rlogin", 514: "rsh",
                      2375: "docker-daemon", 111: "rpcbind", 445: "smb", 139: "netbios"}


_DEB = {"debian", "ubuntu", "kali", "mint", "linuxmint", "raspbian", "pop"}
_RPM = {"rhel", "redhat", "centos", "fedora", "rocky", "almalinux", "amzn", "amazon", "ol",
        "oracle", "suse", "opensuse", "sles"}


def _distro_ecosystem(distro: str) -> str:
    d = distro.strip().lower()
    if d in _DEB:
        return "deb"
    if d == "alpine":
        return "apk"
    if d in _RPM:
        return "rpm"
    return "generic"


class HostPostureInputError(RuntimeError):
    """No authorized posture report was submitted (readiness audit, Phase 4)."""


class HostPostureEngine:
    key = EngineKey.HOST_POSTURE
    name = "Guardian Host & Network Posture (local agent)"
    version = "1.0.0"
    requires_authorization = False  # passive: assesses the authorized agent's own report

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"network_host", "server_host"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="assesses authorized local-agent posture submissions")

    def collect_inventory(self, ctx: ScanContext) -> list[tuple[str, str, str, str]]:
        """Server package inventory (name, version, ecosystem, source) for the SBOM.

        Reads the authorized agent's submitted `server.packages`, mapping the OS distribution to a
        package ecosystem (deb/apk/rpm). Only an authorized server report contributes; a network
        report or an unauthorized/absent one yields nothing (never raises).
        """
        report = self._load(ctx)
        if report is None:
            return []
        posture = normalize(report)
        if not posture.get("authorized") or posture.get("kind") != "server_host":
            return []
        server = posture.get("server") or {}
        eco = _distro_ecosystem(str((server.get("os") or {}).get("distro") or ""))
        out: list[tuple[str, str, str, str]] = []
        for p in server.get("packages") or []:
            name, version = str(p.get("name") or ""), str(p.get("version") or "")
            if name:
                out.append((name, version, eco, "local-agent"))
        return out

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        report = self._load(ctx)
        if report is None:
            raise HostPostureInputError(
                "no posture report was submitted (expected inline JSON or asset_config['posture'])")
        posture = normalize(report)
        if not posture.get("authorized"):
            # Never assess collection that does not assert operator authorization.
            raise HostPostureInputError(
                "the posture report does not assert authorization; refusing to assess it")
        if posture["kind"] == "network_host":
            yield from self._network_findings(posture)
        elif posture["kind"] == "server_host":
            yield from self._server_findings(posture)
        else:
            raise HostPostureInputError(f"unknown posture kind {posture['kind']!r}")

    def _load(self, ctx: ScanContext) -> object | None:
        cfg = ctx.asset_config or {}
        if isinstance(cfg.get("posture"), dict):
            return cfg["posture"]
        if ctx.inline_content:
            try:
                return json.loads(ctx.inline_content)
            except ValueError:
                return None
        return None

    # ── network_host (home router / devices) ────────────────────────────────────────────────────
    def _network_findings(self, p: dict) -> Iterable[RawFinding]:
        net = p["network"]
        r = net["router"]
        host = p.get("hostname") or net.get("gateway") or "the router"
        if r["mgmt_http"] and not r["mgmt_https"]:
            yield _f("Router management over cleartext HTTP", "network-router", Severity.HIGH,
                     "CWE-319", f"The router at {net.get('gateway') or host} exposes its admin "
                     "interface over unencrypted HTTP. Credentials and settings can be read on the "
                     "LAN. Use HTTPS management and disable HTTP.", {"gateway": net.get("gateway")})
        if r["wan_mgmt"]:
            yield _f("Router management exposed to the internet (WAN)", "network-router",
                     Severity.CRITICAL, "CWE-284", "The router's management interface is reachable "
                     "from the WAN side. Remote administration should be disabled or restricted to "
                     "a VPN.", {"gateway": net.get("gateway")})
        if r["upnp"]:
            yield _f("UPnP enabled on the router", "network-router", Severity.MEDIUM, "CWE-284",
                     "UPnP lets any device on the LAN open inbound ports on the router without "
                     "authentication, a common exposure path for IoT malware. Disable it unless a "
                     "specific device requires it.", {"gateway": net.get("gateway")})
        for h in net["hosts"]:
            for port in h["open_ports"]:
                svc = _INSECURE_SERVICES.get(port["port"])
                if svc and svc != "docker-daemon":
                    yield _f(f"Insecure service exposed on the LAN: {svc}", "network-service",
                             Severity.HIGH, "CWE-319",
                             f"Host {h.get('ip') or h.get('hostname')} exposes {svc} on port "
                             f"{port['port']}, a cleartext/legacy protocol. Disable it or use an "
                             "encrypted equivalent.",
                             {"host": h.get("ip"), "port": port["port"], "service": svc})

    # ── server_host (Linux) ─────────────────────────────────────────────────────────────────────
    def _server_findings(self, p: dict) -> Iterable[RawFinding]:
        s = p["server"]
        host = p.get("hostname") or "the server"
        ssh = s.get("ssh") or {}
        if ssh.get("permit_root_login") in ("yes", "prohibit-password", "without-password"):
            sev = Severity.HIGH if ssh["permit_root_login"] == "yes" else Severity.MEDIUM
            yield _f("SSH permits root login", "server-ssh", sev, "CWE-250",
                     f"{host} has sshd PermitRootLogin={ssh['permit_root_login']}. Disable direct "
                     "root login (PermitRootLogin no) and use a named account with sudo.",
                     {"setting": "PermitRootLogin", "value": ssh["permit_root_login"]})
        if ssh.get("password_authentication") == "yes":
            yield _f("SSH allows password authentication", "server-ssh", Severity.MEDIUM,
                     "CWE-262", f"{host} allows SSH password auth, exposing it to credential "
                     "guessing. Prefer key-based auth (PasswordAuthentication no).",
                     {"setting": "PasswordAuthentication", "value": "yes"})
        if ssh.get("protocol") == "1":
            yield _f("SSH protocol 1 enabled", "server-ssh", Severity.HIGH, "CWE-327",
                     f"{host} enables the cryptographically broken SSH protocol 1. Use protocol 2 "
                     "only.", {"setting": "Protocol", "value": "1"})

        if s.get("firewall", {}).get("enabled") is False:
            yield _f("Host firewall disabled", "server-hardening", Severity.MEDIUM, "CWE-1188",
                     f"{host} reports no active host firewall, so every listening service is "
                     "exposed to any reachable network. Enable a default-deny firewall.", {})

        if s.get("os", {}).get("eol"):
            os_ = s["os"]
            yield _f(f"End-of-life operating system: {os_['distro']} {os_['version']}",
                     "server-os", Severity.HIGH, "CWE-1104",
                     f"{host} runs {os_['distro']} {os_['version']}, which no longer receives "
                     "security updates. Upgrade to a supported release.",
                     {"distro": os_["distro"], "version": os_["version"]})

        for port in s.get("listening", []):
            svc = _INSECURE_SERVICES.get(port["port"])
            if svc == "docker-daemon" or (svc == "docker-daemon" and port["port"] == 2375):
                continue  # handled below with richer context
            if svc:
                yield _f(f"Insecure/legacy service listening: {svc}", "server-service",
                         Severity.HIGH, "CWE-319",
                         f"{host} listens on port {port['port']} ({svc}), a cleartext or legacy "
                         "service. Disable it or restrict and encrypt it.",
                         {"port": port["port"], "service": svc, "address": port.get("address")})

        if s.get("users", {}).get("passwordless_sudo"):
            yield _f("Passwordless sudo configured", "server-hardening", Severity.HIGH, "CWE-250",
                     f"{host} grants sudo without a password, so any compromised user or process "
                     "with that account has instant root. Require authentication for sudo.", {})

        docker = s.get("docker") or {}
        if docker.get("daemon_tcp"):
            yield _f("Docker daemon exposed over TCP", "server-docker", Severity.CRITICAL,
                     "CWE-284", f"{host} exposes the Docker daemon over a TCP socket. Access to "
                     "the "
                     "Docker API is equivalent to root on the host. Bind the daemon to the local "
                     "socket only and never expose 2375/2376 without mTLS.", {})
        if docker.get("privileged_containers", 0) > 0:
            yield _f(f"Privileged containers running ({docker['privileged_containers']})",
                     "server-docker", Severity.HIGH, "CWE-250",
                     f"{host} runs {docker['privileged_containers']} privileged container(s), "
                     "which "
                     "can escape to the host. Drop --privileged and grant only required "
                     "capabilities.", {"count": docker["privileged_containers"]})


def _f(title: str, category: str, severity: Severity, cwe: str, description: str,
       location: dict) -> RawFinding:
    return RawFinding(
        engine=EngineKey.HOST_POSTURE, title=title[:300], category=category,
        description=description, base_severity=severity, confidence="high", cwe_id=cwe,
        location={"source": "local-agent", **{k: v for k, v in location.items() if v is not None}},
        evidence={"detector": "host-posture", **location},
        references={"cwe": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"},
    )
