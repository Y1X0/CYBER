"""Turn what a service says about itself into a product and a version (WP-B2).

A port number is not a finding. `5432/tcp open` tells a customer nothing they can act on;
`PostgreSQL 13.4 reachable from 0.0.0.0/0` tells them what to patch and what to firewall — and it is
the only form of the observation that a CVE lookup can consume, which is what WP-C3 is built on.

Two kinds of evidence are used, and they are kept distinct because their strength differs:

* **Volunteered banners.** SSH, SMTP, FTP and MySQL announce themselves on connect. Nothing is sent,
  and what comes back is usually the exact build string. This is the strongest signal available
  short of authenticating.
* **Identification probes.** HTTP, Redis and memcached say nothing until asked. Each probe here is a
  fixed, reviewed, read-only string — `HEAD / HTTP/1.0`, `PING`, `version` — chosen because it
  identifies the service without authenticating, without writing, and without touching data. That is
  the same line the templated-web-checks provider already draws. Anything that would require
  credentials, modify state, or trigger a vulnerability is out of scope for discovery.

A guess is never reported as an observation. When only the port number suggests what is running, the
result says so via a lower confidence and an empty `version`, so downstream CVE matching does not
attribute a vulnerability to a product nobody confirmed.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

PROBE_TIMEOUT = 2.0
PROBE_READ_BYTES = 2048

# Read-only identification probes. Each is a fixed byte string; none authenticates, writes, or
# touches stored data. Keyed by the service we are testing for, not by port, because the port is a
# hint and the point of this module is to stop trusting it.
_PROBES: dict[str, bytes] = {
    "http": b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: guardian-discovery\r\n\r\n",
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
}


@dataclass
class Service:
    """What is running on a port, and how strongly we believe it."""

    port: int
    service: str = ""            # "ssh" | "http" | "postgresql" …
    product: str = ""            # "OpenSSH" | "nginx"
    version: str = ""            # "8.9p1"
    banner: str = ""             # bounded, as observed
    cpe: str = ""                # cpe:2.3:a:vendor:product:version — the CVE lookup key
    confidence: int = 50
    evidence: str = "port"       # "banner" | "probe" | "port"
    attributes: dict = field(default_factory=dict)

    @property
    def identified(self) -> bool:
        return bool(self.product)


@dataclass(frozen=True)
class Signature:
    service: str
    pattern: re.Pattern[str]
    product: str = ""            # empty ⇒ take it from capture group "product"
    vendor: str = ""             # CPE vendor; empty ⇒ reuse the product name lowercased


# Ordered: the first match wins, so a more specific signature must come first.
_SIGNATURES: tuple[Signature, ...] = (
    # SSH announces itself before anything else happens, in a format the RFC fixes.
    Signature("ssh", re.compile(r"^SSH-\d+\.\d+-OpenSSH[_-](?P<version>[\w.]+)"),
              product="OpenSSH", vendor="openbsd"),
    Signature("ssh", re.compile(r"^SSH-\d+\.\d+-dropbear[_-]?(?P<version>[\w.]*)"),
              product="Dropbear", vendor="dropbear_ssh_project"),
    Signature("ssh", re.compile(r"^SSH-\d+\.\d+-(?P<product>[\w.+-]+)")),

    # FTP and SMTP both greet with `220`, so every product-specific signature has to be tried
    # before either generic one — a bare `^220` matcher placed first would label every mail server
    # an FTP server, and the port would be the only thing left disagreeing.
    Signature("ftp", re.compile(r"^220[ -].*vsFTPd (?P<version>[\d.]+)"),
              product="vsftpd", vendor="beasts"),
    Signature("ftp", re.compile(r"^220[ -].*ProFTPD (?P<version>[\d.\w]+)"),
              product="ProFTPD", vendor="proftpd"),
    Signature("smtp", re.compile(r"^220[ -].*Postfix"), product="Postfix", vendor="postfix"),
    Signature("smtp", re.compile(r"^220[ -].*Exim (?P<version>[\d.]+)"),
              product="Exim", vendor="exim"),
    Signature("smtp", re.compile(r"(?i)^220[ -].*\bE?SMTP\b")),
    Signature("ftp", re.compile(r"(?i)^220[ -].*\bFTP\b")),
    # A bare `220` with no protocol word left in it. Reported as neither: the port hint decides,
    # and no product is claimed.
    Signature("", re.compile(r"^220[ -]")),

    Signature("imap", re.compile(r"^\* OK .*IMAP")),
    Signature("pop3", re.compile(r"^\+OK ")),
    Signature("telnet", re.compile(r"^\xff[\xfb-\xfe]")),

    Signature("mysql", re.compile(r"^.\x00\x00\x00\n(?P<version>[\d][\w.\-]+)\x00", re.DOTALL),
              product="MySQL", vendor="oracle"),
    Signature("mongodb", re.compile(r"It looks like you are trying to access MongoDB over HTTP"),
              product="MongoDB", vendor="mongodb"),
    Signature("redis", re.compile(r"^\+PONG"), product="Redis", vendor="redis"),
    Signature("redis", re.compile(r"^-NOAUTH|^-ERR operation not permitted"),
              product="Redis", vendor="redis"),
    Signature("memcached", re.compile(r"^VERSION (?P<version>[\d.]+)"),
              product="memcached", vendor="memcached"),
    Signature("rabbitmq", re.compile(r"^AMQP")),
)

# `Server:` header values, which is where an HTTP service names itself.
_SERVER_HEADER = re.compile(r"(?im)^server:\s*(?P<value>.+)$")
_HTTP_STATUS = re.compile(r"^HTTP/(?P<http>[\d.]+) (?P<code>\d{3})")
_PRODUCT_VERSION = re.compile(r"^(?P<product>[A-Za-z][\w .+-]*?)[/ ](?P<version>\d[\w.\-]*)")

# CPE vendor names that differ from the product name. Guessing `cpe:2.3:a:nginx:nginx` is right;
# guessing `cpe:2.3:a:openssh:openssh` is wrong and would silently match nothing in the feed.
_CPE_VENDORS: dict[str, str] = {
    "openssh": "openbsd",
    "apache": "apache",
    "httpd": "apache",
    "nginx": "nginx",
    "iis": "microsoft",
    "microsoft-iis": "microsoft",
    "postfix": "postfix",
    "exim": "exim",
    "vsftpd": "beasts",
    "proftpd": "proftpd",
    "mysql": "oracle",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "redis": "redis",
    "memcached": "memcached",
    "mongodb": "mongodb",
    "elasticsearch": "elastic",
    "kibana": "elastic",
    "rabbitmq": "pivotal_software",
    "jetty": "eclipse",
    "tomcat": "apache",
    "openresty": "openresty",
    "caddy": "caddyserver",
    "traefik": "traefik",
    "lighttpd": "lighttpd",
    "gunicorn": "gunicorn",
    "werkzeug": "palletsprojects",
    "envoy": "envoyproxy",
    "cloudflare": "cloudflare",
}

_PRODUCT_CPE_NAMES: dict[str, str] = {
    "microsoft-iis": "internet_information_services",
    "httpd": "http_server",
    "apache": "http_server",
    "tomcat": "tomcat",
}


def cpe_for(product: str, version: str = "") -> str:
    """Build a CPE 2.3 application string, the key a CVE feed is indexed by.

    Returns "" when the product is unknown rather than inventing a vendor: a CPE that does not exist
    matches nothing, which looks exactly like "no vulnerabilities" to everything downstream.
    """
    if not product:
        return ""
    key = product.strip().lower().replace(" ", "_")
    vendor = _CPE_VENDORS.get(key)
    if vendor is None:
        return ""
    name = _PRODUCT_CPE_NAMES.get(key, key)
    return f"cpe:2.3:a:{vendor}:{name}:{version or '*'}:*:*:*:*:*:*:*"


def identify(port: int, banner: str, *, expected: str = "") -> Service:
    """Identify a service from a banner alone (nothing was sent)."""
    service = Service(port=port, banner=banner[:512])
    if banner:
        matched = _match_signature(banner)
        if matched is not None:
            signature, groups = matched
            # A signature with no service name matched a greeting shared by several protocols, so
            # the port hint decides what it is and no product is claimed for it.
            service.service = signature.service or expected
            service.product = signature.product or groups.get("product", "")
            service.version = groups.get("version", "")
            service.confidence = 95 if service.product else (80 if signature.service else 50)
            service.evidence = "banner"
            service.cpe = cpe_for(service.product, service.version)
            return service

    # Nothing volunteered, or nothing recognized. The port is a hint and is labelled as one.
    if expected:
        service.service = expected
        service.confidence = 40
        service.evidence = "port"
    return service


def _match_signature(banner: str) -> tuple[Signature, dict[str, str]] | None:
    for signature in _SIGNATURES:
        found = signature.pattern.search(banner)
        if found is None:
            continue
        groups = {k: v for k, v in (found.groupdict() or {}).items() if v}
        return signature, groups
    return None


def identify_http(response: str, port: int) -> Service:
    """Identify a web server from a response to a fixed `HEAD /`."""
    service = Service(port=port, service="http", banner=response[:512],
                      confidence=70, evidence="probe")
    status = _HTTP_STATUS.search(response)
    if status is None:
        return Service(port=port, banner=response[:512])
    service.attributes["status"] = int(status.group("code"))

    header = _SERVER_HEADER.search(response)
    if header is not None:
        value = header.group("value").strip()
        service.attributes["server"] = value[:120]
        parsed = _PRODUCT_VERSION.match(value)
        if parsed is not None:
            service.product = parsed.group("product").strip()
            service.version = parsed.group("version")
            service.confidence = 95
        else:
            service.product = value.split()[0] if value.split() else ""
            service.confidence = 80
        service.cpe = cpe_for(service.product, service.version)
    return service


# ── live identification ───────────────────────────────────────────────────────────────────────────
def probe(host: str, port: int, banner: str, *, expected: str = "",
          allow_probes: bool = True, timeout: float = PROBE_TIMEOUT) -> Service:
    """Identify a service, sending a fixed identification string only when the banner said nothing.

    The order matters: a volunteered banner is preferred because it costs nothing and cannot be
    mistaken for an attack. A probe is a second attempt, not a first move.
    """
    identified = identify(port, banner, expected=expected)
    if identified.identified or not allow_probes:
        return identified

    from guardian_scanner.discovery.ports import TLS_PORTS  # noqa: PLC0415 - avoids a cycle

    for name in _probe_order(port, expected):
        if name == "http" and port in TLS_PORTS:
            continue                     # a plaintext request to a TLS port reads back as garbage
        response = _send(host, port, _PROBES[name], timeout)
        if not response:
            continue
        if name == "http":
            result = identify_http(response, port)
        else:
            result = identify(port, response, expected=expected)
            result.evidence = "probe"
        if result.identified:
            return result
    return identified


def _probe_order(port: int, expected: str) -> list[str]:
    """Try the probe the port suggests first, then the rest. A wrong guess costs one connection."""
    order = [name for name in (expected,) if name in _PROBES]
    order += [name for name in ("http", "redis", "memcached") if name not in order]
    return order


def _send(  # pragma: no cover - network
    host: str, port: int, payload: bytes, timeout: float
) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            chunks: list[bytes] = []
            total = 0
            while total < PROBE_READ_BYTES:
                try:
                    piece = sock.recv(PROBE_READ_BYTES - total)
                except OSError:
                    break
                if not piece:
                    break
                chunks.append(piece)
                total += len(piece)
                if b"\r\n\r\n" in b"".join(chunks) or b"\n" in piece:
                    break
            return b"".join(chunks).decode("latin-1", "replace")
    except OSError:
        return ""
