"""Active port and service discovery (WP-B2).

The live tests here bind real TCP listeners on 127.0.0.1 and sweep them over real sockets. That is
the only way to test a connect scanner honestly: the interesting behaviour is what the kernel does
with a refused connect versus a filtered one, and a mocked socket asserts nothing about either.

Loopback is used because the test creates the listeners itself. The production path refuses any
target that does not resolve to a public address, which is asserted separately — the guard and the
scanner are different layers, and proving one must not require weakening the other.

What the sweep is *for* is the last section: a port number is not a finding, but
`OpenSSH 8.9p1 on 22` is a CVE lookup, and that string is what WP-C3 consumes.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
from guardian_scanner.discovery import fingerprint
from guardian_scanner.discovery.ports import (
    SENSITIVE_PORTS,
    default_ports,
    expected_service,
    resolve_port_set,
)
from guardian_scanner.discovery.portscan import sweep


# ── a real listener ───────────────────────────────────────────────────────────────────────────────
class Listener:
    """A TCP server that speaks one fixed exchange, so a sweep has something real to find."""

    def __init__(self, greeting: bytes = b"", reply: bytes = b"") -> None:
        self.greeting = greeting
        self.reply = reply
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(1.0)
            try:
                if self.greeting:
                    conn.sendall(self.greeting)
                if self.reply:
                    conn.recv(1024)
                    conn.sendall(self.reply)
            except OSError:
                return

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
        self._sock.close()


@pytest.fixture
def listeners():
    created: list[Listener] = []

    def make(greeting: bytes = b"", reply: bytes = b"") -> Listener:
        listener = Listener(greeting, reply)
        created.append(listener)
        return listener

    yield make
    for listener in created:
        listener.close()


def _closed_port() -> int:
    """A port nothing is listening on: bound, read, and released."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ── the sweep, over real sockets ──────────────────────────────────────────────────────────────────
def test_an_open_port_is_found_and_a_closed_one_is_not(listeners):
    open_listener = listeners()
    closed = _closed_port()

    result = sweep("127.0.0.1", [open_listener.port, closed], timeout=2.0, rate=0)

    assert [p.port for p in result.open_ports] == [open_listener.port]
    assert result.scanned == 2
    assert result.complete is True


def test_many_ports_are_swept_concurrently(listeners):
    """A sequential sweep of 60 ports at a 2s timeout would take two minutes."""
    open_ports = sorted(listeners().port for _ in range(3))
    closed = [_closed_port() for _ in range(57)]

    started = time.monotonic()
    result = sweep("127.0.0.1", open_ports + closed, timeout=2.0, concurrency=64, rate=0)
    elapsed = time.monotonic() - started

    assert [p.port for p in result.open_ports] == open_ports
    assert elapsed < 15, f"sweep of 60 ports took {elapsed:.1f}s — concurrency is not working"


def test_a_volunteered_banner_is_captured(listeners):
    listener = listeners(greeting=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
    result = sweep("127.0.0.1", [listener.port], timeout=2.0, rate=0)
    assert result.open_ports[0].banner.startswith("SSH-2.0-OpenSSH_8.9p1")


def test_a_silent_service_still_counts_as_open(listeners):
    """Most services say nothing until spoken to. An empty banner is not a closed port."""
    listener = listeners()
    result = sweep("127.0.0.1", [listener.port], timeout=2.0, rate=0)
    assert [p.port for p in result.open_ports] == [listener.port]
    assert result.open_ports[0].banner == ""


def test_an_unresolvable_host_is_an_error_not_an_empty_result():
    """An empty result reads as "nothing exposed". A host that does not resolve has to say so."""
    result = sweep("this-host-does-not-exist.invalid", [80], timeout=1.0, rate=0)
    assert result.open_ports == []
    assert result.error
    assert result.complete is False


def test_the_deadline_marks_the_result_truncated_rather_than_reporting_it_complete():
    result = sweep("127.0.0.1", list(range(20000, 20400)), timeout=5.0, concurrency=1,
                   rate=2.0, deadline=0.5)
    assert result.truncated is True
    assert result.complete is False


def test_the_port_list_is_bounded():
    from guardian_scanner.discovery.portscan import MAX_PORTS

    result = sweep("127.0.0.1", list(range(1, MAX_PORTS + 500)), timeout=0.05,
                   concurrency=128, rate=0, deadline=1.0)
    assert result.scanned <= MAX_PORTS


def test_the_rate_limiter_bounds_connections_per_second():
    started = time.monotonic()
    sweep("127.0.0.1", [_closed_port() for _ in range(10)], timeout=0.5, concurrency=10, rate=20.0)
    elapsed = time.monotonic() - started
    # 10 connections at 20/s cannot finish faster than ~0.45s.
    assert elapsed >= 0.4, f"rate limit not applied ({elapsed:.2f}s for 10 connections)"


# ── identification from banners ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("banner", "service", "product", "version"),
    [
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", "ssh", "OpenSSH", "8.9p1"),
        ("SSH-2.0-OpenSSH_7.4", "ssh", "OpenSSH", "7.4"),
        ("SSH-2.0-dropbear_2020.81", "ssh", "Dropbear", "2020.81"),
        ("220 (vsFTPd 3.0.5)", "ftp", "vsftpd", "3.0.5"),
        ("220 mail.example.com ESMTP Postfix (Ubuntu)", "smtp", "Postfix", ""),
        ("220 mx.example.com ESMTP Exim 4.96 Mon, 1 Jan 2024", "smtp", "Exim", "4.96"),
        ("VERSION 1.6.21", "memcached", "memcached", "1.6.21"),
        ("+PONG", "redis", "Redis", ""),
    ],
)
def test_banners_identify_product_and_version(banner, service, product, version):
    found = fingerprint.identify(22, banner)
    assert found.service == service
    assert found.product == product
    assert found.version == version
    assert found.evidence == "banner"


def test_an_unauthenticated_redis_is_recognized_from_its_error():
    """A password-protected Redis answers -NOAUTH; that still identifies the product."""
    assert fingerprint.identify(6379, "-NOAUTH Authentication required.").product == "Redis"


def test_a_mysql_handshake_yields_its_version():
    handshake = "J\x00\x00\x00\n8.0.35-0ubuntu0.22.04.1\x00\x0b\x00\x00\x00"
    found = fingerprint.identify(3306, handshake)
    assert found.product == "MySQL"
    assert found.version == "8.0.35-0ubuntu0.22.04.1"


def test_an_unknown_banner_is_not_attributed_to_a_product():
    """Guessing a product from a port number would attribute someone else's CVEs to this service."""
    found = fingerprint.identify(5432, "", expected="postgresql")
    assert found.service == "postgresql"
    assert found.product == ""
    assert found.cpe == ""
    assert found.evidence == "port"
    assert found.confidence < 50


def test_http_server_header_identifies_the_product():
    response = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"
    found = fingerprint.identify_http(response, 80)
    assert found.product == "nginx"
    assert found.version == "1.24.0"
    assert found.attributes["status"] == 200
    assert found.evidence == "probe"


def test_an_http_response_without_a_server_header_still_identifies_http():
    found = fingerprint.identify_http("HTTP/1.1 404 Not Found\r\n\r\n", 8080)
    assert found.service == "http"
    assert found.product == ""


# ── CPE, the key a CVE feed is indexed by ─────────────────────────────────────────────────────────
def test_cpe_uses_the_real_vendor_not_the_product_name():
    """`cpe:2.3:a:openssh:openssh` looks plausible and matches nothing. The vendor is openbsd."""
    assert fingerprint.cpe_for("OpenSSH", "8.9p1") == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    assert fingerprint.cpe_for("nginx", "1.24.0") == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    assert fingerprint.cpe_for("MySQL", "8.0.35") == "cpe:2.3:a:oracle:mysql:8.0.35:*:*:*:*:*:*:*"


def test_an_unknown_product_produces_no_cpe():
    """An invented CPE matches nothing in the feed, which downstream reads as "no vulnerabilities"."""
    assert fingerprint.cpe_for("SomeInternalDaemon", "1.0") == ""


def test_a_versionless_identification_produces_a_wildcard_cpe():
    assert fingerprint.cpe_for("Redis") == "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"


def test_an_identified_banner_carries_a_cpe():
    found = fingerprint.identify(22, "SSH-2.0-OpenSSH_8.9p1")
    assert found.cpe == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"


# ── the port catalogue ────────────────────────────────────────────────────────────────────────────
def test_the_default_port_set_covers_the_services_that_matter():
    ports = set(default_ports())
    for port in (22, 3306, 5432, 6379, 9200, 27017, 3389, 2375):
        assert port in ports, f"{port} ({expected_service(port)}) missing from the default sweep"


def test_sensitive_ports_are_a_subset_of_the_default_set():
    assert set(SENSITIVE_PORTS) <= set(default_ports())


def test_a_named_port_set_resolves():
    assert set(resolve_port_set("sensitive")) == set(SENSITIVE_PORTS)
    assert set(resolve_port_set("web")) <= set(default_ports())
    assert resolve_port_set([22, 443, "80"]) == (22, 80, 443)


def test_an_unknown_port_set_name_falls_back_to_the_default_rather_than_to_nothing():
    """A typo in a setting must not silently turn a scan into a no-op that reports a clean host."""
    assert resolve_port_set("tpo") == default_ports()
    assert resolve_port_set(None) == default_ports()


def test_an_ambiguous_220_greeting_claims_no_product():
    """FTP and SMTP share the `220` greeting. With no protocol word left in the banner, the port
    hint decides the label and nothing claims a product."""
    ambiguous = fingerprint.identify(21, "220 ready", expected="ftp")
    assert ambiguous.service == "ftp"
    assert ambiguous.product == ""
    assert ambiguous.cpe == ""

    as_smtp = fingerprint.identify(25, "220 ready", expected="smtp")
    assert as_smtp.service == "smtp"
    assert as_smtp.product == ""


def test_a_mail_server_on_a_nonstandard_port_is_still_smtp():
    """The banner outranks the port. A `220 ... ESMTP` on 2525 is a mail server."""
    found = fingerprint.identify(2525, "220 mx.example.com ESMTP Postfix")
    assert found.service == "smtp"
    assert found.product == "Postfix"


# ── the provider ──────────────────────────────────────────────────────────────────────────────────
def _context(snapshot, targets=("93.184.216.34",), **settings):
    from guardian_core.discovery import DiscoveryContext

    return DiscoveryContext(
        tenant_id="t", run_id="r", authorized=True, authorized_targets=list(targets),
        settings={"service_scan": snapshot, **settings},
    )


def _collect(ctx):
    from guardian_scanner.discovery.providers.service_scan_provider import ServiceScanProvider

    return list(ServiceScanProvider().collect(ctx))


def test_a_service_asset_carries_product_version_and_cpe():
    """The whole point of the sweep: a port number is not actionable, `OpenSSH 8.9p1` is."""
    snapshot = {"93.184.216.34": {"22": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"}}}
    services = [a for a in _collect(_context(snapshot)) if a.node_type.value == "service"]
    assert len(services) == 1
    attributes = services[0].attributes
    assert attributes["service"] == "ssh"
    assert attributes["product"] == "OpenSSH"
    assert attributes["version"] == "8.9p1"
    assert attributes["cpe"] == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    assert attributes["sensitive_service"] == "ssh"


def test_an_exposed_datastore_is_flagged_by_port_even_without_a_version():
    """Redis reachable from the internet is a finding whether or not the build string is known."""
    snapshot = {"93.184.216.34": {"6379": {"banner": ""}}}
    services = [a for a in _collect(_context(snapshot)) if a.node_type.value == "service"]
    assert services[0].attributes["sensitive_service"] == "redis"
    assert services[0].attributes.get("product") is None
    assert "cpe" not in services[0].attributes


def test_an_ordinary_web_port_is_not_flagged_sensitive():
    snapshot = {"93.184.216.34": {"443": {"tls": {"version": "TLSv1.3"}}}}
    services = [a for a in _collect(_context(snapshot)) if a.node_type.value == "service"]
    assert "sensitive_service" not in services[0].attributes


def test_every_service_gets_a_hosts_edge_from_its_host():
    snapshot = {"93.184.216.34": {"22": {"banner": "SSH-2.0-OpenSSH_9.0"},
                                  "443": {"tls": {"version": "TLSv1.3"}}}}
    assets = _collect(_context(snapshot))
    edges = [e for a in assets for e in a.edges]
    assert {e.dst_key for e in edges} == {"93.184.216.34:22", "93.184.216.34:443"}


def test_nothing_is_probed_without_an_authorized_target():
    assert _collect(_context({"93.184.216.34": {"22": {"banner": "x"}}}, targets=())) == []


def test_offline_mode_never_reaches_the_network():
    """A host with no snapshot and no allow_live produces nothing rather than a live sweep."""
    assert _collect(_context({}, targets=("example.com",))) == []


def test_the_live_path_refuses_a_target_that_is_not_publicly_routable():
    """A hostname resolving to 10.0.0.1 or 169.254.169.254 points at our own infrastructure. The
    guard runs before any packet, so an authorization can never turn Guardian into the pivot."""
    import inspect

    from guardian_scanner.discovery.providers import service_scan_provider as ssp

    source = inspect.getsource(ssp.ServiceScanProvider.collect)
    assert "_is_public(host)" in source
    assert source.index("_is_public(host)") < source.index("sweep(host, ports")


def test_the_public_address_guard_itself(monkeypatch):
    from guardian_scanner.discovery.providers import service_scan_provider as ssp

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    assert ssp._is_public("intranet.example.com") is False

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))])
    assert ssp._is_public("metadata.example.com") is False

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert ssp._is_public("example.com") is True


def test_a_host_with_mixed_public_and_private_addresses_is_refused():
    """One private answer is enough: DNS rebinding is exactly this shape."""
    from guardian_scanner.discovery.providers import service_scan_provider as ssp

    original = socket.getaddrinfo
    socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0)),
                                          (2, 1, 6, "", ("127.0.0.1", 0))]
    try:
        assert ssp._is_public("rebind.example.com") is False
    finally:
        socket.getaddrinfo = original


def test_collection_is_deterministic():
    snapshot = {"93.184.216.34": {"22": {"banner": "SSH-2.0-OpenSSH_9.0"},
                                  "6379": {"banner": "+PONG"},
                                  "443": {"tls": {"version": "TLSv1.3"}}}}
    first = [(a.node_type.value, a.canonical_key) for a in _collect(_context(snapshot))]
    second = [(a.node_type.value, a.canonical_key) for a in _collect(_context(snapshot))]
    assert first == second
    services = [key for kind, key in first if kind == "service"]
    assert services == ["93.184.216.34:22", "93.184.216.34:443", "93.184.216.34:6379"]
