"""Which ports a sweep looks at, and what usually answers there (WP-B2).

A curated catalogue rather than a range, for two reasons. Scanning 1–65535 takes an hour per host
and produces almost nothing the first hundred ports did not; and a fixed, reviewed list is auditable
— a customer can be told exactly what Guardian will touch before it touches anything.

The `expected` name is a hint, never a conclusion. What is actually running on 8080 is decided by
`fingerprint` from what the service says about itself; a port number alone has been wrong about that
since the day someone moved SSH to 2222.
"""

from __future__ import annotations

# Ports whose exposure to the internet is a finding in itself, independent of what version answers.
# Everything here is either an administrative interface or a datastore that is normally
# unauthenticated inside a trust boundary.
SENSITIVE_PORTS: dict[int, str] = {
    22: "ssh",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    4444: "metasploit-default",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    7001: "weblogic",
    8009: "ajp",
    8086: "influxdb",
    9042: "cassandra",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    15672: "rabbitmq-management",
    27017: "mongodb",
    50070: "hadoop-namenode",
}

# Ports that are ordinary to publish. Present so the sweep sees them and can fingerprint what is
# there, not because their presence is a finding.
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1723: "pptp",
    3000: "http-alt",
    3128: "squid",
    4443: "https-alt",
    5000: "http-alt",
    5672: "amqp",
    6443: "kubernetes-api",
    8000: "http-alt",
    8080: "http-alt",
    8081: "http-alt",
    8088: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http-alt",
    9443: "https-alt",
    10250: "kubelet",
}

TOP_PORTS: dict[int, str] = {**COMMON_PORTS, **SENSITIVE_PORTS}

# Ports where a plaintext protocol is expected, so a TLS handshake attempt is a waste of a
# connection; and ports where TLS is expected, so a banner read will time out instead.
TLS_PORTS: frozenset[int] = frozenset(
    {443, 465, 993, 995, 4443, 8443, 9443, 6443, 10250, 2376, 5601}
)


def default_ports() -> tuple[int, ...]:
    return tuple(sorted(TOP_PORTS))


def sensitive_ports() -> tuple[int, ...]:
    return tuple(sorted(SENSITIVE_PORTS))


def expected_service(port: int) -> str:
    return TOP_PORTS.get(port, "")


def resolve_port_set(name_or_list: object) -> tuple[int, ...]:
    """Turn a settings value into a port list.

    Accepts `"top"`, `"sensitive"`, `"web"`, or an explicit list. An unknown name falls back to the
    default set rather than to an empty one: a typo in a setting must not silently turn a scan into
    a no-op that reports the host as clean.
    """
    if isinstance(name_or_list, list | tuple):
        return tuple(sorted({int(p) for p in name_or_list if str(p).isdigit()}))
    name = str(name_or_list or "").strip().lower()
    if name == "sensitive":
        return sensitive_ports()
    if name == "web":
        return tuple(sorted({80, 443, 3000, 8000, 8080, 8081, 8443, 8888, 9090, 9443}))
    return default_ports()
