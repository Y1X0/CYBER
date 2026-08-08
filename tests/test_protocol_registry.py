"""Protocol-registry + probe unit tests (Phase 6C.2). No DB, no network."""

from __future__ import annotations

from guardian_common.ports import ProtocolProbe
from guardian_core.probe import ProbeEvidence
from guardian_scanner.discovery.protocol_registry import (
    available_protocol_probes,
    probe_for,
    probed_ports,
)


def test_only_http_and_tls_registered():
    assert set(available_protocol_probes()) == {"http", "tls"}


def test_ports_are_frozen_to_80_443():
    assert probed_ports() == (80, 443)


def test_probe_dispatch_by_port():
    assert probe_for(80).key == "http"
    assert probe_for(443).key == "tls"
    assert probe_for(22) is None  # no SSH probe — scope frozen


def test_registered_probes_satisfy_the_port():
    for probe in available_protocol_probes().values():
        assert isinstance(probe, ProtocolProbe)


def test_tls_probe_offline_returns_certificate_evidence():
    from guardian_scanner.discovery.protocols.tls_probe import TlsProbe

    ev = TlsProbe().probe("h", 443, timeout=1, allow_live=False,
                          snapshot={"port": 443, "tls": {"version": "TLSv1.3"}})
    assert isinstance(ev, ProbeEvidence)
    assert ev.protocol == "tls"
    assert ev.attributes["tls"] == {"version": "TLSv1.3"}
    assert ev.attributes["missing_tls"] is False


def test_http_probe_offline_returns_banner_evidence():
    from guardian_scanner.discovery.protocols.http_probe import HttpProbe

    ev = HttpProbe().probe("h", 80, timeout=1, allow_live=False, snapshot={"port": 80, "banner": "nginx"})
    assert ev.protocol == "http"
    assert ev.attributes["banner"] == "nginx"
    assert ev.attributes["missing_tls"] is True


def test_probe_offline_without_data_and_no_live_returns_none():
    from guardian_scanner.discovery.protocols.tls_probe import TlsProbe

    assert TlsProbe().probe("h", 443, timeout=1, allow_live=False, snapshot=None) is None


def test_third_party_probe_registers_without_core_or_orchestrator_changes(monkeypatch):
    """The extensibility proof: a new probe is discovered purely via its entry point.

    Nothing in guardian_core or the service_scan orchestrator is touched — the registry finds the
    probe through `guardian.protocol_probes` alone. This is what lets SSH/DB probes land later.
    """
    import guardian_scanner.discovery.protocol_registry as reg

    class FakeSshProbe:
        key = "ssh"
        ports = (2222,)

        def probe(self, host, port, *, timeout, allow_live, snapshot):  # noqa: ANN001, ANN202
            return ProbeEvidence("ssh", port, {"hostkey": "fake"})

    class _EP:
        name = "ssh"

        def load(self):  # noqa: ANN202
            return FakeSshProbe

    real = list(reg.entry_points(group="guardian.protocol_probes"))
    monkeypatch.setattr(reg, "entry_points", lambda group=None: [*real, _EP()])
    reg._load.cache_clear()
    try:
        probes = reg.available_protocol_probes()
        assert "ssh" in probes                    # discovered with zero core/orchestrator edits
        assert reg.probe_for(2222).key == "ssh"
        assert isinstance(probes["ssh"], ProtocolProbe)
    finally:
        reg._load.cache_clear()  # don't leak the fake probe into other tests
