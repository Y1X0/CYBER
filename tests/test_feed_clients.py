"""Feed clients parse provider responses correctly and degrade gracefully (offline-safe)."""

import httpx
from guardian_clients.feeds import EpssClient, KevClient, OsvClient


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_osv_normalizes_vulns():
    def handler(req):
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "GHSA-abcd",
                        "aliases": ["CVE-2020-14343"],
                        "summary": "PyYAML RCE",
                        "references": [{"url": "https://example/adv"}],
                    }
                ]
            },
        )

    out = OsvClient(client=_client(handler)).query_package(
        name="pyyaml", version="5.3", ecosystem="pypi"
    )
    assert len(out) == 1
    assert out[0].external_id == "CVE-2020-14343"
    assert out[0].source == "osv"


def test_epss_parses_probability():
    def handler(req):
        return httpx.Response(200, json={"data": [{"cve": "CVE-2020-14343", "epss": "0.42"}]})

    assert EpssClient(client=_client(handler)).score_for("CVE-2020-14343") == 0.42


def test_kev_returns_id_set():
    def handler(req):
        return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2021-23337"}]})

    assert KevClient(client=_client(handler)).fetch_kev_ids() == {"CVE-2021-23337"}


def test_clients_degrade_on_error():
    def boom(req):
        return httpx.Response(500)

    assert (
        OsvClient(client=_client(boom)).query_package(name="x", version="1", ecosystem="pypi") == []
    )
    assert EpssClient(client=_client(boom)).score_for("CVE-2020-14343") is None
    assert KevClient(client=_client(boom)).fetch_kev_ids() == set()
