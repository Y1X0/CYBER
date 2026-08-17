"""DNS discovery source — the observation semantics that keep false findings out of the product.

The property under test is the distinction between *not asked* and *asked and gone*. An earlier
implementation collapsed the two, so a discovery run with no fixture data reported every seed host
as a subdomain-takeover candidate. These tests pin the difference so it cannot regress.
"""

from __future__ import annotations

from guardian_core.discovery import DiscoveryContext
from guardian_core.enums import NodeType
from guardian_scanner.discovery.providers.dns_provider import DnsProvider
from guardian_scanner.sources import dns as dns_source


def _ctx(snapshot, hosts, **settings):
    return DiscoveryContext(
        tenant_id="t", run_id="r",
        seeds={"hosts": hosts},
        settings={"dns": snapshot, **settings},
    )


# ── the regression: silence about what we never looked at ─────────────────────────────────────────
def test_host_absent_from_snapshot_is_unobserved():
    answer = dns_source.answers_from_snapshot("never-queried.example.com", {})
    assert answer.observed is False
    assert answer.unresolved is False        # cannot be "gone" if we never asked
    assert answer.takeover_candidate is False


def test_unobserved_host_produces_no_assets_at_all():
    """The bug: an empty snapshot used to yield one fabricated takeover finding per seed."""
    assets = list(DnsProvider().collect(_ctx({}, ["a.example.com", "b.example.com"])))
    assert assets == []


def test_unobserved_hosts_never_produce_dangling_flags():
    assets = list(DnsProvider().collect(_ctx({"other.example.com": ["1.1.1.1"]},
                                             ["ghost.example.com"])))
    assert all(not a.attributes.get("dangling_dns") for a in assets)


# ── the true positive that must survive the fix ───────────────────────────────────────────────────
def test_observed_empty_answer_is_dangling():
    answer = dns_source.answers_from_snapshot("gone.example.com", {"gone.example.com": []})
    assert answer.observed is True
    assert answer.unresolved is True

    assets = list(DnsProvider().collect(_ctx({"gone.example.com": []}, ["gone.example.com"])))
    assert len(assets) == 1
    assert assets[0].attributes["dangling_dns"] is True


def test_dangling_cname_is_the_stronger_takeover_signal():
    snapshot = {"old.example.com": {"a": [], "cname": "bucket.s3.amazonaws.com",
                                    "cname_dangling": True}}
    assets = list(DnsProvider().collect(_ctx(snapshot, ["old.example.com"])))
    assert assets[0].attributes["takeover_candidate"] is True
    assert assets[0].attributes["cname"] == "bucket.s3.amazonaws.com"
    # Ranked above a name that is merely absent.
    assert assets[0].confidence > 70


# ── resolution and reachability ───────────────────────────────────────────────────────────────────
def test_resolution_emits_host_and_address_nodes():
    assets = list(DnsProvider().collect(
        _ctx({"api.example.com": ["93.184.216.34"]}, ["api.example.com"])))
    kinds = [a.node_type for a in assets]
    assert NodeType.SUBDOMAIN in kinds
    assert NodeType.IP_ADDRESS in kinds
    host = next(a for a in assets if a.node_type == NodeType.SUBDOMAIN)
    assert host.attributes["internet_reachable"] is True
    assert host.edges[0].dst_key == "93.184.216.34"


def test_private_address_is_not_internet_reachable():
    assets = list(DnsProvider().collect(
        _ctx({"internal.example.com": ["10.0.0.5"]}, ["internal.example.com"])))
    host = next(a for a in assets if a.node_type == NodeType.SUBDOMAIN)
    assert host.attributes["internet_reachable"] is False
    ip = next(a for a in assets if a.node_type == NodeType.IP_ADDRESS)
    # An RFC1918 address is far weaker evidence of tenant ownership than a routable one.
    assert ip.ownership_confidence < 60


def test_ipv6_answers_are_separated_from_ipv4():
    answer = dns_source.answers_from_snapshot(
        "dual.example.com", {"dual.example.com": ["93.184.216.34", "2606:2800:220:1:248:1893::"]})
    assert answer.a == ("93.184.216.34",)
    assert answer.aaaa == ("2606:2800:220:1:248:1893::",)
    assert len(answer.ips) == 2


def test_garbage_snapshot_values_are_ignored_not_crashed():
    answer = dns_source.answers_from_snapshot("x.example.com", {"x.example.com": ["not-an-ip", ""]})
    assert answer.observed is True
    assert answer.ips == ()


# ── wildcard handling ─────────────────────────────────────────────────────────────────────────────
def test_wildcard_profile_matches_identical_address_set():
    profile = dns_source.WildcardProfile(
        domain="example.com", present=True, addresses=frozenset({"1.2.3.4"}))
    matching = dns_source.DnsAnswer(host="anything.example.com", observed=True, a=("1.2.3.4",))
    distinct = dns_source.DnsAnswer(host="real.example.com", observed=True, a=("5.6.7.8",))
    assert profile.matches(matching) is True
    assert profile.matches(distinct) is False


def test_absent_wildcard_never_matches():
    profile = dns_source.WildcardProfile(domain="example.com", present=False)
    answer = dns_source.DnsAnswer(host="a.example.com", observed=True, a=("1.2.3.4",))
    assert profile.matches(answer) is False


# ── offline is the default: no socket without allow_live ──────────────────────────────────────────
def test_offline_mode_never_resolves(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("offline discovery must not open a resolver")

    monkeypatch.setattr(dns_source, "resolve", _boom)
    monkeypatch.setattr(dns_source, "wildcard_profile", _boom)
    assets = list(DnsProvider().collect(_ctx({"a.example.com": ["1.1.1.1"]}, ["a.example.com"])))
    assert len(assets) == 2
