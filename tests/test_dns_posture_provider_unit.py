"""DnsPostureProvider unit contract (no DB, no network) — absence-as-evidence, deterministic.

Proves Provider #3 is a passive, offline posture assessor: it evaluates a DNS record snapshot and
emits a POSITIVE evidence item for each weakness — including absences — so a finding is a per-evidence
deterministic inference. A clean domain yields evidence but no finding; a malformed snapshot fails
closed. It opens no socket and needs no external dependency.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.providers.dns_posture_provider import DnsPostureProvider

_CLEAN = {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "caa": ["0 issue \"le\""],
          "dnssec": True, "mx": ["10 mail.example.com"]}


def _job(snapshot, targets=("example.com",)):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="dns_posture",
        scope=EffectiveScope(targets=tuple(targets), ports=(), protocols=(),
                             network_allowed=False, read_only=True),
        settings={"snapshot": snapshot},
    )


def _kinds(snapshot, host="example.com"):
    ev = list(DnsPostureProvider().execute(_job({host: snapshot}, (host,))))
    return [e.kind for e in ev]


def test_capabilities_are_passive_non_network_no_approval():
    caps = DnsPostureProvider().capabilities
    assert caps.network is False and caps.active is False and caps.destructive is False
    assert caps.requires_authorization is True and caps.requires_human_approval is False


def test_scope_for_this_tool_is_network_disabled():
    from guardian_core.tool import derive_effective_scope
    scope = derive_effective_scope(["example.com"], ["example.com"],
                                   DnsPostureProvider().capabilities, None)
    assert scope.network_allowed is False


def test_clean_domain_is_evidence_only_no_finding():
    ev = list(DnsPostureProvider().execute(_job({"example.com": _CLEAN})))
    assert [e.kind for e in ev] == ["dns_records"]              # only chain-of-custody evidence
    assert ev[0].data["status"] == "observed"
    assert all(DnsPostureProvider().normalize(e) is None for e in ev)


def test_spf_missing_without_mx():
    d = {**_CLEAN, "mx": []}
    del d["spf"]
    assert "dns_spf_missing" in _kinds(d) and "dns_mx_without_spf" not in _kinds(d)


def test_mx_without_spf_supersedes_generic_missing():
    d = {**_CLEAN}
    del d["spf"]                                                 # has MX, no SPF
    kinds = _kinds(d)
    assert "dns_mx_without_spf" in kinds and "dns_spf_missing" not in kinds


def test_spf_permissive_all():
    assert "dns_spf_weak" in _kinds({**_CLEAN, "spf": "v=spf1 +all"})


def test_dmarc_missing_and_monitor_only():
    d = {**_CLEAN}
    del d["dmarc"]
    assert "dns_dmarc_missing" in _kinds(d)
    assert "dns_dmarc_monitor_only" in _kinds({**_CLEAN, "dmarc": "v=DMARC1; p=none; rua=x"})


def test_caa_and_dnssec_missing():
    assert "dns_caa_missing" in _kinds({**_CLEAN, "caa": []})
    assert "dns_dnssec_missing" in _kinds({**_CLEAN, "dnssec": False})


def test_malformed_snapshot_fails_closed():
    ev = list(DnsPostureProvider().execute(_job({"example.com": "garbage"})))
    assert len(ev) == 1 and ev[0].kind == "dns_records"
    assert ev[0].data["status"] == "failed"
    assert ev[0].data["reason"] == "malformed_or_missing_snapshot"
    assert DnsPostureProvider().normalize(ev[0]) is None         # no finding from a failed capture


def test_normalize_maps_issue_to_finding_and_ignores_records():
    d = {**_CLEAN, "caa": []}
    ev = list(DnsPostureProvider().execute(_job({"example.com": d})))
    issue = next(e for e in ev if e.kind == "dns_caa_missing")
    raw = DnsPostureProvider().normalize(issue)
    assert raw is not None and raw.engine == EngineKey.DNS_POSTURE
    assert raw.location["rule"] == "dns-caa-missing" and raw.base_severity.value == "low"
    records = next(e for e in ev if e.kind == "dns_records")
    assert DnsPostureProvider().normalize(records) is None


def test_execution_is_deterministic():
    d = {"example.com": {**_CLEAN, "spf": "v=spf1 +all", "caa": []}}
    a = [(e.target, e.kind) for e in DnsPostureProvider().execute(_job(d))]
    b = [(e.target, e.kind) for e in DnsPostureProvider().execute(_job(d))]
    assert a == b
