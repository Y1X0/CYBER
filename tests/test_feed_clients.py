"""Feed clients parse real provider payloads, and fail loudly (WP-C1).

The behaviour these tests protect is the one WP-C1 reversed. Every client used to swallow errors and
return an empty result, on the reasoning that a feed outage should never break a scan. It reads as
defensive and is not: an empty feed result is indistinguishable from a clean scan, so an outage
became "no vulnerabilities found" — a false negative nothing downstream could detect, in a product
whose entire job is not producing those.

Failures now raise. Whether to degrade is the *caller's* decision, made explicitly and logged, and
`OsvVulnMatcher` is where that decision lives.

Payload shapes below are the real ones each provider publishes, so a contract change fails here
rather than in a customer's scan.
"""

from __future__ import annotations

import gzip

import httpx
import pytest
from guardian_clients.feeds import (
    EpssClient,
    FeedError,
    KevClient,
    NvdClient,
    OsvClient,
    parse_cve,
    parse_epss_csv,
    parse_kev,
    parse_osv_record,
    parse_page,
)
from guardian_clients.feeds.nvd import cpe_configurations, parse_cpe, windows


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _boom(_request):
    return httpx.Response(500)


# ── failures are raised, never returned as emptiness ──────────────────────────────────────────────
def test_osv_query_raises_rather_than_reporting_a_clean_package():
    with pytest.raises(FeedError, match="OSV query failed"):
        OsvClient(client=_client(_boom)).query_package(name="x", version="1", ecosystem="pypi")


def test_epss_raises_rather_than_reporting_no_score():
    with pytest.raises(FeedError, match="EPSS request failed"):
        EpssClient(client=_client(_boom)).score_for("CVE-2020-14343")


def test_kev_raises_rather_than_reporting_nothing_is_exploited():
    with pytest.raises(FeedError):
        KevClient(client=_client(_boom)).fetch_kev_ids()


def test_nvd_raises_rather_than_reporting_no_cves():
    with pytest.raises(FeedError, match="NVD request failed"):
        NvdClient(client=_client(_boom)).fetch_page()


def test_a_payload_missing_its_key_is_a_contract_change_not_an_empty_feed():
    with pytest.raises(FeedError, match="contract changed"):
        parse_kev({"somethingElse": []})
    with pytest.raises(FeedError, match="API contract changed"):
        parse_page({"resultsPerPage": 0})


# ── OSV ───────────────────────────────────────────────────────────────────────────────────────────
def test_osv_query_normalizes_a_vulnerability():
    def handler(_request):
        return httpx.Response(200, json={"vulns": [{
            "id": "GHSA-abcd", "aliases": ["CVE-2020-14343"], "summary": "PyYAML RCE",
            "references": [{"url": "https://example/adv"}],
        }]})

    out = OsvClient(client=_client(handler)).query_package(
        name="pyyaml", version="5.3", ecosystem="pypi"
    )
    assert len(out) == 1
    assert out[0].external_id == "CVE-2020-14343"
    assert out[0].source == "osv"


OSV_RECORD = {
    "id": "GHSA-8r8j-xvfj-36f9",
    "aliases": ["CVE-2023-45803"],
    "summary": "urllib3 leaks request body on redirect",
    "details": "When a redirect changes the method ...",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "database_specific": {"cwe_ids": ["CWE-200"]},
    "published": "2023-10-17T20:15:00Z",
    "modified": "2024-02-16T08:22:15.552Z",
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "urllib3"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.26.18"}]}],
        "versions": ["1.26.0", "1.26.17"],
    }],
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-8r8j"}],
}


def test_a_bulk_osv_record_keeps_its_ranges():
    """The query endpoint answers about one version. A bulk record carries the ranges themselves,
    so the knowledge base can answer for a version it was never asked about."""
    record = parse_osv_record(OSV_RECORD)
    assert record.external_id == "CVE-2023-45803"
    assert record.cwe_ids == ["CWE-200"]
    assert record.cvss_vector.startswith("CVSS:3.1/")
    assert record.affected[0]["package"] == "urllib3"
    assert record.affected[0]["ranges"][0]["events"][1]["fixed"] == "1.26.18"
    assert record.published_at is not None
    assert record.modified_at is not None


def test_an_osv_record_without_a_cve_alias_keeps_its_own_id():
    record = parse_osv_record({"id": "GHSA-only", "summary": "x"})
    assert record.external_id == "GHSA-only"


def test_osv_prefers_a_v3_vector_over_a_v2_one():
    """The arithmetic differs by version, so taking whichever comes first mis-scores the finding."""
    record = parse_osv_record({
        "id": "X", "severity": [
            {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ],
    })
    assert record.cvss_vector.startswith("CVSS:3.1/")


# ── NVD ───────────────────────────────────────────────────────────────────────────────────────────
NVD_CVE = {
    "id": "CVE-2023-38408",
    "published": "2023-07-20T03:15:11.987",
    "lastModified": "2024-01-31T16:15:08.363",
    "descriptions": [
        {"lang": "es", "value": "El reenvio ..."},
        {"lang": "en", "value": "The PKCS#11 feature in ssh-agent in OpenSSH allows RCE."},
    ],
    "metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0,
                                                          "vectorString": "AV:N/AC:L/Au:N/C:P"}}],
        "cvssMetricV31": [{
            "type": "Primary",
            "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }],
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-428"}]}],
    "references": [{"url": "https://www.openssh.com/txt/release-9.3p2"}],
    "configurations": [{
        "nodes": [{
            "operator": "OR", "negate": False,
            "cpeMatch": [
                {"vulnerable": True,
                 "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "5.5", "versionEndExcluding": "9.3.2"},
                {"vulnerable": False,
                 "criteria": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*"},
            ],
        }],
    }],
}


def test_an_nvd_record_is_normalized():
    record = parse_cve(NVD_CVE)
    assert record.external_id == "CVE-2023-38408"
    assert record.source == "nvd"
    assert "OpenSSH" in record.summary
    assert record.cwe_ids == ["CWE-428"]
    assert record.published_at is not None


def test_nvd_prefers_v31_over_v2():
    """A v2 5.0 and a v3 5.0 are not the same severity. Taking the first key mis-ranks findings."""
    record = parse_cve(NVD_CVE)
    assert record.cvss_base == 9.8
    assert record.severity == "critical"
    assert record.cvss_vector.startswith("CVSS:3.1/")


def test_nvd_cpe_applicability_is_flattened_with_its_bounds():
    """This is the field that makes a service version matchable at all — nothing else has it."""
    record = parse_cve(NVD_CVE)
    assert len(record.cpe_configurations) == 1
    row = record.cpe_configurations[0]
    assert row["vendor"] == "openbsd"
    assert row["product"] == "openssh"
    assert row["version_start_including"] == "5.5"
    assert row["version_end_excluding"] == "9.3.2"


def test_a_non_vulnerable_cpe_entry_is_not_treated_as_affected():
    """The `vulnerable: false` entry names the OS the vulnerable product runs on. Counting it would
    attribute an OpenSSH RCE to Ubuntu."""
    rows = cpe_configurations(NVD_CVE["configurations"])
    assert all("ubuntu" not in row["product"] for row in rows)


def test_a_page_reports_whether_it_is_exhausted():
    page = parse_page({"totalResults": 5000, "startIndex": 0,
                       "vulnerabilities": [{"cve": NVD_CVE}]})
    assert page.total == 5000
    assert page.exhausted is False
    assert page.next_index == 1

    last = parse_page({"totalResults": 1, "startIndex": 0, "vulnerabilities": [{"cve": NVD_CVE}]})
    assert last.exhausted is True


def test_a_rejected_entry_does_not_break_the_page():
    page = parse_page({"totalResults": 2, "vulnerabilities": [
        {"cve": {"id": "not-a-cve"}}, {"cve": NVD_CVE},
    ]})
    assert [r.external_id for r in page.records] == ["CVE-2023-38408"]


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        ("cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*", ("openbsd", "openssh", "8.9")),
        ("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", ("nginx", "nginx", "*")),
        ("cpe:/a:openbsd:openssh:8.9", None),
        ("not a cpe", None),
    ],
)
def test_cpe_parsing(criteria, expected):
    assert parse_cpe(criteria) == expected


def test_nvd_windows_are_split_to_what_the_api_accepts():
    """NVD refuses a lastModified window wider than 120 days. A first sync asks for two years, and
    a refused request must not be readable as "nothing changed"."""
    import datetime as dt

    since = dt.datetime(2022, 1, 1, tzinfo=dt.UTC)
    until = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
    spans = windows(since, until)
    assert len(spans) > 6
    assert all((end - start).days <= 110 for start, end in spans)
    assert spans[0][0] == since
    assert spans[-1][1] == until
    assert windows(until, since) == []


# ── KEV ───────────────────────────────────────────────────────────────────────────────────────────
KEV_PAYLOAD = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 RCE", "dateAdded": "2021-12-10",
         "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known",
         "requiredAction": "Apply updates."},
        {"cveID": "CVE-2023-4863", "vendorProject": "Google", "product": "Chrome",
         "vulnerabilityName": "WebP heap overflow", "dateAdded": "2023-09-13",
         "knownRansomwareCampaignUse": "Unknown"},
    ],
}


def test_kev_records_carry_more_than_an_id():
    records = {r.cve_id: r for r in parse_kev(KEV_PAYLOAD)}
    log4shell = records["CVE-2021-44228"]
    assert log4shell.ransomware is True
    assert log4shell.due_date is not None
    assert log4shell.product == "Log4j2"
    assert "Apply updates" in log4shell.required_action


def test_the_ransomware_flag_is_read_as_a_word_not_as_truthiness():
    """The field is the string "Known"/"Unknown". Any-truthy-value would mark every entry."""
    records = {r.cve_id: r for r in parse_kev(KEV_PAYLOAD)}
    assert records["CVE-2023-4863"].ransomware is False


def test_kev_ids_still_work_for_callers_that_only_need_the_flag():
    def handler(_request):
        return httpx.Response(200, json=KEV_PAYLOAD)

    assert KevClient(client=_client(handler)).fetch_kev_ids() == {
        "CVE-2021-44228", "CVE-2023-4863"
    }


def test_an_empty_kev_catalogue_is_refused():
    with pytest.raises(FeedError, match="no usable records"):
        parse_kev({"vulnerabilities": []})


# ── EPSS ──────────────────────────────────────────────────────────────────────────────────────────
EPSS_CSV = (
    "#model_version:v2023.03.01,score_date:2024-05-01T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97556,0.99981\n"
    "CVE-2023-4863,0.00427,0.71234\n"
    "not-a-cve,0.5,0.1\n"
)


def test_the_bulk_csv_skips_the_model_comment_line():
    """The file opens with a `#model_version` line. A plain DictReader reads it as the header and
    every row comes back keyed wrongly — silently, with no error and no scores."""
    scores = parse_epss_csv(EPSS_CSV.encode())
    assert scores["CVE-2021-44228"] == pytest.approx(0.97556)
    assert scores["CVE-2023-4863"] == pytest.approx(0.00427)
    assert "not-a-cve" not in scores


def test_the_bulk_csv_is_read_gzipped():
    scores = parse_epss_csv(gzip.compress(EPSS_CSV.encode()))
    assert len(scores) == 2


def test_a_changed_csv_header_is_an_error_not_zero_scores():
    with pytest.raises(FeedError, match="header is not what was expected"):
        parse_epss_csv(b"identifier,probability\nCVE-1,0.5\n")


def test_an_empty_score_set_is_refused():
    with pytest.raises(FeedError, match="zero scores"):
        parse_epss_csv(b"cve,epss,percentile\n")


def test_epss_single_lookup_still_parses():
    def handler(_request):
        return httpx.Response(200, json={"data": [{"cve": "CVE-2020-14343", "epss": "0.42"}]})

    assert EpssClient(client=_client(handler)).score_for("CVE-2020-14343") == 0.42


def test_the_same_cpe_under_several_nodes_is_recorded_once():
    """NVD legitimately repeats a product across nodes. A duplicated applicability row would
    double-count in a later match and bloat the stored document."""
    duplicated = [{
        "nodes": [
            {"cpeMatch": [{"vulnerable": True,
                           "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                           "versionEndExcluding": "9.3.2"}]},
            {"cpeMatch": [{"vulnerable": True,
                           "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                           "versionEndExcluding": "9.3.2"}]},
        ],
    }]
    assert len(cpe_configurations(duplicated)) == 1


def test_different_bounds_on_the_same_product_are_kept_apart():
    both = [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "9.3.2"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "8.0"},
    ]}]}]
    assert len(cpe_configurations(both)) == 2
