"""Offline knowledge-base seed: a CWE subset + sample vulnerabilities.

Lets the SCA engine and Vulnerability Intelligence features work with zero network access (dev, CI,
demos). Production replaces/augments this via the feed-sync task (NVD/OSV/GHSA/EPSS/KEV).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from guardian_db.models import KbEntry, Vulnerability, Weakness

# CWE Top-relevant subset used by the builtin engines.
_CWE_SEED = [
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)"),
    ("CWE-89", "SQL Injection"),
    ("CWE-78", "OS Command Injection"),
    (
        "CWE-95",
        "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
    ),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    ("CWE-295", "Improper Certificate Validation"),
    ("CWE-502", "Deserialization of Untrusted Data"),
    ("CWE-798", "Use of Hard-coded Credentials"),
]

# Sample advisories with affected package ranges (ecosystem lowercased to match the SCA engine).
_VULN_SEED = [
    {
        "external_id": "CVE-2020-14343",
        "source": "osv",
        "summary": "PyYAML full_load / FullLoader arbitrary code execution via crafted YAML.",
        "cwe_ids": ["CWE-502"],
        "cvss_base": 9.8,
        "epss_score": 0.42,
        "kev": False,
        "affected": [{"ecosystem": "pypi", "package": "pyyaml", "versions": ["5.3", "5.3.1"]}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
    },
    {
        "external_id": "CVE-2019-11324",
        "source": "osv",
        "summary": "urllib3 certificate validation weakness with conflicting configurations.",
        "cwe_ids": ["CWE-295"],
        "cvss_base": 7.5,
        "epss_score": 0.15,
        "kev": False,
        "affected": [{"ecosystem": "pypi", "package": "urllib3", "versions": ["1.24"]}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11324"],
    },
    {
        "external_id": "CVE-2021-23337",
        "source": "osv",
        "summary": "lodash command injection via template.",
        "cwe_ids": ["CWE-78"],
        "cvss_base": 7.2,
        "epss_score": 0.08,
        "kev": True,
        "affected": [{"ecosystem": "npm", "package": "lodash", "versions": ["4.17.20"]}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    },
]

_KB_SEED = [
    {
        "kind": "remediation",
        "title": "Remediating hardcoded secrets",
        "body": "Move secrets to a secrets manager, rotate exposed credentials, and add pre-commit "
        "secret scanning. Never commit credentials to source control.",
        "standards": {"owasp": "A07:2021", "cwe": "CWE-798"},
        "tags": ["secrets", "credentials"],
    },
]


def seed_knowledge_base(session: Session) -> dict[str, int]:
    """Idempotently load the offline KB. Returns counts of newly inserted rows."""
    counts = {"weaknesses": 0, "vulnerabilities": 0, "kb_entries": 0}

    for ext_id, name in _CWE_SEED:
        if not session.query(Weakness).filter(Weakness.external_id == ext_id).first():
            session.add(Weakness(external_id=ext_id, name=name))
            counts["weaknesses"] += 1

    for v in _VULN_SEED:
        if (
            not session.query(Vulnerability)
            .filter(Vulnerability.external_id == v["external_id"])
            .first()
        ):
            session.add(Vulnerability(**v))
            counts["vulnerabilities"] += 1

    for k in _KB_SEED:
        if not session.query(KbEntry).filter(KbEntry.title == k["title"]).first():
            session.add(KbEntry(**k))
            counts["kb_entries"] += 1

    return counts
