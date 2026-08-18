"""Findings against control frameworks (WP-F4).

A compliance report is the artifact a customer hands to an auditor, a board, or a prospect's
security team, which makes the way it can be wrong more consequential than any other output here.
There is one failure mode that matters more than every other combined, and the whole module is
arranged around avoiding it:

**A control with no findings is not a passing control.** It is a passing control only if something
actually looked. If no engine capable of assessing it ran — no cloud collector for the encryption
controls, no dynamic scan for the input-validation ones — then the honest status is `not_assessed`,
and reporting it as `passing` is manufacturing an assurance nobody earned. That is the difference
between a compliance feature and a compliance liability.

So every control declares which engines can speak to it, and the assessment takes the set of engines
that actually completed. Three statuses, not two:

* `failing`   — a finding maps to this control;
* `passing`   — an engine that can assess it ran, completed, and reported nothing against it;
* `not_assessed` — nothing that can assess it ran, or what ran did not complete.

Mappings are deterministic (CWE first, then category), auditable, and small enough to review. This
is not a certification: Guardian can say "the technical control was observed to fail here", never
"you are SOC 2 compliant", and the module's own vocabulary keeps that distinction.
"""

from __future__ import annotations

from dataclasses import dataclass

PASSING = "passing"
FAILING = "failing"
NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class Control:
    """One control, and what could possibly tell us about it."""

    id: str
    framework: str
    title: str
    description: str
    # Engines whose output can speak to this control. Empty means nothing Guardian runs can, and
    # the control is then permanently `not_assessed` — which is still worth printing, because a
    # reader deserves to know what the tool does not cover.
    engines: frozenset[str] = frozenset()
    cwes: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    rules: frozenset[str] = frozenset()


def _c(control_id: str, framework: str, title: str, description: str, *, engines=(), cwes=(),
       categories=(), rules=()) -> Control:  # noqa: ANN001
    return Control(id=control_id, framework=framework, title=title, description=description,
                   engines=frozenset(engines), cwes=frozenset(cwes),
                   categories=frozenset(categories), rules=frozenset(rules))


# ── SOC 2 (Trust Services Criteria, common criteria) ──────────────────────────────────────────────
_SOC2 = [
    _c("CC6.1", "soc2", "Logical access controls",
       "Access to systems and data is restricted to authorized users.",
       engines=("dast", "api", "cspm", "k8s", "iac"),
       cwes=("CWE-284", "CWE-285", "CWE-306", "CWE-287", "CWE-639", "CWE-732", "CWE-269"),
       categories=("api-authorization",)),
    _c("CC6.6", "soc2", "Boundary protection",
       "The system restricts access from outside its boundaries.",
       engines=("nmap", "discovery", "cspm", "k8s", "dast"),
       cwes=("CWE-284", "CWE-668"),
       rules=("sg-admin-port-open", "sg-all-ports-open", "rds-public", "host-network",
              "service-exposed", "s3-public-policy", "s3-public-acl")),
    _c("CC6.7", "soc2", "Transmission of data",
       "Data in transit is protected.",
       engines=("dast", "api", "discovery", "k8s"),
       cwes=("CWE-319",), rules=("ingress-no-tls",)),
    _c("CC6.8", "soc2", "Malicious software and unauthorized change",
       "Unauthorized or malicious software is prevented or detected.",
       engines=("sca", "container", "secrets"),
       cwes=("CWE-1104", "CWE-494"), categories=("vuln-dep",)),
    _c("CC7.1", "soc2", "Vulnerability detection",
       "Vulnerabilities are identified and evaluated.",
       engines=("sca", "sast", "dast", "container", "iac", "service_cve"),
       categories=("vuln-dep", "insecure-code", "injection")),
    _c("CC7.2", "soc2", "Monitoring and logging",
       "System activity is monitored and anomalies are detected.",
       engines=("cspm", "k8s"),
       cwes=("CWE-778",), rules=("cloudtrail-missing", "cloudtrail-single-region",
                                 "cloudtrail-no-validation")),
    _c("CC6.3", "soc2", "Least privilege",
       "Access rights are granted on a least-privilege basis.",
       engines=("cspm", "k8s", "iac"),
       cwes=("CWE-269", "CWE-250"),
       rules=("iam-admin", "iam-escalation", "rbac-cluster-admin", "rbac-wildcard",
              "privileged", "rbac-escalation")),
    _c("CC6.2", "soc2", "Credential management",
       "Credentials are issued, protected, and revoked appropriately.",
       engines=("secrets", "cspm", "container", "k8s"),
       cwes=("CWE-798", "CWE-522", "CWE-256", "CWE-308"),
       categories=("secret",)),
]

# ── ISO/IEC 27001:2022 Annex A ────────────────────────────────────────────────────────────────────
_ISO = [
    _c("A.5.15", "iso27001", "Access control",
       "Rules for physical and logical access are established and implemented.",
       engines=("dast", "api", "cspm", "k8s"),
       cwes=("CWE-284", "CWE-285", "CWE-306", "CWE-639"), categories=("api-authorization",)),
    _c("A.5.17", "iso27001", "Authentication information",
       "Allocation and management of authentication information is controlled.",
       engines=("secrets", "cspm", "container"),
       cwes=("CWE-798", "CWE-522", "CWE-256", "CWE-308"), categories=("secret",)),
    _c("A.8.8", "iso27001", "Management of technical vulnerabilities",
       "Information about technical vulnerabilities is obtained and acted on.",
       engines=("sca", "sast", "dast", "container", "service_cve"),
       categories=("vuln-dep", "insecure-code", "injection")),
    _c("A.8.9", "iso27001", "Configuration management",
       "Configurations of hardware, software and networks are established and monitored.",
       engines=("iac", "k8s", "cspm", "container"),
       categories=("cloud-misconfig", "k8s-misconfig", "iac-misconfig", "container-misconfig")),
    _c("A.8.24", "iso27001", "Use of cryptography",
       "Rules for the effective use of cryptography are defined and implemented.",
       engines=("dast", "cspm", "k8s", "iac"),
       cwes=("CWE-319", "CWE-311", "CWE-327", "CWE-320"),
       rules=("s3-unencrypted", "rds-unencrypted", "kms-no-rotation", "ingress-no-tls")),
    _c("A.8.28", "iso27001", "Secure coding",
       "Secure coding principles are applied to software development.",
       engines=("sast", "sca"),
       cwes=("CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-94", "CWE-502"),
       categories=("insecure-code", "injection")),
    _c("A.8.16", "iso27001", "Monitoring activities",
       "Networks, systems and applications are monitored for anomalous behaviour.",
       engines=("cspm",), cwes=("CWE-778",)),
]

# ── PCI DSS v4.0 (the requirements a technical scan can speak to) ─────────────────────────────────
_PCI = [
    _c("1.3", "pci-dss", "Restrict network access to the cardholder data environment",
       "Network access to and from the CDE is restricted.",
       engines=("nmap", "discovery", "cspm", "k8s"),
       rules=("sg-admin-port-open", "sg-all-ports-open", "rds-public", "service-exposed",
              "host-network")),
    _c("2.2", "pci-dss", "Secure configuration",
       "System components are configured securely and default accounts are managed.",
       engines=("iac", "k8s", "cspm", "container"),
       categories=("cloud-misconfig", "k8s-misconfig", "iac-misconfig", "container-misconfig",
                   "web-misconfig")),
    _c("3.5", "pci-dss", "Protection of stored account data",
       "Stored account data is rendered unreadable.",
       engines=("cspm", "k8s", "iac"),
       cwes=("CWE-311", "CWE-312"), rules=("s3-unencrypted", "rds-unencrypted")),
    _c("4.2", "pci-dss", "Protection of data in transit",
       "Cardholder data is protected with strong cryptography during transmission.",
       engines=("dast", "api", "discovery"), cwes=("CWE-319",)),
    _c("6.2", "pci-dss", "Bespoke software is developed securely",
       "Software is developed based on secure coding practices.",
       engines=("sast", "sca"),
       cwes=("CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-94"),
       categories=("insecure-code", "injection")),
    _c("6.3", "pci-dss", "Security vulnerabilities are identified and addressed",
       "Vulnerabilities are identified, risk-ranked and remediated.",
       engines=("sca", "container", "service_cve", "dast"), categories=("vuln-dep",)),
    _c("8.3", "pci-dss", "Strong authentication",
       "Strong authentication for users and administrators is established.",
       engines=("cspm", "api", "dast"),
       cwes=("CWE-308", "CWE-306", "CWE-287"),
       rules=("iam-root-no-mfa", "iam-user-no-mfa", "iam-root-access-key")),
    _c("10.2", "pci-dss", "Audit logs",
       "Audit logs are implemented to support anomaly detection.",
       engines=("cspm",), cwes=("CWE-778",),
       rules=("cloudtrail-missing", "cloudtrail-no-validation")),
]

CONTROLS: tuple[Control, ...] = tuple(_SOC2 + _ISO + _PCI)
FRAMEWORKS: tuple[str, ...] = ("soc2", "iso27001", "pci-dss")


@dataclass(frozen=True)
class FindingRef:
    """The finding fields a mapping needs, and nothing else."""

    id: str
    severity: str
    title: str
    category: str = ""
    cwe_id: str | None = None
    rule: str = ""
    status: str = "open"


@dataclass
class ControlResult:
    control: Control
    status: str
    findings: tuple[FindingRef, ...] = ()
    # Why the control is in this state, in a sentence a reader can act on.
    rationale: str = ""


@dataclass
class Assessment:
    framework: str
    results: tuple[ControlResult, ...] = ()
    engines_assessed: tuple[str, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        out = {PASSING: 0, FAILING: 0, NOT_ASSESSED: 0}
        for result in self.results:
            out[result.status] = out.get(result.status, 0) + 1
        return out

    @property
    def coverage(self) -> int:
        """Percentage of controls something actually looked at.

        Printed next to every score, because a 100% pass rate over 20% coverage is the number that
        misleads an auditor, and it is only misleading when the denominator is hidden.
        """
        if not self.results:
            return 0
        assessed = sum(1 for r in self.results if r.status != NOT_ASSESSED)
        return round(assessed * 100 / len(self.results))


def controls_for(framework: str) -> tuple[Control, ...]:
    return tuple(c for c in CONTROLS if c.framework == framework)


def maps_to(control: Control, finding: FindingRef) -> bool:
    """Whether this finding is evidence against this control.

    CWE first because it is the identifier every engine sets and a reader can check; then the
    engine's own rule id, which is more specific than a category; then the category as a fallback.
    """
    if finding.cwe_id and finding.cwe_id in control.cwes:
        return True
    if finding.rule and finding.rule in control.rules:
        return True
    return bool(finding.category and finding.category in control.categories)


def assess(
    framework: str,
    findings: list[FindingRef],
    *,
    engines_completed: set[str] | frozenset[str],
) -> Assessment:
    """Assess one framework against the findings, given which engines actually completed.

    `engines_completed` is the load-bearing argument. A control whose engines did not run is
    `not_assessed`, never `passing`: the absence of a finding from a scanner that never looked is
    not evidence of a control working, and a report that says otherwise is worse than no report.
    """
    completed = frozenset(engines_completed)
    open_findings = [f for f in findings if f.status not in ("false_positive", "resolved")]

    results: list[ControlResult] = []
    for control in controls_for(framework):
        matched = tuple(f for f in open_findings if maps_to(control, f))
        if matched:
            worst = min(matched, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
            results.append(ControlResult(
                control=control, status=FAILING, findings=matched,
                rationale=(f"{len(matched)} open finding(s) map to this control; the most severe "
                           f"is {worst.severity} — {worst.title}"),
            ))
            continue

        capable = control.engines & completed
        if capable:
            results.append(ControlResult(
                control=control, status=PASSING, findings=(),
                rationale=("assessed by " + ", ".join(sorted(capable))
                           + "; no finding maps to this control"),
            ))
        else:
            missing = sorted(control.engines - completed)
            results.append(ControlResult(
                control=control, status=NOT_ASSESSED, findings=(),
                rationale=("not assessed: "
                           + (f"no engine that can evaluate it ran ({', '.join(missing)} would)"
                              if missing else
                              "nothing Guardian runs can evaluate this control")),
            ))

    results.sort(key=lambda r: (_STATUS_ORDER[r.status], r.control.id))
    return Assessment(framework=framework, results=tuple(results),
                      engines_assessed=tuple(sorted(completed)))


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STATUS_ORDER = {FAILING: 0, NOT_ASSESSED: 1, PASSING: 2}


def summarize(assessments: list[Assessment]) -> dict:
    """A shape a report or an API can render directly."""
    return {
        "frameworks": [
            {
                "framework": a.framework,
                "counts": a.counts,
                "coverage": a.coverage,
                "engines_assessed": list(a.engines_assessed),
                "controls": [
                    {
                        "id": r.control.id,
                        "title": r.control.title,
                        "description": r.control.description,
                        "status": r.status,
                        "rationale": r.rationale,
                        "findings": [
                            {"id": f.id, "title": f.title, "severity": f.severity}
                            for f in r.findings
                        ],
                    }
                    for r in a.results
                ],
            }
            for a in assessments
        ],
        # Repeated at the top level because it is the number that stops a reader drawing the wrong
        # conclusion from a high pass rate.
        "overall_coverage": (
            round(sum(a.coverage for a in assessments) / len(assessments)) if assessments else 0
        ),
        "disclaimer": (
            "Guardian reports whether a technical control was observed to fail. It does not "
            "certify compliance: controls that are procedural, or that no engine here can "
            "evaluate, are reported as not assessed rather than as passing."
        ),
    }


__all__ = [
    "CONTROLS",
    "FAILING",
    "FRAMEWORKS",
    "NOT_ASSESSED",
    "PASSING",
    "Assessment",
    "Control",
    "ControlResult",
    "FindingRef",
    "assess",
    "controls_for",
    "maps_to",
    "summarize",
]
