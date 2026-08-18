"""CSPM engine — cloud posture from a read-only collector export (WP-D8).

Takes the AWS API's own response shapes (`Buckets`, `SecurityGroups`, `UserDetailList`,
`DBInstances`, `trailList`, the credential report) and evaluates them with the rules in
`guardian_scanner.cloud`. A collector is therefore a script that calls read-only APIs and writes the
responses down — no bespoke schema, and no judgement made before the data reaches Guardian.

The previous engine consumed a snapshot Guardian invented, in which the interesting question had
already been answered by whoever produced it: `{"storage": [{"public": true}]}`. That format is
still accepted, because assets and tests carry it, but it is now clearly the legacy path, and it
cannot express what the real one can — a bucket policy, an ACL and a public access block that
disagree; a security group opening a port *range*; an IAM policy document.

Active posture engine: `requires_authorization=True` (safe-scanning gate, doc 06 §4). It reads
nothing itself — the credential stays with the collector — but the gate governs whether the account
may be assessed at all.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.cloud.aws import (
    Issue,
    iam_issues,
    logging_issues,
    rds_issues,
    s3_issues,
    security_group_issues,
)
from guardian_scanner.engines.base import EngineHealth, ScanContext

log = get_logger("guardian.cspm")

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_SENSITIVE_PORTS = {22, 3389, 0}
_WILDCARD_ACTIONS = {"*", "*:*"}


class CloudSnapshotError(RuntimeError):
    """The snapshot could not be read.

    Raised rather than returning nothing: an unparseable export and a clean account are the same
    empty list to a customer, and only one of them means the account was assessed.
    """


class CspmEngine:
    key = EngineKey.CSPM
    name = "Guardian CSPM (AWS config audit)"
    version = "0.2.0"
    requires_authorization = True
    wants_secrets = True  # consumes cloud credentials from the encrypted secret_ref

    def supports(self, asset_kind: str) -> bool:
        return asset_kind == "cloud_account"

    def health(self) -> EngineHealth:
        return EngineHealth(
            ok=True,
            detail="evaluates AWS API responses (S3, EC2 security groups, IAM policy documents, "
                   "RDS, CloudTrail, KMS); collector supplies the export",
        )

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        snapshot = self._load(ctx)
        if snapshot is None:
            return []
        findings: list[RawFinding] = []

        resources = snapshot.get("resources")
        if isinstance(resources, dict):
            findings.extend(self._aws(resources))
        else:
            # Legacy hand-written snapshot. Kept working; it cannot express a policy document, an
            # ACL, or a port range, which is why the real path exists.
            findings.extend(self._legacy(snapshot))

        log.info("cspm_scan_complete", provider=snapshot.get("provider", "aws"),
                 findings=len(findings), shape="aws-api" if resources else "legacy")
        return findings

    # ── input ────────────────────────────────────────────────────────────────────────────────────
    def _load(self, ctx: ScanContext) -> dict | None:
        snapshot = (ctx.asset_config or {}).get("cloud_config")
        if snapshot:
            if isinstance(snapshot, str):
                return self._parse(snapshot)
            return snapshot
        if ctx.inline_content:
            return self._parse(ctx.inline_content)
        return None

    def _parse(self, text: str) -> dict:
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            # The previous engine returned None here, so a truncated or malformed export produced
            # a clean report.
            raise CloudSnapshotError(f"the cloud snapshot is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise CloudSnapshotError("the cloud snapshot must be a JSON object")
        return parsed

    # ── the real path ────────────────────────────────────────────────────────────────────────────
    def _aws(self, resources: dict) -> Iterable[RawFinding]:
        for bucket in resources.get("Buckets") or resources.get("s3") or []:
            for issue in s3_issues(bucket):
                yield self._finding(issue, "s3")

        for group in resources.get("SecurityGroups") or []:
            for issue in security_group_issues(group):
                yield self._finding(issue, "ec2")

        iam = resources.get("iam") or {}
        if iam:
            for issue in iam_issues(iam):
                yield self._finding(issue, "iam")

        for instance in resources.get("DBInstances") or []:
            for issue in rds_issues(instance):
                yield self._finding(issue, "rds")

        account = {k: v for k, v in resources.items() if k in ("trailList", "CloudTrail", "Keys",
                                                               "KMSKeys")}
        if account:
            for issue in logging_issues(account):
                yield self._finding(issue, "account")

    def _finding(self, issue: Issue, service: str) -> RawFinding:
        return RawFinding(
            engine=EngineKey.CSPM,
            title=issue.title,
            category="cloud-misconfig",
            description=f"{issue.detail}\n\nRemediation: {issue.remediation}",
            base_severity=_SEVERITY.get(issue.severity, Severity.MEDIUM),
            confidence="high",
            cwe_id=issue.cwe,
            location={"resource": issue.resource, "service": service, "rule": issue.rule,
                      "cis": issue.control},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG,
                summary=f"{service}: {issue.resource}",
                detail={"finding": issue.title, "cis": issue.control, **issue.evidence},
            ).to_dict(),
            references={"cis": issue.control},
        )

    # ── legacy snapshot ──────────────────────────────────────────────────────────────────────────
    def _legacy(self, snapshot: dict) -> Iterable[RawFinding]:
        provider = snapshot.get("provider", "cloud")
        for bucket in snapshot.get("storage", []) or []:
            name = bucket.get("name", "storage")
            if bucket.get("public"):
                yield self._legacy_finding(
                    f"Publicly accessible storage: {name}", Severity.HIGH, "CWE-732",
                    f"CIS {provider} Storage — public access", name,
                    "Storage bucket/container is publicly readable.")
            if bucket.get("encrypted") is False:
                yield self._legacy_finding(
                    f"Unencrypted storage at rest: {name}", Severity.MEDIUM, "CWE-311",
                    f"CIS {provider} Storage — encryption at rest", name,
                    "Storage is not encrypted at rest.")

        for user in (snapshot.get("iam", {}) or {}).get("users", []) or []:
            name = user.get("name", "user")
            if user.get("mfa") is False:
                yield self._legacy_finding(
                    f"IAM principal without MFA: {name}", Severity.MEDIUM, "CWE-308",
                    f"CIS {provider} IAM — MFA for users", name,
                    "Console/API principal has no MFA enabled.")
            if any(p in _WILDCARD_ACTIONS for p in user.get("policies", []) or []):
                yield self._legacy_finding(
                    f"Over-permissioned IAM principal: {name}", Severity.HIGH, "CWE-269",
                    f"CIS {provider} IAM — least privilege", name,
                    "Principal is attached to a wildcard (*) policy.")

        for group in snapshot.get("network", []) or []:
            name = group.get("name", "security-group")
            for rule in group.get("ingress", []) or []:
                if rule.get("cidr") in {"0.0.0.0/0", "::/0"} and \
                        rule.get("port") in _SENSITIVE_PORTS:
                    yield self._legacy_finding(
                        f"Network exposed to the internet: {name}:{rule.get('port')}",
                        Severity.HIGH, "CWE-284",
                        f"CIS {provider} Networking — restrict admin ports", name,
                        f"Ingress {rule.get('cidr')} → port {rule.get('port')} is open.")

        logging_config = snapshot.get("logging", {}) or {}
        enabled = logging_config.get("audit_enabled",
                                     logging_config.get("cloudtrail_enabled", True))
        if enabled is False:
            yield self._legacy_finding(
                "Audit logging disabled", Severity.MEDIUM, "CWE-778",
                f"CIS {provider} Logging — enable audit trail", "account",
                "Account-level audit logging is disabled.")

    def _legacy_finding(self, title, sev, cwe, cis, resource, detail) -> RawFinding:  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.CSPM,
            title=title,
            category="cloud-misconfig",
            description=detail,
            base_severity=sev,
            confidence="high",
            cwe_id=cwe,
            location={"resource": resource, "cis": cis},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG, summary=resource, detail={"finding": detail, "cis": cis}
            ).to_dict(),
            references={"cis": cis},
        )
