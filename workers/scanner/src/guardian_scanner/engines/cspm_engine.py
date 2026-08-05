"""CSPM engine — Cloud Security Posture Management (AWS / Azure / GCP).

Evaluates a **read-only cloud configuration snapshot** against CIS-mapped rules (public storage,
IAM over-permission, open networking, missing encryption, disabled audit logging). The snapshot is
provided via the asset config (`cloud_config`) — a live collector (boto3 / az / gcloud read-only
role) is a pluggable input behind this same engine, so it audits without touching a live account in
tests.

Active posture engine: `requires_authorization=True` (safe-scanning gate, doc 06 §4).
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

_SENSITIVE_PORTS = {22, 3389, 0}  # SSH, RDP, and "all" (0 = every port)
_WILDCARD_ACTIONS = {"*", "*:*"}


class CspmEngine:
    key = EngineKey.CSPM
    name = "Guardian CSPM (AWS/Azure/GCP config audit)"
    version = "0.1.0"
    requires_authorization = True

    def supports(self, asset_kind: str) -> bool:
        return asset_kind == "cloud_account"

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="snapshot evaluation; live collector pluggable")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        snapshot = self._load(ctx)
        if not snapshot:
            return
        provider = snapshot.get("provider", "cloud")
        yield from self._check_storage(snapshot.get("storage", []), provider)
        yield from self._check_iam(snapshot.get("iam", {}), provider)
        yield from self._check_network(snapshot.get("network", []), provider)
        yield from self._check_logging(snapshot.get("logging", {}), provider)

    def _load(self, ctx: ScanContext) -> dict | None:
        snap = ctx.asset_config.get("cloud_config")
        if snap:
            return snap
        if ctx.inline_content:
            try:
                return json.loads(ctx.inline_content)
            except ValueError:
                return None
        return None

    def _finding(self, *, title, sev, cwe, cis, resource, detail) -> RawFinding:  # noqa: ANN001
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

    def _check_storage(self, buckets, provider) -> Iterable[RawFinding]:  # noqa: ANN001
        for b in buckets:
            name = b.get("name", "storage")
            if b.get("public"):
                yield self._finding(
                    title=f"Publicly accessible storage: {name}",
                    sev=Severity.HIGH,
                    cwe="CWE-732",
                    cis=f"CIS {provider} Storage — public access",
                    resource=name,
                    detail="Storage bucket/container is publicly readable.",
                )
            if b.get("encrypted") is False:
                yield self._finding(
                    title=f"Unencrypted storage at rest: {name}",
                    sev=Severity.MEDIUM,
                    cwe="CWE-311",
                    cis=f"CIS {provider} Storage — encryption at rest",
                    resource=name,
                    detail="Storage is not encrypted at rest.",
                )

    def _check_iam(self, iam, provider) -> Iterable[RawFinding]:  # noqa: ANN001
        for user in iam.get("users", []):
            name = user.get("name", "user")
            if user.get("mfa") is False:
                yield self._finding(
                    title=f"IAM principal without MFA: {name}",
                    sev=Severity.MEDIUM,
                    cwe="CWE-308",
                    cis=f"CIS {provider} IAM — MFA for users",
                    resource=name,
                    detail="Console/API principal has no MFA enabled.",
                )
            if any(p in _WILDCARD_ACTIONS for p in user.get("policies", [])):
                yield self._finding(
                    title=f"Over-permissioned IAM principal: {name}",
                    sev=Severity.HIGH,
                    cwe="CWE-269",
                    cis=f"CIS {provider} IAM — least privilege",
                    resource=name,
                    detail="Principal is attached to a wildcard (*) policy.",
                )

    def _check_network(self, groups, provider) -> Iterable[RawFinding]:  # noqa: ANN001
        for g in groups:
            name = g.get("name", "security-group")
            for rule in g.get("ingress", []):
                if (
                    rule.get("cidr") in {"0.0.0.0/0", "::/0"}
                    and rule.get("port") in _SENSITIVE_PORTS
                ):
                    yield self._finding(
                        title=f"Network exposed to the internet: {name}:{rule.get('port')}",
                        sev=Severity.HIGH,
                        cwe="CWE-284",
                        cis=f"CIS {provider} Networking — restrict admin ports",
                        resource=name,
                        detail=f"Ingress {rule.get('cidr')} → port {rule.get('port')} is open.",
                    )

    def _check_logging(self, logging, provider) -> Iterable[RawFinding]:  # noqa: ANN001
        enabled = logging.get("audit_enabled", logging.get("cloudtrail_enabled", True))
        if enabled is False:
            yield self._finding(
                title="Audit logging disabled",
                sev=Severity.MEDIUM,
                cwe="CWE-778",
                cis=f"CIS {provider} Logging — enable audit trail",
                resource="account",
                detail="Account-level audit logging is disabled.",
            )
