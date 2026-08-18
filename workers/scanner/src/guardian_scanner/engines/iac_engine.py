"""IaC engine — cloud misconfiguration in the code that creates it (WP-D9).

A misconfiguration found in a Terraform file costs a pull-request comment. The same
misconfiguration found in a live account costs an incident review, a change window, and an
explanation of how long the bucket was public. This engine reads what a repository declares, so the
finding arrives while it is still free to fix.

Passive and dependency-free: no cloud credentials, no external binary, no network. It complements
the CSPM engine rather than replacing it — CSPM sees what a human changed in the console afterwards,
which no amount of reading the repository can reveal.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from guardian_core.enums import EngineKey
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.iac import IacFinding, Resource, evaluate
from guardian_scanner.iac.loaders import load_cloudformation, load_path, load_terraform

_MAX_FINDINGS = 1_000


class IacInputError(RuntimeError):
    """There was no infrastructure code to read (readiness audit, Phase 4)."""


class IacEngine:
    key = EngineKey.IAC
    name = "Guardian IaC (Terraform, CloudFormation, Terraform plan)"
    version = "1.0.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo", "k8s_manifest"}

    def health(self) -> EngineHealth:
        from guardian_scanner.iac.rules import _RULES  # noqa: PLC0415 - reported, not called

        return EngineHealth(ok=True, detail=f"{len(_RULES)} builtin rules, no external binary")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        resources = list(self._resources(ctx))
        emitted = 0
        for resource in resources:
            for issue in evaluate(resource):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield _to_raw(issue, resource)

    def _resources(self, ctx: ScanContext) -> Iterable[Resource]:
        if ctx.inline_content is not None:
            text = ctx.inline_content
            # Inline content is a single file with no name, so the dialect is inferred from the
            # content itself rather than guessed from an extension that is not there.
            if "AWSTemplateFormatVersion" in text[:4000] or "\nResources:" in text[:4000]:
                return load_cloudformation(text, "<inline>")
            return load_terraform(text, "<inline>")
        if not ctx.workspace_path:
            raise IacInputError(
                "no workspace and no inline content, so no infrastructure code was read. An "
                "absence of input is not an absence of misconfiguration."
            )
        root = Path(ctx.workspace_path)
        if not root.exists():
            raise IacInputError(
                f"the workspace path {ctx.workspace_path!r} does not exist, so no infrastructure "
                "code was read"
            )
        return load_path(root)


def _to_raw(issue: IacFinding, resource: Resource) -> RawFinding:
    description = issue.detail
    if issue.remediation:
        description = f"{description}\n\nRemediation: {issue.remediation}"
    return RawFinding(
        engine=EngineKey.IAC,
        title=issue.title,
        category="iac-misconfig",
        description=description,
        base_severity=issue.severity,
        # The rule read a literal value in the file. It is an observation about the declaration —
        # not about the live account, which may have drifted in either direction.
        confidence="high",
        cwe_id=issue.cwe,
        location={"path": issue.path, "line": issue.line, "resource": issue.resource,
                  "rule": issue.rule},
        evidence=Evidence(
            kind=EvidenceKind.CONFIG,
            summary=f"{issue.resource} in {issue.path}",
            location={"path": issue.path, "line": issue.line, "resource": issue.resource},
            detail={"dialect": resource.dialect, "resource_type": resource.type,
                    "rule": issue.rule},
        ).to_dict(),
        references={"cwe": f"https://cwe.mitre.org/data/definitions/{issue.cwe.split('-')[1]}.html"},
    )
