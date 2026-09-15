"""IaC engine — cloud misconfiguration in the code that creates it (WP-D9).

A misconfiguration found in a Terraform file costs a pull-request comment. The same
misconfiguration found in a live account costs an incident review, a change window, and an
explanation of how long the bucket was public. This engine reads what a repository declares, so the
finding arrives while it is still free to fix.

Passive: no cloud credentials, no network. The built-in rules need no external binary, and when the
**checkov** binary is present it is run as an ADDITIONAL backend (thousands of maintained policies,
merged the way SastEngine wraps semgrep) — additive, never a precondition. It complements the CSPM
engine rather than replacing it — CSPM sees what a human changed in the console afterwards, which
no amount of reading the repository can reveal.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell, bounded
from collections.abc import Iterable
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.iac import IacFinding, Resource, evaluate
from guardian_scanner.iac.loaders import load_cloudformation, load_path, load_terraform

log = get_logger("guardian.engine.iac")

_MAX_FINDINGS = 1_000

# checkov (Apache-2.0, APPROVED) is run as an ADDITIONAL backend when present — thousands of
# maintained policies across Terraform, CloudFormation, Kubernetes, ARM and more, merged rather than
# reimplemented, the same way SastEngine wraps semgrep and SecretsEngine wraps gitleaks. Additive,
# never a precondition: the built-in rules are a complete detector on their own, so the engine is
# never "degraded" without checkov — it only finds more when checkov is present. It needs files on
# disk, so it runs on a workspace but not on inline content.
_CHECKOV_TIMEOUT = 300
_CHECKOV_MAX_FINDINGS = 2_000
_CHECKOV_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.LOW,
}


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

        # Built-in rules are complete on their own, so the engine is never degraded — checkov only
        # adds policies. The detail reports whether it augmented, so a scan stays legible after.
        has_checkov = bool(shutil.which("checkov"))
        return EngineHealth(
            ok=True,
            detail=(f"{len(_RULES)} builtin rules"
                    + (" + checkov policies" if has_checkov else " (checkov absent)")),
        )

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        resources = list(self._resources(ctx))
        emitted = 0
        for resource in resources:
            for issue in evaluate(resource):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield _to_raw(issue, resource)
        # checkov needs files on disk; it augments a workspace scan, not an inline one.
        if ctx.inline_content is None and ctx.workspace_path:
            root = Path(ctx.workspace_path)
            if root.exists():
                yield from self._run_checkov_if_available(root)

    def _run_checkov_if_available(self, root: Path) -> Iterable[RawFinding]:
        """Wrap checkov when installed. No-op otherwise; CI and the built-in path are unchanged."""
        exe = shutil.which("checkov")
        if not exe:
            return
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, bounded
                [exe, "-d", str(root), "-o", "json", "--compact", "--quiet"],
                capture_output=True, text=True, timeout=_CHECKOV_TIMEOUT, check=False)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            # checkov is installed but did not answer. The built-in rules still ran, so this is
            # reduced coverage rather than a failed scan — but it must not be silent: fewer
            # findings from a crashed tool looks exactly like cleaner infrastructure.
            log.warning("iac_checkov_failed", error=f"{type(exc).__name__}: {exc}"[:200])
            return
        # checkov emits one result object per framework, or a list of them when several apply.
        blocks = data if isinstance(data, list) else [data]
        emitted = 0
        seen: set[tuple[str, str, int]] = set()
        for block in blocks:
            if not isinstance(block, dict):
                continue
            results = (block.get("results") or {})
            check_type = str(block.get("check_type") or "").strip()
            for check in results.get("failed_checks", []):
                if emitted >= _CHECKOV_MAX_FINDINGS:
                    return
                finding = self._checkov_finding(check, check_type)
                if finding is None:
                    continue
                dedup = (finding.location.get("rule", ""), finding.location.get("path", ""),
                         int(finding.location.get("line") or 0))
                if dedup in seen:
                    continue
                seen.add(dedup)
                emitted += 1
                yield finding

    def _checkov_finding(self, check: dict, check_type: str) -> RawFinding | None:
        if not isinstance(check, dict):
            return None
        rule = str(check.get("check_id") or "").strip()
        path = str(check.get("file_path") or "").strip()
        if not rule or not path:
            return None
        line_range = check.get("file_line_range") or []
        line = line_range[0] if isinstance(line_range, list) and line_range else None
        resource = str(check.get("resource") or "").strip()
        name = str(check.get("check_name") or rule).strip()[:300]
        sev = _CHECKOV_SEVERITY.get(str(check.get("severity") or "").upper(), Severity.MEDIUM)
        guideline = str(check.get("guideline") or "").strip()
        description = f"{name} (checkov {rule})."
        if guideline:
            description = f"{description} See {guideline}"
        return RawFinding(
            engine=EngineKey.IAC,
            title=f"IaC misconfiguration: {name}"[:300],
            category="iac-misconfig",
            description=description,
            base_severity=sev,
            confidence="high",
            location={"path": path, "line": line, "resource": resource, "rule": rule},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG,
                summary=f"{resource or rule} in {path}",
                location={"path": path, "line": line, "resource": resource},
                detail={"detector": "checkov", "rule": rule, "framework": check_type},
            ).to_dict(),
            references={"checkov": f"https://www.checkov.io/ ({rule})"},
        )

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
