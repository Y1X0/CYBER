"""Kubernetes engine — cluster posture from manifests or a cluster export (WP-D7).

Runs `guardian_scanner.k8s`'s rules over every Kubernetes object it can find: workloads, RBAC roles
and bindings, Secrets and ConfigMaps, Services, Ingresses and NetworkPolicies. Passive — it reads
manifests the customer provides, or a `kubectl get -o json` export of a live cluster placed in the
asset config. It never talks to an API server itself, so it needs no cluster credential and no
authorization gate.

Two behaviours that are not rules but matter as much as any of them:

* a file that could not be parsed is **reported**, not skipped. The previous engine returned
  silently on a YAML error, so a Helm chart — which does not parse as YAML — produced no findings
  and no complaint, which reads exactly like a chart with nothing wrong;
* Helm templates are analysed rather than skipped, by rendering template actions to a placeholder.
  A rule about structure reads correctly through that; a rule about a templated value declines to
  conclude anything.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.k8s.model import Document, LoadResult, load
from guardian_scanner.k8s.rules import Issue, analyse

log = get_logger("guardian.k8s")

MAX_FILES = 2_000
MAX_FILE_BYTES = 2_000_000

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_MANIFEST_SUFFIXES = {".yaml", ".yml", ".json"}
# Directories whose YAML is never a cluster manifest. Scanning them produces noise and burns time.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build",
              ".mypy_cache", ".pytest_cache", ".github"}


class K8sEngine:
    key = EngineKey.K8S
    name = "Guardian Kubernetes (workloads, RBAC, secrets, network)"
    version = "0.2.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"k8s_manifest", "repo"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="builtin rules over workloads, RBAC, secrets, "
                                            "services, ingresses and network policies (PyYAML)")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        documents: list[Document] = []
        errors: list[str] = []
        templated: list[str] = []
        files_read = 0
        truncated = False

        for name, text in self._sources(ctx):
            files_read += 1
            if files_read > MAX_FILES:
                truncated = True
                break
            result: LoadResult = load(name, text)
            documents.extend(result.documents)
            errors.extend(result.errors)
            templated.extend(result.templated_files)

        for document in documents:
            for issue in analyse(document):
                yield self._finding(document, issue)

        if errors or truncated:
            yield self._coverage_finding(documents, errors, templated, truncated, files_read)

        log.info("k8s_scan_complete", objects=len(documents), files=files_read,
                 unparsed=len(errors), templated=len(set(templated)))

    # ── inputs ───────────────────────────────────────────────────────────────────────────────────
    def _sources(self, ctx: ScanContext) -> Iterable[tuple[str, str]]:
        if ctx.inline_content is not None:
            yield "manifest.yaml", ctx.inline_content
            return

        # A `kubectl get -o json` export of a live cluster. The same rules apply to what is running
        # as to what is committed, and this is the only honest way to reach live state without
        # holding a cluster credential.
        export = (ctx.asset_config or {}).get("k8s_export")
        if export:
            import json  # noqa: PLC0415

            yield "cluster-export.json", export if isinstance(export, str) else json.dumps(export)
            return

        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _MANIFEST_SUFFIXES:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text("utf-8", "ignore")
            except OSError as exc:
                log.warning("k8s_file_unreadable", path=str(path), error=str(exc)[:200])
                continue
            # Cheap pre-filter: a Kubernetes object always names its kind and apiVersion.
            if "kind:" not in text and '"kind"' not in text:
                continue
            yield str(path.relative_to(root)), text

    # ── findings ─────────────────────────────────────────────────────────────────────────────────
    def _finding(self, doc: Document, issue: Issue) -> RawFinding:
        description = issue.detail
        if doc.templated:
            description += ("\n\nThis object comes from a template; the structural rule that "
                            "fired reads the same after rendering, but any templated *value* was "
                            "not evaluated.")
        return RawFinding(
            engine=EngineKey.K8S,
            title=issue.title,
            category="k8s-misconfig",
            description=f"{description}\n\nRemediation: {issue.remediation}",
            base_severity=_SEVERITY.get(issue.severity, Severity.MEDIUM),
            confidence="medium" if doc.templated else "high",
            cwe_id=issue.cwe,
            location={
                "path": doc.path,
                "workload": doc.label,
                "rule": issue.rule,
                "cis": issue.control,
                "subject": issue.subject,
            },
            evidence=Evidence(
                kind=EvidenceKind.CONFIG,
                summary=f"{doc.path}: {doc.label}"
                        + (f" ({issue.subject})" if issue.subject else ""),
                detail={
                    "object": doc.label,
                    "control": issue.control,
                    "finding": issue.title,
                    **issue.evidence,
                },
            ).to_dict(),
            references={"cis": issue.control},
        )

    def _coverage_finding(self, documents: list[Document], errors: list[str],
                          templated: list[str], truncated: bool, files_read: int) -> RawFinding:
        reasons = [f"{path}" for path in errors[:10]]
        if truncated:
            reasons.append(f"stopped after {MAX_FILES} files")
        return RawFinding(
            engine=EngineKey.K8S,
            title="Kubernetes manifests could not be fully analysed",
            category="scan-coverage",
            description=(
                f"{len(errors)} file(s) could not be parsed as Kubernetes objects, so nothing in "
                "them was checked. The absence of findings for those files is not evidence that "
                "they are sound.\n\n" + "\n".join(reasons)
            ),
            base_severity=Severity.INFO,
            confidence="high",
            location={"path": errors[0].split(":")[0] if errors else "", "rule": "k8s-coverage"},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG,
                summary=f"{len(documents)} objects analysed across {files_read} files; "
                        f"{len(errors)} unparsed",
                detail={"unparsed": errors[:20], "templated": sorted(set(templated))[:20],
                        "objects": len(documents), "files": files_read},
            ).to_dict(),
            references={},
        )
