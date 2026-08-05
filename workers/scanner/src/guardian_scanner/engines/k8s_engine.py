"""Kubernetes engine — manifest security analysis (CIS Kubernetes Benchmark).

Builtin ruleset (kube-linter / Checkov-style, no external binary) over pod-spec security settings:
privileged containers, host namespaces, privilege escalation, running as root, dangerous
capabilities, hostPath mounts, missing resource limits. Passive — analyzes provided manifests.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE"}
_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


class K8sEngine:
    key = EngineKey.K8S
    name = "Guardian Kubernetes (manifest CIS rules)"
    version = "0.1.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"k8s_manifest", "repo"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="builtin manifest rules (PyYAML)")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_text("manifest.yaml", ctx.inline_content)
            return
        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}:
                try:
                    text = path.read_text("utf-8", "ignore")
                except OSError:
                    continue
                yield from self._scan_text(str(path.relative_to(root)), text)

    def _scan_text(self, path: str, text: str) -> Iterable[RawFinding]:
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            return
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") not in _WORKLOAD_KINDS:
                continue
            name = (doc.get("metadata") or {}).get("name", "workload")
            pod = self._pod_spec(doc)
            if not pod:
                continue
            yield from self._check_pod(path, name, pod)

    @staticmethod
    def _pod_spec(doc: dict) -> dict | None:
        spec = doc.get("spec", {})
        if doc.get("kind") == "Pod":
            return spec
        # Deployment/... → spec.template.spec ; CronJob → jobTemplate.spec.template.spec
        tmpl = spec.get("template") or (spec.get("jobTemplate", {}).get("spec", {}).get("template"))
        return (tmpl or {}).get("spec") if tmpl else None

    def _check_pod(self, path: str, name: str, pod: dict) -> Iterable[RawFinding]:
        if pod.get("hostNetwork") or pod.get("hostPID") or pod.get("hostIPC"):
            yield self._f(
                "Pod shares a host namespace (hostNetwork/PID/IPC)",
                Severity.HIGH,
                "CWE-668",
                "CIS K8s 5.2.4",
                path,
                name,
            )
        for vol in pod.get("volumes", []) or []:
            if "hostPath" in vol:
                yield self._f(
                    "hostPath volume mounts the node filesystem",
                    Severity.MEDIUM,
                    "CWE-668",
                    "CIS K8s 5.2.12",
                    path,
                    name,
                )
        for c in pod.get("containers", []) or []:
            sc = c.get("securityContext", {}) or {}
            if sc.get("privileged"):
                yield self._f(
                    f"Privileged container: {c.get('name')}",
                    Severity.CRITICAL,
                    "CWE-250",
                    "CIS K8s 5.2.1",
                    path,
                    name,
                )
            if sc.get("allowPrivilegeEscalation") is not False:
                yield self._f(
                    f"allowPrivilegeEscalation not disabled: {c.get('name')}",
                    Severity.MEDIUM,
                    "CWE-250",
                    "CIS K8s 5.2.5",
                    path,
                    name,
                )
            if sc.get("runAsNonRoot") is not True:
                yield self._f(
                    f"Container may run as root: {c.get('name')}",
                    Severity.MEDIUM,
                    "CWE-250",
                    "CIS K8s 5.2.6",
                    path,
                    name,
                )
            caps = ((sc.get("capabilities") or {}).get("add")) or []
            dangerous = _DANGEROUS_CAPS & {cap.upper() for cap in caps}
            if dangerous:
                yield self._f(
                    f"Dangerous capabilities added ({', '.join(sorted(dangerous))})",
                    Severity.HIGH,
                    "CWE-250",
                    "CIS K8s 5.2.8",
                    path,
                    name,
                )
            if not (c.get("resources") or {}).get("limits"):
                yield self._f(
                    f"No resource limits set: {c.get('name')}",
                    Severity.LOW,
                    "CWE-400",
                    "CIS K8s 5.7.3",
                    path,
                    name,
                )

    def _f(self, title, sev, cwe, cis, path, name) -> RawFinding:  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.K8S,
            title=title,
            category="k8s-misconfig",
            description=f"{title} ({cis}).",
            base_severity=sev,
            confidence="high",
            cwe_id=cwe,
            location={"path": path, "workload": name, "cis": cis},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG,
                summary=f"{path}:{name}",
                detail={"finding": title, "cis": cis},
            ).to_dict(),
            references={"cis": cis},
        )
