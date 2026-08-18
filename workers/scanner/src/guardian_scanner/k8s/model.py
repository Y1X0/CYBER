"""Getting Kubernetes objects out of a file (WP-D7).

Two things make this more than `yaml.safe_load_all`.

**Helm.** Most real manifests in a repository are Helm templates, and `{{ .Values.image.tag }}` is
not valid YAML in a value position. The previous engine let the parse error propagate to a bare
`except yaml.YAMLError: return`, so an entire chart produced no findings and no complaint — the
worst possible outcome, because it is indistinguishable from a clean chart. Templates are rendered
to a neutral placeholder before parsing: the *structure* is what the rules examine, and the
structure survives.

**Shape.** Objects arrive as single documents, as multi-document streams, as `List` kinds, and — for
a live cluster export — as `kubectl get -o json` output with an `items` array. All four are the same
thing to a rule.

Parse failures are collected, never swallowed. A file the analyser could not read is a file it did
not check, and the engine reports that as its own finding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

# `{{ ... }}` and `{%- ... -%}`: Helm/Jinja template actions. Replaced with a placeholder scalar so
# the document parses and the structure stays intact.
_TEMPLATE_ACTION = re.compile(r"\{\{-?.*?-?\}\}|\{%-?.*?-?%\}", re.DOTALL)
# A whole line that is only a template control statement (`{{- if .Values.x }}`) is dropped rather
# than replaced: leaving a placeholder where a mapping key belongs produces a different error.
_TEMPLATE_LINE = re.compile(r"^\s*\{\{-?\s*(?:if|else|end|range|with|define|include|template|"
                            r"block)\b.*?-?\}\}\s*$", re.MULTILINE)

PLACEHOLDER = "GUARDIAN_TEMPLATED"

_LIST_KINDS = {"List", "ConfigMapList", "SecretList", "PodList", "DeploymentList"}


@dataclass
class Document:
    """One Kubernetes object, with where it came from."""

    kind: str
    name: str
    namespace: str
    body: dict
    path: str
    templated: bool = False

    @property
    def label(self) -> str:
        scope = f"{self.namespace}/" if self.namespace else ""
        return f"{scope}{self.kind}/{self.name}"


@dataclass
class LoadResult:
    documents: list[Document] = field(default_factory=list)
    # Files that could not be parsed at all. Surfaced by the engine — a file it could not read is a
    # file it did not check, and silence there reads as "nothing wrong here".
    errors: list[str] = field(default_factory=list)
    templated_files: list[str] = field(default_factory=list)


def is_template(text: str) -> bool:
    return bool(_TEMPLATE_ACTION.search(text))


def derender(text: str) -> str:
    """Replace template actions with a placeholder so the document parses.

    Analysing the rendered-with-placeholders form is a deliberate trade. A rule that depends on a
    templated *value* (`image: {{ .Values.image }}`) cannot conclude anything and does not fire; a
    rule about *structure* (`privileged: true`, a hostPath volume, a wildcard RBAC verb) reads
    exactly what the chart will produce. The alternative — skipping charts entirely — is what the
    engine used to do.
    """
    text = _TEMPLATE_LINE.sub("", text)
    return _TEMPLATE_ACTION.sub(PLACEHOLDER, text)


def _objects(doc: Any) -> list[dict]:
    """Flatten `List` kinds and `kubectl -o json` `items` arrays."""
    if not isinstance(doc, dict):
        return []
    if doc.get("kind") in _LIST_KINDS or (isinstance(doc.get("items"), list) and "kind" in doc):
        out: list[dict] = []
        for item in doc.get("items") or []:
            out.extend(_objects(item))
        return out
    if "kind" in doc:
        return [doc]
    return []


def load(path: str, text: str) -> LoadResult:
    """Every Kubernetes object in one file."""
    result = LoadResult()
    templated = is_template(text)
    source = derender(text) if templated else text
    if templated:
        result.templated_files.append(path)

    try:
        if source.lstrip().startswith("{"):
            documents = [json.loads(source)]
        else:
            documents = list(yaml.safe_load_all(source))
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        # Reported, not skipped. The previous engine returned silently here, so a chart that failed
        # to parse looked exactly like a chart with nothing wrong.
        detail = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
        result.errors.append(f"{path}: {detail}")
        return result

    for document in documents:
        for obj in _objects(document):
            metadata = obj.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            result.documents.append(Document(
                kind=str(obj.get("kind") or ""),
                name=str(metadata.get("name") or "unnamed"),
                namespace=str(metadata.get("namespace") or ""),
                body=obj,
                path=path,
                templated=templated,
            ))
    return result


# ── pod-spec navigation ───────────────────────────────────────────────────────────────────────────
WORKLOAD_KINDS = frozenset({
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
    "ReplicationController",
})


def pod_spec(body: dict) -> dict | None:
    """The pod spec inside any workload kind."""
    spec = body.get("spec")
    if not isinstance(spec, dict):
        return None
    if body.get("kind") == "Pod":
        return spec
    template = spec.get("template")
    if template is None:
        job_template = spec.get("jobTemplate")
        if isinstance(job_template, dict):
            template = (job_template.get("spec") or {}).get("template")
    if isinstance(template, dict):
        inner = template.get("spec")
        return inner if isinstance(inner, dict) else None
    return None


def containers(pod: dict) -> list[tuple[str, dict]]:
    """(section, container) for every container in the pod.

    `initContainers` and `ephemeralContainers` are included because they are containers: an
    initContainer with `privileged: true` runs as root on the node before the workload starts, and
    the engine that only looked at `containers` could not see it at all.
    """
    out: list[tuple[str, dict]] = []
    for section in ("containers", "initContainers", "ephemeralContainers"):
        for container in pod.get(section) or []:
            if isinstance(container, dict):
                out.append((section, container))
    return out


def effective_security(pod: dict, container: dict) -> dict:
    """The container's security context after the pod-level defaults are applied.

    Kubernetes merges these: a field set on the pod applies to every container that does not
    override it. Checking the container alone reports a correctly-hardened workload as three
    findings per container, which is how a scanner trains people to ignore it.
    """
    pod_level = pod.get("securityContext") or {}
    container_level = container.get("securityContext") or {}
    merged = {**(pod_level if isinstance(pod_level, dict) else {}),
              **(container_level if isinstance(container_level, dict) else {})}
    # `capabilities` and `seccompProfile` are container-scoped only — a pod-level value never
    # supplies them — so they must not be inherited from the merge above.
    if isinstance(container_level, dict):
        for key in ("capabilities",):
            if key in container_level:
                merged[key] = container_level[key]
            else:
                merged.pop(key, None)
    return merged


__all__ = [
    "PLACEHOLDER",
    "WORKLOAD_KINDS",
    "Document",
    "LoadResult",
    "containers",
    "derender",
    "effective_security",
    "is_template",
    "load",
    "pod_spec",
]
