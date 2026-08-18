"""What is wrong with a Kubernetes object (WP-D7).

Grouped by the question each group answers:

* **workload** — what can this container do to the node it lands on?
* **rbac** — what can a compromised pod do to the cluster through the API server?
* **secrets** — what is stored in plaintext in the manifest itself?
* **network** — what can reach it, and what can it reach?

The second group is the one the previous engine had none of, and it is where the severity lives: a
container that is merely `runAsRoot` is contained by the node, while a service account bound to
`cluster-admin` is the cluster.

Every rule is a pure function of one parsed document. Rules never raise on a malformed object — a
manifest with `spec: null` is a real thing that exists in real repositories — but they never guess
either: a field that is templated or absent yields no finding rather than a default assumption.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from guardian_scanner.k8s.model import (
    PLACEHOLDER,
    WORKLOAD_KINDS,
    Document,
    containers,
    effective_security,
    pod_spec,
)

DANGEROUS_CAPABILITIES = frozenset({
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_BOOT", "SYS_RAWIO",
    "DAC_READ_SEARCH", "DAC_OVERRIDE", "BPF", "PERFMON", "NET_RAW",
})

# Verbs and resources that amount to control of the cluster.
_WRITE_VERBS = frozenset({"create", "update", "patch", "delete", "deletecollection", "*"})
_ESCALATION_RESOURCES = frozenset({
    "secrets", "pods/exec", "pods/attach", "pods/portforward", "clusterrolebindings",
    "rolebindings", "clusterroles", "roles", "serviceaccounts/token", "nodes/proxy",
    "certificatesigningrequests/approval", "*",
})
_SUPERUSER_ROLES = frozenset({"cluster-admin"})
# Groups that mean "anyone", including unauthenticated callers.
_EVERYONE = frozenset({"system:anonymous", "system:unauthenticated", "system:authenticated"})

_PRIVILEGED_HOST_PATHS = (
    "/", "/etc", "/var/run/docker.sock", "/var/run/containerd", "/var/lib/kubelet", "/proc",
    "/sys", "/dev", "/root", "/var/log",
)

# A value that looks like a real credential rather than a placeholder.
_PLACEHOLDER_VALUES = re.compile(
    r"(?i)^(?:changeme|placeholder|example|redacted|xxx+|test|dummy|todo|<[^>]+>|\$\{[^}]+\}|"
    + re.escape(PLACEHOLDER) + r")$"
)
_SECRET_KEY = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
)


@dataclass(frozen=True)
class Issue:
    rule: str
    title: str
    severity: str
    cwe: str
    control: str          # CIS Kubernetes Benchmark / NSA-CISA reference
    detail: str
    remediation: str
    subject: str = ""     # container / subject / key the finding is about
    evidence: dict = field(default_factory=dict)


def _verb(direction: str) -> str:
    return "accept" if direction == "ingress" else "reach"


def _first(*values):  # noqa: ANN002, ANN201 - the first value that is not None
    for value in values:
        if value is not None:
            return value
    return None


# ── workloads ─────────────────────────────────────────────────────────────────────────────────────
def workload_issues(doc: Document) -> Iterator[Issue]:
    if doc.kind not in WORKLOAD_KINDS:
        return
    pod = pod_spec(doc.body)
    if not pod:
        return

    if pod.get("hostNetwork") is True:
        yield Issue(
            "host-network", "Pod shares the node's network namespace", "high", "CWE-668",
            "CIS 5.2.4",
            "hostNetwork gives the pod the node's interfaces and its localhost, which reaches "
            "services that are bound to 127.0.0.1 precisely so nothing else can reach them — "
            "including the kubelet's read-only port and any node-local metadata agent.",
            "Remove hostNetwork and expose the pod through a Service.",
        )
    for field_name, label in (("hostPID", "process"), ("hostIPC", "IPC")):
        if pod.get(field_name) is True:
            yield Issue(
                f"host-{label}", f"Pod shares the node's {label} namespace", "high", "CWE-668",
                "CIS 5.2.3",
                f"{field_name} lets the pod see and signal every other process on the node, "
                "including processes holding other workloads' credentials in memory.",
                f"Remove {field_name}.",
            )

    if pod.get("automountServiceAccountToken") is not False and _mounts_token(pod):
        yield Issue(
            "token-automount", "The service account token is mounted into the pod", "medium",
            "CWE-522", "CIS 5.1.6",
            "Every container gets a credential for the Kubernetes API whether or not it talks to "
            "the API. It is the first thing anything that lands in the pod will read.",
            "Set automountServiceAccountToken: false on the pod or the service account.",
        )

    for volume in pod.get("volumes") or []:
        if not isinstance(volume, dict):
            continue
        host_path = (volume.get("hostPath") or {}).get("path") if volume.get("hostPath") else None
        if not host_path:
            continue
        sensitive = _is_sensitive_host_path(str(host_path))
        yield Issue(
            "host-path", f"hostPath volume mounts {host_path} from the node",
            "critical" if sensitive else "medium", "CWE-668", "CIS 5.2.12",
            "A hostPath mount is the node's filesystem inside the container."
            + (f" {host_path} in particular is a documented container-escape path: writing to it "
               "reaches the container runtime, the kubelet's credentials, or the node's own "
               "configuration." if sensitive else ""),
            "Use a PersistentVolumeClaim, a projected volume, or an emptyDir instead.",
            subject=volume.get("name", ""),
            evidence={"path": host_path},
        )

    for section, container in containers(pod):
        yield from _container_issues(doc, pod, section, container)


def _is_sensitive_host_path(host_path: str) -> bool:
    """Whether the mounted node path is one of the documented escape routes.

    `/` is compared exactly and never as a prefix: `p.rstrip("/")` turns it into the empty string,
    and every absolute path starts with `"" + "/"` — which graded `/opt/data` as a container escape.
    """
    normalized = host_path.rstrip("/") or "/"
    for candidate in _PRIVILEGED_HOST_PATHS:
        target = candidate.rstrip("/") or "/"
        if normalized == target:
            return True
        if target != "/" and normalized.startswith(target + "/"):
            return True
    return False


def _mounts_token(pod: dict) -> bool:
    """Whether the API token actually lands in the pod.

    Defaults to true because Kubernetes does — but a pod that explicitly projects no token, or that
    names a service account with automounting disabled, is not reported. The rule is about a
    credential being present, not about a field being absent.
    """
    return pod.get("automountServiceAccountToken") is not False


def _container_issues(doc: Document, pod: dict, section: str, container: dict) -> Iterator[Issue]:
    name = container.get("name", "container")
    where = f"{section}:{name}"
    security = effective_security(pod, container)

    if security.get("privileged") is True:
        yield Issue(
            "privileged", f"Privileged container: {name}", "critical", "CWE-250", "CIS 5.2.1",
            "A privileged container has all capabilities and unrestricted device access. Escaping "
            "to the node from one is a documented, single-step operation, and this applies to an "
            f"{section[:-1]} exactly as it does to the main container.",
            "Remove privileged: true and grant only the specific capabilities needed.",
            subject=where,
        )

    if security.get("allowPrivilegeEscalation") is not False and security.get(
            "privileged") is not True:
        yield Issue(
            "privilege-escalation", f"allowPrivilegeEscalation is not disabled: {name}", "medium",
            "CWE-250", "CIS 5.2.5",
            "Without this set to false a process in the container can gain more privileges than "
            "its parent — through a setuid binary, for instance.",
            "Set securityContext.allowPrivilegeEscalation: false.",
            subject=where,
        )

    runs_as_root = security.get("runAsNonRoot") is not True and (
        security.get("runAsUser") is None or security.get("runAsUser") == 0
    )
    if runs_as_root:
        yield Issue(
            "run-as-root", f"Container may run as root: {name}", "medium", "CWE-250", "CIS 5.2.6",
            "Nothing in the manifest prevents the image's default user, which is root unless the "
            "image says otherwise. Root in the container is root on the node for anything that "
            "escapes the namespace.",
            "Set runAsNonRoot: true, or runAsUser to a non-zero uid.",
            subject=where,
        )

    added = {str(cap).upper() for cap in
             ((security.get("capabilities") or {}).get("add") or [])}
    dangerous = DANGEROUS_CAPABILITIES & added
    if dangerous:
        yield Issue(
            "dangerous-capabilities",
            f"Dangerous capabilities added to {name}: {', '.join(sorted(dangerous))}",
            "critical" if {"ALL", "SYS_ADMIN", "SYS_MODULE"} & dangerous else "high",
            "CWE-250", "CIS 5.2.8",
            "These capabilities lift the restrictions that keep a container inside its namespace. "
            "SYS_ADMIN and ALL are equivalent to privileged for most escape techniques.",
            "Drop ALL and add back only the specific capabilities the workload needs.",
            subject=where,
            evidence={"capabilities": sorted(dangerous)},
        )

    if security.get("readOnlyRootFilesystem") is not True:
        yield Issue(
            "writable-root", f"Root filesystem is writable: {name}", "low", "CWE-732",
            "CIS 5.2.11",
            "A writable root filesystem lets an attacker who achieves execution persist a payload "
            "and modify the application's own binaries.",
            "Set readOnlyRootFilesystem: true and mount an emptyDir for paths that need writing.",
            subject=where,
        )

    for port in container.get("ports") or []:
        if isinstance(port, dict) and port.get("hostPort"):
            yield Issue(
                "host-port", f"Container binds hostPort {port['hostPort']}: {name}", "medium",
                "CWE-668", "CIS 5.2.9",
                "A hostPort binds the container's port on the node itself, bypassing Services and "
                "any NetworkPolicy that governs pod-to-pod traffic.",
                "Expose the port through a Service instead.",
                subject=where,
                evidence={"hostPort": port.get("hostPort")},
            )

    image = str(container.get("image") or "")
    if image and PLACEHOLDER not in image:
        tag = image.rsplit("/", 1)[-1]
        if "@sha256:" not in image and (":" not in tag or tag.endswith(":latest")):
            yield Issue(
                "mutable-image", f"Image is not pinned: {name}", "low", "CWE-494", "CIS 5.5.1",
                f"`{image}` resolves to whatever the registry serves at pull time, so what is "
                "running cannot be determined from the manifest and a rebuild silently changes it.",
                "Pin the image by digest (image@sha256:…).",
                subject=where,
                evidence={"image": image},
            )

    if not (container.get("resources") or {}).get("limits"):
        yield Issue(
            "no-resource-limits", f"No resource limits set: {name}", "low", "CWE-400",
            "CIS 5.7.3",
            "A container without limits can consume the node's CPU and memory, which takes down "
            "every other workload scheduled there.",
            "Set resources.limits for cpu and memory.",
            subject=where,
        )
    del doc


# ── RBAC ──────────────────────────────────────────────────────────────────────────────────────────
def rbac_issues(doc: Document) -> Iterator[Issue]:
    if doc.kind in ("Role", "ClusterRole"):
        yield from _role_issues(doc)
    elif doc.kind in ("RoleBinding", "ClusterRoleBinding"):
        yield from _binding_issues(doc)


def _role_issues(doc: Document) -> Iterator[Issue]:
    for rule in doc.body.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        verbs = {str(v).lower() for v in (rule.get("verbs") or [])}
        resources = {str(r).lower() for r in (rule.get("resources") or [])}
        groups = {str(g).lower() for g in (rule.get("apiGroups") or [])}

        if "*" in verbs and "*" in resources:
            yield Issue(
                "rbac-wildcard", f"{doc.kind} grants every verb on every resource", "critical",
                "CWE-269", "CIS 5.1.3",
                f"`{doc.name}` is cluster-admin by another name. Anything bound to it can read "
                "every secret, run any pod, and modify the cluster's own authorization rules.",
                "Enumerate the verbs and resources the workload actually uses.",
                subject=doc.name,
                evidence={"apiGroups": sorted(groups), "resources": ["*"], "verbs": ["*"]},
            )
            continue

        escalating = resources & _ESCALATION_RESOURCES
        if escalating and (verbs & _WRITE_VERBS or "get" in verbs or "list" in verbs):
            severity = "critical" if doc.kind == "ClusterRole" else "high"
            yield Issue(
                "rbac-escalation",
                f"{doc.kind} grants {', '.join(sorted(verbs))} on "
                f"{', '.join(sorted(escalating))}",
                severity, "CWE-269", "CIS 5.1.1",
                "These resources are the ones that grant further access: reading secrets yields "
                "credentials, `pods/exec` is a shell in any pod, and writing role bindings is the "
                "ability to grant oneself anything.",
                "Scope the rule to named resources, or drop it.",
                subject=doc.name,
                evidence={"resources": sorted(escalating), "verbs": sorted(verbs)},
            )


def _binding_issues(doc: Document) -> Iterator[Issue]:
    role = doc.body.get("roleRef") or {}
    role_name = str(role.get("name") or "")
    subjects = doc.body.get("subjects") or []

    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        kind = str(subject.get("kind") or "")
        name = str(subject.get("name") or "")
        label = f"{kind}/{name}"

        if role_name in _SUPERUSER_ROLES:
            yield Issue(
                "rbac-cluster-admin", f"{label} is bound to {role_name}", "critical", "CWE-269",
                "CIS 5.1.1",
                f"`{doc.name}` gives {label} full control of the cluster. If it is a "
                "ServiceAccount, every pod using it holds that control, and anything that "
                "compromises one of those pods holds the cluster.",
                "Bind a role scoped to what the workload needs.",
                subject=label,
                evidence={"roleRef": role_name, "binding": doc.name},
            )
        if name.lower() in _EVERYONE or (kind == "Group" and name.lower() in _EVERYONE):
            yield Issue(
                "rbac-everyone", f"A role is bound to {name}", "critical", "CWE-284",
                "CIS 5.1.1",
                f"`{name}` covers every caller the API server sees — for "
                "`system:unauthenticated` and `system:anonymous`, that includes callers with no "
                "credentials at all.",
                "Bind the role to specific service accounts or users.",
                subject=label,
                evidence={"roleRef": role_name, "subject": name},
            )
        if kind == "ServiceAccount" and name == "default":
            yield Issue(
                "rbac-default-sa", f"The default service account is bound to {role_name}",
                "high", "CWE-269", "CIS 5.1.5",
                "Every pod in the namespace that does not name a service account uses `default`, "
                "so this grant reaches workloads nobody intended to give it to.",
                "Create a dedicated service account for the workload that needs the role.",
                subject=label,
                evidence={"roleRef": role_name},
            )


# ── secrets in manifests ──────────────────────────────────────────────────────────────────────────
def secret_issues(doc: Document) -> Iterator[Issue]:
    """A credential committed in a manifest.

    Kubernetes Secrets are base64, not encryption. A `Secret` in a repository is a plaintext
    credential with an extra step, and the extra step is why it survives review.
    """
    if doc.kind == "Secret":
        for key, value in (doc.body.get("data") or {}).items():
            decoded = _b64(str(value))
            if decoded is None or _is_placeholder(decoded):
                continue
            yield _secret_issue(doc, key, decoded, encoded=True)
        for key, value in (doc.body.get("stringData") or {}).items():
            if _is_placeholder(str(value)):
                continue
            yield _secret_issue(doc, key, str(value), encoded=False)
        return

    if doc.kind == "ConfigMap":
        for key, value in (doc.body.get("data") or {}).items():
            if not _SECRET_KEY.search(str(key)) or _is_placeholder(str(value)):
                continue
            yield Issue(
                "configmap-credential", f"ConfigMap `{doc.name}` holds a credential in `{key}`",
                "high", "CWE-798", "CIS 5.4.1",
                "A ConfigMap is not a Secret: it is not encrypted at rest, it is readable by "
                "anything with `get configmaps`, and it is routinely dumped into logs and "
                "diagnostics bundles.",
                "Move the value to a Secret, or to an external secret store.",
                subject=key,
                # The value itself is never carried into a finding.
                evidence={"key": key, "length": len(str(value))},
            )
        return

    # A credential passed as a literal environment variable in a workload.
    if doc.kind in WORKLOAD_KINDS:
        pod = pod_spec(doc.body)
        if not pod:
            return
        for section, container in containers(pod):
            for env in container.get("env") or []:
                if not isinstance(env, dict) or "value" not in env:
                    continue
                key, value = str(env.get("name") or ""), str(env.get("value") or "")
                if not _SECRET_KEY.search(key) or _is_placeholder(value) or not value:
                    continue
                yield Issue(
                    "env-credential",
                    f"Credential passed as a literal environment variable: {key}", "high",
                    "CWE-798", "CIS 5.4.1",
                    "The value is in the manifest, in the pod spec, and in `kubectl describe` "
                    "output for anyone who can read pods in the namespace.",
                    "Use valueFrom.secretKeyRef, or an external secret store.",
                    subject=f"{section}:{container.get('name', '')}:{key}",
                    evidence={"variable": key, "length": len(value)},
                )


def _secret_issue(doc: Document, key: str, value: str, *, encoded: bool) -> Issue:
    return Issue(
        "manifest-secret", f"Secret `{doc.name}` carries a value for `{key}` in the manifest",
        "high", "CWE-798", "CIS 5.4.1",
        "Kubernetes Secrets are base64, not encryption"
        + (" — this value decodes to readable text." if encoded else ", and this one is not even "
           "encoded.")
        + " A manifest in a repository is a credential in a repository.",
        "Keep the value in an external secret store and reference it, or seal it with a tool that "
        "encrypts to the cluster's key.",
        subject=key,
        # Length only. The value is what the finding is about and it is never persisted.
        evidence={"key": key, "length": len(value), "encoded": encoded},
    )


def _b64(value: str) -> str | None:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return not stripped or bool(_PLACEHOLDER_VALUES.match(stripped)) or PLACEHOLDER in stripped


# ── exposure and network ──────────────────────────────────────────────────────────────────────────
def network_issues(doc: Document) -> Iterator[Issue]:
    if doc.kind == "Service":
        service_type = str((doc.body.get("spec") or {}).get("type") or "ClusterIP")
        if service_type in ("NodePort", "LoadBalancer"):
            yield Issue(
                "service-exposed", f"Service `{doc.name}` is exposed as {service_type}",
                "medium" if service_type == "NodePort" else "low", "CWE-668", "CIS 5.7.4",
                f"A {service_type} Service is reachable from outside the cluster"
                + (" on every node, on a port no ingress controller or WAF sits in front of."
                   if service_type == "NodePort" else "."),
                "Route external traffic through an Ingress with TLS, and keep the Service "
                "ClusterIP.",
                subject=doc.name,
                evidence={"type": service_type},
            )

    if doc.kind == "Ingress":
        spec = doc.body.get("spec") or {}
        if not spec.get("tls"):
            yield Issue(
                "ingress-no-tls", f"Ingress `{doc.name}` has no TLS configuration", "high",
                "CWE-319", "NSA-CISA network hardening",
                "Traffic to this application crosses the network in plaintext, including any "
                "session cookie and any credential posted to it.",
                "Add a tls block referencing a certificate secret.",
                subject=doc.name,
            )

    if doc.kind == "NetworkPolicy":
        spec = doc.body.get("spec") or {}
        selector = spec.get("podSelector")
        types = {str(t).lower() for t in (spec.get("policyTypes") or [])}
        if selector == {} and "egress" in types and not spec.get("egress"):
            # A default-deny egress policy. Not a finding — recorded here so the rule set is
            # explicitly aware of the good case rather than silent about it.
            return
        for direction in ("ingress", "egress"):
            for rule in spec.get(direction) or []:
                if not isinstance(rule, dict):
                    continue
                peers = rule.get("from" if direction == "ingress" else "to")
                if peers == [] or peers is None:
                    yield Issue(
                        f"netpol-open-{direction}",
                        f"NetworkPolicy `{doc.name}` allows unrestricted {direction} traffic",
                        "medium", "CWE-668", "NSA-CISA network hardening",
                        f"An empty {direction} rule matches every peer, so this policy permits "
                        "what a reader would expect it to restrict.",
                        f"Name the peers this workload must {_verb(direction)}.",
                        subject=doc.name,
                    )


ALL_RULES = (workload_issues, rbac_issues, secret_issues, network_issues)


def analyse(doc: Document) -> list[Issue]:
    issues: list[Issue] = []
    for rule in ALL_RULES:
        issues.extend(rule(doc))
    return issues


__all__ = [
    "ALL_RULES",
    "DANGEROUS_CAPABILITIES",
    "Issue",
    "analyse",
    "network_issues",
    "rbac_issues",
    "secret_issues",
    "workload_issues",
]
