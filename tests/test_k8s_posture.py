"""Kubernetes posture rules (WP-D7).

Two properties, tested rule by rule: the manifest that must be reported is reported, and the
correctly-configured manifest right next to it is not.

The false-positive half is where the previous engine failed hardest. It ignored pod-level
`securityContext`, so a workload that set `runAsNonRoot: true` once for the whole pod — the way the
Kubernetes documentation tells you to — was reported three times per container, while a privileged
**initContainer**, which runs as root on the node before anything else starts, was reported not at
all.
"""

from __future__ import annotations

import base64

import pytest
from guardian_scanner.k8s.model import (
    PLACEHOLDER,
    Document,
    containers,
    derender,
    effective_security,
    is_template,
    load,
    pod_spec,
)
from guardian_scanner.k8s.rules import analyse


def _docs(text: str, path: str = "manifest.yaml"):
    result = load(path, text)
    assert result.errors == [], result.errors
    return result.documents


def _rules(text: str) -> set[str]:
    fired: set[str] = set()
    for document in _docs(text):
        fired.update(issue.rule for issue in analyse(document))
    return fired


def _issues(text: str) -> list:
    out = []
    for document in _docs(text):
        out.extend(analyse(document))
    return out


# ── loading ───────────────────────────────────────────────────────────────────────────────────────
def test_a_multi_document_file_yields_every_object():
    text = """
apiVersion: v1
kind: Pod
metadata: {name: a}
---
apiVersion: v1
kind: Service
metadata: {name: b}
"""
    assert [d.kind for d in _docs(text)] == ["Pod", "Service"]


def test_a_list_kind_is_flattened():
    text = """
apiVersion: v1
kind: List
items:
  - {apiVersion: v1, kind: Pod, metadata: {name: a}}
  - {apiVersion: v1, kind: Service, metadata: {name: b}}
"""
    assert [d.kind for d in _docs(text)] == ["Pod", "Service"]


def test_a_kubectl_json_export_is_read_the_same_way():
    """The rules do not care whether the object is committed or running."""
    text = ('{"apiVersion":"v1","kind":"List","items":['
            '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"live","namespace":"prod"},'
            '"spec":{"hostNetwork":true,"containers":[{"name":"c","image":"nginx:1"}]}}]}')
    documents = _docs(text, "cluster-export.json")
    assert documents[0].label == "prod/Pod/live"
    assert "host-network" in {issue.rule for issue in analyse(documents[0])}


def test_a_helm_chart_is_analysed_rather_than_skipped():
    """This is the defect that mattered most: `{{ .Values.x }}` is not YAML, the loader raised, the
    engine returned silently, and an entire chart looked clean."""
    text = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: {{ .Values.image.repository }}:{{ .Values.image.tag }}
          securityContext:
            privileged: true
"""
    assert is_template(text) is True
    result = load("chart/templates/deploy.yaml", text)
    assert result.errors == []
    assert result.templated_files == ["chart/templates/deploy.yaml"]
    fired = {issue.rule for doc in result.documents for issue in analyse(doc)}
    assert {"privileged", "host-network"} <= fired


def test_a_templated_value_does_not_produce_a_value_based_finding():
    """The image tag is unknown until Helm renders it. Reporting `not pinned` on a placeholder
    would be inventing a fact."""
    text = """
apiVersion: v1
kind: Pod
metadata: {name: a}
spec:
  containers:
    - name: app
      image: {{ .Values.image }}
"""
    result = load("t.yaml", text)
    fired = {issue.rule for doc in result.documents for issue in analyse(doc)}
    assert "mutable-image" not in fired


def test_template_control_lines_do_not_break_the_document():
    text = """
apiVersion: v1
kind: Pod
metadata: {name: a}
spec:
{{- if .Values.hostNetwork }}
  hostNetwork: true
{{- end }}
  containers:
    - name: app
      image: nginx@sha256:aaa
"""
    assert "host-network" in _rules(text)


def test_a_file_that_cannot_be_parsed_is_reported_not_swallowed():
    result = load("broken.yaml", "kind: Pod\n  bad: [indent\n")
    assert result.documents == []
    assert result.errors and "broken.yaml" in result.errors[0]


def test_an_empty_or_null_document_is_survivable():
    assert _docs("---\n---\nkind: Pod\nmetadata: {name: a}\n")[0].kind == "Pod"
    assert analyse(Document(kind="Pod", name="a", namespace="", body={"kind": "Pod", "spec": None},
                            path="p")) == []


# ── pod-level security context inheritance ────────────────────────────────────────────────────────
SAFE_POD = """
apiVersion: v1
kind: Pod
metadata: {name: hardened}
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      image: nginx@sha256:abc123
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources:
        limits: {cpu: "1", memory: 256Mi}
"""


def test_a_correctly_hardened_pod_produces_nothing():
    """Every setting the rules ask for, set the way the Kubernetes documentation says to set it."""
    assert _rules(SAFE_POD) == set()


def test_pod_level_settings_are_inherited_by_containers():
    """The previous engine looked only at the container, so a pod-level `runAsNonRoot: true` — the
    documented way to set it once — was reported on every container anyway."""
    pod = pod_spec(_docs(SAFE_POD)[0].body)
    security = effective_security(pod, pod["containers"][0])
    assert security["runAsNonRoot"] is True
    assert security["allowPrivilegeEscalation"] is False


def test_a_container_can_override_the_pod_and_that_is_what_counts():
    text = SAFE_POD.replace(
        "      securityContext:\n        allowPrivilegeEscalation: false",
        "      securityContext:\n        runAsNonRoot: false\n        runAsUser: 0\n"
        "        allowPrivilegeEscalation: false",
    )
    assert "run-as-root" in _rules(text)


def test_run_as_non_root_false_with_a_non_zero_uid_is_not_reported():
    """`runAsNonRoot: false` only removes the kubelet's refusal to start a root image; a container
    with `runAsUser: 1000` still runs as 1000. Reporting it would be reporting a field, not a
    fact."""
    text = SAFE_POD.replace(
        "      securityContext:\n        allowPrivilegeEscalation: false",
        "      securityContext:\n        runAsNonRoot: false\n        allowPrivilegeEscalation: false",
    )
    assert "run-as-root" not in _rules(text)


def test_capabilities_are_never_inherited_from_the_pod():
    """`capabilities` is a container-scoped field; a pod-level value does not supply it, and
    treating it as inherited would attribute one container's capabilities to another."""
    pod = {"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}
    assert "capabilities" not in effective_security(pod, {"name": "c"})


# ── workload rules ────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("snippet", "rule"), [
    ("hostNetwork: true", "host-network"),
    ("hostPID: true", "host-process"),
    ("hostIPC: true", "host-IPC"),
])
def test_host_namespace_sharing_is_reported(snippet, rule):
    text = SAFE_POD.replace("  automountServiceAccountToken: false",
                            f"  automountServiceAccountToken: false\n  {snippet}")
    assert rule in _rules(text)


def test_a_privileged_init_container_is_found():
    """An initContainer runs as root on the node before the workload starts. The previous engine
    iterated `containers` only, so this was invisible."""
    text = SAFE_POD + """
  initContainers:
    - name: setup
      image: busybox@sha256:def
      securityContext: {privileged: true, allowPrivilegeEscalation: true}
      resources: {limits: {cpu: "1", memory: 64Mi}}
"""
    issues = [i for i in _issues(text) if i.rule == "privileged"]
    assert issues and "initContainers:setup" in issues[0].subject


def test_a_sensitive_host_path_outranks_an_ordinary_one():
    """`/var/run/docker.sock` is a container escape; `/opt/data` is a mounted directory."""
    def mount(path):
        return SAFE_POD + f"""
  volumes:
    - name: v
      hostPath: {{path: {path}}}
"""
    critical = [i for i in _issues(mount("/var/run/docker.sock")) if i.rule == "host-path"]
    # `/` is matched exactly, never as a prefix — the first version of this rule graded every
    # absolute path as an escape because `"/".rstrip("/")` is the empty string.
    ordinary = [i for i in _issues(mount("/opt/data")) if i.rule == "host-path"]
    assert critical[0].severity == "critical"
    assert ordinary[0].severity == "medium"


def test_dangerous_capabilities_are_graded():
    def with_cap(cap):
        return SAFE_POD.replace("capabilities: {drop: [ALL]}", f"capabilities: {{add: [{cap}]}}")

    assert [i.severity for i in _issues(with_cap("SYS_ADMIN")) if
            i.rule == "dangerous-capabilities"] == ["critical"]
    assert [i.severity for i in _issues(with_cap("NET_RAW")) if
            i.rule == "dangerous-capabilities"] == ["high"]


def test_an_unpinned_image_is_reported_and_a_digest_is_not():
    assert "mutable-image" in _rules(SAFE_POD.replace("nginx@sha256:abc123", "nginx:latest"))
    assert "mutable-image" in _rules(SAFE_POD.replace("nginx@sha256:abc123", "nginx"))
    assert "mutable-image" not in _rules(SAFE_POD)


def test_a_host_port_is_reported():
    text = SAFE_POD + """
      ports:
        - containerPort: 8080
          hostPort: 8080
"""
    assert "host-port" in _rules(text)


def test_the_service_account_token_mount_is_reported_when_not_disabled():
    assert "token-automount" in _rules(SAFE_POD.replace(
        "automountServiceAccountToken: false", "automountServiceAccountToken: true"))


# ── RBAC ──────────────────────────────────────────────────────────────────────────────────────────
def test_a_cluster_admin_binding_is_critical():
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: give-everything}
roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: build-runner, namespace: ci}
"""
    issues = [i for i in _issues(text) if i.rule == "rbac-cluster-admin"]
    assert issues and issues[0].severity == "critical"
    assert "build-runner" in issues[0].subject


def test_a_wildcard_role_is_critical():
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: everything}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""
    assert "rbac-wildcard" in _rules(text)


def test_reading_secrets_across_the_cluster_is_reported():
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
"""
    issues = [i for i in _issues(text) if i.rule == "rbac-escalation"]
    assert issues and issues[0].severity == "critical"


def test_a_binding_to_unauthenticated_is_reported():
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: open}
roleRef: {kind: ClusterRole, name: view, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: Group, name: system:unauthenticated, apiGroup: rbac.authorization.k8s.io}
"""
    assert "rbac-everyone" in _rules(text)


def test_a_binding_to_the_default_service_account_is_reported():
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: b, namespace: app}
roleRef: {kind: Role, name: editor, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: default, namespace: app}
"""
    assert "rbac-default-sa" in _rules(text)


def test_a_narrowly_scoped_role_is_not_reported():
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: config-reader, namespace: app}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get"]
"""
    assert _rules(text) == set()


# ── secrets ───────────────────────────────────────────────────────────────────────────────────────
def test_a_committed_secret_is_reported_without_its_value():
    value = base64.b64encode(b"hunter2-the-real-password").decode()
    text = f"""
apiVersion: v1
kind: Secret
metadata: {{name: db}}
data:
  password: {value}
"""
    issues = [i for i in _issues(text) if i.rule == "manifest-secret"]
    assert issues
    # The finding is about a credential; carrying it into the finding would republish it.
    rendered = f"{issues[0].detail} {issues[0].evidence} {issues[0].title}"
    assert "hunter2" not in rendered
    assert issues[0].evidence["length"] == len("hunter2-the-real-password")


def test_a_placeholder_secret_is_not_reported():
    """Charts ship `password: changeme` for a reason, and reporting it trains people to ignore the
    rule that catches the real one."""
    for placeholder in ("changeme", "CHANGEME", "placeholder", "<your-password>"):
        value = base64.b64encode(placeholder.encode()).decode()
        text = f"apiVersion: v1\nkind: Secret\nmetadata: {{name: s}}\ndata:\n  password: {value}\n"
        assert _rules(text) == set(), placeholder


def test_a_credential_in_a_configmap_is_reported():
    text = """
apiVersion: v1
kind: ConfigMap
metadata: {name: app-config}
data:
  DATABASE_PASSWORD: s3cret-value-here
  LOG_LEVEL: debug
"""
    issues = [i for i in _issues(text) if i.rule == "configmap-credential"]
    assert len(issues) == 1
    assert issues[0].subject == "DATABASE_PASSWORD"
    assert "s3cret" not in f"{issues[0].detail}{issues[0].evidence}"


def test_a_literal_credential_env_var_is_reported():
    text = """
apiVersion: v1
kind: Pod
metadata: {name: a}
spec:
  containers:
    - name: app
      image: nginx@sha256:abc
      env:
        - {name: API_KEY, value: live-key-value}
        - {name: LOG_LEVEL, value: debug}
"""
    issues = [i for i in _issues(text) if i.rule == "env-credential"]
    assert len(issues) == 1
    assert "live-key-value" not in f"{issues[0].detail}{issues[0].evidence}"


def test_a_secret_reference_is_not_a_finding():
    text = """
apiVersion: v1
kind: Pod
metadata: {name: a}
spec:
  containers:
    - name: app
      image: nginx@sha256:abc
      env:
        - name: API_KEY
          valueFrom: {secretKeyRef: {name: api, key: key}}
"""
    assert "env-credential" not in _rules(text)


# ── network and exposure ──────────────────────────────────────────────────────────────────────────
def test_a_nodeport_service_is_reported():
    text = "apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec:\n  type: NodePort\n"
    assert "service-exposed" in _rules(text)


def test_a_clusterip_service_is_not():
    text = "apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec:\n  type: ClusterIP\n"
    assert _rules(text) == set()


def test_an_ingress_without_tls_is_reported():
    text = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web}
spec:
  rules: [{host: app.example.com}]
"""
    assert "ingress-no-tls" in _rules(text)


def test_an_ingress_with_tls_is_not():
    text = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web}
spec:
  tls: [{hosts: [app.example.com], secretName: web-cert}]
  rules: [{host: app.example.com}]
"""
    assert _rules(text) == set()


def test_a_default_deny_network_policy_is_not_a_finding():
    """This repository's own reference policies start with exactly this object."""
    text = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny-all, namespace: guardian}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""
    assert _rules(text) == set()


def test_a_policy_that_allows_everything_is_reported():
    text = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-all, namespace: app}
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - {}
"""
    assert "netpol-open-ingress" in _rules(text)


# ── mechanics ─────────────────────────────────────────────────────────────────────────────────────
def test_derender_keeps_the_structure():
    rendered = derender("image: {{ .Values.image }}\nname: app\n")
    assert PLACEHOLDER in rendered
    assert "name: app" in rendered


def test_containers_includes_every_section():
    pod = {"containers": [{"name": "a"}], "initContainers": [{"name": "b"}],
           "ephemeralContainers": [{"name": "c"}]}
    assert [name for _, c in containers(pod) for name in [c["name"]]] == ["a", "b", "c"]


def test_every_issue_carries_a_control_and_a_remediation():
    text = SAFE_POD.replace("automountServiceAccountToken: false", "hostNetwork: true")
    for issue in _issues(text):
        assert issue.control
        assert issue.cwe.startswith("CWE-")
        assert len(issue.remediation) > 10
        assert issue.severity in ("critical", "high", "medium", "low", "info")
