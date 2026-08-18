"""Kubernetes posture analysis (WP-D7).

The engine that existed checked seven pod-spec settings on workload manifests. Everything else a
cluster is made of was invisible: the `ClusterRoleBinding` granting `cluster-admin` to a service
account, the `Secret` with a base64'd password committed next to it, the namespace with no
NetworkPolicy, the Ingress serving plaintext. Those are the objects that decide what an attacker who
lands in one pod can reach, which is the question Kubernetes posture is actually about.

It also had two silent failures worth naming, both of which made a repository look clean:

* a Helm chart's `{{ .Values.image }}` is not YAML, so `yaml.safe_load_all` raised and the whole
  file was skipped without a word — and Helm charts are how most people's manifests are written;
* pod-level `securityContext` was ignored, so a correctly-hardened workload was reported as
  three findings per container while a privileged **initContainer** was reported as none.

Rules are pure functions over parsed documents, so each one is tested against the manifest that must
trigger it and the manifest that must not.
"""

from __future__ import annotations
