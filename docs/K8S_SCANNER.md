# Kubernetes scanner (manifests + cluster export)

**Status: STATIC ONLY — the `k8s` engine (`EngineKey.K8S`) reviews Kubernetes objects it is given.
It never contacts an API server, holds no cluster credential, and needs no authorization gate
(`requires_authorization = False`).**

## What it reads

`K8sEngine` (`guardian_scanner/engines/k8s_engine.py`) runs `guardian_scanner.k8s`'s rules over every
object it can find, from three sources (all offline):

- inline manifest content;
- a `kubectl get -o json` **cluster export** placed in the asset config (`k8s_export`) — the same
  rules apply to what is running as to what is committed;
- every `*.yaml`/`*.yml`/`*.json` under a workspace/repo (Helm templates are rendered to a
  placeholder so structure survives; a file that will not parse is **reported**, not skipped).

Objects arrive as single documents, multi-document streams, `List` kinds, and `items` arrays — all
the same to a rule.

## Checks

Rules are pure functions of one parsed object, except the NetworkPolicy-coverage rule, which is an
**aggregate pass over the whole document set** (see below). Each finding carries a CIS/NSA-CISA/PSS
control and a remediation.

| Group | Rule(s) | Control |
|---|---|---|
| Workload isolation | `host-network`, `host-process`, `host-IPC`, `host-path` (critical for docker.sock/proc/…), `privileged`, `privilege-escalation`, `host-port` | CIS 5.2.x |
| **Run-as-root** | `run-as-root` — fires unless `runAsNonRoot: true` **or** a non-zero `runAsUser` is enforced (pod-level context is inherited) | CIS 5.2.6 |
| **Seccomp** | `seccomp-profile` — no `seccompProfile.type: RuntimeDefault`/`Localhost` (field or legacy pod annotation), or an explicit `Unconfined` | CIS 5.7.2 / PSS-restricted |
| **AppArmor** | `apparmor-unconfined` — an explicit `unconfined` override (1.30+ `appArmorProfile` field or the legacy per-container annotation). *Absence is not flagged* — PSS-baseline only forbids `unconfined`, it does not require AppArmor be set | PSS-baseline / NSA-CISA |
| **Capabilities** | `dangerous-capabilities` (SYS_ADMIN/NET_RAW/…), and `capabilities-drop-all` — every container must `drop: ["ALL"]` (skipped when already `privileged`) | CIS 5.2.8 / PSS-restricted |
| Filesystem / limits | `writable-root`, `no-resource-limits` | CIS 5.2.11 / 5.7.3 |
| **Service-account token** | `token-automount` — the API token is auto-mounted without an explicit `automountServiceAccountToken: false` | CIS 5.1.6 |
| **Image provenance** | `mutable-image` — the image is **not pinned by digest** (`@sha256:…`); any tag, including a specific version, is mutable | CIS 5.5.1 |
| RBAC | `rbac-wildcard`, `rbac-escalation` (secrets/exec/bindings), `rbac-cluster-admin`, `rbac-everyone` (anonymous/authenticated groups), `rbac-default-sa` | CIS 5.1.x |
| Secrets in manifests | `manifest-secret`, `configmap-credential`, `env-credential` (value never persisted into the finding) | CIS 5.4.1 |
| Exposure | `service-exposed` (NodePort/LoadBalancer), `ingress-no-tls` | CIS 5.7.4 / NSA-CISA |
| Network policy | `netpol-open-ingress`/`netpol-open-egress` (empty peer list); default-deny is correctly ignored | NSA-CISA |
| **Missing NetworkPolicy** (aggregate) | `netpol-missing` — a namespace runs workloads but its pods are selected by **no** NetworkPolicy, so traffic is default-allow | CIS 5.3.2 / NSA-CISA |

The rows in **bold** are the PSS-restricted / zero-trust batch. `run-as-root` and `token-automount`
already enforced their controls; the seccomp, AppArmor, capabilities-drop-ALL, digest-pinning and
missing-NetworkPolicy checks complete the profile.

### The aggregate pass (`netpol-missing`)

Kubernetes networking is **default-allow**: a pod selected by no NetworkPolicy can be reached by
anything in the cluster and can reach anything. Whether a namespace is governed is a question no
single manifest answers, so `namespace_issues()` runs once over the whole document set: it groups
workloads and NetworkPolicies by namespace and flags a namespace whose workloads are selected by no
policy. A policy selects a pod when its `podSelector` is empty (all pods) or its `matchLabels` are a
subset of the pod-template labels; `matchExpressions` is treated as covering (fail-safe toward
silence, never inventing a gap). Each finding is anchored to a representative uncovered workload so
it points at a real file. This is the engine's first cross-resource rule.

## Security model

- Static only: no cluster contact, no credential, no network, no execution.
- Helm templates are analysed structurally; a rule that depends on a templated *value* declines to
  conclude (no invented facts), and templated findings are emitted at lower confidence.
- Secret values are never carried into a finding — only their key and length.

## Not in this batch (deliberately deferred)

- **RBAC binding→role reach**: bindings are still graded in isolation (`rbac-cluster-admin`,
  `rbac-default-sa`, `rbac-everyone`) rather than by resolving each `roleRef` to the verbs it grants.
  This is the documented next step, not part of the PSS-restricted batch.
