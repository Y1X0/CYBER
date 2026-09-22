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
| **RBAC binding→role reach** (aggregate) | `rbac-binding-reach` — a binding's subject reaches a dangerous grant via the resolved role; `rbac-unresolved-role` — coverage finding when the `roleRef` is out of scan scope | CIS 5.1.1 |

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

### The second aggregate pass — RBAC binding→role reach (`rbac-binding-reach`)

The per-document RBAC rules grade a **role** or a **binding in isolation**: a wildcard role is
flagged where it is defined, a `cluster-admin` binding where it is written. What neither can see is
what a *subject* actually reaches — a binding does not carry the role's verbs, and a role does not
know who is bound to it. `rbac_reachability()` runs once over the whole set to join them:

1. **Index** every `Role`/`ClusterRole` by `(kind[, namespace], name)` with the verbs+resources it
   grants.
2. For each `RoleBinding`/`ClusterRoleBinding`, **resolve** its `roleRef` to that index and grade
   the subject's effective reach **from the resolved role's actual grants** — never the binding
   alone. A finding (HIGH) fires when the grants include any of: read access to **Secrets**
   (`get`/`list`, CWE-522, credential theft); **exec/attach** into pods (code execution); the
   ability to **escalate** — writing `rolebindings`/`clusterrolebindings`, or the `bind`/`escalate`
   verb (CWE-269); **wildcard** verbs or resources; or the **impersonate** verb. A binding to a
   harmless role (e.g. `view` on configmaps) does **not** fire.
3. A `roleRef` that resolves to **neither a scanned role nor a well-known built-in** yields a
   **coverage finding** (`rbac-unresolved-role`, INFO, `scan-coverage`) — "role X referenced by
   binding Y is not in scan scope" — never a silent pass and never a guessed grant.

Only the four **well-known built-in ClusterRoles** are resolved by name when absent from the
manifests — `cluster-admin` (wildcard), `admin` and `edit` (secrets + exec; `admin` also
rolebindings), and `view` (read-only, no secrets/exec, so it never fires); the finding records
`resolved_via: builtin`. Anything else unresolved is a coverage finding. Each finding is anchored to
the **binding + resolved role + subject**, and the evidence names the verbs/resources that triggered
it. Results are emitted in a stable, order-independent order.

**Not inferred:** "create/update pods + use a *privileged* service account" cannot be judged from
RBAC alone (whether a given SA is privileged is not in the binding), so the escalation trigger keys
on the determinable part — writing role bindings, or the `bind`/`escalate` verb.

## Security model

- Static only: no cluster contact, no credential, no network, no execution.
- Helm templates are analysed structurally; a rule that depends on a templated *value* declines to
  conclude (no invented facts), and templated findings are emitted at lower confidence.
- Secret values are never carried into a finding — only their key and length.

## Not in this batch (deliberately deferred)

- **Privileged-SA escalation via pod creation**: judging whether a subject that can create pods can
  thereby assume a *privileged* service account needs to know which SAs are privileged — not
  determinable from a binding alone — so `rbac-binding-reach` grades the escalation path on the
  determinable part (writing role bindings / the `bind`/`escalate` verb) rather than guessing.
- **`aggregationRule` ClusterRoles**: a ClusterRole whose grants are aggregated from labelled
  sub-roles is resolved by its own explicit `rules` only; the label-selector aggregation is not
  expanded (it would require matching every ClusterRole's labels, and an unexpanded aggregate is not
  a guessed grant).
