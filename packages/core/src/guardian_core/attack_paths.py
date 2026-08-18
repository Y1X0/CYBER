"""Chaining findings into attack paths (WP-E4).

`attack_graph.attack_paths` answers "can the internet reach a host that has a finding". That is a
real answer and it is one hop long: every path ends at the first finding it touches. What an
attacker does next — and what a defender is actually afraid of — is the part after that. A remote
code execution on a public web host is not the incident; the incident is that from there, a
credential in the repository the host builds from opens the database.

Continuing past the first finding needs one thing the platform never modelled: what a finding
**grants**. A path traversal grants the ability to read files; a command injection grants execution;
a committed credential grants authentication somewhere else; a privileged container grants the node.
Each of those is a capability, each capability satisfies some other finding's precondition, and a
chain is a sequence where every step's precondition is met by the step before it.

Two rules keep this from becoming fiction, which is the failure mode of every attack-path feature:

1. **Every hop is an edge the data actually has.** Movement between assets happens only along the
   graph the discovery pipeline built. Nothing is inferred from "these look related".
2. **Every hop is a finding that was actually reported**, with its own evidence. A chain is an
   ordering of observations, never a new claim; if the reader disagrees with one hop, they can go
   and read the finding it names.

Deterministic throughout: capabilities come from a fixed table, ordering is stable, and no score
here is produced by a model.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Capability(str, Enum):
    """What holding a position gets you.

    Deliberately coarse. A finer taxonomy (ATT&CK technique level) would be more precise about the
    *how* and no more accurate about the *whether*, and the whether is what a chain asserts.
    """

    NETWORK_ACCESS = "network_access"          # can reach the service over the network
    CODE_EXECUTION = "code_execution"          # can run code on the host
    CREDENTIAL_ACCESS = "credential_access"    # holds a credential usable elsewhere
    DATA_ACCESS = "data_access"                # can read data the service holds
    PRIVILEGE_ESCALATION = "privilege_escalation"  # more rights on the same host/account
    LATERAL_MOVEMENT = "lateral_movement"      # can act on a neighbouring host/account


@dataclass(frozen=True)
class Profile:
    """What a class of finding requires and grants."""

    requires: frozenset[Capability]
    grants: frozenset[Capability]
    # How reliably an attacker converts this into the granted capability, 0–100. Deterministic and
    # conservative: it grades the *step*, not the attacker.
    reliability: int
    rationale: str


# Capabilities that come with others by definition. Kept to what is true without argument: if you
# can run code on a host, you can read what that process can read — which is why "RCE on the web
# server, then the credential committed in its repository" is a chain and not two unrelated
# findings. Nothing else is implied, because every implication added here is an assertion the
# customer cannot check.
IMPLIES: dict[Capability, frozenset[Capability]] = {
    Capability.CODE_EXECUTION: frozenset({Capability.DATA_ACCESS}),
}


def expand(capabilities: frozenset[Capability]) -> frozenset[Capability]:
    """`capabilities` plus everything they imply."""
    result = set(capabilities)
    for capability in capabilities:
        result |= IMPLIES.get(capability, frozenset())
    return frozenset(result)


_NET = frozenset({Capability.NETWORK_ACCESS})
_NONE: frozenset[Capability] = frozenset()

# Keyed by CWE, because that is the one identifier every engine already sets and the one a reader
# can check. Category is the fallback for findings without one.
_BY_CWE: dict[str, Profile] = {
    # ── execution ────────────────────────────────────────────────────────────────────────────────
    "CWE-78": Profile(_NET, frozenset({Capability.CODE_EXECUTION}), 90,
                      "OS command injection runs an attacker's command on the host"),
    "CWE-94": Profile(_NET, frozenset({Capability.CODE_EXECUTION}), 90,
                      "code injection runs attacker-supplied code in the application"),
    "CWE-502": Profile(_NET, frozenset({Capability.CODE_EXECUTION}), 80,
                       "unsafe deserialization commonly reaches code execution"),
    "CWE-1336": Profile(_NET, frozenset({Capability.CODE_EXECUTION}), 85,
                        "server-side template injection evaluates attacker input"),
    "CWE-434": Profile(_NET, frozenset({Capability.CODE_EXECUTION}), 70,
                       "an unrestricted upload becomes execution when the file is served"),
    # ── data ─────────────────────────────────────────────────────────────────────────────────────
    "CWE-89": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 85,
                      "SQL injection reads the database the application uses"),
    "CWE-22": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 80,
                      "path traversal reads files outside the intended directory"),
    "CWE-639": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 85,
                       "broken object level authorization reads other tenants' records"),
    "CWE-213": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 60,
                       "the response carries fields the client was not meant to receive"),
    "CWE-918": Profile(_NET, frozenset({Capability.NETWORK_ACCESS, Capability.LATERAL_MOVEMENT}),
                       75, "server-side request forgery reaches services the attacker cannot"),
    # ── credentials ──────────────────────────────────────────────────────────────────────────────
    "CWE-798": Profile(frozenset({Capability.DATA_ACCESS}),
                       frozenset({Capability.CREDENTIAL_ACCESS}), 95,
                       "a hardcoded credential authenticates wherever it is valid"),
    "CWE-522": Profile(frozenset({Capability.DATA_ACCESS}),
                       frozenset({Capability.CREDENTIAL_ACCESS}), 80,
                       "the credential is insufficiently protected where it is stored"),
    "CWE-256": Profile(frozenset({Capability.DATA_ACCESS}),
                       frozenset({Capability.CREDENTIAL_ACCESS}), 80,
                       "the credential is stored in plaintext"),
    "CWE-306": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 90,
                       "the function requires no authentication at all"),
    "CWE-287": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 70,
                       "authentication can be bypassed"),
    "CWE-308": Profile(frozenset({Capability.CREDENTIAL_ACCESS}),
                       frozenset({Capability.DATA_ACCESS}), 70,
                       "a stolen password is sufficient with no second factor"),
    # ── privilege and movement ───────────────────────────────────────────────────────────────────
    "CWE-269": Profile(frozenset({Capability.CREDENTIAL_ACCESS}),
                       frozenset({Capability.PRIVILEGE_ESCALATION,
                                  Capability.LATERAL_MOVEMENT}), 85,
                       "the principal's permissions exceed its purpose"),
    "CWE-250": Profile(frozenset({Capability.CODE_EXECUTION}),
                       frozenset({Capability.PRIVILEGE_ESCALATION,
                                  Capability.LATERAL_MOVEMENT}), 80,
                       "the workload runs with privileges that reach the node"),
    "CWE-284": Profile(_NONE, frozenset({Capability.NETWORK_ACCESS}), 90,
                       "access control does not restrict who can reach the service"),
    "CWE-668": Profile(frozenset({Capability.CODE_EXECUTION}),
                       frozenset({Capability.LATERAL_MOVEMENT}), 75,
                       "the resource is exposed to a sphere that should not have it"),
    "CWE-732": Profile(_NONE, frozenset({Capability.DATA_ACCESS}), 80,
                       "permissions allow access the resource's owner did not intend"),
    # ── transport and disclosure ─────────────────────────────────────────────────────────────────
    "CWE-319": Profile(frozenset({Capability.NETWORK_ACCESS}),
                       frozenset({Capability.CREDENTIAL_ACCESS}), 40,
                       "credentials cross the network in cleartext for anyone positioned to read"),
    "CWE-200": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 40,
                       "information is disclosed to an unauthorized actor"),
    "CWE-79": Profile(_NET, frozenset({Capability.CREDENTIAL_ACCESS}), 55,
                      "cross-site scripting steals the session of whoever views the page"),
}

# Fallbacks for findings without a CWE. Category is set by every engine.
_BY_CATEGORY: dict[str, Profile] = {
    "secret": _BY_CWE["CWE-798"],
    "injection": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 70,
                         "the input reaches an interpreter"),
    "vuln-dep": Profile(_NET, frozenset({Capability.CODE_EXECUTION}), 50,
                        "a known-vulnerable component is in the running code path"),
    "cloud-misconfig": Profile(_NONE, frozenset({Capability.DATA_ACCESS}), 60,
                               "the cloud resource is configured more openly than intended"),
    "k8s-misconfig": Profile(frozenset({Capability.CODE_EXECUTION}),
                             frozenset({Capability.PRIVILEGE_ESCALATION}), 70,
                             "the workload's settings weaken the boundary around it"),
    "api-authorization": _BY_CWE["CWE-639"],
    "web-misconfig": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 40,
                             "the service's configuration exposes more than intended"),
    "insecure-code": Profile(_NET, frozenset({Capability.DATA_ACCESS}), 50,
                             "the code path handles untrusted input unsafely"),
}

# A KEV-listed or weaponized vulnerability is not a *different* step; it is the same step with the
# uncertainty removed, so it raises reliability rather than inventing a capability.
_EXPLOIT_BONUS = {"high": 10, "functional": 8, "poc": 3, "unproven": 0}


@dataclass(frozen=True)
class FindingView:
    """A finding as the chainer sees it. Only fields the deterministic pipeline produced."""

    id: str
    asset_id: str
    title: str
    severity: str
    risk_score: int = 0
    category: str = ""
    cwe_id: str | None = None
    kev: bool = False
    exploit_maturity: str | None = None
    # The graph node this finding hangs off, when the projector made one.
    node_id: str = ""

    def profile(self) -> Profile | None:
        return profile_for(self)


def profile_for(finding: FindingView) -> Profile | None:
    """What this finding requires and grants, or None when nothing is claimed.

    Returning None is the important case: a finding whose class does not map to a capability is
    still a finding — it simply cannot be used as a *step*, and inventing a capability so that it
    can is how attack-path features start describing attacks that are not possible.
    """
    base = _BY_CWE.get(str(finding.cwe_id or "")) or _BY_CATEGORY.get(finding.category)
    if base is None:
        return None
    bonus = _EXPLOIT_BONUS.get(str(finding.exploit_maturity or ""), 0) + (10 if finding.kev else 0)
    return Profile(
        requires=base.requires,
        grants=base.grants,
        reliability=min(99, base.reliability + bonus),
        rationale=base.rationale,
    )


# ── chains ────────────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Step:
    """One hop: a finding, on an asset, granting something."""

    finding_id: str
    asset_id: str
    node_id: str
    title: str
    severity: str
    cwe_id: str | None
    grants: tuple[str, ...]
    reliability: int
    rationale: str


@dataclass(frozen=True)
class Chain:
    """A sequence of observed findings an attacker could use in order."""

    steps: tuple[Step, ...]
    entry_node_id: str = ""
    entry_key: str = ""
    # Product of the steps' reliabilities, 0–100. Multiplicative because a chain is only as good as
    # every one of its links, and a five-step chain of coin flips is not a 50% chain.
    likelihood: int = 0
    impact: int = 0
    score: int = 0

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(g for step in self.steps for g in step.grants)


_IMPACT_BY_CAPABILITY = {
    Capability.CODE_EXECUTION: 90,
    Capability.PRIVILEGE_ESCALATION: 85,
    Capability.CREDENTIAL_ACCESS: 80,
    Capability.LATERAL_MOVEMENT: 75,
    Capability.DATA_ACCESS: 70,
    Capability.NETWORK_ACCESS: 30,
}


def score_chain(steps: tuple[Step, ...], *, asset_criticality: str = "medium") -> tuple[int, int,
                                                                                        int]:
    """(likelihood, impact, score), all deterministic.

    Likelihood multiplies the steps because every link has to hold. Impact is the worst capability
    the chain ends up holding, raised by the criticality of the asset it ends on — a chain into a
    development sandbox and the same chain into the billing database are not the same finding.
    """
    if not steps:
        return 0, 0, 0
    likelihood = 1.0
    for step in steps:
        likelihood *= step.reliability / 100.0
    likelihood_int = max(1, round(likelihood * 100))

    granted = {Capability(g) for step in steps for g in step.grants}
    impact = max((_IMPACT_BY_CAPABILITY.get(c, 0) for c in granted), default=0)
    impact += {"critical": 10, "high": 5, "medium": 0, "low": -10}.get(asset_criticality, 0)
    impact = max(0, min(100, impact))

    # Length is a modifier, not a multiplier: a two-step chain is materially more likely to be
    # walked than a five-step one, but the five-step one is not worthless.
    length_penalty = min(15, (len(steps) - 1) * 5)
    score = max(0, min(100, round((likelihood_int * 0.4) + (impact * 0.6)) - length_penalty))
    return likelihood_int, impact, score


@dataclass
class ChainResult:
    chains: tuple[Chain, ...] = ()
    truncated: bool = False
    # Findings that could not be used as a step, and why. Reported rather than dropped: "we found
    # no attack path" and "we could not reason about half your findings" are different statements.
    unmapped: tuple[str, ...] = ()


MAX_CHAIN_LENGTH = 4
MAX_CHAINS = 50


def build_chains(
    findings: list[FindingView],
    *,
    reachable: dict[str, set[str]],
    entry_assets: set[str],
    entry_keys: dict[str, str] | None = None,
    criticality: dict[str, str] | None = None,
    max_length: int = MAX_CHAIN_LENGTH,
    max_chains: int = MAX_CHAINS,
) -> ChainResult:
    """Chain findings into ordered attack paths.

    `reachable` is the adjacency the discovery graph actually contains: asset → the assets it can
    reach. Movement happens only along it. `entry_assets` are the assets an unauthenticated attacker
    can reach from the internet, which is where a chain has to start — a chain that begins on an
    internal host describes an attacker who is already inside, and that is a different question.
    """
    entry_keys = entry_keys or {}
    criticality = criticality or {}

    by_asset: dict[str, list[FindingView]] = {}
    unmapped: list[str] = []
    for finding in sorted(findings, key=lambda f: (-f.risk_score, f.id)):
        if profile_for(finding) is None:
            unmapped.append(finding.id)
            continue
        by_asset.setdefault(finding.asset_id, []).append(finding)

    chains: list[Chain] = []
    truncated = False

    for entry in sorted(entry_assets):
        starts = [f for f in by_asset.get(entry, [])
                  if not (profile_for(f).requires - {Capability.NETWORK_ACCESS})]  # type: ignore[union-attr]
        for start in starts:
            for chain in _extend(start, entry, by_asset, reachable, max_length):
                if len(chains) >= max_chains:
                    truncated = True
                    break
                last_asset = chain[-1].asset_id
                likelihood, impact, score = score_chain(
                    chain, asset_criticality=criticality.get(last_asset, "medium"))
                chains.append(Chain(steps=chain, entry_node_id=entry,
                                    entry_key=entry_keys.get(entry, entry),
                                    likelihood=likelihood, impact=impact, score=score))
            if truncated:
                break
        if truncated:
            break

    # Worst first, then longest, then by id so the order never depends on dictionary iteration.
    chains.sort(key=lambda c: (-c.score, -c.length, c.steps[0].finding_id))
    return ChainResult(chains=tuple(chains), truncated=truncated, unmapped=tuple(sorted(unmapped)))


def _extend(
    start: FindingView, asset: str, by_asset: dict[str, list[FindingView]],
    reachable: dict[str, set[str]], max_length: int,
) -> list[tuple[Step, ...]]:
    """Every chain beginning at `start`, depth-first, without revisiting a finding."""
    results: list[tuple[Step, ...]] = []

    def walk(steps: tuple[Step, ...], held: frozenset[Capability], current_asset: str,
             used: frozenset[str]) -> None:
        results.append(steps)
        if len(steps) >= max_length:
            return
        # The next hop is a finding on this asset or on one this asset can actually reach.
        candidates: list[tuple[str, FindingView]] = []
        for candidate in by_asset.get(current_asset, []):
            candidates.append((current_asset, candidate))
        if Capability.LATERAL_MOVEMENT in held or Capability.CODE_EXECUTION in held or \
                Capability.NETWORK_ACCESS in held:
            for neighbour in sorted(reachable.get(current_asset, set())):
                for candidate in by_asset.get(neighbour, []):
                    candidates.append((neighbour, candidate))

        for next_asset, candidate in candidates:
            if candidate.id in used:
                continue
            profile = profile_for(candidate)
            if profile is None or not profile.requires <= held:
                continue
            step = _step(candidate, next_asset, profile)
            if not (expand(profile.grants) - held):
                # Adds nothing new. Recording it would inflate the chain without changing what the
                # attacker can do, and every extra hop makes the path harder to check.
                continue
            walk(steps + (step,), expand(held | profile.grants), next_asset,
                 used | {candidate.id})

    first = profile_for(start)
    if first is None:
        return []
    walk((_step(start, asset, first),),
         expand(frozenset({Capability.NETWORK_ACCESS}) | first.grants), asset,
         frozenset({start.id}))
    # Only chains worth calling chains: a single step is already reported as a finding.
    return [chain for chain in results if len(chain) >= 2]


def _step(finding: FindingView, asset: str, profile: Profile) -> Step:
    return Step(
        finding_id=finding.id, asset_id=asset, node_id=finding.node_id, title=finding.title,
        severity=finding.severity, cwe_id=finding.cwe_id,
        grants=tuple(sorted(c.value for c in profile.grants)),
        reliability=profile.reliability, rationale=profile.rationale,
    )


def describe(chain: Chain) -> str:
    """One sentence per hop, in order. The narrative a report prints and a reader can check."""
    parts = [f"An attacker who can reach {chain.entry_key or 'the entry point'}"]
    for index, step in enumerate(chain.steps):
        verb = "uses" if index == 0 else "then uses"
        parts.append(f"{verb} `{step.title}` ({step.cwe_id or step.severity}) — {step.rationale}")
    return "; ".join(parts) + "."


__all__ = [
    "MAX_CHAINS",
    "MAX_CHAIN_LENGTH",
    "IMPLIES",
    "Capability",
    "Chain",
    "ChainResult",
    "FindingView",
    "Profile",
    "Step",
    "build_chains",
    "describe",
    "expand",
    "profile_for",
    "score_chain",
]
