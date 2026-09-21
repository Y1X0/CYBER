"""Cross-engine correlation (WP-E1).

Nine engines report on the same estate and nothing joined their answers. The result was a report
that was both repetitive and incomplete: three engines can find the same hardcoded credential — in
the source, in the git history, in an image layer — and a customer saw three criticals for one
problem, while the two findings that together mean *the credential is publicly retrievable* sat in
different sections with nothing saying so.

Three kinds of group, because they mean different things and deserve different treatment:

* **duplicate** — several engines saw one issue. The group exists so a report shows it once, with
  every engine's evidence attached. Nothing is deleted; the members stay individually inspectable,
  because a scanner that quietly drops one of three corroborating observations has destroyed the
  thing a customer would use to check the claim.
* **corroboration** — independent engines reached the same conclusion by different routes. A SAST
  taint path to a SQL sink and a DAST injection finding on the same application are not one finding;
  they are two, and together they turn "suspected" into "confirmed".
* **chain** — findings that are individually moderate and jointly serious. An exposed `.git`
  directory is a medium. A credential in that repository is a high. Together they mean an attacker
  already has the credential, and that is the finding a customer needs to see first.

Every rule is deterministic and every escalation is written into the group's rationale, for the same
reason the risk engine records its arithmetic: an escalation a customer cannot trace is one they
learn to ignore.

CONFIDENCE (WP-E1, slice 1). Each group carries a `CorrelationConfidence` describing how strongly
the *relationship* is evidenced — a separate question from how real or how severe the individual
findings are. The tier is derived from the kind of evidence the rule actually matched on, and NEVER
from member count, member severity, or `Finding.confidence`:

    rule                        relationship proven by            tier
    ─────────────────────────── ───────────────────────────────── ───────────────
    same-secret (keyed identity) same keyed secret identity (HMAC CONFIRMED
                                of the raw secret) — same credential
    same-secret (redaction only) same LOSSY display redaction —    STRONG_EVIDENCE (a redaction
                                legacy/gitleaks, no keyed identity  can collide across secrets)
    same-secret (position only) same path:line, no value          STRONG_EVIDENCE
    same-cve-on-asset           same CVE id + same asset_id       STRONG_EVIDENCE
    injection-corroborated      same CWE, static + dynamic, same  STRONG_EVIDENCE
                                customer (not proven same sink)
    shipped-and-running         same CVE shipped + running, keyed POTENTIAL — the running service
                                on customer only (not same asset)  is not proven the shipped one
    exposed-repository-secret   exposure + a secret, keyed on     POTENTIAL — the secret is not
                                customer only (not same repo)      proven to live in the exposure

The two "chain" rules are deliberately POTENTIAL, not CONFIRMED: their evidence ties only a weak key
(the customer), so the chain is plausible but unproven. Forcing them to CONFIRMED would be the
manufactured-tier failure this model exists to prevent. A future rule must state its own tier from
its own evidence — nothing inherits a tier from `kind`.

ORDERED MEMBERS + PER-EDGE EVIDENCE (WP-E1, slice 2). A group now also carries:

* ``ordered`` — a deterministic PRESENTATION order (the primary first, then the remaining members by
  their finding-id string). It is stable across runs and independent of input iteration or database
  insertion order. It is NOT a causal or attack sequence: an ordered list of correlated findings is
  not an attack path, and E1 deliberately does not assert directionality. The future E4→E1 bridge
  owns real ordered attack paths; this ordinal only makes a report render the same way every time.
* ``edges`` — the pairwise RELATIONSHIPS the rule actually evidenced, each with its own rationale
  and its own ``CorrelationConfidence``. Every edge is anchored at the primary (``source``) purely
  so each non-primary member has one incoming edge to read; ``source``→``dest`` is NOT "source
  caused dest". Each rule owns its edges — there is no generic fallback that stamps one rationale on
  every rule — and an edge's tier follows the evidence for THAT pair, which is why a corroboration
  group's cross-side edge (static⟷dynamic) can be STRONG_EVIDENCE while a same-side edge between two
  static findings is only POTENTIAL.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from guardian_common.logging import get_logger
from guardian_core.enums import CorrelationConfidence, Severity
from guardian_db.models import Finding, FindingCorrelation, FindingCorrelationMember
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.correlation")

MAX_FINDINGS = 20_000
MAX_GROUP_SIZE = 200

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Injection classes where a static path and a dynamic observation are genuinely independent
# evidence of one weakness.
_INJECTION_CWES = {"CWE-89", "CWE-79", "CWE-78", "CWE-95", "CWE-22", "CWE-918", "CWE-1336"}

_SECRET_ENGINES = {"secrets", "sast", "container", "iac"}
_DEPENDENCY_ENGINES = {"sca", "container"}
_DYNAMIC_ENGINES = {"dast", "api", "web_checks"}


@dataclass
class MemberEdge:
    """A pairwise RELATIONSHIP between two members of one correlation (WP-E1, slice 2).

    ``source``→``dest`` is an anchoring convention, NOT causation: every edge is anchored at the
    group's primary so each non-primary member has exactly one incoming edge to read. E1 does not
    assert that the source caused, enabled, or precedes the destination — that directional, causal
    reading belongs to attack paths (the future E4→E1 bridge), deliberately not here.

    ``rationale`` describes the evidence for the pair; ``confidence`` is that pair's own
    ``CorrelationConfidence``, following the evidence — never the members' severity or count.
    """

    source: uuid.UUID
    dest: uuid.UUID
    rationale: str
    confidence: CorrelationConfidence


@dataclass
class Group:
    """A correlation before it is persisted."""

    rule: str
    kind: str
    title: str
    description: str
    members: list[uuid.UUID]
    primary: uuid.UUID
    severity: Severity
    risk_score: int
    # How strongly the RELATIONSHIP is evidenced (not the members' own severity/confidence). Every
    # rule sets it explicitly from the evidence it matched on — see the module docstring's table.
    confidence: CorrelationConfidence
    rationale: list[str] = field(default_factory=list)
    customer_id: uuid.UUID | None = None
    # Deterministic PRESENTATION order (primary first, then remaining members by id string). Filled
    # by __post_init__ when a rule does not set it. NOT a causal/attack sequence.
    ordered: list[uuid.UUID] = field(default_factory=list)
    # Pairwise relationships the rule evidenced, each anchored at the primary. Each rule owns these.
    edges: list[MemberEdge] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.ordered:
            self.ordered = _presentation_order(self.primary, self.members)

    def fingerprint(self) -> str:
        """Stable across runs, so a re-scan updates the group rather than making a second one."""
        blob = self.rule + "|" + "|".join(sorted(str(m) for m in self.members))
        return hashlib.sha256(blob.encode()).hexdigest()[:32]


def _severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def _escalate(severity: Severity, steps: int = 1) -> Severity:
    index = min(len(_SEVERITY_ORDER) - 1, _SEVERITY_ORDER.index(severity) + steps)
    return _SEVERITY_ORDER[index]


def _secret_identity(finding: Finding) -> tuple[str, str, str] | None:
    """What makes two secret findings the same secret, HOW we know, and a human-safe label.

    Returns ``(bucket_key, basis, display)`` where basis is, strongest first:

    * ``"identity"`` — the keyed, one-way secret-correlation identity matched. This is derived from
      the RAW secret at detection time (``Finding.secret_correlation_id``), so a match means the
      same credential — the basis that earns CONFIRMED.
    * ``"value"`` — only the lossy display *redaction* matched. A redaction is lossy on purpose (two
      different secrets of equal length ≤ 8, or sharing first-two/last-two/length, redact to one
      string), so this is STRONG_EVIDENCE at most, never CONFIRMED. It covers findings created
      before the identity existed, and gitleaks findings pre-redacted so no raw value is available.
    * ``"position"`` — only file:line matched (no value at all). STRONG_EVIDENCE.

    ``None`` when nothing is available. ``bucket_key`` is namespaced by basis so the three bases can
    never share a bucket. ``display`` is a human-safe snippet for the description — the redacted
    value for the value basis, and empty for the others (the keyed identity is internal and must
    never appear in customer-visible text).
    """
    identity = getattr(finding, "secret_correlation_id", None)
    if isinstance(identity, str) and identity:
        # Proven same credential (up to HMAC collision). The identity itself never leaves this
        # function's bucket key — it is not put into any human-readable field.
        return f"identity:{identity}", "identity", ""

    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    detail = evidence.get("detail")
    sources = [evidence, detail if isinstance(detail, dict) else {}]
    for source in sources:
        for key in ("redacted", "redacted_excerpt", "excerpt", "match"):
            value = source.get(key)
            if isinstance(value, str) and value.strip() and value != "<redacted>":
                snippet = value.strip()[:120]
                return f"value:{snippet}", "value", snippet

    # No value at all, so fall back to position. The rule name discriminates when present, so three
    # patterns matching one line of a `.env` stay three credentials rather than being merged.
    location = finding.location or {}
    path, line, rule = location.get("path"), location.get("line"), location.get("rule")
    if path and line:
        pos = f"{path}:{line}:{rule}" if rule else f"{path}:{line}"
        return f"position:{pos}", "position", ""
    return None


def _cves(finding: Finding) -> set[str]:
    return {c for c in (finding.cve_ids or []) if isinstance(c, str) and c.startswith("CVE-")}


# ── rules ─────────────────────────────────────────────────────────────────────────────────────────
def group_same_secret(findings: list[Finding]) -> list[Group]:
    """One credential reported by several engines."""
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    basis_of: dict[tuple, str] = {}
    display_of: dict[tuple, str] = {}
    for finding in findings:
        if finding.category not in {"secret", "insecure-code", "container-misconfig"}:
            continue
        engine = (finding.location or {}).get("engine") or _engine_of(finding)
        if engine not in _SECRET_ENGINES:
            continue
        result = _secret_identity(finding)
        if result:
            bucket_key, basis, display = result
            key = (finding.customer_id, bucket_key)
            buckets[key].append(finding)
            # A bucket is homogeneous by basis (each basis namespaces its key), so any member's
            # basis is the bucket's basis.
            basis_of.setdefault(key, basis)
            display_of.setdefault(key, display)

    groups: list[Group] = []
    for key, members in buckets.items():
        if len(members) < 2:
            continue
        customer_id, _bucket_key = key
        # CONFIRMED requires the keyed identity — proof it is the same credential. The lossy display
        # redaction (value) and position are STRONG_EVIDENCE at most: a redaction can collide across
        # two different secrets, so it must never earn CONFIRMED.
        basis = basis_of[key]
        confidence = (CorrelationConfidence.CONFIRMED if basis == "identity"
                      else CorrelationConfidence.STRONG_EVIDENCE)
        edge_rationale = {
            "identity": "Both findings resolve to the same keyed secret identity — the same "
                        "credential.",
            "value": "Both findings share the same redacted secret representation; a redaction is "
                     "lossy, so this is not proof they are the same credential.",
            "position": "Both findings reference the same file location (path:line); no value was "
                        "available to compare.",
        }[basis]
        # Only the redacted value is human-safe to show; the keyed identity is internal.
        detail = f" ({display_of[key][:40]})" if display_of[key] else ""
        groups.append(_duplicate_group(
            rule="same-secret",
            title="One credential reported by several engines",
            description=(
                f"{len(members)} findings describe the same credential{detail}. "
                "Rotating it once resolves all of them; the individual findings are kept so each "
                "engine's evidence remains checkable."
            ),
            members=members,
            customer_id=customer_id,
            confidence=confidence,
            edge_rationale=edge_rationale,
        ))
    return groups


def group_same_cve_on_asset(findings: list[Finding]) -> list[Group]:
    """The same advisory reported against one asset by more than one engine."""
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    for finding in findings:
        for cve in _cves(finding):
            buckets[(finding.asset_id, cve)].append(finding)

    groups: list[Group] = []
    for (_asset_id, cve), members in buckets.items():
        if len(members) < 2:
            continue
        groups.append(_duplicate_group(
            rule="same-cve-on-asset",
            title=f"{cve} reported by several engines on one asset",
            description=(
                f"{len(members)} findings report {cve} against the same asset. One fix closes "
                "them all."
            ),
            members=members,
            customer_id=members[0].customer_id,
            # Same CVE id + same asset is a strong match, but the rule does not prove the two
            # engines saw the *same component instance*, so it is not CONFIRMED.
            confidence=CorrelationConfidence.STRONG_EVIDENCE,
            edge_rationale="Both findings reference the same CVE on the same asset.",
        ))
    return groups


def group_shipped_and_running(findings: list[Finding]) -> list[Group]:
    """A vulnerable component that is both in the code and answering on a port.

    Materially worse than either alone: the dependency scan says it will be exposed the next time
    this is deployed, and the service scan says it already is. That combination is what turns a
    patch from "next sprint" into "today", so it is escalated — and the escalation is recorded.
    """
    by_cve: dict[tuple, dict[str, list[Finding]]] = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        engine = _engine_of(finding)
        if finding.category == "vuln-service":
            side = "running"
        elif engine in _DEPENDENCY_ENGINES and finding.category in {"vuln-dep"}:
            side = "shipped"
        else:
            continue
        for cve in _cves(finding):
            by_cve[(finding.customer_id, cve)][side].append(finding)

    groups: list[Group] = []
    for (customer_id, cve), sides in by_cve.items():
        if not (sides.get("shipped") and sides.get("running")):
            continue
        members = [*sides["shipped"], *sides["running"]]
        severity, score, rationale = _escalated(members, steps=1, reason=(
            f"{cve} is both shipped in the codebase and answering on a reachable service — the "
            "vulnerable component is already running, not merely scheduled to be deployed"
        ))
        member_ids = [f.id for f in members][:MAX_GROUP_SIZE]
        primary_id = _primary(members).id
        shipped_ids = {f.id for f in sides["shipped"]}
        edges = _bipartite_edges(
            primary_id, member_ids, shipped_ids,
            # The cross-side pair is the whole point — and it is only POTENTIAL: the same CVE id
            # does not prove the running service IS the shipped dependency.
            cross_rationale=(
                f"The same CVE ({cve}) is shipped as a dependency and is answering on a reachable "
                "service; not proven to be the same component."
            ),
            cross_confidence=CorrelationConfidence.POTENTIAL,
            same_rationale=(
                f"The same CVE ({cve}) reported on the same side (both shipped, or both running)."
            ),
            same_confidence=CorrelationConfidence.POTENTIAL,
        )
        groups.append(Group(
            rule="shipped-and-running",
            kind="chain",
            title=f"{cve} is deployed and reachable",
            description=(
                f"{cve} appears both as a dependency in the codebase and in a service that is "
                "answering. Patching the dependency does not fix the running instance until it is "
                "redeployed."
            ),
            members=member_ids,
            primary=primary_id,
            severity=severity, risk_score=score, rationale=rationale,
            # Keyed on (customer, CVE) only: the running service is NOT proven to be the shipped
            # component, so the chain is plausible but unconfirmed.
            confidence=CorrelationConfidence.POTENTIAL,
            customer_id=customer_id, edges=edges,
        ))
    return groups


def group_injection_corroborated(findings: list[Finding]) -> list[Group]:
    """A static path to a sink, and a dynamic observation of the same weakness class."""
    static: dict[tuple, list[Finding]] = defaultdict(list)
    dynamic: dict[tuple, list[Finding]] = defaultdict(list)
    for finding in findings:
        cwe = finding.cwe_id
        if cwe not in _INJECTION_CWES:
            continue
        engine = _engine_of(finding)
        if engine == "sast":
            static[(finding.customer_id, cwe)].append(finding)
        elif engine in _DYNAMIC_ENGINES:
            dynamic[(finding.customer_id, cwe)].append(finding)

    groups: list[Group] = []
    for key, static_members in static.items():
        dynamic_members = dynamic.get(key)
        if not dynamic_members:
            continue
        customer_id, cwe = key
        members = [*static_members, *dynamic_members]
        severity, score, rationale = _escalated(members, steps=1, reason=(
            f"a static data-flow path to a {cwe} sink and a dynamic observation of {cwe} on the "
            "same application agree — two independent methods reaching one conclusion"
        ))
        member_ids = [f.id for f in members][:MAX_GROUP_SIZE]
        primary_id = _primary(members).id
        static_ids = {f.id for f in static_members}
        edges = _bipartite_edges(
            primary_id, member_ids, static_ids,
            # The corroboration IS the cross-side (static⟷dynamic) pair — strong, independent, but
            # not proof of the same sink.
            cross_rationale=(
                f"Static and dynamic analysis corroborate the same weakness class ({cwe}) for the "
                "customer; not proven to be the same sink."
            ),
            cross_confidence=CorrelationConfidence.STRONG_EVIDENCE,
            # Two findings from the SAME analysis type are not independent corroboration.
            same_rationale=(
                f"Both findings report {cwe} from the same analysis type; not independent "
                "corroboration."
            ),
            same_confidence=CorrelationConfidence.POTENTIAL,
        )
        groups.append(Group(
            rule="injection-corroborated",
            kind="corroboration",
            title=f"{cwe} confirmed by static and dynamic analysis",
            description=(
                "Source analysis found a path from attacker-controlled input to a dangerous "
                f"operation, and a dynamic check independently observed {cwe} behaviour. Neither "
                "alone proves exploitability; together they are as close as scanning gets."
            ),
            members=member_ids,
            primary=primary_id,
            severity=severity, risk_score=score, rationale=rationale,
            # Static + dynamic agreement on one CWE class is strong, independent evidence, but the
            # rule keys on (customer, CWE) — it does not prove both engines hit the SAME sink — so
            # it is STRONG_EVIDENCE, not CONFIRMED.
            confidence=CorrelationConfidence.STRONG_EVIDENCE,
            customer_id=customer_id, edges=edges,
        ))
    return groups


def group_exposed_repository_secret(findings: list[Finding]) -> list[Group]:
    """A publicly readable repository, and a credential inside it.

    Either finding alone is a normal week's work. Together they mean the credential is already
    retrievable by anyone who found the host, which changes what the customer has to do first —
    rotate, not merely remove.
    """
    exposures: dict[uuid.UUID, list[Finding]] = defaultdict(list)
    secrets: dict[uuid.UUID, list[Finding]] = defaultdict(list)
    for finding in findings:
        rule = (finding.location or {}).get("rule") or ""
        if isinstance(rule, str) and rule.startswith(("web-check-git", "web-check-env")):
            exposures[finding.customer_id].append(finding)
        elif _engine_of(finding) == "secrets":
            secrets[finding.customer_id].append(finding)

    groups: list[Group] = []
    for customer_id, exposure_members in exposures.items():
        secret_members = secrets.get(customer_id)
        if not secret_members:
            continue
        members = [*exposure_members, *secret_members]
        severity, score, rationale = _escalated(members, steps=1, reason=(
            "a repository or dotenv file is readable over HTTP and a credential was found in the "
            "same customer's source — treat the credential as disclosed, not merely committed"
        ))
        member_ids = [f.id for f in members][:MAX_GROUP_SIZE]
        primary_id = _primary(members).id
        exposure_ids = {f.id for f in exposure_members}
        edges = _bipartite_edges(
            primary_id, member_ids, exposure_ids,
            # The cross-side pair (exposure⟷secret) is only POTENTIAL: keyed on the customer, it
            # does not prove the credential lives inside the exposed repository.
            cross_rationale=(
                "A repository or dotenv file is publicly readable and a credential exists in the "
                "same customer's source; not proven the credential is inside that exposure."
            ),
            cross_confidence=CorrelationConfidence.POTENTIAL,
            same_rationale="Additional exposure or secret for the same customer.",
            same_confidence=CorrelationConfidence.POTENTIAL,
        )
        groups.append(Group(
            rule="exposed-repository-secret",
            kind="chain",
            title="A committed credential is publicly retrievable",
            description=(
                "A repository directory or dotenv file is served over HTTP, and a credential was "
                "found in this customer's source. Removing the file does not help: assume the "
                "credential has been read and rotate it."
            ),
            members=member_ids,
            primary=primary_id,
            severity=severity, risk_score=score, rationale=rationale,
            # Keyed on the customer only: the exposure and the secret are not proven to be the same
            # repository, so the chain is plausible but unconfirmed — POTENTIAL.
            confidence=CorrelationConfidence.POTENTIAL,
            customer_id=customer_id, edges=edges,
        ))
    return groups


RULES = (
    group_same_secret,
    group_same_cve_on_asset,
    group_shipped_and_running,
    group_injection_corroborated,
    group_exposed_repository_secret,
)


# ── helpers ───────────────────────────────────────────────────────────────────────────────────────
def _engine_of(finding: Finding) -> str:
    """Which engine produced a finding.

    Derived from the location's `engine` when present and from the category otherwise, because
    `findings` records the engine run rather than the engine name and a join per finding to recover
    a string is not worth it.
    """
    location = finding.location or {}
    engine = location.get("engine")
    if isinstance(engine, str) and engine:
        return engine
    rule = str(location.get("rule") or "")
    if rule.startswith("taint-") or rule.startswith("py-") or rule.startswith("js-"):
        return "sast"
    if rule.startswith("web-check-"):
        return "web_checks"
    if rule.startswith("image-"):
        return "container"
    if rule.startswith("iac-"):
        return "iac"
    if rule.startswith("service-cve-"):
        return "service_cve"
    return {"secret": "secrets", "vuln-dep": "sca", "vuln-service": "service_cve"}.get(
        finding.category, finding.category
    )


def _primary(members: list[Finding]) -> Finding:
    """The member a reader should look at first: highest risk, then highest severity.

    The finding-id string is the final tiebreak so the choice is deterministic — two members of
    equal risk and severity must not depend on input iteration order, or the ordinal (and the edge
    anchor derived from it) would drift between runs.
    """
    return max(members, key=lambda f: (f.risk_score or 0, _severity(f.severity).rank, str(f.id)))


def _presentation_order(primary: uuid.UUID, members: list[uuid.UUID]) -> list[uuid.UUID]:
    """Deterministic order for display: the primary first, then the rest by id string.

    Derived only from identifiers already on the findings — never insertion order or a timestamp —
    so repeated runs and any input order produce identical ordinals. This is presentation order,
    not a causal sequence (see the module docstring).
    """
    rest = sorted((m for m in members if m != primary), key=str)
    return [primary, *rest]


def _star_edges(primary: uuid.UUID, members: list[uuid.UUID], *, rationale: str,
                confidence: CorrelationConfidence) -> list[MemberEdge]:
    """Uniform edges from the primary to every other member — for rules whose evidence is the same
    for every pair (a duplicate group: the primary shares the identical secret/CVE with each other
    member, transitively). One edge per non-primary member, so each has a single incoming edge."""
    return [MemberEdge(primary, m, rationale, confidence) for m in members if m != primary]


def _bipartite_edges(primary: uuid.UUID, members: list[uuid.UUID], one_side: set[uuid.UUID], *,
                     cross_rationale: str, cross_confidence: CorrelationConfidence,
                     same_rationale: str, same_confidence: CorrelationConfidence
                     ) -> list[MemberEdge]:
    """Edges from the primary to every other member, distinguishing the pair the rule actually
    corroborates (crossing the two sides) from a same-side pair the rule does NOT.

    A corroboration/chain rule proves a relationship BETWEEN two sides (static⟷dynamic,
    shipped⟷running, exposure⟷secret). Only a cross-side pair carries that evidence; a pair on one
    side (two static findings, two exposures) does not, so it gets its own weaker rationale and
    tier. This is what keeps the rule from manufacturing an edge it cannot support."""
    primary_on_side = primary in one_side
    edges: list[MemberEdge] = []
    for m in members:
        if m == primary:
            continue
        crosses = (m in one_side) != primary_on_side
        if crosses:
            edges.append(MemberEdge(primary, m, cross_rationale, cross_confidence))
        else:
            edges.append(MemberEdge(primary, m, same_rationale, same_confidence))
    return edges


def _duplicate_group(*, rule, title, description, members, customer_id,  # noqa: ANN001
                     confidence: CorrelationConfidence, edge_rationale: str) -> Group:
    primary = _primary(members)
    severity = _severity(primary.severity)
    member_ids = [f.id for f in members][:MAX_GROUP_SIZE]
    # A duplicate's evidence is transitive (every member is the same secret/CVE), so every edge from
    # the primary carries the same rationale and the same tier as the group.
    edges = _star_edges(primary.id, member_ids, rationale=edge_rationale, confidence=confidence)
    return Group(
        rule=rule, kind="duplicate", title=title, description=description,
        members=member_ids, primary=primary.id,
        severity=severity, risk_score=primary.risk_score or 0, confidence=confidence,
        rationale=[
            f"Grouped by rule `{rule}`: {len(members)} findings describe one issue",
            f"Severity {severity.value} taken from the strongest member — grouping does not "
            "escalate a duplicate, it only stops it being counted several times",
        ],
        customer_id=customer_id, edges=edges,
    )


def _escalated(members: list[Finding], *, steps: int, reason: str):  # noqa: ANN202
    primary = _primary(members)
    base = _severity(primary.severity)
    severity = _escalate(base, steps)
    score = min(100, (primary.risk_score or 0) + 5 * steps)
    rationale = [
        f"Strongest member: {base.value} at risk {primary.risk_score or 0}",
        f"Escalated to {severity.value} (+{5 * steps} risk) because {reason}",
    ]
    return severity, score, rationale


def correlate(findings: list[Finding]) -> list[Group]:
    """Run every rule. Pure: no database, so the rules are testable on their own."""
    groups: list[Group] = []
    for rule in RULES:
        groups.extend(rule(findings))
    return groups


# ── persistence ───────────────────────────────────────────────────────────────────────────────────
@celery_app.task(name="guardian.correlate_findings")
def correlate_tenant(tenant_id: str, customer_id: str | None = None) -> dict:
    """Correlate a tenant's open findings and persist the groups."""
    tenant = uuid.UUID(tenant_id)
    stats = {"findings": 0, "groups": 0, "created": 0, "updated": 0, "members": 0}

    with session_scope() as session:
        query = select(Finding).where(
            Finding.tenant_id == tenant,
            Finding.status.in_(["open", "triaged", "confirmed"]),
        ).limit(MAX_FINDINGS)
        if customer_id:
            query = query.where(Finding.customer_id == uuid.UUID(customer_id))
        findings = list(session.execute(query).scalars())
        stats["findings"] = len(findings)

        for group in correlate(findings):
            stats["groups"] += 1
            created = _persist(session, tenant, group)
            stats["created" if created else "updated"] += 1
            stats["members"] += len(group.members)

    log.info("correlation_complete", tenant=tenant_id, **stats)
    return stats


def _persist(session, tenant: uuid.UUID, group: Group) -> bool:  # noqa: ANN001
    fingerprint = group.fingerprint()
    existing = session.execute(
        select(FindingCorrelation).where(
            FindingCorrelation.tenant_id == tenant,
            FindingCorrelation.fingerprint == fingerprint,
        )
    ).scalars().first()

    if existing is None:
        correlation = FindingCorrelation(
            tenant_id=tenant, customer_id=group.customer_id, rule=group.rule,
            fingerprint=fingerprint, title=group.title, description=group.description,
            kind=group.kind, severity=group.severity.value, risk_score=group.risk_score,
            confidence=group.confidence.value,
            rationale=list(group.rationale), member_count=len(group.members),
        )
        session.add(correlation)
        session.flush()
        created = True
    else:
        correlation = existing
        correlation.severity = group.severity.value
        correlation.risk_score = group.risk_score
        correlation.confidence = group.confidence.value
        correlation.rationale = list(group.rationale)
        correlation.member_count = len(group.members)
        created = False

    existing_members = {
        row.finding_id: row for row in session.execute(
            select(FindingCorrelationMember).where(
                FindingCorrelationMember.correlation_id == correlation.id
            )
        ).scalars()
    }
    # Deterministic presentation ordinal, and the one incoming edge each non-primary member carries.
    ordinal_of = {finding_id: i for i, finding_id in enumerate(group.ordered)}
    edge_of = {edge.dest: edge for edge in group.edges}
    for finding_id in group.members:
        role = "primary" if finding_id == group.primary else (
            "duplicate" if group.kind == "duplicate" else "corroborating"
        )
        ordinal = ordinal_of.get(finding_id, 0)
        edge = edge_of.get(finding_id)
        edge_source = edge.source if edge else None
        edge_rationale = edge.rationale if edge else None
        edge_confidence = edge.confidence.value if edge else None
        row = existing_members.get(finding_id)
        if row is None:
            session.add(FindingCorrelationMember(
                correlation_id=correlation.id, finding_id=finding_id,
                tenant_id=tenant, role=role, ordinal=ordinal,
                edge_source_finding_id=edge_source, edge_rationale=edge_rationale,
                edge_confidence=edge_confidence,
            ))
        else:
            # Re-running must UPDATE the existing row, not add a second (composite PK forbids it)
            # and not leave a pre-slice-2 row without its ordinal/edge — that is how a historical
            # group gains real, recomputed edge evidence rather than a fabricated migration value.
            row.role = role
            row.ordinal = ordinal
            row.edge_source_finding_id = edge_source
            row.edge_rationale = edge_rationale
            row.edge_confidence = edge_confidence
        finding = session.get(Finding, finding_id)
        if finding is not None:
            # Set, never used to hide: the finding stays open and individually inspectable.
            finding.correlation_id = correlation.id
    return created
