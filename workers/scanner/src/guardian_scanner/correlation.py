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
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from guardian_common.logging import get_logger
from guardian_core.enums import Severity
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
    rationale: list[str] = field(default_factory=list)
    customer_id: uuid.UUID | None = None

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


def _secret_identity(finding: Finding) -> str | None:
    """What makes two secret findings the same secret.

    The redacted form is used deliberately — it is what the engines persist, and it is stable for
    one credential across the source file, the git history and an image layer. Comparing raw values
    would mean storing them, which is the thing every secrets engine here is careful not to do.
    """
    evidence = finding.evidence or {}
    detail = evidence.get("detail") if isinstance(evidence, dict) else None
    detail = detail if isinstance(detail, dict) else {}
    for key in ("redacted", "redacted_excerpt", "excerpt", "match"):
        value = detail.get(key)
        if isinstance(value, str) and value.strip() and value != "<redacted>":
            return value.strip()[:120]
    location = finding.location or {}
    path, line = location.get("path"), location.get("line")
    if path and line:
        return f"{path}:{line}"
    return None


def _cves(finding: Finding) -> set[str]:
    return {c for c in (finding.cve_ids or []) if isinstance(c, str) and c.startswith("CVE-")}


# ── rules ─────────────────────────────────────────────────────────────────────────────────────────
def group_same_secret(findings: list[Finding]) -> list[Group]:
    """One credential reported by several engines."""
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.category not in {"secret", "insecure-code", "container-misconfig"}:
            continue
        engine = (finding.location or {}).get("engine") or _engine_of(finding)
        if engine not in _SECRET_ENGINES:
            continue
        identity = _secret_identity(finding)
        if identity:
            buckets[(finding.customer_id, identity)].append(finding)

    groups: list[Group] = []
    for (customer_id, identity), members in buckets.items():
        if len(members) < 2:
            continue
        groups.append(_duplicate_group(
            rule="same-secret",
            title="One credential reported by several engines",
            description=(
                f"{len(members)} findings describe the same credential ({identity[:40]}). "
                "Rotating it once resolves all of them; the individual findings are kept so each "
                "engine's evidence remains checkable."
            ),
            members=members,
            customer_id=customer_id,
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
        groups.append(Group(
            rule="shipped-and-running",
            kind="chain",
            title=f"{cve} is deployed and reachable",
            description=(
                f"{cve} appears both as a dependency in the codebase and in a service that is "
                "answering. Patching the dependency does not fix the running instance until it is "
                "redeployed."
            ),
            members=[f.id for f in members][:MAX_GROUP_SIZE],
            primary=_primary(members).id,
            severity=severity, risk_score=score, rationale=rationale,
            customer_id=customer_id,
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
        groups.append(Group(
            rule="injection-corroborated",
            kind="corroboration",
            title=f"{cwe} confirmed by static and dynamic analysis",
            description=(
                "Source analysis found a path from attacker-controlled input to a dangerous "
                f"operation, and a dynamic check independently observed {cwe} behaviour. Neither "
                "alone proves exploitability; together they are as close as scanning gets."
            ),
            members=[f.id for f in members][:MAX_GROUP_SIZE],
            primary=_primary(members).id,
            severity=severity, risk_score=score, rationale=rationale,
            customer_id=customer_id,
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
        groups.append(Group(
            rule="exposed-repository-secret",
            kind="chain",
            title="A committed credential is publicly retrievable",
            description=(
                "A repository directory or dotenv file is served over HTTP, and a credential was "
                "found in this customer's source. Removing the file does not help: assume the "
                "credential has been read and rotate it."
            ),
            members=[f.id for f in members][:MAX_GROUP_SIZE],
            primary=_primary(members).id,
            severity=severity, risk_score=score, rationale=rationale,
            customer_id=customer_id,
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
    """The member a reader should look at first: highest risk, then highest severity."""
    return max(members, key=lambda f: (f.risk_score or 0, _severity(f.severity).rank))


def _duplicate_group(*, rule, title, description, members, customer_id) -> Group:  # noqa: ANN001
    primary = _primary(members)
    severity = _severity(primary.severity)
    return Group(
        rule=rule, kind="duplicate", title=title, description=description,
        members=[f.id for f in members][:MAX_GROUP_SIZE], primary=primary.id,
        severity=severity, risk_score=primary.risk_score or 0,
        rationale=[
            f"Grouped by rule `{rule}`: {len(members)} findings describe one issue",
            f"Severity {severity.value} taken from the strongest member — grouping does not "
            "escalate a duplicate, it only stops it being counted several times",
        ],
        customer_id=customer_id,
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
            rationale=list(group.rationale), member_count=len(group.members),
        )
        session.add(correlation)
        session.flush()
        created = True
    else:
        correlation = existing
        correlation.severity = group.severity.value
        correlation.risk_score = group.risk_score
        correlation.rationale = list(group.rationale)
        correlation.member_count = len(group.members)
        created = False

    known = {
        row.finding_id for row in session.execute(
            select(FindingCorrelationMember).where(
                FindingCorrelationMember.correlation_id == correlation.id
            )
        ).scalars()
    }
    for finding_id in group.members:
        role = "primary" if finding_id == group.primary else (
            "duplicate" if group.kind == "duplicate" else "corroborating"
        )
        if finding_id not in known:
            session.add(FindingCorrelationMember(
                correlation_id=correlation.id, finding_id=finding_id,
                tenant_id=tenant, role=role,
            ))
        finding = session.get(Finding, finding_id)
        if finding is not None:
            # Set, never used to hide: the finding stays open and individually inspectable.
            finding.correlation_id = correlation.id
    return created
