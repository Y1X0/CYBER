"""The fix lifecycle (WP-F5).

`remediation_items` has existed as a table since the first schema and nothing has ever written to
it. The loop it was meant to close is the one that decides whether any of this work matters:
finding → an owner and a date → a fix → **a rescan that proves it** → verified.

The last step is the whole design. A remediation workflow where a human clicks "done" and the
platform believes them is a to-do list, and a to-do list is what security teams already have and
already do not trust. So `verified` is not a status anybody can set: it is reachable only from a
scan that ran the engine which found the issue, saw the engine complete cleanly, and did not report
it again (WP-E2 decides that; this module refuses the transition without it). A human can say
`fixed`. Only evidence says `verified`.

Everything here is pure: due dates, transitions, and the ticket payload a customer's automation
files into Jira or GitHub.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

OPEN = "open"
IN_PROGRESS = "in_progress"
FIXED = "fixed"
VERIFIED = "verified"
REOPENED = "reopened"
RISK_ACCEPTED = "risk_accepted"
WONT_FIX = "wont_fix"

STATUSES = (OPEN, IN_PROGRESS, FIXED, VERIFIED, REOPENED, RISK_ACCEPTED, WONT_FIX)

# Statuses a person may set directly. `verified` is absent by design.
HUMAN_SETTABLE = frozenset({OPEN, IN_PROGRESS, FIXED, RISK_ACCEPTED, WONT_FIX})

# Deciding not to fix something is a decision somebody has to own on the record.
NEEDS_JUSTIFICATION = frozenset({RISK_ACCEPTED, WONT_FIX})

# Statuses that still need work. Everything else is done or deliberately parked.
ACTIVE = frozenset({OPEN, IN_PROGRESS, REOPENED})

# Remediation windows in days, by severity. Deliberately conservative and deliberately visible: a
# customer who disagrees should change a number they can see, not discover one buried in a scorer.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
# An internet-facing asset gets the shorter clock, because the population able to reach it is
# everybody.
EXPOSURE_MULTIPLIER = {"public": 0.5, "internal": 1.0, "unknown": 1.0}
MIN_SLA_DAYS = 1


class InvalidTransition(ValueError):
    """The status change is not one this workflow allows."""


def due_at(severity: str, *, exposure: str = "unknown", opened_at: dt.datetime) -> dt.datetime:
    """When this has to be fixed by.

    Severity sets the window; exposure halves it for anything the internet can reach. Both inputs
    come from the deterministic pipeline, so two people looking at the same finding get the same
    date.
    """
    days = SLA_DAYS.get((severity or "").lower(), SLA_DAYS["medium"])
    days = max(MIN_SLA_DAYS, round(days * EXPOSURE_MULTIPLIER.get((exposure or "").lower(), 1.0)))
    return opened_at + dt.timedelta(days=days)


def is_overdue(item_status: str, due: dt.datetime | None, *, now: dt.datetime) -> bool:
    """Overdue means still outstanding past its date.

    A verified item is not overdue however late it was, and an accepted risk is not overdue at all —
    somebody decided, on the record, not to fix it.
    """
    if due is None or item_status not in ACTIVE and item_status != FIXED:
        return False
    return due < now


def validate_transition(current: str, target: str, *, by_scan: bool = False,
                        justification: str = "") -> None:
    """Raise unless this transition is allowed. The rules, in order of how much they matter:

    1. **`verified` requires a scan.** Not an assignee, not a manager, not an API caller with a
       token — a scan that looked again and did not find it. Without this the workflow certifies
       whatever the person under deadline pressure typed.
    2. `reopened` is likewise scan-driven: the finding came back.
    3. Not fixing something needs a stated reason, because it is a decision somebody owns.
    """
    if target not in STATUSES:
        raise InvalidTransition(f"{target!r} is not a remediation status")
    if current == target:
        return
    if target in (VERIFIED, REOPENED) and not by_scan:
        raise InvalidTransition(
            f"{target!r} is set by a verifying scan, not by hand: a fix is verified when the "
            "engine that found the issue ran again, completed cleanly, and did not report it"
        )
    if target in NEEDS_JUSTIFICATION and not justification.strip():
        raise InvalidTransition(f"{target!r} requires a justification")
    if current == VERIFIED and target in HUMAN_SETTABLE and target != OPEN:
        raise InvalidTransition(
            "a verified item is closed; if the issue is back, a scan reopens it"
        )


@dataclass(frozen=True)
class TicketPayload:
    """What a customer's automation files into Jira, GitHub, or ServiceNow.

    Rendered here rather than in an integration so the content is identical whatever the
    destination, and so it can be reviewed — a ticket body leaves the platform and lands in a
    system with a different audience.
    """

    title: str
    body: str
    labels: tuple[str, ...] = ()
    due_at: str | None = None
    external_ref: str = ""
    fields: dict = field(default_factory=dict)


def ticket_payload(
    *,
    finding_title: str,
    severity: str,
    risk_score: int,
    asset: str,
    description: str = "",
    remediation: str = "",
    cwe_id: str | None = None,
    owasp_ref: str | None = None,
    cve_ids: tuple[str, ...] = (),
    evidence_summary: str = "",
    due: dt.datetime | None = None,
    finding_url: str = "",
    duplicate_count: int = 0,
) -> TicketPayload:
    """One ticket for one underlying issue.

    `duplicate_count` is why this takes a correlation group rather than a finding: three engines
    finding the same credential is one thing to fix, and three tickets for it is how a remediation
    backlog stops being believed.
    """
    lines = [f"**Severity:** {severity} (risk {risk_score})", f"**Asset:** {asset}"]
    if cwe_id or owasp_ref:
        lines.append(f"**Standards:** {' '.join(filter(None, [cwe_id, owasp_ref]))}")
    if cve_ids:
        lines.append(f"**CVEs:** {', '.join(cve_ids)}")
    if due:
        lines.append(f"**Due:** {due.date().isoformat()}")
    if duplicate_count:
        lines.append(
            f"**Reported by {duplicate_count + 1} findings** — the same underlying issue. "
            "Fixing it resolves all of them."
        )
    if description:
        lines += ["", "### What it is", description]
    if evidence_summary:
        # Evidence is quoted, never re-derived: the ticket has to be checkable against the finding.
        lines += ["", "### Evidence", f"`{evidence_summary}`"]
    if remediation:
        lines += ["", "### How to fix it", remediation]
    if finding_url:
        lines += ["", f"[Open the finding in Guardian]({finding_url})"]
    lines += ["", "_Verification is automatic: this closes when a scan runs the engine that found "
              "it, completes cleanly, and no longer reports it._"]

    labels = ["security", f"severity:{severity}"]
    if cwe_id:
        labels.append(cwe_id.lower())
    return TicketPayload(
        title=f"[{severity.upper()}] {finding_title}"[:250],
        body="\n".join(lines),
        labels=tuple(labels),
        due_at=due.isoformat() if due else None,
        fields={"risk_score": risk_score, "asset": asset},
    )


@dataclass
class SlaSummary:
    total: int = 0
    active: int = 0
    overdue: int = 0
    verified: int = 0
    accepted: int = 0
    by_severity: dict = field(default_factory=dict)

    @property
    def on_time_rate(self) -> int:
        """Percentage of items that are not overdue, of those that could be.

        Reported over active plus fixed rather than over everything, so closing a stale backlog by
        accepting the risk does not improve the number.
        """
        countable = self.active + self.verified
        if countable == 0:
            return 100
        return round((countable - self.overdue) * 100 / countable)


def summarize(items: list[dict], *, now: dt.datetime) -> SlaSummary:
    """`items` are dicts with `status`, `severity`, `due_at` (datetime or None)."""
    summary = SlaSummary()
    for item in items:
        status = str(item.get("status") or OPEN)
        summary.total += 1
        if status in ACTIVE:
            summary.active += 1
        if status == VERIFIED:
            summary.verified += 1
        if status in NEEDS_JUSTIFICATION:
            summary.accepted += 1
        if is_overdue(status, item.get("due_at"), now=now):
            summary.overdue += 1
        severity = str(item.get("severity") or "medium")
        summary.by_severity[severity] = summary.by_severity.get(severity, 0) + 1
    return summary


__all__ = [
    "ACTIVE",
    "FIXED",
    "HUMAN_SETTABLE",
    "IN_PROGRESS",
    "NEEDS_JUSTIFICATION",
    "OPEN",
    "REOPENED",
    "RISK_ACCEPTED",
    "SLA_DAYS",
    "STATUSES",
    "VERIFIED",
    "WONT_FIX",
    "InvalidTransition",
    "SlaSummary",
    "TicketPayload",
    "due_at",
    "is_overdue",
    "summarize",
    "ticket_payload",
    "validate_transition",
]
