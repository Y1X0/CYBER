"""DNS / email-security posture provider (Framework — third provider, posture / non-network).

The counterpart to Providers #1 (active/network) and #2 (offline artifact): it proves the
*posture* branch — deriving findings from the **aggregate and the ABSENCE** of DNS records, not from
a single positive observation. The pattern (locked in ADR-0019) is **absence-as-evidence**: the
provider evaluates the full record set inside `execute()` and emits a POSITIVE evidence item for
each weakness it observes — including "record absent" — so `normalize()` stays per-evidence and the
shared framework contract is untouched. An absence is itself a recorded observation, not a gap in
logic.

Offline-first and hermetic: the authoritative DNS record set arrives as a bounded snapshot inside
`ToolJob.settings` (no live resolver, no new egress). The snapshot is authoritative — a record key
it omits means that record was not observed (absent), which is a legitimate posture signal. A
snapshot entry that is structurally malformed fails closed for that target (evidence marked failed).

Conservative by design: it reports posture weaknesses (missing/again permissive SPF, missing/monitor
-only DMARC, missing CAA, unproven DNSSEC, MX-without-SPF) and NEVER infers compromise, takeover, or
intrusion from them. No AI, no new scoring — deterministic derivation only.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

# kind → (title, severity, rule, cwe, short reason). One per detected weakness; drives normalize().
_ISSUE_FINDINGS = {
    "dns_spf_missing": ("SPF record missing", Severity.MEDIUM, "dns-spf-missing", "CWE-290",
                        "No SPF record was observed, so senders cannot be validated."),
    "dns_spf_weak": ("SPF policy is permissive (+all)", Severity.MEDIUM, "dns-spf-weak", "CWE-290",
                     "The SPF record ends in a pass-all mechanism, so it authorizes any sender."),
    "dns_dmarc_missing": ("DMARC record missing", Severity.MEDIUM, "dns-dmarc-missing", "CWE-290",
                          "No DMARC record was observed, so spoofed mail is unhandled."),
    "dns_dmarc_monitor_only": ("DMARC policy is monitor-only (p=none)", Severity.LOW,
                               "dns-dmarc-p-none", "CWE-290",
                               "DMARC is set to p=none, which monitors but does not reject."),
    "dns_caa_missing": ("CAA record missing", Severity.LOW, "dns-caa-missing", None,
                        "No CAA record was observed, so certificate issuance is unrestricted."),
    "dns_dnssec_missing": ("DNSSEC not enabled", Severity.LOW, "dns-dnssec-missing", None,
                           "DNSSEC was not observed as enabled for the zone."),
    "dns_mx_without_spf": ("MX present without SPF", Severity.MEDIUM, "dns-mx-without-spf",
                           "CWE-290",
                           "Mail exchangers are configured but no SPF record protects the domain."),
}


def _spf_is_permissive(spf: str) -> bool:
    """True only for an explicit pass-all mechanism (+all) — the clearly-insecure case."""
    return "+all" in spf.replace(" ", "").lower()


def _dmarc_policy(dmarc: str) -> str | None:
    """The `p=` value of a DMARC record, lowercased, or None if not present."""
    for part in dmarc.split(";"):
        token = part.strip().lower()
        if token.startswith("p="):
            return token[2:].strip()
    return None


class DnsPostureProvider:
    """A governed, offline, read-only DNS/email-security posture assessor. Never self-authorizes."""

    key = "dns_posture"
    name = "DNS / Email-Security Posture"
    version = "1"

    @property
    def capabilities(self) -> ToolCapabilities:
        # Passive posture assessment (offline snapshot): no network, no active touch, no approval.
        return ToolCapabilities(
            category="dns_assessment", network=False, active=False, destructive=False,
            requires_authorization=True, requires_human_approval=False,
            supported_targets=("domain", "subdomain"),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane already ran the gate."""
        if not job.scope.targets:
            raise ValueError("dns_posture: no in-scope target")

    def _records_evidence(self, job: ToolJob, host: str, snap: dict, *,
                          status: str, reason: str = "") -> RawEvidence:
        """Chain-of-custody: the DNS record set observed for a target (records are not secrets)."""
        spf = snap.get("spf")
        dmarc = snap.get("dmarc")
        caa = snap.get("caa") or []
        mx = snap.get("mx") or []
        data = {
            "domain": host, "status": status, "reason": reason,
            "spf_present": bool(spf), "spf": spf if isinstance(spf, str) else None,
            "dmarc_present": bool(dmarc),
            "dmarc_policy": _dmarc_policy(dmarc) if isinstance(dmarc, str) else None,
            "caa_present": bool(caa), "caa_count": len(caa) if isinstance(caa, list) else 0,
            "dnssec": bool(snap.get("dnssec")),
            "mx_present": bool(mx), "mx_count": len(mx) if isinstance(mx, list) else 0,
        }
        return RawEvidence(
            tool=self.key, execution_id=job.job_id, target=host, kind="dns_records", data=data,
            provenance={"mode": "offline", "source": self.key, "snapshot": True},
            occurred_at=str(snap.get("observed_at") or ""),
        )

    def _issue(self, job: ToolJob, host: str, kind: str, extra: dict) -> RawEvidence:
        return RawEvidence(
            tool=self.key, execution_id=job.job_id, target=host, kind=kind,
            data={"domain": host, **extra},
            provenance={"mode": "offline", "source": self.key, "snapshot": True}, occurred_at="",
        )

    def execute(self, job: ToolJob):  # noqa: ANN201
        """Evaluate each in-scope domain's snapshot; yield records + one evidence per weakness."""
        snapshot = (job.settings or {}).get("snapshot") or {}
        for host in job.scope.targets:
            entry = snapshot.get(host)
            if not isinstance(entry, dict):                 # fail-closed: malformed/absent snapshot
                yield self._records_evidence(job, host, {}, status="failed",
                                             reason="malformed_or_missing_snapshot")
                continue
            yield self._records_evidence(job, host, entry, status="observed")

            spf = entry.get("spf")
            dmarc = entry.get("dmarc")
            mx = entry.get("mx") or []
            has_spf = isinstance(spf, str) and spf.strip() != ""
            has_mx = isinstance(mx, list) and len(mx) > 0

            # SPF: MX-without-SPF is the higher-signal case and supersedes the generic "missing".
            if not has_spf:
                yield (self._issue(job, host, "dns_mx_without_spf", {"mx_count": len(mx)})
                       if has_mx else self._issue(job, host, "dns_spf_missing", {}))
            elif _spf_is_permissive(spf):
                yield self._issue(job, host, "dns_spf_weak", {"spf": spf})

            # DMARC: absent vs monitor-only (p=none).
            if not (isinstance(dmarc, str) and dmarc.strip()):
                yield self._issue(job, host, "dns_dmarc_missing", {})
            elif _dmarc_policy(dmarc) == "none":
                yield self._issue(job, host, "dns_dmarc_monitor_only", {"dmarc": dmarc})

            if not (entry.get("caa") or []):
                yield self._issue(job, host, "dns_caa_missing", {})
            if not entry.get("dnssec"):
                yield self._issue(job, host, "dns_dnssec_missing", {})

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:
        """Derive a finding ONLY from a recorded weakness evidence item (absence included)."""
        spec = _ISSUE_FINDINGS.get(evidence.kind)
        if spec is None:                                # dns_records / anything else ⇒ no finding
            return None
        title, severity, rule, cwe, reason = spec
        host = evidence.target
        return RawFinding(
            engine=EngineKey.DNS_POSTURE, title=title, category="misconfig",
            base_severity=severity, confidence="high", cwe_id=cwe,
            description=f"{reason} (domain {host}).",
            location={"endpoint": host, "rule": rule},
            evidence={k: v for k, v in (evidence.data or {}).items() if k != "domain"},
        )
