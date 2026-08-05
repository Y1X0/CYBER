"""Deterministic, offline provider — the default when no API key is configured.

It composes grounded, useful output purely from the structured `context` (the finding + retrieved
KB). No network, no key, fully reproducible — which also makes the analyst unit-testable. It never
invents a severity, CVE, or reference that isn't in the context.
"""

from __future__ import annotations

from typing import Any


class StubProvider:
    name = "stub"

    def complete_json(
        self, *, system: str, prompt: str, schema: dict, context: dict[str, Any] | None = None
    ) -> dict:
        ctx = context or {}
        kind = ctx.get("_kind")
        if kind == "finding_explanation":
            return self._explain(ctx)
        if kind == "executive_summary":
            return self._executive(ctx)
        return {}

    def complete_text(
        self, *, system: str, prompt: str, context: dict[str, Any] | None = None
    ) -> str:
        ctx = context or {}
        return self._chat_answer(ctx)

    # ── finding explanation ──
    def _explain(self, ctx: dict) -> dict:
        f = ctx.get("finding", {})
        kb = ctx.get("kb", [])
        title = f.get("title", "the issue")
        cwe = f.get("cwe_id")
        owasp = f.get("owasp_ref")
        sev = f.get("severity", "medium")
        category = f.get("category", "issue")
        kb_advice = " ".join(e.get("body", "") for e in kb)[:600]

        explanation = (
            f"{title} is a {sev}-severity {category} finding"
            + (f" mapped to {cwe}" if cwe else "")
            + (f" ({owasp})" if owasp else "")
            + ". "
            + (f.get("description") or "")
        ).strip()
        impact = (
            "If exploited, an attacker could leverage this weakness to compromise the affected "
            "asset's confidentiality, integrity, or availability. "
            f"The risk score is {f.get('risk_score', 'n/a')}/100 based on exploitability and "
            "business exposure."
        )
        attack_scenario = (
            "A malicious actor identifies the weakness during reconnaissance and abuses it through "
            "standard tooling against the exposed surface. (Non-actionable summary — no exploit "
            "code is provided.)"
        )
        remediation = kb_advice or (
            f"Remediate the underlying {category}: follow the referenced CWE/OWASP guidance, "
            "apply the vendor-recommended fix, and re-scan to verify."
        )
        return {
            "explanation": explanation,
            "impact": impact,
            "attack_scenario": attack_scenario,
            "remediation": remediation,
            "references": _finding_refs(f),
        }

    # ── executive summary ──
    def _executive(self, ctx: dict) -> dict:
        counts = ctx.get("severity_counts", {})
        total = ctx.get("total", 0)
        score = ctx.get("security_score", 0)
        top = ctx.get("top_risks", [])
        posture = _posture(score)
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        summary = (
            f"This assessment identified {total} finding(s), including {crit} critical and {high} "
            f"high-severity issues. The overall security score is {score}/100 ({posture}). "
            + (
                "Immediate remediation of critical and high findings is recommended."
                if crit or high
                else "No critical or high-severity issues were identified in this scan."
            )
        )
        return {
            "posture": posture,
            "summary": summary,
            "recommendation": (
                "Prioritize the highest risk-scored findings, assign owners, and re-scan to verify "
                "fixes before the next release."
            ),
            "top_risks": [
                {
                    "title": t.get("title"),
                    "severity": t.get("severity"),
                    "risk_score": t.get("risk_score"),
                }
                for t in top[:5]
            ],
        }

    # ── chat ──
    def _chat_answer(self, ctx: dict) -> str:
        question = ctx.get("question", "")
        findings = ctx.get("findings", [])
        if not findings:
            return (
                "I can only answer from this project's scan findings and knowledge base, and I "
                "don't have any findings in scope to reference for that question."
            )
        lines = [
            f"- [{f.get('severity', '?').upper()}] {f.get('title')} "
            f"(risk {f.get('risk_score', '?')}, {f.get('cwe_id') or 'no CWE'})"
            for f in findings[:5]
        ]
        return (
            f'Based on this project\'s findings, here is what is relevant to "{question}":\n'
            + "\n".join(lines)
            + "\n\nEach item's severity and risk score come from the deterministic risk engine; "
            "open a finding for its evidence and remediation."
        )


def _finding_refs(f: dict) -> list[str]:
    refs: list[str] = []
    if f.get("cwe_id"):
        refs.append(f["cwe_id"])
    if f.get("owasp_ref"):
        refs.append(f["owasp_ref"])
    refs.extend(f.get("cve_ids", []) or [])
    return refs


def _posture(score: int) -> str:
    if score >= 85:
        return "strong"
    if score >= 70:
        return "moderate"
    if score >= 50:
        return "at risk"
    return "critical"
