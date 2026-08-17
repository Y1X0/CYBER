"""CVSS v3.x base score from a vector string.

Feeds publish severity as a vector (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), not as a
number. Without evaluating it every advisory arrives with no base score, severity banding falls
back to its default, and the deterministic risk engine loses its strongest input — so findings from
a live feed would rank below findings from the six hand-seeded rows.

The specification is arithmetic, which is exactly the kind of thing that belongs in core: pure,
reproducible, and checkable against the published examples. The AI analyst may explain a score; it
can never produce one.
"""

from __future__ import annotations

import math

# Metric weights, CVSS v3.1 specification §7.4.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}   # a changed scope makes privileges worth more
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def parse_vector(vector: str) -> dict[str, str]:
    """Split a vector into its metrics. Unknown or malformed segments are ignored."""
    metrics: dict[str, str] = {}
    for part in str(vector or "").strip().split("/"):
        key, sep, value = part.partition(":")
        if sep and key and value:
            metrics[key.upper()] = value.upper()
    return metrics


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A: round up to one decimal, avoiding binary float surprises."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Base score for a CVSS v3.x vector, or None when the vector is not v3 or is incomplete.

    Returning None rather than 0.0 matters: 0.0 is a real CVSS score meaning "no impact", while
    None means "we could not evaluate this", and a caller must be able to tell those apart.
    """
    metrics = parse_vector(vector)
    version = metrics.get("CVSS", "")
    if version and not version.startswith("3"):
        return None                      # v2 and v4 use different arithmetic; do not guess
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in metrics for k in required):
        return None

    scope_changed = metrics["S"] == "C"
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        conf, integ, avail = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


# Qualitative bands, specification §5.
_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def severity_label(score: float | None) -> str | None:
    """The qualitative band for a base score, or None when there is no score to band."""
    if score is None:
        return None
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "none"
