"""Version comparison and range evaluation, per ecosystem.

Vulnerability data expresses "which versions are affected" as ranges — `>=1.0, <1.4.2` — because
that is how the world actually publishes advisories. Guardian previously asked whether a version
string appeared verbatim in a list, which meant a correctly-ingested advisory matched almost
nothing: `1.4.1` is affected by `<1.4.2`, but it is not the string `1.4.2`.

Comparison is not one algorithm. `1.0.0-rc1` precedes `1.0.0` under SemVer; `1.0~rc1` precedes
`1.0` under Debian for an entirely different reason; RPM compares alternating digit and alphabetic
runs; PEP 440 has epochs, post-releases and dev-releases that sort in a specific order. Getting
these wrong is not cosmetic — it decides whether a customer is told they are exposed.

Everything here is pure: no I/O, no database, no network. That makes each ecosystem's ordering
directly testable against the examples its specification publishes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from typing import Any


class Ecosystem(str, Enum):
    """The ordering rules a version string obeys. Aliases map on to these in `normalize`."""

    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    RUBYGEMS = "rubygems"
    GO = "go"
    NUGET = "nuget"
    DEBIAN = "debian"
    RPM = "rpm"
    SEMVER = "semver"
    GENERIC = "generic"


_ALIASES = {
    "pypi": Ecosystem.PYPI, "python": Ecosystem.PYPI, "pip": Ecosystem.PYPI,
    "npm": Ecosystem.NPM, "node": Ecosystem.NPM, "nodejs": Ecosystem.NPM, "yarn": Ecosystem.NPM,
    "maven": Ecosystem.MAVEN, "java": Ecosystem.MAVEN, "gradle": Ecosystem.MAVEN,
    "rubygems": Ecosystem.RUBYGEMS, "gem": Ecosystem.RUBYGEMS, "ruby": Ecosystem.RUBYGEMS,
    "go": Ecosystem.GO, "golang": Ecosystem.GO,
    "nuget": Ecosystem.NUGET, "dotnet": Ecosystem.NUGET, "csharp": Ecosystem.NUGET,
    "debian": Ecosystem.DEBIAN, "ubuntu": Ecosystem.DEBIAN, "deb": Ecosystem.DEBIAN,
    "rpm": Ecosystem.RPM, "redhat": Ecosystem.RPM, "rhel": Ecosystem.RPM,
    "centos": Ecosystem.RPM, "fedora": Ecosystem.RPM, "suse": Ecosystem.RPM,
    "alpine": Ecosystem.RPM,   # apk orders like rpm for the cases we see in advisories
    "semver": Ecosystem.SEMVER, "crates.io": Ecosystem.SEMVER, "cargo": Ecosystem.SEMVER,
    "rust": Ecosystem.SEMVER, "packagist": Ecosystem.SEMVER, "composer": Ecosystem.SEMVER,
    "php": Ecosystem.SEMVER, "hex": Ecosystem.SEMVER, "pub": Ecosystem.SEMVER,
}


def normalize_ecosystem(name: str | None) -> Ecosystem:
    """Map a feed's ecosystem label on to an ordering. Unknown labels get generic ordering, which
    is right far more often than refusing to compare at all."""
    if not name:
        return Ecosystem.GENERIC
    return _ALIASES.get(str(name).strip().lower(), Ecosystem.GENERIC)


# ── sentinels ─────────────────────────────────────────────────────────────────────────────────────
class _Inf:
    """Sorts above everything. Used where a missing component means 'latest'."""

    def __repr__(self) -> str:
        return "Inf"

    def __lt__(self, other: Any) -> bool:
        return False

    def __gt__(self, other: Any) -> bool:
        return not isinstance(other, _Inf)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, _Inf)

    def __le__(self, other: Any) -> bool:
        return isinstance(other, _Inf)

    def __ge__(self, other: Any) -> bool:
        return True

    def __hash__(self) -> int:
        return hash("Inf")


class _NegInf:
    """Sorts below everything."""

    def __repr__(self) -> str:
        return "-Inf"

    def __lt__(self, other: Any) -> bool:
        return not isinstance(other, _NegInf)

    def __gt__(self, other: Any) -> bool:
        return False

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, _NegInf)

    def __le__(self, other: Any) -> bool:
        return True

    def __ge__(self, other: Any) -> bool:
        return isinstance(other, _NegInf)

    def __hash__(self) -> int:
        return hash("-Inf")


INF = _Inf()
NEG_INF = _NegInf()


# ── PEP 440 ───────────────────────────────────────────────────────────────────────────────────────
_PEP440 = re.compile(
    r"^\s*v?"
    r"(?:(?P<epoch>\d+)!)?"
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d*))?"
    r"(?P<post>(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>\d*)))?"
    r"(?P<dev>[-_.]?dev[-_.]?(?P<dev_n>\d*))?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?"
    r"\s*$",
    re.IGNORECASE,
)
_PRE_NORMAL = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def _pep440_key(raw: str):  # noqa: ANN202
    m = _PEP440.match(raw)
    if not m:
        return _generic_key(raw)
    epoch = int(m.group("epoch") or 0)
    release = tuple(int(p) for p in m.group("release").split("."))
    # Trailing zeros are not significant: 1.0 == 1.0.0
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]

    pre = None
    if m.group("pre_l"):
        letter = m.group("pre_l").lower()
        pre = (_PRE_NORMAL.get(letter, letter), int(m.group("pre_n") or 0))
    post = None
    if m.group("post_n1"):
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n") or 0)
    dev = int(m.group("dev_n") or 0) if m.group("dev") else None

    # PEP 440 ordering: a dev release precedes everything of its release, a post release follows it.
    if pre is None and post is None and dev is not None:
        pre_key: Any = NEG_INF
    elif pre is None:
        pre_key = INF
    else:
        pre_key = pre
    post_key: Any = NEG_INF if post is None else post
    dev_key: Any = INF if dev is None else dev
    return (epoch, release, pre_key, post_key, dev_key)


# ── SemVer (npm, cargo, composer, go, nuget) ──────────────────────────────────────────────────────
_SEMVER = re.compile(
    r"^\s*v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:-(?P<pre>[0-9a-z.-]+))?"
    r"(?:\+(?P<build>[0-9a-z.-]+))?\s*$",
    re.IGNORECASE,
)


def _semver_pre_key(pre: str | None):  # noqa: ANN202
    """Absence of a pre-release outranks any pre-release; within one, numeric identifiers rank
    below alphanumeric ones (SemVer §11.4)."""
    if pre is None:
        return (INF,)
    parts: list[Any] = []
    for ident in pre.split("."):
        if ident.isdigit():
            parts.append((0, int(ident), ""))
        else:
            parts.append((1, 0, ident.lower()))
    return tuple(parts)


def _semver_key(raw: str):  # noqa: ANN202
    cleaned = raw.strip()
    if cleaned.lower().endswith("+incompatible"):      # Go module convention
        cleaned = cleaned[: -len("+incompatible")]
    m = _SEMVER.match(cleaned)
    if not m:
        return _generic_key(raw)
    release = tuple(int(p) for p in m.group("release").split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    return (0, release, _semver_pre_key(m.group("pre")), NEG_INF, INF)


# ── Maven ─────────────────────────────────────────────────────────────────────────────────────────
# Maven's qualifier ordering, lowest first; anything unrecognised sorts after the known qualifiers
# and is compared lexically (approximation of the reference implementation's rules).
_MAVEN_QUALIFIERS = {
    "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3,
    "rc": 4, "cr": 4, "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7,
}


def _maven_key(raw: str):  # noqa: ANN202
    tokens = re.split(r"[.\-_]", raw.strip().lower())
    numeric: list[int] = []
    qualifier_rank = _MAVEN_QUALIFIERS[""]
    qualifier_num = 0
    qualifier_text = ""
    for tok in tokens:
        if tok.isdigit():
            if qualifier_rank == _MAVEN_QUALIFIERS[""] and not qualifier_text:
                numeric.append(int(tok))
            else:
                qualifier_num = int(tok)
            continue
        m = re.match(r"^([a-z]+)(\d*)$", tok)
        if m and m.group(1) in _MAVEN_QUALIFIERS:
            qualifier_rank = _MAVEN_QUALIFIERS[m.group(1)]
            if m.group(2):
                qualifier_num = int(m.group(2))
        elif tok:
            qualifier_rank = 8
            qualifier_text = tok
    while len(numeric) > 1 and numeric[-1] == 0:
        numeric.pop()
    return (0, tuple(numeric), ((qualifier_rank, qualifier_num, qualifier_text),), NEG_INF, INF)


# ── Debian ────────────────────────────────────────────────────────────────────────────────────────
def _debian_order(ch: str) -> int:
    """Debian's collation: `~` sorts before the empty string, letters before everything else."""
    if ch == "~":
        return -1
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _debian_compare_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _debian_order(a[i]) if i < len(a) else 0
            bc = _debian_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if first_diff == 0:
                first_diff = (ord(a[i]) > ord(b[j])) - (ord(a[i]) < ord(b[j]))
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


@total_ordering
@dataclass(frozen=True)
class _EvrVersion:
    """Debian/RPM epoch:version-release, compared by the distribution's own algorithm."""

    epoch: int
    upstream: str
    revision: str
    rpm: bool = False

    def _cmp(self, other: _EvrVersion) -> int:
        if self.epoch != other.epoch:
            return -1 if self.epoch < other.epoch else 1
        compare = _rpm_compare_part if self.rpm else _debian_compare_part
        result = compare(self.upstream, other.upstream)
        if result:
            return result
        return compare(self.revision, other.revision)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _EvrVersion):
            return NotImplemented
        return self._cmp(other) < 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _EvrVersion):
            return NotImplemented
        return self._cmp(other) == 0

    def __hash__(self) -> int:
        return hash((self.epoch, self.upstream, self.revision))


def _parse_evr(raw: str, *, rpm: bool) -> _EvrVersion:
    text = raw.strip()
    epoch = 0
    if ":" in text:
        head, _, tail = text.partition(":")
        if head.isdigit():
            epoch, text = int(head), tail
    upstream, sep, revision = text.rpartition("-")
    if not sep:
        upstream, revision = text, ""
    return _EvrVersion(epoch=epoch, upstream=upstream, revision=revision, rpm=rpm)


def _rpm_compare_part(a: str, b: str) -> int:
    """rpmvercmp: alternating alphabetic and numeric runs; `~` sorts before anything, including
    the end of string, so `1.0~rc1` precedes `1.0`."""
    i = j = 0
    while i < len(a) or j < len(b):
        if i < len(a) and a[i] == "~" and j < len(b) and b[j] == "~":
            i += 1
            j += 1
            continue
        if i < len(a) and a[i] == "~":
            return -1
        if j < len(b) and b[j] == "~":
            return 1
        while i < len(a) and not a[i].isalnum():
            i += 1
        while j < len(b) and not b[j].isalnum():
            j += 1
        if i >= len(a) or j >= len(b):
            break
        if a[i].isdigit():
            if not b[j].isdigit():
                return 1                      # numeric segments outrank alphabetic ones
            si, sj = i, j
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
            na, nb = a[si:i].lstrip("0") or "0", b[sj:j].lstrip("0") or "0"
            if len(na) != len(nb):
                return -1 if len(na) < len(nb) else 1
            if na != nb:
                return -1 if na < nb else 1
        else:
            if b[j].isdigit():
                return -1
            si, sj = i, j
            while i < len(a) and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isalpha():
                j += 1
            sa, sb = a[si:i], b[sj:j]
            if sa != sb:
                return -1 if sa < sb else 1
    if i >= len(a) and j >= len(b):
        return 0
    return 1 if i < len(a) else -1


# ── generic fallback ──────────────────────────────────────────────────────────────────────────────
def _generic_key(raw: str):  # noqa: ANN202
    """Split into numeric and non-numeric runs so unparseable strings still order sensibly."""
    parts: list[Any] = []
    for tok in re.findall(r"\d+|[a-zA-Z]+", raw.strip().lower()):
        parts.append((0, int(tok), "") if tok.isdigit() else (1, 0, tok))
    return (0, tuple(), tuple(parts) or ((1, 0, raw.strip().lower()),), NEG_INF, INF)


# ── public API ────────────────────────────────────────────────────────────────────────────────────
def version_key(raw: str, ecosystem: Ecosystem | str = Ecosystem.GENERIC):  # noqa: ANN201
    """A sortable key for `raw` under `ecosystem`'s rules. Never raises."""
    eco = ecosystem if isinstance(ecosystem, Ecosystem) else normalize_ecosystem(ecosystem)
    text = (raw or "").strip()
    if not text:
        return _generic_key("")
    try:
        if eco is Ecosystem.PYPI:
            return _pep440_key(text)
        if eco in (Ecosystem.NPM, Ecosystem.SEMVER, Ecosystem.GO, Ecosystem.NUGET,
                   Ecosystem.RUBYGEMS):
            return _semver_key(text)
        if eco is Ecosystem.MAVEN:
            return _maven_key(text)
        if eco is Ecosystem.DEBIAN:
            return _parse_evr(text, rpm=False)
        if eco is Ecosystem.RPM:
            return _parse_evr(text, rpm=True)
    except Exception:  # noqa: BLE001 - an unparseable version must degrade, never abort a scan
        return _generic_key(text)
    return _generic_key(text)


def compare(a: str, b: str, ecosystem: Ecosystem | str = Ecosystem.GENERIC) -> int:
    """-1 / 0 / 1 for a<b, a==b, a>b. Mismatched key shapes fall back to generic ordering."""
    ka, kb = version_key(a, ecosystem), version_key(b, ecosystem)
    try:
        if ka == kb:
            return 0
        return -1 if ka < kb else 1
    except TypeError:
        ga, gb = _generic_key(a), _generic_key(b)
        if ga == gb:
            return 0
        return -1 if ga < gb else 1


# ── range evaluation ──────────────────────────────────────────────────────────────────────────────
# Advisories express affected versions two ways. OSV uses an event stream — `introduced` at one
# version, `fixed` at another — which is precise but only meaningful once the events are sorted.
# Most other feeds use constraint strings (`>=1.0,<1.4.2`). Both are supported so ingestion can
# store whichever a source publishes, without a lossy conversion in between.

_CONSTRAINT = re.compile(r"^\s*(?P<op>>=|<=|==|!=|>|<|~>|\^|=)?\s*(?P<ver>[^\s,]+)\s*$")
# A bound must at least begin like a version. Without this, `>>>garbage` parses as `>` plus the
# bound `>>garbage`, generic ordering reports the running version as greater, and a malformed
# constraint silently claims a match — a false positive manufactured out of a typo in a feed.
_BOUND = re.compile(r"^[vV]?\d")


def _event_points(events: list[dict], eco: Ecosystem) -> list[tuple[Any, str]]:
    """(sort key, kind) for each event. `introduced: "0"` means the beginning of time."""
    points: list[tuple[Any, str]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in event:
                raw = str(event[kind])
                key = NEG_INF if (kind == "introduced" and raw in {"0", ""}) else \
                    version_key(raw, eco)
                points.append((key, kind))
                break
    return points


def _sortable(points: list[tuple[Any, str]]) -> list[tuple[Any, str]]:
    """Sort event points, tolerating the sentinel that stands in for 'from the beginning'."""
    try:
        return sorted(points, key=lambda p: (isinstance(p[0], _NegInf) and -1 or 0,))  # stable pre
    except TypeError:
        return points


def in_event_range(version: str, events: list[dict], ecosystem: Ecosystem | str) -> bool:
    """OSV semantics: affected when the latest event at or before `version` is an `introduced`."""
    eco = ecosystem if isinstance(ecosystem, Ecosystem) else normalize_ecosystem(ecosystem)
    points = _event_points(events, eco)
    if not points:
        return False
    vkey = version_key(version, eco)

    affected = False
    # Evaluate in version order. Events from a single OSV range are already ordered in practice,
    # but a feed is untrusted input, so ordering is established here rather than assumed.
    def _le(point_key: Any) -> bool:
        if isinstance(point_key, _NegInf):
            return True
        try:
            return not (vkey < point_key)
        except TypeError:
            return False

    def _lt(point_key: Any) -> bool:
        if isinstance(point_key, _NegInf):
            return True
        try:
            return point_key < vkey
        except TypeError:
            return False

    ordered = _sortable(points)
    for key, kind in ordered:
        if kind == "introduced" and _le(key):
            affected = True
        elif kind in {"fixed", "limit"} and _le(key):
            affected = False
        elif kind == "last_affected" and _lt(key) and not _le(key):
            affected = False
    # `last_affected` is inclusive: anything strictly greater is no longer affected.
    for key, kind in ordered:
        if kind == "last_affected" and not isinstance(key, _NegInf):
            try:
                if key < vkey:
                    affected = False
            except TypeError:
                pass
    return affected


def satisfies_constraint(version: str, constraint: str, ecosystem: Ecosystem | str) -> bool:
    """Evaluate one comma-separated constraint expression, e.g. `>=1.0,<1.4.2`."""
    eco = ecosystem if isinstance(ecosystem, Ecosystem) else normalize_ecosystem(ecosystem)
    clauses = [c for c in str(constraint).split(",") if c.strip()]
    if not clauses:
        return False
    for clause in clauses:
        m = _CONSTRAINT.match(clause)
        if not m:
            return False
        op = m.group("op") or "=="
        bound = m.group("ver")
        if not _BOUND.match(bound):
            return False
        try:
            result = compare(version, bound, eco)
        except Exception:  # noqa: BLE001 - a malformed bound must not claim a match
            return False
        if op in {"==", "="} and result != 0:
            return False
        if op == "!=" and result == 0:
            return False
        if op == ">" and result <= 0:
            return False
        if op == ">=" and result < 0:
            return False
        if op == "<" and result >= 0:
            return False
        if op == "<=" and result > 0:
            return False
        if op in {"~>", "^"}:
            # Compatible-release: at least the bound, below the next significant increment.
            if result < 0:
                return False
            parts = re.findall(r"\d+", bound)
            if parts:
                idx = 0 if op == "^" else max(0, len(parts) - 2)
                ceiling_parts = parts[: idx + 1]
                ceiling_parts[idx] = str(int(ceiling_parts[idx]) + 1)
                if compare(version, ".".join(ceiling_parts), eco) >= 0:
                    return False
    return True


def version_affected(entry: dict, version: str, ecosystem: Ecosystem | str | None = None) -> bool:
    """Is `version` affected by one advisory `affected` entry?

    Understands, in order of precedence: OSV `ranges` events, constraint strings, an explicit
    `versions` list, and finally a bare `version` field. An entry that pins nothing is treated as
    affecting the whole package — that is how package-level advisories are published, and treating
    it as "no match" would silently drop them.
    """
    eco = ecosystem or entry.get("ecosystem")
    eco_enum = eco if isinstance(eco, Ecosystem) else normalize_ecosystem(eco)
    version = (version or "").strip()
    if not version:
        return False

    ranges = entry.get("ranges")
    if isinstance(ranges, list) and ranges:
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events")
            if isinstance(events, list) and events and in_event_range(version, events, eco_enum):
                return True
            constraint = rng.get("constraint") or rng.get("range")
            if constraint and satisfies_constraint(version, str(constraint), eco_enum):
                return True
        # Explicit ranges that all evaluated false are a definite answer, not a fall-through.
        if not entry.get("versions") and not entry.get("version"):
            return False

    versions = entry.get("versions")
    if isinstance(versions, list) and versions:
        return any(compare(version, str(v), eco_enum) == 0 for v in versions)

    if entry.get("version"):
        return compare(version, str(entry["version"]), eco_enum) == 0

    constraint = entry.get("constraint")
    if constraint:
        return satisfies_constraint(version, str(constraint), eco_enum)

    return True  # package-level advisory with no version pinning → assume affected
