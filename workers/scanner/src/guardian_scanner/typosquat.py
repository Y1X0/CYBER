"""Typosquat indicators for direct dependencies (SCA, additive to vuln matching).

A typosquat is a package whose *name* is a near-miss of a popular one — `python-dateuti`, `loadsh`,
`reqeusts` — betting a developer mistypes or misremembers. This is an INDICATOR, never a verdict: a
name resembling a popular package is a reason to look, not proof of malice. Findings built from this
module are labelled POTENTIAL (guardian_core CorrelationConfidence) and say "verify intent".

Two design points keep the false-positive rate honest:

* **Ecosystem-aware canonicalization.** PyPI normalizes names per PEP 503 (case-fold; runs of
  ``-``/``_``/``.`` collapse to a single ``-``), so ``python-dateutil`` and ``python_dateutil`` are
  the *same* package — comparing on the canonical form means a separator variant on PyPI is not a
  squat. npm does NOT normalize separators, so ``lo-dash`` and ``lodash`` are distinct and a
  separator variant there IS an indicator — which falls out of the edit-distance check naturally.
* **The package's own name never squats itself.** If the dependency's canonical name equals a
  popular entry, it *is* that package; distance 0 is excluded, only 1..threshold fires.

The popular list is small, bundled, and VERSIONED (`POPULAR_LIST_VERSION`) — no network to any
registry at scan time. It covers npm and PyPI at minimum. Everything here is pure and deterministic:
the same name yields the same result regardless of call order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Bump when the curated lists below change, so a finding can record which list produced it.
POPULAR_LIST_VERSION = "2026.09.1"

# Curated, roughly popularity-ordered. Not exhaustive — the point is high-value names attackers
# actually target. Order matters only for deterministic tie-breaking (earlier = preferred).
_POPULAR_NPM = (
    "react", "react-dom", "lodash", "axios", "express", "chalk", "commander", "debug", "next",
    "webpack", "typescript", "vue", "moment", "request", "async", "bluebird", "underscore",
    "jquery", "babel-core", "eslint", "prettier", "dotenv", "uuid", "classnames", "redux",
    "rxjs", "socket.io", "mongoose", "jsonwebtoken", "bcrypt", "node-fetch", "cross-env",
    "colors", "yargs", "inquirer", "glob", "semver", "ws", "cheerio", "nodemon", "body-parser",
    "cors", "passport", "winston", "mocha", "jest", "chai", "sinon", "ramda", "fastify",
)
_POPULAR_PYPI = (
    "requests", "urllib3", "setuptools", "certifi", "idna", "charset-normalizer", "numpy",
    "pyyaml", "six", "python-dateutil", "cryptography", "boto3", "botocore", "click", "jinja2",
    "flask", "django", "fastapi", "pydantic", "sqlalchemy", "pytest", "pandas", "scipy",
    "pillow", "wheel", "packaging", "attrs", "colorama", "tqdm", "beautifulsoup4", "lxml",
    "aiohttp", "httpx", "starlette", "uvicorn", "celery", "redis", "psycopg2", "pymongo",
    "matplotlib", "scikit-learn", "torch", "tensorflow", "openai", "typing-extensions",
    "markupsafe", "werkzeug", "pyjwt", "cffi", "protobuf", "grpcio",
)

_POPULAR = {"npm": _POPULAR_NPM, "pypi": _POPULAR_PYPI}
# Ecosystem hints the parsers emit that map onto a list we carry.
_ECOSYSTEM_ALIAS = {"npm": "npm", "node": "npm", "pypi": "pypi", "python": "pypi"}

_PEP503 = re.compile(r"[-_.]+")


@dataclass(frozen=True)
class TyposquatMatch:
    popular: str      # the popular package this name resembles
    distance: int     # Damerau-Levenshtein distance on canonical forms
    list_version: str


def _canonical(name: str, ecosystem: str) -> str:
    n = (name or "").strip().lower()
    if ecosystem == "pypi":
        return _PEP503.sub("-", n)          # PEP 503: separator runs collapse; variants are one pkg
    if ecosystem == "npm" and n.startswith("@") and "/" in n:
        return n.split("/", 1)[1]           # unscoped base — a scope can't launder a squat
    return n


def _damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (adjacent transposition counts as one edit)."""
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def _max_distance(popular: str) -> int:
    # Short names get only distance 1 — distance 2 on a 5-char name matches too much.
    return 1 if len(popular) <= 6 else 2


def nearest_popular(name: str, ecosystem: str) -> TyposquatMatch | None:
    """The popular package `name` most resembles (a near-miss), or None.

    Returns None when the name is not close to any popular package, or when it *is* one (its own
    name is never a squat). Deterministic: for a given (name, ecosystem) the same match is returned,
    ties broken by the list's fixed order.
    """
    eco = _ECOSYSTEM_ALIAS.get((ecosystem or "").lower())
    if eco is None:
        return None
    canon = _canonical(name, eco)
    if len(canon) < 4:                       # too short to distinguish a squat from a coincidence
        return None
    popular = _POPULAR[eco]
    popular_canon = [_canonical(p, eco) for p in popular]
    if canon in popular_canon:               # the package's own name — not a squat (hard rule)
        return None
    best: TyposquatMatch | None = None
    for original, pcanon in zip(popular, popular_canon, strict=True):
        distance = _damerau_levenshtein(canon, pcanon)
        if 1 <= distance <= _max_distance(pcanon) and (best is None or distance < best.distance):
            best = TyposquatMatch(popular=original, distance=distance,
                                  list_version=POPULAR_LIST_VERSION)
    return best


__all__ = ["POPULAR_LIST_VERSION", "TyposquatMatch", "nearest_popular"]
