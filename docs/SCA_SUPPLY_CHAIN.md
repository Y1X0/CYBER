# SCA supply-chain signals: malicious packages & typosquats

The SCA engine already matches dependencies to known vulnerabilities (range-aware version→CVE via the
KB + OSV, enriched with KEV/EPSS/exploit maturity). This adds a **separate, orthogonal** capability:
flagging packages that are **malicious** or **typosquats**, not just vulnerable. The vuln→CVE path is
unchanged.

## 1. Malicious-package advisories (CONFIRMED)

OSV publishes malicious-package advisories under **`MAL-`** ids. These already flow into the
knowledge base through the **same feed seam** as every other advisory — `sync_osv` pulls each
ecosystem's whole corpus and `parse_osv_record` keeps the `MAL-` id when there is no CVE alias, so
nothing new is ingested. What's new is that a match is now **labelled and routed** correctly:

- `VulnMatch.malicious` is set by the matchers (`vuln_match._is_malicious`) when the advisory id
  starts with `MAL-` — a deterministic, source-defined signal, not a heuristic.
- When a dependency's exact name+version matches a `MAL-` advisory, the SCA engine emits a distinct
  **`malicious-dep`** finding (not `vuln-dep`):
  - **confidence tier `CONFIRMED`** (`guardian_core.CorrelationConfidence`), `confidence: high`;
  - **evidence** carries the advisory id, `source: osv-malicious-packages`, and `malicious: true`;
  - **severity** comes from the advisory but is **floored at HIGH** — a confirmed backdoored
    dependency is never low-severity, and `MAL-` records rarely carry a CVSS of their own;
  - remediation says to remove it, rotate any secret it could have read, and audit where it ran.
- Both the KB matcher and the optional osv-scanner path route `MAL-` to the same finding.

This is a lookup with a low false-positive rate: it fires only on an exact name+version match to a
published malicious-package advisory.

## 2. Typosquat indicators (POTENTIAL)

For each **direct** dependency (manifest-declared: `requirements*.txt`, `package.json` — never
transitive lockfile names, which would be noise), the engine flags names that closely resemble a
popular package. This is an **indicator, never a verdict**: `typosquat-dep`, confidence tier
**`POTENTIAL`**, `confidence: low`, `MEDIUM` severity, and copy that says *"name resembles popular
package X; verify intent"* — it is never presented as confirmed malicious.

`guardian_scanner/typosquat.py`:
- **Bundled, versioned popular lists** per ecosystem (npm + PyPI at minimum), `POPULAR_LIST_VERSION`
  stamped into every finding. **No network to any registry at scan time.**
- **Damerau-Levenshtein** distance (adjacent transposition = one edit) on canonical names, threshold
  1 for short names and 2 for longer ones.
- **Ecosystem-aware canonicalization** keeps the false-positive rate honest:
  - **PyPI** normalizes per PEP 503 (case-fold; `-`/`_`/`.` runs collapse), so `python_dateutil`
    and `python-dateutil` are the *same* package — a separator variant on PyPI is **not** a squat.
  - **npm** does not normalize separators, so `lo-dash` vs `lodash` (distance 1) **is** an indicator;
    a scoped name (`@evil/lodahs`) is compared on its unscoped base so a scope can't launder a squat.
- **The package's own name never squats itself**: if the canonical name equals a popular entry,
  distance 0 is excluded — only 1..threshold fires.
- **Deterministic**: pure functions, fixed list order for tie-breaking; the SCA engine emits
  typosquat findings in a stable `(name, ecosystem)` order, so the same manifest yields the same
  findings regardless of file-walk order.

## Reuse (no parallel framework)

Everything rides the existing seams: the `Finding`/`RawFinding` schema, `dependency_evidence`, the
`CorrelationConfidence` vocabulary (`confirmed`/`potential`) from the correlation work, `VulnMatch`
and the `VulnMatcher` protocol, and the OSV feed/ingestion path. No new data store, no new matcher
framework, no registry calls at scan time.

## Deferred / not in this batch

- **Scope-impersonation beyond the unscoped-base check** (e.g. an attacker-controlled npm scope that
  re-publishes a popular package under a look-alike scope) is only partially covered.
- **More ecosystems** for typosquat (Go, crates, RubyGems, Maven): the popular lists cover npm + PyPI
  for now; adding an ecosystem is a data-only change to `typosquat._POPULAR`.
