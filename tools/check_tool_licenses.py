"""Refuse to ship a binary that the licence registry has not approved.

A scanner platform's value comes from tools other people wrote, which makes licence compliance a
shipping concern rather than a paperwork one. Two of the most obvious tools in the category cannot
be bundled at all: nmap's NPSL restricts redistribution in a commercial product, and masscan and
TruffleHog are AGPL, whose §13 covers exactly the network interaction a SaaS product is.

So the registry is the gate. This reads the runtime image definition, extracts the tools it
installs, and fails when any of them is missing from `docs/TOOL_LICENSES.md` or is not approved.
A tool nobody reviewed is treated as unapproved — the default has to be refusal, because the
failure mode of the opposite default is discovered during due diligence.

Usage:
    python tools/check_tool_licenses.py [--image infra/docker/Dockerfile.scanner]
    python tools/check_tool_licenses.py --notice > NOTICE
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REGISTRY = Path("docs/TOOL_LICENSES.md")

APPROVED_STATES = {"APPROVED", "APPROVED_SEPARATE_PROCESS"}
# NOT_ADOPTED: the licence is fine but the capability is deliberately not used, so the tool must not
# appear in an image either. Blocked, with a different reason from a licence block.
BLOCKED_STATES = {"LEGAL_REVIEW", "PROHIBITED", "NOT_ADOPTED"}
# Column headings, not states. Anything else unrecognized is a typo in a security gate and is
# fatal:
# silently skipping it would drop a tool out of the registry, and an unregistered tool is one the
# gate can no longer refuse.
_NON_STATE = {"STATUS", "STATE", "APPROVAL"}

_ROW = re.compile(r"^\|\s*\*{0,2}([^|*]+?)\*{0,2}\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|"
                  r"\s*`?(\w+)`?\s*\|\s*([^|]*?)\s*\|\s*$")
# Tools an image installs via a package manager.
_INSTALL = re.compile(
    r"(?:apt-get\s+install|apk\s+add|go\s+install|pip\s+install|npm\s+i(?:nstall)?)\s+([^\n&|]+)"
)
# Tools an image installs by DOWNLOADING a release — the pattern this repo actually uses for its
# main binaries (trivy, gitleaks, syft, grype, osv-scanner all arrive via `curl … | tar`). The
# package-manager regex above never saw them, so a curl-fetched prohibited binary walked straight
# past the gate — the exact false negative the tool exists to prevent (Phase-0 audit P1-2). Three
# complementary signals, deliberately over-inclusive:
#   * the binary named as the member extracted from a tarball: `tar -xzf trivy.tgz trivy`;
#   * a bare binary written by curl/wget with `-o name` (no archive extension): `-o osv-scanner`;
#   * the repo in a GitHub release URL when it appears literally: `github.com/owner/grype/releases`.
_TAR_MEMBER = re.compile(
    r"tar\s+-[A-Za-z]*x[A-Za-z]*f?\s+\S+\.(?:tgz|tar\.gz|tar|tar\.xz)\s+([A-Za-z0-9][\w.+-]+)")
_CURL_OUT = re.compile(r"(?:curl|wget)\b[^\n&|]*?\s-o\s+(\S+)")
_GH_RELEASE = re.compile(r"github\.com/[\w.-]+/([\w.-]+)/releases/download")
_ARCHIVE_SUFFIX = (".tgz", ".tar.gz", ".tar", ".tar.xz", ".zip", ".gz")
# A package token can arrive as `name`, `"name==1.2.3"`, `name@v1.2.3`, `owner/repo@v1`, or
# `name=1.2-3` (apk/apt pins). Anchoring on "ends with @ or end-of-string" missed every quoted
# pip pin — semgrep and checkov walked straight past the gate, which is the false negative this
# tool exists to prevent. Strip decoration first, then take the package name.
_BINARY_HINT = re.compile(r"^([a-z0-9][a-z0-9_.+-]{1,})$")


def _package_name(token: str) -> str | None:
    """The package a token installs, or None when the token is not a package."""
    token = token.strip().strip("\"'").lower()
    if not token or token.startswith("-"):
        return None
    # A requirements file (`-r requirements.lock`/`.txt`) is not a third-party tool to licence-gate:
    # it lists the app's OWN pinned dependencies, audited separately (pip-audit against the lock in
    # CI). Without this the lock filename was mis-read as a package needing a registry row.
    if token.endswith((".lock", ".txt")):
        return None
    for sep in ("==", ">=", "<=", "~=", "@", "="):
        if sep in token:
            token = token.split(sep, 1)[0]
            break
    token = token.rsplit("/", 1)[-1]          # owner/repo → repo
    m = _BINARY_HINT.match(token)
    return m.group(1) if m else None


class Entry:
    __slots__ = ("name", "version", "licence", "state", "notes")

    def __init__(self, name, version, licence, state, notes):  # noqa: ANN001
        self.name = name.strip().lower()
        self.version = version.strip()
        self.licence = licence.strip()
        self.state = state.strip().upper()
        self.notes = notes.strip()


def load_registry(path: Path = REGISTRY) -> dict[str, Entry]:
    if not path.exists():
        raise SystemExit(f"licence registry missing: {path}")
    entries: dict[str, Entry] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        name, version, licence, state, notes = m.groups()
        if state.upper() in _NON_STATE:
            continue                      # the table header
        if state.upper() not in APPROVED_STATES | BLOCKED_STATES:
            raise SystemExit(
                f"licence registry: unknown state {state!r} for {name.strip()!r}. "
                f"Valid states: {sorted(APPROVED_STATES | BLOCKED_STATES)}"
            )
        entry = Entry(name, version, licence, state, notes)
        if entry.name and not entry.name.startswith(("tool", "source", "-")):
            entries[entry.name] = entry
    return entries


def tools_in_image(path: Path) -> set[str]:
    """Best-effort extraction of what an image installs. Deliberately over-inclusive: a false
    positive costs one registry row, a false negative ships an unreviewed binary."""
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8")
    found: set[str] = set()

    # Package-manager installs.
    for match in _INSTALL.finditer(text):
        for token in match.group(1).split():
            name = _package_name(token.strip("\\"))
            if name:
                found.add(name)

    # Downloaded-release installs (curl|tar / curl -o / GitHub release URL).
    for member in _TAR_MEMBER.findall(text):
        name = _package_name(member)
        if name:
            found.add(name)
    for target in _CURL_OUT.findall(text):
        cleaned = target.strip("\"'\\")
        if cleaned.lower().endswith(_ARCHIVE_SUFFIX):
            continue                      # `-o trivy.tgz` is the archive, not the tool
        name = _package_name(cleaned)
        if name:
            found.add(name)
    for repo in _GH_RELEASE.findall(text):
        name = _package_name(repo)
        if name:
            found.add(name)

    return found


def check(image: Path, registry: dict[str, Entry]) -> list[str]:
    problems: list[str] = []
    for tool in sorted(tools_in_image(image)):
        entry = registry.get(tool)
        if entry is None:
            problems.append(
                f"{tool}: installed by {image} but absent from the licence registry. "
                f"Add a row to {REGISTRY} with its licence and approval state.")
        elif entry.state in BLOCKED_STATES:
            problems.append(
                f"{tool}: state is {entry.state} ({entry.licence}). {entry.notes}")
    return problems


def render_notice(registry: dict[str, Entry]) -> str:
    lines = ["Guardian bundles the following third-party tools.", ""]
    for entry in sorted(registry.values(), key=lambda e: e.name):
        if entry.state in APPROVED_STATES:
            lines.append(f"  {entry.name} ({entry.version or 'pinned'}) — {entry.licence}")
    lines.append("")
    lines.append("Vulnerability data is provided by OSV.dev, the NVD, the GitHub Advisory")
    lines.append("Database, CISA KEV and FIRST EPSS, under their respective terms.")
    return "\n".join(lines)


# Every runtime image that ships tools. Both must be gated: the scanner image installs the SCA and
# secrets binaries, and the worker-tools image installs the network-plane binaries (nftables today,
# nmap/naabu tomorrow). Gating only the first — the previous behaviour — left the second able
# to ship a blocked binary with no CI catching it (Phase-0 audit P1-2).
_DEFAULT_IMAGES = ("infra/docker/Dockerfile.scanner", "infra/docker/Dockerfile")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", type=Path,
                        help="a runtime image to gate; repeatable. Defaults to every shipping "
                             "image.")
    parser.add_argument("--notice", action="store_true", help="print a NOTICE file and exit")
    args = parser.parse_args(argv)

    registry = load_registry()
    if args.notice:
        print(render_notice(registry))
        return 0

    blocked = [e for e in registry.values() if e.state in BLOCKED_STATES]
    print(f"registry: {len(registry)} tools, {len(blocked)} not approved for shipping")
    for entry in sorted(blocked, key=lambda e: e.name):
        print(f"  {entry.state:<14} {entry.name} ({entry.licence})")

    # An explicitly-named image that does not exist is a HARD failure: a renamed or removed
    # Dockerfile must turn the gate red, not green. When no --image is given we gate every default
    # image that exists, and require at least one — a repo with no gateable image is itself a fault.
    explicit = args.image is not None
    images = args.image if explicit else [Path(p) for p in _DEFAULT_IMAGES]

    present = [img for img in images if img.exists()]
    missing = [img for img in images if not img.exists()]

    if explicit and missing:
        for img in missing:
            print(f"\n✗ requested image {img} does not exist — the gate cannot verify it")
        return 1
    if not present:
        print("\n✗ no runtime image found to gate — "
              f"expected one of {', '.join(str(p) for p in images)}")
        return 1
    for img in missing:
        print(f"\nnote: {img} not present, skipping (not explicitly requested)")

    total = 0
    for img in present:
        problems = check(img, registry)
        total += len(problems)
        if problems:
            print(f"\n{len(problems)} licence problem(s) in {img}:")
            for problem in problems:
                print(f"  ✗ {problem}")
        else:
            print(f"\nevery tool installed by {img} is approved")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
