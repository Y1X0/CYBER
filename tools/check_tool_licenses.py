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
BLOCKED_STATES = {"LEGAL_REVIEW", "PROHIBITED"}

_ROW = re.compile(r"^\|\s*\*{0,2}([^|*]+?)\*{0,2}\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|"
                  r"\s*`?(\w+)`?\s*\|\s*([^|]*?)\s*\|\s*$")
# Tools an image installs, however it installs them.
_INSTALL = re.compile(
    r"(?:apt-get\s+install|apk\s+add|go\s+install|pip\s+install|npm\s+i(?:nstall)?)\s+([^\n&|]+)"
)
_BINARY_HINT = re.compile(r"(?:^|/)([a-z0-9][a-z0-9_-]{2,})(?:@|$)")


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
        if state.upper() not in APPROVED_STATES | BLOCKED_STATES:
            continue                      # header and separator rows
        entry = Entry(name, version, licence, state, notes)
        if entry.name and not entry.name.startswith(("tool", "source", "-")):
            entries[entry.name] = entry
    return entries


def tools_in_image(path: Path) -> set[str]:
    """Best-effort extraction of what an image installs. Deliberately over-inclusive: a false
    positive costs one registry row, a false negative ships an unreviewed binary."""
    if not path.exists():
        return set()
    found: set[str] = set()
    for match in _INSTALL.finditer(path.read_text(encoding="utf-8")):
        for token in match.group(1).split():
            token = token.strip().strip("\\").lower()
            if not token or token.startswith("-"):
                continue
            hint = _BINARY_HINT.search(token)
            if hint:
                found.add(hint.group(1))
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="infra/docker/Dockerfile.scanner", type=Path)
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

    if not args.image.exists():
        print(f"\nno runtime image at {args.image} yet — registry checked, nothing to enforce")
        return 0

    problems = check(args.image, registry)
    if problems:
        print(f"\n{len(problems)} licence problem(s) in {args.image}:")
        for problem in problems:
            print(f"  ✗ {problem}")
        return 1
    print(f"\nevery tool installed by {args.image} is approved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
