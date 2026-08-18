"""Inventory the software inside an image (WP-D6).

The point of reading these databases is to reach the existing `VulnMatcher` seam with real package
names and versions, so a container inherits the version-range matching built for SCA rather than a
second, subtly different implementation of it.

Only formats with a plain-text database are read: dpkg's `status` file and apk's `installed`. The
RPM database is a Berkeley DB / sqlite blob, and guessing at it would produce a package list that is
confidently wrong — which is worse than a stated gap, because a wrong version silently clears a real
CVE. `rpm_present()` reports the gap instead.
"""

from __future__ import annotations

from collections.abc import Iterator

DPKG_STATUS = "var/lib/dpkg/status"
APK_INSTALLED = "lib/apk/db/installed"
RPM_DB_PREFIXES = ("var/lib/rpm/", "usr/lib/sysimage/rpm/")

MAX_PACKAGES = 20_000


def parse_dpkg_status(text: str) -> Iterator[tuple[str, str, str, str]]:
    """Debian/Ubuntu. Yields (name, version, ecosystem, source).

    Only packages whose status line says they are actually installed are reported. A `deinstall ok
    config-files` entry still has a Version field, and counting it would attribute a CVE to a
    package that is not on the image.
    """
    count = 0
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        key = ""
        for line in block.splitlines():
            if line[:1] in (" ", "\t") and key:
                continue                                   # continuation of a multi-line field
            name, _, value = line.partition(":")
            if _:
                key = name.strip().lower()
                fields[key] = value.strip()
        status = fields.get("status", "")
        if "installed" not in status or status.startswith(("deinstall", "purge")):
            continue
        package, version = fields.get("package", ""), fields.get("version", "")
        if not package or not version:
            continue
        count += 1
        if count > MAX_PACKAGES:
            return
        yield package, version, "Debian", DPKG_STATUS


def parse_apk_installed(text: str) -> Iterator[tuple[str, str, str, str]]:
    """Alpine. The database is a sequence of `K:value` lines, blank-line separated."""
    count = 0
    for block in text.split("\n\n"):
        package, version = "", ""
        for line in block.splitlines():
            if line.startswith("P:"):
                package = line[2:].strip()
            elif line.startswith("V:"):
                version = line[2:].strip()
        if not package or not version:
            continue
        count += 1
        if count > MAX_PACKAGES:
            return
        yield package, version, "Alpine", APK_INSTALLED


def parse_python_metadata(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """A `*.dist-info/METADATA` or `*.egg-info/PKG-INFO` file inside the image.

    Site-packages is where a container's real Python dependency set lives: the requirements file
    that produced it is usually not in the image at all, and when it is, it lists ranges rather than
    what was actually installed.
    """
    name, version = "", ""
    for line in text.splitlines():
        if line.startswith("Name:") and not name:
            name = line[5:].strip()
        elif line.startswith("Version:") and not version:
            version = line[8:].strip()
        elif not line.strip():
            break                                          # headers end at the first blank line
    if name and version:
        yield name, version, "PyPI", source


def parse_node_package_json(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """An installed `node_modules/<pkg>/package.json` — the resolved version, not a range."""
    import json

    try:
        doc = json.loads(text)
    except ValueError:
        return
    if not isinstance(doc, dict):
        return
    name, version = doc.get("name"), doc.get("version")
    if isinstance(name, str) and isinstance(version, str) and name and version:
        yield name, version, "npm", source


def is_python_metadata(path: str) -> bool:
    return path.endswith(("dist-info/METADATA", "egg-info/PKG-INFO"))


def is_node_manifest(path: str) -> bool:
    return path.endswith("/package.json") and "/node_modules/" in f"/{path}"


def rpm_present(paths) -> bool:  # noqa: ANN001
    """Whether the image carries an RPM database this reader cannot parse.

    Reported as a gap in the scan rather than treated as "no packages found": an empty inventory and
    an unreadable inventory look identical in a report, and only one of them is good news.
    """
    return any(p.startswith(RPM_DB_PREFIXES) for p in paths)
