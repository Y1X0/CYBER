"""Inventory the software inside an image (WP-D6).

The point of reading these files is to reach the existing `VulnMatcher` seam with real package names
and versions, so a container inherits the version-range matching built for SCA rather than a second,
subtly different implementation of it.

Two families are read, both from files the layer walker already extracts, in memory, read-only:

* **OS packages** — dpkg's `status` file (Debian) and apk's `installed` (Alpine), plain-text DBs.
* **Language packages** — Python `dist-info`/`egg-info`, npm (`package.json` and now
  `package-lock.json`/`yarn.lock`), Java (`pom.properties` / `MANIFEST.MF` inside JAR/WAR, including
  one level of nested fat-jar), Ruby (`Gemfile.lock` / `*.gemspec`), and Go modules embedded in a
  compiled binary (`go version -m` block, located by the linker's sentinels — no section parsing,
  no execution).

The **RPM** database is deliberately NOT parsed: it is a Berkeley DB or a sqlite blob whose package
records are RPM header binary structures, and a safe pure-in-memory parser for it is heavy and
error-prone. Guessing at it would produce a package list that is confidently wrong — worse than a
stated gap, because a wrong version silently clears a real CVE. `rpm_present()` reports the gap
instead. Everything here is bounded (bomb-safe) and deterministic; malformed input yields nothing
rather than raising.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections.abc import Iterator

DPKG_STATUS = "var/lib/dpkg/status"
APK_INSTALLED = "lib/apk/db/installed"
RPM_DB_PREFIXES = ("var/lib/rpm/", "usr/lib/sysimage/rpm/")

MAX_PACKAGES = 20_000

# ── language-package limits (bomb-safe, mirror the image reader's posture) ──────────────────
_MAX_JAR_DEPTH = 1               # a fat/uber jar's directly-bundled jars (one level of nesting)
_MAX_JAR_ENTRIES = 50_000        # members scanned in one jar
_MAX_NESTED_JARS = 200           # nested jars followed per top-level jar
_MAX_ZIP_MEMBER_BYTES = 4_000_000  # a pom.properties / MANIFEST.MF is bytes; a nested jar is capped
_MAX_GO_MODINFO_BYTES = 2_000_000

# The 16-byte sentinels the Go linker writes around the module-info string in a compiled binary
# (runtime/debug/mod.go). The text between them is the `path/mod/dep/build` block `go version -m`
# reads — so the module list can be recovered without parsing ELF/PE/Mach-O sections at all.
_GO_INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
_GO_INFO_END = bytes.fromhex("f932433186182072008242104116d8f2")


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


# ── Go binaries ─────────────────────────────────────────────────────────────────────────────────
def parse_go_buildinfo(data: bytes, source: str) -> Iterator[tuple[str, str, str, str]]:
    """Modules embedded in a compiled Go binary. Yields (module, version, "Go", source).

    Read-only: the string between the linker's two 16-byte sentinels is the `go version -m` block —
    `dep\\t<path>\\t<version>\\t<hash>` lines, with `=>` replace directives. Nothing is executed and
    no binary sections are parsed, so this works across ELF/PE/Mach-O alike. A binary without the
    sentinels (not a module-mode Go build) yields nothing.
    """
    start = data.find(_GO_INFO_START)
    if start < 0:
        return
    end = data.find(_GO_INFO_END, start + len(_GO_INFO_START))
    if end < 0:
        return
    blob = data[start + len(_GO_INFO_START):end][:_MAX_GO_MODINFO_BYTES]
    text = blob.decode("utf-8", "replace")
    modules: dict[str, str] = {}
    prev: str | None = None     # the module path a following `=>` replace directive applies to
    for line in text.splitlines():
        parts = line.split("\t")
        tag = parts[0]
        if tag == "dep" and len(parts) >= 3:
            path, version = parts[1].strip(), parts[2].strip()
            prev = path
            if path and version and not version.startswith("("):
                modules[path] = version
        elif tag == "mod" and len(parts) >= 2:
            prev = parts[1].strip()            # the main module is not itself a dependency
        elif tag == "=>" and len(parts) >= 3 and prev is not None:
            # A replace directive: the replacement (path may differ) is what actually shipped.
            path, version = parts[1].strip(), parts[2].strip()
            modules.pop(prev, None)
            if path and version and not version.startswith("("):
                modules[path] = version
            prev = None
        if len(modules) > MAX_PACKAGES:
            break
    for path in sorted(modules):               # sorted: deterministic, order-independent
        yield path, modules[path], "Go", source


def looks_like_binary(data: bytes) -> bool:
    """A cheap gate before scanning a file for Go build info: an executable magic number."""
    return data[:4] in (b"\x7fELF", b"MZ\x90\x00", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") \
        or data[:2] == b"MZ" or data[:4] == b"\xca\xfe\xba\xbe"


# ── Java: JAR / WAR (Maven coordinates) ───────────────────────────────────────────────────────────
_POM_RE = re.compile(r"(?m)^\s*(groupId|artifactId|version)\s*=\s*(.+?)\s*$")


def parse_jar(data: bytes, source: str, _depth: int = 0, _budget: list[int] | None = None
              ) -> Iterator[tuple[str, str, str, str]]:
    """Dependencies inside a JAR/WAR. Yields (groupId:artifactId, version, "Maven", source).

    Prefers `META-INF/maven/**/pom.properties` (exact coordinates); falls back to
    `META-INF/MANIFEST.MF` Implementation-Title/Version. Fat/uber jars nest jars — followed to a
    bounded depth, reusing the archive-bomb caps. Malformed input yields nothing, never raises.
    """
    if _budget is None:
        _budget = [_MAX_NESTED_JARS]
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return
    manifest_bytes: bytes | None = None
    found_pom = False
    nested: list[str] = []
    with zf:
        names = zf.namelist()[:_MAX_JAR_ENTRIES]
        for name in names:
            if name.endswith("pom.properties") and "META-INF/maven/" in name:
                fields: dict[str, str] = {}
                for key, value in _POM_RE.findall(_zip_text(zf, name)):
                    fields[key] = value
                group, artifact = fields.get("groupId"), fields.get("artifactId")
                version = fields.get("version")
                if group and artifact and version:
                    found_pom = True
                    yield f"{group}:{artifact}", version, "Maven", source
            elif name.endswith("META-INF/MANIFEST.MF") and manifest_bytes is None:
                manifest_bytes = _zip_bytes(zf, name)
            elif name.endswith((".jar", ".war")) and _depth < _MAX_JAR_DEPTH and _budget[0] > 0:
                nested.append(name)
        if not found_pom and manifest_bytes is not None:
            title, version = _manifest_coordinate(manifest_bytes.decode("utf-8", "replace"))
            if title and version:
                yield title, version, "Maven", source
        for name in sorted(nested):            # sorted: deterministic across runs
            if _budget[0] <= 0:
                break
            _budget[0] -= 1
            inner = _zip_bytes(zf, name)
            if inner:
                yield from parse_jar(inner, f"{source}!{name}", _depth + 1, _budget)


def _manifest_coordinate(text: str) -> tuple[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            values[key.strip().lower()] = value.strip()
    title = values.get("implementation-title") or values.get("bundle-symbolicname", "")
    version = values.get("implementation-version") or values.get("bundle-version", "")
    return title.split(";")[0].strip(), version


def _zip_bytes(zf: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        with zf.open(name) as fh:
            return fh.read(_MAX_ZIP_MEMBER_BYTES)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return None


def _zip_text(zf: zipfile.ZipFile, name: str) -> str:
    data = _zip_bytes(zf, name)
    return data.decode("utf-8", "replace") if data else ""


# ── Ruby: Gemfile.lock / *.gemspec ────────────────────────────────────────────────────────────────
_GEMSPEC_NAME = re.compile(r"""\.name\s*=\s*["']([^"']+)["']""")
_GEMSPEC_VERSION = re.compile(r"""\.version\s*=\s*["']([^"']+)["']""")


def parse_gemfile_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """Bundler's lockfile — the indented `name (version)` entries under GEM/specs are the resolved
    versions. Yields (name, version, "RubyGems", source)."""
    in_specs = False
    count = 0
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            m = re.match(r"^\s{4,6}([A-Za-z0-9_.-]+) \(([^)<>=~ ]+)\)\s*$", line)
            if m:
                count += 1
                if count > MAX_PACKAGES:
                    return
                yield m.group(1), m.group(2), "RubyGems", source


def parse_gemspec(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """A `*.gemspec` — read its declared name and version by regex (never evaluated as Ruby)."""
    name = _GEMSPEC_NAME.search(text)
    version = _GEMSPEC_VERSION.search(text)
    if name and version:
        yield name.group(1), version.group(1), "RubyGems", source


# ── npm lockfiles (resolved/transitive versions, unlike a bare package.json) ─────────────
def parse_package_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """npm package-lock.json / npm-shrinkwrap.json — v2/v3 `packages`, else v1 `dependencies`."""
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    count = 0
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if name and version:
                count += 1
                if count > MAX_PACKAGES:
                    return
                yield str(name), str(version), "npm", source
        return

    def _walk(node, depth=0):  # noqa: ANN001, ANN202
        if depth > 50 or not isinstance(node, dict):
            return
        for name, meta in node.items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    yield str(name), str(meta["version"]), "npm", source
                yield from _walk(meta.get("dependencies") or {}, depth + 1)
    dependencies = data.get("dependencies") or {}
    for name, version, ecosystem, src in _walk(dependencies):
        count += 1
        if count > MAX_PACKAGES:
            return
        yield name, version, ecosystem, src


def parse_yarn_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """yarn.lock (classic + berry): an entry block keys one or more specs, then states `version`."""
    current: list[str] = []
    count = 0
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            current = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                name = spec[: spec.rfind("@")] if spec.rfind("@") > 0 else spec
                if name:
                    current.append(name)
        else:
            stripped = line.strip()
            if stripped.startswith("version") and current:
                version = stripped.split(None, 1)[-1].strip().strip('"').strip("'")
                for name in current:
                    count += 1
                    if count > MAX_PACKAGES:
                        return
                    yield name, version, "npm", source
                current = []


# ── detection ─────────────────────────────────────────────────────────────────────────────────────
def is_jar(path: str) -> bool:
    return path.endswith((".jar", ".war"))


def is_gemfile_lock(path: str) -> bool:
    return path.endswith("Gemfile.lock")


def is_gemspec(path: str) -> bool:
    return path.endswith(".gemspec")


def is_npm_lockfile(path: str) -> bool:
    return path.endswith(("/package-lock.json", "/npm-shrinkwrap.json", "/yarn.lock")) \
        or path in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock")


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
