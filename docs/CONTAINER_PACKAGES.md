# Container image package inventory

The container engine reads the software inside an image archive (`docker save` / OCI tar) and feeds
each `(name, version, ecosystem)` through the **same shared `VulnMatcher`** the SCA engine uses — so
a container inherits the version-range CVE matching (KB + OSV, KEV/EPSS) rather than a second
implementation of it. Everything is read **in memory, read-only, over the files the layer walker
already extracts**: no execution of image contents, no shelling out to `go`/`mvn`/`gem`/`rpm`, and
the existing archive-bomb / path-traversal / size caps apply throughout.

## What is inventoried

| Family | Source file(s) | Ecosystem tag |
|---|---|---|
| Debian/Ubuntu | `var/lib/dpkg/status` | `Debian` |
| Alpine | `lib/apk/db/installed` | `Alpine` |
| Python | `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` | `PyPI` |
| npm (installed) | `node_modules/**/package.json` | `npm` |
| **npm (locked)** | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` | `npm` |
| **Java** | `META-INF/maven/**/pom.properties` (groupId:artifactId), `META-INF/MANIFEST.MF` fallback — inside `.jar`/`.war`, one nested fat-jar level | `Maven` |
| **Ruby** | `Gemfile.lock`, `*.gemspec` | `RubyGems` |
| **Go** | modules embedded in a compiled binary (`go version -m` block) | `Go` |
| RPM | `var/lib/rpm/*`, `usr/lib/sysimage/rpm/*` | **not parsed — stated gap** |

Rows in **bold** are added in this batch. The npm-lockfile row captures transitive/locked versions a
bare `package.json` misses.

### Go binaries

The Go linker frames the module-info block (`path`/`mod`/`dep`/`build` lines, the same text
`go version -m` prints) between two fixed 16-byte sentinels in the binary's data. The parser locates
those sentinels and reads the `dep` lines — resolving `=>` replace directives to the version that
actually shipped — **without parsing ELF/PE/Mach-O sections and without running anything**. Only
files carrying an executable magic number are probed, and the number of binaries probed per image is
capped so a large image cannot be read wholesale into memory.

### Java JAR/WAR

`META-INF/maven/<group>/<artifact>/pom.properties` gives exact Maven coordinates
(`groupId:artifactId` + version); `META-INF/MANIFEST.MF` `Implementation-Title`/`-Version` (or
`Bundle-SymbolicName`/`-Version`) is a fallback. Fat/uber jars bundle jars — followed **one level**
deep, reusing the zip bomb caps (bounded member reads, entry count, and nested-jar count).

## What is skipped, and why — RPM

The **RPM database is deliberately not parsed.** It is a Berkeley DB (RHEL 7/8, `Packages` hash
file) or a sqlite blob (RHEL 9+/Fedora, `rpmdb.sqlite`), and in both cases each package record is an
RPM *header* binary structure (tag/type/offset/count index + data section). A correct pure-Python,
in-memory parser for that — with no `rpm` binary, no writing the untrusted DB to disk for `sqlite3`,
and full bomb-safety — is heavy and error-prone, and a wrong parse would **confidently mis-version
packages and silently clear real CVEs**, which is worse than a stated gap. The engine keeps emitting
the honest `image-rpm-not-parsed` scan-gap finding (an unread inventory and an empty one look
identical in a report; only one is good news). This matches the batch instruction: *if a safe pure
parser is too heavy, say so and skip rather than shell out to `rpm`.*

## Guarantees

- **One matcher, no parallel path.** All families dedup into one `(name, ecosystem) → latest-version`
  inventory (a later layer supersedes an earlier one) and are matched through the injected
  `VulnMatcher`; the SBOM (`collect_inventory`) reuses the exact same readers.
- **Deterministic.** Same image → same inventory → same findings, independent of walk order
  (dedup + sorted emission, sorted nested-jar and Go-module output).
- **Safe on malformed input.** A truncated jar, non-JSON lockfile, or a binary without the Go
  sentinels yields nothing and never raises; caps bound every read.
