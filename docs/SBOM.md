# SBOM — Software Bill of Materials (CycloneDX)

**Status: IMPLEMENTED, multi-asset.** A scan produces one CycloneDX 1.5 SBOM merged from **every
engine that can enumerate components** — source dependencies, container image packages, server
packages (via the authorized agent), and the native libraries / frameworks bundled in a mobile app.
It is a *view* over inventories the scanners already resolve — **not a new scanner, not a new finding
type, and not a separate SBOM system per scanner.**

## Sources (one SBOM per scan, merged)

| Asset / engine | Components | Versions | Ecosystem (PURL) |
|---|---|---|---|
| Source repo — `sca` | manifest + lockfile dependencies | yes | pypi/npm/golang/gem/cargo/composer |
| Container image — `container` | OS + language packages (dpkg, apk, site-packages, node_modules) | yes | deb / apk / pypi / npm |
| Server — `host_posture` | submitted package inventory (authorized agent) | yes | deb / apk / rpm (from the OS) |
| Android `.apk` — `mobile` | bundled native libraries (`lib/<abi>/*.so`) | no* | generic |
| iOS `.ipa` — `ios` | embedded frameworks + dylibs | frameworks: yes; dylibs: no* | generic |

\* A static mobile package rarely exposes a library *version*; CycloneDX does not require one, so
these ship as version-less components — legitimate "what is inside this app" inventory. iOS
frameworks carry a version in their own `Info.plist` and are reported with it.

Any engine that exposes a `collect_inventory(ctx)` method contributes automatically; adding a new
source is one method, no pipeline change. Vulnerabilities are cross-referenced from the same scan's
findings, so the SBOM and the findings never disagree.

## Why it exists

An SBOM is a procurement and compliance deliverable: NTIA's minimum elements and US EO 14028 make a
bill of materials a routine ask from government and enterprise buyers. Guardian already resolved the
full dependency graph during SCA; before this, only the *vulnerable* components became findings and
the rest was discarded with the ephemeral scan workspace. The SBOM keeps the complete inventory so
it survives the scan and can be exported.

## What it is (and is not)

- **Is:** the CycloneDX 1.5 JSON inventory of every dependency the SCA engine resolved for the
  asset, with vulnerabilities cross-referenced from *this same scan's* SCA findings so the SBOM and
  the findings never disagree.
- **Is not:** a second dependency scanner, a separate finding store, or a separate report system.
  It reuses `guardian_core.sbom` (a pure serializer), the SCA engine's existing lockfile parsing,
  and the normal tenant/RLS persistence.

## How it is produced

1. An engine that can enumerate components exposes `collect_inventory(ctx)` returning a deduped
   `(name, version, ecosystem, source)` list — reusing the same parsing its `run()` already does
   for findings, without changing the findings path. Implemented on `sca`, `container`,
   `host_posture`, `mobile`, and `ios`.
2. As each engine in a scan completes, the pipeline (`tasks._accumulate_sbom`) collects that
   engine's inventory and any package vulnerabilities it found into scan-level accumulators. This is
   parent-side (not inside a sandboxed child), so it works whether or not an engine is sandboxed.
3. After the whole engine loop, `tasks._finalize_sbom` builds **one** CycloneDX document from the
   merged inventory + vulnerabilities and stores it. **Never fatal** — an SBOM is a bonus
   deliverable, so a failure here never fails the scan.
4. The document is persisted in `sbom_documents` (plain JSONB — an SBOM is a deliverable, not a
   secret), isolated per tenant by Row-Level Security like every other tenant-owned table.

## PURLs

Each component carries a Package-URL that is also its stable CycloneDX `bom-ref`:

| SCA ecosystem | purl type | example |
|---|---|---|
| pypi | pypi | `pkg:pypi/Flask@2.0.1` |
| npm | npm | `pkg:npm/lodash@4.17.19` |
| go | golang | `pkg:golang/golang.org/x/net@0.1.0` |
| rubygems | gem | `pkg:gem/rails@7.0.0` |
| cargo | cargo | `pkg:cargo/serde@1.0.0` |
| packagist | composer | `pkg:composer/monolog/monolog@2.0` |

An unknown ecosystem falls back to its own label as the purl type — a stable, honest PURL rather
than a wrong one. The document is **deterministic**: components are sorted and each carries a stable
ref, so two SBOMs of the same inventory are byte-identical and diff cleanly across scans.

## API

- `GET /api/v1/scans/{scan_id}/sbom/meta` — `{available, format, spec_version, component_count,
  vulnerable_count}`. Lets the UI show the download only when there is something to download.
- `GET /api/v1/scans/{scan_id}/sbom` — the CycloneDX JSON as an attachment
  (`application/vnd.cyclonedx+json`). Tenant-scoped (another tenant's scan 404s) and **audited**:
  who exported a customer's bill of materials is recorded (`scan.sbom.export`).

## Frontend

The scan detail screen shows a **Software Bill of Materials (SBOM)** card with the component and
vulnerable counts and a *Download SBOM (CycloneDX JSON)* button — only when an SBOM exists. No fake
control is shown for a scan that produced none.

## Known limitations

- **Scope:** the SBOM covers what the scanners resolve — dependency manifests/lockfiles, container
  OS/language packages, submitted server packages, and bundled mobile libraries. It does not invent
  components a scanner cannot see.
- **Mobile versions:** a static `.apk`/`.ipa` rarely exposes native-library versions, so those
  components are version-less (iOS frameworks are the exception — versioned from their `Info.plist`).
  Version-less components carry no CVE correlation.
- **Server packages:** contributed only when the authorized local agent submits a package inventory
  (opt-in; the reference agent ships an empty list by default). RPM ecosystem is labelled from the
  OS but the image RPM database itself is still not parsed for the container path.
- **Format:** CycloneDX JSON only (the platform's self-SBOM in `tools/generate_sbom.py` uses the
  same shape). SPDX is not emitted.
- **Bounded:** the inventory is capped (20,000 components) and truncation is recorded in the
  document metadata, so a pathological input widens the SBOM but never makes it unbounded.
