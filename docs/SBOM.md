# SBOM — Software Bill of Materials (CycloneDX)

**Status: IMPLEMENTED.** Every scan that runs the SCA engine over an asset with dependency
manifests produces a CycloneDX 1.5 SBOM, downloadable from the scan. It is a *view* over the
dependency inventory the SCA engine already resolves — **not a new scanner and not a new finding
type**.

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

1. The SCA engine (`ScaEngine`) parses manifests and lockfiles as it always has. Its new
   `collect_inventory()` returns the **full** deduped `(name, version, ecosystem, source)` list —
   the same parsing `run()` uses for findings, exposed without changing the findings path.
2. After an SCA run completes, the scan pipeline (`tasks._maybe_store_sbom`) builds a CycloneDX
   document from that inventory plus the vulnerabilities just found, and stores one SBOM per scan.
   This is **never fatal** — an SBOM is a bonus deliverable, so a failure here never fails the scan.
3. The document is persisted in `sbom_documents` (plain JSONB — an SBOM is a deliverable, not a
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

- **Scope:** the SBOM covers what the SCA engine resolves — application dependency manifests and
  lockfiles (and, where present, container OS packages via the existing image inventory). It does
  not invent components the SCA engine cannot see.
- **Format:** CycloneDX JSON only (the platform's self-SBOM in `tools/generate_sbom.py` uses the
  same shape). SPDX is not emitted.
- **Bounded:** the inventory is capped (20,000 components) and truncation is recorded in the
  document metadata, so a pathological lockfile widens the SBOM but never makes it unbounded.
