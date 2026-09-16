# Scan artifact uploads (.apk / .ipa)

The console offers "Upload the .apk / .ipa" for the mobile scanners. This document is the real path
behind that offer — how an artifact is uploaded, stored, secured, resolved by the worker, and cleaned
up — and, deliberately, what is **not** upload-driven and why. It closes the onboarding gap AUD-P1-7
and the artifact-boundary issues AUD-P1-6 (arbitrary worker file read) and AUD-P1-5 (decompression
bombs) from `FULL_PRODUCT_AUDIT.md`.

## Which asset types take an upload

Only the two whose scan genuinely consumes an uploaded binary:

| Asset kind | Artifact | Engine | Analysis |
|------------|----------|--------|----------|
| `mobile_app` | Android `.apk` | `mobile` | static, offline, never executed |
| `ios_app` | iOS `.ipa` | `ios` | static, offline, never executed |

Every other asset kind is driven by input that is **not** a browser upload, and the console says so:

| Asset kind | Input | Not an upload because |
|------------|-------|------------------------|
| `repo` | git URL (or inline content) | the worker clones it (SSRF-guarded) |
| `web` / `api` | URL (+ optional OpenAPI spec in config) | live/declared target, not a file |
| `cloud_account` | read-only collector export (JSON in config) | structured config, not a binary |
| `network_host` / `server_host` | local-agent posture report (JSON) | produced by the agent |
| `k8s_manifest` | manifests via inline content / workspace | text, not a binary artifact |
| `container_image` | image archive **via the API**, not the console | image tarballs are far too large for a browser upload / Postgres row; the console copy states this rather than implying an upload |

The mapping is defined once in `guardian_core.artifacts.ASSET_KIND_TO_ARTIFACT` and consumed by the
API, the worker, and the frontend catalog — there is no place for the surfaces to drift.

## Storage: Postgres, because the pilot disk is ephemeral

Artifacts are stored **in Postgres** (`scan_artifacts.content`, a `bytea`), exactly as the SBOM and
evidence are. This is a deliberate deployment-reality choice:

- The pilot runs on Render's free tier, whose **local disk is ephemeral** — a worker restart wipes
  it. Writing an uploaded artifact to local disk would silently lose customer uploads between the
  upload and the scan. There is **no object storage and no persistent disk** in this deployment.
- Postgres is the platform's durable store. An artifact written there survives to the moment the scan
  runs and is isolated per tenant by Row-Level Security like every other tenant-owned table.

**Durability caveat (documented, not hidden):** the free pilot Postgres itself is deleted after 30
days (`render.yaml`) — a property of the whole database, not of this feature. A production deployment
must use managed Postgres (already a documented pilot→production step). No part of this feature
pretends ephemeral storage is durable.

If artifacts ever outgrow row storage (they are bounded to 100 MB, below), the `artifact_store`
seam is the single place to swap in object storage without touching the API or worker.

## Limits

All bounded, all from the project's config conventions (`guardian_common.config`):

| Limit | Value | Where |
|-------|-------|-------|
| Max artifact size | `artifact_max_bytes`, default **100 MiB** (`GUARDIAN_ARTIFACT_MAX_BYTES`) | upload endpoint (Content-Length pre-check + hard read cap) |
| Allowed types | `.apk`, `.ipa`, validated by **content** (zip structure), derived from the asset kind server-side | `guardian_core.artifacts.validate_artifact` |
| Filename | sanitized to a bounded basename, **display only**, never a path | `sanitize_filename` |
| Per-archive-member read (bomb guard) | 25 MiB bounded read; 15 MiB for whole-member parses | `guardian_scanner.mobile.safezip` |
| Per-scan content budget | 40 MiB (`_MAX_SCAN_BYTES` / `_MAX_SECRET_BYTES`) | mobile/iOS engines |

The size cap bounds worker memory as much as storage: the artifact is held in memory to store it and
again to read it statically, so 100 MiB is conservative for a small (single-instance, concurrency-1)
worker. Raise it for a larger deployment.

## Security boundary

- **Authentication / authorization:** upload/list/delete require `require_staff_write` (same
  authority as creating the asset). No unauthenticated upload endpoint exists.
- **Tenant isolation:** the table has RLS (`tenant_isolation`), and every lookup is additionally
  filtered by `tenant_id`. A tenant cannot upload to, read, or delete another tenant's asset by
  changing an id — verified by regression tests (`tests/integration/test_artifact_upload.py`).
- **Opaque references:** an artifact is addressed only by its server-generated UUID. The browser
  never supplies a filesystem path; the former free-form `apk_path` / `ipa_path` / `local_path` /
  `image_archive` config keys are no longer read by any engine (**AUD-P1-6 closed**).
- **Worker resolution:** the worker resolves the `artifact_id` on the asset config through a
  `(tenant_id, asset_id)`-scoped lookup, writes the bytes to a fresh temp dir under a fixed
  server-chosen filename, and passes only that path to the engine. An id smuggled in from another
  tenant/asset resolves to nothing.
- **Type honesty:** the bytes must actually be the archive the asset needs (zip magic + a structural
  marker: `AndroidManifest.xml` for APK, `Payload/*.app/` for IPA). A renamed PDF or a wrong-platform
  bundle is refused up front. Inspection reads only the zip central directory — never extraction or
  execution.
- **Decompression-bomb safety (AUD-P1-5):** all member reads are bounded (`safezip.read_bounded` /
  `read_whole_capped`) — a high-ratio DEFLATE member is never inflated past the budget, unlike the
  former `zipfile.read()[:n]` which decompressed the whole member first.
- **Static only:** an uploaded artifact is never executed, installed, or emulated. Mobile analysis
  stays static, exactly as before.
- **Safe errors:** upload failures return customer-safe messages (wrong type / too large / not a
  readable archive) with no filesystem path, tenant id, or stack trace; operators get structured log
  lines (`artifact_upload_accepted` / `artifact_upload_rejected`).

## Lifecycle and cleanup

- An upload is attached to its asset immediately (its id is written to `asset.config`), so there is
  no separate "pending upload" limbo to accumulate. Re-uploading replaces the pointer.
- The worker's materialized temp file is removed in a `finally` on **every** path — success, engine
  failure, or a failure outside the per-engine guard — so an uploaded binary never lingers on the
  worker.
- `DELETE /api/v1/assets/{id}/artifacts/{artifact_id}` removes an artifact and clears the asset
  pointer (so a later scan cleanly reports "needs upload").
- Deleting an asset cascades to its artifacts (`ON DELETE CASCADE`) — no orphaned, indefinitely
  stored blob.

**Deferred (intentionally):** there is no automatic time-based sweep of old-but-attached artifacts.
Given uploads are attached (not orphaned) and cascade on asset deletion, a retention subsystem would
be scope creep; if per-artifact TTL is wanted later, the `artifact_store` + the existing beat
scheduler are the seam.

## API

```
POST   /api/v1/assets/{asset_id}/artifact         multipart file=<.apk|.ipa>  → 201 ArtifactOut
GET    /api/v1/assets/{asset_id}/artifacts                                     → [ArtifactOut]
DELETE /api/v1/assets/{asset_id}/artifacts/{id}                               → 204
```

`ArtifactOut` carries metadata only (id, kind, filename, size, sha256, status, timestamps) — never
the bytes. There is deliberately no content-download endpoint: the worker reads the artifact
internally, so exposing the raw bytes would add attack surface for no product need.
