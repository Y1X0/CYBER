"""Artifact validation — what a `.apk` / `.ipa` upload must be before it is ever stored or scanned.

Pure, dependency-free, no DB and no filesystem: the API calls it on upload, the worker can re-check
what it read, and tests exercise it directly. The rules are deliberately *static* — an artifact is
inspected by reading the zip central directory (metadata only), never by extracting or executing it,
so validating a hostile upload cannot itself run code or inflate a bomb.

Two things are enforced here:

  * **type honesty** — the bytes must actually be the artifact the asset needs. An `.apk` is a zip
    containing `AndroidManifest.xml`; an `.ipa` is a zip containing `Payload/<App>.app/`. Checking
    the magic bytes plus one structural marker rejects a renamed PDF or a wrong-platform bundle up
    front, so the engine never receives something it cannot analyse.
  * **filename safety** — the uploader's filename is reduced to a bare, bounded basename kept for
    display only. It is never used to build a storage key or a path (the artifact's opaque id is its
    only address), but sanitizing it keeps traversal/control characters out of logs and the UI.
"""

from __future__ import annotations

import io
import zipfile

# The asset kinds whose scan genuinely consumes an uploaded binary, mapped to the artifact type the
# offline engine expects. Every other asset kind is driven by a URL, an agent report, or inline
# content and takes no upload — see docs/ARTIFACT_UPLOADS.md.
ASSET_KIND_TO_ARTIFACT: dict[str, str] = {
    "mobile_app": "apk",
    "ios_app": "ipa",
}
# The artifact kinds this module knows how to validate.
ARTIFACT_KINDS: frozenset[str] = frozenset(ASSET_KIND_TO_ARTIFACT.values())

# A zip local-file-header magic. Both an APK and an IPA are zip archives.
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

# How much of the central directory we are willing to walk when detecting the kind. An APK/IPA has a
# few thousand entries; a pathological archive with millions is rejected rather than walked.
_MAX_ENTRIES_INSPECTED = 200_000

_FILENAME_MAX = 255
# A conservative display charset. Anything else in the uploader's filename becomes '_'.
_FILENAME_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._- ()"
)


class ArtifactValidationError(ValueError):
    """The uploaded bytes are not a valid artifact of the required kind.

    The message is customer-safe: it says what was wrong (wrong type / not a readable archive),
    never a filesystem path, tenant id, or stack detail.
    """


def artifact_kind_for_asset(asset_kind: str) -> str | None:
    """The artifact type an asset of this kind requires, or None if it takes no upload."""
    return ASSET_KIND_TO_ARTIFACT.get(asset_kind)


def asset_requires_artifact(asset_kind: str) -> bool:
    """Whether a scan of this asset kind cannot run until an artifact is uploaded."""
    return asset_kind in ASSET_KIND_TO_ARTIFACT


def sanitize_filename(name: str | None) -> str:
    """Reduce an uploader-supplied filename to a safe, bounded basename for DISPLAY ONLY.

    Strips any directory component (so `../../etc/passwd` becomes `passwd`), replaces anything
    outside a conservative charset with '_', and caps the length. The result is never used to build
    a path or a storage key — the artifact's opaque id is its only address — so this is defence in
    depth for logs and the UI, not the primary path-safety control.
    """
    if not name:
        return "artifact"
    # Drop everything up to the last path separator, either flavour.
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    cleaned = "".join(ch if ch in _FILENAME_SAFE else "_" for ch in base)
    cleaned = cleaned.strip(". ") or "artifact"
    return cleaned[:_FILENAME_MAX]


def detect_artifact_kind(data: bytes) -> str | None:
    """Return "apk" / "ipa" by static structural inspection, or None if it is neither.

    Reads only the zip central directory (member names), never decompresses a member, so it is safe
    to run on untrusted bytes. An archive that is both (neither marker) or too large to inspect
    returns None.
    """
    if not data[:4].startswith(tuple(m[:4] for m in _ZIP_MAGICS)):
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return None
    try:
        names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return None
    finally:
        zf.close()
    if len(names) > _MAX_ENTRIES_INSPECTED:
        return None
    is_apk = "AndroidManifest.xml" in names
    is_ipa = any(n.startswith("Payload/") and ".app/" in n for n in names)
    if is_apk and not is_ipa:
        return "apk"
    if is_ipa and not is_apk:
        return "ipa"
    return None


def validate_artifact(expected_kind: str, data: bytes) -> None:
    """Raise ArtifactValidationError unless `data` is a readable artifact of `expected_kind`.

    `expected_kind` is one of ARTIFACT_KINDS, derived from the asset kind server-side (never taken
    from the client).
    """
    if expected_kind not in ARTIFACT_KINDS:
        raise ArtifactValidationError("unsupported artifact type")
    if not data:
        raise ArtifactValidationError("the uploaded file is empty")
    detected = detect_artifact_kind(data)
    if detected is None:
        raise ArtifactValidationError(
            "the uploaded file is not a readable "
            f"{'Android .apk' if expected_kind == 'apk' else 'iOS .ipa'} archive"
        )
    if detected != expected_kind:
        want = "an Android .apk" if expected_kind == "apk" else "an iOS .ipa"
        got = "an Android .apk" if detected == "apk" else "an iOS .ipa"
        raise ArtifactValidationError(f"this asset needs {want}, but the file looks like {got}")
