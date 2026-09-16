"""Decompression-bomb-safe zip member reads (AUD-P1-5).

`zipfile.ZipFile.read(name)` fully decompresses a member into memory and only then does a caller
slice it, so a small `.apk`/`.ipa` with a high DEFLATE ratio can inflate to gigabytes in the worker
before the slice ever runs — an OOM/crash DoS. These helpers read through `ZipFile.open()`, which
decompresses lazily, and stop at a byte budget, so a hostile member costs at most that budget of RAM
regardless of what its header claims. The correct pattern already used for container layers
(`images/oci.py`) — check size, then bounded read — applied to the zip-based mobile artifacts.
"""

from __future__ import annotations

import zipfile

# The most we read from any single member while string/secret-scanning content. Truncation past this
# is fine there (a 25 MB window of a member is ample signal); the point is the bound, not the tail.
MAX_MEMBER_BYTES = 25_000_000
# The most we read for a member we must parse whole (a manifest, plist, or provisioning profile).
# These are kilobytes in a real app; anything larger is treated as hostile/malformed, not parsed.
MAX_METADATA_BYTES = 15_000_000


class ArchiveMemberTooLarge(RuntimeError):
    """A member that must be read whole exceeds the metadata budget (bomb guard)."""


def read_bounded(zf: zipfile.ZipFile, name: str, limit: int = MAX_MEMBER_BYTES) -> bytes:
    """Return at most `limit` decompressed bytes of `name`, without inflating the whole member.

    Truncation is intentional and safe for scanning: the read never materializes more than `limit`
    bytes even if the member declares (or actually inflates to) far more.
    """
    with zf.open(name) as fh:
        return fh.read(limit)


def read_whole_capped(zf: zipfile.ZipFile, name: str, cap: int = MAX_METADATA_BYTES) -> bytes:
    """Return the FULL member, but only if it fits in `cap`; raise ArchiveMemberTooLarge otherwise.

    Used where the bytes must be parsed as a whole (manifest/plist). A declared-size pre-check
    rejects the obvious bomb up front; the bounded read (`cap + 1`) is the real guard against a
    lying header — at most `cap + 1` bytes are ever inflated.
    """
    try:
        info = zf.getinfo(name)
    except KeyError as exc:  # pragma: no cover - callers check membership first
        raise ArchiveMemberTooLarge(f"{name} is absent") from exc
    if info.file_size > cap:
        raise ArchiveMemberTooLarge(
            f"{name} declares {info.file_size} bytes, over the {cap}-byte limit")
    with zf.open(name) as fh:
        data = fh.read(cap + 1)
    if len(data) > cap:
        raise ArchiveMemberTooLarge(f"{name} inflated past the {cap}-byte limit")
    return data
