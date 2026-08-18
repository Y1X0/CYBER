"""Read a container image archive without extracting it (WP-D6).

A container image is a stack of tar layers plus a JSON config. Scanning only the *final* filesystem
misses the finding that matters most in practice: a credential added in one layer and deleted in a
later one is gone from `docker run`, still present in the image, and pullable by anyone with access
to the registry. `docker history` shows the layer; the file is in the blob.

Nothing is written to disk. The archive is untrusted input — it is exactly the kind of file an
attacker would hand a scanner — so every member is read in memory under explicit caps, and the tar
metadata is treated as data rather than as instructions: absolute paths and `..` are normalized
away, symlinks and hardlinks are recorded but never followed, and device/fifo entries are ignored.
"""

from __future__ import annotations

import io
import json
import posixpath
import tarfile
from dataclasses import dataclass, field

MAX_LAYERS = 128
MAX_MEMBERS_PER_LAYER = 200_000
MAX_FILE_BYTES = 8_000_000        # the largest single file this reads into memory
MAX_TOTAL_READ_BYTES = 400_000_000  # bomb guard across the whole image
WHITEOUT_PREFIX = ".wh."
OPAQUE_MARKER = ".wh..wh..opq"


class ImageFormatError(ValueError):
    """The archive is not a container image this reader understands."""


@dataclass(frozen=True)
class LayerEntry:
    """One path as it appeared in one layer."""

    layer_index: int
    layer_name: str
    path: str                     # normalized, no leading slash
    size: int
    mode: int
    is_file: bool
    is_symlink: bool
    link_target: str = ""
    whiteout_of: str = ""         # the path this entry deletes, if it is a whiteout marker


@dataclass
class ImageConfig:
    user: str = ""
    env: tuple[str, ...] = ()
    exposed_ports: tuple[str, ...] = ()
    entrypoint: tuple[str, ...] = ()
    cmd: tuple[str, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)
    healthcheck: bool = False
    history: tuple[dict, ...] = ()
    repo_tags: tuple[str, ...] = ()
    diff_ids: tuple[str, ...] = ()


class ImageArchive:
    """A read-only view over a `docker save` / OCI-layout tarball.

    Opened lazily and closed by the caller (or by `with`). Layer contents are streamed on demand:
    holding a whole image in memory would make the scanner the easiest denial-of-service target in
    the product.
    """

    def __init__(self, path: str) -> None:
        try:
            self._tar = tarfile.open(path, mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            raise ImageFormatError(f"cannot read image archive: {exc}") from exc
        self._names = set(self._tar.getnames())
        self._read_bytes = 0
        self.layer_names: tuple[str, ...] = ()
        self.config = ImageConfig()
        self._load_manifest()

    # ── lifecycle ────────────────────────────────────────────────────────────────────────────────
    def __enter__(self) -> ImageArchive:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        self._tar.close()

    # ── manifest ─────────────────────────────────────────────────────────────────────────────────
    def _read_json(self, name: str) -> dict | list:
        raw = self._read_member(name)
        if raw is None:
            raise ImageFormatError(f"missing {name} in image archive")
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            raise ImageFormatError(f"{name} is not valid JSON: {exc}") from exc

    def _load_manifest(self) -> None:
        if "manifest.json" in self._names:
            self._load_docker_manifest()
        elif "index.json" in self._names:
            self._load_oci_index()
        else:
            raise ImageFormatError(
                "archive has neither manifest.json nor index.json — not a container image"
            )

    def _load_docker_manifest(self) -> None:
        manifest = self._read_json("manifest.json")
        if not isinstance(manifest, list) or not manifest:
            raise ImageFormatError("manifest.json is empty")
        entry = manifest[0]
        layers = [str(item) for item in (entry.get("Layers") or [])][:MAX_LAYERS]
        self.layer_names = tuple(layers)
        config_name = str(entry.get("Config") or "")
        repo_tags = tuple(str(t) for t in (entry.get("RepoTags") or []))
        raw_config = self._read_json(config_name) if config_name in self._names else {}
        self.config = _parse_config(raw_config if isinstance(raw_config, dict) else {}, repo_tags)

    def _load_oci_index(self) -> None:
        index = self._read_json("index.json")
        manifests = (index or {}).get("manifests") if isinstance(index, dict) else None
        if not manifests:
            raise ImageFormatError("index.json lists no manifests")
        manifest = self._read_json(_blob_path(manifests[0].get("digest", "")))
        if not isinstance(manifest, dict):
            raise ImageFormatError("OCI manifest is not an object")
        self.layer_names = tuple(
            _blob_path(layer.get("digest", "")) for layer in (manifest.get("layers") or [])
        )[:MAX_LAYERS]
        config_digest = (manifest.get("config") or {}).get("digest", "")
        raw_config = self._read_json(_blob_path(config_digest)) if config_digest else {}
        self.config = _parse_config(raw_config if isinstance(raw_config, dict) else {}, ())

    # ── layers ───────────────────────────────────────────────────────────────────────────────────
    def _read_member(self, name: str) -> bytes | None:
        if name not in self._names:
            return None
        try:
            member = self._tar.getmember(name)
        except KeyError:
            return None
        if not member.isfile() or member.size > MAX_FILE_BYTES:
            return None
        if self._read_bytes + member.size > MAX_TOTAL_READ_BYTES:
            return None
        handle = self._tar.extractfile(member)
        if handle is None:
            return None
        data = handle.read(MAX_FILE_BYTES)
        self._read_bytes += len(data)
        return data

    def _open_layer(self, name: str) -> tarfile.TarFile | None:
        raw = self._read_member(name)
        if raw is None:
            return None
        try:
            # `r:*` handles a plain tar and a gzip/zstd-wrapped one alike, which is the difference
            # between the docker-save and OCI spellings of the same layer.
            return tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        except tarfile.TarError:
            return None

    def layers(self):  # noqa: ANN201 - yields (index, name, TarFile)
        """Yield each layer's open tar, oldest first. Unreadable layers are skipped, not fatal."""
        for index, name in enumerate(self.layer_names):
            layer = self._open_layer(name)
            if layer is None:
                continue
            try:
                yield index, name, layer
            finally:
                layer.close()

    def walk(self):  # noqa: ANN201 - yields (LayerEntry, reader)
        """Every entry in every layer, oldest layer first.

        `reader` is a zero-argument callable returning the member's bytes, or None for a directory,
        symlink or oversized file. It is deliberately lazy: most entries are never read.
        """
        for index, name, layer in self.layers():
            seen = 0
            for member in layer:
                seen += 1
                if seen > MAX_MEMBERS_PER_LAYER:
                    break
                entry = _entry_for(member, index, name)
                if entry is None:
                    continue
                yield entry, _reader_for(layer, member, self)

    def final_filesystem(self) -> dict[str, LayerEntry]:
        """The paths a running container would see, after whiteouts are applied.

        Kept separate from `walk` on purpose: the difference between the two is the set of files
        that were deleted but are still in the image, which is the finding this reader exists for.
        """
        view: dict[str, LayerEntry] = {}
        for entry, _reader in self.walk():
            if entry.whiteout_of:
                if entry.whiteout_of.endswith("/"):        # opaque directory
                    prefix = entry.whiteout_of
                    for path in [p for p in view if p.startswith(prefix)]:
                        del view[path]
                else:
                    view.pop(entry.whiteout_of, None)
                continue
            view[entry.path] = entry
        return view


# ── helpers ───────────────────────────────────────────────────────────────────────────────────────
def _blob_path(digest: str) -> str:
    return "blobs/" + digest.replace(":", "/") if digest else ""


def _normalize(path: str) -> str:
    """Strip the archive's own path semantics.

    Nothing is extracted, so a `..` cannot escape a directory here — but a path that still contains
    one would let a crafted layer disguise `/root/.ssh/id_rsa` as `app/../root/.ssh/id_rsa` and slip
    past a path-based rule. Normalizing first means the rules see one spelling.
    """
    cleaned = posixpath.normpath(path.replace("\\", "/")).lstrip("/")
    while cleaned.startswith("../"):
        cleaned = cleaned[3:]
    return "" if cleaned in {".", ".."} else cleaned


def _entry_for(member: tarfile.TarInfo, index: int, layer_name: str) -> LayerEntry | None:
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        return None                                 # devices, fifos: metadata only, nothing to read
    path = _normalize(member.name)
    if not path:
        return None

    whiteout_of = ""
    base = posixpath.basename(path)
    parent = posixpath.dirname(path)
    if base == OPAQUE_MARKER:
        whiteout_of = (parent + "/") if parent else ""
    elif base.startswith(WHITEOUT_PREFIX):
        deleted = base[len(WHITEOUT_PREFIX):]
        whiteout_of = posixpath.join(parent, deleted) if parent else deleted

    return LayerEntry(
        layer_index=index,
        layer_name=layer_name,
        path=path,
        size=int(member.size),
        mode=int(member.mode),
        is_file=member.isfile(),
        is_symlink=member.issym() or member.islnk(),
        link_target=_normalize(member.linkname) if member.linkname else "",
        whiteout_of=whiteout_of,
    )


def _reader_for(layer: tarfile.TarFile, member: tarfile.TarInfo, archive: ImageArchive):  # noqa: ANN201
    def read() -> bytes | None:
        if not member.isfile() or member.size > MAX_FILE_BYTES:
            return None
        if archive._read_bytes + member.size > MAX_TOTAL_READ_BYTES:  # noqa: SLF001
            return None
        handle = layer.extractfile(member)
        if handle is None:
            return None
        data = handle.read(MAX_FILE_BYTES)
        archive._read_bytes += len(data)  # noqa: SLF001
        return data

    return read


def _parse_config(raw: dict, repo_tags: tuple[str, ...]) -> ImageConfig:
    config = raw.get("config") or raw.get("Config") or {}
    if not isinstance(config, dict):
        config = {}
    history = tuple(h for h in (raw.get("history") or []) if isinstance(h, dict))
    rootfs = raw.get("rootfs") or {}
    return ImageConfig(
        user=str(config.get("User") or ""),
        env=tuple(str(e) for e in (config.get("Env") or [])),
        exposed_ports=tuple(str(p) for p in (config.get("ExposedPorts") or {})),
        entrypoint=tuple(str(e) for e in (config.get("Entrypoint") or [])),
        cmd=tuple(str(c) for c in (config.get("Cmd") or [])),
        labels={str(k): str(v) for k, v in (config.get("Labels") or {}).items()},
        healthcheck=bool(config.get("Healthcheck")),
        history=history,
        repo_tags=repo_tags,
        diff_ids=tuple(str(d) for d in (rootfs.get("diff_ids") or [])),
    )
