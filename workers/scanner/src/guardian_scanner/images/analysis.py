"""What is wrong with a container image (WP-D6).

Three classes of finding, in descending order of how hard they are to get any other way:

1. **A secret that was deleted in a later layer.** It is gone from a running container and still in
   the image, so `docker run` and a filesystem scan both say the image is clean while anyone who can
   pull it can read the credential out of the blob. This is the finding that justifies reading
   layers at all.
2. **Credential material and private keys baked into the image**, deleted or not.
3. **Image configuration** — running as root, secrets in `ENV`, a mutable base tag, SSH exposed.

Package vulnerabilities are deliberately *not* here: they go through the same `VulnMatcher` seam the
SCA engine uses, so a container and a repository get the same version-range logic rather than two
implementations that disagree at the edges.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from guardian_core.enums import Severity

from guardian_scanner.images.oci import ImageArchive, ImageConfig, LayerEntry

# Files that are a credential by their nature. A match is about the path, so a rule fires even when
# the content is a format this scanner cannot parse.
_SENSITIVE_PATHS: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (re.compile(r"(^|/)\.ssh/id_(rsa|dsa|ecdsa|ed25519)$"), "SSH private key", Severity.CRITICAL),
    (re.compile(r"(^|/)\.aws/credentials$"), "AWS credentials file", Severity.CRITICAL),
    (re.compile(r"(^|/)\.docker/config\.json$"), "Docker registry credentials", Severity.HIGH),
    (re.compile(r"(^|/)\.kube/config$"), "Kubernetes cluster credentials", Severity.HIGH),
    (re.compile(r"(^|/)\.netrc$"), "netrc credentials", Severity.HIGH),
    (re.compile(r"(^|/)\.npmrc$"), "npm registry token file", Severity.MEDIUM),
    (re.compile(r"(^|/)\.pypirc$"), "PyPI upload credentials", Severity.HIGH),
    (re.compile(r"(^|/)\.git-credentials$"), "git credentials", Severity.HIGH),
    (re.compile(r"(^|/)\.env$"), "dotenv file", Severity.HIGH),
    (re.compile(r"(^|/)id_rsa$"), "SSH private key", Severity.CRITICAL),
    (re.compile(r"\.pem$"), "PEM key or certificate material", Severity.MEDIUM),
    (re.compile(r"\.p12$|\.pfx$|\.jks$|\.keystore$"), "Key store", Severity.HIGH),
    (re.compile(r"(^|/)\.git/config$"), "Git repository metadata", Severity.LOW),
    (re.compile(r"(^|/)\.bash_history$"), "Shell history", Severity.LOW),
)

# Content patterns worth reading a file for. Deliberately narrower than the secrets engine's full
# ruleset: an image contains far more text than a repository, and a scanner that reads every file
# in every layer is a denial-of-service against itself.
_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("Private key block",
     re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     Severity.CRITICAL),
    ("AWS access key id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
    ("GitHub token", re.compile(rb"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), Severity.HIGH),
    ("Slack token", re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("Stripe secret key", re.compile(rb"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), Severity.HIGH),
)

_ENV_SECRET = re.compile(
    r"(?i)^(\w*(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\w*)="
)
# Values that are obviously not a credential, so an ENV named `TOKEN_PATH=/etc/token` is not
# reported as one.
_ENV_INNOCUOUS = re.compile(r"^(|/[\w./-]*|true|false|\d+|none|null)$", re.IGNORECASE)

_READABLE_SUFFIXES = (".env", ".pem", ".key", ".json", ".yaml", ".yml", ".conf", ".cfg", ".ini",
                      ".txt", ".sh", ".bash", ".properties", ".xml", ".netrc", ".npmrc", ".toml")
_MAX_CONTENT_BYTES = 512_000
_MAX_FILES_READ = 4_000


@dataclass(frozen=True)
class ImageFinding:
    """One issue found in an image. Rendered into a RawFinding by the engine."""

    rule: str
    title: str
    severity: Severity
    cwe: str
    detail: str
    path: str = ""
    layer_index: int = -1
    deleted_later: bool = False
    excerpt: str = ""


# ── configuration ─────────────────────────────────────────────────────────────────────────────────
def analyze_config(config: ImageConfig) -> list[ImageFinding]:
    findings: list[ImageFinding] = []

    user = config.user.strip()
    if user in {"", "root", "0", "0:0", "root:root"}:
        findings.append(ImageFinding(
            rule="image-runs-as-root",
            title="Image runs as root",
            severity=Severity.HIGH,
            cwe="CWE-250",
            detail=(
                "The image config sets no unprivileged USER"
                if not user else f"The image config sets USER {user!r}"
            ) + ". A container process running as uid 0 keeps root's privileges against every "
                "mounted volume, and turns a container escape into host root.",
        ))

    for entry in config.env:
        name, _, value = entry.partition("=")
        if _ENV_SECRET.match(entry) and not _ENV_INNOCUOUS.match(value.strip()):
            findings.append(ImageFinding(
                rule="image-secret-in-env",
                title="Credential baked into the image environment",
                severity=Severity.HIGH,
                cwe="CWE-798",
                path=name,
                detail=(
                    f"ENV {name} carries a value in the image config. Anyone who can pull the "
                    "image can read it with `docker inspect` — no container needs to run."
                ),
                excerpt=f"{name}=<redacted, len={len(value)}>",
            ))

    for tag in config.repo_tags:
        if tag.endswith(":latest") or ":" not in tag.rsplit("/", 1)[-1]:
            findings.append(ImageFinding(
                rule="image-mutable-tag",
                title="Image published under a mutable tag",
                severity=Severity.LOW,
                cwe="CWE-1357",
                path=tag,
                detail=f"{tag} can be repointed at different content, so a deployment cannot be "
                       "reproduced and a rollback cannot be trusted. Pin by digest.",
            ))

    if any(port.startswith("22/") for port in config.exposed_ports):
        findings.append(ImageFinding(
            rule="image-ssh-exposed",
            title="SSH exposed from the container",
            severity=Severity.MEDIUM,
            cwe="CWE-1327",
            detail="Port 22 is declared. A container with sshd is a second, unmanaged access path "
                   "into the cluster with its own credential lifecycle.",
        ))

    if not config.healthcheck:
        findings.append(ImageFinding(
            rule="image-no-healthcheck",
            title="No HEALTHCHECK defined",
            severity=Severity.INFO,
            cwe="CWE-1088",
            detail="Without a healthcheck the orchestrator cannot tell a hung process from a "
                   "working one, so a failed container keeps receiving traffic.",
        ))

    for step in config.history:
        created = str(step.get("created_by") or "")
        if re.search(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(sh|bash)", created):
            findings.append(ImageFinding(
                rule="image-remote-script-piped-to-shell",
                title="Build step piped a remote script into a shell",
                severity=Severity.MEDIUM,
                cwe="CWE-494",
                detail="The image was built by executing whatever a remote host served at build "
                       "time. Nothing about the image records what that was.",
                excerpt=created[:200],
            ))

    return findings


# ── layers ────────────────────────────────────────────────────────────────────────────────────────
def analyze_layers(archive: ImageArchive) -> list[ImageFinding]:
    """Walk every layer, then compare against what a running container would actually see."""
    findings: list[ImageFinding] = []
    final = set(archive.final_filesystem())
    files_read = 0
    reported: set[tuple[str, str]] = set()

    for entry, reader in archive.walk():
        if entry.whiteout_of or not entry.is_file or entry.size == 0:
            continue

        deleted = entry.path not in final
        for pattern, label, severity in _SENSITIVE_PATHS:
            if not pattern.search("/" + entry.path):
                continue
            key = ("path", entry.path)
            if key in reported:
                continue
            reported.add(key)
            findings.append(_sensitive_finding(entry, label, severity, deleted))
            break

        if files_read < _MAX_FILES_READ and _worth_reading(entry):
            data = reader()
            files_read += 1
            if not data:
                continue
            for label, pattern, severity in _CONTENT_PATTERNS:
                if not pattern.search(data[:_MAX_CONTENT_BYTES]):
                    continue
                key = ("content", f"{entry.path}:{label}")
                if key in reported:
                    continue
                reported.add(key)
                findings.append(_content_finding(entry, label, severity, deleted))
                break

    return findings


def _worth_reading(entry: LayerEntry) -> bool:
    if entry.size > _MAX_CONTENT_BYTES:
        return False
    base = posixpath.basename(entry.path).lower()
    return base.endswith(_READABLE_SUFFIXES) or base.startswith(".") or "credential" in base


def _sensitive_finding(
    entry: LayerEntry, label: str, severity: Severity, deleted: bool
) -> ImageFinding:
    return ImageFinding(
        rule="image-sensitive-file-deleted" if deleted else "image-sensitive-file",
        title=(f"{label} present in an image layer after deletion" if deleted
               else f"{label} baked into the image"),
        severity=severity,
        cwe="CWE-538",
        path=entry.path,
        layer_index=entry.layer_index,
        deleted_later=deleted,
        detail=_explain(entry, label, deleted),
    )


def _content_finding(
    entry: LayerEntry, label: str, severity: Severity, deleted: bool
) -> ImageFinding:
    return ImageFinding(
        rule="image-secret-in-layer-deleted" if deleted else "image-secret-in-layer",
        title=(f"{label} in a deleted image layer file" if deleted
               else f"{label} in an image layer file"),
        severity=severity,
        cwe="CWE-798",
        path=entry.path,
        layer_index=entry.layer_index,
        deleted_later=deleted,
        detail=_explain(entry, label, deleted),
        excerpt="<redacted — the matched value is never persisted>",
    )


def _explain(entry: LayerEntry, label: str, deleted: bool) -> str:
    where = f"layer {entry.layer_index} at /{entry.path}"
    if deleted:
        return (
            f"{label} was added in {where} and removed in a later layer. A running container does "
            "not show it and a filesystem scan of the container reports nothing, but the file is "
            "still in the image: anyone who can pull it can read the value out of that layer. "
            "Deleting a file in a subsequent RUN does not remove it from the image — treat the "
            "credential as disclosed and rotate it."
        )
    return f"{label} is present in the image at {where} and ships to every host that pulls it."
