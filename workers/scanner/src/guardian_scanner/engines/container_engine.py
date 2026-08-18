"""Container engine — Dockerfile rules plus image analysis (WP-D6).

Two inputs, because they answer different questions:

* **A Dockerfile** says what the image was *meant* to be. Cheap, always available in a repository,
  and wrong as often as any other intention — the running image is built from a base the Dockerfile
  did not write and layers a later `RUN` modified.
* **An image archive** says what the image *is*. Reading its layers is the only way to see the
  finding that matters most in practice: a credential added in one layer and deleted in a later one
  is absent from a running container and still present in the image, so `docker run` and a
  filesystem scan both report clean while anyone who can pull the image reads the secret out of the
  blob.

Package vulnerabilities go through the injected `VulnMatcher`, the same seam the SCA engine uses, so
a container inherits the version-range logic built for dependencies rather than a second
implementation of it. No external binary: the archive is read in-process, so this stays in the
artifact plane and needs no kernel privileges.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import code_evidence, dependency_evidence
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.images import (
    ImageArchive,
    ImageFinding,
    ImageFormatError,
    analyze_config,
    analyze_layers,
)
from guardian_scanner.images import packages as pkg

_SECRET_ENV = re.compile(r"(?i)\b(ENV|ARG)\s+\w*(password|secret|token|api[_-]?key)\w*\s*[= ]")
_CURL_PIPE = re.compile(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(sh|bash)")
_IMAGE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".oci")
_MAX_PACKAGE_FILES = 5_000


class ContainerEngine:
    key = EngineKey.CONTAINER
    name = "Guardian Container (Dockerfile rules + image layer analysis)"
    version = "2.0.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"container_image", "repo"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="builtin Dockerfile rules + in-process image reader")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_dockerfile("Dockerfile", ctx.inline_content)
            return

        archive_path = self._image_path(ctx)
        if archive_path:
            yield from self.scan_image(archive_path, ctx)

        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        if not root.is_dir():
            return
        for path in root.rglob("*"):
            if path.is_file() and path.name.lower().startswith("dockerfile"):
                try:
                    text = path.read_text("utf-8", "ignore")
                except OSError:
                    continue
                yield from self._scan_dockerfile(str(path.relative_to(root)), text)

    # ── image archive ────────────────────────────────────────────────────────────────────────────
    def _image_path(self, ctx: ScanContext) -> str | None:
        """Where the image archive is, if there is one.

        The path is taken from the asset's own config or from the workspace the task prepared —
        never from a scan setting a caller supplies, which would let a scan request name any file on
        the worker and have its contents reported back as evidence.
        """
        candidate = (ctx.asset_config or {}).get("image_archive")
        if isinstance(candidate, str) and candidate:
            return candidate
        if ctx.workspace_path:
            root = Path(ctx.workspace_path)
            if root.is_file() and root.name.endswith(_IMAGE_SUFFIXES):
                return str(root)
            if root.is_dir():
                for child in sorted(root.iterdir()):
                    if child.is_file() and child.name.endswith(_IMAGE_SUFFIXES):
                        return str(child)
        return None

    def scan_image(self, archive_path: str, ctx: ScanContext) -> Iterator[RawFinding]:
        """Analyse one image archive. Public so a caller can scan an image without a workspace."""
        try:
            archive = ImageArchive(archive_path)
        except ImageFormatError as exc:
            yield RawFinding(
                engine=EngineKey.CONTAINER,
                title="Container image could not be read",
                category="scan-error",
                description=(
                    f"{exc} — the image was not analysed. Reported rather than skipped: an image "
                    "that produced no findings because it could not be opened is indistinguishable "
                    "from a clean one."
                ),
                base_severity=Severity.INFO,
                confidence="high",
                location={"path": archive_path, "rule": "image-unreadable"},
                evidence={"error": str(exc)[:300]},
            )
            return

        with archive:
            for issue in analyze_config(archive.config):
                yield _image_finding(issue, archive_path)
            for issue in analyze_layers(archive):
                yield _image_finding(issue, archive_path)
            yield from self._image_packages(archive, archive_path, ctx)

    def _image_packages(
        self, archive: ImageArchive, archive_path: str, ctx: ScanContext
    ) -> Iterator[RawFinding]:
        """Inventory the image and match it through the injected matcher."""
        inventory: list[tuple[str, str, str, str]] = []
        paths: list[str] = []
        read = 0

        for entry, reader in archive.walk():
            if entry.whiteout_of or not entry.is_file:
                continue
            paths.append(entry.path)
            if read >= _MAX_PACKAGE_FILES:
                continue
            parsed: Iterator[tuple[str, str, str, str]] | None = None
            if entry.path == pkg.DPKG_STATUS:
                data = reader()
                parsed = pkg.parse_dpkg_status(data.decode("utf-8", "replace")) if data else None
            elif entry.path == pkg.APK_INSTALLED:
                data = reader()
                parsed = pkg.parse_apk_installed(data.decode("utf-8", "replace")) if data else None
            elif pkg.is_python_metadata(entry.path):
                data = reader()
                parsed = (pkg.parse_python_metadata(data.decode("utf-8", "replace"), entry.path)
                          if data else None)
            elif pkg.is_node_manifest(entry.path):
                data = reader()
                parsed = (pkg.parse_node_package_json(data.decode("utf-8", "replace"), entry.path)
                          if data else None)
            if parsed is not None:
                read += 1
                inventory.extend(parsed)

        # A later layer's database supersedes an earlier one's, so the last reading of a package
        # wins — otherwise an upgraded package is reported at its pre-upgrade version, which is a
        # vulnerability report against software that is not on the image.
        latest: dict[tuple[str, str], tuple[str, str, str, str]] = {}
        for name, version, ecosystem, source in inventory:
            latest[(name, ecosystem)] = (name, version, ecosystem, source)

        if pkg.rpm_present(paths):
            yield RawFinding(
                engine=EngineKey.CONTAINER,
                title="RPM package database not inventoried",
                category="scan-gap",
                description=(
                    "The image carries an RPM database, which this reader does not parse — its "
                    "packages were not checked for known vulnerabilities. Stated rather than "
                    "silently omitted: an empty package list and an unread one look identical in a "
                    "report, and only one of them is good news."
                ),
                base_severity=Severity.INFO,
                confidence="high",
                location={"path": archive_path, "rule": "image-rpm-not-parsed"},
                evidence={"packages_from_other_sources": len(latest)},
            )

        if ctx.vuln_matcher is None:
            return
        for name, version, ecosystem, source in sorted(latest.values()):
            for match in ctx.vuln_matcher.match(name=name, version=version, ecosystem=ecosystem):
                yield RawFinding(
                    engine=EngineKey.CONTAINER,
                    title=f"Vulnerable image package: {name}@{version} ({match.external_id})",
                    category="vuln-dep",
                    description=(
                        match.summary
                        or f"{name}@{version} in this image is affected by {match.external_id}."
                    ),
                    base_severity=match.severity,
                    confidence="high",
                    cwe_id=match.cwe_ids[0] if match.cwe_ids else None,
                    cve_ids=[match.external_id] if match.external_id.startswith("CVE-") else [],
                    cvss_base=match.cvss_base,
                    epss_score=match.epss_score,
                    kev=match.kev,
                    exploit_maturity=match.exploit_maturity,
                    ransomware=match.ransomware,
                    location={"path": archive_path, "package": name, "version": version,
                              "ecosystem": ecosystem, "source": source,
                              "rule": "image-vulnerable-package"},
                    evidence=dependency_evidence(package=name, version=version,
                                                 ecosystem=ecosystem, advisory=match.external_id),
                    references={"refs": match.references, "advisory": match.external_id},
                )

    # ── Dockerfile ───────────────────────────────────────────────────────────────────────────────
    def _scan_dockerfile(self, path: str, text: str) -> Iterable[RawFinding]:
        has_user = False
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            upper = line.upper()
            if upper.startswith("USER "):
                has_user = True
                if line.split()[1].lower() in {"root", "0"}:
                    yield self._f("Container runs as root (USER root)", Severity.HIGH, "CWE-250",
                                  "CIS Docker 4.1", path, lineno, line)
            if upper.startswith("FROM ") and (":latest" in line or ":" not in line.split()[1]):
                yield self._f("Base image uses mutable 'latest' tag", Severity.MEDIUM, "CWE-1357",
                              "CIS Docker 4.9", path, lineno, line)
            if _SECRET_ENV.search(line):
                yield self._f("Secret baked into image (ENV/ARG)", Severity.HIGH, "CWE-798",
                              "CIS Docker 4.10", path, lineno, line)
            if _CURL_PIPE.search(line):
                yield self._f("Remote script piped to shell (curl|bash)", Severity.HIGH, "CWE-494",
                              "CIS Docker 4.7", path, lineno, line)
            if upper.startswith("ADD ") and "http" not in line:
                yield self._f("Use COPY instead of ADD for local files", Severity.LOW, "CWE-669",
                              "CIS Docker 4.9", path, lineno, line)
        if not has_user:
            yield self._f("No USER instruction — image runs as root by default", Severity.HIGH,
                          "CWE-250", "CIS Docker 4.1", path, 0, "(no USER directive)")

    def _f(self, title, sev, cwe, cis, path, lineno, line) -> RawFinding:  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.CONTAINER,
            title=title,
            category="container-misconfig",
            description=f"{title} ({cis}).",
            base_severity=sev,
            confidence="high",
            cwe_id=cwe,
            location={"path": path, "line": lineno, "cis": cis, "rule": cis},
            evidence=code_evidence(path=path, line=lineno, redacted_excerpt=line[:200], rule=cis),
            references={"cis": cis},
        )


def _image_finding(issue: ImageFinding, archive_path: str) -> RawFinding:
    evidence = {
        "image": archive_path,
        "path": issue.path,
        "layer_index": issue.layer_index,
        "deleted_in_a_later_layer": issue.deleted_later,
    }
    if issue.excerpt:
        evidence["excerpt"] = issue.excerpt
    return RawFinding(
        engine=EngineKey.CONTAINER,
        title=issue.title,
        category="container-misconfig",
        description=issue.detail,
        base_severity=issue.severity,
        # A path or content match inside a layer is an observation of a file that is really there,
        # not an inference about how it is used.
        confidence="high",
        cwe_id=issue.cwe,
        location={"path": issue.path or archive_path, "layer": issue.layer_index,
                  "rule": issue.rule},
        evidence=evidence,
    )
