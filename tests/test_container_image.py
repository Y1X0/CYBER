"""Container image analysis (WP-D6).

The test that carries the weight is `test_a_secret_deleted_in_a_later_layer_is_still_found`. That
finding is the reason for reading layers at all: a credential added in one `RUN` and deleted in the
next is absent from a running container, so `docker run`, `docker exec` and a filesystem scan all
report the image clean — while anyone who can pull it reads the secret straight out of the blob. A
container scanner that only looks at the flattened filesystem cannot see it, and a customer who
deleted the file believes the problem is fixed.

Images are built here with `tarfile`, byte for byte in the `docker save` layout, rather than pulled.
That is not a limitation of this environment: constructing the archive is how a whiteout marker, a
path-traversal name and a decompression bomb can be tested at all, since no registry serves one.
"""

from __future__ import annotations

import io
import json
import tarfile

import pytest
from guardian_core.enums import Severity
from guardian_scanner.engines.base import ScanContext, VulnMatch
from guardian_scanner.engines.container_engine import ContainerEngine
from guardian_scanner.images import ImageArchive, ImageFormatError, analyze_config
from guardian_scanner.images.oci import ImageConfig
from guardian_scanner.images.packages import (
    parse_apk_installed,
    parse_dpkg_status,
    parse_node_package_json,
    parse_python_metadata,
)

PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAxfixture0000000000000000000000000000000000000000\n"
    "-----END RSA PRIVATE KEY-----\n"
)


# ── building an image ─────────────────────────────────────────────────────────────────────────────
def _layer(files: dict[str, str | bytes]) -> bytes:
    """One layer tarball. A key ending in '/' is a directory; '.wh.name' is a deletion marker."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in files.items():
            if name.endswith("/"):
                info = tarfile.TarInfo(name.rstrip("/"))
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
                continue
            payload = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def build_image(tmp_path, layers, config=None, repo_tags=("fixture:latest",), name="image.tar"):
    """A `docker save` archive: manifest.json, a config blob, and one tar per layer."""
    path = tmp_path / name
    config_doc = {
        "architecture": "amd64",
        "config": config if config is not None else {"User": "app"},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{i:064x}" for i in range(len(layers))]},
        "history": [{"created_by": f"RUN step {i}"} for i in range(len(layers))],
    }
    layer_names = [f"layer{i}/layer.tar" for i in range(len(layers))]
    manifest = [{"Config": "config.json", "RepoTags": list(repo_tags), "Layers": layer_names}]

    with tarfile.open(path, mode="w") as tar:
        def add(member_name: str, payload: bytes) -> None:
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        add("manifest.json", json.dumps(manifest).encode())
        add("config.json", json.dumps(config_doc).encode())
        for member_name, blob in zip(layer_names, layers, strict=True):
            add(member_name, blob)
    return str(path)


def _findings(path, matcher=None, asset_kind="container_image"):
    ctx = ScanContext(scan_id="t", asset_kind=asset_kind, asset_identifier="fixture",
                      workspace_path=path, vuln_matcher=matcher)
    return list(ContainerEngine().run(ctx))


def _rules(findings):
    return {f.location.get("rule") for f in findings}


# ── the finding this engine exists for ────────────────────────────────────────────────────────────
def test_a_secret_deleted_in_a_later_layer_is_still_found(tmp_path):
    """Added in layer 0, deleted in layer 1. Gone from the container, still in the image."""
    image = build_image(tmp_path, [
        _layer({"root/.ssh/id_rsa": PRIVATE_KEY, "app/main.py": "print('hi')\n"}),
        _layer({"root/.ssh/.wh.id_rsa": ""}),
    ])
    findings = _findings(image)

    deleted = [f for f in findings if f.location.get("rule") == "image-sensitive-file-deleted"]
    assert len(deleted) == 1
    assert deleted[0].base_severity is Severity.CRITICAL
    assert deleted[0].location["path"] == "root/.ssh/id_rsa"
    assert deleted[0].location["layer"] == 0
    assert deleted[0].evidence["deleted_in_a_later_layer"] is True
    assert "rotate it" in deleted[0].description


def test_the_same_file_still_present_is_reported_differently(tmp_path):
    """Not deleted: a real finding too, but a different one — and the description must not claim a
    deletion that did not happen."""
    image = build_image(tmp_path, [_layer({"root/.ssh/id_rsa": PRIVATE_KEY})])
    findings = _findings(image)
    present = [f for f in findings if f.location.get("rule") == "image-sensitive-file"]
    assert len(present) == 1
    assert present[0].evidence["deleted_in_a_later_layer"] is False
    assert "removed in a later layer" not in present[0].description


def test_the_raw_secret_is_never_carried_in_the_finding(tmp_path):
    image = build_image(tmp_path, [
        _layer({"app/.env": "STRIPE_KEY=sk_live_abcdefghijklmnop1234\n"}),
        _layer({"app/.wh..env": ""}),
    ])
    findings = _findings(image)
    blob = json.dumps([{"d": f.description, "e": f.evidence, "l": f.location} for f in findings])
    assert "sk_live_abcdefghijklmnop1234" not in blob
    assert any(f.location.get("rule", "").startswith("image-s") for f in findings)


def test_a_secret_by_content_rather_than_by_filename(tmp_path):
    """The path says nothing; the content is a private key."""
    image = build_image(tmp_path, [_layer({"opt/app/config.json": PRIVATE_KEY})])
    rules = _rules(_findings(image))
    assert "image-secret-in-layer" in rules


def test_an_opaque_whiteout_removes_a_whole_directory(tmp_path):
    image = build_image(tmp_path, [
        _layer({"secrets/": "", "secrets/id_rsa": PRIVATE_KEY}),
        _layer({"secrets/.wh..wh..opq": ""}),
    ])
    findings = _findings(image)
    assert "image-sensitive-file-deleted" in _rules(findings)


# ── image configuration ───────────────────────────────────────────────────────────────────────────
def test_no_user_in_the_config_is_running_as_root():
    findings = analyze_config(ImageConfig(user=""))
    rules = {f.rule for f in findings}
    assert "image-runs-as-root" in rules


@pytest.mark.parametrize("user", ["root", "0", "0:0", "root:root"])
def test_explicit_root_users_are_all_recognized(user):
    assert "image-runs-as-root" in {f.rule for f in analyze_config(ImageConfig(user=user))}


def test_an_unprivileged_user_is_not_reported():
    assert "image-runs-as-root" not in {f.rule for f in analyze_config(ImageConfig(user="app"))}


def test_a_secret_in_env_is_reported_without_its_value():
    findings = analyze_config(ImageConfig(user="app", env=("DB_PASSWORD=hunter2xyz",)))
    hit = next(f for f in findings if f.rule == "image-secret-in-env")
    assert "hunter2xyz" not in hit.excerpt and "hunter2xyz" not in hit.detail
    assert "docker inspect" in hit.detail


def test_a_path_valued_env_is_not_mistaken_for_a_secret():
    """`TOKEN_PATH=/etc/token` names a file; reporting it as a baked-in credential is noise."""
    findings = analyze_config(ImageConfig(user="app", env=("TOKEN_PATH=/etc/token", "DEBUG=false")))
    assert "image-secret-in-env" not in {f.rule for f in findings}


def test_a_mutable_tag_is_reported():
    findings = analyze_config(ImageConfig(user="app", repo_tags=("registry/app:latest",)))
    assert "image-mutable-tag" in {f.rule for f in findings}
    findings = analyze_config(ImageConfig(user="app", repo_tags=("registry/app:1.4.2",)))
    assert "image-mutable-tag" not in {f.rule for f in findings}


def test_exposed_ssh_and_missing_healthcheck():
    findings = analyze_config(ImageConfig(user="app", exposed_ports=("22/tcp",)))
    rules = {f.rule for f in findings}
    assert {"image-ssh-exposed", "image-no-healthcheck"} <= rules


def test_a_build_step_piping_a_remote_script_to_a_shell_is_reported():
    config = ImageConfig(user="app", healthcheck=True,
                         history=({"created_by": "/bin/sh -c curl -s https://x.example/i.sh | sh"},))
    assert "image-remote-script-piped-to-shell" in {f.rule for f in analyze_config(config)}


# ── package inventory → the shared matcher ────────────────────────────────────────────────────────
DPKG = """Package: openssl
Status: install ok installed
Version: 1.1.1n-0+deb11u3
Description: cryptography

Package: removed-thing
Status: deinstall ok config-files
Version: 9.9.9

Package: zlib1g
Status: install ok installed
Version: 1:1.2.11.dfsg-2+deb11u2
"""


def test_dpkg_status_is_parsed_and_uninstalled_packages_are_skipped():
    parsed = list(parse_dpkg_status(DPKG))
    assert ("openssl", "1.1.1n-0+deb11u3", "Debian", "var/lib/dpkg/status") in parsed
    assert ("zlib1g", "1:1.2.11.dfsg-2+deb11u2", "Debian", "var/lib/dpkg/status") in parsed
    # `deinstall ok config-files` still carries a Version. Counting it attributes a CVE to software
    # that is not on the image.
    assert not any(name == "removed-thing" for name, *_ in parsed)


def test_apk_installed_is_parsed():
    parsed = list(parse_apk_installed("P:musl\nV:1.2.3-r4\n\nP:busybox\nV:1.36.1-r5\n"))
    assert ("musl", "1.2.3-r4", "Alpine", "lib/apk/db/installed") in parsed
    assert ("busybox", "1.36.1-r5", "Alpine", "lib/apk/db/installed") in parsed


def test_python_and_node_metadata_are_parsed():
    meta = "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nName: not-this\n"
    assert list(parse_python_metadata(meta, "x")) == [("requests", "2.31.0", "PyPI", "x")]
    manifest = '{"name":"lodash","version":"4.17.20"}'
    assert list(parse_node_package_json(manifest, "y")) == [("lodash", "4.17.20", "npm", "y")]


class _Matcher:
    """Stands in for the KB/feed-backed matcher; the seam is what is under test, not the feed."""

    def __init__(self, hits):
        self.hits = hits
        self.seen = []

    def match(self, *, name, version, ecosystem):
        self.seen.append((name, version, ecosystem))
        return self.hits.get((name, version), [])


def test_image_packages_reach_the_shared_vulnerability_matcher(tmp_path):
    image = build_image(tmp_path, [_layer({"var/lib/dpkg/status": DPKG})])
    matcher = _Matcher({
        ("openssl", "1.1.1n-0+deb11u3"): [
            VulnMatch(external_id="CVE-2022-0778", summary="Infinite loop in BN_mod_sqrt",
                      severity=Severity.HIGH, cvss_base=7.5, cwe_ids=["CWE-835"])
        ]
    })
    findings = _findings(image, matcher)

    assert ("openssl", "1.1.1n-0+deb11u3", "Debian") in matcher.seen
    assert ("zlib1g", "1:1.2.11.dfsg-2+deb11u2", "Debian") in matcher.seen
    vulns = [f for f in findings if f.location.get("rule") == "image-vulnerable-package"]
    assert len(vulns) == 1
    assert vulns[0].cve_ids == ["CVE-2022-0778"]
    assert vulns[0].cvss_base == 7.5
    assert vulns[0].location["package"] == "openssl"


def test_an_upgraded_package_is_reported_at_its_final_version(tmp_path):
    """A later layer's database supersedes an earlier one. Reporting the pre-upgrade version is a
    vulnerability claim about software that is not on the image."""
    old = "Package: openssl\nStatus: install ok installed\nVersion: 1.1.1n\n"
    new = "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11\n"
    image = build_image(tmp_path, [
        _layer({"var/lib/dpkg/status": old}),
        _layer({"var/lib/dpkg/status": new}),
    ])
    matcher = _Matcher({})
    _findings(image, matcher)
    assert ("openssl", "3.0.11", "Debian") in matcher.seen
    assert ("openssl", "1.1.1n", "Debian") not in matcher.seen


def test_an_rpm_database_is_reported_as_a_gap_not_as_zero_packages(tmp_path):
    """An empty package list and an unread one look identical in a report."""
    image = build_image(tmp_path, [_layer({"var/lib/rpm/Packages": "binary-db"})])
    findings = _findings(image)
    gap = [f for f in findings if f.location.get("rule") == "image-rpm-not-parsed"]
    assert len(gap) == 1
    assert gap[0].category == "scan-gap"


# ── robustness against a hostile archive ──────────────────────────────────────────────────────────
def test_a_layer_path_cannot_escape_via_traversal(tmp_path):
    """Nothing is extracted, but a `..` in a member name would let a crafted layer disguise a
    sensitive path from the rules that match on it."""
    image = build_image(tmp_path, [_layer({"app/../root/.ssh/id_rsa": PRIVATE_KEY})])
    findings = _findings(image)
    hit = next(f for f in findings if f.location.get("rule", "").startswith("image-sensitive-file"))
    assert hit.location["path"] == "root/.ssh/id_rsa"
    assert ".." not in hit.location["path"]


def test_an_absolute_layer_path_is_normalized(tmp_path):
    image = build_image(tmp_path, [_layer({"/root/.ssh/id_rsa": PRIVATE_KEY})])
    hit = next(f for f in _findings(image)
               if f.location.get("rule", "").startswith("image-sensitive-file"))
    assert hit.location["path"] == "root/.ssh/id_rsa"


def test_a_non_image_archive_is_reported_rather_than_silently_producing_nothing(tmp_path):
    path = tmp_path / "notanimage.tar"
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo("hello.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))
    findings = _findings(str(path))
    assert [f.location["rule"] for f in findings] == ["image-unreadable"]
    assert findings[0].category == "scan-error"


def test_a_corrupt_archive_raises_a_typed_error(tmp_path):
    path = tmp_path / "broken.tar"
    path.write_bytes(b"not a tar file at all")
    with pytest.raises(ImageFormatError):
        ImageArchive(str(path))


def test_an_unreadable_layer_does_not_stop_the_scan(tmp_path):
    """One corrupt blob must not silence the layers that parsed."""
    good = _layer({"root/.ssh/id_rsa": PRIVATE_KEY})
    image = build_image(tmp_path, [b"this is not a tar", good])
    assert "image-sensitive-file" in _rules(_findings(image))


def test_layer_count_is_bounded(tmp_path):
    from guardian_scanner.images.oci import MAX_LAYERS

    image = build_image(tmp_path, [_layer({f"f{i}.txt": "x"}) for i in range(MAX_LAYERS + 10)])
    with ImageArchive(image) as archive:
        assert len(archive.layer_names) == MAX_LAYERS


# ── the Dockerfile rules still work ───────────────────────────────────────────────────────────────
DOCKERFILE = """FROM python:latest
ENV API_TOKEN=abcdef123456
RUN curl -s https://example.com/i.sh | bash
ADD ./src /app
"""


def test_dockerfile_rules_are_unchanged():
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      inline_content=DOCKERFILE)
    titles = {f.title for f in ContainerEngine().run(ctx)}
    assert "Base image uses mutable 'latest' tag" in titles
    assert "Secret baked into image (ENV/ARG)" in titles
    assert "Remote script piped to shell (curl|bash)" in titles
    assert "Use COPY instead of ADD for local files" in titles
    assert "No USER instruction — image runs as root by default" in titles


def test_a_repository_containing_both_a_dockerfile_and_an_image_scans_both(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    build_image(tmp_path, [_layer({"root/.ssh/id_rsa": PRIVATE_KEY})])
    findings = _findings(str(tmp_path), asset_kind="repo")
    rules = _rules(findings)
    assert "image-sensitive-file" in rules
    assert any(str(r).startswith("CIS Docker") for r in rules)


def test_a_well_built_image_produces_nothing(tmp_path):
    """A scanner that always finds something is a scanner nobody reads. A non-root user, a pinned
    tag, a healthcheck and ordinary files must be silent — including `0.0.0.0` in a config file,
    which is how a container is supposed to bind."""
    image = build_image(
        tmp_path,
        [_layer({
            "usr/bin/app": "binary",
            "etc/passwd": "root:x:0:0::/root:/bin/sh\napp:x:10001:10001::/app:/bin/sh\n",
            "app/config.yaml": "listen: 0.0.0.0:8080\nlog_level: info\n",
            "var/lib/dpkg/status": "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\n",
        })],
        config={"User": "app", "Healthcheck": {"Test": ["CMD", "/usr/bin/app", "-health"]},
                "Env": ["PATH=/usr/bin", "APP_ENV=production"]},
        repo_tags=("registry.example.com/app:1.4.2",),
    )
    assert _findings(image) == []
