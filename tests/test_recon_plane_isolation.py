"""Recon (network) plane isolation invariants — the hard boundary, enforced in CI. No DB, no network.

The recon plane is the ONE privileged image (root + CAP_NET_ADMIN + nmap + nftables). These tests lock
in the properties that keep that privilege where it belongs:

  * NET_ADMIN / --cap-add appears ONLY in guardian-recon-plane.yml — never the scan/artifact plane.
    This is the hard invariant: if someone ever adds the capability to the scan plane, this fails.
  * The recon image ships nmap + nftables and NONE of the artifact-scanning binaries, runs as root,
    and consumes only the recon/tools queues.
  * The recon plane holds no JWT secret, no KMS master, no signing private key (secret boundary).
  * A recon/tool co-located plane still requires the broker-seal key (config tightening), while a
    pure recon plane does not.
  * Owner-direct recon carries its own authorization basis and its scope derivation is deterministic.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from pydantic import ValidationError

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_WORKFLOWS = _ROOT / ".github/workflows"
_RECON_PLANE = _WORKFLOWS / "guardian-recon-plane.yml"
_SCAN_PLANE = _WORKFLOWS / "guardian-scan-plane.yml"
_DOCKERFILE_RECON = _ROOT / "infra/docker/Dockerfile.recon"
_DOCKERFILE_SCANNER = _ROOT / "infra/docker/Dockerfile.scanner"

# The ACTUAL runtime capability grants — the docker flags, not the words. Matching prose ("the
# privileged image", "CAP_NET_ADMIN") would false-positive on comments; the invariant is about what a
# container is actually GRANTED at `docker run`, which is `--cap-add` / `--privileged`.
_CAP_PATTERNS = (re.compile(r"--cap-add", re.IGNORECASE), re.compile(r"--privileged", re.IGNORECASE))


def _dockerfile_directives(path: pathlib.Path) -> str:
    """The Dockerfile's effective directives — comment (#...) and blank lines stripped — so a check
    tests what the image DOES, never what a comment mentions."""
    lines = []
    for raw in path.read_text().splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return "\n".join(lines)


# ── THE HARD INVARIANT: NET_ADMIN / cap-add lives ONLY on the recon plane ─────────────────────────
def test_net_admin_appears_only_in_the_recon_plane_workflow():
    offenders: dict[str, list[str]] = {}
    for wf in sorted(_WORKFLOWS.glob("*.yml")):
        if wf.name == "guardian-recon-plane.yml":
            continue
        text = wf.read_text()
        hits = [p.pattern for p in _CAP_PATTERNS if p.search(text)]
        if hits:
            offenders[wf.name] = hits
    assert not offenders, (
        "NET_ADMIN / --cap-add / privileged must appear ONLY in guardian-recon-plane.yml; "
        f"found in: {offenders}"
    )


def test_scan_plane_workflow_has_no_capability_grant():
    text = _SCAN_PLANE.read_text()
    for pat in _CAP_PATTERNS:
        assert not pat.search(text), (
            f"the scan/artifact plane must never grant {pat.pattern}; adding it here is exactly the "
            "regression this guard exists to catch"
        )


def test_recon_plane_workflow_does_grant_net_admin():
    # The positive half: the recon plane MUST add NET_ADMIN, or nmap fails closed for a packaging
    # reason rather than a policy one. If this ever stops being true, the workflow is broken.
    text = _RECON_PLANE.read_text()
    assert "--cap-add=NET_ADMIN" in text


def test_artifact_scanner_image_stays_unprivileged():
    directives = _dockerfile_directives(_DOCKERFILE_SCANNER)
    assert "USER guardian" in directives, "the artifact/scan image must drop to an unprivileged user"
    # And it must not INSTALL the network scanner (a comment may mention it; a directive may not).
    assert "nmap" not in directives.lower(), "nmap must not be installed in the artifact/scan image"


# ── recon image contents: nmap + nftables, root, no artifact tooling ──────────────────────────────
def test_recon_image_installs_nmap_and_nftables():
    text = _DOCKERFILE_RECON.read_text()
    apt = re.search(r"apt-get install[^\n]*", text)
    assert apt, "Dockerfile.recon must apt-install its tools"
    assert "nmap" in apt.group(0), "the recon image must install nmap"
    assert "nftables" in apt.group(0), "the recon image must install nftables for the uid_nft cage"


def test_recon_image_runs_as_root_for_setuid_and_net_admin():
    # The uid_nft backend must setuid each run + build nft tables, which needs starting as root. The
    # recon image is the ONE image that must NOT drop to a non-root user (checked on directives, not
    # the comment that explains why).
    directives = _dockerfile_directives(_DOCKERFILE_RECON)
    assert "USER guardian" not in directives
    assert "\nUSER " not in ("\n" + directives), "the recon image must not drop privileges"


def test_recon_image_ships_no_artifact_scanning_binaries():
    directives = _dockerfile_directives(_DOCKERFILE_RECON).lower()
    for forbidden in ("trivy", "gitleaks", "syft", "grype", "osv-scanner", "semgrep", "checkov",
                      "modelscan"):
        assert forbidden not in directives, (
            f"{forbidden} is artifact tooling and must not be installed in the recon image"
        )


def test_recon_image_consumes_only_recon_and_tools_queues():
    directives = _dockerfile_directives(_DOCKERFILE_RECON)
    assert "recon,tools" in directives, "the recon image default command must consume recon,tools"
    assert "--concurrency" in directives and '"1"' in directives.replace("'", '"'), \
        "the recon image must run at concurrency 1 (uid_nft single-allocator)"


# ── recon plane secret boundary + wiring ──────────────────────────────────────────────────────────
def test_recon_plane_holds_no_master_secrets():
    text = _RECON_PLANE.read_text()
    # A secret reaches the runner only through `secrets.<NAME>`. The DB-less recon plane never carries
    # a token-minting or KMS master key, nor the job-signing PRIVATE key — none is referenced.
    assert "secrets.GUARDIAN_JWT_SECRET" not in text
    assert "secrets.GUARDIAN_ENCRYPTION_KEY" not in text
    assert "secrets.GUARDIAN_JOB_SIGNING_PRIVATE_KEY" not in text
    # It DOES set the plane markers and pass the PUBLIC verify key (not a secret).
    assert "GUARDIAN_RECON_PLANE=true" in text
    assert "GUARDIAN_TOOL_PLANE=true" in text
    assert "secrets.GUARDIAN_JOB_SIGNING_PUBLIC_KEY" in text


def test_recon_plane_is_workflow_dispatch_only():
    text = _RECON_PLANE.read_text()
    assert "workflow_dispatch" in text
    assert "schedule:" not in text, "active recon must never begin because a cron fired"


# ── config: a recon/tool co-located plane still requires the broker-seal key ──────────────────────
_STRONG_SEAL = "a-strong-seal-key-0123456789abcdef-distinct"
_PUBKEY = "ZmFrZS1lZDI1NTE5LXB1YmxpYy1rZXktMzItYnl0ZXM="  # any non-empty value satisfies the check


def _plane(**over):
    from guardian_common.config import _DEV_JWT_SENTINEL, Settings

    # Pin the execution-plane secrets explicitly (init kwargs beat env vars in pydantic-settings), so
    # a GUARDIAN_JWT_SECRET / GUARDIAN_ENCRYPTION_KEY present in the CI environment does not trip the
    # JWT/KMS boundary check before the broker-seal check under test. Execution planes must NOT carry
    # a real JWT secret or KMS master — the sentinel/empty are the allowed values.
    base = dict(
        env="production", database_url="", app_database_url="",
        redis_url="rediss://:rpw@frankfurt-keyvalue.render.com:6379/0",
        jwt_secret=_DEV_JWT_SENTINEL, encryption_key="",
        broker_seal_key=_STRONG_SEAL, job_signing_public_key=_PUBKEY,
    )
    base.update(over)
    return Settings(**base)


def test_recon_tool_colocated_plane_requires_broker_seal():
    # recon_plane + tool_plane co-located (the network plane): run_tool seals its result, so the seal
    # key is required even though recon_plane is set. This is the config tightening.
    with pytest.raises(ValidationError, match="BROKER_SEAL_KEY"):
        _plane(recon_plane=True, tool_plane=True, broker_seal_key="")


def test_pure_recon_plane_does_not_require_broker_seal():
    # A PURE recon plane (discovery probing only) never seals, so it is allowed with no seal key.
    s = _plane(recon_plane=True, tool_plane=False, broker_seal_key="", job_signing_public_key="")
    assert s.recon_plane is True and s.tool_plane is False


def test_recon_tool_plane_forbids_jwt_and_kms_master():
    # The secret boundary the workflow proves is also enforced by config: a real JWT secret or KMS
    # master on the recon/tool plane refuses to boot.
    with pytest.raises(ValidationError, match="JWT_SECRET"):
        _plane(recon_plane=True, tool_plane=True, jwt_secret="a-real-strong-jwt-secret-not-sentinel")
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY"):
        _plane(recon_plane=True, tool_plane=True,
               encryption_key="a-real-strong-kms-master-not-sentinel")


def test_owner_direct_recon_flag_is_off_by_default():
    from guardian_common.config import Settings

    assert Settings(env="local").owner_direct_recon is False


# ── owner-direct-recon basis + deterministic scope ────────────────────────────────────────────────
def test_owner_direct_recon_basis_value():
    from guardian_core.enums import AuthorizationBasis

    assert AuthorizationBasis.OWNER_DIRECT_RECON.value == "owner-direct-recon"


def test_owner_direct_recon_scope_is_deterministic_and_confined_to_target():
    # Owner-direct treats the requested target as authorized; the cage is bound to exactly that scope.
    from guardian_core.tool import derive_effective_scope
    from guardian_scanner.tools.providers.nmap_provider import NmapProvider

    caps = NmapProvider().capabilities
    a = derive_effective_scope(["203.0.113.7"], ["203.0.113.7"], caps)
    b = derive_effective_scope(["203.0.113.7"], ["203.0.113.7"], caps)
    assert a == b                                   # deterministic
    assert a.targets == ("203.0.113.7",)            # confined to exactly the affirmed target
    assert 23 in a.ports and 3389 in a.ports        # the nmap capability port allowlist


def test_recon_route_rejects_non_ip_target():
    from guardian_api.routes.recon import _valid_ip

    assert _valid_ip("203.0.113.7") == "203.0.113.7"
    assert _valid_ip("evil.example.com") is None      # a hostname can never smuggle a flag
    assert _valid_ip("203.0.113.7; rm -rf /") is None
