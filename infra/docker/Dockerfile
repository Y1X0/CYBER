# Single image running either the API or the scanner worker (command chosen in compose).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# git: the scanner worker shallow-clones repo assets.
# nftables (P1-ε): the uid_nft execution backend builds a per-run kernel egress allowlist with `nft`;
# without the binary an external-binary run fails closed (never runs unconfined), so it MUST ship in
# the image that runs worker-tools.
# `upgrade` before `install`, and in the same layer as `update`: the base image is a floating tag, so
# it carries whatever its packages were at ITS build time, and nothing here ever refreshed them.
# Without this the release gate blocks on base-image CVEs that Debian has already fixed and we simply
# never pulled — as it did for CVE-2026-53612/53613/53614/53615 in util-linux (mount TOCTOU, a
# nosuid/noexec bypass via LIBMOUNT_FORCE_MOUNT2, and an integer overflow in libblkid), all fixed in
# util-linux 2.41-5 and shipping in the same Debian 13 the base already tracks.
#
# A blanket upgrade rather than a named list on purpose: the gate is `--ignore-unfixed`, so it only
# ever demands fixes that exist, and a named list goes stale silently — the next base CVE blocks a
# release instead of being picked up. This costs nothing in reproducibility that was not already
# spent by a floating base tag and an unpinned `apt-get update`.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git curl nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Source must be present before the editable install (monorepo, multi-src discovery).
COPY pyproject.toml README.md alembic.ini ./
COPY packages ./packages
COPY services ./services
COPY workers ./workers

# setuptools >=78.1.1 fixes CVE-2025-47273 (path traversal); upgraded in-image before the install.
# Then drop pip's bundled vendoring manifests (bom.cdx.json = CycloneDX SBOM, vendor.txt = pin list).
# These describe pip's OWN internal _vendor copies (setuptools 70.3.0 / msgpack 1.1.2), not the
# runtime packages (which are the upgraded 84.0.0 / 1.2.1). Trivy's SBOM analyzer parses them and
# mis-attributes those vendored versions as image findings. They are build/maintenance metadata only
# (bom.cdx.json is never read by pip; vendor.txt is read solely by the `pip debug` subcommand), so
# removing them clears the false attribution at its source without touching any runtime dependency.
RUN pip install --upgrade pip "setuptools>=78.1.1" && pip install -e . \
    && vendor="$(python -c 'import os, pip._vendor as v; print(os.path.dirname(v.__file__))')" \
    && rm -f "$vendor/bom.cdx.json" "$vendor/vendor.txt"

# Drop privileges.
RUN useradd --create-home --uid 10001 guardian && chown -R guardian:guardian /app
USER guardian

EXPOSE 8000

CMD ["uvicorn", "guardian_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
