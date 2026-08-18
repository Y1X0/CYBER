"""Container image analysis (WP-D6).

Reads a `docker save` / OCI-layout archive without extracting it, inventories the software inside,
and reports what is wrong with the image itself. The package inventory is fed to the existing
`VulnMatcher` seam rather than matched here, so an image and a repository get the same version-range
logic instead of two implementations that disagree at the edges.
"""

from guardian_scanner.images.analysis import ImageFinding, analyze_config, analyze_layers
from guardian_scanner.images.oci import ImageArchive, ImageConfig, ImageFormatError, LayerEntry
from guardian_scanner.images.packages import (
    parse_apk_installed,
    parse_dpkg_status,
    parse_node_package_json,
    parse_python_metadata,
)

__all__ = [
    "ImageArchive",
    "ImageConfig",
    "ImageFinding",
    "ImageFormatError",
    "LayerEntry",
    "analyze_config",
    "analyze_layers",
    "parse_apk_installed",
    "parse_dpkg_status",
    "parse_node_package_json",
    "parse_python_metadata",
]
