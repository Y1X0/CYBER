"""Nuclei-format detection templates, executed natively (WP-D1).

Guardian reads the ecosystem's template format but does not shell out to the `nuclei` binary. Three
reasons, in order of weight:

1. **The safety boundary is ours.** `loader` denies by default: only `http` templates, only GET and
   HEAD, no DSL evaluation, no payload sets, no raw requests, no redirects, no out-of-band
   callbacks. Handing a YAML file to an external engine means inheriting whatever that engine is
   willing to do with it, against a customer's production systems.
2. **It stays in the artifact plane.** An external binary is forced onto the `uid_nft` execution
   backend, which needs `CAP_NET_ADMIN`. An in-process HTTP check does not, so this runs anywhere a
   container runs.
3. **The templates remain reviewable.** They are files in this repository, loaded from disk, never
   fetched at scan time — the integrity boundary the original "no remote template feed" decision
   was protecting.

Nuclei and nuclei-templates are MIT licensed, so reading the format and adopting reviewed templates
carries no distribution obligation (see `docs/TOOL_LICENSES.md`).
"""

from guardian_scanner.templates.loader import (
    Rejection,
    TemplateRejected,
    library_path,
    load_directory,
    load_template,
)
from guardian_scanner.templates.model import Detection, Template
from guardian_scanner.templates.runner import Response, evaluate, run_template

__all__ = [
    "Detection",
    "Rejection",
    "Response",
    "Template",
    "TemplateRejected",
    "evaluate",
    "library_path",
    "load_directory",
    "load_template",
    "run_template",
]
