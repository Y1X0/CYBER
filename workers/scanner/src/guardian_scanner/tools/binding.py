"""Tool-target → Asset binding (Framework) — deterministic, exact, tenant-scoped, or nothing.

Evidence is always the primary truth (persisted independently). A *Finding* is only derived when a
tool's evidence binds to exactly ONE managed asset — never a guess. The binding rule (locked):

  * the asset is web/api (its identifier is a URL with a host),
  * its exact canonical host equals the evidence host (the same rule 6E's `serves` uses — no fuzzy,
    no brand, no IP-literal match),
  * within the tenant, and
  * there is EXACTLY one such asset.

Zero or two-plus matches → `None` (Evidence-only, no Finding). The provider NEVER creates an asset.
"""

from __future__ import annotations

import uuid

from guardian_core.canonicalize import canonical_key
from guardian_core.enums import NodeType
from guardian_db.models import Asset
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_scanner.discovery.enricher import _asset_host  # exact canonical-host identity (6E)


def resolve_asset(session: Session, *, tenant_id: uuid.UUID, host: str) -> Asset | None:
    """The single tenant web/api asset whose exact canonical host == `host`, else None.

    Returns None for zero OR more than one match — Evidence-only, never an ambiguous binding.
    """
    if not host:
        return None
    want = canonical_key(NodeType.SUBDOMAIN, host)
    matches = [
        a for a in session.execute(
            select(Asset).where(
                Asset.tenant_id == tenant_id,
                Asset.kind.in_(("web", "api")),
            ).order_by(Asset.id)
        ).scalars()
        if _asset_host(a) == want
    ]
    return matches[0] if len(matches) == 1 else None
