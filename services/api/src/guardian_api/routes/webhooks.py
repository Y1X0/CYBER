"""GitHub webhook receiver — triggers a scan on push/PR (DevSecOps, doc 01 §7).

Unauthenticated but HMAC-verified: the `X-Hub-Signature-256` header is checked against the
configured secret with a constant-time comparison (doc 06 §3). External payload content is treated
as untrusted — only the repo URL is used, to look up a pre-registered asset in this tenant.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac

from fastapi import APIRouter, Header, HTTPException, Request, status
from guardian_common.config import get_settings
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Scan
from guardian_db.session import get_session
from sqlalchemy.orm import Session

from guardian_api.deps import get_db  # noqa: F401 - kept for parity; we open our own session
from guardian_api.publisher import enqueue_scan

router = APIRouter()


def _verify(secret: str, body: bytes, signature: str | None) -> bool:
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/github", status_code=202)
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> dict:
    settings = get_settings()
    body = await request.body()
    if not _verify(settings.github_webhook_secret, body, x_hub_signature_256):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")
    if x_github_event not in {"push", "pull_request"}:
        return {"status": "ignored", "event": x_github_event}

    payload = await request.json()
    repo = payload.get("repository") or {}
    repo_urls = {repo.get("clone_url"), repo.get("html_url"), repo.get("ssh_url")}
    repo_urls.discard(None)
    ref = payload.get("after") or str((payload.get("pull_request") or {}).get("number", ""))

    db: Session = get_session()
    try:
        asset = (
            db.query(Asset).filter(Asset.kind == "repo", Asset.identifier.in_(repo_urls)).first()
            if repo_urls
            else None
        )
        if asset is None:
            return {"status": "no_matching_asset"}
        scan = Scan(
            tenant_id=asset.tenant_id,
            customer_id=asset.customer_id,
            asset_id=asset.id,
            trigger="webhook",
            ref=ref or None,
            status="queued",
            requested_engines=["secrets", "sast", "sca"],
            stats={},
        )
        db.add(scan)
        db.flush()
        record_audit(
            db,
            action="scan.webhook",
            tenant_id=asset.tenant_id,
            customer_id=asset.customer_id,
            entity_type="scan",
            entity_id=str(scan.id),
            metadata={"event": x_github_event, "ref": ref},
        )
        db.commit()
        scan_id = str(scan.id)
    finally:
        db.close()

    enqueue_scan(scan_id)
    return {"status": "scan_queued", "scan_id": scan_id, "at": dt.datetime.now(dt.UTC).isoformat()}
