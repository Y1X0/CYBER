"""AI chat — grounded strictly on the caller's own findings (doc: user's Phase 3 idea #4)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from guardian_ai.chat import answer_question
from guardian_ai.providers import get_provider
from guardian_db.models import Finding
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.schemas import ChatRequest, ChatResponse

router = APIRouter()


@router.post("", response_model=ChatResponse)
def chat(
    body: ChatRequest,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> ChatResponse:
    # Context is strictly tenant-scoped (and customer-scoped for portal contacts).
    q = db.query(Finding).filter(Finding.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        q = q.filter(Finding.customer_id == identity.portal_customer_id)
    elif body.customer_id is not None:
        q = q.filter(Finding.customer_id == body.customer_id)
    if body.scan_id is not None:
        q = q.filter(Finding.scan_id == body.scan_id)
    findings = q.order_by(Finding.risk_score.desc()).limit(50).all()

    result = answer_question(body.question, findings, get_provider())
    return ChatResponse(**result)
