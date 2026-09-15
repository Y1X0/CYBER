"""Encrypted persistence for the Proof-of-Vulnerability vault.

Wraps `guardian_core.proof` (which decides what is *safe* to store) with the *storage* concerns:
encryption at rest and integrity. The proof body is sealed with the credential KMS before it touches
the database, and a SHA-256 of the plaintext is kept alongside so tampering with the ciphertext is
caught on read. Tenant isolation is enforced one level down by Row-Level Security on the table.

The seal/unseal helpers are pure so the crypto + integrity path is testable without a database.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from guardian_common.crypto import decrypt_secret, encrypt_secret
from guardian_common.logging import get_logger
from guardian_core.proof import ProofOfVulnerability

from guardian_db.models import Finding, ProofRecord

log = get_logger("guardian.proof_store")


def _seal(proof_dict: dict) -> tuple[str, str]:
    """Serialize, hash, and encrypt a (already safe, already redacted) proof dict.

    Returns (sealed_ciphertext, sha256_of_plaintext). The hash is over the canonical JSON so it is
    stable and can be recomputed on read to detect tampering.
    """
    payload = json.dumps(proof_dict, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return encrypt_secret(payload), digest


def _unseal(sealed: str, expected_sha256: str) -> dict | None:
    """Decrypt and integrity-check a sealed proof. Returns None (and logs) on decrypt failure or a
    hash mismatch — a proof that does not verify is not shown, rather than shown as trustworthy."""
    payload = decrypt_secret(sealed)
    if payload is None:
        log.warning("proof_unseal_failed", reason="decrypt_failed")
        return None
    if hashlib.sha256(payload.encode()).hexdigest() != expected_sha256:
        # The ciphertext was altered at rest, or the row was stitched together from parts. Refuse
        # to present it as evidence — an evidence vault that serves tampered proof is worse than one
        # that serves none.
        log.error("proof_integrity_mismatch", detail="stored proof failed its SHA-256 check")
        return None
    try:
        return json.loads(payload)
    except ValueError:
        log.warning("proof_unseal_failed", reason="not_json")
        return None


def store_proof(
    session,  # noqa: ANN001 - SQLAlchemy Session
    *,
    finding: Finding,
    proof: ProofOfVulnerability,
    created_by: uuid.UUID | None = None,
) -> ProofRecord:
    """Encrypt and persist a proof for a finding, scoped to that finding's tenant/customer.

    The proof must already have been built via `guardian_core.proof.build_proof`, so it is safe and
    redacted by construction; this only seals and stores it.
    """
    sealed, digest = _seal(proof.to_dict())
    record = ProofRecord(
        tenant_id=finding.tenant_id,
        customer_id=finding.customer_id,
        finding_id=finding.id,
        vuln_class=(proof.vuln_class or "")[:64],
        method=(proof.reproduction.method or "")[:40],
        safe=True,
        sealed_proof=sealed,
        content_sha256=digest,
        created_by=created_by,
    )
    session.add(record)
    return record


def load_proof(record: ProofRecord) -> dict | None:
    """Decrypt and integrity-check a stored proof for presentation. None if it cannot be trusted."""
    return _unseal(record.sealed_proof, record.content_sha256)
