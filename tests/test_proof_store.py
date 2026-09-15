"""Encrypted persistence for the Proof-of-Vulnerability vault.

No database: ProofRecord instances construct fine in memory and the seal/unseal path is pure, so the
encryption + integrity guarantees are fully testable here. What matters: the proof round-trips
through encryption, and a proof whose ciphertext or hash was tampered with at rest is refused on read
rather than served as if trustworthy.
"""

from __future__ import annotations

from types import SimpleNamespace

from guardian_core.proof import SafeReproduction, build_proof
from guardian_db.proof_store import _seal, _unseal, load_proof, store_proof

_PROOF = build_proof(
    finding_fingerprint="fp1", vuln_class="CWE-89",
    reproduction=SafeReproduction(method="http_probe", probe="id=1'",
                                  expected_signal="SQL syntax error",
                                  target={"endpoint": "/user", "param": "id"}),
    observed_evidence="You have an error in your SQL syntax near ''",
    regression_ref={"engine": "web_checks", "check": "sqli-error-based"})


def test_a_proof_round_trips_through_encryption():
    sealed, digest = _seal(_PROOF.to_dict())
    assert sealed and len(digest) == 64
    assert _PROOF.reproduction.probe not in sealed          # it is encrypted, not just encoded
    out = _unseal(sealed, digest)
    assert out is not None
    assert out["vuln_class"] == "CWE-89"
    assert out["reproduction"]["probe"] == "id=1'"
    assert out["regression_ref"]["check"] == "sqli-error-based"


def test_a_tampered_hash_is_refused():
    sealed, _digest = _seal(_PROOF.to_dict())
    assert _unseal(sealed, "0" * 64) is None                # wrong hash -> not trusted


def test_a_tampered_ciphertext_is_refused():
    sealed, digest = _seal(_PROOF.to_dict())
    # Flip the ciphertext: decryption fails (or, if it somehow decodes, the hash won't match).
    broken = sealed[:-4] + ("aaaa" if sealed[-4:] != "aaaa" else "bbbb")
    assert _unseal(broken, digest) is None


def test_the_hash_is_stable_for_the_same_proof():
    _s1, d1 = _seal(_PROOF.to_dict())
    _s2, d2 = _seal(_PROOF.to_dict())
    assert d1 == d2                                          # canonical JSON -> stable digest


def test_store_proof_builds_a_scoped_encrypted_record_that_loads_back():
    added = []
    session = SimpleNamespace(add=added.append)
    finding = SimpleNamespace(
        id="finding-uuid", tenant_id="tenant-uuid", customer_id="customer-uuid")

    record = store_proof(session, finding=finding, proof=_PROOF, created_by="user-uuid")

    assert record in added
    assert record.tenant_id == "tenant-uuid"                # scoped to the finding's tenant
    assert record.customer_id == "customer-uuid"
    assert record.finding_id == "finding-uuid"
    assert record.vuln_class == "CWE-89"
    assert record.method == "http_probe"
    assert record.safe is True
    assert record.created_by == "user-uuid"
    assert record.sealed_proof and record.content_sha256

    # The whole point: what was stored decrypts back to the original proof.
    loaded = load_proof(record)
    assert loaded is not None
    assert loaded["reproduction"]["probe"] == "id=1'"
    assert loaded["observed_evidence"].startswith("You have an error")


def test_a_corrupted_stored_record_loads_as_none():
    record = SimpleNamespace(sealed_proof="not-a-valid-token", content_sha256="x" * 64)
    assert load_proof(record) is None
