"""Creating an asset that already exists returns a clean 409, not a 500.

A duplicate identifier used to surface the raw uq_asset_identity IntegrityError as a 500, which
dead-ended the New Scan flow for any target already in the inventory. Now it returns 409 with the
existing asset's id so the caller can scan that one.

Gated by GUARDIAN_RUN_DB_TESTS=1 (needs a live database).
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _client_and_customer():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_api.ratelimit import login_limiter

    login_limiter().reset()
    client = TestClient(app)
    slug = uuid.uuid4().hex[:10]
    signup = client.post("/api/v1/auth/signup", json={
        "organization": f"Org {slug}", "company": "Test estate", "name": "Owner",
        "email": f"owner-{slug}@x.invalid", "password": "a-long-enough-password"})
    assert signup.status_code == 201, signup.text
    hdr = {"Authorization": f"Bearer {signup.json()['access_token']}"}
    customer_id = signup.json()["customer_id"]
    return client, hdr, customer_id


def _asset_body(customer_id: str, identifier: str) -> dict:
    return {"customer_id": customer_id, "name": "app", "kind": "web",
            "identifier": identifier, "exposure": "public"}


def test_creating_a_duplicate_asset_returns_409_naming_the_existing_one():
    client, hdr, customer_id = _client_and_customer()
    ident = f"https://{uuid.uuid4().hex[:8]}.example.com"

    first = client.post("/api/v1/assets", headers=hdr, json=_asset_body(customer_id, ident))
    assert first.status_code == 201, first.text
    first_id = first.json()["id"]

    dup = client.post("/api/v1/assets", headers=hdr, json=_asset_body(customer_id, ident))
    assert dup.status_code == 409, dup.text
    detail = dup.json()["detail"]
    assert detail["code"] == "asset_exists"
    # It names the existing asset so the caller can scan that one instead of dead-ending.
    assert detail["asset_id"] == first_id


def test_a_distinct_identifier_still_creates():
    client, hdr, customer_id = _client_and_customer()
    a = client.post("/api/v1/assets", headers=hdr,
                    json=_asset_body(customer_id, f"https://{uuid.uuid4().hex[:8]}.example.com"))
    b = client.post("/api/v1/assets", headers=hdr,
                    json=_asset_body(customer_id, f"https://{uuid.uuid4().hex[:8]}.example.com"))
    assert a.status_code == 201 and b.status_code == 201
    assert a.json()["id"] != b.json()["id"]
