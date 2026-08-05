"""App-level smoke tests that require no database."""

from fastapi.testclient import TestClient
from guardian_api.main import app

client = TestClient(app)


def test_root_ok():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_health_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_openapi_served():
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert "/api/v1/scans" in resp.json()["paths"]


def test_protected_route_requires_auth():
    resp = client.get("/api/v1/customers")
    assert resp.status_code in (401, 403)
