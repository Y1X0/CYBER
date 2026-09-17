"""Server-side access-token revocation via users.token_version (Item 1).

Every access token carries the token_version it was minted at (claim `tv`). get_current_identity
rejects a token whose `tv` != the user's current token_version, and POST /auth/logout bumps that
version — so a bearer token stolen before logout stops working on the next request, statelessly.

No database: get_current_identity is exercised with a small fake session (the `tv` check runs before
any membership query), and the login token is minted through the real route with a fake get_db.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from guardian_api import deps, ratelimit
from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.main import app
from guardian_api.routes.auth import logout
from guardian_common.config import get_settings
from guardian_common.security import create_access_token, decode_access_token

_CORRECT = "correct-horse-battery-staple"


class _User:
    def __init__(self, token_version=0, status="active"):
        self.id = uuid.uuid4()
        self.email = "user@example.com"
        self.name = "User"
        self.password_hash = "argon2-hash"
        self.status = status
        self.token_version = token_version


class _Row:
    def __init__(self, tenant_id, role):
        self.tenant_id = tenant_id
        self.role = role


class _Result:
    def __init__(self, rows=None, scalar=None):
        self._rows = rows or []
        self._scalar = scalar

    def all(self):
        return self._rows

    def first(self):
        return self._rows[0] if self._rows else None

    def scalar(self):
        return self._scalar


class _DB:
    """Just enough Session for get_current_identity's tv check + membership resolution."""

    def __init__(self, user, tenant_id):
        self._user = user
        self._tid = tenant_id
        self.info = {}
        self.committed = False

    def get(self, _model, _uid):
        return self._user

    def execute(self, stmt, params=None):  # noqa: ANN001
        sql = str(stmt)
        if "auth_memberships" in sql:
            return _Result(rows=[_Row(self._tid, "owner")])
        if "auth_portal" in sql:
            return _Result(rows=[])
        if "SELECT settings FROM tenants" in sql:
            return _Result(scalar={})
        return _Result()

    def add(self, *a, **k):
        pass

    def commit(self):
        self.committed = True


def _token(uid, tv):
    s = get_settings()
    return create_access_token(subject=str(uid), secret=s.jwt_secret,
                               algorithm=s.jwt_algorithm, claims={"tv": tv})


def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.fixture(autouse=True)
def _reset():
    ratelimit.reset_login_limiter()
    yield
    ratelimit.reset_login_limiter()


def test_matching_token_version_is_accepted():
    user = _User(token_version=3)
    tid = uuid.uuid4()
    db = _DB(user, tid)
    identity = get_current_identity(creds=_creds(_token(user.id, 3)), x_tenant_id=None, db=db)
    assert isinstance(identity, Identity)
    assert identity.tenant_id == tid


def test_revoked_token_is_rejected_after_a_version_bump():
    # Token minted at tv=0, but the user has since bumped to 1 (a logout happened) → rejected.
    user = _User(token_version=1)
    db = _DB(user, uuid.uuid4())
    with pytest.raises(HTTPException) as exc:
        get_current_identity(creds=_creds(_token(user.id, 0)), x_tenant_id=None, db=db)
    assert exc.value.status_code == 401
    assert "revoked" in exc.value.detail


def test_logout_bumps_token_version_and_commits(monkeypatch):
    monkeypatch.setattr("guardian_api.routes.auth.record_audit", lambda *a, **k: None)
    user = _User(token_version=0)
    tid = uuid.uuid4()
    db = _DB(user, tid)
    identity = Identity(user=user, tenant_id=tid, staff_role="owner", portal_customer_id=None)
    resp = logout(identity=identity, db=db)
    assert resp.status_code == 204
    assert user.token_version == 1          # every previously-issued token is now revoked
    assert db.committed is True


def test_login_token_carries_the_current_token_version(monkeypatch):
    # The login route must stamp the user's token_version into the token, or revocation is inert.
    s = get_settings()
    monkeypatch.setattr(s, "trusted_proxy_count", 0)
    monkeypatch.setattr("guardian_api.routes.auth.verify_password", lambda pw, h: pw == _CORRECT)
    user = _User(token_version=7)

    class _LoginDB:
        def query(self, *a, **k):
            return self

        def filter(self, *a, **k):
            return self

        def first(self):
            return user

        def add(self, *a, **k):
            pass

        def commit(self):
            pass

    app.dependency_overrides[get_db] = lambda: _LoginDB()
    try:
        r = TestClient(app).post("/api/v1/auth/login",
                                 json={"email": "user@example.com", "password": _CORRECT})
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200, r.text
    payload = decode_access_token(r.json()["access_token"], secret=s.jwt_secret,
                                  algorithms=[s.jwt_algorithm])
    assert payload["tv"] == 7


def test_api_key_path_is_unaffected(monkeypatch):
    # A machine identity (API key) short-circuits before the tv check; assert the tv logic does not
    # touch that path by making _api_key_identity return a machine and confirming it is returned.
    sentinel = object()
    monkeypatch.setattr(deps, "_api_key_identity", lambda cred, db: sentinel)
    monkeypatch.setattr(deps, "_enforce_rate_limit", lambda ident, db: None)
    out = get_current_identity(creds=_creds("gk_whatever"), x_tenant_id=None, db=_DB(_User(), None))
    assert out is sentinel
