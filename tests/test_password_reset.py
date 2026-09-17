"""Password-reset flow (Item 6): no enumeration, hashed single-use token, expiry, rate limit, and a
token_version bump that revokes existing sessions.

No database: get_db is overridden with a small fake whose canned query results drive the two
endpoints. The reset token is hashed before storage, so the fake asserts the RAW token is never the
stored value.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient
from guardian_api import ratelimit
from guardian_api.deps import get_db
from guardian_api.main import app
from guardian_common.config import get_settings
from guardian_db.models import PasswordResetToken, User


class _User:
    def __init__(self, status="active", token_version=0):
        self.id = uuid.uuid4()
        self.email = "victim@example.com"
        self.name = "Victim"
        self.password_hash = "old-argon2-hash"
        self.status = status
        self.token_version = token_version


class _Query:
    def __init__(self, result, on_update=None):
        self._result = result
        self._on_update = on_update

    def filter(self, *a, **k):
        return self

    def first(self):
        return self._result

    def update(self, values):
        if self._on_update:
            self._on_update(values)
        return 1


class _DB:
    def __init__(self, user_by_email=None, token_row=None, user_by_id=None):
        self.user_by_email = user_by_email
        self.token_row = token_row
        self.user_by_id = user_by_id
        self.added = []
        self.committed = False
        self.updated = None

    def query(self, model):
        if model is User:
            return _Query(self.user_by_email)
        if model is PasswordResetToken:
            return _Query(self.token_row, on_update=self._mark_used)
        return _Query(None)

    def get(self, _model, _id):
        return self.user_by_id

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed = True

    def _mark_used(self, values):
        self.updated = values


@pytest.fixture(autouse=True)
def _reset_limiter():
    ratelimit.reset_login_limiter()
    yield
    ratelimit.reset_login_limiter()


def _client(db):
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _teardown():
    app.dependency_overrides.pop(get_db, None)


# ── request: no enumeration ──────────────────────────────────────────────────────────────────────
def test_request_for_unknown_email_returns_202_and_creates_no_token():
    db = _DB(user_by_email=None)
    try:
        r = _client(db).post("/api/v1/auth/password-reset/request",
                             json={"email": "nobody@example.com"})
    finally:
        _teardown()
    assert r.status_code == 202
    assert db.added == []                       # no token minted for a non-existent account


def test_request_for_known_email_returns_202_and_stores_a_hashed_token():
    user = _User()
    db = _DB(user_by_email=user)
    try:
        r = _client(db).post("/api/v1/auth/password-reset/request",
                             json={"email": user.email})
    finally:
        _teardown()
    assert r.status_code == 202
    tokens = [o for o in db.added if isinstance(o, PasswordResetToken)]
    assert len(tokens) == 1
    tok = tokens[0]
    # The stored value is a 64-char SHA-256 hex, never a raw token.
    assert len(tok.token_hash) == 64 and all(c in "0123456789abcdef" for c in tok.token_hash)
    assert tok.expires_at is not None


def test_the_two_responses_are_identical_so_the_endpoint_does_not_enumerate():
    unknown = _DB(user_by_email=None)
    known = _DB(user_by_email=_User())
    try:
        r1 = _client(unknown).post("/api/v1/auth/password-reset/request",
                                   json={"email": "nobody@example.com"})
        _teardown()
        r2 = _client(known).post("/api/v1/auth/password-reset/request",
                                 json={"email": "victim@example.com"})
    finally:
        _teardown()
    assert r1.status_code == r2.status_code == 202
    assert r1.json() == r2.json()               # same body — existence is not revealed


def test_request_is_rate_limited_per_email(monkeypatch):
    monkeypatch.setattr(get_settings(), "password_reset_per_minute", 2)
    ratelimit.reset_login_limiter()
    db = _DB(user_by_email=_User())
    try:
        client = _client(db)
        codes = [client.post("/api/v1/auth/password-reset/request",
                             json={"email": "victim@example.com"}).status_code for _ in range(4)]
    finally:
        _teardown()
    assert codes[:2] == [202, 202]
    assert codes[2] == 429 and codes[3] == 429   # bounded per email


# ── confirm: single-use, sets password, bumps token_version ──────────────────────────────────────
_RAW_TOKEN = "the-raw-token-1234567890abcdef"   # >= 20 chars (schema minimum)


def _token_row(user_id, used=False):
    row = PasswordResetToken()
    row.user_id = user_id
    row.token_hash = hashlib.sha256(_RAW_TOKEN.encode()).hexdigest()
    row.used_at = object() if used else None
    return row


def test_confirm_sets_the_password_and_bumps_token_version():
    user = _User(token_version=4)
    db = _DB(token_row=_token_row(user.id), user_by_id=user)
    try:
        r = _client(db).post("/api/v1/auth/password-reset/confirm",
                             json={"token": _RAW_TOKEN, "new_password": "a-brand-new-pass-123"})
    finally:
        _teardown()
    assert r.status_code == 204
    assert user.password_hash != "old-argon2-hash"      # password changed
    assert user.token_version == 5                       # every existing session revoked (Item 1)
    assert db.updated is not None                        # outstanding tokens consumed
    assert db.committed is True


def test_confirm_with_no_matching_token_is_rejected_generically():
    db = _DB(token_row=None)
    try:
        r = _client(db).post("/api/v1/auth/password-reset/confirm",
                             json={"token": "wrong-token-value-2345678", "new_password": "a-brand-new-pass"})
    finally:
        _teardown()
    assert r.status_code == 400
    assert "invalid or expired" in r.json()["detail"]


def test_confirm_rejects_a_short_new_password():
    # The new password must meet the same minimum as sign-up (schema validation → 422).
    db = _DB(token_row=_token_row(uuid.uuid4()), user_by_id=_User())
    try:
        r = _client(db).post("/api/v1/auth/password-reset/confirm",
                             json={"token": _RAW_TOKEN, "new_password": "short"})
    finally:
        _teardown()
    assert r.status_code == 422


def test_stored_hash_matches_sha256_of_the_raw_token():
    from guardian_api.routes.auth import _hash_reset_token

    assert _hash_reset_token("abc") == hashlib.sha256(b"abc").hexdigest()
