"""Asset config must not carry a server-side filesystem path (AUD-P1-6 defense in depth).

A tenant/staff user submits `config` freely on asset create. A stale scanner image honoured keys like
`local_path` as a workspace path and read arbitrary files off the worker — which holds ENCRYPTION_KEY
and JWT_SECRET. The API now refuses any `*_path` key (plus `image_archive`) with a validation error,
so the hostile value is never stored regardless of which worker image runs. FastAPI turns the
resulting Pydantic ValidationError into a 422.
"""

from __future__ import annotations

import uuid

import pytest
from guardian_api.schemas import AssetCreate, reject_path_config_keys
from pydantic import ValidationError


def _kwargs(config: dict) -> dict:
    return {"customer_id": uuid.uuid4(), "name": "web", "kind": "web", "config": config}


@pytest.mark.parametrize("key", [
    "local_path", "apk_path", "ipa_path", "image_archive", "workspace_path", "artifact_path",
    "some_custom_path", "PAYLOAD_path",
])
def test_forbidden_path_key_is_rejected(key):
    with pytest.raises(ValidationError) as exc:
        AssetCreate(**_kwargs({key: "/etc/shadow"}))
    assert key in str(exc.value)


def test_multiple_forbidden_keys_all_reported():
    with pytest.raises(ValidationError) as exc:
        AssetCreate(**_kwargs({"local_path": "/etc/shadow", "apk_path": "/root/.ssh/id_rsa"}))
    msg = str(exc.value)
    assert "apk_path" in msg and "local_path" in msg


def test_clean_config_is_accepted():
    # The legitimate keys the worker actually reads must still pass.
    good = {"inline_content": "x", "history_depth": 5, "artifact_id": str(uuid.uuid4()),
            "artifact_kind": "apk", "business_impact": "high"}
    asset = AssetCreate(**_kwargs(good))
    assert asset.config == good


def test_empty_config_is_accepted():
    assert AssetCreate(**_kwargs({})).config == {}


def test_helper_reports_sorted_forbidden_keys():
    assert reject_path_config_keys({"b_path": 1, "a_path": 2, "ok": 3}) == ["a_path", "b_path"]
    assert reject_path_config_keys({"image_archive": 1}) == ["image_archive"]
    assert reject_path_config_keys({"artifact_id": "x"}) == []
    assert reject_path_config_keys(None) == []
