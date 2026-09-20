"""A web/api asset target must carry an explicit http:// or https:// scheme.

The DAST/API engines fetch the identifier exactly as stored and do not follow redirects, so the
protocol is load-bearing. A bare hostname (the testphp.vulnweb.com case) or an HTTP-only host
silently treated as https:// is simply unreachable — and an unreachable target used to read as a
clean 0-findings scan. The API refuses to guess the scheme; it requires the operator to state it.
FastAPI turns the resulting Pydantic ValidationError into a 422.
"""

from __future__ import annotations

import uuid

import pytest
from guardian_api.schemas import AssetCreate
from pydantic import ValidationError


def _kwargs(kind: str, identifier: str) -> dict:
    return {"customer_id": uuid.uuid4(), "name": "app", "kind": kind, "identifier": identifier}


@pytest.mark.parametrize("kind", ["web", "api"])
@pytest.mark.parametrize("url", ["http://testphp.vulnweb.com", "https://app.example.com/login"])
def test_explicit_http_scheme_is_accepted(kind, url):
    assert AssetCreate(**_kwargs(kind, url)).identifier == url


@pytest.mark.parametrize("kind", ["web", "api"])
def test_scheme_less_target_is_rejected_with_guidance(kind):
    with pytest.raises(ValidationError) as exc:
        AssetCreate(**_kwargs(kind, "testphp.vulnweb.com"))
    msg = str(exc.value)
    # Names both options so the operator can choose the right protocol, not have one guessed.
    assert "http://testphp.vulnweb.com" in msg and "https://testphp.vulnweb.com" in msg


@pytest.mark.parametrize("kind", ["web", "api"])
def test_unsupported_scheme_is_rejected(kind):
    with pytest.raises(ValidationError) as exc:
        AssetCreate(**_kwargs(kind, "ftp://files.example.com"))
    assert "ftp://" in str(exc.value) and "http" in str(exc.value)


def test_surrounding_whitespace_is_trimmed():
    asset = AssetCreate(**_kwargs("web", "  http://testphp.vulnweb.com  "))
    assert asset.identifier == "http://testphp.vulnweb.com"


def test_repo_and_other_kinds_are_not_scheme_constrained():
    # A repo git URL / inline artefact id is not an http target; it must pass unchanged.
    assert AssetCreate(**_kwargs("repo", "git@github.com:acme/app.git")).identifier \
        == "git@github.com:acme/app.git"
    assert AssetCreate(**_kwargs("repo", "inline-artifact-123")).identifier == "inline-artifact-123"


def test_empty_web_identifier_is_allowed():
    # An asset may be created without a target yet; the scheme rule only bites once one is given.
    assert AssetCreate(**_kwargs("web", "")).identifier == ""
