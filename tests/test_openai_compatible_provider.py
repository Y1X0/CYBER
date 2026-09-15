"""OpenAI-compatible provider — the free-LLM path for the analyst.

The provider makes a real HTTP call, so these tests fake `httpx.post` with canned OpenAI-shaped
responses — no network, no key needed in CI. What matters: it speaks the /chat/completions format,
survives the free-model quirks (markdown-fenced JSON, an endpoint that rejects response_format), and
turns every failure into an LLMError so `get_provider` can fall back to the stub instead of crashing
a scan's analysis.
"""

from __future__ import annotations

import pytest
from guardian_ai.providers import get_provider
from guardian_ai.providers import openai_compatible as oc
from guardian_ai.providers.base import LLMError
from guardian_ai.providers.openai_compatible import OpenAICompatibleProvider
from guardian_ai.providers.stub import StubProvider
from guardian_common.config import get_settings


class _Resp:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def _chat_body(content: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


@pytest.fixture
def _configured(monkeypatch):
    monkeypatch.setenv("GUARDIAN_AI_API_KEY", "free-key")
    monkeypatch.setenv("GUARDIAN_AI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("GUARDIAN_AI_MODEL", "gemini-2.0-flash")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _capture_post(monkeypatch, responses):
    """Feed a queue of responses to successive httpx.post calls; record each payload."""
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):  # noqa: A002, ANN001
        calls.append({"url": url, "headers": headers, "payload": json})
        return responses[len(calls) - 1]

    monkeypatch.setattr(oc.httpx, "post", fake_post)
    return calls


def test_requires_key_and_base_url(monkeypatch):
    monkeypatch.delenv("GUARDIAN_AI_API_KEY", raising=False)
    monkeypatch.delenv("GUARDIAN_AI_BASE_URL", raising=False)
    get_settings.cache_clear()
    with pytest.raises(LLMError):
        OpenAICompatibleProvider()
    get_settings.cache_clear()


def test_complete_json_parses_a_clean_object(_configured, monkeypatch):
    calls = _capture_post(monkeypatch, [_Resp(body=_chat_body('{"explanation": "clear", "x": 1}'))])
    out = OpenAICompatibleProvider().complete_json(
        system="sys", prompt="p", schema={"type": "object"})
    assert out == {"explanation": "clear", "x": 1}
    # It hit the OpenAI chat endpoint with a bearer token and the configured model.
    assert calls[0]["url"] == "https://example.test/v1/chat/completions"
    assert calls[0]["headers"]["Authorization"] == "Bearer free-key"
    assert calls[0]["payload"]["model"] == "gemini-2.0-flash"
    assert calls[0]["payload"]["response_format"] == {"type": "json_object"}


def test_a_markdown_fenced_json_reply_is_recovered(_configured, monkeypatch):
    fenced = "```json\n{\"explanation\": \"fine\"}\n```"
    _capture_post(monkeypatch, [_Resp(body=_chat_body(fenced))])
    out = OpenAICompatibleProvider().complete_json(system="s", prompt="p", schema={})
    assert out["explanation"] == "fine"


def test_json_padded_with_prose_is_recovered_via_outermost_object(_configured, monkeypatch):
    padded = 'Sure! Here is the result:\n{"explanation": "ok"}\nHope that helps.'
    _capture_post(monkeypatch, [_Resp(body=_chat_body(padded))])
    out = OpenAICompatibleProvider().complete_json(system="s", prompt="p", schema={})
    assert out["explanation"] == "ok"


def test_response_format_rejection_is_retried_without_it(_configured, monkeypatch):
    # First call (with response_format) 400s; the retry without it succeeds.
    calls = _capture_post(monkeypatch, [
        _Resp(status_code=400, text="response_format not supported"),
        _Resp(body=_chat_body('{"explanation": "second try"}')),
    ])
    out = OpenAICompatibleProvider().complete_json(system="s", prompt="p", schema={})
    assert out["explanation"] == "second try"
    assert len(calls) == 2
    assert "response_format" in calls[0]["payload"]
    assert "response_format" not in calls[1]["payload"]


def test_a_persistent_http_error_becomes_an_llm_error(_configured, monkeypatch):
    _capture_post(monkeypatch, [_Resp(status_code=500, text="server error"),
                                _Resp(status_code=500, text="server error")])
    with pytest.raises(LLMError):
        OpenAICompatibleProvider().complete_json(system="s", prompt="p", schema={})


def test_unparseable_json_becomes_an_llm_error(_configured, monkeypatch):
    _capture_post(monkeypatch, [_Resp(body=_chat_body("this is not json at all"))])
    with pytest.raises(LLMError):
        OpenAICompatibleProvider().complete_json(system="s", prompt="p", schema={})


def test_a_network_failure_becomes_an_llm_error(_configured, monkeypatch):
    def boom(*a, **k):  # noqa: ANN002, ANN003
        raise oc.httpx.ConnectError("no route")

    monkeypatch.setattr(oc.httpx, "post", boom)
    with pytest.raises(LLMError):
        OpenAICompatibleProvider().complete_text(system="s", prompt="p")


def test_complete_text_returns_the_raw_message(_configured, monkeypatch):
    calls = _capture_post(monkeypatch, [_Resp(body=_chat_body("a plain answer"))])
    out = OpenAICompatibleProvider().complete_text(system="s", prompt="p")
    assert out == "a plain answer"
    assert "response_format" not in calls[0]["payload"]   # text mode never asks for JSON


def test_get_provider_selects_openai_compatible_when_configured(_configured, monkeypatch):
    monkeypatch.delenv("GUARDIAN_ANTHROPIC_API_KEY", raising=False)
    get_settings.cache_clear()
    provider = get_provider()
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name == "openai_compatible"
    get_settings.cache_clear()


def test_get_provider_falls_back_to_stub_without_any_key(monkeypatch):
    for var in ("GUARDIAN_ANTHROPIC_API_KEY", "GUARDIAN_AI_API_KEY", "GUARDIAN_AI_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    get_settings.cache_clear()
    assert isinstance(get_provider(), StubProvider)
    get_settings.cache_clear()


def test_a_base_url_with_a_trailing_slash_is_normalized(monkeypatch):
    monkeypatch.setenv("GUARDIAN_AI_API_KEY", "k")
    monkeypatch.setenv("GUARDIAN_AI_BASE_URL", "https://example.test/v1/")
    get_settings.cache_clear()
    calls = _capture_post(monkeypatch, [_Resp(body=_chat_body("hi"))])
    OpenAICompatibleProvider().complete_text(system="s", prompt="p")
    assert calls[0]["url"] == "https://example.test/v1/chat/completions"   # no double slash
    get_settings.cache_clear()
