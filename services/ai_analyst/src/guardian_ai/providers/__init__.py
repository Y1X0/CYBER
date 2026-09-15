"""Provider factory — Claude when configured, deterministic stub otherwise."""

from __future__ import annotations

from guardian_common.config import get_settings
from guardian_common.logging import get_logger

from guardian_ai.providers.base import LLMError, LLMProvider
from guardian_ai.providers.stub import StubProvider

log = get_logger("guardian.ai")

__all__ = ["LLMError", "LLMProvider", "StubProvider", "get_provider"]


def get_provider() -> LLMProvider:
    """Return the configured provider, in order of preference, falling back to the deterministic
    stub if none is available:

    1. Claude, when a paid Anthropic key is set (`GUARDIAN_ANTHROPIC_API_KEY`).
    2. Any OpenAI-compatible API, when `GUARDIAN_AI_API_KEY` + `GUARDIAN_AI_BASE_URL` are set — this
       is how the analyst runs on a FREE LLM (Gemini's OpenAI endpoint, Groq, OpenRouter, …).
    3. The offline stub — grounded, deterministic, needs no key.
    """
    settings = get_settings()
    if settings.anthropic_api_key:
        try:
            from guardian_ai.providers.anthropic_provider import AnthropicProvider

            return AnthropicProvider()
        except LLMError as exc:
            log.info("ai_provider_fallback_to_stub", reason=str(exc))
    if settings.ai_api_key and settings.ai_base_url:
        try:
            from guardian_ai.providers.openai_compatible import OpenAICompatibleProvider

            return OpenAICompatibleProvider()
        except LLMError as exc:
            log.info("ai_provider_fallback_to_stub", reason=str(exc))
    return StubProvider()
