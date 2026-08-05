"""Provider factory — Claude when configured, deterministic stub otherwise."""

from __future__ import annotations

from guardian_common.config import get_settings
from guardian_common.logging import get_logger

from guardian_ai.providers.base import LLMError, LLMProvider
from guardian_ai.providers.stub import StubProvider

log = get_logger("guardian.ai")

__all__ = ["LLMError", "LLMProvider", "StubProvider", "get_provider"]


def get_provider() -> LLMProvider:
    """Return the configured provider. Falls back to the stub if Claude is unavailable."""
    settings = get_settings()
    if settings.anthropic_api_key:
        try:
            from guardian_ai.providers.anthropic_provider import AnthropicProvider

            return AnthropicProvider()
        except LLMError as exc:
            log.info("ai_provider_fallback_to_stub", reason=str(exc))
    return StubProvider()
