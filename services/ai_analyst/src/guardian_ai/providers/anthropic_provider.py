"""Claude provider via the official Anthropic SDK (ADR-006).

Used when an API key is configured and the `anthropic` package is installed. Uses structured
outputs (`output_config.format`) so responses validate against the analyst's schema, and handles
the `refusal` stop reason. Scanned content in the prompt is delimited and treated as untrusted data.
"""

from __future__ import annotations

import json
from typing import Any

from guardian_common.config import get_settings

from guardian_ai.providers.base import LLMError


class AnthropicProvider:
    name = "anthropic"

    def __init__(self) -> None:
        try:
            import anthropic  # noqa: PLC0415 - optional dependency
        except ImportError as exc:  # pragma: no cover - exercised only with extra installed
            raise LLMError("anthropic package not installed; install the 'ai' extra") from exc
        settings = get_settings()
        if not settings.anthropic_api_key:
            raise LLMError("GUARDIAN_ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self._model = settings.ai_model
        self._effort = settings.ai_effort
        self._max_tokens = settings.ai_max_tokens

    def _message(self, *, system: str, prompt: str, output_config: dict | None = None) -> str:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {"effort": self._effort},
        }
        if output_config:
            kwargs["output_config"].update(output_config)
        resp = self._client.messages.create(**kwargs)
        if resp.stop_reason == "refusal":
            raise LLMError("model declined the request (safety refusal)")
        return next((b.text for b in resp.content if getattr(b, "type", None) == "text"), "")

    def complete_json(
        self, *, system: str, prompt: str, schema: dict, context: dict[str, Any] | None = None
    ) -> dict:
        text = self._message(
            system=system,
            prompt=prompt,
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        try:
            return json.loads(text)
        except ValueError as exc:
            raise LLMError("model did not return valid JSON") from exc

    def complete_text(
        self, *, system: str, prompt: str, context: dict[str, Any] | None = None
    ) -> str:
        return self._message(system=system, prompt=prompt)
