"""OpenAI-compatible chat provider — bring any compatible LLM, including free ones (ADR-006).

The analyst is vendor-neutral. This provider speaks the OpenAI `/chat/completions` wire format,
which is also what Google Gemini's OpenAI endpoint, Groq, OpenRouter, Together and most local
servers expose — so a *free* LLM becomes a first-class option and the platform never requires a
paid key to explain a finding. Configure `GUARDIAN_AI_API_KEY` + `GUARDIAN_AI_BASE_URL`
(+ `GUARDIAN_AI_MODEL`).

The same safety rules as every provider apply: scanned content arrives inside the prompt as
untrusted DATA, never instructions (prompt-injection defense, doc 06 §3), and the analyst's guard
still runs on whatever comes back. Not every free model honours `response_format`, so JSON mode is
requested but the result is also parsed defensively (fences stripped, outermost object extracted)
rather than trusted to be clean.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from guardian_common.config import get_settings
from guardian_common.logging import get_logger

from guardian_ai.providers.base import LLMError

log = get_logger("guardian.ai")

_TIMEOUT = 60.0
# Status codes that mean "the request shape was rejected" — worth one retry without response_format,
# which some otherwise-fine models/endpoints do not accept.
_SHAPE_REJECTED = frozenset({400, 404, 422, 501})


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self) -> None:
        settings = get_settings()
        if not settings.ai_api_key:
            raise LLMError("GUARDIAN_AI_API_KEY is not set")
        if not settings.ai_base_url:
            raise LLMError("GUARDIAN_AI_BASE_URL is not set")
        self._key = settings.ai_api_key
        self._base = settings.ai_base_url.rstrip("/")
        self._model = settings.ai_model
        self._max_tokens = settings.ai_max_tokens

    def _post(self, payload: dict[str, Any]) -> httpx.Response:
        try:
            return httpx.post(
                f"{self._base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from exc

    def _chat(self, *, system: str, prompt: str, json_mode: bool) -> str:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self._max_tokens,
            "temperature": 0,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        resp = self._post(payload)
        # Some providers/models reject response_format outright. Retry once without it rather than
        # fail — a JSON answer parsed from plain text is better than no answer at all. Build a fresh
        # payload rather than mutating the one already sent.
        if json_mode and resp.status_code in _SHAPE_REJECTED:
            retry = {k: v for k, v in payload.items() if k != "response_format"}
            resp = self._post(retry)
        if resp.status_code >= 400:
            body = (resp.text or "")[:200]
            raise LLMError(f"LLM returned HTTP {resp.status_code}: {body}")
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("LLM returned an unexpected response shape") from exc
        return content or ""

    def complete_json(
        self, *, system: str, prompt: str, schema: dict, context: dict[str, Any] | None = None
    ) -> dict:
        # Belt and suspenders alongside JSON mode: name the exact shape in the system prompt, since
        # a free model may ignore response_format.
        grounded_system = (
            f"{system}\n\nReturn ONLY a single JSON object that conforms to this JSON schema. No "
            f"prose, no explanation, no markdown code fences:\n{json.dumps(schema)}"
        )
        return _parse_json(self._chat(system=grounded_system, prompt=prompt, json_mode=True))

    def complete_text(
        self, *, system: str, prompt: str, context: dict[str, Any] | None = None
    ) -> str:
        return self._chat(system=system, prompt=prompt, json_mode=False)


def _parse_json(text: str) -> dict:
    """Parse a model's JSON reply defensively: strip a ```json fence, then fall back to the
    outermost `{ ... }` object. A free model that pads its JSON must not fail the whole analysis."""
    s = (text or "").strip()
    if s.startswith("```"):
        inner = s.split("```")
        # ```json\n{...}\n``` -> the middle segment is the body
        s = (inner[1] if len(inner) >= 2 else s).strip()
        if s[:4].lower() == "json":
            s = s[4:].strip()
    try:
        parsed = json.loads(s)
    except ValueError:
        start, end = s.find("{"), s.rfind("}")
        if start == -1 or end <= start:
            raise LLMError("LLM did not return valid JSON") from None
        try:
            parsed = json.loads(s[start:end + 1])
        except ValueError as exc:
            raise LLMError("LLM did not return valid JSON") from exc
    if not isinstance(parsed, dict):
        raise LLMError("LLM returned JSON that was not an object")
    return parsed
