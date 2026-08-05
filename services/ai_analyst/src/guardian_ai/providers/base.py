"""The LLM provider port. Keeps the platform vendor-neutral (ADR-006)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class LLMError(Exception):
    """Raised when a provider cannot produce a usable result (incl. safety refusals)."""


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal contract the analyst needs.

    `context` carries the structured grounding data (the finding, KB entries, weakness). A real LLM
    provider ignores it — the same data is already serialized into `prompt` — while the
    deterministic stub uses it to compose grounded output offline. Either way the context is DATA,
    never instructions (prompt-injection defense, doc 06 §3).
    """

    name: str

    def complete_json(
        self, *, system: str, prompt: str, schema: dict, context: dict[str, Any] | None = None
    ) -> dict:
        """Return a JSON object validated against `schema` (structured output)."""
        ...

    def complete_text(
        self, *, system: str, prompt: str, context: dict[str, Any] | None = None
    ) -> str:
        """Return free-form text (used by the grounded chat interface)."""
        ...
