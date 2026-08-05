"""guardian_ai — AI Security Analyst.

Retrieval-grounded explanation, remediation, executive summaries, and a grounded chat interface.
The AI augments deterministic results (doc 01 §6): it explains and prioritizes, it never originates
severities or invents findings. All AI access is behind the `LLMProvider` port; the default is a
deterministic offline stub so the platform works with no API key.
"""

from guardian_ai.providers import get_provider
from guardian_ai.security_score import security_score

__all__ = ["get_provider", "security_score"]
