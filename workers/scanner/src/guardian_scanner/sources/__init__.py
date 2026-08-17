"""Live external data sources for discovery.

A *source* is the hardened network path to one third-party data provider (CT logs, DNS). It is
deliberately separate from the providers that consume it, because the security review that matters
here — SSRF confinement, redirect refusal, public-address enforcement, response bounding — must
exist in exactly one place. Two providers reaching the same third party through two copies of that
logic is two things to keep correct forever.

Every source in this package obeys the same contract:

  * the endpoint is a code-owned constant; a caller can never redirect it;
  * caller input rides only where it cannot change the destination;
  * a non-public resolved address is refused, not warned about;
  * failure returns an explicit "we could not observe this" result, never an exception that a
    caller might mistake for "there is nothing there".

That last rule is the one that keeps false findings out of the product: absence of evidence and
evidence of absence are different values, and only the second may become a finding.
"""

from __future__ import annotations

__all__ = ["ct", "dns"]
