"""Dynamic application security testing (WP-D2).

What was here before was a header/cookie/TLS inspector on a single response — worth having, and not
DAST. DAST is the class of finding that only exists when the application is *running*: an injection
that reaches an interpreter, a redirect a user can be sent through, a template that evaluates what a
parameter contains. None of that is visible in source, and none of it was being looked for.

The shape follows WP-D1's precedent. Rather than shipping a heavyweight external scanner and
inheriting its process, licence and privilege footprint, the behaviour is implemented natively:
crawl within scope, discover parameters, and run a catalogue of **safe, evidence-producing** checks
against them.

Three rules constrain every payload in this package, and they are why an active scanner is
defensible at all:

1. **Read-only.** No payload deletes, writes, or changes state. SQL probes are boolean and error
   based, never `DROP` or stacked statements. Command-injection probes echo a marker and do nothing
   else. There is no timing attack, because a payload whose signal is "the server got slower" is a
   payload whose failure mode is a denial of service.
2. **In scope.** Every request is checked against the authorized host before it is made, not after.
3. **Bounded.** Request budget, per-host rate limit, and a wall-clock deadline, all enforced in the
   scanner loop rather than left to the caller.
"""

from __future__ import annotations
