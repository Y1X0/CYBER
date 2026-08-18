"""API authorization testing (WP-D10).

The engine that existed read an OpenAPI document and complained about what the document did not
say — no `securitySchemes`, no documented 429, a parameter with no schema. Those are contract
review, not security testing, and they cannot find the vulnerability that sits at the top of the
OWASP API Security list.

**Broken object level authorization** is that vulnerability, and it is invisible to static analysis
by construction. `GET /invoices/{id}` looks identical whether the handler checks that the invoice
belongs to the caller or not; the only way to know is to ask for somebody else's invoice with your
own credentials and see what comes back. The same is true of function-level authorization (can a
normal user call the admin operation?) and of endpoints that are simply unauthenticated despite the
spec claiming otherwise.

So this package does what only a dynamic test can:

* **unauthenticated access** — the operation answers with no credential at all;
* **BOLA** — principal A's credential retrieves principal B's object;
* **BFLA** — a low-privilege credential invokes a privileged operation;
* **excessive data exposure** — the response carries fields no client should receive.

The safety rules are the same as WP-D2's, and one more that matters specifically here: **only object
identifiers the customer supplied** are requested. The scanner does not walk `id+1` through a
production database looking for records that answer, because those records are real people's data
and reading them is the harm, not the proof.
"""

from __future__ import annotations
