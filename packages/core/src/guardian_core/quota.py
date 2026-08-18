"""What one tenant may consume before it becomes everyone else's problem (WP-G2).

This platform is multi-tenant and every expensive thing in it is triggered by an authenticated
request: a scan queues work on a shared worker fleet, a report renders every finding it can find, a
list endpoint returns every row a tenant owns. None of that was bounded. The only rate limit in the
codebase guarded the login endpoint, which protects the password hash and nothing else — a CI key
with `scans:write` could queue ten thousand scans in a minute and every other tenant's work would
sit behind them.

Three limits, and the reason each exists:

* **requests per minute.** Bounds the API against a runaway client — a retry loop with no backoff
  is far more common than an attacker, and it does the same damage.
* **concurrent scans.** Bounds the *queue*, which is the shared resource. WP-H3 caps concurrent
  scans per asset in the worker, which stops one host being hammered; it does nothing about ten
  thousand scans of ten thousand assets. Admission control belongs at the point where the work is
  accepted, because a queue you can always add to is not a queue with a limit.
* **page size.** Bounds a single response. An estate with 200,000 discovered assets returned all of
  them, as one JSON array, built entirely in memory first.

A refusal here says which limit was hit and when to retry. A 429 with no `Retry-After` teaches
clients to retry immediately, which is how a rate limit becomes an amplifier.

The limits are platform defaults that a tenant may override in `tenants.settings["quota"]`. A
malformed override falls back to the platform default and says so, rather than being read as
"unlimited": the two failure directions are not symmetric, and the one where a typo removes a limit
is the one that takes the platform down.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

# A page nobody asked to be this large. Chosen to be big enough that a console screen is one
# request and small enough that a response is bounded.
DEFAULT_PAGE_SIZE = 50
HARD_MAX_PAGE_SIZE = 500


@dataclass(frozen=True)
class Quota:
    """What a tenant may consume. Every field is a ceiling, never a reservation."""

    requests_per_minute: int = 600
    # Queued or running at once. Ten is a lot of concurrent scanning for one customer estate and
    # nowhere near enough to starve a fleet.
    concurrent_scans: int = 10
    max_page_size: int = 200
    # A report rendering every finding of a 50,000-finding scan is a memory event, and a PDF nobody
    # reads. Bounded, and the document says it was bounded — see `truncation_note`.
    max_report_findings: int = 2000

    def with_overrides(self, raw: object) -> tuple[Quota, list[str]]:
        """Apply a tenant's overrides, reporting anything that could not be read.

        An unreadable override is not permission to ignore the limit: the platform default applies
        and the reason is returned, so a typo shows up as a refusal a customer can ask about rather
        than as a limit that quietly stopped existing.
        """
        if raw is None:
            return self, []
        if not isinstance(raw, dict):
            return self, ["the quota override is not an object; platform defaults apply"]

        values: dict[str, int] = {}
        problems: list[str] = []
        for field in ("requests_per_minute", "concurrent_scans", "max_page_size",
                      "max_report_findings"):
            if field not in raw:
                continue
            value = raw[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                problems.append(
                    f"quota override {field}={value!r} is not a positive integer; "
                    f"the platform default of {getattr(self, field)} applies"
                )
                continue
            values[field] = value

        quota = replace(self, **values) if values else self
        if quota.max_page_size > HARD_MAX_PAGE_SIZE:
            problems.append(
                f"quota override max_page_size={quota.max_page_size} exceeds the platform ceiling "
                f"of {HARD_MAX_PAGE_SIZE}; the ceiling applies"
            )
            quota = replace(quota, max_page_size=HARD_MAX_PAGE_SIZE)
        return quota, problems


DEFAULT = Quota()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    retry_after: int = 0


class InvalidPageSize(ValueError):
    """The caller asked for a page size that is not a page size."""


def page_size(requested: int | None, *, maximum: int, default: int = DEFAULT_PAGE_SIZE) -> int:
    """Clamp a requested page size, refusing values that are not requests for a page.

    `limit=0` and `limit=-1` are refused rather than clamped. Both are idioms for "all of them",
    and answering them with a default page is how a client ends up silently processing the first
    fifty of nine thousand rows and reporting a clean result.
    """
    if requested is None:
        return min(default, maximum)
    if requested < 1:
        raise InvalidPageSize(
            f"limit must be at least 1; {requested} is not a page size. There is no way to request "
            f"every row — page through them with the cursor."
        )
    return min(requested, maximum)


def admit_scan(*, active: int, limit: int) -> Decision:
    """Whether one more scan may be queued.

    Refused rather than queued-and-deferred: a scan accepted into a queue it will not leave for an
    hour looks, to the customer who asked for it, exactly like a scan that is running.
    """
    if limit <= 0:
        return Decision(False, "scan admission is disabled for this tenant")
    if active >= limit:
        return Decision(
            False,
            f"{active} scans are already queued or running and this tenant's limit is {limit}; "
            f"wait for one to finish, or ask for the limit to be raised",
            retry_after=60,
        )
    return Decision(True)


def rate_refusal(retry_after: float, *, limit: int) -> Decision:
    """The refusal a rate-limited caller gets. It always carries a retry time."""
    return Decision(
        False,
        f"this tenant is over its limit of {limit} requests per minute",
        # Rounded up: a client told to wait 0 seconds retries immediately, which is how a rate
        # limit turns into an amplifier.
        retry_after=max(1, int(retry_after) + (1 if retry_after % 1 else 0)),
    )


def truncation_note(*, shown: int, total: int, subject: str = "findings") -> str:
    """What a bounded result has to say about what it left out.

    A report that silently drops half its findings is more dangerous than one that refuses to
    render: the reader has no way to know the difference between "nothing else was found" and
    "nothing else fitted".
    """
    if shown >= total:
        return ""
    return (
        f"This document shows {shown:,} of {total:,} {subject}, ordered by risk. "
        f"{total - shown:,} more are recorded and available through the API — they are omitted "
        f"here, not absent."
    )


__all__ = [
    "DEFAULT",
    "DEFAULT_PAGE_SIZE",
    "HARD_MAX_PAGE_SIZE",
    "Decision",
    "InvalidPageSize",
    "Quota",
    "admit_scan",
    "page_size",
    "rate_refusal",
    "truncation_note",
]
