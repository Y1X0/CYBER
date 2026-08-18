"""The controls that keep an authorized scan from becoming somebody's incident (WP-H3).

Authorization (WP-H1) answers *may* we scan this. These answer *now*, *how hard*, and *at all* — the
questions whose wrong answers put the customer's production estate on the wrong end of a scanner
they consented to.

Four controls, each of which exists because of a specific way this goes wrong in the field:

* **Blackout windows.** A customer's peak trading hours, a change freeze, a board demo. A scan that
  starts then is not a security event, it is an outage with a security team's name on it. Scans are
  *deferred*, never silently skipped — a skipped scan looks like a clean one.
* **Concurrency.** Every engine has its own budget, and nothing stopped five scans hitting the same
  host at once. Budgets that only hold individually are not budgets.
* **Intensity.** A profile the customer sets, capping requests and rate. The default is the
  conservative one, because the setting somebody never touches should be the safe one.
* **The kill switch.** Emergency stop, per customer or platform-wide, and **fail closed**: if the
  switch cannot be read, active scanning stops. A stop button that only works when everything else
  is working is not a stop button.

All pure. The caller supplies the clock and the current state; nothing here reads a database or a
socket, so every rule is testable at the boundary where it is actually decided.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

# Intensity profiles: (max requests per scan, requests per second, max concurrent targets).
# `safe` is the default and is deliberately slow — the customer who never opens the settings page
# should get the profile that cannot hurt them.
PROFILES: dict[str, dict] = {
    "safe": {"max_requests": 150, "rate_per_second": 2.0, "concurrency": 2},
    "standard": {"max_requests": 400, "rate_per_second": 8.0, "concurrency": 4},
    "thorough": {"max_requests": 1500, "rate_per_second": 15.0, "concurrency": 8},
}
DEFAULT_PROFILE = "safe"

# One active scan per asset at a time. Two scanners on one host produce twice the traffic the
# customer agreed to and findings that race each other.
DEFAULT_MAX_CONCURRENT_SCANS_PER_ASSET = 1

_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class SafeScanRefusal(Exception):
    """Active scanning must not proceed. The message is what the operator will read."""


@dataclass(frozen=True)
class Window:
    """A recurring blackout, in the customer's own timezone offset.

    Stored as an offset rather than a timezone name deliberately: a name needs a database that has
    to be right about a customer's DST, and being wrong by an hour twice a year is being wrong
    during exactly the window they cared about.
    """

    days: tuple[str, ...]
    start_hour: int
    end_hour: int
    utc_offset_hours: float = 0.0
    label: str = ""

    def contains(self, moment: dt.datetime) -> bool:
        local = moment.astimezone(dt.UTC) + dt.timedelta(hours=self.utc_offset_hours)
        if self.days and _DAYS[local.weekday()] not in {d.lower()[:3] for d in self.days}:
            return False
        hour = local.hour + local.minute / 60
        if self.start_hour <= self.end_hour:
            return self.start_hour <= hour < self.end_hour
        # A window that wraps midnight (22:00–06:00) is two intervals, and the naive comparison
        # matches neither of them.
        return hour >= self.start_hour or hour < self.end_hour


@dataclass(frozen=True)
class Policy:
    """One customer's safe-scanning settings, as read from `Customer.settings`."""

    profile: str = DEFAULT_PROFILE
    windows: tuple[Window, ...] = ()
    paused: bool = False
    pause_reason: str = ""
    max_concurrent_scans_per_asset: int = DEFAULT_MAX_CONCURRENT_SCANS_PER_ASSET

    @property
    def limits(self) -> dict:
        return dict(PROFILES.get(self.profile, PROFILES[DEFAULT_PROFILE]))


def parse_policy(settings: dict | None) -> Policy:
    """Read a policy out of a customer's settings blob.

    Anything unrecognized falls back to the conservative default rather than being ignored: a
    profile name with a typo must not silently become the fastest one.
    """
    raw = (settings or {}).get("safe_scanning") or {}
    profile = str(raw.get("profile") or DEFAULT_PROFILE).lower()
    if profile not in PROFILES:
        profile = DEFAULT_PROFILE

    windows: list[Window] = []
    for entry in raw.get("blackout_windows") or []:
        if not isinstance(entry, dict):
            continue
        try:
            windows.append(Window(
                days=tuple(str(d) for d in (entry.get("days") or ())),
                start_hour=int(entry.get("start_hour", 0)),
                end_hour=int(entry.get("end_hour", 0)),
                utc_offset_hours=float(entry.get("utc_offset_hours", 0)),
                label=str(entry.get("label") or ""),
            ))
        except (TypeError, ValueError):
            # A malformed window is not "no window": it is a window the customer meant to have.
            # Refusing to parse it into silence, the caller is told rather than the entry dropped.
            raise SafeScanRefusal(
                "a blackout window in this customer's settings is malformed; active scanning is "
                "refused until it is corrected rather than run through a window that may exist"
            ) from None

    return Policy(
        profile=profile,
        windows=tuple(windows),
        paused=bool(raw.get("paused")),
        pause_reason=str(raw.get("pause_reason") or ""),
        max_concurrent_scans_per_asset=max(
            1, int(raw.get("max_concurrent_scans_per_asset")
                   or DEFAULT_MAX_CONCURRENT_SCANS_PER_ASSET)),
    )


@dataclass
class Verdict:
    """Whether an active scan may start now, and if not, what to do about it."""

    allowed: bool
    reason: str = ""
    # `defer` means try again later; `refuse` means do not retry without a human.
    action: str = "run"
    retry_after: dt.datetime | None = None
    limits: dict = field(default_factory=dict)


def next_open(windows: tuple[Window, ...], moment: dt.datetime) -> dt.datetime:
    """When the blackout ends. Stepping by the hour is precise enough for a window in hours."""
    probe = moment
    for _ in range(24 * 8):  # a week and a day; a window that never opens is a configuration error
        probe = probe + dt.timedelta(minutes=30)
        if not any(window.contains(probe) for window in windows):
            return probe
    return moment + dt.timedelta(hours=24)


def check(
    policy: Policy,
    *,
    now: dt.datetime,
    active_scans_on_asset: int = 0,
    platform_paused: bool = False,
    switch_readable: bool = True,
) -> Verdict:
    """The safe-scanning gate for one active scan.

    Order matters: the kill switch is evaluated before anything else, because the point of a stop
    button is that nothing else gets a say.
    """
    if not switch_readable:
        # Fail closed. A stop button that only works when the rest of the system is healthy is not
        # a stop button, and this is the state where an operator is most likely to be reaching for
        # it.
        return Verdict(False, "the emergency stop could not be read, so active scanning is "
                              "refused until it can be", action="refuse")
    if platform_paused:
        return Verdict(False, "active scanning is paused platform-wide", action="refuse")
    if policy.paused:
        return Verdict(
            False,
            "active scanning is paused for this customer"
            + (f": {policy.pause_reason}" if policy.pause_reason else ""),
            action="refuse",
        )

    inside = [w for w in policy.windows if w.contains(now)]
    if inside:
        label = inside[0].label or "a blackout window"
        return Verdict(
            False,
            f"the customer is inside {label}; the scan is deferred rather than skipped, because a "
            "skipped scan reads as a clean one",
            action="defer",
            retry_after=next_open(policy.windows, now),
        )

    if active_scans_on_asset >= policy.max_concurrent_scans_per_asset:
        return Verdict(
            False,
            f"{active_scans_on_asset} scan(s) are already running against this asset; a second one "
            "doubles the traffic the customer agreed to",
            action="defer",
            retry_after=now + dt.timedelta(minutes=10),
        )

    return Verdict(True, f"within the {policy.profile} profile", action="run",
                   limits=policy.limits)


__all__ = [
    "DEFAULT_MAX_CONCURRENT_SCANS_PER_ASSET",
    "DEFAULT_PROFILE",
    "PROFILES",
    "Policy",
    "SafeScanRefusal",
    "Verdict",
    "Window",
    "check",
    "next_open",
    "parse_policy",
]
