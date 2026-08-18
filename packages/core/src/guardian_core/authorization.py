"""One place that decides whether a target may be scanned (WP-H1).

Two gates existed and they disagreed. The discovery gate matched `Authorization.authorized_targets`
by domain, netblock and host. The scan gate matched `Authorization.asset_id` and nothing else. Both
are correct on their own terms; together they meant a **domain a customer had proved they own could
not authorize a scan of that domain's asset** — WP-F1 issues an authorization with
`authorized_targets=[{"type": "domain", …}]` and no `asset_id`, so the scan gate looked straight
past it and skipped every active engine.

That is the gap this module closes, by being the only implementation of the question. Both gates now
ask the same function, and any future gate inherits the same rules:

* **Method decides the plane.** `written_consent` covers an artifact the customer handed over — a
  repository, an image, a manifest — and grants nothing on the network. `active_recon` and
  `ownership_verified` cover sending packets at a host. An artifact scan does not need a network
  authorization; a network scan is never satisfied by an artifact one.
* **Scope is explicit.** An authorization covers the asset it names, or the targets it lists.
  Nothing covers "everything" — an empty target list with no asset grants nothing at all, which is
  the safe reading of a record somebody half-filled in.
* **Time and revocation are absolute.** Outside the window, or revoked, is refused whatever else
  matches.
* **Every refusal has a reason.** "Blocked" in an audit log with no cause is a support ticket; the
  reason names the target and what would have covered it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

# What each method is evidence of. `ownership_verified` is machine-checked (WP-F1) and
# `active_recon` is an operator's recorded engagement scope; both permit touching a host.
# `written_consent` is a customer handing over an artifact, which says nothing about their network.
NETWORK_METHODS = frozenset({"active_recon", "ownership_verified"})
ARTIFACT_METHODS = frozenset({"written_consent", "active_recon", "ownership_verified"})

# Asset kinds whose scanning means sending packets at something.
NETWORK_ASSET_KINDS = frozenset({"web", "api", "host", "netblock", "cloud_account"})


@dataclass(frozen=True)
class AuthorizationView:
    """An authorization as the evaluator sees it. Only fields the database already carries."""

    id: str
    method: str
    asset_id: str | None
    customer_id: str | None
    targets: tuple[dict, ...]
    valid_from: dt.datetime | None
    valid_until: dt.datetime | None
    revoked_at: dt.datetime | None = None

    def active(self, now: dt.datetime) -> bool:
        if self.revoked_at is not None:
            return False
        if self.valid_from is not None and _aware(self.valid_from) > now:
            return False
        return not (self.valid_until is not None and _aware(self.valid_until) < now)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    authorization_id: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def host_of(identifier: str) -> str:
    """The host inside an asset identifier: a URL, a `host:port`, or a bare name."""
    text = (identifier or "").strip()
    if not text:
        return ""
    if "://" in text:
        return (urlparse(text).hostname or "").lower().rstrip(".")
    if text.startswith("["):  # [ipv6]:port
        return text[1:].split("]")[0].lower()
    host, separator, port = text.rpartition(":")
    if separator and port.isdigit():
        return host.lower().rstrip(".")
    return text.lower().rstrip(".")


def target_matches(targets, value: str) -> bool:  # noqa: ANN001
    """Whether `value` (a host, an IP, or a bare name) falls inside any authorized target.

    Domain matching is downward only: an authorization for `example.com` covers
    `app.example.com`, and one for `app.example.com` does not cover the apex. Whoever controls a
    zone can create any name inside it; controlling one host in a zone is not controlling the zone.
    """
    host = (value or "").lower().rstrip(".")
    if not host:
        return False
    address = None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass

    for entry in targets or ():
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type", "")).lower()
        target = str(entry.get("value", "")).lower().rstrip(".")
        if not target:
            continue
        if kind == "domain":
            if host == target or host.endswith("." + target):
                return True
        elif kind == "netblock" and address is not None:
            try:
                if address in ipaddress.ip_network(target, strict=False):
                    return True
            except ValueError:
                continue
        elif kind in ("ip", "host") and host == target:
            return True
    return False


def authorizes(
    authorization: AuthorizationView,
    *,
    asset_id: str | None,
    asset_identifier: str,
    needs_network: bool,
    now: dt.datetime,
) -> bool:
    """Whether one authorization covers this target."""
    if not authorization.active(now):
        return False
    allowed_methods = NETWORK_METHODS if needs_network else ARTIFACT_METHODS
    if authorization.method not in allowed_methods:
        return False
    if authorization.asset_id and asset_id and str(authorization.asset_id) == str(asset_id):
        return True
    if authorization.targets:
        return target_matches(authorization.targets, host_of(asset_identifier))
    # No asset, no targets: a record somebody half-filled in. It grants nothing, which is the safe
    # reading — the alternative is a blank authorization covering the estate.
    return False


def decide(
    authorizations: list[AuthorizationView],
    *,
    asset_id: str | None,
    asset_identifier: str,
    asset_kind: str,
    engine: str,
    engine_touches_network: bool | None = None,
    now: dt.datetime | None = None,
) -> Decision:
    """The gate. Returns whether this engine may run against this asset, and why not if not.

    `engine_touches_network` lets a caller be explicit; otherwise it is inferred from the asset
    kind, because scanning a web or cloud asset means reaching it and scanning a repository does
    not.
    """
    now = now or dt.datetime.now(dt.UTC)
    needs_network = (engine_touches_network if engine_touches_network is not None
                     else asset_kind in NETWORK_ASSET_KINDS)

    for authorization in authorizations:
        if authorizes(authorization, asset_id=asset_id, asset_identifier=asset_identifier,
                      needs_network=needs_network, now=now):
            return Decision(True, f"authorized by {authorization.method}", authorization.id)

    # The reason distinguishes the three ways this fails, because they need different fixes and
    # "blocked" alone is a support ticket.
    expired = [a for a in authorizations if not a.active(now)]
    wrong_plane = [
        a for a in authorizations
        if a.active(now) and needs_network and a.method not in NETWORK_METHODS
        and (str(a.asset_id or "") == str(asset_id or "") or
             target_matches(a.targets, host_of(asset_identifier)))
    ]
    host = host_of(asset_identifier) or asset_identifier

    if wrong_plane:
        return Decision(
            False,
            f"{engine} needs permission to send traffic to {host}; the authorization on file is "
            f"{wrong_plane[0].method}, which covers an artifact the customer provided rather than "
            "their network",
        )
    if expired and not [a for a in authorizations if a.active(now)]:
        return Decision(
            False,
            f"the authorization covering {host} is expired or revoked",
        )
    return Decision(
        False,
        f"no authorization covers {host}"
        + (" — prove ownership of the domain or record an engagement scope"
           if needs_network else " — record the customer's consent for this artifact"),
    )


__all__ = [
    "ARTIFACT_METHODS",
    "NETWORK_ASSET_KINDS",
    "NETWORK_METHODS",
    "AuthorizationView",
    "Decision",
    "authorizes",
    "decide",
    "host_of",
    "target_matches",
]
