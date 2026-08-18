"""Go and look for the ownership proof (WP-F1).

`guardian_core.ownership` decides what counts as proof. This performs the lookup and, when the
proof holds, creates the `Authorization` that the active-scanning gate has always required and that
nothing has ever earned honestly.

The egress here follows the same discipline as every other outward request in the platform:
resolved once, refused for a non-public address, and — for the HTTP challenge — **no redirects**,
which is not a hardening detail but the point. If `example.com` redirects to a host the requester
controls, following it would let them publish the token on their own site and be credited with
owning `example.com`.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import uuid

from guardian_common.logging import get_logger
from guardian_core.ownership import (
    DEFAULT_VALIDITY_DAYS,
    HTTP_PATH,
    MAX_ATTEMPTS,
    CheckResult,
    dns_record_name,
    evaluate_dns,
    evaluate_http,
    http_challenge_url,
    normalize_domain,
)
from guardian_db.models import Authorization, DomainVerification
from guardian_db.session import session_scope

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.ownership")

DNS_TIMEOUT = 8.0
HTTP_TIMEOUT = 10.0
MAX_BODY_BYTES = 4_096


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


# ── lookups ───────────────────────────────────────────────────────────────────────────────────────
def lookup_txt(name: str) -> list[str] | None:  # pragma: no cover - network
    """TXT records at `name`, or None when the name does not exist.

    None and `[]` are different answers: "there is no such record" and "there is a record and it is
    empty" lead to the same verdict here, but conflating them in the log would hide a customer who
    published the record on the wrong name.
    """
    try:
        import dns.rdatatype
        import dns.resolver
    except ImportError:
        log.error("dns_library_missing", detail="dnspython is required to verify a TXT challenge")
        return None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    try:
        answer = resolver.resolve(name, dns.rdatatype.TXT)
    except Exception:  # noqa: BLE001 - NXDOMAIN, timeout and SERVFAIL are all "not proven"
        return None
    values: list[str] = []
    for record in answer:
        # A TXT record longer than 255 bytes arrives as several strings that must be joined.
        parts = getattr(record, "strings", None) or []
        if parts:
            values.append(b"".join(parts).decode("utf-8", "replace"))
        else:
            values.append(str(record).strip('"'))
    return values


def _is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_reserved or address.is_unspecified):
            return False
    return bool(infos)


def fetch_challenge(domain: str) -> tuple[int, str, str]:  # pragma: no cover - network
    """(status, body, final_url) for the well-known challenge file. Redirects are not followed."""
    import httpx

    url = http_challenge_url(domain)
    if not _is_public(domain):
        return 0, "", f"refused: {domain} does not resolve to a public address"
    with httpx.Client(follow_redirects=False, timeout=HTTP_TIMEOUT,
                      headers={"user-agent": "guardian-ownership-check"}) as client:
        response = client.get(url)
        if 300 <= response.status_code < 400:
            # Reported as a redirect rather than followed, so `evaluate_http` can refuse it with a
            # reason the customer can act on.
            return response.status_code, "", str(response.headers.get("location", ""))
        return response.status_code, response.text[:MAX_BODY_BYTES], url


# ── the check ─────────────────────────────────────────────────────────────────────────────────────
def check(verification: DomainVerification, *, dns_lookup=None,  # noqa: ANN001
          http_fetch=None) -> CheckResult:
    """One verification attempt.

    The lookups are injectable so the decision is testable without a network, and they are resolved
    at call time rather than bound as defaults — otherwise the task path, which passes neither,
    would hold a reference captured at import and no test could reach it.
    """
    dns_lookup = dns_lookup or lookup_txt
    http_fetch = http_fetch or fetch_challenge
    domain = verification.domain
    if verification.method == "dns_txt":
        records = dns_lookup(dns_record_name(domain))
        return evaluate_dns(verification.token, records)
    if verification.method == "http_file":
        status, body, final_url = http_fetch(domain)
        if status == 0:
            return CheckResult(False, final_url or "the challenge file could not be fetched")
        return evaluate_http(
            verification.token, status=status, body=body, final_url=final_url,
            expected_url=http_challenge_url(domain),
        )
    return CheckResult(False, f"unknown verification method {verification.method!r}")


@celery_app.task(name="guardian.check_domain_verification")
def check_domain_verification(verification_id: str) -> dict:
    """Check one pending verification and, if it holds, grant the authorization."""
    with session_scope() as session:
        verification = session.get(DomainVerification, uuid.UUID(verification_id))
        if verification is None:
            return {"status": "unknown"}

        now = _now()
        if verification.status == "verified":
            return {"status": "verified", "domain": verification.domain}
        if verification.expires_at <= now:
            verification.status = "expired"
            verification.last_error = "the challenge expired before it was satisfied"
            return {"status": "expired", "domain": verification.domain}
        if verification.attempts >= MAX_ATTEMPTS:
            verification.status = "failed"
            verification.last_error = f"gave up after {MAX_ATTEMPTS} attempts"
            return {"status": "failed", "reason": verification.last_error}

        verification.attempts += 1
        verification.last_checked_at = now

        try:
            result = check(verification)
        except Exception as exc:  # noqa: BLE001 - a lookup failure is not a proof
            verification.last_error = f"{type(exc).__name__}: {exc}"[:500]
            log.warning("ownership_check_error", domain=verification.domain,
                        error=verification.last_error)
            return {"status": "pending", "reason": verification.last_error}

        if not result.verified:
            verification.last_error = result.reason[:500]
            log.info("ownership_not_proven", domain=verification.domain, reason=result.reason[:200])
            return {"status": "pending", "reason": result.reason}

        verification.status = "verified"
        verification.verified_at = now
        verification.last_error = None
        authorization = _grant(session, verification, now)
        verification.authorization_id = authorization.id
        log.info("ownership_verified", domain=verification.domain,
                 method=verification.method, authorization=str(authorization.id))
        return {"status": "verified", "domain": verification.domain,
                "authorization_id": str(authorization.id)}


def _grant(session, verification: DomainVerification, now: dt.datetime) -> Authorization:  # noqa: ANN001
    """Create the authorization the proof earns.

    Scoped to the verified domain, which covers its subdomains and nothing above it — whoever
    controls a zone can create any name inside it, but control of one host is not control of the
    zone, and a shared-hosting customer must not be able to claim the apex.
    """
    authorization = Authorization(
        tenant_id=verification.tenant_id,
        customer_id=verification.customer_id,
        asset_id=None,
        scope=f"Ownership of {verification.domain} proved by {verification.method}",
        authorized_targets=[{"type": "domain", "value": verification.domain}],
        method="ownership_verified",
        authorized_by=verification.created_by,
        valid_from=now,
        valid_until=verification.expires_at,
    )
    session.add(authorization)
    session.flush()
    return authorization


def create_verification(
    session, *, tenant_id, customer_id, domain: str, method: str,  # noqa: ANN001
    created_by, validity_days: int = DEFAULT_VALIDITY_DAYS,  # noqa: ANN001
) -> DomainVerification:
    """Issue a challenge. The token is fresh per verification, so one cannot be replayed."""
    from guardian_core.ownership import new_token  # noqa: PLC0415

    if method not in {"dns_txt", "http_file"}:
        raise ValueError(f"unknown verification method: {method!r}")
    if created_by is None:
        # The authorization this can grant is a record of who cleared a target for probing, and
        # `authorizations.authorized_by` is NOT NULL for that reason. Refusing here means the
        # attribution is missing at the point a human can still supply it, rather than the task
        # failing later with the customer told their proof is being checked.
        raise ValueError("create_verification requires created_by: an authorization must name "
                         "the person who requested it")
    normalized = normalize_domain(domain)
    now = _now()
    verification = DomainVerification(
        tenant_id=tenant_id, customer_id=customer_id, domain=normalized, method=method,
        token=new_token(), status="pending", expires_at=now + dt.timedelta(days=validity_days),
        created_by=created_by,
    )
    session.add(verification)
    session.flush()
    return verification


def instructions_for(verification: DomainVerification) -> dict:
    from guardian_core.ownership import instructions  # noqa: PLC0415

    return instructions(verification.domain, verification.method, verification.token)


__all__ = [
    "HTTP_PATH",
    "check",
    "check_domain_verification",
    "create_verification",
    "instructions_for",
]
