"""DNS as a discovery source — resolution, wildcard detection, and takeover evidence.

Three things live here, and the third is the reason the module exists at all.

**Resolution.** A/AAAA records turn a name into addresses, which is what every downstream stage
(netblock mapping, port discovery, service probing) needs before it can do anything.

**Wildcard detection.** A domain with `*.example.com` answers for every name ever queried. Without
detection, brute-forced and permuted names all "resolve" and the inventory fills with assets that
do not exist. We probe a name nobody would register and remember what it answered; anything
answering identically is an artifact of the wildcard, not a discovery.

**The distinction between not-asked and asked-and-gone.** This is the correctness property. The
previous implementation treated an absent snapshot entry as proof that a name no longer resolves,
and emitted a subdomain-takeover candidate for it — so running discovery with no data produced a
fabricated finding for every host it was given. An unobserved name is `observed=False` and yields
nothing. A takeover candidate requires positive evidence: a CNAME pointing at a name that itself
does not resolve. That is the actual signal, and it is the only thing that earns a finding.
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field

_TIMEOUT = 4.0        # per-query seconds
_LIFETIME = 8.0       # total seconds including retries
_MAX_ANSWERS = 64     # a name answering with more than this is noise, not inventory


@dataclass(frozen=True)
class DnsAnswer:
    """What we know about one name. `observed` is the honest floor: when it is False every other
    field is meaningless and no caller may infer anything from the absence of records."""

    host: str
    observed: bool = False
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname: str | None = None
    nxdomain: bool = False           # authoritative: the name itself does not exist
    cname_dangling: bool = False     # CNAME target does not resolve → takeover candidate
    wildcard: bool = False           # answers match the domain's wildcard → not a real asset
    error: str | None = None

    @property
    def ips(self) -> tuple[str, ...]:
        return self.a + self.aaaa

    @property
    def resolves(self) -> bool:
        return bool(self.ips)

    @property
    def public(self) -> bool:
        """True when at least one address is globally routable — reachable from the internet."""
        return any(is_public_ip(ip) for ip in self.ips)

    @property
    def unresolved(self) -> bool:
        """We looked and the name answers with nothing. Distinct from `observed=False`, which means
        we never asked — that difference is the whole point of this type."""
        return self.observed and not self.resolves

    @property
    def takeover_candidate(self) -> bool:
        """The strong signal: a CNAME whose target authoritatively does not exist. An unresolved
        name with no CNAME is merely absent; an alias pointing at unclaimed infrastructure is a
        name an attacker can register and answer for."""
        return self.observed and self.cname_dangling


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@dataclass
class WildcardProfile:
    """The address set a domain's wildcard answers with, if it has one."""

    domain: str
    present: bool = False
    addresses: frozenset[str] = field(default_factory=frozenset)

    def matches(self, answer: DnsAnswer) -> bool:
        if not self.present or not answer.ips:
            return False
        return frozenset(answer.ips) == self.addresses


def _resolver():  # pragma: no cover - thin construction, exercised through resolve()
    import dns.resolver  # noqa: PLC0415 - local so the module imports without a DNS stack

    r = dns.resolver.Resolver()
    r.timeout = _TIMEOUT
    r.lifetime = _LIFETIME
    return r


def _query(resolver, name: str, rdtype: str):  # noqa: ANN001, ANN202
    """One record type. Returns (values, nxdomain, error) and never raises — a resolver failure is
    an observation problem, not a property of the name."""
    import dns.resolver  # noqa: PLC0415

    try:
        answers = resolver.resolve(name, rdtype)
        return [str(rr).rstrip(".") for rr in answers][:_MAX_ANSWERS], False, None
    except dns.resolver.NXDOMAIN:
        return [], True, None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [], False, None
    except Exception as exc:  # noqa: BLE001 - timeouts, malformed names, resolver config
        return [], False, f"{type(exc).__name__}"


def wildcard_profile(domain: str, *, probe_label: str | None = None) -> WildcardProfile:
    """Learn whether `domain` answers for names that do not exist.

    The probe label is random by default so a domain cannot pre-register it; tests pin it.
    """
    label = probe_label or f"guardian-wildcard-probe-{secrets.token_hex(8)}"
    resolver = _resolver()
    a, _, _ = _query(resolver, f"{label}.{domain}", "A")
    aaaa, _, _ = _query(resolver, f"{label}.{domain}", "AAAA")
    addresses = frozenset(a + aaaa)
    return WildcardProfile(domain=domain, present=bool(addresses), addresses=addresses)


def resolve(host: str, *, wildcard: WildcardProfile | None = None) -> DnsAnswer:
    """Resolve one name. Always returns an answer; never raises."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return DnsAnswer(host=host)

    resolver = _resolver()
    a, a_nx, a_err = _query(resolver, host, "A")
    aaaa, aaaa_nx, _ = _query(resolver, host, "AAAA")
    cnames, _, _ = _query(resolver, host, "CNAME")
    cname = cnames[0].lower() if cnames else None

    # A dangling CNAME is the takeover signal, and it needs its own lookup: the alias exists, the
    # target does not. Only an authoritative NXDOMAIN on the target counts — a timeout does not.
    dangling = False
    if cname and not (a or aaaa):
        t_a, t_nx, _ = _query(resolver, cname, "A")
        t_aaaa, t_nx6, _ = _query(resolver, cname, "AAAA")
        dangling = bool(t_nx or t_nx6) and not (t_a or t_aaaa)

    answer = DnsAnswer(
        host=host,
        observed=True,
        a=tuple(a),
        aaaa=tuple(aaaa),
        cname=cname,
        nxdomain=bool(a_nx and aaaa_nx),
        cname_dangling=dangling,
        error=a_err,
    )
    if wildcard is not None and wildcard.matches(answer):
        # Rebuild rather than mutate: the frozen dataclass is what makes the answer safe to cache.
        answer = DnsAnswer(
            host=answer.host, observed=True, a=answer.a, aaaa=answer.aaaa, cname=answer.cname,
            nxdomain=answer.nxdomain, cname_dangling=answer.cname_dangling, wildcard=True,
            error=answer.error,
        )
    return answer


def answers_from_snapshot(host: str, snapshot: dict | None) -> DnsAnswer:
    """Offline mode. A host absent from the snapshot is UNOBSERVED — not gone.

    This is the function that keeps a missing fixture from becoming a takeover finding.
    """
    host = host.strip().lower().rstrip(".")
    entry = (snapshot or {}).get(host)
    if entry is None:
        return DnsAnswer(host=host, observed=False)
    if isinstance(entry, dict):        # rich fixture: {"a": [...], "cname": "...", ...}
        a = tuple(str(ip) for ip in entry.get("a", []) if is_ip(str(ip)) and ":" not in str(ip))
        aaaa = tuple(str(ip) for ip in entry.get("aaaa", []) if is_ip(str(ip)))
        return DnsAnswer(
            host=host, observed=True, a=a, aaaa=aaaa,
            cname=(str(entry["cname"]).lower() if entry.get("cname") else None),
            nxdomain=bool(entry.get("nxdomain")),
            cname_dangling=bool(entry.get("cname_dangling")),
        )
    if isinstance(entry, list):        # legacy fixture: a bare list of addresses
        ips = [str(ip) for ip in entry if is_ip(str(ip))]
        return DnsAnswer(
            host=host, observed=True,
            a=tuple(ip for ip in ips if ":" not in ip),
            aaaa=tuple(ip for ip in ips if ":" in ip),
            nxdomain=not ips,
        )
    return DnsAnswer(host=host, observed=False)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
