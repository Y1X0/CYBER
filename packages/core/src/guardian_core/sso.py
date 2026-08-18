"""Single sign-on: verifying an identity provider's token (WP-G1).

An enterprise customer will not create passwords in a vendor's console, so SSO is the difference
between a product they can buy and one they cannot. The security of it lives almost entirely in one
function — the one that decides whether a token really came from their identity provider — and
almost every real-world break of that function is one of a small number of mistakes:

* **Algorithm confusion.** The token names its own algorithm. A verifier that trusts that field will
  accept `alg: none`, or accept an HS256 token signed with the provider's *public* key as the HMAC
  secret. The allowed algorithms are fixed here and the header's claim is never consulted.
* **A missing audience check.** A token issued for a different application by the same provider is
  a perfectly valid token; without an audience check it is also a valid login here.
* **A missing issuer check.** Any provider's token verifies against that provider's keys.
* **Trusting an unverified email.** `email` is a claim; `email_verified` is the one that says the
  provider checked it. Matching a user by an unverified email lets somebody claim an account by
  registering the address at a provider that does not check.

Provisioning has one rule of its own: a new user is created only when their email domain belongs to
the tenant, and never with a role that can administer anything. An SSO group can promote somebody
to an analyst; making an owner stays a deliberate act by an existing owner.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import jwt
from jwt import PyJWKClient  # noqa: F401 - re-exported for callers that fetch a live JWKS

# Asymmetric only. An HMAC algorithm here is the algorithm-confusion attack: the "secret" would be
# the provider's published public key, which the attacker also has.
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")

# Roles SSO may assign. `owner` and `admin` are deliberately absent: an identity provider group is
# managed by whoever administers that provider, and letting a group name mint a Guardian owner moves
# the trust boundary somewhere the customer may not have thought about.
ASSIGNABLE_ROLES = ("analyst", "reviewer", "pentester")
DEFAULT_ROLE = "analyst"

LEEWAY_SECONDS = 60


class SsoError(Exception):
    """The token is not one this tenant accepts. The message says which rule it failed."""


@dataclass(frozen=True)
class SsoConfig:
    """What one tenant's identity provider is allowed to assert."""

    issuer: str
    audience: str
    # Email domains this tenant owns. A user is provisioned only from one of these — the same
    # reasoning as WP-F1's domain proof: a claim about a domain is worth exactly what the
    # proof behind it is.
    allowed_domains: tuple[str, ...] = ()
    # IdP group → Guardian role. Unmapped groups grant the default role, never more.
    group_roles: dict = field(default_factory=dict)
    default_role: str = DEFAULT_ROLE


@dataclass(frozen=True)
class Principal:
    """Who the provider says this is."""

    subject: str
    email: str
    name: str = ""
    groups: tuple[str, ...] = ()
    email_verified: bool = False


def verify_id_token(token: str, *, key, config: SsoConfig,  # noqa: ANN001
                    now: dt.datetime | None = None) -> Principal:
    """Verify an OIDC id token and return who it is for.

    `key` is the provider's public key (or a JWKS-resolved key). Everything the token says about
    itself — including which algorithm to use — is ignored in favour of what this tenant configured.
    """
    del now  # PyJWT reads the clock itself; the parameter exists for callers that log it
    try:
        claims = jwt.decode(
            token,
            key=key,
            # Fixed, not read from the token's header. This single argument is what prevents both
            # `alg: none` and HMAC confusion.
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=config.audience,
            issuer=config.issuer,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "sub"],
                     "verify_signature": True, "verify_exp": True, "verify_aud": True,
                     "verify_iss": True},
        )
    except jwt.ExpiredSignatureError as exc:
        raise SsoError("the identity token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise SsoError("the identity token was issued for a different application") from exc
    except jwt.InvalidIssuerError as exc:
        raise SsoError("the identity token came from a different issuer") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise SsoError(f"the identity token is missing a required claim: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise SsoError(f"the identity token did not verify: {type(exc).__name__}") from exc

    email = str(claims.get("email") or "").strip().lower()
    if not email:
        raise SsoError("the identity token carries no email address")
    if claims.get("email_verified") is not True:
        # A claim the provider did not check is a claim anybody can make by registering the address
        # somewhere that does not check it.
        raise SsoError("the identity provider did not verify this email address")

    groups = claims.get("groups") or claims.get("roles") or []
    if isinstance(groups, str):
        groups = [groups]

    return Principal(
        subject=str(claims["sub"]),
        email=email,
        name=str(claims.get("name") or claims.get("preferred_username") or ""),
        groups=tuple(str(g) for g in groups),
        email_verified=True,
    )


def domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].strip().lower() if "@" in email else ""


def may_provision(principal: Principal, config: SsoConfig) -> bool:
    """Whether a user may be created for this principal.

    Only from a domain the tenant declared. Without it, anyone whose provider will issue a token for
    this application's audience gets an account — which is the entire access-control decision handed
    to whoever configures the IdP.
    """
    if not config.allowed_domains:
        return False
    return domain_of(principal.email) in {d.lower() for d in config.allowed_domains}


def role_for(principal: Principal, config: SsoConfig) -> str:
    """The Guardian role this principal gets.

    Never above what SSO may assign: a group mapped to `owner` in a configuration file is capped
    here, because promoting somebody to owner should be an act by an existing owner rather than a
    consequence of a group membership in a directory Guardian does not control.
    """
    for group in principal.groups:
        mapped = str(config.group_roles.get(group) or "").lower()
        if mapped in ASSIGNABLE_ROLES:
            return mapped
    default = (config.default_role or DEFAULT_ROLE).lower()
    return default if default in ASSIGNABLE_ROLES else DEFAULT_ROLE


__all__ = [
    "ALLOWED_ALGORITHMS",
    "ASSIGNABLE_ROLES",
    "DEFAULT_ROLE",
    "Principal",
    "SsoConfig",
    "SsoError",
    "domain_of",
    "may_provision",
    "role_for",
    "verify_id_token",
]
