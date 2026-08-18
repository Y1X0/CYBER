"""Reading an IAM policy document (WP-D8).

An IAM policy is not a list of strings; it is a document with statements, effects, wildcards,
`NotAction`, `NotResource`, principals and conditions, and the interactions between those are where
the over-permission hides. `"Action": "*"` is obvious. `"NotAction": "iam:*"` grants everything
except IAM and reads, at a glance, like a restriction. `iam:PassRole` on `"Resource": "*"` grants
nothing by itself and lets the holder attach any role in the account to a service they control.

Deny is honoured: a statement that allows `s3:*` next to one that denies it is not a finding, and
reporting it as one is how a scanner loses an operator's trust in a single review.

Pure functions over parsed JSON. No AWS SDK, no network.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

# Actions that let a principal increase its own privileges. Holding any of these with a wildcard
# resource is equivalent to holding whatever they can reach — which, for most of them, is the
# account. Drawn from the documented IAM privilege-escalation paths.
ESCALATION_ACTIONS: frozenset[str] = frozenset({
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:updateassumerolepolicy",
    "iam:passrole",
    "sts:assumerole",
    "lambda:createfunction",
    "lambda:updatefunctioncode",
    "glue:updatedevendpoint",
    "cloudformation:createstack",
    "datapipeline:createpipeline",
    "ec2:runinstances",
})

# Wildcard principals: "anyone on the internet", with or without an AWS account.
_ANY_PRINCIPAL = {"*", "arn:aws:iam::*:root"}


@dataclass(frozen=True)
class Statement:
    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    principals: tuple[str, ...] = ()
    conditions: dict = field(default_factory=dict)
    sid: str = ""

    @property
    def allows(self) -> bool:
        return self.effect.lower() == "allow"


def _as_tuple(value) -> tuple[str, ...]:  # noqa: ANN001
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def _principals(value) -> tuple[str, ...]:  # noqa: ANN001
    """Principals, flattened.

    `"Principal": "*"` and `"Principal": {"AWS": "*"}` mean the same thing and appear in roughly
    equal numbers in the wild.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    if isinstance(value, dict):
        out: list[str] = []
        for values in value.values():
            out.extend(_as_tuple(values))
        return tuple(out)
    return ()


def parse(document) -> list[Statement]:  # noqa: ANN001
    """Statements out of a policy document. Malformed input yields nothing rather than raising."""
    if isinstance(document, str):
        import json  # noqa: PLC0415
        from urllib.parse import unquote  # noqa: PLC0415

        text = document.strip()
        # `get_role`/`get_account_authorization_details` return URL-encoded documents.
        if text.startswith("%7B"):
            text = unquote(text)
        try:
            document = json.loads(text)
        except ValueError:
            return []
    if not isinstance(document, dict):
        return []

    raw = document.get("Statement")
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    statements: list[Statement] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        statements.append(Statement(
            effect=str(item.get("Effect") or "Allow"),
            actions=_as_tuple(item.get("Action")),
            not_actions=_as_tuple(item.get("NotAction")),
            resources=_as_tuple(item.get("Resource")),
            not_resources=_as_tuple(item.get("NotResource")),
            principals=_principals(item.get("Principal")),
            conditions=item.get("Condition") if isinstance(item.get("Condition"), dict) else {},
            sid=str(item.get("Sid") or ""),
        ))
    return statements


def matches(pattern: str, value: str) -> bool:
    """IAM wildcard matching: `*` and `?`, case-insensitive."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def statement_allows(statement: Statement, action: str, resource: str = "*") -> bool:
    """Whether one Allow statement covers this action on this resource."""
    if not statement.allows:
        return False
    if statement.not_actions:
        # `NotAction` grants everything *except* the listed actions — the inversion that reads like
        # a restriction and is the opposite of one.
        if any(matches(pattern, action) for pattern in statement.not_actions):
            return False
    elif not any(matches(pattern, action) for pattern in statement.actions):
        return False

    if statement.not_resources:
        return not any(matches(pattern, resource) for pattern in statement.not_resources)
    if not statement.resources:
        # A resource-less statement in an identity policy is malformed; treat it as not granting
        # rather than as granting everything.
        return False
    return any(matches(pattern, resource) for pattern in statement.resources)


def denies(statements: list[Statement], action: str, resource: str = "*") -> bool:
    """Whether an explicit Deny covers this action. Deny always wins in IAM, and here too."""
    for statement in statements:
        if statement.allows:
            continue
        action_hit = (
            not any(matches(p, action) for p in statement.not_actions)
            if statement.not_actions
            else any(matches(p, action) for p in statement.actions)
        )
        if not action_hit:
            continue
        if statement.resources and not any(matches(p, resource) for p in statement.resources):
            continue
        return True
    return False


def grants(statements: list[Statement], action: str, resource: str = "*") -> bool:
    """Whether the policy, as a whole, grants this action — Deny beating Allow."""
    if denies(statements, action, resource):
        return False
    return any(statement_allows(s, action, resource) for s in statements)


def is_admin(statements: list[Statement]) -> bool:
    """Full control of the account, however it is spelled."""
    for statement in statements:
        if not statement.allows:
            continue
        every_action = "*" in statement.actions or (
            bool(statement.not_actions) and not statement.actions
        )
        every_resource = "*" in statement.resources or (
            bool(statement.not_resources) and not statement.resources
        )
        if every_action and every_resource and not denies(statements, "iam:*", "*"):
            return True
    return False


def escalation_paths(statements: list[Statement]) -> list[str]:
    """Actions in the policy that let the holder grant itself more.

    Only counted when the resource is unconstrained: `iam:PassRole` on one specific role is how a
    correctly-scoped deployment policy is written, and reporting that would report every correct
    policy.
    """
    found: set[str] = set()
    for action in ESCALATION_ACTIONS:
        for statement in statements:
            if not statement_allows(statement, action, "*"):
                continue
            if denies(statements, action, "*"):
                continue
            if "*" not in statement.resources and not statement.not_resources:
                continue
            found.add(action)
    return sorted(found)


def public_principals(statements: list[Statement]) -> list[Statement]:
    """Statements that allow a wildcard principal — i.e. anyone.

    A `Condition` does not clear the statement, but it changes what it means: `aws:SourceIp` or
    `aws:PrincipalOrgID` narrows "anyone" to "anyone from there", which is a decision an operator
    may well have made deliberately. The caller reports the difference rather than this function
    guessing.
    """
    return [
        s for s in statements
        if s.allows and any(p in _ANY_PRINCIPAL or p == "*" for p in s.principals)
    ]


def has_meaningful_condition(statement: Statement) -> bool:
    """Whether a condition actually narrows who the statement applies to."""
    narrowing = {
        "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:principalorgid",
        "aws:principalaccount", "aws:principalarn", "aws:sourcearn", "aws:sourceaccount",
        "aws:sourceowner", "aws:username", "aws:userid",
    }
    for operands in (statement.conditions or {}).values():
        if not isinstance(operands, dict):
            continue
        for key in operands:
            if str(key).lower() in narrowing:
                return True
    return False


__all__ = [
    "ESCALATION_ACTIONS",
    "Statement",
    "denies",
    "escalation_paths",
    "grants",
    "has_meaningful_condition",
    "is_admin",
    "matches",
    "parse",
    "public_principals",
    "statement_allows",
]
