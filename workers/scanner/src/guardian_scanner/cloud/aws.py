"""AWS posture rules over real API shapes (WP-D8).

The input is what `aws <service> <describe|list|get>` actually returns — `Buckets`,
`SecurityGroups`, `UserDetailList`, `DBInstances`, `trailList` — so a collector is a script that
calls the API and writes the responses down, and the rules below do the judging. That split is the
point: the previous engine took a snapshot carrying `"public": true`, which meant whoever produced
the snapshot had already answered the only interesting question.

Each rule states what an attacker gets, because "CIS 2.1.5" is not a reason and nobody remediates a
control number.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field

from guardian_scanner.cloud import policy as pol

# Ports whose exposure to the internet is a finding on its own. Everything else open to 0.0.0.0/0
# is reported at a lower severity: a public web server is a public web server.
ADMIN_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API",
    2376: "Docker API (TLS)", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5984: "CouchDB",
    6379: "Redis", 7001: "WebLogic", 8020: "Hadoop", 9200: "Elasticsearch", 11211: "memcached",
    27017: "MongoDB",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ACCESS_KEY_MAX_AGE_DAYS = 90


@dataclass(frozen=True)
class Issue:
    rule: str
    title: str
    severity: str
    cwe: str
    control: str
    detail: str
    remediation: str
    resource: str
    evidence: dict = field(default_factory=dict)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _age_days(value, now: dt.datetime) -> float | None:  # noqa: ANN001
    if not value:
        return None
    if isinstance(value, dt.datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    else:
        try:
            stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=dt.UTC)
    return (now - stamp).total_seconds() / 86400


# ── S3 ────────────────────────────────────────────────────────────────────────────────────────────
def s3_issues(bucket: dict) -> Iterator[Issue]:
    """One bucket, from `list_buckets` plus the per-bucket calls a collector makes alongside it.

    Whether a bucket is public is decided from three sources that routinely disagree — the bucket
    policy, the ACL, and the account/bucket public access block — which is why a collector cannot
    reduce it to a boolean without doing the analysis this function exists to do.
    """
    name = str(bucket.get("Name") or bucket.get("name") or "bucket")
    block = bucket.get("PublicAccessBlockConfiguration") or {}
    policy_blocked = bool(block.get("RestrictPublicBuckets") or block.get("BlockPublicPolicy"))
    acl_blocked = bool(block.get("IgnorePublicAcls") or block.get("BlockPublicAcls"))

    statements = pol.parse(bucket.get("Policy"))
    public_statements = pol.public_principals(statements)
    if public_statements and not policy_blocked:
        conditioned = [s for s in public_statements if pol.has_meaningful_condition(s)]
        unconditioned = [s for s in public_statements if not pol.has_meaningful_condition(s)]
        if unconditioned:
            actions = sorted({a for s in unconditioned for a in s.actions})
            writable = any(pol.matches(a, "s3:PutObject") or pol.matches(a, "s3:DeleteObject")
                           or a == "*" for a in actions)
            yield Issue(
                "s3-public-policy",
                f"S3 bucket `{name}` is readable by anyone"
                + (" and writable by anyone" if writable else ""),
                "critical" if writable else "high", "CWE-732", "CIS AWS 2.1.5",
                "The bucket policy allows a wildcard principal with no condition narrowing who "
                "that is, so the objects are retrievable by anyone who knows or guesses the name"
                + (". The policy also allows writes, so anyone can replace an object the "
                   "application serves — which is a defacement, a malware distribution point, or "
                   "a supply-chain injection depending on what reads from it." if writable else
                   "."),
                "Remove the wildcard principal, or enable the bucket's public access block.",
                name,
                {"actions": actions[:10], "statements": len(unconditioned)},
            )
        elif conditioned:
            yield Issue(
                "s3-conditional-public",
                f"S3 bucket `{name}` allows a wildcard principal under a condition", "medium",
                "CWE-732", "CIS AWS 2.1.5",
                "The policy grants anyone, narrowed by a condition (a source IP range, an "
                "organization, a VPC endpoint). That may be deliberate; it is worth confirming "
                "the condition is what the operator thinks it is.",
                "Confirm the condition, or replace the wildcard principal with named accounts.",
                name,
                {"conditions": [s.conditions for s in conditioned][:3]},
            )

    for grant in bucket.get("Grants") or bucket.get("ACLGrants") or []:
        grantee = (grant.get("Grantee") or {}) if isinstance(grant, dict) else {}
        uri = str(grantee.get("URI") or "")
        if "AllUsers" in uri and not acl_blocked:
            yield Issue(
                "s3-public-acl", f"S3 bucket `{name}` has an ACL granting AllUsers", "high",
                "CWE-732", "CIS AWS 2.1.5",
                f"The legacy ACL grants `{grant.get('Permission', 'READ')}` to every AWS user and "
                "anonymous callers. ACLs are evaluated independently of the bucket policy, so a "
                "policy that looks private does not close this.",
                "Remove the grant and enable the bucket's public access block.",
                name,
                {"permission": grant.get("Permission"), "grantee": uri},
            )
        elif "AuthenticatedUsers" in uri and not acl_blocked:
            yield Issue(
                "s3-authenticated-acl",
                f"S3 bucket `{name}` grants every AWS account", "high", "CWE-732", "CIS AWS 2.1.5",
                "`AuthenticatedUsers` means every account in AWS, not every account in this "
                "organization. Anyone who can create an AWS account can read the bucket.",
                "Remove the grant.",
                name,
                {"permission": grant.get("Permission")},
            )

    encryption = bucket.get("ServerSideEncryptionConfiguration")
    if encryption is not None and not (encryption or {}).get("Rules"):
        yield Issue(
            "s3-unencrypted", f"S3 bucket `{name}` has no default encryption", "medium",
            "CWE-311", "CIS AWS 2.1.1",
            "Objects written without an explicit encryption header are stored unencrypted, so the "
            "protection depends on every writer remembering to ask for it.",
            "Set a default encryption rule on the bucket.",
            name,
        )

    versioning = bucket.get("Versioning")
    if isinstance(versioning, dict) and versioning.get("Status") not in ("Enabled",):
        yield Issue(
            "s3-no-versioning", f"S3 bucket `{name}` has versioning disabled", "low", "CWE-693",
            "CIS AWS 2.1.3",
            "Without versioning, an object that ransomware or a mistake overwrites is gone. It is "
            "also what makes an MFA-delete policy possible.",
            "Enable versioning.",
            name,
        )


# ── EC2 security groups ───────────────────────────────────────────────────────────────────────────
def security_group_issues(group: dict) -> Iterator[Issue]:
    """`describe_security_groups` output.

    Ports are ranges. The previous rule compared `rule["port"] == 22`, so a group opening
    `FromPort: 0, ToPort: 65535` to the internet — which exposes SSH, RDP, the database, and
    everything else at once — matched nothing at all.
    """
    name = str(group.get("GroupName") or group.get("GroupId") or "security-group")
    identifier = str(group.get("GroupId") or name)

    for permission in group.get("IpPermissions") or []:
        protocol = str(permission.get("IpProtocol", "-1"))
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        cidrs = [str(r.get("CidrIp")) for r in (permission.get("IpRanges") or [])
                 if r.get("CidrIp")]
        cidrs += [str(r.get("CidrIpv6")) for r in (permission.get("Ipv6Ranges") or [])
                  if r.get("CidrIpv6")]
        open_to_world = [c for c in cidrs if c in OPEN_CIDRS]
        if not open_to_world:
            continue

        if protocol == "-1" or from_port is None:
            yield Issue(
                "sg-all-ports-open",
                f"Security group `{name}` allows every port from the internet", "critical",
                "CWE-284", "CIS AWS 5.2",
                "The rule covers all protocols and all ports from "
                f"{', '.join(open_to_world)}. Every service on every instance in this group is "
                "reachable from the internet, including ones nobody intended to publish.",
                "Replace with rules naming the ports and source ranges that are actually needed.",
                identifier,
                {"cidrs": open_to_world, "protocol": protocol},
            )
            continue

        exposed_admin = {port: label for port, label in ADMIN_PORTS.items()
                         if int(from_port) <= port <= int(to_port)}
        span = int(to_port) - int(from_port)
        if exposed_admin:
            listed = ", ".join(f"{label} ({port})" for port, label in sorted(exposed_admin.items()))
            yield Issue(
                "sg-admin-port-open",
                f"Security group `{name}` exposes {listed} to the internet", "high", "CWE-284",
                "CIS AWS 5.2",
                f"Ports {from_port}-{to_port}/{protocol} accept traffic from "
                f"{', '.join(open_to_world)}. These are administrative and database ports: "
                "exposing them puts authentication — often a password — as the only thing between "
                "the internet and the host."
                + (f" The rule spans {span + 1} ports, so the exposure is broader than the named "
                   "services." if span > 0 else ""),
                "Restrict the source to a bastion, a VPN range, or use SSM Session Manager.",
                identifier,
                {"from_port": from_port, "to_port": to_port, "cidrs": open_to_world,
                 "services": sorted(exposed_admin.values())},
            )
        elif span > 100:
            yield Issue(
                "sg-wide-range-open",
                f"Security group `{name}` opens {span + 1} ports to the internet", "medium",
                "CWE-284", "CIS AWS 5.2",
                f"Ports {from_port}-{to_port} are reachable from {', '.join(open_to_world)}. A "
                "range this wide is rarely intentional and covers whatever gets deployed into the "
                "group later.",
                "Name the ports the workload serves.",
                identifier,
                {"from_port": from_port, "to_port": to_port, "cidrs": open_to_world},
            )


# ── IAM ───────────────────────────────────────────────────────────────────────────────────────────
def iam_issues(details: dict, *, now: dt.datetime | None = None) -> Iterator[Issue]:
    """`get_account_authorization_details` output, plus the credential report if collected."""
    now = now or _now()
    policies = {
        str(p.get("Arn")): _default_document(p)
        for p in details.get("Policies") or []
    }

    for user in details.get("UserDetailList") or []:
        yield from _principal_issues(user, "user", policies, now=now)
    for role in details.get("RoleDetailList") or []:
        yield from _role_trust_issues(role)
        yield from _principal_issues(role, "role", policies, now=now)

    for entry in details.get("CredentialReport") or []:
        yield from _credential_issues(entry, now=now)


def _default_document(managed: dict) -> list[pol.Statement]:
    for version in managed.get("PolicyVersionList") or []:
        if version.get("IsDefaultVersion"):
            return pol.parse(version.get("Document"))
    return []


def _attached_statements(principal: dict, policies: dict) -> list[pol.Statement]:
    statements: list[pol.Statement] = []
    for inline in principal.get("UserPolicyList") or principal.get("RolePolicyList") or []:
        statements.extend(pol.parse(inline.get("PolicyDocument")))
    for attached in principal.get("AttachedManagedPolicies") or []:
        statements.extend(policies.get(str(attached.get("PolicyArn")), []))
        if str(attached.get("PolicyName")) == "AdministratorAccess" and not policies:
            # The managed policy body was not collected; its name is unambiguous.
            statements.append(pol.Statement(effect="Allow", actions=("*",), resources=("*",)))
    return statements


def _principal_issues(principal: dict, kind: str, policies: dict, *,
                      now: dt.datetime) -> Iterator[Issue]:
    name = str(principal.get("UserName") or principal.get("RoleName") or kind)
    statements = _attached_statements(principal, policies)
    if not statements:
        return

    if pol.is_admin(statements):
        yield Issue(
            "iam-admin", f"IAM {kind} `{name}` has full administrative access", "high",
            "CWE-269", "CIS AWS 1.16",
            f"The {kind}'s policies allow every action on every resource. Anything that "
            f"compromises this {kind} — a leaked key, a stolen session, a workload it is attached "
            "to — holds the account.",
            "Replace with a policy naming the services and actions actually used.",
            name,
        )

    escalations = pol.escalation_paths(statements)
    if escalations and not pol.is_admin(statements):
        yield Issue(
            "iam-escalation",
            f"IAM {kind} `{name}` can escalate its own privileges", "high", "CWE-269",
            "CIS AWS 1.16",
            "The policy grants "
            + ", ".join(f"`{a}`" for a in escalations[:6])
            + " on an unconstrained resource. These are not administrative permissions by name, "
            "but each is a documented path from them to administrative permissions in one step — "
            "`iam:PassRole` with a wildcard resource, for instance, attaches any role in the "
            "account to a service the holder controls.",
            "Constrain the resource to the specific roles or policies the workload needs.",
            name,
            {"actions": escalations},
        )
    del now


def _role_trust_issues(role: dict) -> Iterator[Issue]:
    """Who is allowed to assume the role — the control that decides whether it is reachable."""
    name = str(role.get("RoleName") or "role")
    trust = pol.parse(role.get("AssumeRolePolicyDocument"))
    for statement in pol.public_principals(trust):
        if pol.has_meaningful_condition(statement):
            continue
        yield Issue(
            "iam-role-any-principal", f"IAM role `{name}` can be assumed by any AWS principal",
            "critical", "CWE-284", "CIS AWS 1.16",
            "The trust policy names a wildcard principal with no condition, so any AWS account in "
            "the world can assume this role and act with its permissions inside this account.",
            "Name the accounts or services that may assume the role, or add an ExternalId "
            "condition.",
            name,
            {"sid": statement.sid},
        )


def _credential_issues(entry: dict, *, now: dt.datetime) -> Iterator[Issue]:
    """One row of `get_credential_report`."""
    user = str(entry.get("user") or entry.get("UserName") or "user")

    if user == "<root_account>":
        if str(entry.get("mfa_active")).lower() not in ("true", "yes"):
            yield Issue(
                "iam-root-no-mfa", "The root account has no MFA", "critical", "CWE-308",
                "CIS AWS 1.5",
                "The root account cannot be restricted by IAM policy and can close the account, "
                "change the payment method, and recover any other credential. A password is the "
                "only thing protecting it.",
                "Enable hardware MFA on the root account and store the device securely.",
                user,
            )
        if str(entry.get("access_key_1_active")).lower() in ("true", "yes"):
            yield Issue(
                "iam-root-access-key", "The root account has an active access key", "critical",
                "CWE-522", "CIS AWS 1.4",
                "A root access key is an unrestricted, non-expiring credential for the entire "
                "account, usable without MFA. There is no legitimate use for one.",
                "Delete the root access key.",
                user,
            )
        return

    if str(entry.get("password_enabled")).lower() in ("true", "yes") and \
            str(entry.get("mfa_active")).lower() not in ("true", "yes"):
        yield Issue(
            "iam-user-no-mfa", f"IAM user `{user}` has console access without MFA", "high",
            "CWE-308", "CIS AWS 1.10",
            "A password is the only credential needed to sign in as this user, so a phish or a "
            "reused password is a full session.",
            "Enable MFA, or move the user to federated sign-in.",
            user,
        )

    for index in (1, 2):
        if str(entry.get(f"access_key_{index}_active")).lower() not in ("true", "yes"):
            continue
        age = _age_days(entry.get(f"access_key_{index}_last_rotated"), now)
        if age is not None and age > ACCESS_KEY_MAX_AGE_DAYS:
            yield Issue(
                "iam-stale-key", f"IAM user `{user}` has an access key {int(age)} days old",
                "medium", "CWE-522", "CIS AWS 1.14",
                "A long-lived key has had a long time to end up in a repository, a CI log, or a "
                "laptop backup, and nothing about its age is visible to whoever holds a copy.",
                "Rotate the key and shorten the rotation period.",
                user,
                {"age_days": int(age), "key": index},
            )


# ── RDS ───────────────────────────────────────────────────────────────────────────────────────────
def rds_issues(instance: dict) -> Iterator[Issue]:
    name = str(instance.get("DBInstanceIdentifier") or "db")
    if instance.get("PubliclyAccessible") is True:
        yield Issue(
            "rds-public", f"RDS instance `{name}` is publicly accessible", "high", "CWE-284",
            "CIS AWS 2.3.1",
            "The instance has a public endpoint. Whether anything reaches it then depends "
            "entirely on its security group, which makes one misconfigured rule the difference "
            "between a private database and an internet-facing one.",
            "Set PubliclyAccessible to false and reach the database from inside the VPC.",
            name,
            {"engine": instance.get("Engine")},
        )
    if instance.get("StorageEncrypted") is False:
        yield Issue(
            "rds-unencrypted", f"RDS instance `{name}` is not encrypted at rest", "medium",
            "CWE-311", "CIS AWS 2.3.1",
            "Snapshots and the underlying volumes are readable by anyone who obtains them, and "
            "encryption cannot be enabled in place — it requires a restore.",
            "Restore into an encrypted instance.",
            name,
        )
    if instance.get("BackupRetentionPeriod") == 0:
        yield Issue(
            "rds-no-backups", f"RDS instance `{name}` has automated backups disabled", "medium",
            "CWE-693", "CIS AWS 2.3.2",
            "There is no point-in-time recovery. A destructive query or a ransomware event on "
            "this database is final.",
            "Set a backup retention period of at least 7 days.",
            name,
        )


# ── account-level logging and keys ────────────────────────────────────────────────────────────────
def logging_issues(snapshot: dict) -> Iterator[Issue]:
    trails = snapshot.get("trailList") or snapshot.get("CloudTrail") or []
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not trails:
        yield Issue(
            "cloudtrail-missing", "No CloudTrail trail is configured", "high", "CWE-778",
            "CIS AWS 3.1",
            "Nothing is recording API activity in this account. An intrusion leaves no trail to "
            "find, and no answer to what an attacker did.",
            "Create a multi-region trail delivering to a dedicated, restricted bucket.",
            "account",
        )
    elif not multi_region:
        yield Issue(
            "cloudtrail-single-region", "No multi-region CloudTrail trail", "medium", "CWE-778",
            "CIS AWS 3.1",
            "Activity in regions the trail does not cover is unrecorded, and an unused region is "
            "exactly where an intruder prefers to work.",
            "Enable IsMultiRegionTrail on a trail.",
            "account",
        )
    for trail in trails:
        if trail.get("LogFileValidationEnabled") is False:
            yield Issue(
                "cloudtrail-no-validation",
                f"CloudTrail `{trail.get('Name', 'trail')}` has log file validation disabled",
                "medium", "CWE-778", "CIS AWS 3.2",
                "Without validation there is no way to prove the log was not edited after the "
                "fact, which is the first thing an intruder with access to the bucket would do.",
                "Enable log file validation.",
                str(trail.get("Name") or "trail"),
            )

    for key in snapshot.get("Keys") or snapshot.get("KMSKeys") or []:
        if key.get("KeyRotationEnabled") is False and key.get("KeyManager") != "AWS":
            yield Issue(
                "kms-no-rotation",
                f"KMS key `{key.get('KeyId', 'key')}` does not rotate", "low", "CWE-320",
                "CIS AWS 3.8",
                "A key that never rotates means one compromised key material protects every "
                "object ever written under it.",
                "Enable automatic annual rotation.",
                str(key.get("KeyId") or "key"),
            )


__all__ = [
    "ACCESS_KEY_MAX_AGE_DAYS",
    "ADMIN_PORTS",
    "OPEN_CIDRS",
    "Issue",
    "iam_issues",
    "logging_issues",
    "rds_issues",
    "s3_issues",
    "security_group_issues",
]
