"""Cloud misconfiguration rules over declared infrastructure (WP-D9).

Every rule answers a question about a resource that is *declared*, which is both the strength and
the limit of scanning IaC: it catches the problem before it exists, and it cannot see anything a
human changed in the console afterwards. Rules say what they saw, never what they assume.

The discipline that matters here is silence on the unknown. `encrypted = var.encrypt_everything`
tells this engine nothing, so no rule fires on it — `Resource.is_false` returns False for an
unresolved expression precisely so a rule cannot report "encryption disabled" about a value it never
read. A Terraform *plan* has those variables resolved, which is why the plan loader exists: the same
rules produce a stronger answer when CI hands them a plan.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from guardian_core.enums import Severity

from guardian_scanner.iac.model import Resource, as_list, as_text

OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
_ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                27017: "MongoDB", 9200: "Elasticsearch", 1433: "MSSQL", 5984: "CouchDB",
                11211: "memcached", 2375: "Docker daemon", 23: "telnet"}
_SECRET_KEY = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
)
_AWS_SECRET_VALUE = re.compile(r"^(AKIA[0-9A-Z]{16}|[0-9a-zA-Z/+]{40})$")


@dataclass(frozen=True)
class IacFinding:
    rule: str
    title: str
    severity: Severity
    cwe: str
    detail: str
    resource: str
    path: str
    line: int = 0
    remediation: str = ""


Rule = Callable[[Resource], Iterator[IacFinding]]
_RULES: list[tuple[frozenset[str], Rule]] = []


def rule(*types: str) -> Callable[[Rule], Rule]:
    def register(func: Rule) -> Rule:
        _RULES.append((frozenset(types), func))
        return func
    return register


def evaluate(resource: Resource) -> list[IacFinding]:
    findings: list[IacFinding] = []
    for types, func in _RULES:
        if types and resource.type not in types:
            continue
        findings.extend(func(resource))
    return findings


def _finding(resource: Resource, rule_id: str, title: str, severity: Severity, cwe: str,
             detail: str, remediation: str = "") -> IacFinding:
    return IacFinding(
        rule=rule_id, title=title, severity=severity, cwe=cwe, detail=detail,
        resource=f"{resource.type}.{resource.name}", path=resource.path, line=resource.line,
        remediation=remediation,
    )


# ── network exposure ──────────────────────────────────────────────────────────────────────────────
@rule("aws_security_group", "aws_security_group_rule", "AWS::EC2::SecurityGroup")
def open_ingress(resource: Resource) -> Iterator[IacFinding]:
    """An ingress rule reachable from the whole internet.

    Severity depends on the port. `0.0.0.0/0` on 443 is a web server; on 22 or 5432 it is a database
    or an administrative interface published to every scanner on the internet, which is a different
    class of problem and must not be reported at the same severity.
    """
    rules = list(resource.nested("ingress"))
    rules += [r for r in as_list(resource.get("SecurityGroupIngress")) if isinstance(r, dict)]
    if resource.type == "aws_security_group_rule" and as_text(resource.get("type")) == "ingress":
        rules.append(resource.attributes)

    for entry in rules:
        cidrs = {
            str(c) for c in (as_list(entry.get("cidr_blocks")) + as_list(entry.get("cidr_ipv6"))
                             + as_list(entry.get("ipv6_cidr_blocks")) + as_list(entry.get("CidrIp"))
                             + as_list(entry.get("CidrIpv6")))
        }
        if not (cidrs & OPEN_CIDRS):
            continue
        low = entry.get("from_port", entry.get("FromPort"))
        high = entry.get("to_port", entry.get("ToPort"))
        protocol = str(entry.get("protocol", entry.get("IpProtocol", ""))).lower()

        exposed = [
            (port, name) for port, name in _ADMIN_PORTS.items()
            if isinstance(low, int) and isinstance(high, int) and low <= port <= high
        ]
        all_ports = protocol in {"-1", "all"} or (low in (0, None) and high in (65535, None))

        if exposed:
            names = ", ".join(f"{name} ({port})" for port, name in sorted(exposed))
            yield _finding(
                resource, "iac-open-admin-port",
                f"Administrative service open to the internet: {names}",
                Severity.CRITICAL, "CWE-284",
                f"The security group allows 0.0.0.0/0 to reach {names}. These services are "
                "credential-guarded only — every host on the internet gets unlimited "
                "authentication attempts against them, continuously.",
                "Restrict the source to a known CIDR, or front the service with a bastion or "
                "identity-aware proxy.",
            )
        elif all_ports:
            yield _finding(
                resource, "iac-open-all-ports",
                "Security group allows every port from the internet",
                Severity.CRITICAL, "CWE-284",
                "The rule permits 0.0.0.0/0 on all ports and protocols, so anything that ever "
                "listens on this instance is published the moment it starts.",
                "Enumerate the ports the workload actually serves.",
            )
        else:
            yield _finding(
                resource, "iac-open-ingress",
                "Security group open to the internet",
                Severity.MEDIUM, "CWE-284",
                f"Ingress from 0.0.0.0/0 on ports {low}-{high}. Expected for a public web "
                "listener; a finding worth confirming for anything else.",
                "Confirm this port is meant to be public.",
            )


@rule("google_compute_firewall")
def gcp_open_firewall(resource: Resource) -> Iterator[IacFinding]:
    ranges = {str(c) for c in as_list(resource.get("source_ranges"))}
    if ranges & OPEN_CIDRS:
        yield _finding(
            resource, "iac-open-ingress", "GCP firewall rule open to the internet",
            Severity.HIGH, "CWE-284",
            "source_ranges includes 0.0.0.0/0, so the rule applies to every host on the internet.",
            "Narrow source_ranges, or use a target tag with an identity-aware proxy.",
        )


# ── storage ───────────────────────────────────────────────────────────────────────────────────────
@rule("aws_s3_bucket", "AWS::S3::Bucket")
def s3_public_acl(resource: Resource) -> Iterator[IacFinding]:
    acl = as_text(resource.get("acl", "AccessControl")).lower()
    if acl in {"public-read", "public-read-write", "publicread", "publicreadwrite",
               "authenticated-read"}:
        severity = Severity.CRITICAL if "write" in acl else Severity.HIGH
        yield _finding(
            resource, "iac-s3-public-acl", f"S3 bucket ACL is {acl}",
            severity, "CWE-732",
            f"The bucket grants {acl} access. "
            + ("Anyone on the internet can write to it, which makes it a hosting platform for "
               "whatever they upload and a way to alter what your application reads."
               if "write" in acl else
               "Every object in it is readable by anyone who learns the bucket name, and bucket "
               "names are routinely enumerated."),
            "Set the ACL to private and use a bucket policy or presigned URLs for sharing.",
        )


@rule("aws_s3_bucket")
def s3_missing_controls(resource: Resource) -> Iterator[IacFinding]:
    if not resource.nested("server_side_encryption_configuration") and resource.missing(
        "server_side_encryption_configuration"
    ):
        yield _finding(
            resource, "iac-s3-no-encryption", "S3 bucket has no server-side encryption configured",
            Severity.MEDIUM, "CWE-311",
            "No encryption configuration is declared on the bucket. Encryption at rest is what "
            "makes a lost or mis-shared storage snapshot recoverable rather than a disclosure.",
            "Declare server_side_encryption_configuration with aws:kms or AES256.",
        )
    versioning = resource.nested("versioning")
    if versioning and all(not v.get("enabled") for v in versioning):
        yield _finding(
            resource, "iac-s3-no-versioning", "S3 bucket versioning disabled",
            Severity.LOW, "CWE-693",
            "Without versioning an object deleted or overwritten — by a mistake or by ransomware — "
            "cannot be recovered.",
            "Enable versioning, and add a lifecycle rule to bound the cost.",
        )


@rule("aws_s3_bucket_public_access_block")
def s3_access_block_disabled(resource: Resource) -> Iterator[IacFinding]:
    weak = [
        name for name in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                          "restrict_public_buckets")
        if resource.is_false(name)
    ]
    if weak:
        yield _finding(
            resource, "iac-s3-public-access-block-disabled",
            "S3 public access block explicitly disabled",
            Severity.HIGH, "CWE-732",
            f"{', '.join(weak)} set to false. This is the account-level guard that stops a future "
            "policy or ACL change from making the bucket public by accident; turning it off "
            "removes the safety net rather than the exposure.",
            "Leave every block_* setting true unless a specific object must be public.",
        )


@rule("azurerm_storage_account")
def azure_storage_http(resource: Resource) -> Iterator[IacFinding]:
    if resource.is_false("enable_https_traffic_only", "https_traffic_only_enabled"):
        yield _finding(
            resource, "iac-azure-storage-http", "Azure storage account allows plaintext HTTP",
            Severity.HIGH, "CWE-319",
            "Unencrypted transport is permitted, so the account's access key travels in the clear "
            "on any request a client makes over HTTP.",
            "Set enable_https_traffic_only = true.",
        )
    if as_text(resource.get("public_network_access_enabled")).lower() == "true" or \
            resource.is_true("allow_nested_items_to_be_public"):
        yield _finding(
            resource, "iac-azure-storage-public", "Azure storage allows public blob access",
            Severity.HIGH, "CWE-732",
            "Containers in this account may be made publicly readable.",
            "Set allow_nested_items_to_be_public = false.",
        )


@rule("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding")
def gcs_public(resource: Resource) -> Iterator[IacFinding]:
    members = {str(m) for m in as_list(resource.get("member", "members"))}
    if members & {"allUsers", "allAuthenticatedUsers"}:
        yield _finding(
            resource, "iac-gcs-public", "GCS bucket granted to allUsers",
            Severity.HIGH, "CWE-732",
            "The binding grants access to every Google account, or to the whole internet.",
            "Grant to a specific service account or group.",
        )


# ── databases ─────────────────────────────────────────────────────────────────────────────────────
@rule("aws_db_instance", "aws_rds_cluster", "AWS::RDS::DBInstance")
def rds_exposure(resource: Resource) -> Iterator[IacFinding]:
    if resource.is_true("publicly_accessible", "PubliclyAccessible"):
        yield _finding(
            resource, "iac-rds-public", "RDS instance is publicly accessible",
            Severity.CRITICAL, "CWE-284",
            "The database is given a public endpoint. Its only remaining protection is the "
            "security group and the database password, and a database published to the internet is "
            "found by scanners within hours.",
            "Set publicly_accessible = false and reach it from inside the VPC.",
        )
    if resource.is_false("storage_encrypted", "StorageEncrypted") or resource.missing(
        "storage_encrypted", "StorageEncrypted"
    ):
        yield _finding(
            resource, "iac-rds-unencrypted", "RDS storage is not encrypted",
            Severity.HIGH, "CWE-311",
            "Storage encryption is off or unset. It cannot be enabled in place later — the "
            "instance has to be recreated from a snapshot, which is why this is worth catching "
            "before the resource exists.",
            "Set storage_encrypted = true now.",
        )
    retention = resource.get("backup_retention_period", "BackupRetentionPeriod")
    if isinstance(retention, int) and retention == 0:
        yield _finding(
            resource, "iac-rds-no-backups", "RDS automated backups disabled",
            Severity.MEDIUM, "CWE-693",
            "backup_retention_period is 0, so there is no point-in-time recovery: a bad migration "
            "or a ransomware event is unrecoverable.",
            "Set a retention period of at least 7 days.",
        )
    if resource.is_false("deletion_protection"):
        yield _finding(
            resource, "iac-rds-no-deletion-protection", "RDS deletion protection disabled",
            Severity.LOW, "CWE-693",
            "A single terraform apply against the wrong workspace destroys the database.",
            "Set deletion_protection = true for production instances.",
        )


@rule("aws_ebs_volume", "aws_instance", "AWS::EC2::Volume")
def ebs_unencrypted(resource: Resource) -> Iterator[IacFinding]:
    if resource.is_false("encrypted", "Encrypted"):
        yield _finding(
            resource, "iac-ebs-unencrypted", "EBS volume is explicitly unencrypted",
            Severity.MEDIUM, "CWE-311",
            "encrypted = false. A detached or snapshotted volume carries its data in the clear.",
            "Set encrypted = true, or enable EBS encryption by default for the account.",
        )


# ── identity ──────────────────────────────────────────────────────────────────────────────────────
@rule("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy",
      "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy")
def iam_wildcard(resource: Resource) -> Iterator[IacFinding]:
    """`Action: *` on `Resource: *` is administrator, whatever the policy is called."""
    document = resource.get("policy", "PolicyDocument", "inline_policy")
    parsed = _as_policy(document)
    if parsed is None:
        return
    for statement in as_list(parsed.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = {str(a) for a in as_list(statement.get("Action"))}
        resources = {str(r) for r in as_list(statement.get("Resource"))}
        if "*" in actions and "*" in resources:
            yield _finding(
                resource, "iac-iam-admin-wildcard",
                "IAM policy grants every action on every resource",
                Severity.HIGH, "CWE-732",
                'Action "*" on Resource "*" is full administrator. Whatever compromises the '
                "principal holding it — a leaked key, a vulnerable instance — inherits control of "
                "the entire account, including the audit trail.",
                "Enumerate the actions the workload calls; start from CloudTrail if unknown.",
            )
        elif "*" in actions:
            yield _finding(
                resource, "iac-iam-wildcard-action", "IAM policy allows every action",
                Severity.MEDIUM, "CWE-732",
                'Action "*" is scoped to specific resources, which bounds the damage but still '
                "grants deletion and policy modification on them.",
                "List the actions explicitly.",
            )
        principal = statement.get("Principal")
        trusted = as_list(principal.get("AWS")) if isinstance(principal, dict) else []
        if principal == "*" or "*" in trusted:
            yield _finding(
                resource, "iac-iam-public-principal", "IAM policy trusts every principal",
                Severity.CRITICAL, "CWE-284",
                'Principal "*" means any AWS account, and for a resource policy that means anyone.',
                "Name the account or role that is allowed to assume this.",
            )


def _as_policy(value: object) -> dict | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


# ── secrets in the configuration itself ───────────────────────────────────────────────────────────
@rule()
def hardcoded_credentials(resource: Resource) -> Iterator[IacFinding]:
    """A literal credential in infrastructure code.

    Only *literal* values are reported. `password = var.db_password` is the correct pattern and
    firing on it would train customers to ignore the rule.
    """
    for key, value in resource.attributes.items():
        if not isinstance(value, str) or isinstance(value, type(None)):
            continue
        from guardian_scanner.iac.hcl import Unresolved  # noqa: PLC0415 - avoids a cycle

        if isinstance(value, Unresolved) or len(value) < 6:
            continue
        if _SECRET_KEY.search(key) and not value.startswith(("arn:", "/", "$")):
            severity = Severity.HIGH if _AWS_SECRET_VALUE.match(value) else Severity.MEDIUM
            yield _finding(
                resource, "iac-hardcoded-credential",
                f"Credential written into infrastructure code ({key})",
                severity, "CWE-798",
                f"{key} is set to a literal value. Infrastructure code is committed, shared and "
                "usually world-readable inside the company; a credential in it is disclosed to "
                "everyone with repository access and to everyone who ever had it.",
                "Move the value into a secret manager and reference it, then rotate the one that "
                "was committed.",
            )


@rule("terraform_provider")
def provider_static_keys(resource: Resource) -> Iterator[IacFinding]:
    if any(isinstance(resource.get(k), str) and resource.get(k) for k in ("access_key",
                                                                          "secret_key")):
        yield _finding(
            resource, "iac-provider-static-credentials",
            "Provider configured with a static access key",
            Severity.HIGH, "CWE-798",
            "The provider block carries long-lived credentials in the repository rather than "
            "taking them from the environment or an assumed role.",
            "Use an instance profile, OIDC federation, or the environment.",
        )


# ── logging and audit ─────────────────────────────────────────────────────────────────────────────
@rule("aws_cloudtrail", "AWS::CloudTrail::Trail")
def cloudtrail_weak(resource: Resource) -> Iterator[IacFinding]:
    if resource.is_false("is_multi_region_trail", "IsMultiRegionTrail") or resource.missing(
        "is_multi_region_trail", "IsMultiRegionTrail"
    ):
        yield _finding(
            resource, "iac-cloudtrail-single-region", "CloudTrail is not multi-region",
            Severity.MEDIUM, "CWE-778",
            "Activity in every other region is unlogged, which is where an intruder will operate "
            "precisely because it is unlogged.",
            "Set is_multi_region_trail = true.",
        )
    if resource.is_false("enable_log_file_validation", "EnableLogFileValidation"):
        yield _finding(
            resource, "iac-cloudtrail-no-validation", "CloudTrail log file validation disabled",
            Severity.LOW, "CWE-778",
            "Without digest files there is no way to prove the audit log was not edited after the "
            "fact — which is the first thing worth doing to an audit log.",
            "Set enable_log_file_validation = true.",
        )


@rule("aws_eks_cluster")
def eks_public_endpoint(resource: Resource) -> Iterator[IacFinding]:
    for access in resource.nested("vpc_config"):
        if access.get("endpoint_public_access") is True:
            public_cidrs = {str(c) for c in as_list(access.get("public_access_cidrs"))}
            if not public_cidrs or public_cidrs & OPEN_CIDRS:
                yield _finding(
                    resource, "iac-eks-public-api",
                    "EKS API server published to the internet",
                    Severity.HIGH, "CWE-284",
                    "The Kubernetes API endpoint is publicly reachable with no CIDR restriction. "
                    "The API server is the control plane for everything in the cluster.",
                    "Disable public access, or restrict public_access_cidrs to known networks.",
                )


@rule("aws_lambda_function", "AWS::Lambda::Function")
def lambda_env_secrets(resource: Resource) -> Iterator[IacFinding]:
    for environment in resource.nested("environment"):
        variables = environment.get("variables")
        if not isinstance(variables, dict):
            continue
        for key, value in variables.items():
            from guardian_scanner.iac.hcl import Unresolved  # noqa: PLC0415 - avoids a cycle

            if _SECRET_KEY.search(str(key)) and isinstance(value, str) and \
                    not isinstance(value, Unresolved):
                yield _finding(
                    resource, "iac-lambda-env-secret",
                    f"Lambda environment variable holds a literal credential ({key})",
                    Severity.HIGH, "CWE-798",
                    "Lambda environment variables are readable by anyone with lambda:GetFunction, "
                    "and are shown in the console.",
                    "Read the value from Secrets Manager or SSM Parameter Store at runtime.",
                )
