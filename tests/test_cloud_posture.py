"""AWS posture rules (WP-D8).

Every fixture here is the shape the AWS API actually returns, because that is the whole point of
the package: the previous engine consumed a snapshot carrying `{"public": true}`, which meant
whoever wrote the snapshot had already answered the question the scanner exists to answer.

The recurring theme in these tests is the *correct* configuration sitting next to the broken one —
a bucket policy with a wildcard principal but a public access block that overrides it, an
`iam:PassRole` scoped to one role, a security group open on 443. Each of those is a place a naive
rule fires and an operator stops reading.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest
from guardian_scanner.cloud import policy as pol
from guardian_scanner.cloud.aws import (
    iam_issues,
    logging_issues,
    rds_issues,
    s3_issues,
    security_group_issues,
)

NOW = dt.datetime(2026, 8, 18, tzinfo=dt.UTC)


def _rules(issues) -> set[str]:
    return {issue.rule for issue in issues}


# ── IAM policy documents ──────────────────────────────────────────────────────────────────────────
ADMIN = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ_ONLY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
     "Resource": ["arn:aws:s3:::reports", "arn:aws:s3:::reports/*"]}]}


def test_a_wildcard_policy_is_administrative():
    assert pol.is_admin(pol.parse(ADMIN)) is True


def test_a_scoped_policy_is_not():
    assert pol.is_admin(pol.parse(READ_ONLY)) is False


def test_not_action_grants_everything_it_does_not_name():
    """`NotAction` reads like a restriction and is the inverse of one: this allows every action in
    AWS except IAM."""
    document = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    statements = pol.parse(document)
    assert pol.grants(statements, "s3:DeleteBucket") is True
    assert pol.grants(statements, "iam:CreateUser") is False


def test_an_explicit_deny_beats_an_allow():
    """Reporting a policy that allows `s3:*` next to one that denies it loses an operator's trust
    in a single review."""
    document = {"Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
    ]}
    statements = pol.parse(document)
    assert pol.grants(statements, "s3:GetObject") is True
    assert pol.grants(statements, "s3:DeleteBucket") is False


def test_pass_role_on_any_resource_is_an_escalation_path():
    """It grants nothing by itself, and it lets the holder attach any role in the account to a
    service they control."""
    document = {"Statement": [
        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}
    assert "iam:passrole" in pol.escalation_paths(pol.parse(document))


def test_pass_role_scoped_to_one_role_is_not():
    """This is how a correctly-written deployment policy looks, and flagging it flags every one."""
    document = {"Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole",
         "Resource": "arn:aws:iam::123456789012:role/app-task"}]}
    assert pol.escalation_paths(pol.parse(document)) == []


def test_a_url_encoded_document_is_parsed():
    """`get_account_authorization_details` returns policy documents URL-encoded."""
    from urllib.parse import quote

    encoded = quote(json.dumps(ADMIN))
    assert pol.is_admin(pol.parse(encoded)) is True


def test_malformed_policy_input_yields_nothing_rather_than_raising():
    assert pol.parse("not json") == []
    assert pol.parse(None) == []
    assert pol.parse({"Statement": "nonsense"}) == []


def test_a_wildcard_principal_is_recognized_in_both_spellings():
    for principal in ("*", {"AWS": "*"}, {"AWS": ["*"]}):
        statements = pol.parse({"Statement": [
            {"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::b/*"}]})
        assert pol.public_principals(statements)


# ── S3 ────────────────────────────────────────────────────────────────────────────────────────────
def _bucket(**overrides):
    bucket = {"Name": "reports", "Versioning": {"Status": "Enabled"},
              "ServerSideEncryptionConfiguration": {"Rules": [{}]}}
    bucket.update(overrides)
    return bucket


PUBLIC_READ = json.dumps({"Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::reports/*"}]})
PUBLIC_WRITE = json.dumps({"Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": ["s3:GetObject", "s3:PutObject"],
     "Resource": "arn:aws:s3:::reports/*"}]})


def test_a_bucket_policy_open_to_anyone_is_reported():
    issues = list(s3_issues(_bucket(Policy=PUBLIC_READ)))
    assert [i.rule for i in issues] == ["s3-public-policy"]
    assert issues[0].severity == "high"


def test_a_publicly_writable_bucket_outranks_a_readable_one():
    """Anyone replacing an object the application serves is a defacement or a supply-chain
    injection, depending on what reads from it."""
    issues = list(s3_issues(_bucket(Policy=PUBLIC_WRITE)))
    assert issues[0].severity == "critical"
    assert "writable" in issues[0].title


def test_a_public_access_block_overrides_the_policy():
    """The three sources disagree constantly; this is why a collector cannot reduce it to a
    boolean."""
    bucket = _bucket(Policy=PUBLIC_READ,
                     PublicAccessBlockConfiguration={"RestrictPublicBuckets": True,
                                                     "BlockPublicPolicy": True})
    assert _rules(s3_issues(bucket)) == set()


def test_a_conditioned_wildcard_is_reported_as_worth_confirming_not_as_open():
    bucket = _bucket(Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::reports/*",
         "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}))
    issues = list(s3_issues(bucket))
    assert [i.rule for i in issues] == ["s3-conditional-public"]
    assert issues[0].severity == "medium"


def test_a_public_acl_is_reported_even_when_the_policy_is_private():
    """ACLs are evaluated independently of the bucket policy."""
    bucket = _bucket(Grants=[{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                                          "Type": "Group"}, "Permission": "READ"}])
    assert "s3-public-acl" in _rules(s3_issues(bucket))


def test_authenticated_users_means_every_aws_account():
    bucket = _bucket(Grants=[{"Grantee": {
        "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}, "Permission": "READ"}])
    issues = list(s3_issues(bucket))
    assert issues[0].rule == "s3-authenticated-acl"
    assert "every AWS account" in issues[0].title


def test_an_acl_block_suppresses_the_acl_finding():
    bucket = _bucket(
        Grants=[{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                 "Permission": "READ"}],
        PublicAccessBlockConfiguration={"IgnorePublicAcls": True},
    )
    assert _rules(s3_issues(bucket)) == set()


def test_a_private_bucket_produces_nothing():
    assert _rules(s3_issues(_bucket())) == set()


def test_missing_encryption_and_versioning_are_reported():
    bucket = _bucket(ServerSideEncryptionConfiguration={}, Versioning={"Status": "Suspended"})
    assert _rules(s3_issues(bucket)) == {"s3-unencrypted", "s3-no-versioning"}


def test_an_uncollected_field_is_not_treated_as_absent():
    """A collector that did not call `get_bucket_encryption` has not established that encryption is
    off, and inventing the finding would be inventing the fact."""
    bucket = {"Name": "b"}
    assert _rules(s3_issues(bucket)) == set()


# ── security groups ───────────────────────────────────────────────────────────────────────────────
def _group(**permission):
    return {"GroupId": "sg-01", "GroupName": "web", "IpPermissions": [permission]}


def test_ssh_open_to_the_internet_is_reported():
    group = _group(IpProtocol="tcp", FromPort=22, ToPort=22,
                   IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    issues = list(security_group_issues(group))
    assert issues[0].rule == "sg-admin-port-open"
    assert "SSH" in issues[0].title


def test_a_port_range_covering_ssh_is_reported():
    """The defect this replaces: the old rule compared `port == 22`, so `0-65535` — which exposes
    SSH along with everything else — matched nothing at all."""
    group = _group(IpProtocol="tcp", FromPort=0, ToPort=65535,
                   IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    issues = list(security_group_issues(group))
    assert issues[0].rule == "sg-admin-port-open"
    assert "SSH" in issues[0].evidence["services"]


def test_all_protocols_open_is_critical():
    group = _group(IpProtocol="-1", IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    issues = list(security_group_issues(group))
    assert issues[0].rule == "sg-all-ports-open"
    assert issues[0].severity == "critical"


def test_an_ipv6_wildcard_counts_too():
    group = _group(IpProtocol="tcp", FromPort=3389, ToPort=3389,
                   Ipv6Ranges=[{"CidrIpv6": "::/0"}])
    assert "sg-admin-port-open" in _rules(security_group_issues(group))


def test_a_public_web_port_is_not_a_finding():
    """A public web server is a public web server."""
    group = _group(IpProtocol="tcp", FromPort=443, ToPort=443,
                   IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    assert _rules(security_group_issues(group)) == set()


def test_ssh_from_a_bastion_range_is_not_a_finding():
    group = _group(IpProtocol="tcp", FromPort=22, ToPort=22,
                   IpRanges=[{"CidrIp": "10.0.1.0/24"}])
    assert _rules(security_group_issues(group)) == set()


def test_a_wide_non_admin_range_is_reported_at_medium():
    group = _group(IpProtocol="tcp", FromPort=30000, ToPort=32000,
                   IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    issues = list(security_group_issues(group))
    assert issues[0].rule == "sg-wide-range-open"
    assert issues[0].severity == "medium"


# ── IAM principals ────────────────────────────────────────────────────────────────────────────────
def test_an_administrative_user_is_reported():
    details = {"UserDetailList": [
        {"UserName": "ops", "UserPolicyList": [{"PolicyName": "inline", "PolicyDocument": ADMIN}]}]}
    assert "iam-admin" in _rules(iam_issues(details, now=NOW))


def test_a_managed_policy_body_is_resolved():
    details = {
        "Policies": [{"Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                      "PolicyVersionList": [{"IsDefaultVersion": True, "Document": ADMIN}]}],
        "UserDetailList": [{"UserName": "ops", "AttachedManagedPolicies": [
            {"PolicyName": "AdministratorAccess",
             "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}],
    }
    assert "iam-admin" in _rules(iam_issues(details, now=NOW))


def test_a_scoped_user_produces_nothing():
    details = {"UserDetailList": [
        {"UserName": "reader",
         "UserPolicyList": [{"PolicyName": "ro", "PolicyDocument": READ_ONLY}]}]}
    assert _rules(iam_issues(details, now=NOW)) == set()


def test_a_role_assumable_by_anyone_is_critical():
    details = {"RoleDetailList": [{
        "RoleName": "deploy",
        "AssumeRolePolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]},
    }]}
    issues = [i for i in iam_issues(details, now=NOW) if i.rule == "iam-role-any-principal"]
    assert issues and issues[0].severity == "critical"


def test_a_role_with_an_external_id_condition_is_not_reported():
    """This is the documented pattern for granting a third party access, not a mistake."""
    details = {"RoleDetailList": [{
        "RoleName": "vendor",
        "AssumeRolePolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"sts:ExternalId": "abc",
                                            "aws:PrincipalAccount": "123456789012"}}}]},
    }]}
    assert "iam-role-any-principal" not in _rules(iam_issues(details, now=NOW))


# ── credential report ─────────────────────────────────────────────────────────────────────────────
def test_root_without_mfa_and_with_a_key_are_both_critical():
    details = {"CredentialReport": [{
        "user": "<root_account>", "mfa_active": "false", "access_key_1_active": "true"}]}
    issues = list(iam_issues(details, now=NOW))
    assert _rules(issues) == {"iam-root-no-mfa", "iam-root-access-key"}
    assert all(i.severity == "critical" for i in issues)


def test_a_console_user_without_mfa_is_reported():
    details = {"CredentialReport": [
        {"user": "alice", "password_enabled": "true", "mfa_active": "false"}]}
    assert "iam-user-no-mfa" in _rules(iam_issues(details, now=NOW))


def test_a_console_user_with_mfa_is_not():
    details = {"CredentialReport": [
        {"user": "alice", "password_enabled": "true", "mfa_active": "true"}]}
    assert _rules(iam_issues(details, now=NOW)) == set()


def test_a_stale_access_key_is_reported_with_its_age():
    details = {"CredentialReport": [{
        "user": "ci", "access_key_1_active": "true",
        "access_key_1_last_rotated": "2025-01-01T00:00:00+00:00"}]}
    issues = [i for i in iam_issues(details, now=NOW) if i.rule == "iam-stale-key"]
    assert issues and issues[0].evidence["age_days"] > 90


def test_a_recently_rotated_key_is_not():
    details = {"CredentialReport": [{
        "user": "ci", "access_key_1_active": "true",
        "access_key_1_last_rotated": "2026-08-01T00:00:00+00:00"}]}
    assert _rules(iam_issues(details, now=NOW)) == set()


# ── RDS ───────────────────────────────────────────────────────────────────────────────────────────
def test_a_public_unencrypted_database_is_reported():
    instance = {"DBInstanceIdentifier": "prod", "PubliclyAccessible": True,
                "StorageEncrypted": False, "BackupRetentionPeriod": 0, "Engine": "postgres"}
    assert _rules(rds_issues(instance)) == {"rds-public", "rds-unencrypted", "rds-no-backups"}


def test_a_private_encrypted_database_is_not():
    instance = {"DBInstanceIdentifier": "prod", "PubliclyAccessible": False,
                "StorageEncrypted": True, "BackupRetentionPeriod": 7}
    assert _rules(rds_issues(instance)) == set()


# ── account logging ───────────────────────────────────────────────────────────────────────────────
def test_no_trail_at_all_is_high():
    issues = list(logging_issues({"trailList": []}))
    assert issues[0].rule == "cloudtrail-missing"
    assert issues[0].severity == "high"


def test_a_single_region_trail_is_reported():
    snapshot = {"trailList": [{"Name": "t", "IsMultiRegionTrail": False,
                               "LogFileValidationEnabled": True}]}
    assert "cloudtrail-single-region" in _rules(logging_issues(snapshot))


def test_a_multi_region_validated_trail_is_not():
    snapshot = {"trailList": [{"Name": "t", "IsMultiRegionTrail": True,
                               "LogFileValidationEnabled": True}]}
    assert _rules(logging_issues(snapshot)) == set()


def test_a_customer_key_without_rotation_is_reported():
    snapshot = {"trailList": [{"Name": "t", "IsMultiRegionTrail": True,
                               "LogFileValidationEnabled": True}],
                "Keys": [{"KeyId": "k1", "KeyRotationEnabled": False, "KeyManager": "CUSTOMER"}]}
    assert "kms-no-rotation" in _rules(logging_issues(snapshot))


def test_an_aws_managed_key_is_not_reported():
    """AWS-managed keys rotate on AWS's schedule and the customer cannot change it."""
    snapshot = {"trailList": [{"Name": "t", "IsMultiRegionTrail": True,
                               "LogFileValidationEnabled": True}],
                "Keys": [{"KeyId": "k1", "KeyRotationEnabled": False, "KeyManager": "AWS"}]}
    assert _rules(logging_issues(snapshot)) == set()


# ── every finding is actionable ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issues", [
    list(s3_issues(_bucket(Policy=PUBLIC_WRITE))),
    list(security_group_issues(_group(IpProtocol="-1", IpRanges=[{"CidrIp": "0.0.0.0/0"}]))),
    list(iam_issues({"CredentialReport": [{"user": "<root_account>", "mfa_active": "false"}]},
                    now=NOW)),
    list(rds_issues({"DBInstanceIdentifier": "d", "PubliclyAccessible": True})),
])
def test_a_finding_says_what_an_attacker_gets_and_what_to_do(issues):
    """`CIS 2.1.5` is not a reason, and nobody remediates a control number."""
    for issue in issues:
        assert len(issue.detail) > 60
        assert len(issue.remediation) > 15
        assert issue.control
        assert issue.cwe.startswith("CWE-")
