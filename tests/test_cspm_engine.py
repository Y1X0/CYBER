"""The CSPM engine over a collector export (WP-D8).

`test_cloud_posture.py` tests each rule. This tests the engine: that it reads the AWS API's own
shapes, that the legacy hand-written snapshot still works because assets carry it, and that a
snapshot it cannot read is an error rather than a clean report.
"""

from __future__ import annotations

import json

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.cspm_engine import CloudSnapshotError, CspmEngine

# What a read-only collector writes down: the responses, unmodified.
EXPORT = {
    "provider": "aws",
    "account_id": "123456789012",
    "resources": {
        "Buckets": [
            {"Name": "customer-exports",
             "Policy": json.dumps({"Statement": [
                 {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:PutObject"],
                  "Resource": "arn:aws:s3:::customer-exports/*"}]}),
             "Versioning": {"Status": "Enabled"},
             "ServerSideEncryptionConfiguration": {"Rules": [{}]}},
            {"Name": "private-logs",
             "Versioning": {"Status": "Enabled"},
             "ServerSideEncryptionConfiguration": {"Rules": [{}]}},
        ],
        "SecurityGroups": [
            {"GroupId": "sg-01", "GroupName": "bastion", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"GroupId": "sg-02", "GroupName": "web", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        ],
        "iam": {
            "UserDetailList": [
                {"UserName": "ci-deploy", "UserPolicyList": [
                    {"PolicyName": "deploy", "PolicyDocument": {"Statement": [
                        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"],
                         "Resource": "*"}]}}]},
            ],
            "CredentialReport": [
                {"user": "<root_account>", "mfa_active": "false",
                 "access_key_1_active": "false"},
            ],
        },
        "DBInstances": [
            {"DBInstanceIdentifier": "orders", "PubliclyAccessible": True,
             "StorageEncrypted": True, "BackupRetentionPeriod": 7, "Engine": "postgres"},
        ],
        "trailList": [
            {"Name": "audit", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True},
        ],
    },
}

LEGACY = {
    "provider": "aws",
    "storage": [{"name": "b1", "public": True, "encrypted": False}],
    "iam": {"users": [{"name": "svc", "mfa": False, "policies": ["*"]}]},
    "network": [{"name": "sg1", "ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}],
    "logging": {"cloudtrail_enabled": False},
}


def _ctx(*, inline=None, config=None):
    return ScanContext(scan_id="t", asset_kind="cloud_account", asset_identifier="aws:acct",
                       inline_content=inline, asset_config=config or {})


@pytest.fixture(scope="module")
def findings():
    return list(CspmEngine().run(_ctx(config={"cloud_config": EXPORT})))


def _rules(findings) -> set[str]:
    return {f.location["rule"] for f in findings}


def test_the_export_produces_the_findings_it_should(findings):
    assert _rules(findings) == {
        "s3-public-policy", "sg-admin-port-open", "iam-escalation", "iam-root-no-mfa", "rds-public",
    }


def test_the_correctly_configured_resources_produce_nothing(findings):
    """A private bucket, a web security group, a multi-region validated trail, a root account with
    no access key — all present in the export, none reported."""
    resources = {f.location["resource"] for f in findings}
    assert "private-logs" not in resources
    assert "sg-02" not in resources


def test_the_writable_public_bucket_is_critical(findings):
    bucket = next(f for f in findings if f.location["rule"] == "s3-public-policy")
    assert bucket.base_severity == Severity.CRITICAL


def test_every_finding_carries_its_service_resource_and_control(findings):
    for finding in findings:
        assert finding.engine == EngineKey.CSPM
        assert finding.location["service"] in ("s3", "ec2", "iam", "rds", "account")
        assert finding.location["resource"]
        assert finding.references["cis"]
        assert "Remediation:" in finding.description


def test_the_engine_still_requires_authorization():
    assert CspmEngine().requires_authorization is True


def test_the_legacy_snapshot_still_works():
    """Assets in the database carry this shape. It keeps working; it simply cannot express a
    policy document, an ACL, or a port range."""
    findings = list(CspmEngine().run(_ctx(inline=json.dumps(LEGACY))))
    titles = " ".join(f.title for f in findings)
    assert "Publicly accessible storage" in titles
    assert "Over-permissioned IAM" in titles
    assert "Audit logging disabled" in titles


def test_an_unreadable_snapshot_raises_rather_than_reporting_a_clean_account():
    """The previous engine returned None here, so a truncated export produced an empty finding list
    that the orchestrator recorded as a successful scan."""
    with pytest.raises(CloudSnapshotError, match="not valid JSON"):
        list(CspmEngine().run(_ctx(inline="{ truncated")))


def test_no_snapshot_at_all_is_not_an_error():
    """An asset with no collector export yet has not failed; it has nothing to assess."""
    assert list(CspmEngine().run(_ctx())) == []
