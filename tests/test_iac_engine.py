"""Infrastructure-as-code analysis (WP-D9).

The rule this file exists to protect is *silence on the unknown*. `storage_encrypted = var.encrypt`
tells the scanner nothing, and a scanner that reports it as "encryption disabled" is guessing at a
customer's infrastructure — which is how a security tool teaches people to ignore it. Half the tests
below are about what must NOT be reported.

The other half is the dialect surface: Terraform HCL, CloudFormation (whose intrinsic tags make a
plain YAML loader refuse the document outright), and Terraform plan JSON, where variables are
already resolved and the same rules therefore give a stronger answer.
"""

from __future__ import annotations

import json

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.iac_engine import IacEngine
from guardian_scanner.iac import evaluate, load_cloudformation, load_terraform, load_terraform_plan
from guardian_scanner.iac.hcl import Unresolved, parse


def scan(text: str):
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=text)
    return list(IacEngine().run(ctx))


def rules(text: str) -> set[str]:
    return {f.location["rule"] for f in scan(text)}


def _tf_rules(text: str) -> set[str]:
    return {f.rule for r in load_terraform(text, "main.tf") for f in evaluate(r)}


# ── silence on the unknown ────────────────────────────────────────────────────────────────────────
def test_an_unresolved_variable_produces_no_finding():
    """The single most important property. `var.encrypt` is not evidence of anything."""
    assert _tf_rules("""
resource "aws_db_instance" "db" {
  publicly_accessible = var.expose
  storage_encrypted   = var.encrypt
}
""") == set()


def test_the_same_resource_with_literal_values_is_reported():
    """Proving the previous test is about the unknown, not about the rule being broken."""
    found = _tf_rules("""
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
""")
    assert {"iac-rds-public", "iac-rds-unencrypted"} <= found


def test_a_credential_read_from_a_variable_is_not_a_hardcoded_credential():
    """`password = var.db_password` is the correct pattern. Firing on it trains people to ignore
    the rule, which costs more than the finding is worth."""
    assert "iac-hardcoded-credential" not in _tf_rules("""
resource "aws_db_instance" "db" {
  password = var.db_password
}
""")


def test_a_literal_credential_is_reported():
    assert "iac-hardcoded-credential" in _tf_rules("""
resource "aws_db_instance" "db" {
  password = "hunter2-not-a-variable"
}
""")


def test_a_secret_arn_reference_is_not_a_credential():
    """`password = "arn:aws:secretsmanager:..."` names where the secret lives, not the secret."""
    assert "iac-hardcoded-credential" not in _tf_rules("""
resource "aws_db_instance" "db" {
  password = "arn:aws:secretsmanager:us-east-1:1234:secret:db-AbCdEf"
}
""")


def test_a_well_configured_stack_produces_nothing():
    assert _tf_rules("""
resource "aws_s3_bucket" "logs" {
  bucket = "app-logs"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  versioning {
    enabled = true
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
""") == set()


# ── network exposure, graded by what is exposed ───────────────────────────────────────────────────
def _sg(from_port: int, to_port: int, cidr: str = "0.0.0.0/0", protocol: str = "tcp") -> str:
    return f"""
resource "aws_security_group" "x" {{
  ingress {{
    from_port   = {from_port}
    to_port     = {to_port}
    protocol    = "{protocol}"
    cidr_blocks = ["{cidr}"]
  }}
}}
"""


def test_ssh_open_to_the_internet_is_critical():
    findings = [f for r in load_terraform(_sg(22, 22), "m.tf") for f in evaluate(r)]
    assert [f.rule for f in findings] == ["iac-open-admin-port"]
    assert findings[0].severity is Severity.CRITICAL
    assert "SSH (22)" in findings[0].title


def test_a_database_port_open_to_the_internet_is_critical():
    findings = [f for r in load_terraform(_sg(5432, 5432), "m.tf") for f in evaluate(r)]
    assert findings[0].severity is Severity.CRITICAL
    assert "PostgreSQL" in findings[0].title


def test_https_open_to_the_internet_is_only_worth_confirming():
    """A public web listener is the normal case. Reporting it as critical is how a report becomes
    noise that hides the open database three rows down."""
    findings = [f for r in load_terraform(_sg(443, 443), "m.tf") for f in evaluate(r)]
    assert [f.rule for f in findings] == ["iac-open-ingress"]
    assert findings[0].severity is Severity.MEDIUM


def test_all_ports_open_is_critical():
    findings = [f for r in load_terraform(_sg(0, 65535, protocol="-1"), "m.tf")
                for f in evaluate(r)]
    assert findings[0].rule in {"iac-open-all-ports", "iac-open-admin-port"}
    assert findings[0].severity is Severity.CRITICAL


def test_a_restricted_cidr_is_not_reported():
    assert [f for r in load_terraform(_sg(22, 22, "10.0.0.0/8"), "m.tf") for f in evaluate(r)] == []


def test_a_port_range_covering_an_admin_port_is_caught():
    """`from_port = 0, to_port = 9000` includes SSH even though nothing says 22."""
    findings = [f for r in load_terraform(_sg(0, 9000), "m.tf") for f in evaluate(r)]
    assert findings[0].rule == "iac-open-admin-port"


# ── storage and identity ──────────────────────────────────────────────────────────────────────────
def test_public_read_write_bucket_outranks_public_read():
    read = next(f for r in load_terraform(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }', "m.tf") for f in evaluate(r)
        if f.rule == "iac-s3-public-acl")
    write = next(f for r in load_terraform(
        'resource "aws_s3_bucket" "b" { acl = "public-read-write" }', "m.tf") for f in evaluate(r)
        if f.rule == "iac-s3-public-acl")
    assert read.severity is Severity.HIGH
    assert write.severity is Severity.CRITICAL


def test_disabling_the_public_access_block_is_reported():
    found = _tf_rules("""
resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls  = false
  block_public_policy = false
}
""")
    assert "iac-s3-public-access-block-disabled" in found


def test_iam_admin_wildcard():
    found = _tf_rules("""
resource "aws_iam_policy" "admin" {
  policy = <<EOT
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOT
}
""")
    assert "iac-iam-admin-wildcard" in found


def test_a_scoped_iam_policy_is_not_reported():
    assert _tf_rules("""
resource "aws_iam_policy" "scoped" {
  policy = <<EOT
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}
EOT
}
""") == set()


def test_a_deny_statement_with_a_wildcard_is_not_a_grant():
    """`Effect: Deny` on `Action: *` is a guardrail, not a privilege."""
    assert "iac-iam-admin-wildcard" not in _tf_rules("""
resource "aws_iam_policy" "guard" {
  policy = <<EOT
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}
EOT
}
""")


def test_a_resource_policy_trusting_every_principal():
    assert "iac-iam-public-principal" in _tf_rules("""
resource "aws_iam_policy" "open" {
  policy = <<EOT
{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}
EOT
}
""")


def test_eks_public_api_endpoint():
    assert "iac-eks-public-api" in _tf_rules("""
resource "aws_eks_cluster" "c" {
  vpc_config {
    endpoint_public_access = true
  }
}
""")


def test_cloudtrail_single_region():
    assert "iac-cloudtrail-single-region" in _tf_rules("""
resource "aws_cloudtrail" "t" {
  name = "audit"
  is_multi_region_trail = false
}
""")


def test_azure_and_gcp_rules_fire():
    assert "iac-azure-storage-http" in _tf_rules("""
resource "azurerm_storage_account" "s" {
  enable_https_traffic_only = false
}
""")
    assert "iac-gcs-public" in _tf_rules("""
resource "google_storage_bucket_iam_member" "m" {
  member = "allUsers"
}
""")
    assert "iac-open-ingress" in _tf_rules("""
resource "google_compute_firewall" "f" {
  source_ranges = ["0.0.0.0/0"]
}
""")


# ── the HCL reader ────────────────────────────────────────────────────────────────────────────────
def test_a_url_in_a_string_is_not_a_comment():
    """`//` inside a string would otherwise truncate the rest of the block, and a rule cannot
    report on an attribute the parser threw away."""
    block = parse('resource "x" "y" {\n  endpoint = "https://example.com/path"\n  acl = "public-read"\n}\n')[0]
    assert block.attributes["endpoint"] == "https://example.com/path"
    assert block.attributes["acl"] == "public-read"


def test_a_hash_inside_a_string_is_not_a_comment():
    block = parse('resource "x" "y" {\n  color = "#ff0000"\n  acl = "public-read"\n}\n')[0]
    assert block.attributes["color"] == "#ff0000"
    assert block.attributes["acl"] == "public-read"


def test_comments_are_removed():
    block = parse("""
# leading comment with a } brace
resource "x" "y" {
  acl = "private"   // trailing
  /* block
     comment */
  name = "n"
}
""")[0]
    assert block.attributes == {"acl": "private", "name": "n"}


def test_literals_are_typed():
    block = parse("""
resource "x" "y" {
  count    = 3
  ratio    = 1.5
  enabled  = true
  disabled = false
  nothing  = null
  text     = "hello"
  list     = ["a", "b"]
  map      = { k = "v" }
  expr     = var.something
  interp   = "prefix-${var.name}"
}
""")[0]
    a = block.attributes
    assert a["count"] == 3 and a["ratio"] == 1.5
    assert a["enabled"] is True and a["disabled"] is False and a["nothing"] is None
    assert a["text"] == "hello" and a["list"] == ["a", "b"] and a["map"] == {"k": "v"}
    assert isinstance(a["expr"], Unresolved)
    # An interpolated string is not a literal: its value depends on something we did not evaluate.
    assert isinstance(a["interp"], Unresolved)


def test_a_multi_line_list_is_read_whole():
    block = parse("""
resource "x" "y" {
  cidr_blocks = [
    "10.0.0.0/8",
    "0.0.0.0/0",
  ]
}
""")[0]
    assert block.attributes["cidr_blocks"] == ["10.0.0.0/8", "0.0.0.0/0"]


def test_a_heredoc_stays_text():
    """Running a heredoc through the literal parser turns an inline JSON policy into a dict —
    convenient until the heredoc holds a shell script."""
    block = parse('resource "x" "y" {\n  script = <<EOT\n#!/bin/sh\necho hi\nEOT\n}\n')[0]
    assert block.attributes["script"] == "#!/bin/sh\necho hi"


def test_unparseable_input_yields_nothing_rather_than_raising():
    assert parse("this is not HCL at all {{{") == []
    assert scan("}}}}") == []


# ── CloudFormation ────────────────────────────────────────────────────────────────────────────────
CFN = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: false
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""


def test_cloudformation_resources_are_analysed():
    found = {f.rule for r in load_cloudformation(CFN, "stack.yaml") for f in evaluate(r)}
    assert {"iac-s3-public-acl", "iac-rds-public", "iac-rds-unencrypted",
            "iac-open-admin-port"} <= found


def test_intrinsic_tags_do_not_break_the_loader():
    """`!Ref` and friends make yaml.safe_load refuse the whole document, so a template using them —
    which is nearly all of them — would silently scan as empty."""
    template = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: !Ref ExposeDatabase
      StorageEncrypted: !If [IsProd, true, false]
      MasterUserPassword: !Sub '${Password}'
"""
    resources = load_cloudformation(template, "stack.yaml")
    assert len(resources) == 1
    # An intrinsic is an expression, so it is unknown for the same reason `var.x` is.
    assert resources[0].unresolved("PubliclyAccessible")
    assert [f for r in resources for f in evaluate(r)] == []


def test_the_cloudformation_loader_constructs_no_python_objects():
    """A template is a file the customer did not necessarily write. `yaml.load` on it would be
    remote code execution triggered by a scan."""
    malicious = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  X: !!python/object/apply:os.system ['id']\n"
    )
    assert load_cloudformation(malicious, "stack.yaml") == []


def test_a_kubernetes_manifest_is_not_mistaken_for_a_template():
    manifest = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"
    assert load_cloudformation(manifest, "pod.yaml") == []


# ── Terraform plan ────────────────────────────────────────────────────────────────────────────────
def test_a_terraform_plan_resolves_what_the_source_could_not():
    """The same configuration whose variables made it unanalysable becomes a definite answer once
    CI produces a plan — which is the reason the plan loader exists."""
    plan = {
        "terraform_version": "1.7.0",
        "planned_values": {"root_module": {
            "resources": [{
                "type": "aws_db_instance", "name": "db",
                "values": {"publicly_accessible": True, "storage_encrypted": False},
            }],
            "child_modules": [{"resources": [{
                "type": "aws_s3_bucket", "name": "data", "values": {"acl": "public-read"},
            }]}],
        }},
    }
    resources = load_terraform_plan(json.dumps(plan), "plan.json")
    found = {f.rule for r in resources for f in evaluate(r)}
    assert {"iac-rds-public", "iac-rds-unencrypted", "iac-s3-public-acl"} <= found
    # Child modules are where most real infrastructure lives.
    assert any(r.name == "data" for r in resources)


# ── engine wiring ─────────────────────────────────────────────────────────────────────────────────
def test_findings_carry_the_engine_and_a_resource_address():
    findings = scan('resource "aws_s3_bucket" "b" { acl = "public-read" }')
    assert findings and findings[0].engine is EngineKey.IAC
    assert findings[0].location["resource"] == "aws_s3_bucket.b"
    assert findings[0].evidence["detail"]["dialect"] == "terraform"
    assert "Remediation:" in findings[0].description


def test_the_engine_reads_a_directory(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" { acl = "public-read" }')
    (tmp_path / "stack.yaml").write_text(CFN)
    (tmp_path / "readme.md").write_text("not infrastructure")
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      workspace_path=str(tmp_path))
    found = {f.location["rule"] for f in IacEngine().run(ctx)}
    assert "iac-s3-public-acl" in found
    assert "iac-open-admin-port" in found


def test_the_engine_reports_its_rule_count():
    health = IacEngine().health()
    assert health.ok is True and "rules" in health.detail


@pytest.mark.parametrize("kind", ["repo", "k8s_manifest"])
def test_supported_asset_kinds(kind):
    assert IacEngine().supports(kind) is True


def test_unsupported_asset_kind():
    assert IacEngine().supports("web") is False
