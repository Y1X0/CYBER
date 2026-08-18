"""Infrastructure-as-code analysis (WP-D9).

Reads Terraform HCL, CloudFormation and Terraform plan JSON into one resource shape, then runs cloud
misconfiguration rules over it. No external binary and no cloud credentials: this analyses what a
repository *declares*, which is where a misconfiguration can still be fixed for free.

The counterpart is CSPM, which asks the same questions of a live account and sees what a human
changed in the console afterwards. Neither replaces the other.
"""

from guardian_scanner.iac.loaders import (
    load_cloudformation,
    load_path,
    load_terraform,
    load_terraform_plan,
)
from guardian_scanner.iac.model import Resource
from guardian_scanner.iac.rules import IacFinding, evaluate

__all__ = [
    "IacFinding",
    "Resource",
    "evaluate",
    "load_cloudformation",
    "load_path",
    "load_terraform",
    "load_terraform_plan",
]
