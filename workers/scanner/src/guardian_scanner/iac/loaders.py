"""Turn IaC files into `Resource`s (WP-D9).

Three dialects, one output shape:

* **Terraform HCL** — what a repository holds.
* **CloudFormation** — YAML or JSON, with intrinsic function tags (`!Ref`, `!GetAtt`, `!Sub`) that a
  plain YAML loader refuses outright.
* **Terraform plan JSON** — what CI actually has, and the only one of the three where variables and
  modules are already resolved. A plan is the strongest input this engine can get.

The CloudFormation loader constructs no Python objects from the document. `yaml.safe_load` with an
added multi-constructor keeps intrinsics as data; `yaml.load` on a customer's template would be
arbitrary code execution triggered by a file the customer did not write.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from guardian_scanner.iac.hcl import Block, Unresolved, parse
from guardian_scanner.iac.model import Resource

MAX_FILE_BYTES = 2_000_000
MAX_RESOURCES = 5_000

TERRAFORM_SUFFIXES = (".tf",)
CFN_SUFFIXES = (".yaml", ".yml", ".json", ".template")
_CFN_NAME_HINTS = ("cloudformation", "cfn", "template", "stack")


# ── Terraform ─────────────────────────────────────────────────────────────────────────────────────
def load_terraform(text: str, path: str) -> list[Resource]:
    resources: list[Resource] = []
    for block in parse(text):
        if block.type == "resource" and len(block.labels) >= 2:
            resources.append(_from_block(block, block.labels[0], block.labels[1], path))
        elif block.type in {"provider", "module", "data"} and block.labels:
            # A provider block is where a static access key gets committed, and a module source is
            # where a supply-chain decision is made — both are worth a rule.
            resources.append(_from_block(block, f"terraform_{block.type}", block.labels[0], path))
    return resources[:MAX_RESOURCES]


def _from_block(block: Block, type_name: str, name: str, path: str) -> Resource:
    nested: dict[str, list[dict]] = {}
    for child in block.blocks:
        nested.setdefault(child.type, []).append(_flatten(child))
    return Resource(
        type=type_name, name=name, dialect="terraform",
        attributes=dict(block.attributes), blocks=nested, path=path, line=block.line,
    )


def _flatten(block: Block) -> dict:
    """A nested block as a dict, with its own children under their type names."""
    data = dict(block.attributes)
    for child in block.blocks:
        data.setdefault(child.type, []).append(_flatten(child))  # type: ignore[union-attr]
    return data


# ── CloudFormation ────────────────────────────────────────────────────────────────────────────────
class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that keeps `!Ref`-style intrinsics as data instead of refusing the document."""


def _intrinsic(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> object:
    del loader
    # An intrinsic is an expression, so it is Unresolved for exactly the same reason a Terraform
    # variable reference is: a rule must not read `!Ref EnableEncryption` as "encryption off".
    return Unresolved(f"!{tag_suffix}")


_CfnLoader.add_multi_constructor("!", _intrinsic)


def load_cloudformation(text: str, path: str) -> list[Resource]:
    try:
        doc = yaml.load(text, Loader=_CfnLoader)  # noqa: S506 - SafeLoader subclass, see above
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    raw_resources = doc.get("Resources")
    if not isinstance(raw_resources, dict):
        return []

    resources: list[Resource] = []
    for name, body in raw_resources.items():
        if not isinstance(body, dict):
            continue
        properties = body.get("Properties")
        resources.append(Resource(
            type=str(body.get("Type") or ""),
            name=str(name),
            dialect="cloudformation",
            attributes=dict(properties) if isinstance(properties, dict) else {},
            path=path,
        ))
        if len(resources) >= MAX_RESOURCES:
            break
    return resources


def looks_like_cloudformation(text: str) -> bool:
    """A YAML file is only a template if it says so — a Kubernetes manifest is also YAML."""
    head = text[:4000]
    return "AWSTemplateFormatVersion" in head or ('"Resources"' in head or "\nResources:" in head)


# ── Terraform plan ────────────────────────────────────────────────────────────────────────────────
def load_terraform_plan(text: str, path: str) -> list[Resource]:
    """`terraform show -json`. Variables and modules are already resolved, so nothing is Unresolved
    and a rule's answer is about what will actually be created."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []

    resources: list[Resource] = []

    def walk(module: dict) -> None:
        for item in module.get("resources") or []:
            if not isinstance(item, dict):
                continue
            values = item.get("values")
            resources.append(Resource(
                type=str(item.get("type") or ""),
                name=str(item.get("name") or ""),
                dialect="terraform-plan",
                attributes=dict(values) if isinstance(values, dict) else {},
                path=path,
            ))
        for child in module.get("child_modules") or []:
            if isinstance(child, dict):
                walk(child)

    planned = doc.get("planned_values") or doc.get("values") or {}
    root = planned.get("root_module") if isinstance(planned, dict) else None
    if isinstance(root, dict):
        walk(root)
    return resources[:MAX_RESOURCES]


def is_terraform_plan(text: str) -> bool:
    head = text[:2000]
    return '"planned_values"' in head or '"terraform_version"' in head


# ── directory walk ────────────────────────────────────────────────────────────────────────────────
_SKIP_DIRS = {".git", "node_modules", ".terraform", "vendor", "__pycache__", ".venv", "venv"}


def load_path(root: Path) -> list[Resource]:
    """Every IaC resource under `root`. A file that will not parse yields nothing, not an error."""
    resources: list[Resource] = []
    if root.is_file():
        return _load_file(root, root.name)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TERRAFORM_SUFFIXES + CFN_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        resources.extend(_load_file(path, str(path.relative_to(root))))
        if len(resources) >= MAX_RESOURCES:
            break
    return resources


def _load_file(path: Path, relative: str) -> list[Resource]:
    try:
        text = path.read_text("utf-8", "ignore")
    except OSError:
        return []
    suffix = path.suffix.lower()
    if suffix in TERRAFORM_SUFFIXES:
        return load_terraform(text, relative)
    if suffix == ".json":
        if is_terraform_plan(text):
            return load_terraform_plan(text, relative)
        if looks_like_cloudformation(text):
            return load_cloudformation(text, relative)
        return []
    if looks_like_cloudformation(text) or any(h in path.name.lower() for h in _CFN_NAME_HINTS):
        return load_cloudformation(text, relative)
    return []
