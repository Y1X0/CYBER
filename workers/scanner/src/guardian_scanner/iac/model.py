"""One resource shape for every IaC dialect (WP-D9).

Terraform, CloudFormation and a Terraform plan all describe the same cloud objects in different
spellings. Normalizing them here means a rule is written once — "an S3 bucket that allows public
access" — instead of three times with three chances to disagree about what counts.

The normalization stops at the resource boundary on purpose. Attribute names are *not* translated
between dialects, because a mapping table that is 90% right produces findings that are confidently
wrong about the other 10%, and a rule can name both spellings in one line.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardian_scanner.iac.hcl import Unresolved


@dataclass
class Resource:
    """A declared cloud resource, whatever dialect declared it."""

    type: str                                   # "aws_s3_bucket" / "AWS::S3::Bucket"
    name: str
    dialect: str                                # "terraform" | "cloudformation" | "terraform-plan"
    attributes: dict[str, object] = field(default_factory=dict)
    blocks: dict[str, list[dict]] = field(default_factory=dict)   # nested HCL blocks by type
    path: str = ""
    line: int = 0

    # ── attribute access that knows what it does not know ────────────────────────────────────────
    def get(self, *names: str, default: object = None) -> object:
        """First present attribute among `names`, so a rule can accept both dialects' spellings."""
        for name in names:
            if name in self.attributes:
                return self.attributes[name]
        return default

    def is_true(self, *names: str) -> bool:
        return _truthy(self.get(*names))

    def is_false(self, *names: str) -> bool:
        """Explicitly false — not merely absent, and not an expression we could not evaluate.

        The distinction is the whole reason `Unresolved` exists. `encrypted = var.encrypt` is not
        evidence of anything, and reporting it as "encryption disabled" teaches a customer that the
        scanner guesses.
        """
        value = self.get(*names, default=_MISSING)
        if value is _MISSING or isinstance(value, Unresolved):
            return False
        return not _truthy(value)

    def missing(self, *names: str) -> bool:
        """True when no spelling of the attribute is present at all."""
        return all(name not in self.attributes for name in names)

    def unresolved(self, *names: str) -> bool:
        return isinstance(self.get(*names), Unresolved)

    def nested(self, block_type: str) -> list[dict]:
        return self.blocks.get(block_type, [])


class _Missing:
    __slots__ = ()


_MISSING = _Missing()


def _truthy(value: object) -> bool:
    if isinstance(value, Unresolved):
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "enabled", "1"}
    if isinstance(value, int | float):
        return bool(value)
    return bool(value)


def as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


def as_text(value: object) -> str:
    return value if isinstance(value, str) else ""
