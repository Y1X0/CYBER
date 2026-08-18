"""A focused HCL2 reader for Terraform (WP-D9).

Not a Terraform implementation, and deliberately not trying to be one. A security scanner needs to
know which resources a configuration declares and what literal values their attributes carry; it
does not need to evaluate expressions, resolve modules, or produce a plan. Everything that cannot be
read as a literal is preserved as its source text, so a rule can distinguish "explicitly false" from
"a variable this scanner cannot resolve" — and a rule that cannot tell the difference must not claim
a finding.

Writing this rather than taking a dependency is a deliberate trade. An HCL library would parse more
of the language, but it would also decide, outside our review, what a scanner points at a customer's
infrastructure code is willing to do with it. The grammar a scanner needs is small: blocks,
attributes, and literal values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_BYTES = 2_000_000
MAX_DEPTH = 24

_IDENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_BLOCK_HEADER = re.compile(rf'^\s*({_IDENT})((?:\s+(?:"[^"\n]*"|{_IDENT}))*)\s*\{{\s*$')
_ATTRIBUTE = re.compile(rf"^\s*({_IDENT})\s*=\s*(.*)$")
_HEREDOC = re.compile(r"^<<[-~]?([A-Za-z_][A-Za-z0-9_]*)\s*$")
_HEREDOC_OPEN = re.compile(r"<<[-~]?([A-Za-z_][A-Za-z0-9_]*)[ \t]*(?=\n)")
_LABEL = re.compile(rf'"([^"\n]*)"|({_IDENT})')
# `versioning { enabled = true }` — a block written on one line. Common in generated configuration
# and in examples, and invisible to a line-oriented parser that expects `{` to end the line.
_INLINE_BLOCK = re.compile(
    rf'^(?P<indent>\s*)(?P<head>{_IDENT}(?:\s+(?:"[^"\n]*"|{_IDENT}))*)\s*\{{(?P<body>.*)\}}\s*$'
)


@dataclass
class Block:
    """One HCL block: `resource "aws_s3_bucket" "logs" { ... }`."""

    type: str
    labels: tuple[str, ...]
    attributes: dict[str, object] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)
    line: int = 0

    def nested(self, block_type: str) -> list[Block]:
        return [b for b in self.blocks if b.type == block_type]

    def get(self, name: str, default: object = None) -> object:
        return self.attributes.get(name, default)


class Unresolved(str):
    """An expression this reader did not evaluate, carried as its source text.

    A distinct type rather than a bare string so a rule can ask "is this literally false" and get
    the right answer for `false`, a different one for `var.enable_encryption`, and never mistake the
    second for the first. Silence about an unknown is correct; a finding about one is a guess.
    """

    __slots__ = ()


def parse(text: str) -> list[Block]:
    """Parse HCL into top-level blocks. Never raises: a file that will not parse yields nothing."""
    if len(text) > MAX_BYTES:
        return []
    lines = _expand_inline_blocks(_strip_comments(text).splitlines())
    blocks, _attributes, _index = _parse_body(lines, 0, depth=0)
    return blocks


# ── lexing ────────────────────────────────────────────────────────────────────────────────────────
def _strip_comments(text: str) -> str:  # noqa: C901 - one lexer, clearer whole than split up
    """Blank comments while preserving line count and string contents.

    `bucket = "https://example.com"` must not lose everything after `//`, and a `#` inside a string
    is data. Getting this wrong silently truncates configuration, and a rule cannot report on an
    attribute the parser threw away.

    Heredoc bodies are copied verbatim for the same reason: a `user_data` script starting with
    `#!/bin/sh` would otherwise have its first line erased as a comment, and the rules that read
    scripts would be looking at something the author never wrote.
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    heredoc_end: str | None = None

    while i < n:
        ch = text[i]
        if heredoc_end is not None:
            line_end = text.find("\n", i)
            line_end = n if line_end < 0 else line_end
            line = text[i:line_end]
            out.append(line)
            if line_end < n:
                out.append("\n")
            if line.strip() == heredoc_end:
                heredoc_end = None
            i = line_end + 1
            continue
        if quote is None and not in_line_comment and not in_block_comment:
            opener = _HEREDOC_OPEN.match(text, i)
            if opener is not None:
                out.append(opener.group(0))
                heredoc_end = opener.group(1)
                i = opener.end()
                continue
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif in_block_comment:
            if text.startswith("*/", i):
                out.append("  ")
                i += 2
                in_block_comment = False
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif quote is not None:
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
        elif ch == '"':
            quote = ch
            out.append(ch)
            i += 1
        elif text.startswith("/*", i):
            in_block_comment = True
            out.append("  ")
            i += 2
        elif text.startswith("//", i) or ch == "#":
            in_line_comment = True
            out.append(" ")
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _expand_inline_blocks(lines: list[str], depth: int = 0) -> list[str]:
    """Rewrite one-line blocks into the multi-line form the parser reads.

    Line numbers shift as a result, which is a real cost — but a block the parser cannot see is a
    rule that cannot fire, and a finding at a slightly wrong line beats no finding at all.
    """
    if depth > MAX_DEPTH:
        return lines
    expanded: list[str] = []
    changed = False
    for line in lines:
        match = _INLINE_BLOCK.match(line)
        if match is None or not _balanced(line):
            expanded.append(line)
            continue
        body = match.group("body").strip()
        if not body:
            expanded.append(line)
            continue
        changed = True
        indent = match.group("indent")
        expanded.append(f"{indent}{match.group('head')} {{")
        expanded.extend(f"{indent}  {part}" for part in _split_statements(body))
        expanded.append(f"{indent}}}")
    return _expand_inline_blocks(expanded, depth + 1) if changed else expanded


def _split_statements(body: str) -> list[str]:
    """Split a one-line block body into statements, respecting strings and nesting."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escape = False
    for ch in body:
        if quote is not None:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch == '"':
            quote = ch
            current.append(ch)
        elif ch in "[{(":
            depth += 1
            current.append(ch)
        elif ch in "]})":
            depth -= 1
            current.append(ch)
        elif ch in ",;" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _labels_of(raw: str) -> tuple[str, ...]:
    return tuple(quoted or bare for quoted, bare in _LABEL.findall(raw or ""))


def _balanced(text: str) -> bool:
    """Whether brackets close, ignoring anything inside a string."""
    depth = 0
    quote: str | None = None
    escape = False
    for ch in text:
        if quote is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch == '"':
            quote = ch
        elif ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
    return depth <= 0 and quote is None


# ── parsing ───────────────────────────────────────────────────────────────────────────────────────
def _parse_body(
    lines: list[str], start: int, depth: int
) -> tuple[list[Block], dict[str, object], int]:
    """Parse one body. Returns its child blocks, its own attributes, and where it ended."""
    blocks: list[Block] = []
    attributes: dict[str, object] = {}
    index = start

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped == "}":
            return blocks, attributes, index + 1

        header = _BLOCK_HEADER.match(line)
        if header and depth < MAX_DEPTH:
            block = Block(type=header.group(1), labels=_labels_of(header.group(2)), line=index + 1)
            block.blocks, block.attributes, index = _parse_body(lines, index + 1, depth + 1)
            blocks.append(block)
            continue

        attribute = _ATTRIBUTE.match(line)
        if attribute:
            name = attribute.group(1)
            value_text, index, is_heredoc = _read_value(lines, index, attribute.group(2))
            # A heredoc is text by definition. Running it through `_literal` would turn an inline
            # JSON policy into a dict — convenient until the heredoc holds a shell script, which
            # would then be parsed as something it is not.
            attributes[name] = value_text if is_heredoc else _literal(value_text)
            continue

        index += 1

    return blocks, attributes, index


def _read_value(lines: list[str], index: int, first: str) -> tuple[str, int, bool]:
    """Read one attribute value, continuing across lines for a list, object or heredoc.

    The third element says whether the value came from a heredoc, which the caller keeps as text.
    """
    heredoc = _HEREDOC.match(first.strip())
    if heredoc:
        terminator = heredoc.group(1)
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != terminator:
            body.append(lines[index])
            index += 1
        return "\n".join(body), index + 1, True

    value = first.rstrip()
    index += 1
    while not _balanced(value) and index < len(lines):
        value += "\n" + lines[index].rstrip()
        index += 1
    return value, index, False


def _literal(text: str) -> object:
    """Convert a value to a Python literal, or keep its source text as `Unresolved`."""
    value = text.strip()
    if not value:
        return Unresolved("")
    if value in {"true", "false"}:
        return value == "true"
    if value == "null":
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"' and "${" not in value:
        return _unescape(value[1:-1])
    if value.startswith("["):
        return _sequence(value)
    if value.startswith("{"):
        return _mapping(value)
    return Unresolved(value)


def _unescape(value: str) -> str:
    return (value.replace("\\n", "\n").replace("\\t", "\t")
                 .replace('\\"', '"').replace("\\\\", "\\"))


def _split_top_level(body: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escape = False
    for ch in body:
        if quote is not None:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch == '"':
            quote = ch
            current.append(ch)
        elif ch in "[{(":
            depth += 1
            current.append(ch)
        elif ch in "]})":
            depth -= 1
            current.append(ch)
        elif ch in ",\n" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _sequence(value: str) -> object:
    inner = value[1:-1] if value.endswith("]") else value[1:]
    return [_literal(item) for item in _split_top_level(inner)]


def _mapping(value: str) -> object:
    inner = value[1:-1] if value.endswith("}") else value[1:]
    result: dict[str, object] = {}
    for item in _split_top_level(inner):
        key, sep, raw = item.partition("=")
        if not sep:
            key, sep, raw = item.partition(":")
        if not sep:
            continue
        name = key.strip().strip('"')
        if name:
            result[name] = _literal(raw)
    return result
