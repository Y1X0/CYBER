"""Blank out comments and string literals before pattern matching (WP-D4).

v1 ran its regexes over raw lines, so a docstring describing `eval()` and a commented-out
`child_process.exec(` were reported as vulnerabilities. False positives are not a cosmetic problem
for a security product: a customer who finds two fabricated criticals stops reading the report, and
the real finding on page three is never seen. Masking is the cheapest structural fix — the text
keeps its exact shape (same length, same line numbers, same column offsets) with non-code regions
replaced by spaces, so a match in the masked text points at the identical position in the original.

This is a lexer, not a parser: it tracks quote state, escapes, and comment state. It does not need
to understand the grammar, and deliberately does not try — regex-based "strip comments" that use a
single `re.sub` get `"http://example.com"` wrong, and getting that wrong reintroduces exactly the
false positives this exists to remove.
"""

from __future__ import annotations

_PY_LIKE = {".py", ".pyi"}
_HASH_ONLY = {".rb", ".sh", ".bash", ".yml", ".yaml"}
_SLASH_AND_HASH = {".php"}          # PHP accepts both // and # for line comments
_C_LIKE = {".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".c", ".h", ".cpp", ".cs", ".kt", ".rs"}


def mask_non_code(text: str, suffix: str) -> str:
    """Return `text` with comments and string bodies replaced by spaces.

    Newlines are preserved so line numbers are unchanged, and every other character is replaced
    one-for-one so column offsets survive too.

    The comment markers are per language rather than a union of all of them. Treating `#` as a
    comment in JavaScript would blank the rest of any line using a private field (`this.#count`),
    which silently disables every rule on that line — a scanner that stops looking is worse than
    one that occasionally over-reports.
    """
    suffix = suffix.lower()
    if suffix in _PY_LIKE:
        return _mask(text, line_comments=("#",), block=None, triple_quotes=True)
    if suffix in _HASH_ONLY:
        return _mask(text, line_comments=("#",), block=None, triple_quotes=False)
    if suffix in _SLASH_AND_HASH:
        return _mask(text, line_comments=("//", "#"), block=("/*", "*/"), triple_quotes=False)
    if suffix in _C_LIKE:
        return _mask(text, line_comments=("//",), block=("/*", "*/"), triple_quotes=False)
    return text


def _blank(ch: str) -> str:
    return "\n" if ch == "\n" else " "


def _mask(  # noqa: C901 - a lexer's state machine is clearer as one function than as five
    text: str,
    *,
    line_comments: tuple[str, ...],
    block: tuple[str, str] | None,
    triple_quotes: bool,
) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None          # the delimiter currently open, "" if none
    in_line_comment = False
    in_block_comment = False

    while i < n:
        ch = text[i]

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        if in_block_comment:
            assert block is not None
            if text.startswith(block[1], i):
                out.append(" " * len(block[1]))
                i += len(block[1])
                in_block_comment = False
            else:
                out.append(_blank(ch))
                i += 1
            continue

        if quote is not None:
            if ch == "\\" and i + 1 < n:
                # An escape consumes the next character, so a trailing \" does not close the string.
                out.append(_blank(ch))
                out.append(_blank(text[i + 1]))
                i += 2
                continue
            if text.startswith(quote, i):
                out.append(" " * len(quote))
                i += len(quote)
                quote = None
                continue
            out.append(_blank(ch))
            i += 1
            continue

        # ── outside any string or comment ────────────────────────────────────────────────────────
        if block is not None and text.startswith(block[0], i):
            out.append(" " * len(block[0]))
            i += len(block[0])
            in_block_comment = True
            continue

        started_comment = False
        for marker in line_comments:
            if text.startswith(marker, i):
                out.append(" " * len(marker))
                i += len(marker)
                in_line_comment = True
                started_comment = True
                break
        if started_comment:
            continue

        if triple_quotes and (text.startswith('"""', i) or text.startswith("'''", i)):
            quote = text[i : i + 3]
            out.append("   ")
            i += 3
            continue

        if ch in ('"', "'", "`"):
            quote = ch
            out.append(" ")
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def suppressed_lines(text: str) -> frozenset[int]:
    """Line numbers carrying an explicit security suppression.

    `# nosec` is the established convention and is honoured. A generic `# noqa` is not: it is a
    style-linter directive, and treating it as a security waiver would let an unrelated formatting
    suppression silently delete a critical finding.
    """
    hits: set[int] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if "# nosec" in lowered or "#nosec" in lowered or "guardian:ignore" in lowered:
            hits.add(lineno)
    return frozenset(hits)
