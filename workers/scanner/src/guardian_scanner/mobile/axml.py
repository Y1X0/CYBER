"""A compact decoder for Android binary XML (AXML) — used to read `AndroidManifest.xml` from an APK.

An APK stores its manifest as Android's binary resource-XML format, not text, so static analysis
cannot work without decoding it. This is a focused, dependency-free reader: it walks the string pool
and the start-element/attribute chunks and yields a normalized element tree (tag local-name +
attributes keyed by local-name, values resolved to str/bool/int). It intentionally does not resolve
`resources.arsc` references — an unresolved `@ref` attribute is reported as a reference
marker, enough to know a setting is present (e.g. a networkSecurityConfig is declared).

Format reference: ResChunk headers, RES_STRING_POOL_TYPE (0x0001), RES_XML_TYPE (0x0003) with
START_ELEMENT (0x0102) / END_ELEMENT (0x0103) nodes. Bounded and defensive: malformed input raises
`AxmlError` rather than looping or crashing the scan.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_RES_STRING_POOL = 0x0001
_RES_XML_TYPE = 0x0003
_XML_START_ELEMENT = 0x0102
_XML_END_ELEMENT = 0x0103
_XML_CDATA = 0x0104
_UTF8_FLAG = 1 << 8

# Attribute typed-value data types (subset we care about).
_TYPE_REFERENCE = 0x01
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOL = 0x12

_MAX_STRINGS = 200_000
_MAX_NODES = 500_000


class AxmlError(ValueError):
    """The bytes are not decodable Android binary XML."""


@dataclass
class Element:
    tag: str
    attrs: dict[str, object] = field(default_factory=dict)
    children: list[Element] = field(default_factory=list)
    # Concatenated CDATA/text of the element. Empty for most manifest nodes; populated for leaves
    # like a network-security-config `<domain>` whose hostname is text, not an attribute.
    text: str = ""


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _read_string_pool(data: bytes, off: int) -> list[str]:
    # ResChunk_header: type(u16) headerSize(u16) size(u32); then string_count, style_count, flags,
    # strings_start, styles_start; then string_count u32 offsets; then the string data.
    _type = _u16(data, off)
    size = _u32(data, off + 4)
    string_count = _u32(data, off + 8)
    flags = _u32(data, off + 16)
    strings_start = _u32(data, off + 20)
    if string_count > _MAX_STRINGS:
        raise AxmlError("string pool too large")
    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_base = off + 28
    data_base = off + strings_start
    end = off + size
    out: list[str] = []
    for i in range(string_count):
        so = _u32(data, offsets_base + i * 4)
        p = data_base + so
        if p < 0 or p >= end:
            out.append("")
            continue
        try:
            out.append(_decode_pool_string(data, p, is_utf8))
        except (struct.error, UnicodeDecodeError, IndexError):
            out.append("")
    return out


def _decode_pool_string(data: bytes, p: int, is_utf8: bool) -> str:
    if is_utf8:
        # (u8 or 2-byte) char length, then (u8 or 2-byte) byte length, then bytes, then NUL.
        n_chars, p = _len8(data, p)
        n_bytes, p = _len8(data, p)
        return data[p:p + n_bytes].decode("utf-8", "replace")
    # UTF-16LE: (u16 or 4-byte) length in code units, then bytes, then 0x0000.
    n, p = _len16(data, p)
    return data[p:p + n * 2].decode("utf-16-le", "replace")


def _len8(data: bytes, p: int) -> tuple[int, int]:
    x = data[p]
    p += 1
    if x & 0x80:
        x = ((x & 0x7F) << 8) | data[p]
        p += 1
    return x, p


def _len16(data: bytes, p: int) -> tuple[int, int]:
    x = _u16(data, p)
    p += 2
    if x & 0x8000:
        x = ((x & 0x7FFF) << 16) | _u16(data, p)
        p += 2
    return x, p


def _s(pool: list[str], idx: int) -> str:
    return pool[idx] if 0 <= idx < len(pool) else ""


def parse_axml(data: bytes) -> Element:
    """Decode AXML bytes into a normalized `Element` tree (synthetic root). Raises AxmlError."""
    if len(data) < 8:
        raise AxmlError("too short")
    magic = _u16(data, 0)
    if magic != _RES_XML_TYPE:
        raise AxmlError("not RES_XML_TYPE")
    total = _u32(data, 4)
    if total > len(data):
        total = len(data)

    # First locate the string pool (usually the first inner chunk).
    pool: list[str] = []
    off = _u16(data, 2)  # header size of the XML chunk
    nodes = 0
    root = Element(tag="#root")
    stack: list[Element] = [root]

    while off + 8 <= total:
        ctype = _u16(data, off)
        _header_size = _u16(data, off + 2)
        csize = _u32(data, off + 4)
        if csize < 8 or off + csize > total:
            break
        if ctype == _RES_STRING_POOL and not pool:
            pool = _read_string_pool(data, off)
        elif ctype == _XML_START_ELEMENT:
            nodes += 1
            if nodes > _MAX_NODES:
                raise AxmlError("too many nodes")
            el = _read_start_element(data, off, pool)
            stack[-1].children.append(el)
            stack.append(el)
        elif ctype == _XML_END_ELEMENT:
            if len(stack) > 1:
                stack.pop()
        elif ctype == _XML_CDATA and len(stack) > 1 and off + 20 <= total:
            # CDATA node: after the 8-byte header come lineNumber(u32) + comment(u32), then the
            # text's string-pool index (u32). Attach it to the currently open element.
            stack[-1].text += _s(pool, _u32(data, off + 16))
        off += csize
    return root


def _read_start_element(data: bytes, off: int, pool: list[str]) -> Element:
    # After the 8-byte ResChunk header and 8 bytes (lineNumber, comment) comes the element body:
    # ns(u32) name(u32) attrStart(u16) attrSize(u16) attrCount(u16) id/class/style(3xu16).
    base = off + 16
    name_idx = _u32(data, base + 4)
    attr_start = _u16(data, base + 8)
    attr_count = _u16(data, base + 12)
    el = Element(tag=_localname(_s(pool, name_idx)))
    ap = base + attr_start
    for _ in range(attr_count):
        ns_idx = _u32(data, ap)
        aname_idx = _u32(data, ap + 4)
        raw_val_idx = _u32(data, ap + 8)
        data_type = data[ap + 15]
        adata = _u32(data, ap + 16)
        key = _localname(_s(pool, aname_idx)) or f"attr{ns_idx}"
        el.attrs[key] = _attr_value(data_type, adata, raw_val_idx, pool)
        ap += 20
    return el


def _attr_value(data_type: int, adata: int, raw_val_idx: int, pool: list[str]) -> object:
    if data_type == _TYPE_STRING:
        return _s(pool, adata) if adata != 0xFFFFFFFF else _s(pool, raw_val_idx)
    if data_type == _TYPE_INT_BOOL:
        return adata != 0
    if data_type in (_TYPE_INT_DEC, _TYPE_INT_HEX):
        return adata if adata < 0x80000000 else adata - 0x100000000
    if data_type == _TYPE_REFERENCE:
        return f"@ref/0x{adata:08x}"
    if raw_val_idx != 0xFFFFFFFF:
        return _s(pool, raw_val_idx)
    return adata


def _localname(name: str) -> str:
    # Names arrive as local names already; strip a namespace prefix if any.
    return name.split(":", 1)[1] if ":" in name else name
