"""Keyset paging for the newest-first list endpoints (WP-G2).

Every list endpoint in this API orders by `created_at DESC` and then either returned everything
(`assets`, `customers`) or stopped at a hard cap with no way to see past it and no indication that
it had stopped (`scans`, `discovery`, `reports`). Both are wrong in the same way: the caller cannot
tell the difference between "that is all of them" and "that is all you are getting".

Keyset rather than `OFFSET`, for the same reason WP-F2's findings pages are: `OFFSET 10000` makes
the database walk ten thousand rows to discard them, and a row inserted between two requests shifts
every subsequent page by one, so a client paging through an estate silently skips assets.

The cursor is `(created_at, id)`. `created_at` alone is not a total order — two assets discovered in
the same transaction share a timestamp, and a page boundary that lands between them drops one.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import uuid
from dataclasses import dataclass

from fastapi import HTTPException, Response, status
from guardian_core import quota
from sqlalchemy import tuple_


class InvalidCursor(ValueError):
    """The cursor did not come from here, or has been edited."""


@dataclass(frozen=True)
class TimeCursor:
    created_at: dt.datetime
    id: uuid.UUID


def encode_cursor(created_at: dt.datetime, row_id: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{created_at.isoformat()}|{row_id}".encode()).decode()


def decode_cursor(raw: str) -> TimeCursor:
    """Refuse an unreadable cursor rather than starting again from the top.

    Silently restarting is how a client paging through 40,000 assets processes the first page
    forever and reports success.
    """
    try:
        decoded = base64.urlsafe_b64decode(raw.encode()).decode()
        timestamp, _, row_id = decoded.partition("|")
        return TimeCursor(dt.datetime.fromisoformat(timestamp), uuid.UUID(row_id))
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InvalidCursor(f"the cursor is not one this API issued: {exc}") from exc


def apply_cursor(query, model, cursor: TimeCursor | None):  # noqa: ANN001, ANN201
    """Continue strictly after the cursor row, in `(created_at DESC, id DESC)` order."""
    if cursor is None:
        return query
    return query.filter(
        tuple_(model.created_at, model.id) < tuple_(cursor.created_at, cursor.id)
    )


def order_newest_first(query, model):  # noqa: ANN001, ANN201
    return query.order_by(model.created_at.desc(), model.id.desc())


def paginate(response: Response, rows: list, limit: int) -> list:
    """Trim the one extra row that was fetched to detect a next page, and say what was found.

    `X-Has-More` is the part that matters: a page that is exactly `limit` long is otherwise
    indistinguishable from the end of the data.
    """
    has_more = len(rows) > limit
    page = rows[:limit]
    response.headers["X-Has-More"] = "true" if has_more else "false"
    response.headers["X-Page-Limit"] = str(limit)
    if has_more and page:
        last = page[-1]
        response.headers["X-Next-Cursor"] = encode_cursor(last.created_at, last.id)
    return page


def page_request(limit: int | None, cursor: str | None, *,
                 maximum: int) -> tuple[int, TimeCursor | None]:
    """Read the paging arguments, refusing the ones that cannot mean what they say."""
    try:
        size = quota.page_size(limit, maximum=maximum, default=maximum)
    except quota.InvalidPageSize as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    try:
        decoded = decode_cursor(cursor) if cursor else None
    except InvalidCursor as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return size, decoded


__all__ = [
    "InvalidCursor",
    "TimeCursor",
    "apply_cursor",
    "decode_cursor",
    "encode_cursor",
    "order_newest_first",
    "page_request",
    "paginate",
]
