"""Conversion of real exchangelib objects, which the fake backend does not exercise.

Regression: the first real search failed because EWSDateTime rejects a standard
`timezone.utc` in `astimezone`, so every message with a date crashed the tool.
"""

from __future__ import annotations

from datetime import UTC, datetime

from exchangelib import EWSDate, EWSDateTime, EWSTimeZone, Mailbox, Message
from exchangelib.properties import ConversationId

from ews_mcp.ews import EwsBackend, _dt
from ews_mcp.tools import _detail, _summary


def test_dt_converts_ewsdatetime_in_any_zone() -> None:
    hk = EWSTimeZone("Asia/Hong_Kong")
    v = EWSDateTime(2026, 11, 8, 11, 0, tzinfo=hk)
    d = _dt(v)
    assert type(d) is datetime
    assert d == datetime(2026, 11, 8, 3, 0, tzinfo=UTC)
    assert d.isoformat(timespec="seconds") == "2026-11-08T03:00:00+00:00"
    assert _dt(EWSDateTime(2026, 11, 8, 3, 0, tzinfo=EWSTimeZone("UTC"))) == d


def test_dt_handles_naive_none_and_dates() -> None:
    assert _dt(None) is None
    assert _dt(datetime(2026, 1, 2, 3, 4)) == datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
    assert _dt(EWSDate(2026, 1, 2)) is None  # dates without time are not message timestamps


def _real_message() -> Message:
    utc = EWSTimeZone("UTC")
    return Message(
        id="AAMk-test",
        changekey="CQAA",
        conversation_id=ConversationId(id="AAQk-conv"),
        subject="Hello",
        sender=Mailbox(name="Sender", email_address="s@example.com"),
        to_recipients=[Mailbox(name="Me", email_address="me@example.com")],
        cc_recipients=[],
        datetime_received=EWSDateTime(2026, 11, 8, 3, 0, tzinfo=utc),
        datetime_sent=EWSDateTime(2026, 11, 8, 2, 59, tzinfo=utc),
        has_attachments=False,
        is_read=False,
        size=1234,
        text_body="Body text",
        message_id="<x@example.com>",
    )


def test_summary_and_detail_from_real_exchangelib_message() -> None:
    m = _real_message()
    summary = _summary(EwsBackend._summary(m, folder_name="Inbox"))
    assert summary["received"] == "2026-11-08T03:00:00+00:00"
    assert summary["conversation_id"] == "AAQk-conv"
    assert summary["from"] == {"name": "Sender", "email": "s@example.com"}
    detail = _detail(EwsBackend._detail(m, max_body_chars=1000))
    assert detail["body_text"] == "Body text"
    assert detail["sent"] == "2026-11-08T02:59:00+00:00"
