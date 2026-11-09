"""Search planning: exact EWS restrictions for structured filters, AQS only for index terms.

Regression: on the real server the content index is incomplete, so a date-only search
through AQS returned a handful of messages for a day that had dozens. Dates, unread,
attachments and subject must never depend on the index.
"""

from __future__ import annotations

from datetime import UTC, datetime

from exchangelib import EWSDateTime

from ews_mcp.backend import Address, MessageSummary, SearchQuery
from ews_mcp.ews import build_aqs, build_restriction, matches, needs_index


def _summary(**overrides) -> MessageSummary:
    base = dict(
        id="m1",
        conversation_id=None,
        subject="Quarterly report",
        sender=Address("A", "a@example.com"),
        to=(),
        received=datetime(2026, 11, 8, 3, 0, tzinfo=UTC),
        sent=None,
        has_attachments=True,
        is_read=False,
        size=1,
    )
    base.update(overrides)
    return MessageSummary(**base)


def test_structured_filters_do_not_need_the_index() -> None:
    q = SearchQuery(
        since=datetime(2026, 11, 1, tzinfo=UTC), unread_only=True, has_attachments=True, subject="x"
    )
    assert needs_index(q) is False
    assert build_aqs(q) is None
    for q in (SearchQuery(text="hello"), SearchQuery(sender="bob"), SearchQuery(recipient="me@x")):
        assert needs_index(q) is True


def test_aqs_only_carries_index_terms() -> None:
    q = SearchQuery(text='budget "v2"', sender="bob", recipient="me", subject="ignored", unread_only=True)
    assert build_aqs(q) == '"budget  v2" AND from:"bob" AND to:"me"'


def test_restriction_uses_ews_datetimes_and_exact_fields() -> None:
    q = SearchQuery(
        since=datetime(2026, 11, 1, 0, 0, tzinfo=UTC),
        until=datetime(2026, 11, 3, 23, 59, 59, tzinfo=UTC),
        has_attachments=False,
        unread_only=True,
        subject="Report",
    )
    kw = build_restriction(q)
    assert set(kw) == {
        "datetime_received__gte",
        "datetime_received__lte",
        "has_attachments",
        "is_read",
        "subject__icontains",
    }
    assert type(kw["datetime_received__gte"]) is EWSDateTime
    assert kw["datetime_received__gte"] == datetime(2026, 11, 1, tzinfo=UTC)
    assert kw["is_read"] is False and kw["has_attachments"] is False
    assert kw["subject__icontains"] == "Report"
    assert build_restriction(SearchQuery()) == {}


def test_matches_rechecks_structured_filters_client_side() -> None:
    s = _summary()
    assert matches(s, SearchQuery()) is True
    assert matches(s, SearchQuery(since=datetime(2026, 11, 8, tzinfo=UTC))) is True
    assert matches(s, SearchQuery(since=datetime(2026, 11, 9, tzinfo=UTC))) is False
    assert matches(s, SearchQuery(until=datetime(2026, 11, 7, tzinfo=UTC))) is False
    assert matches(s, SearchQuery(has_attachments=False)) is False
    assert matches(s, SearchQuery(unread_only=True)) is True
    assert matches(_summary(is_read=True), SearchQuery(unread_only=True)) is False
    assert matches(_summary(is_read=None), SearchQuery(unread_only=True)) is False
    assert matches(s, SearchQuery(subject="quarterly")) is True
    assert matches(s, SearchQuery(subject="invoice")) is False
    assert matches(_summary(received=None), SearchQuery(since=datetime(2026, 1, 1, tzinfo=UTC))) is False
