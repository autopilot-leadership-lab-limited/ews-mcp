"""An in-memory `MailBackend` for tests. Nothing here talks to Exchange."""

from __future__ import annotations

from datetime import UTC, datetime

from ews_mcp.backend import (
    Address,
    AttachmentInfo,
    AuthFailed,
    FolderInfo,
    MessageDetail,
    NotFound,
    Page,
    SearchQuery,
)
from ews_mcp.ews import EwsCredentials

ME = Address("Pilot User", "pilot@example.com")
CLIENT = Address("A Client", "client@partner.example")

MESSAGES: list[MessageDetail] = [
    MessageDetail(
        id="m1",
        conversation_id="c1",
        subject="Invoice for October",
        sender=CLIENT,
        to=(ME,),
        received=datetime(2026, 11, 3, 9, 0, tzinfo=UTC),
        sent=datetime(2026, 11, 3, 8, 59, tzinfo=UTC),
        has_attachments=True,
        is_read=False,
        size=1200,
        folder="Inbox",
        body_text="Please find the invoice attached.",
        attachments=(AttachmentInfo("invoice.pdf", "application/pdf", 54321, False),),
        internet_message_id="<a@partner.example>",
    ),
    MessageDetail(
        id="m2",
        conversation_id="c1",
        subject="RE: Invoice for October",
        sender=ME,
        to=(CLIENT,),
        received=datetime(2026, 11, 3, 10, 0, tzinfo=UTC),
        sent=datetime(2026, 11, 3, 10, 0, tzinfo=UTC),
        has_attachments=False,
        is_read=True,
        size=800,
        folder="Sent Items",
        body_text="Received, thank you. Paying this week.",
        in_reply_to="<a@partner.example>",
    ),
    MessageDetail(
        id="m3",
        conversation_id="c2",
        subject="Team lunch",
        sender=Address("Colleague", "colleague@example.com"),
        to=(ME,),
        received=datetime(2026, 11, 5, 12, 0, tzinfo=UTC),
        sent=None,
        has_attachments=False,
        is_read=True,
        size=300,
        folder="Inbox",
        body_text="Friday? " * 500,
    ),
]


class FakeBackend:
    def __init__(self, creds: EwsCredentials | None = None, *, fail_auth: bool = False) -> None:
        self.creds = creds
        self.fail_auth = fail_auth
        self.calls: list[str] = []

    def _check(self) -> None:
        if self.fail_auth:
            raise AuthFailed("bad password")

    def verify(self) -> str:
        self.calls.append("verify")
        self._check()
        return self.creds.email if self.creds else ME.email or ""

    def list_folders(self) -> list[FolderInfo]:
        self.calls.append("list_folders")
        self._check()
        return [
            FolderInfo("f1", "Inbox", "Inbox", 2, 1, 1),
            FolderInfo("f2", "Clients", "Inbox/Clients", 0, 0, 0),
            FolderInfo("f3", "Sent Items", "Sent Items", 1, 0, 0),
        ]

    def search(self, folder: str, query: SearchQuery, *, limit: int, offset: int) -> Page:
        self.calls.append(f"search:{folder}")
        self._check()
        wanted = {"inbox": "Inbox", "sent": "Sent Items"}.get(folder.lower(), folder)
        items = [m for m in MESSAGES if m.folder == wanted]
        if query.text:
            items = [m for m in items if query.text.lower() in (m.subject + m.body_text).lower()]
        if query.sender:
            items = [m for m in items if m.sender and query.sender.lower() in str(m.sender).lower()]
        if query.since:
            items = [m for m in items if m.received and m.received >= query.since]
        if query.until:
            items = [m for m in items if m.received and m.received <= query.until]
        if query.unread_only:
            items = [m for m in items if m.is_read is False]
        items.sort(key=lambda m: m.received or datetime.min.replace(tzinfo=UTC), reverse=True)
        chunk = items[offset : offset + limit]
        return Page(items=list(chunk), offset=offset, limit=limit, has_more=len(items) > offset + limit)

    def get_message(self, message_id: str, *, max_body_chars: int) -> MessageDetail:
        self.calls.append(f"get:{message_id}")
        self._check()
        for m in MESSAGES:
            if m.id == message_id:
                if len(m.body_text) > max_body_chars:
                    return MessageDetail(
                        **{**m.__dict__, "body_text": m.body_text[:max_body_chars], "body_truncated": True}
                    )
                return m
        raise NotFound(message_id)

    def get_thread(self, conversation_id: str, *, limit: int, max_body_chars: int) -> list[MessageDetail]:
        self.calls.append(f"thread:{conversation_id}")
        self._check()
        return [m for m in MESSAGES if m.conversation_id == conversation_id][:limit]
