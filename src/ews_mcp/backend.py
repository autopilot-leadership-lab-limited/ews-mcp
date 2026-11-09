"""The mail backend interface and its data models.

Everything the MCP tools know about mail goes through `MailBackend`. The EWS
implementation lives in `ews.py`; a Microsoft Graph implementation could
replace it later without touching the tools.

The interface is deliberately read-only. There is no method that sends,
deletes, moves, flags or marks mail; adding one is a design change, not a
patch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


class MailError(Exception):
    """Base class for errors the tools report to the AI client."""


class AuthFailed(MailError):
    """The mailbox rejected the stored credentials.

    The caller must stop and ask the person to log in again. It must never retry
    with the same credentials: repeated failures can lock the directory account.
    """


class NotFound(MailError):
    """The requested folder or message does not exist or is not visible."""


class BackendUnavailable(MailError):
    """The mail server could not be reached or returned an unexpected error."""


@dataclass(frozen=True)
class Address:
    name: str | None
    email: str | None

    def __str__(self) -> str:
        if self.name and self.email:
            return f"{self.name} <{self.email}>"
        return self.email or self.name or ""


@dataclass(frozen=True)
class FolderInfo:
    id: str
    name: str
    path: str
    total_count: int | None
    unread_count: int | None
    child_count: int | None


@dataclass(frozen=True)
class AttachmentInfo:
    name: str
    content_type: str | None
    size: int | None
    is_inline: bool


@dataclass(frozen=True)
class MessageSummary:
    id: str
    conversation_id: str | None
    subject: str
    sender: Address | None
    to: tuple[Address, ...]
    received: datetime | None
    sent: datetime | None
    has_attachments: bool
    is_read: bool | None
    size: int | None
    folder: str | None = None


@dataclass(frozen=True)
class MessageDetail(MessageSummary):
    cc: tuple[Address, ...] = ()
    body_text: str = ""
    body_truncated: bool = False
    attachments: tuple[AttachmentInfo, ...] = ()
    internet_message_id: str | None = None
    in_reply_to: str | None = None


@dataclass(frozen=True)
class SearchQuery:
    """Filters for `MailBackend.search`. All fields are optional and combine with AND."""

    text: str | None = None
    sender: str | None = None
    recipient: str | None = None
    subject: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    has_attachments: bool | None = None
    unread_only: bool = False

    def is_empty(self) -> bool:
        return self == SearchQuery()


@dataclass
class Page:
    items: list[MessageSummary] = field(default_factory=list)
    offset: int = 0
    limit: int = 0
    has_more: bool = False
    note: str | None = None


MAX_PAGE_SIZE = 50
DEFAULT_BODY_CHARS = 20_000
MAX_BODY_CHARS = 100_000


class MailBackend(Protocol):
    """Read-only access to one person's mailbox."""

    def verify(self) -> str:
        """Check the credentials work and return the mailbox's primary address.

        Raises `AuthFailed` or `BackendUnavailable`.
        """
        ...

    def list_folders(self) -> list[FolderInfo]: ...

    def search(self, folder: str, query: SearchQuery, *, limit: int, offset: int) -> Page: ...

    def get_message(self, message_id: str, *, max_body_chars: int) -> MessageDetail: ...

    def get_thread(self, conversation_id: str, *, limit: int, max_body_chars: int) -> list[MessageDetail]: ...
