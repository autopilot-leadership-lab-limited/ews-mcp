"""EWS implementation of `MailBackend`, built on exchangelib.

Read-only by construction: this module only ever issues FindFolder, GetFolder,
FindItem and GetItem requests. It never calls `send`, `delete`, `move`,
`save` or anything that marks an item read.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any

from exchangelib import DELEGATE, Account, Configuration, Credentials, FailFast, Folder
from exchangelib.errors import (
    ErrorFolderNotFound,
    ErrorInvalidIdMalformed,
    ErrorItemNotFound,
    ErrorNonExistentMailbox,
    EWSError,
    TransportError,
    UnauthorizedError,
)
from exchangelib.folders import FolderCollection
from exchangelib.properties import ConversationId

from .backend import (
    MAX_BODY_CHARS,
    MAX_PAGE_SIZE,
    Address,
    AttachmentInfo,
    AuthFailed,
    BackendUnavailable,
    FolderInfo,
    MessageDetail,
    MessageSummary,
    NotFound,
    Page,
    SearchQuery,
)

log = logging.getLogger(__name__)

# exchangelib logs full request and response XML at DEBUG, which would put mail
# content into log files. Pin it to WARNING regardless of the root logger.
logging.getLogger("exchangelib").setLevel(logging.WARNING)

_LIST_FIELDS = (
    "id",
    "changekey",
    "conversation_id",
    "subject",
    "sender",
    "to_recipients",
    "datetime_received",
    "datetime_sent",
    "has_attachments",
    "is_read",
    "size",
)
_DETAIL_FIELDS = _LIST_FIELDS + (
    "cc_recipients",
    "text_body",
    "body",
    "attachments",
    "message_id",
    "in_reply_to",
)

_WELL_KNOWN = {
    "inbox": "inbox",
    "sent": "sent",
    "sent items": "sent",
    "sentitems": "sent",
    "drafts": "drafts",
    "junk": "junk",
    "junk email": "junk",
    "deleted": "trash",
    "deleted items": "trash",
    "trash": "trash",
    "archive": "archive",
}


@dataclass(frozen=True)
class EwsSettings:
    """Where the Exchange server is. Shared by every user of one deployment."""

    host: str
    auth_type: str | None = None  # None = let exchangelib detect (NTLM, Basic, ...)
    timeout_seconds: int = 60


@dataclass(frozen=True)
class EwsCredentials:
    """One person's login. `username` is what Exchange expects (UPN or DOMAIN\\user)."""

    email: str
    username: str
    password: str


class _TextExtractor(HTMLParser):
    _skip = {"script", "style", "head", "title"}

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in self._skip:
            self._depth += 1
        elif tag in {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "blockquote"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._skip and self._depth:
            self._depth -= 1
        elif tag in {"p", "div", "tr", "li", "table"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._depth:
            self._parts.append(data)

    def text(self) -> str:
        raw = "".join(self._parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
        return raw.strip()


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return parser.text()


def _addr(mailbox: Any) -> Address | None:
    if mailbox is None:
        return None
    return Address(name=getattr(mailbox, "name", None), email=getattr(mailbox, "email_address", None))


def _addrs(mailboxes: Any) -> tuple[Address, ...]:
    if not mailboxes:
        return ()
    return tuple(a for a in (_addr(m) for m in mailboxes) if a is not None)


def _dt(value: Any) -> datetime | None:
    """Convert exchangelib's EWSDateTime/EWSDate to a plain, UTC-aware `datetime`.

    EWSDateTime rejects standard `tzinfo` objects in `astimezone`/`replace`, so it is
    rebuilt as a plain datetime from its UTC timestamp before anything else touches it.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return datetime(*value.timetuple()[:6], value.microsecond, tzinfo=UTC)
        return datetime.fromtimestamp(value.timestamp(), tz=UTC)
    return None


def _aqs_quote(value: str) -> str:
    return '"' + value.replace('"', " ").strip() + '"'


def build_aqs(query: SearchQuery) -> str | None:
    """Translate a `SearchQuery` into an Exchange AQS (query string) filter.

    AQS is used instead of EWS restrictions because recipient fields are not
    restrictable in FindItem and free-text search needs the content index anyway.
    """
    terms: list[str] = []
    if query.text:
        terms.append(_aqs_quote(query.text))
    if query.sender:
        terms.append(f"from:{_aqs_quote(query.sender)}")
    if query.recipient:
        terms.append(f"to:{_aqs_quote(query.recipient)}")
    if query.subject:
        terms.append(f"subject:{_aqs_quote(query.subject)}")
    if query.since:
        terms.append(f"received>={query.since.astimezone(UTC):%Y-%m-%d}")
    if query.until:
        terms.append(f"received<={query.until.astimezone(UTC):%Y-%m-%d}")
    if query.has_attachments is not None:
        terms.append(f"hasattachment:{'true' if query.has_attachments else 'false'}")
    if query.unread_only:
        terms.append("isread:false")
    return " AND ".join(terms) if terms else None


class EwsBackend:
    """`MailBackend` for one person's mailbox on one Exchange server."""

    def __init__(self, settings: EwsSettings, creds: EwsCredentials) -> None:
        self._settings = settings
        self._email = creds.email
        config = Configuration(
            server=settings.host,
            credentials=Credentials(username=creds.username, password=creds.password),
            auth_type=settings.auth_type,
            retry_policy=FailFast(),
            max_connections=2,
        )
        # autodiscover=False: only the configured host is ever contacted.
        self._account = Account(
            primary_smtp_address=creds.email,
            config=config,
            autodiscover=False,
            access_type=DELEGATE,
        )
        self._account.protocol.TIMEOUT = settings.timeout_seconds

    # -- error translation -------------------------------------------------

    @staticmethod
    def _translate(exc: Exception) -> Exception:
        if isinstance(exc, UnauthorizedError):
            return AuthFailed("The mailbox rejected the login")
        if isinstance(exc, ErrorNonExistentMailbox):
            return AuthFailed("No mailbox for this address")
        if isinstance(exc, ErrorItemNotFound | ErrorFolderNotFound | ErrorInvalidIdMalformed):
            return NotFound(str(exc.__class__.__name__))
        if isinstance(exc, TransportError | EWSError):
            # Error text from exchangelib can include server detail; keep only the class.
            return BackendUnavailable(f"Exchange error: {exc.__class__.__name__}")
        return BackendUnavailable(f"Unexpected error: {exc.__class__.__name__}")

    # -- MailBackend -------------------------------------------------------

    def verify(self) -> str:
        try:
            # A single GetFolder on the inbox: cheapest call that needs valid credentials.
            self._account.inbox.refresh()
        except Exception as exc:  # noqa: BLE001 - translated below
            raise self._translate(exc) from None
        return str(self._account.primary_smtp_address or self._email)

    def list_folders(self) -> list[FolderInfo]:
        try:
            folders = list(self._account.msg_folder_root.walk())
        except Exception as exc:  # noqa: BLE001
            raise self._translate(exc) from None
        out: list[FolderInfo] = []
        for f in folders:
            fclass = getattr(f, "folder_class", None) or ""
            if fclass and not fclass.startswith("IPF.Note"):
                continue  # calendars, contacts, tasks, search folders
            out.append(
                FolderInfo(
                    id=f.id,
                    name=f.name,
                    path=self._folder_path(f),
                    total_count=f.total_count,
                    unread_count=f.unread_count,
                    child_count=f.child_folder_count,
                )
            )
        out.sort(key=lambda x: x.path.lower())
        return out

    def search(self, folder: str, query: SearchQuery, *, limit: int, offset: int) -> Page:
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        offset = max(0, offset)
        try:
            target = self._resolve_folder(folder)
            aqs = build_aqs(query)
            qs = target.filter(aqs) if aqs else target.all()
            qs = qs.only(*_LIST_FIELDS).order_by("-datetime_received")
            items = list(qs[offset : offset + limit + 1])
            has_more = len(items) > limit
            summaries = [
                self._summary(i, folder_name=target.name)
                for i in items[:limit]
                if not isinstance(i, Exception)
            ]
        except Exception as exc:  # noqa: BLE001
            raise self._translate(exc) from None
        return Page(items=summaries, offset=offset, limit=limit, has_more=has_more)

    def get_message(self, message_id: str, *, max_body_chars: int) -> MessageDetail:
        try:
            items = list(self._account.fetch(ids=[message_id], only_fields=list(_DETAIL_FIELDS)))
        except Exception as exc:  # noqa: BLE001
            raise self._translate(exc) from None
        if not items:
            raise NotFound("Message not found")
        item = items[0]
        if isinstance(item, Exception):
            raise self._translate(item) from None
        try:
            return self._detail(item, max_body_chars=max_body_chars)
        except Exception as exc:  # noqa: BLE001
            raise self._translate(exc) from None

    def get_thread(self, conversation_id: str, *, limit: int, max_body_chars: int) -> list[MessageDetail]:
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        try:
            scope = FolderCollection(account=self._account, folders=[self._account.inbox, self._account.sent])
            qs = (
                scope.filter(conversation_id=ConversationId(id=conversation_id))
                .only(*_DETAIL_FIELDS)
                .order_by("datetime_received")
            )
            items = [i for i in qs[:limit] if not isinstance(i, Exception)]
            return [self._detail(i, max_body_chars=max_body_chars) for i in items]
        except Exception as exc:  # noqa: BLE001
            raise self._translate(exc) from None

    # -- helpers -----------------------------------------------------------

    def _resolve_folder(self, folder: str) -> Folder:
        key = (folder or "inbox").strip()
        well_known = _WELL_KNOWN.get(key.lower())
        if well_known:
            return getattr(self._account, well_known)
        if "/" in key:
            node: Folder = self._account.msg_folder_root
            for part in key.split("/"):
                if part:
                    node = node / part
            return node
        # Otherwise a folder ID or a display name at any depth.
        for f in self._account.msg_folder_root.walk():
            if f.id == key or f.name.lower() == key.lower():
                return f
        raise ErrorFolderNotFound(folder)

    def _folder_path(self, f: Folder) -> str:
        try:
            absolute = f.absolute  # e.g. "/root/Top of Information Store/Inbox/Clients"
        except Exception:  # noqa: BLE001
            return f.name
        prefix = "/root/Top of Information Store/"
        return absolute[len(prefix) :] if absolute.startswith(prefix) else absolute.lstrip("/")

    @staticmethod
    def _summary(item: Any, folder_name: str | None = None) -> MessageSummary:
        return MessageSummary(
            id=item.id,
            conversation_id=getattr(getattr(item, "conversation_id", None), "id", None),
            subject=item.subject or "",
            sender=_addr(getattr(item, "sender", None)),
            to=_addrs(getattr(item, "to_recipients", None)),
            received=_dt(getattr(item, "datetime_received", None)),
            sent=_dt(getattr(item, "datetime_sent", None)),
            has_attachments=bool(getattr(item, "has_attachments", False)),
            is_read=getattr(item, "is_read", None),
            size=getattr(item, "size", None),
            folder=folder_name,
        )

    @classmethod
    def _detail(cls, item: Any, *, max_body_chars: int) -> MessageDetail:
        max_body_chars = max(200, min(max_body_chars, MAX_BODY_CHARS))
        text = getattr(item, "text_body", None)
        if not text:
            body = getattr(item, "body", None)
            text = html_to_text(str(body)) if body else ""
        truncated = len(text) > max_body_chars
        if truncated:
            text = text[:max_body_chars]
        attachments = tuple(
            AttachmentInfo(
                name=getattr(a, "name", None) or "(unnamed)",
                content_type=getattr(a, "content_type", None),
                size=getattr(a, "size", None),
                is_inline=bool(getattr(a, "is_inline", False)),
            )
            for a in (getattr(item, "attachments", None) or [])
        )
        base = cls._summary(item)
        return MessageDetail(
            **base.__dict__,
            cc=_addrs(getattr(item, "cc_recipients", None)),
            body_text=text,
            body_truncated=truncated,
            attachments=attachments,
            internet_message_id=getattr(item, "message_id", None),
            in_reply_to=getattr(item, "in_reply_to", None),
        )
