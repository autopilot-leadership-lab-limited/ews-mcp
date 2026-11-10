"""Maps the authenticated person, and the mailbox they ask for, to a mailbox backend.

A person has one *primary* mailbox (the login they signed in with) and may add
*additional* mailboxes, each with its own Exchange login. Tools take an optional
`mailbox` argument (an e-mail address); empty means the primary mailbox.

Two implementations:

* `StoreAccounts` (hosted mode): looks the person up in the `Store`, decrypts
  the password of the mailbox asked for, builds a backend and caches it for a
  while. On the first authentication failure it flags that one mailbox as
  needing a new password and stops using the stored one, so a changed or
  expired password can never lock a directory account through repeated retries.
* `LocalAccounts` (local stdio mode): fixed backends for the one person running
  the process, built at start-up from the environment and the OS keyring.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .backend import AuthFailed, MailBackend, MailError
from .ews import EwsBackend, EwsCredentials, EwsSettings
from .store import Store, StoredMailbox, StoredUser

log = logging.getLogger(__name__)

BackendFactory = Callable[[EwsCredentials], MailBackend]

PRIMARY_ALIASES = ("", "primary", "default", "main")


class NeedsLogin(MailError):
    """No usable login for this mailbox; the person must (re-)enter its password."""

    def __init__(self, message: str, *, mailbox: str | None = None) -> None:
        super().__init__(message)
        self.mailbox = mailbox  # None = the primary mailbox


class UnknownMailbox(MailError):
    """The person asked for a mailbox they have not added."""


@dataclass(frozen=True)
class MailboxInfo:
    address: str
    primary: bool
    needs_password: bool


def _norm(mailbox: str | None) -> str:
    return (mailbox or "").strip().lower()


@dataclass
class _Cached:
    backend: MailBackend
    created_at: float


class StoreAccounts:
    def __init__(
        self,
        store: Store,
        settings: EwsSettings,
        *,
        factory: BackendFactory | None = None,
        cache_ttl: float = 900.0,
    ) -> None:
        self._store = store
        self._settings = settings
        self._factory: BackendFactory = factory or (lambda creds: EwsBackend(settings, creds))
        self._ttl = cache_ttl
        self._cache: dict[tuple[str, str], _Cached] = {}
        self._lock = threading.Lock()

    # -- resolving -------------------------------------------------------------

    def _resolve(self, sub: str, mailbox: str | None) -> tuple[StoredUser, StoredMailbox | None]:
        """Return the person and, for an additional mailbox, its record (None = primary)."""
        user = self._store.get_user(sub)
        if user is None:
            raise NeedsLogin("This account has no mailbox login yet")
        wanted = _norm(mailbox)
        if wanted in PRIMARY_ALIASES or wanted == user.sub:
            return user, None
        extra = self._store.get_mailbox(sub, wanted)
        if extra is None:
            known = ", ".join([user.email] + [m.email for m in self._store.list_mailboxes(sub)])
            raise UnknownMailbox(f"No mailbox {mailbox!r} on this connector. Available: {known}")
        return user, extra

    def mailboxes(self, sub: str) -> list[MailboxInfo]:
        user = self._store.get_user(sub)
        if user is None:
            raise NeedsLogin("This account has no mailbox login yet")
        out = [MailboxInfo(address=user.email, primary=True, needs_password=user.needs_relogin)]
        out += [
            MailboxInfo(address=m.email, primary=False, needs_password=m.needs_relogin)
            for m in self._store.list_mailboxes(sub)
        ]
        return out

    def backend_for(self, sub: str, mailbox: str | None = None) -> MailBackend:
        user, extra = self._resolve(sub, mailbox)
        key = (sub, extra.address if extra else "")
        now = time.time()
        with self._lock:
            cached = self._cache.get(key)
            if cached and now - cached.created_at < self._ttl:
                return cached.backend
            self._cache.pop(key, None)
        if extra is None:
            if user.needs_relogin:
                raise NeedsLogin("The stored mailbox password stopped working")
            password = self._store.get_password(sub)
            creds_email, creds_user = user.email, user.username
        else:
            if extra.needs_relogin:
                raise NeedsLogin("The stored password for this mailbox stopped working", mailbox=extra.email)
            password = self._store.get_mailbox_password(sub, extra.address)
            creds_email, creds_user = extra.email, extra.username
        if password is None:
            raise NeedsLogin(
                "The stored mailbox login could not be read", mailbox=extra.email if extra else None
            )
        backend = self._factory(EwsCredentials(email=creds_email, username=creds_user, password=password))
        with self._lock:
            self._cache[key] = _Cached(backend=backend, created_at=now)
        return backend

    def on_auth_failed(self, sub: str, mailbox: str | None = None) -> str | None:
        """Stop using the stored password of that one mailbox until the person enters it again.

        Returns the additional mailbox's address, or None when it was the primary one.
        """
        try:
            _, extra = self._resolve(sub, mailbox)
        except MailError:
            extra = None
        with self._lock:
            self._cache.pop((sub, extra.address if extra else ""), None)
        if extra is None:
            log.warning("mailbox login failed for sub=%s (primary); marking for re-login", sub)
            self._store.mark_needs_relogin(sub)
            return None
        log.warning("mailbox login failed for sub=%s (additional mailbox); marking for re-login", sub)
        self._store.mark_mailbox_needs_relogin(sub, extra.address)
        return extra.email

    # -- signing in / adding ----------------------------------------------------

    def login(self, email: str, username: str, password: str) -> StoredUser:
        """Verify a login against Exchange and store it. Raises `AuthFailed` or `BackendUnavailable`."""
        creds = EwsCredentials(
            email=email.strip(), username=username.strip() or email.strip(), password=password
        )
        backend = self._factory(creds)
        resolved = backend.verify()  # raises on bad credentials
        user = self._store.save_user(
            email=resolved or creds.email, username=creds.username, password=password
        )
        with self._lock:
            self._cache[(user.sub, "")] = _Cached(backend=backend, created_at=time.time())
        return user

    def add_mailbox(self, owner_sub: str, email: str, username: str, password: str) -> StoredMailbox:
        """Verify an additional mailbox's login against Exchange and store it for `owner_sub`.

        Raises `AuthFailed`, `BackendUnavailable` or `ValueError` (limit reached, same as primary).
        """
        if _norm(email) == owner_sub:
            raise ValueError("That is already your main mailbox")
        creds = EwsCredentials(
            email=email.strip(), username=username.strip() or email.strip(), password=password
        )
        backend = self._factory(creds)
        resolved = backend.verify()
        if _norm(resolved or creds.email) == owner_sub:
            raise ValueError("That is already your main mailbox")
        mb = self._store.save_mailbox(owner_sub, resolved or creds.email, creds.username, password)
        with self._lock:
            self._cache[(owner_sub, mb.address)] = _Cached(backend=backend, created_at=time.time())
        return mb

    def remove_mailbox(self, owner_sub: str, email: str) -> bool:
        address = _norm(email)
        with self._lock:
            self._cache.pop((owner_sub, address), None)
        return self._store.delete_mailbox(owner_sub, address)

    def forget(self, sub: str) -> None:
        self._store.delete_user(sub)
        with self._lock:
            for key in [k for k in self._cache if k[0] == sub]:
                self._cache.pop(key, None)


class LocalAccounts:
    """Local mode: one person, a primary backend and optional additional ones, fixed at start-up."""

    def __init__(
        self,
        primary: MailBackend,
        *,
        primary_address: str = "primary",
        extras: dict[str, MailBackend] | None = None,
    ) -> None:
        self._primary_address = primary_address
        self._backends: dict[str, MailBackend | None] = {"": primary}
        self._labels: dict[str, str] = {"": primary_address}
        for address, backend in (extras or {}).items():
            self._backends[_norm(address)] = backend
            self._labels[_norm(address)] = address.strip()

    def _key(self, mailbox: str | None) -> str:
        wanted = _norm(mailbox)
        if wanted in PRIMARY_ALIASES or wanted == _norm(self._primary_address):
            return ""
        if wanted not in self._backends:
            known = ", ".join(self._labels.values())
            raise UnknownMailbox(f"No mailbox {mailbox!r} on this connector. Available: {known}")
        return wanted

    def mailboxes(self, sub: str) -> list[MailboxInfo]:
        return [
            MailboxInfo(address=self._labels[k], primary=(k == ""), needs_password=b is None)
            for k, b in self._backends.items()
        ]

    def backend_for(self, sub: str, mailbox: str | None = None) -> MailBackend:
        key = self._key(mailbox)
        backend = self._backends[key]
        if backend is None:
            raise NeedsLogin(
                "The mailbox password stopped working; restart with the new password",
                mailbox=self._labels[key] if key else None,
            )
        return backend

    def on_auth_failed(self, sub: str, mailbox: str | None = None) -> str | None:
        try:
            key = self._key(mailbox)
        except UnknownMailbox:
            return None
        log.warning("mailbox login failed; refusing further attempts on it until restart")
        self._backends[key] = None
        return self._labels[key] if key else None


def SingleAccount(backend: MailBackend) -> LocalAccounts:  # noqa: N802 - kept for compatibility
    """Local mode with just one mailbox."""
    return LocalAccounts(backend)


__all__ = [
    "AuthFailed",
    "BackendFactory",
    "LocalAccounts",
    "MailboxInfo",
    "NeedsLogin",
    "SingleAccount",
    "StoreAccounts",
    "UnknownMailbox",
]
