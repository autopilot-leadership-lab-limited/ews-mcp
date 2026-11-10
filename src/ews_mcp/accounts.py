"""Maps the authenticated person, and the mailbox they ask for, to a mailbox backend.

A person has one *primary* mailbox (the login they signed in with) and may add
*additional* mailboxes, each with its own Exchange login. Tools take an optional
`mailbox` argument (an e-mail address); empty means the primary mailbox.

Two implementations:

* `StoreAccounts` (hosted mode): looks the person up in the `Store`, opens the
  password of the mailbox asked for with the caller's own OAuth token (it is
  sealed per connection, see `sealing.py`), builds a backend and caches it in
  memory for a while. On the first authentication failure it flags that one mailbox as
  needing a new password and stops using the stored one, so a changed or
  expired password can never lock a directory account through repeated retries.
* `LocalAccounts` (local stdio mode): fixed backends for the one person running
  the process, built at start-up from the environment and the OS keyring.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .backend import AuthFailed, MailBackend, MailError
from .ews import EwsBackend, EwsCredentials, EwsSettings
from .sealing import SealError, new_key_pair, open_sealed, seal, unwrap_key
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
    """Hosted mode. Passwords are sealed per OAuth grant and opened only with the caller's token."""

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
        # In-memory only: (grant_id, address) -> backend holding the opened password.
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

    def _grant_key(self, sub: str, token: str | None) -> tuple[str, bytes]:
        """Open the caller's grant private key with their access token."""
        if not token:
            raise NeedsLogin("No access token on this request")
        t = self._store.get_token(token, "access")
        if t is None or t.sub != sub or not t.grant_id or not t.wrapped_key:
            raise NeedsLogin("This connection has no stored mailbox key; connect the app again")
        try:
            return t.grant_id, unwrap_key(t.wrapped_key, token, context=t.grant_id)
        except SealError:
            raise NeedsLogin(
                "This connection's mailbox key could not be opened; connect the app again"
            ) from None

    def _has_secret(self, sub: str, token: str | None, address: str) -> bool:
        if not token:
            return False
        t = self._store.get_token(token, "access")
        return bool(t and t.grant_id and self._store.get_secret(t.grant_id, address))

    def mailboxes(self, sub: str, *, token: str | None = None) -> list[MailboxInfo]:
        user = self._store.get_user(sub)
        if user is None:
            raise NeedsLogin("This account has no mailbox login yet")
        out = [MailboxInfo(address=user.email, primary=True, needs_password=user.needs_relogin)]
        out += [
            MailboxInfo(
                address=m.email,
                primary=False,
                needs_password=m.needs_relogin or not self._has_secret(sub, token, m.address),
            )
            for m in self._store.list_mailboxes(sub)
        ]
        return out

    def backend_for(self, sub: str, mailbox: str | None = None, *, token: str | None = None) -> MailBackend:
        user, extra = self._resolve(sub, mailbox)
        if extra is None and user.needs_relogin:
            raise NeedsLogin("The stored mailbox password stopped working")
        if extra is not None and extra.needs_relogin:
            raise NeedsLogin("The stored password for this mailbox stopped working", mailbox=extra.email)
        grant_id, priv = self._grant_key(sub, token)
        address = extra.address if extra else user.sub
        key = (grant_id, address)
        now = time.time()
        with self._lock:
            cached = self._cache.get(key)
            if cached and now - cached.created_at < self._ttl:
                return cached.backend
            self._cache.pop(key, None)
        sealed = self._store.get_secret(grant_id, address)
        if sealed is None:
            raise NeedsLogin(
                "This mailbox's password is not stored for this connection",
                mailbox=extra.email if extra else None,
            )
        try:
            password = open_sealed(priv, sealed, context=f"{grant_id}|{address}")
        except SealError:
            raise NeedsLogin(
                "The stored mailbox login could not be opened", mailbox=extra.email if extra else None
            ) from None
        email, username = (extra.email, extra.username) if extra else (user.email, user.username)
        backend = self._factory(EwsCredentials(email=email, username=username, password=password))
        with self._lock:
            self._cache[key] = _Cached(backend=backend, created_at=now)
        return backend

    def _drop_cached(self, sub: str, address: str | None = None) -> None:
        grants = {g.grant_id for g in self._store.list_grants(sub)}
        with self._lock:
            for k in [k for k in self._cache if k[0] in grants and (address is None or k[1] == address)]:
                self._cache.pop(k, None)

    def on_auth_failed(self, sub: str, mailbox: str | None = None) -> str | None:
        """Stop using that mailbox's password, on every connection, until the person enters it again.

        Returns the additional mailbox's address, or None when it was the primary one.
        """
        try:
            user, extra = self._resolve(sub, mailbox)
        except MailError:
            return None
        self._drop_cached(sub, extra.address if extra else user.sub)
        if extra is None:
            log.warning("mailbox login failed for sub=%s (primary); marking for re-login", sub)
            self._store.mark_needs_relogin(sub)
            return None
        log.warning("mailbox login failed for sub=%s (additional mailbox); marking for re-login", sub)
        self._store.mark_mailbox_needs_relogin(sub, extra.address)
        return extra.email

    # -- signing in / adding ----------------------------------------------------

    def _seal_everywhere(self, sub: str, address: str, password: str) -> None:
        for g in self._store.list_grants(sub):
            self._store.put_secret(
                g.grant_id, address, seal(g.public_key, password, context=f"{g.grant_id}|{address}")
            )

    def login(self, email: str, username: str, password: str) -> StoredUser:
        """Verify a login against Exchange, record the person, and re-seal the password for
        every existing connection (so a changed password works everywhere at once).

        Raises `AuthFailed` or `BackendUnavailable`.
        """
        creds = EwsCredentials(
            email=email.strip(), username=username.strip() or email.strip(), password=password
        )
        resolved = self._factory(creds).verify()  # raises on bad credentials
        user = self._store.save_user(email=resolved or creds.email, username=creds.username)
        self._seal_everywhere(user.sub, user.sub, password)
        self._drop_cached(user.sub, user.sub)
        return user

    def new_grant(self, user: StoredUser, client_id: str, password: str) -> tuple[str, bytes]:
        """Create a connection key pair for one AI app and seal the main password to it.

        Returns (grant_id, private_key); the caller wraps the private key under the
        authorization code and never stores it in the clear. Additional mailboxes added
        on other connections are not readable here and show as needing a password.
        """
        grant_id = secrets.token_urlsafe(16)
        priv, pub = new_key_pair()
        self._store.create_grant(grant_id, user.sub, client_id, pub)
        self._store.put_secret(grant_id, user.sub, seal(pub, password, context=f"{grant_id}|{user.sub}"))
        return grant_id, priv

    def verify_owner(self, email: str, password: str) -> StoredUser:
        """Check a connected person's main login against Exchange (the server cannot compare it
        with anything stored). Raises `NeedsLogin`, `AuthFailed` or `BackendUnavailable`."""
        user = self._store.get_user(self._store.sub_for_email(email))
        if user is None:
            raise NeedsLogin("Not a connected account")
        creds = EwsCredentials(email=user.email, username=user.username, password=password)
        self._factory(creds).verify()
        return user

    def add_mailbox(self, owner_sub: str, email: str, username: str, password: str) -> StoredMailbox:
        """Verify an additional mailbox's login against Exchange and seal it for every connection
        of `owner_sub`. Raises `AuthFailed`, `BackendUnavailable` or `ValueError`."""
        if _norm(email) == owner_sub:
            raise ValueError("That is already your main mailbox")
        if not self._store.list_grants(owner_sub):
            raise ValueError("Connect your AI app first, then add mailboxes")
        creds = EwsCredentials(
            email=email.strip(), username=username.strip() or email.strip(), password=password
        )
        resolved = self._factory(creds).verify()
        if _norm(resolved or creds.email) == owner_sub:
            raise ValueError("That is already your main mailbox")
        mb = self._store.save_mailbox(owner_sub, resolved or creds.email, creds.username)
        self._seal_everywhere(owner_sub, mb.address, password)
        self._drop_cached(owner_sub, mb.address)
        return mb

    def remove_mailbox(self, owner_sub: str, email: str) -> bool:
        self._drop_cached(owner_sub, _norm(email))
        return self._store.delete_mailbox(owner_sub, _norm(email))

    def forget(self, sub: str) -> None:
        self._drop_cached(sub)
        self._store.delete_user(sub)


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

    def mailboxes(self, sub: str, *, token: str | None = None) -> list[MailboxInfo]:
        return [
            MailboxInfo(address=self._labels[k], primary=(k == ""), needs_password=b is None)
            for k, b in self._backends.items()
        ]

    def backend_for(self, sub: str, mailbox: str | None = None, *, token: str | None = None) -> MailBackend:
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
