"""Maps the authenticated person to their mailbox backend.

Two implementations:

* `StoreAccounts` (hosted mode): looks the person up in the `Store`, decrypts
  their Exchange password, builds a backend and caches it for a while. On the
  first authentication failure it flags the person as needing to log in again
  and stops using the stored password, so a changed or expired password can
  never lock the directory account through repeated retries.
* `SingleAccount` (local stdio mode): one backend for the one person running
  the process.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .backend import AuthFailed, MailBackend, MailError
from .ews import EwsBackend, EwsCredentials, EwsSettings
from .store import Store, StoredUser

log = logging.getLogger(__name__)

BackendFactory = Callable[[EwsCredentials], MailBackend]


class NeedsLogin(MailError):
    """No usable login for this person; they must (re-)enter their password."""


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
        self._cache: dict[str, _Cached] = {}
        self._lock = threading.Lock()

    def backend_for(self, sub: str) -> MailBackend:
        now = time.time()
        with self._lock:
            cached = self._cache.get(sub)
            if cached and now - cached.created_at < self._ttl:
                return cached.backend
            self._cache.pop(sub, None)
        user = self._store.get_user(sub)
        if user is None:
            raise NeedsLogin("This account has no mailbox login yet")
        if user.needs_relogin:
            raise NeedsLogin("The stored mailbox password stopped working")
        password = self._store.get_password(sub)
        if password is None:
            raise NeedsLogin("The stored mailbox login could not be read")
        backend = self._factory(EwsCredentials(email=user.email, username=user.username, password=password))
        with self._lock:
            self._cache[sub] = _Cached(backend=backend, created_at=now)
        return backend

    def on_auth_failed(self, sub: str) -> None:
        """Stop using the stored password until the person logs in again."""
        log.warning("mailbox login failed for sub=%s; marking for re-login", sub)
        self._store.mark_needs_relogin(sub)
        with self._lock:
            self._cache.pop(sub, None)

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
            self._cache[user.sub] = _Cached(backend=backend, created_at=time.time())
        return user

    def forget(self, sub: str) -> None:
        self._store.delete_user(sub)
        with self._lock:
            self._cache.pop(sub, None)


class SingleAccount:
    """Local mode: one person, one backend, credentials supplied at start-up."""

    def __init__(self, backend: MailBackend) -> None:
        self._backend: MailBackend | None = backend

    def backend_for(self, sub: str) -> MailBackend:
        if self._backend is None:
            raise NeedsLogin("The mailbox password stopped working; restart with the new password")
        return self._backend

    def on_auth_failed(self, sub: str) -> None:
        log.warning("mailbox login failed; refusing further attempts until restart")
        self._backend = None


__all__ = ["AuthFailed", "NeedsLogin", "SingleAccount", "StoreAccounts", "BackendFactory"]
