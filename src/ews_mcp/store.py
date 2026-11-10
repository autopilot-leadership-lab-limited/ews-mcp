"""Persistent state for the hosted server: users' encrypted Exchange logins and OAuth records.

One SQLite file. Exchange passwords are encrypted with a master key kept in a
separate file; OAuth access and refresh tokens are stored only as SHA-256
hashes, so the database alone yields neither passwords nor usable tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    sub TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    enc_password BLOB NOT NULL,
    needs_relogin INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_txns (
    txn TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    data TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    pair_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    sub TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires_at REAL
);
CREATE INDEX IF NOT EXISTS tokens_pair ON tokens(pair_id);
CREATE TABLE IF NOT EXISTS extra_mailboxes (
    owner_sub TEXT NOT NULL,
    address TEXT NOT NULL,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    enc_password BLOB NOT NULL,
    needs_relogin INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (owner_sub, address)
);
"""

MAX_EXTRA_MAILBOXES = 10


def load_or_create_master_key(path: Path) -> bytes:
    """Read the Fernet master key from `path`, creating it (mode 0600) on first run."""
    if path.exists():
        key = path.read_bytes().strip()
        Fernet(key)  # validate
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class StoredUser:
    sub: str
    email: str
    username: str
    needs_relogin: bool


@dataclass(frozen=True)
class StoredMailbox:
    """An additional mailbox, with its own login, that a signed-in person has added."""

    owner_sub: str
    address: str
    email: str
    username: str
    needs_relogin: bool


@dataclass(frozen=True)
class StoredToken:
    kind: str
    pair_id: str
    client_id: str
    sub: str
    scopes: list[str]
    resource: str | None
    expires_at: float | None


class Store:
    def __init__(self, db_path: Path, master_key: bytes) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._fernet = Fernet(master_key)
        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass

    # -- users ---------------------------------------------------------------

    @staticmethod
    def sub_for_email(email: str) -> str:
        return email.strip().lower()

    def save_user(self, email: str, username: str, password: str) -> StoredUser:
        sub = self.sub_for_email(email)
        now = time.time()
        enc = self._fernet.encrypt(password.encode())
        with self._lock:
            self._conn.execute(
                """INSERT INTO users(sub, email, username, enc_password, needs_relogin, created_at, updated_at)
                   VALUES(?,?,?,?,0,?,?)
                   ON CONFLICT(sub) DO UPDATE SET email=excluded.email, username=excluded.username,
                       enc_password=excluded.enc_password, needs_relogin=0, updated_at=excluded.updated_at""",
                (sub, email.strip(), username, enc, now, now),
            )
        return StoredUser(sub=sub, email=email.strip(), username=username, needs_relogin=False)

    def get_user(self, sub: str) -> StoredUser | None:
        row = self._conn.execute(
            "SELECT sub, email, username, needs_relogin FROM users WHERE sub=?", (sub,)
        ).fetchone()
        if not row:
            return None
        return StoredUser(sub=row[0], email=row[1], username=row[2], needs_relogin=bool(row[3]))

    def get_password(self, sub: str) -> str | None:
        """Decrypt a user's Exchange password. Only `ews_mcp.accounts` calls this."""
        row = self._conn.execute("SELECT enc_password FROM users WHERE sub=?", (sub,)).fetchone()
        if not row:
            return None
        try:
            return self._fernet.decrypt(bytes(row[0])).decode()
        except InvalidToken:
            return None

    def mark_needs_relogin(self, sub: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE users SET needs_relogin=1, updated_at=? WHERE sub=?", (time.time(), sub)
            )

    def check_password(self, sub: str, password: str) -> bool:
        """Constant-time comparison with the stored password; no call to Exchange."""
        stored = self.get_password(sub)
        if stored is None or not password:
            return False
        return hmac.compare_digest(stored.encode(), password.encode())

    def delete_user(self, sub: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM users WHERE sub=?", (sub,))
            self._conn.execute("DELETE FROM tokens WHERE sub=?", (sub,))
            self._conn.execute("DELETE FROM extra_mailboxes WHERE owner_sub=?", (sub,))

    # -- additional mailboxes ------------------------------------------------

    def save_mailbox(self, owner_sub: str, email: str, username: str, password: str) -> StoredMailbox:
        address = self.sub_for_email(email)
        now = time.time()
        enc = self._fernet.encrypt(password.encode())
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM extra_mailboxes WHERE owner_sub=? AND address=?", (owner_sub, address)
            ).fetchone()
            if not exists:
                (count,) = self._conn.execute(
                    "SELECT COUNT(*) FROM extra_mailboxes WHERE owner_sub=?", (owner_sub,)
                ).fetchone()
                if count >= MAX_EXTRA_MAILBOXES:
                    raise ValueError(f"At most {MAX_EXTRA_MAILBOXES} additional mailboxes per person")
            self._conn.execute(
                """INSERT INTO extra_mailboxes(owner_sub, address, email, username, enc_password, needs_relogin, created_at, updated_at)
                   VALUES(?,?,?,?,?,0,?,?)
                   ON CONFLICT(owner_sub, address) DO UPDATE SET email=excluded.email, username=excluded.username,
                       enc_password=excluded.enc_password, needs_relogin=0, updated_at=excluded.updated_at""",
                (owner_sub, address, email.strip(), username, enc, now, now),
            )
        return StoredMailbox(owner_sub, address, email.strip(), username, False)

    def list_mailboxes(self, owner_sub: str) -> list[StoredMailbox]:
        rows = self._conn.execute(
            "SELECT owner_sub, address, email, username, needs_relogin FROM extra_mailboxes WHERE owner_sub=? ORDER BY address",
            (owner_sub,),
        ).fetchall()
        return [StoredMailbox(r[0], r[1], r[2], r[3], bool(r[4])) for r in rows]

    def get_mailbox(self, owner_sub: str, address: str) -> StoredMailbox | None:
        row = self._conn.execute(
            "SELECT owner_sub, address, email, username, needs_relogin FROM extra_mailboxes WHERE owner_sub=? AND address=?",
            (owner_sub, self.sub_for_email(address)),
        ).fetchone()
        return StoredMailbox(row[0], row[1], row[2], row[3], bool(row[4])) if row else None

    def get_mailbox_password(self, owner_sub: str, address: str) -> str | None:
        """Decrypt an additional mailbox's password. Only `ews_mcp.accounts` calls this."""
        row = self._conn.execute(
            "SELECT enc_password FROM extra_mailboxes WHERE owner_sub=? AND address=?",
            (owner_sub, self.sub_for_email(address)),
        ).fetchone()
        if not row:
            return None
        try:
            return self._fernet.decrypt(bytes(row[0])).decode()
        except InvalidToken:
            return None

    def mark_mailbox_needs_relogin(self, owner_sub: str, address: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE extra_mailboxes SET needs_relogin=1, updated_at=? WHERE owner_sub=? AND address=?",
                (time.time(), owner_sub, self.sub_for_email(address)),
            )

    def delete_mailbox(self, owner_sub: str, address: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM extra_mailboxes WHERE owner_sub=? AND address=?",
                (owner_sub, self.sub_for_email(address)),
            )
        return cur.rowcount > 0

    # -- OAuth clients -------------------------------------------------------

    def save_client(self, client_id: str, data: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO oauth_clients(client_id, data, created_at) VALUES(?,?,?)",
                (client_id, json.dumps(data), time.time()),
            )

    def get_client(self, client_id: str) -> dict | None:
        row = self._conn.execute("SELECT data FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
        return json.loads(row[0]) if row else None

    # -- pending authorizations (login page transactions) --------------------

    def save_txn(self, txn: str, client_id: str, data: dict, ttl: float = 600) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO auth_txns(txn, client_id, data, expires_at) VALUES(?,?,?,?)",
                (txn, client_id, json.dumps(data), time.time() + ttl),
            )

    def pop_txn(self, txn: str) -> tuple[str, dict] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, data, expires_at FROM auth_txns WHERE txn=?", (txn,)
            ).fetchone()
            if not row:
                return None
            self._conn.execute("DELETE FROM auth_txns WHERE txn=?", (txn,))
        if row[2] < time.time():
            return None
        return row[0], json.loads(row[1])

    def peek_txn(self, txn: str) -> tuple[str, dict] | None:
        row = self._conn.execute(
            "SELECT client_id, data, expires_at FROM auth_txns WHERE txn=? AND expires_at>?",
            (txn, time.time()),
        ).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    # -- authorization codes -------------------------------------------------

    def save_code(self, code: str, data: dict, expires_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO auth_codes(code, data, expires_at) VALUES(?,?,?)",
                (hash_token(code), json.dumps(data), expires_at),
            )

    def get_code(self, code: str) -> dict | None:
        row = self._conn.execute(
            "SELECT data FROM auth_codes WHERE code=? AND expires_at>?", (hash_token(code), time.time())
        ).fetchone()
        return json.loads(row[0]) if row else None

    def delete_code(self, code: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM auth_codes WHERE code=?", (hash_token(code),))

    # -- tokens --------------------------------------------------------------

    def save_token(
        self,
        token: str,
        *,
        kind: str,
        pair_id: str,
        client_id: str,
        sub: str,
        scopes: list[str],
        resource: str | None,
        expires_at: float | None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO tokens(token_hash, kind, pair_id, client_id, sub, scopes, resource, expires_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (hash_token(token), kind, pair_id, client_id, sub, " ".join(scopes), resource, expires_at),
            )

    def get_token(self, token: str, kind: str) -> StoredToken | None:
        row = self._conn.execute(
            "SELECT kind, pair_id, client_id, sub, scopes, resource, expires_at FROM tokens WHERE token_hash=? AND kind=?",
            (hash_token(token), kind),
        ).fetchone()
        if not row:
            return None
        if row[6] is not None and row[6] < time.time():
            return None
        return StoredToken(
            kind=row[0],
            pair_id=row[1],
            client_id=row[2],
            sub=row[3],
            scopes=row[4].split() if row[4] else [],
            resource=row[5],
            expires_at=row[6],
        )

    def delete_token_pair(self, pair_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM tokens WHERE pair_id=?", (pair_id,))

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute("DELETE FROM auth_txns WHERE expires_at<?", (now,))
            self._conn.execute("DELETE FROM auth_codes WHERE expires_at<?", (now,))
            self._conn.execute("DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at<?", (now,))

    def close(self) -> None:
        self._conn.close()
