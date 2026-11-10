from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from cryptography.fernet import Fernet

from ews_mcp.store import Store, hash_token, load_or_create_master_key


def make_store(tmp_path: Path) -> Store:
    return Store(tmp_path / "db.sqlite3", Fernet.generate_key())


def test_master_key_is_created_once_with_tight_permissions(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "master.key"
    k1 = load_or_create_master_key(path)
    k2 = load_or_create_master_key(path)
    assert k1 == k2
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_users_hold_no_password(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    user = store.save_user("Pilot@Example.com", "DOMAIN\\pilot")
    assert user.sub == "pilot@example.com"
    raw = sqlite3.connect(tmp_path / "db.sqlite3").execute("SELECT enc_password FROM users").fetchone()[0]
    assert bytes(raw) == b""


def test_relogin_flag_cleared_by_new_login(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.save_user("p@example.com", "p")
    store.mark_needs_relogin("p@example.com")
    assert store.get_user("p@example.com").needs_relogin is True
    store.save_user("p@example.com", "p")
    assert store.get_user("p@example.com").needs_relogin is False


def test_tokens_are_stored_hashed_and_expire(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.save_user("p@example.com", "p")
    store.save_token(
        "tok-abc",
        kind="access",
        pair_id="pair",
        client_id="c",
        sub="p@example.com",
        scopes=["mail.read"],
        resource=None,
        expires_at=time.time() + 60,
    )
    store.save_token(
        "tok-old",
        kind="access",
        pair_id="pair2",
        client_id="c",
        sub="p@example.com",
        scopes=["mail.read"],
        resource=None,
        expires_at=time.time() - 1,
    )
    rows = sqlite3.connect(tmp_path / "db.sqlite3").execute("SELECT token_hash FROM tokens").fetchall()
    assert {r[0] for r in rows} == {hash_token("tok-abc"), hash_token("tok-old")}
    assert store.get_token("tok-abc", "access").sub == "p@example.com"
    assert store.get_token("tok-abc", "refresh") is None  # kind must match
    assert store.get_token("tok-old", "access") is None  # expired
    store.delete_token_pair("pair")
    assert store.get_token("tok-abc", "access") is None


def test_delete_user_removes_tokens(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.save_user("p@example.com", "p")
    store.save_token(
        "t",
        kind="refresh",
        pair_id="pr",
        client_id="c",
        sub="p@example.com",
        scopes=[],
        resource=None,
        expires_at=None,
    )
    store.delete_user("p@example.com")
    assert store.get_user("p@example.com") is None
    assert store.get_token("t", "refresh") is None


def test_additional_mailboxes(tmp_path: Path) -> None:
    import pytest

    from ews_mcp.store import MAX_EXTRA_MAILBOXES

    store = make_store(tmp_path)
    store.save_user("p@example.com", "p")
    store.save_mailbox("p@example.com", "Info@Example.com", "Info@Example.com")
    store.mark_mailbox_needs_relogin("p@example.com", "INFO@example.com")
    assert store.get_mailbox("p@example.com", "info@example.com").needs_relogin is True
    store.save_mailbox("p@example.com", "info@example.com", "info@example.com")
    assert store.get_mailbox("p@example.com", "info@example.com").needs_relogin is False
    assert [m.address for m in store.list_mailboxes("p@example.com")] == ["info@example.com"]

    store.create_grant("g1", "p@example.com", "c", b"k" * 32)
    store.put_secret("g1", "Info@Example.com", b"sealed")
    assert store.get_secret("g1", "info@example.com") == b"sealed"

    for i in range(1, MAX_EXTRA_MAILBOXES):
        store.save_mailbox("p@example.com", f"b{i}@example.com", f"b{i}@example.com")
    with pytest.raises(ValueError):
        store.save_mailbox("p@example.com", "one-too-many@example.com", "x")

    assert store.delete_mailbox("p@example.com", "info@example.com") is True
    assert store.get_secret("g1", "info@example.com") is None  # its sealed passwords go too
    assert store.delete_mailbox("p@example.com", "info@example.com") is False
    store.delete_user("p@example.com")
    assert store.list_mailboxes("p@example.com") == []
    assert store.list_grants("p@example.com") == []


def test_version_1_database_is_wiped_of_passwords_and_tokens(tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite3"
    key = Fernet.generate_key()
    old = sqlite3.connect(db)
    old.executescript(
        """CREATE TABLE users (sub TEXT PRIMARY KEY, email TEXT NOT NULL, username TEXT NOT NULL,
               enc_password BLOB NOT NULL, needs_relogin INTEGER NOT NULL DEFAULT 0,
               created_at REAL NOT NULL, updated_at REAL NOT NULL);
           CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, pair_id TEXT NOT NULL,
               client_id TEXT NOT NULL, sub TEXT NOT NULL, scopes TEXT NOT NULL, resource TEXT, expires_at REAL);"""
    )
    old.execute(
        "INSERT INTO users VALUES('p@example.com','p@example.com','p',?,0,0,0)",
        (Fernet(key).encrypt(b"old-secret"),),
    )
    old.execute("INSERT INTO tokens VALUES('h','access','pr','c','p@example.com','mail.read',NULL,NULL)")
    old.commit()
    old.close()

    store = Store(db, key)
    raw = sqlite3.connect(db).execute("SELECT enc_password FROM users").fetchone()[0]
    assert bytes(raw) == b""
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0
    assert store.get_user("p@example.com") is not None  # the person stays; they sign in once again
    store.close()
    Store(db, key).close()  # re-opening a version 2 database changes nothing
