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


def test_password_is_encrypted_at_rest(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    user = store.save_user("Pilot@Example.com", "DOMAIN\\pilot", "s3cret-pass")
    assert user.sub == "pilot@example.com"
    raw = sqlite3.connect(tmp_path / "db.sqlite3").execute("SELECT enc_password FROM users").fetchone()[0]
    assert b"s3cret-pass" not in bytes(raw)
    assert store.get_password("pilot@example.com") == "s3cret-pass"


def test_relogin_flag_and_overwrite(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.save_user("p@example.com", "p", "old")
    store.mark_needs_relogin("p@example.com")
    assert store.get_user("p@example.com").needs_relogin is True
    store.save_user("p@example.com", "p", "new")
    assert store.get_user("p@example.com").needs_relogin is False
    assert store.get_password("p@example.com") == "new"


def test_tokens_are_stored_hashed_and_expire(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.save_user("p@example.com", "p", "x")
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
    store.save_user("p@example.com", "p", "x")
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
