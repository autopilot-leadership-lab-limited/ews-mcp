"""Local-mode CLI: password storage and extra-mailbox credential lookup, with a fake keyring."""

from __future__ import annotations

import sys
import types
from argparse import Namespace

import pytest

from ews_mcp import cli


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    store: dict[tuple[str, str], str] = {}
    mod = types.ModuleType("keyring")
    mod.get_password = lambda service, user: store.get((service, user))  # type: ignore[attr-defined]
    mod.set_password = lambda service, user, pw: store.__setitem__((service, user), pw)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", mod)
    return store


def _prompts(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    it = iter(answers)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(it))


def test_set_password_rejects_empty(monkeypatch, fake_keyring) -> None:
    _prompts(monkeypatch, "")
    with pytest.raises(SystemExit, match="Empty password"):
        cli.cmd_set_password(Namespace(email="hi@example.com"))
    assert fake_keyring == {}


def test_set_password_rejects_mismatch(monkeypatch, fake_keyring) -> None:
    _prompts(monkeypatch, "one", "two")
    with pytest.raises(SystemExit, match="differ"):
        cli.cmd_set_password(Namespace(email="hi@example.com"))
    assert fake_keyring == {}


def test_set_password_stores_confirmed(monkeypatch, fake_keyring) -> None:
    _prompts(monkeypatch, "s3cret", "s3cret")
    cli.cmd_set_password(Namespace(email="hi@example.com"))
    assert fake_keyring == {("ews-mcp", "hi@example.com"): "s3cret"}


def test_extra_credentials_missing_vs_empty(fake_keyring) -> None:
    fake_keyring[("ews-mcp", "a@example.com")] = "pa"
    fake_keyring[("ews-mcp", "empty@example.com")] = ""
    creds = cli._extra_credentials(Namespace(mailboxes="a@example.com, me@example.com"), "me@example.com")
    assert [c.email for c in creds] == ["a@example.com"]  # primary is skipped
    with pytest.raises(SystemExit, match="is empty"):
        cli._extra_credentials(Namespace(mailboxes="empty@example.com"), "me@example.com")
    with pytest.raises(SystemExit, match="No password"):
        cli._extra_credentials(Namespace(mailboxes="none@example.com"), "me@example.com")
