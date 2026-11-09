"""Hosted mode end to end: dynamic client registration, sign-in page, PKCE token exchange,
bearer-protected tool call, token refresh, and the stop-on-password-change behaviour."""

from __future__ import annotations

import base64
import hashlib
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from ews_mcp.app import HostedConfig, build_app
from ews_mcp.backend import AuthFailed
from ews_mcp.ews import EwsCredentials

from .fake_backend import FakeBackend

BASE = "https://testserver"
REDIRECT = "http://client.example/callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}


class PasswordCheckingBackend(FakeBackend):
    """Accepts only the password currently held in `state["password"]`, checked on every call."""

    def __init__(self, creds: EwsCredentials, state: dict[str, str]) -> None:
        super().__init__(creds)
        self._state = state

    def _check(self) -> None:
        assert self.creds is not None
        if self.creds.password != self._state["password"]:
            raise AuthFailed("bad password")


@pytest.fixture
def state() -> dict[str, str]:
    return {"password": "good-password"}


@pytest.fixture
def client(tmp_path: Path, state: dict[str, str]):
    config = HostedConfig(
        base_url=BASE, exchange_host="mail.example.test", data_dir=tmp_path / "data", json_response=True
    )
    app = build_app(config, backend_factory=lambda creds: PasswordCheckingBackend(creds, state))
    with TestClient(app, base_url=BASE) as c:  # runs the lifespan the session manager needs
        yield c


def register(client: TestClient) -> str:
    r = client.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "Test AI app",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def sign_in(client: TestClient, client_id: str, password: str) -> tuple[str, str]:
    """Run authorize -> login page -> code, returning (code, verifier)."""
    verifier, challenge = pkce()
    r = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "scope": "mail.read",
            "resource": f"{BASE}/mcp",
        },
        follow_redirects=False,
    )
    assert r.status_code in (302, 307), r.text
    login_url = r.headers["location"]
    assert login_url.startswith(f"{BASE}/login?txn=")
    txn = parse_qs(urlparse(login_url).query)["txn"][0]

    page = client.get(login_url)
    assert page.status_code == 200 and "read-only" in page.text

    r = client.post(
        "/login",
        data={"txn": txn, "email": "Pilot@Example.com", "username": "", "password": password},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    back = urlparse(r.headers["location"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT
    q = parse_qs(back.query)
    assert q["state"] == ["xyz"]
    return q["code"][0], verifier


def exchange(client: TestClient, client_id: str, code: str, verifier: str) -> dict:
    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "resource": f"{BASE}/mcp",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def call_tool(client: TestClient, token: str, name: str, arguments: dict | None = None) -> dict:
    r = client.post(
        "/mcp",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["result"]


def test_health_and_metadata(client: TestClient) -> None:
    assert client.get("/health").json()["ok"] is True
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["authorization_endpoint"] == f"{BASE}/authorize"
    assert meta["token_endpoint"] == f"{BASE}/token"
    assert "S256" in meta["code_challenge_methods_supported"]


def test_mcp_requires_bearer(client: TestClient) -> None:
    r = client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")


def test_wrong_password_is_rejected_and_nothing_stored(client: TestClient) -> None:
    client_id = register(client)
    verifier, challenge = pkce()
    r = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
        },
        follow_redirects=False,
    )
    txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
    r = client.post("/login", data={"txn": txn, "email": "p@example.com", "password": "wrong"})
    assert r.status_code == 401
    assert client.app.state.store.get_user("p@example.com") is None


def test_full_flow_then_password_change(client: TestClient, state: dict[str, str]) -> None:
    client_id = register(client)
    code, verifier = sign_in(client, client_id, "good-password")
    tokens = exchange(client, client_id, code, verifier)
    assert tokens["token_type"].lower() == "bearer" and tokens["refresh_token"]

    # The code is single-use.
    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": REDIRECT,
        },
    )
    assert r.status_code == 400

    # Authenticated tool call reaches the person's mailbox.
    result = call_tool(client, tokens["access_token"], "list_folders")
    assert [f["path"] for f in result["structuredContent"]["folders"]] == [
        "Inbox",
        "Inbox/Clients",
        "Sent Items",
    ]

    # Refresh rotates both tokens; the old access token dies.
    r = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client_id,
        },
    )
    assert r.status_code == 200, r.text
    new_tokens = r.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    r = client.post(
        "/mcp",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert r.status_code == 401
    call_tool(client, new_tokens["access_token"], "list_folders")

    # The person changes their Exchange password: the first failure stops the connector...
    state["password"] = "new-password"
    client.app.state.accounts._cache.clear()  # expire the cached backend as time would
    result = call_tool(client, new_tokens["access_token"], "list_folders")
    assert result["isError"] is True
    assert f"{BASE}/relogin" in result["content"][0]["text"]
    assert client.app.state.store.get_user("pilot@example.com").needs_relogin is True

    # ...and a wrong password on /relogin changes nothing...
    r = client.post("/relogin", data={"email": "pilot@example.com", "password": "still-wrong"})
    assert r.status_code == 401
    result = call_tool(client, new_tokens["access_token"], "list_folders")
    assert result["isError"] is True

    # ...until the person enters the new one. The existing OAuth token keeps working.
    r = client.post("/relogin", data={"email": "pilot@example.com", "password": "new-password"})
    assert r.status_code == 200
    result = call_tool(client, new_tokens["access_token"], "search_messages", {"folder": "sent"})
    assert [m["id"] for m in result["structuredContent"]["messages"]] == ["m2"]


def test_login_rate_limit(client: TestClient) -> None:
    for _ in range(5):
        client.post("/relogin", data={"email": "x@example.com", "password": "wrong"})
    r = client.post("/relogin", data={"email": "x@example.com", "password": "wrong"})
    assert r.status_code == 429
