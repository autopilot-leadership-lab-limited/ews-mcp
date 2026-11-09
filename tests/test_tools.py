"""The four tools, exercised through a real in-memory MCP client against the fake backend."""

from __future__ import annotations

import pytest
from mcp import Client

from ews_mcp.accounts import SingleAccount
from ews_mcp.tools import build_server

from .fake_backend import FakeBackend

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_tools_are_read_only_and_exactly_four() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        tools = (await client.list_tools()).tools
    names = sorted(t.name for t in tools)
    assert names == ["get_message", "get_thread", "list_folders", "search_messages"]
    for t in tools:
        assert t.annotations is not None and t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False
    forbidden = ("send", "delete", "move", "forward", "flag", "mark")
    assert not any(any(w in t.name for w in forbidden) for t in tools)


async def test_list_folders() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        result = await client.call_tool("list_folders", {})
    paths = [f["path"] for f in result.structured_content["folders"]]
    assert paths == ["Inbox", "Inbox/Clients", "Sent Items"]


async def test_search_inbox_and_sent() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        inbox = await client.call_tool("search_messages", {"folder": "inbox", "limit": 10})
        sent = await client.call_tool("search_messages", {"folder": "sent"})
        unread = await client.call_tool("search_messages", {"unread_only": True})
        dated = await client.call_tool("search_messages", {"since": "2026-11-04", "until": "2026-11-05"})
    assert [m["id"] for m in inbox.structured_content["messages"]] == ["m3", "m1"]  # newest first
    assert inbox.structured_content["has_more"] is False
    assert [m["id"] for m in sent.structured_content["messages"]] == ["m2"]
    assert sent.structured_content["messages"][0]["from"]["email"] == "pilot@example.com"
    assert [m["id"] for m in unread.structured_content["messages"]] == ["m1"]
    assert [m["id"] for m in dated.structured_content["messages"]] == ["m3"]
    # headers only: no body in search results
    assert "body_text" not in inbox.structured_content["messages"][0]


async def test_search_rejects_bad_inputs() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        too_many = await client.call_tool("search_messages", {"limit": 500})
        bad_date = await client.call_tool("search_messages", {"since": "yesterday"})
    assert too_many.is_error and "50" in too_many.content[0].text
    assert bad_date.is_error and "ISO date" in bad_date.content[0].text


async def test_get_message_and_truncation() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        m1 = await client.call_tool("get_message", {"message_id": "m1"})
        m3 = await client.call_tool("get_message", {"message_id": "m3", "max_body_chars": 300})
        missing = await client.call_tool("get_message", {"message_id": "nope"})
    body = m1.structured_content
    assert body["subject"] == "Invoice for October"
    assert body["attachments"] == [
        {"name": "invoice.pdf", "content_type": "application/pdf", "size": 54321, "is_inline": False}
    ]
    assert body["received"] == "2026-11-03T09:00:00+00:00"
    assert m3.structured_content["body_truncated"] is True
    assert len(m3.structured_content["body_text"]) == 300
    assert missing.is_error and "Not found" in missing.content[0].text


async def test_get_thread_spans_inbox_and_sent() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        thread = await client.call_tool("get_thread", {"conversation_id": "c1"})
    msgs = thread.structured_content["messages"]
    assert [m["id"] for m in msgs] == ["m1", "m2"]
    assert msgs[1]["in_reply_to"] == "<a@partner.example>"


async def test_auth_failure_stops_further_attempts() -> None:
    backend = FakeBackend(fail_auth=True)
    mcp = build_server(SingleAccount(backend))
    async with Client(mcp) as client:
        first = await client.call_tool("list_folders", {})
        second = await client.call_tool("list_folders", {})
    assert first.is_error and "login failed" in first.content[0].text
    assert second.is_error and "login failed" in second.content[0].text
    # The backend was asked exactly once; after the failure nothing retried with the stored password.
    assert backend.calls == ["list_folders"]


async def test_instructions_state_confidentiality() -> None:
    mcp = build_server(SingleAccount(FakeBackend()))
    async with Client(mcp) as client:
        init = client.server_info if hasattr(client, "server_info") else None
    text = mcp.instructions or ""
    assert "CONFIDENTIAL" in text and "cannot send" in text
    assert init is None or init.name == "exchange-mail"
