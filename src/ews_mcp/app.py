"""Assembles the hosted (remote MCP) application from environment configuration."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from . import __version__
from .accounts import BackendFactory, StoreAccounts
from .ews import EwsSettings
from .oauth import SCOPE, ExchangeLoginProvider
from .store import Store, load_or_create_master_key
from .tools import build_server

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class HostedConfig:
    base_url: str  # public URL of this server, e.g. https://mail-mcp.example.com
    exchange_host: str  # e.g. mail.example.com (EWS at https://<host>/EWS/Exchange.asmx)
    data_dir: Path
    exchange_auth_type: str | None = None
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    stateless: bool = True
    json_response: bool = False  # plain JSON instead of SSE responses; handy for tests and curl

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> HostedConfig:
        e = env if env is not None else dict(os.environ)

        def need(name: str) -> str:
            v = e.get(name, "").strip()
            if not v:
                raise SystemExit(f"{name} is required")
            return v

        return cls(
            base_url=need("EWS_MCP_BASE_URL").rstrip("/"),
            exchange_host=need("EWS_MCP_EXCHANGE_HOST"),
            data_dir=Path(e.get("EWS_MCP_DATA_DIR", "./data")).expanduser(),
            exchange_auth_type=e.get("EWS_MCP_EXCHANGE_AUTH") or None,
            bind_host=e.get("EWS_MCP_BIND_HOST", "127.0.0.1"),
            bind_port=int(e.get("EWS_MCP_BIND_PORT", "8000")),
            stateless=e.get("EWS_MCP_STATELESS", "1") not in ("0", "false", "no"),
            json_response=e.get("EWS_MCP_JSON_RESPONSE", "0") in ("1", "true", "yes"),
        )


def _installed_commit() -> str | None:
    """The git commit this package was installed from (pip records it), so anyone can check
    which public code the server runs. None for a plain or editable install."""
    try:
        import json
        from importlib.metadata import distribution

        raw = distribution("ews-mcp").read_text("direct_url.json")
        return json.loads(raw).get("vcs_info", {}).get("commit_id") if raw else None
    except Exception:
        return None


def build_app(config: HostedConfig, *, backend_factory: BackendFactory | None = None) -> Starlette:
    key = load_or_create_master_key(config.data_dir / "master.key")
    store = Store(config.data_dir / "ews-mcp.sqlite3", key)
    store.purge_expired()
    settings = EwsSettings(host=config.exchange_host, auth_type=config.exchange_auth_type)
    accounts = StoreAccounts(store, settings, factory=backend_factory)
    provider = ExchangeLoginProvider(store, accounts, config.base_url)

    mcp_url = f"{config.base_url}/mcp"
    auth = AuthSettings(
        issuer_url=AnyHttpUrl(config.base_url),
        resource_server_url=AnyHttpUrl(mcp_url),
        required_scopes=[SCOPE],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
        ),
        revocation_options=RevocationOptions(enabled=True),
        validate_token_resource=False,
    )
    mcp = build_server(
        accounts,
        login_url=f"{config.base_url}/relogin",
        mailboxes_url=f"{config.base_url}/mailboxes",
        auth=auth,
        auth_server_provider=provider,
    )

    mcp.custom_route("/login", methods=["GET"])(provider.login_get)
    mcp.custom_route("/login", methods=["POST"])(provider.login_post)
    mcp.custom_route("/relogin", methods=["GET"])(provider.relogin_get)
    mcp.custom_route("/relogin", methods=["POST"])(provider.relogin_post)
    mcp.custom_route("/mailboxes", methods=["GET"])(provider.mailboxes_get)
    mcp.custom_route("/mailboxes", methods=["POST"])(provider.mailboxes_post)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_: Request) -> Response:
        return JSONResponse({"ok": True, "version": __version__, "commit": _installed_commit()})

    @mcp.custom_route("/", methods=["GET"])
    async def index(_: Request) -> Response:
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>Exchange mail connector</title>"
            "<h1>Exchange mail connector</h1>"
            f"<p>Read-only MCP server for the company mailbox. Add <code>{mcp_url}</code> to your AI app "
            "as a remote MCP server; it will send you here to sign in.</p>"
            '<p>Changed your password? <a href="/relogin">Update it here</a>.</p>'
            '<p>Another mailbox with its own login? <a href="/mailboxes">Add it here</a>.</p>'
        )

    public_host = urlparse(config.base_url).netloc
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[public_host, f"{config.bind_host}:{config.bind_port}", "localhost:*", "127.0.0.1:*"],
        allowed_origins=[config.base_url],
    )
    app = mcp.streamable_http_app(
        stateless_http=config.stateless, json_response=config.json_response, transport_security=security
    )
    app.state.store = store
    app.state.accounts = accounts
    app.state.provider = provider
    return app
