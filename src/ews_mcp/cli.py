"""Command line: `ews-mcp serve` (hosted), `ews-mcp stdio` (local), `ews-mcp check`, `ews-mcp set-password`."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys

from . import __version__

KEYRING_SERVICE = "ews-mcp"


def _logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Never let exchangelib's XML dumps into the logs, whatever the root level.
    logging.getLogger("exchangelib").setLevel(logging.WARNING)


def _local_credentials(args: argparse.Namespace):
    from .ews import EwsCredentials

    email = args.email or os.environ.get("EWS_MCP_EMAIL", "").strip()
    if not email:
        sys.exit("EWS_MCP_EMAIL (or --email) is required")
    username = args.username or os.environ.get("EWS_MCP_USERNAME", "").strip() or email
    password = os.environ.get("EWS_MCP_PASSWORD", "")
    if not password:
        try:
            import keyring  # type: ignore

            password = keyring.get_password(KEYRING_SERVICE, email) or ""
        except ImportError:
            pass
    if not password and sys.stdin.isatty():
        password = getpass.getpass(f"Exchange password for {email}: ")
    if not password:
        sys.exit("No password: run `ews-mcp set-password`, or set EWS_MCP_PASSWORD")
    return EwsCredentials(email=email, username=username, password=password)


def _local_settings(args: argparse.Namespace):
    from .ews import EwsSettings

    host = args.exchange_host or os.environ.get("EWS_MCP_EXCHANGE_HOST", "").strip()
    if not host:
        sys.exit("EWS_MCP_EXCHANGE_HOST (or --exchange-host) is required")
    return EwsSettings(host=host, auth_type=os.environ.get("EWS_MCP_EXCHANGE_AUTH") or None)


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    from .app import HostedConfig, build_app

    config = HostedConfig.from_env()
    app = build_app(config)
    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.bind_port,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("EWS_MCP_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_level=args.log_level.lower(),
    )


def cmd_stdio(args: argparse.Namespace) -> None:
    from .accounts import SingleAccount
    from .ews import EwsBackend
    from .tools import build_server

    backend = EwsBackend(_local_settings(args), _local_credentials(args))
    mcp = build_server(SingleAccount(backend))
    mcp.run(transport="stdio")


def cmd_check(args: argparse.Namespace) -> None:
    from .ews import EwsBackend

    backend = EwsBackend(_local_settings(args), _local_credentials(args))
    address = backend.verify()
    folders = backend.list_folders()
    print(f"OK: signed in as {address}; {len(folders)} mail folders visible")


def cmd_set_password(args: argparse.Namespace) -> None:
    try:
        import keyring  # type: ignore
    except ImportError:
        sys.exit("Install the keyring extra: pip install 'ews-mcp[keyring]'")
    email = args.email or os.environ.get("EWS_MCP_EMAIL", "").strip() or input("Work e-mail: ").strip()
    password = getpass.getpass(f"Exchange password for {email}: ")
    keyring.set_password(KEYRING_SERVICE, email, password)
    print("Stored in the system keyring.")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="ews-mcp", description="Read-only MCP server for an Exchange mailbox")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--log-level", default=os.environ.get("EWS_MCP_LOG_LEVEL", "INFO"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the hosted HTTP server (config from EWS_MCP_* env vars)")
    s.set_defaults(fn=cmd_serve)

    for name, fn, help_ in (
        ("stdio", cmd_stdio, "run as a local MCP server over stdio for one person"),
        ("check", cmd_check, "verify the Exchange login and list folders, then exit"),
    ):
        q = sub.add_parser(name, help=help_)
        q.add_argument("--exchange-host")
        q.add_argument("--email")
        q.add_argument("--username")
        q.set_defaults(fn=fn)

    k = sub.add_parser("set-password", help="store the Exchange password in the OS keyring (local mode)")
    k.add_argument("--email")
    k.set_defaults(fn=cmd_set_password)

    args = p.parse_args(argv)
    _logging(args.log_level)
    args.fn(args)


if __name__ == "__main__":
    main()
