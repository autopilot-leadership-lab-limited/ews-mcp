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


def _extra_addresses(args: argparse.Namespace) -> list[str]:
    raw = getattr(args, "mailboxes", None) or os.environ.get("EWS_MCP_EXTRA_MAILBOXES", "")
    seen: list[str] = []
    for part in raw.replace(";", ",").split(","):
        addr = part.strip()
        if addr and addr.lower() not in (s.lower() for s in seen):
            seen.append(addr)
    return seen


def _extra_credentials(args: argparse.Namespace, primary_email: str):
    """Credentials for EWS_MCP_EXTRA_MAILBOXES: one address each, password from the OS keyring."""
    from .ews import EwsCredentials

    out = []
    for addr in _extra_addresses(args):
        if addr.lower() == primary_email.lower():
            continue
        try:
            import keyring  # type: ignore

            password = keyring.get_password(KEYRING_SERVICE, addr) or ""
        except ImportError:
            password = ""
        if not password:
            sys.exit(f"No password for {addr}: run `ews-mcp set-password --email {addr}`")
        out.append(EwsCredentials(email=addr, username=addr, password=password))
    return out


def _local_accounts(args: argparse.Namespace):
    from .accounts import LocalAccounts
    from .ews import EwsBackend

    settings = _local_settings(args)
    primary = _local_credentials(args)
    extras = {c.email: EwsBackend(settings, c) for c in _extra_credentials(args, primary.email)}
    return LocalAccounts(EwsBackend(settings, primary), primary_address=primary.email, extras=extras)


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
    from .tools import build_server

    mcp = build_server(_local_accounts(args))
    mcp.run(transport="stdio")


def cmd_check(args: argparse.Namespace) -> None:
    from .backend import AuthFailed

    accounts = _local_accounts(args)
    for box in accounts.mailboxes("local"):
        backend = accounts.backend_for("local", None if box.primary else box.address)
        try:
            address = backend.verify()
        except AuthFailed:
            # Stop at the first rejected login: no further attempts, so no account lockout.
            sys.exit(
                f"FAILED: {box.address} rejected the login. Fix it with `ews-mcp set-password --email {box.address}`"
            )
        folders = backend.list_folders()
        print(f"OK: {address}{' (primary)' if box.primary else ''}; {len(folders)} mail folders visible")


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
        q.add_argument(
            "--mailboxes", help="additional mailbox addresses, comma separated (or EWS_MCP_EXTRA_MAILBOXES)"
        )
        q.set_defaults(fn=fn)

    k = sub.add_parser("set-password", help="store the Exchange password in the OS keyring (local mode)")
    k.add_argument("--email")
    k.set_defaults(fn=cmd_set_password)

    args = p.parse_args(argv)
    _logging(args.log_level)
    args.fn(args)


if __name__ == "__main__":
    main()
