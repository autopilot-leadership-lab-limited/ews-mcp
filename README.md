# ews-mcp — read-only MCP server for a self-hosted Exchange mailbox

An [MCP](https://modelcontextprotocol.io) server that lets any AI assistant read the signed-in
person's **own** mailbox on a self-hosted Microsoft Exchange server, over EWS (Exchange Web
Services). It is vendor-neutral: any MCP client works (Claude, ChatGPT, Cursor, VS Code, Gemini
CLI, …), on desktop, web or mobile.

**What it can do:** list folders, search mail (Inbox, Sent Items or any folder), read one message,
read a whole conversation.

**What it cannot do, by design:** send, reply, forward, delete, move, flag or mark mail as read,
change rules or settings, open attachments. There is no code path for any of these. A later phase
may add *saving drafts* (never sending).

This is ALLab's first AI workflow; the rules it implements are in
[`allab-workspace/systems/exchange-mail.md`](https://github.com/autopilot-leadership-lab-limited/allab-workspace/blob/main/systems/exchange-mail.md).

## Two ways to run it

| | Hosted (remote MCP) | Local (stdio) |
|---|---|---|
| Who it serves | Many people, each with their own login | One person, on their own computer |
| AI clients | Any that supports remote MCP: desktop, web **and mobile** apps | Desktop apps and CLIs only |
| Sign-in | OAuth 2.1 between the AI client and this server; the person enters their Exchange password **once** on this server's login page | Password from the OS keyring or an env var |
| Where the Exchange password lives | Encrypted (Fernet) in SQLite on the server; master key in a separate file | The person's OS keyring |

The AI vendor never sees the Exchange password in either mode. In hosted mode it only holds an
OAuth token issued by this server.

## Hosted mode

### Requirements

- Python 3.11+ on a server that can reach `https://<exchange-host>/EWS/Exchange.asmx` and is
  reachable by the AI vendors over HTTPS.
- A reverse proxy that terminates TLS (Caddy, nginx) and forwards to this process on localhost.
  `deploy/` has a Caddyfile and a systemd unit.

### Configuration (environment variables)

| Variable | Meaning |
|---|---|
| `EWS_MCP_BASE_URL` | Public URL of this server, e.g. `https://mail-mcp.example.com` (no trailing slash) |
| `EWS_MCP_EXCHANGE_HOST` | Exchange host name, e.g. `mail.example.com`. Only this host is ever contacted |
| `EWS_MCP_DATA_DIR` | Where the SQLite database and master key live (default `./data`). Back it up; keep it `0700` |
| `EWS_MCP_EXCHANGE_AUTH` | Optional: `NTLM` or `basic`. Default: detect |
| `EWS_MCP_BIND_HOST` / `EWS_MCP_BIND_PORT` | Where uvicorn listens (default `127.0.0.1:8000`) |
| `EWS_MCP_FORWARDED_ALLOW_IPS` | Reverse-proxy IPs trusted for `X-Forwarded-*` (default `127.0.0.1`) |
| `EWS_MCP_LOG_LEVEL` | Default `INFO`. Logs never contain mail content, even at `DEBUG` |

### Run

```sh
pip install .
export EWS_MCP_BASE_URL=https://mail-mcp.example.com EWS_MCP_EXCHANGE_HOST=mail.example.com
export EWS_MCP_DATA_DIR=/var/lib/ews-mcp
ews-mcp serve
```

Endpoints: `/mcp` (MCP, bearer-protected), `/.well-known/oauth-authorization-server`,
`/authorize`, `/token`, `/register`, `/revoke` (OAuth), `/login` (sign-in page the OAuth flow
sends people to), `/relogin` (update a changed password), `/health`.

### Connect an AI client

Add `https://mail-mcp.example.com/mcp` as a **remote MCP server** (sometimes called a custom
connector or custom integration) in the AI app. The app discovers the OAuth endpoints, opens the
sign-in page in a browser, and the person enters their work e-mail and Exchange password once.
Access tokens last 1 hour and refresh silently for 30 days; after that the person signs in again.

If the person changes their Exchange password, the connector stops at the first failed login (it
never retries, so it cannot lock the directory account) and the AI tells them to visit `/relogin`.

### Adding a second person

The pilot deployment serves one person. Before anyone else is connected, one of the three
conditions in `exchange-mail.md` ("Before a second person is connected") must be in place.

## Local mode

macOS / Linux:

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install '.[keyring]'
export EWS_MCP_EXCHANGE_HOST=mail.example.com EWS_MCP_EMAIL=you@example.com
# optional, when the login name differs from the e-mail:
export EWS_MCP_USERNAME='DOMAIN\you'
ews-mcp set-password        # prompts for the password; stored in the OS keyring
ews-mcp check               # verifies the login and lists folders
```

Windows (PowerShell; needs Python 3.11+ from python.org with "Add to PATH" ticked):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install -e ".[keyring]"
$env:EWS_MCP_EXCHANGE_HOST = "mail.example.com"
$env:EWS_MCP_EMAIL = "you@example.com"
# $env:EWS_MCP_USERNAME = "DOMAIN\you"   # only if the login name differs
ews-mcp set-password            # prompts; stored in Windows Credential Manager
ews-mcp check
```

`$env:` settings last for that window only; the AI client config below sets them per launch.

Then register `ews-mcp stdio` in the AI app. Generic MCP config (Claude Desktop, Cursor, VS Code,
Gemini CLI and most others accept this shape):

```json
{
  "mcpServers": {
    "exchange-mail": {
      "command": "ews-mcp",
      "args": ["stdio"],
      "env": {
        "EWS_MCP_EXCHANGE_HOST": "mail.example.com",
        "EWS_MCP_EMAIL": "you@example.com"
      }
    }
  }
}
```

## Tools

| Tool | Does |
|---|---|
| `list_folders` | Folder paths with total and unread counts |
| `search_messages` | Headers from one folder, newest first; filters: text, sender, recipient, subject, since/until, has_attachments, unread_only; pages of ≤ 50 |
| `get_message` | One message: headers, plain-text body (truncated at a limit), attachment names |
| `get_thread` | A conversation across Inbox and Sent Items, oldest first |

Every tool is annotated read-only. The server's instructions tell the AI that mail is
confidential, must not go into long-term memory, and is data rather than instructions.

## Development

```sh
pip install -e '.[dev]'
pytest
ruff check src tests
```

Tests use a fake mail backend; nothing talks to a real Exchange server. The EWS backend
(`src/ews_mcp/ews.py`) must be validated against the real server with `ews-mcp check` and a few
searches before rollout; see the checklist in `deploy/README.md`.

## Layout

```
src/ews_mcp/
  backend.py   MailBackend interface and data models (read-only by construction)
  ews.py       EWS implementation (exchangelib); only FindFolder/GetFolder/FindItem/GetItem
  store.py     SQLite: encrypted logins, OAuth clients, codes, hashed tokens
  accounts.py  Person -> backend; stops on the first auth failure
  oauth.py     OAuth 2.1 authorization server + sign-in pages
  tools.py     The MCP server and its four tools
  app.py       Hosted app assembly from environment
  cli.py       serve / stdio / check / set-password
```
