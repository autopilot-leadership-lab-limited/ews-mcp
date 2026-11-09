# Deploying the hosted server

One small Linux VM or container, behind a reverse proxy that terminates TLS. The process itself
listens on localhost only.

## 1. Install

```sh
sudo useradd --system --home /var/lib/ews-mcp --shell /usr/sbin/nologin ews-mcp
sudo mkdir -p /var/lib/ews-mcp /opt/ews-mcp && sudo chown ews-mcp: /var/lib/ews-mcp
sudo chmod 700 /var/lib/ews-mcp
cd /opt/ews-mcp && sudo python3 -m venv venv && sudo ./venv/bin/pip install git+https://github.com/autopilot-leadership-lab-limited/ews-mcp@v0.1.0
```

Pin a tag, never a branch, so the running code is a release colleagues can read in the repo.

## 2. Configure

Copy `ews-mcp.env.example` to `/etc/ews-mcp.env`, fill in the public URL and the Exchange host, and
`chmod 600` it. The file holds no secrets today (the master key is generated into the data dir on
first start), but keep it tight anyway.

## 3. Run as a service

```sh
sudo cp deploy/ews-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ews-mcp
curl -s http://127.0.0.1:8000/health
```

## 4. Reverse proxy

`Caddyfile.example` gives automatic TLS. Keep the proxy on the same host (or set
`EWS_MCP_FORWARDED_ALLOW_IPS` to the proxy's address) so the rate limiter sees real client IPs.

## 5. Container alternative

```sh
docker build -t ews-mcp .
docker run -d --name ews-mcp --env-file /etc/ews-mcp.env -v ews-mcp-data:/data -p 127.0.0.1:8000:8000 ews-mcp
```

## Before the first real sign-in: validation checklist

The test suite runs against a fake backend. Validate the EWS backend against the real server once,
from a machine that can reach it, with the pilot user's own login:

1. `EWS_MCP_EXCHANGE_HOST=… EWS_MCP_EMAIL=… ews-mcp check` prints "OK" and a folder count.
   If it fails with an authentication error, try `EWS_MCP_USERNAME='DOMAIN\user'` and/or
   `EWS_MCP_EXCHANGE_AUTH=NTLM`.
2. `ews-mcp stdio` connected to a desktop AI client: run `search_messages` on `inbox` and `sent`,
   `get_message` on one result, `get_thread` on its `conversation_id`. Check that a message read
   this way is still unread in Outlook.
3. Only then deploy the hosted server and sign in through an AI app.

## Operations

- **Backups:** `/var/lib/ews-mcp` (database + `master.key`). Without the key the database is useless;
  with both, it holds encrypted mailbox passwords, so treat the backup as `restricted`.
- **Logs:** `journalctl -u ews-mcp`. They contain tool names, subjects (`sub`, the signed-in e-mail)
  and errors, never mail content.
- **Removing a person:** delete their row in `users` (`sqlite3 /var/lib/ews-mcp/ews-mcp.sqlite3
  "DELETE FROM users WHERE sub='x@example.com'"`); their tokens stop working at once.
- **Upgrading:** `pip install git+…@vX.Y.Z` into the venv, then `systemctl restart ews-mcp`.
