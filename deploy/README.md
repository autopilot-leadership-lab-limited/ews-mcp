# Deploying the hosted server

One small Linux VM or container, behind a reverse proxy that terminates TLS. The process itself
listens on localhost only.

## 0. Prepare the host (Ubuntu 24.04)

Cloud firewall (security group): inbound 80 and 443 from anywhere; 22 only from the operator's
own address, and removed altogether once Tailscale works. Log in as the non-root sudo user with an
SSH key, then:

```sh
git clone https://github.com/autopilot-leadership-lab-limited/ews-mcp.git ~/ews-mcp
sudo bash ~/ews-mcp/deploy/harden-ubuntu.sh
```

The script is idempotent and prints what it does: updates and automatic security upgrades, a swap
file, key-only sshd, CrowdSec (blocks scanning and brute-force addresses, community blocklist
included), public DNS resolvers (Alibaba Cloud's internal resolvers sit inside the CGNAT range
Tailscale routes, so names stop resolving once Tailscale is up), Tailscale (private admin
network), Caddy, Python tooling. It ends by telling the
operator to run `sudo tailscale up --accept-dns=false`, verify SSH over the Tailscale address, and then close public
port 22 in the security group. Every later admin login goes over Tailscale.

## 1. Install

```sh
sudo useradd --system --home /var/lib/ews-mcp --shell /usr/sbin/nologin ews-mcp
sudo mkdir -p /var/lib/ews-mcp /opt/ews-mcp && sudo chown ews-mcp: /var/lib/ews-mcp
sudo chmod 700 /var/lib/ews-mcp
cd /opt/ews-mcp && sudo python3 -m venv venv && sudo ./venv/bin/pip install 'git+https://github.com/autopilot-leadership-lab-limited/ews-mcp@v0.1.0'
```

Pin a tag (or a full commit SHA), never a branch, so the running code is a release colleagues can
read in the repo. `v0.1.0` is the first release: read-only tools, validated in local mode on
2026-11-09.

## 2. Configure

Copy `ews-mcp.env.example` to `/etc/ews-mcp.env`, fill in the public URL and the Exchange host, and
`chmod 600` it:

```sh
sudo cp ~/ews-mcp/deploy/ews-mcp.env.example /etc/ews-mcp.env
sudo chmod 600 /etc/ews-mcp.env
sudo nano /etc/ews-mcp.env      # set EWS_MCP_BASE_URL and EWS_MCP_EXCHANGE_HOST
```
 The file holds no secrets today (the master key is generated into the data dir on
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

```sh
sudo cp ~/ews-mcp/deploy/Caddyfile.example /etc/caddy/Caddyfile
sudo sed -i 's/mail-mcp.example.com/<your public host name>/' /etc/caddy/Caddyfile
sudo systemctl restart caddy
curl -s https://<your public host name>/health
```

The DNS A record for the host name must already point at the server, or Caddy cannot obtain a
certificate.

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
