#!/usr/bin/env bash
# Baseline hardening for a fresh Ubuntu 24.04 VM that will host ews-mcp (and later
# other AI workspace tools). Idempotent: safe to run again.
#
#   sudo bash deploy/harden-ubuntu.sh
#
# What it does, in order (each step prints a heading):
#   1. system updates + automatic security updates
#   2. 2 GiB swap file (small VMs have none)
#   3. sshd: key-only, no root login
#   4. CrowdSec + firewall bouncer: blocks IPs that scan or brute-force, using the
#      community blocklist as well as local detections
#   5. Tailscale: private admin network, so public SSH can be closed afterwards
#   6. Caddy: reverse proxy with automatic TLS
#   7. Python 3 venv tooling + git
#
# It does NOT change the cloud firewall (security group) and does NOT run
# `tailscale up`; both need the operator. See deploy/README.md.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive

step() { printf '\n==> %s\n' "$*"; }

step "1/7 System updates and unattended security upgrades"
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q unattended-upgrades apt-listchanges curl gnupg ca-certificates
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
# Reboot automatically for kernel updates at a quiet hour (HKT 04:30 = 20:30 UTC).
sed -i 's|^//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "20:30";|' /etc/apt/apt.conf.d/50unattended-upgrades
systemctl enable --now unattended-upgrades

step "2/7 Swap file (2 GiB)"
if ! swapon --show | grep -q '^/swapfile'; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi
sysctl -q -w vm.swappiness=10
echo 'vm.swappiness=10' >/etc/sysctl.d/90-swappiness.conf

step "3/7 sshd: keys only, no root login"
install -d -m 755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/90-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
EOF
sshd -t
systemctl reload ssh || systemctl reload sshd

step "4/7 CrowdSec and its firewall bouncer"
if ! command -v cscli >/dev/null; then
  curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey | gpg --dearmor -o /usr/share/keyrings/crowdsec.gpg
  echo "deb [signed-by=/usr/share/keyrings/crowdsec.gpg] https://packagecloud.io/crowdsec/crowdsec/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") main" \
    >/etc/apt/sources.list.d/crowdsec.list
  apt-get update -q
fi
apt-get install -y -q crowdsec crowdsec-firewall-bouncer-nftables
cscli collections install crowdsecurity/sshd crowdsecurity/linux crowdsecurity/caddy --force >/dev/null 2>&1 || true
systemctl enable --now crowdsec crowdsec-firewall-bouncer

step "5/7 Tailscale"
# Alibaba Cloud's internal services (DNS 100.100.2.x, package mirror, metadata
# 100.100.100.200, Cloud Assistant) live inside 100.64.0.0/10, the CGNAT range that
# Tailscale routes into the tailnet, so they all go dark once tailscaled is up. Send
# 100.100.0.0/16 through the main routing table instead, persistently. Harmless on
# other clouds.
cat >/etc/systemd/system/alicloud-cgnat-route.service <<'EOF'
[Unit]
Description=Let Alibaba Cloud internal services (100.100.0.0/16) work next to Tailscale
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Routing: send that range through the main table, not into the tailnet.
ExecStart=/bin/sh -c 'ip rule show | grep -q "to 100.100.0.0/16 lookup main" || ip rule add to 100.100.0.0/16 lookup main priority 5000'
# Filtering: Tailscale's ts-input chain drops CGNAT-range packets not from tailscale0;
# let replies from Alibaba's service range in on eth0 (approved by the IT head 2026-11-09).
ExecStart=/bin/sh -c 'iptables -C INPUT -s 100.100.0.0/16 -i eth0 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s 100.100.0.0/16 -i eth0 -j ACCEPT'
ExecStop=/bin/sh -c 'ip rule del to 100.100.0.0/16 lookup main priority 5000 || true'
ExecStop=/bin/sh -c 'iptables -D INPUT -s 100.100.0.0/16 -i eth0 -j ACCEPT || true'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now alicloud-cgnat-route
if ! command -v tailscale >/dev/null; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi
systemctl enable --now tailscaled

step "6/7 Caddy"
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' >/etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
fi
apt-get install -y -q caddy
systemctl enable caddy

step "7/7 Python tooling and git"
apt-get install -y -q python3-venv python3-pip git sqlite3

step "Done"
cat <<'EOF'
Next (operator):
  1. sudo tailscale up --accept-dns=false
                                  -> open the printed link, sign in, approve the machine
                                     (--accept-dns=false keeps the cloud DNS; Tailscale DNS
                                     broke name resolution on the first Alibaba Cloud VM)
     tailscale ip -4              -> note the 100.x address; test:  ssh ecs-user@<100.x>
  2. In the cloud console, remove the public SSH (22) rule from the security group.
  3. Continue with deploy/README.md to install ews-mcp and Caddy config.
EOF
