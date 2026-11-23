#!/bin/sh
# One-off install on the VPS. Run as root after copying the sshmcp binary to /tmp/sshmcp.
set -eu
id sshmcp >/dev/null 2>&1 || useradd --system --home /var/lib/sshmcp --shell /usr/sbin/nologin sshmcp
install -d -o sshmcp -g sshmcp -m 700 /var/lib/sshmcp
install -d -m 755 /opt/sshmcp
install -m 755 /tmp/sshmcp /opt/sshmcp/sshmcp
install -m 644 deploy/sshmcp.service /etc/systemd/system/sshmcp.service
install -m 644 deploy/Caddyfile.mcp /etc/caddy/conf.d/mcp.caddy
systemctl daemon-reload
echo "Next: sudo -u sshmcp env SSHMCP_DIR=/var/lib/sshmcp /opt/sshmcp/sshmcp passwd && ... totp"
