#!/usr/bin/env bash
# Phase 2: obtain TLS certificate via certbot and enable HTTPS.
# Run as root on the target VPS after deploy/install-nginx.sh has succeeded.
set -euo pipefail

# shellcheck source=lib/preflight.sh
source "$(dirname "$0")/lib/preflight.sh"

CONF_DST=/etc/nginx/sites-enabled/falconeye.conf

if [ ! -L "${CONF_DST}" ] && [ ! -f "${CONF_DST}" ]; then
  echo "ERROR: nginx vhost not found at ${CONF_DST}."
  echo "Run deploy/install-nginx.sh first."
  exit 1
fi

if ! command -v certbot &>/dev/null; then
  echo "ERROR: certbot is not installed."
  echo "Install it with: sudo apt-get install -y certbot python3-certbot-nginx"
  exit 1
fi

echo "Obtaining TLS certificate via certbot ..."
certbot --nginx -d falconeye.osintph.info \
  --email sigmund@osintph.info \
  --agree-tos --no-eff-email --redirect

nginx -t
systemctl reload nginx

echo ""
echo "TLS certificate installed. HTTPS is now active."
echo "certbot will auto-renew via its own systemd timer."
