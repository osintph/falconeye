#!/usr/bin/env bash
# Phase 1: install FalconEye HTTP-only nginx vhost.
# Run as root on the target VPS.
# After this script succeeds, run deploy/install-tls.sh for the TLS certificate.
set -euo pipefail

# shellcheck source=lib/preflight.sh
source "$(dirname "$0")/lib/preflight.sh"

CONF_SRC="$(cd "$(dirname "$0")/nginx" && pwd)/falconeye.conf"
CONF_DST=/etc/nginx/sites-available/falconeye.conf
LINK_DST=/etc/nginx/sites-enabled/falconeye.conf

echo "Installing nginx HTTP vhost ..."
cp "${CONF_SRC}" "${CONF_DST}"
chmod 644 "${CONF_DST}"

if [ ! -L "${LINK_DST}" ]; then
  ln -s "${CONF_DST}" "${LINK_DST}"
fi

nginx -t
systemctl reload nginx

echo ""
echo "Phase 1 complete. Dashboard is live on port 80."
echo "Run deploy/install-tls.sh to obtain the TLS certificate and enable HTTPS."
