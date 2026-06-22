#!/usr/bin/env bash
# Install FalconEye nginx vhost and obtain TLS cert. Run as root on the target VPS.
set -euo pipefail

CONF_SRC="$(cd "$(dirname "$0")/nginx" && pwd)/falconeye.conf"
CONF_DST=/etc/nginx/sites-available/falconeye.conf
LINK_DST=/etc/nginx/sites-enabled/falconeye.conf

echo "Installing nginx vhost ..."
cp "${CONF_SRC}" "${CONF_DST}"
chmod 644 "${CONF_DST}"

if [ ! -L "${LINK_DST}" ]; then
  ln -s "${CONF_DST}" "${LINK_DST}"
fi

nginx -t
systemctl reload nginx

echo ""
echo "Obtaining TLS certificate via certbot ..."
certbot --nginx -d falconeye.osintph.info \
  --email sigmund@osintph.info \
  --agree-tos --no-eff-email --redirect

nginx -t
systemctl reload nginx

echo "nginx vhost installed and TLS certificate obtained."
