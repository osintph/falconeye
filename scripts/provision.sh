#!/bin/bash
set -euo pipefail

REPO_URL="https://github.com/osintph/falconeye.git"
INSTALL_DIR="/opt/falconeye"
SERVICE_USER="ubuntu"

echo "=== FalconEye v3 Provisioning ==="

echo "[1/8] Creating directories..."
mkdir -p "$INSTALL_DIR/data"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo "[2/8] Updating package index..."
apt-get update -qq

echo "[3/8] Installing system dependencies..."
apt-get install -y --no-install-recommends python3 python3-pip python3-venv git

echo "[4/8] Cloning repository..."
git clone "$REPO_URL" "$INSTALL_DIR/app_src"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/app_src"

echo "[5/8] Creating virtualenv and installing dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/app_src/requirements.txt" --quiet

echo "[6/8] Initializing database..."
FALCONEYE_DB="$INSTALL_DIR/data/falconeye.db" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/app_src/scripts/db_init.py"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/data/falconeye.db"

echo "[7/8] Installing systemd service..."
cp "$INSTALL_DIR/app_src/falconeye.service" /etc/systemd/system/falconeye.service
systemctl daemon-reload
systemctl enable falconeye
systemctl restart falconeye
sleep 2
systemctl status falconeye --no-pager -l

echo "[8/8] Installing nginx config..."
cp "$INSTALL_DIR/app_src/nginx/falconeye.conf" /etc/nginx/sites-available/falconeye
ln -sf /etc/nginx/sites-available/falconeye /etc/nginx/sites-enabled/falconeye
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ""
echo "=== Provisioning complete ==="
echo "Health check:"
curl -sk https://falconeye.osintph.info/health || curl -s http://127.0.0.1:8000/health
