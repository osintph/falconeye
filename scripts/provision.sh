#!/bin/bash
set -euo pipefail

REPO_URL="https://github.com/osintph/falconeye.git"
INSTALL_DIR="/opt/falconeye"
DB_DIR="/opt/falconeye/data"
SERVICE_NAME="falconeye"
PYTHON_MIN="3.11"

echo "=== FalconEye v2 VPS Provisioning ==="

# Wipe existing install
echo "[1/9] Wiping existing /opt/falconeye..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$DB_DIR"

# Update package index only — no autoremove, no full upgrade
echo "[2/9] Updating package index..."
apt-get update -qq

# Install Python and git if not present
echo "[3/9] Installing dependencies..."
apt-get install -y --no-install-recommends python3 python3-pip python3-venv git

# Clone repo
echo "[4/9] Cloning repository..."
git clone "$REPO_URL" "$INSTALL_DIR/app_src"

# Create virtualenv
echo "[5/9] Creating Python virtualenv..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/app_src/requirements.txt" --quiet

# Initialize database
echo "[6/9] Initializing database..."
cd "$INSTALL_DIR/app_src"
"$INSTALL_DIR/venv/bin/python" scripts/db_init.py

# Install systemd service
echo "[7/9] Installing systemd service..."
cp "$INSTALL_DIR/app_src/falconeye.service" /etc/systemd/system/falconeye.service
systemctl daemon-reload
systemctl enable falconeye
systemctl restart falconeye

# Install nginx config
echo "[8/9] Installing nginx config..."
cp "$INSTALL_DIR/app_src/nginx/falconeye.conf" /etc/nginx/sites-available/falconeye
ln -sf /etc/nginx/sites-available/falconeye /etc/nginx/sites-enabled/falconeye
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# Install cron cleanup job
echo "[9/9] Installing cron cleanup..."
echo "*/30 * * * * root find /tmp -name 'falconeye_*' -mmin +30 -delete" > /etc/cron.d/falconeye-cleanup
chmod 644 /etc/cron.d/falconeye-cleanup

echo ""
echo "=== Provisioning complete ==="
echo "Service status:"
systemctl status falconeye --no-pager -l
