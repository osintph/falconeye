#!/bin/bash
# FalconEye provisioning script — Ubuntu 22.04 / 24.04
# Run as root: sudo bash scripts/provision.sh [--test]
#
# Flags:
#   --test    Run pytest after installing dependencies and before enabling
#             the systemd service. Requires the test suite to pass (122 passed,
#             3 skipped baseline) or the script exits without starting the service.
#
# Note on dependency pinning: requirements.txt pins most packages to known-good
# versions, but Pillow uses >= instead of ==. Review pip install output for
# unexpected upgrades before deploying to production. A full pip freeze of the
# working venv is the safest way to lock a production environment.

set -euo pipefail

REPO_URL="https://github.com/osintph/falconeye.git"
INSTALL_DIR="/opt/falconeye"
SERVICE_USER="ubuntu"
RUN_TESTS=false

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --test) RUN_TESTS=true ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

echo "=== FalconEye v3.5.0 Provisioning ==="

# --- Pre-flight: warn if critical env vars are missing in the target .env file ---
# The service will start either way, but LLM tabs and Image Search will be broken
# without these. The .env file is expected at $INSTALL_DIR/.env.
preflight_warn() {
    local env_file="$INSTALL_DIR/.env"
    if [[ ! -f "$env_file" ]]; then
        echo "[WARNING] No .env found at $env_file — copy and fill in .env.example after provisioning."
        return
    fi
    for var in IMAGE_UPLOAD_SECRET FALCONEYE_DB; do
        if ! grep -q "^${var}=.\+" "$env_file" 2>/dev/null; then
            echo "[WARNING] $env_file: $var is missing or empty — some features will not work."
        fi
    done
    # Detect old DB_PATH alias from pre-v3.5.0 .env files
    if grep -q "^DB_PATH=" "$env_file" 2>/dev/null && ! grep -q "^FALCONEYE_DB=" "$env_file" 2>/dev/null; then
        echo "[WARNING] $env_file uses DB_PATH= (pre-v3.5.0 name). Rename to FALCONEYE_DB= — the app will not find the database otherwise."
    fi
}

echo "[1/8] Creating directories..."
mkdir -p "$INSTALL_DIR/data"
mkdir -p /var/log/falconeye
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chown "$SERVICE_USER:$SERVICE_USER" /var/log/falconeye

echo "[2/8] Updating package index..."
apt-get update -qq

echo "[3/8] Installing system dependencies..."
apt-get install -y --no-install-recommends python3 python3-pip python3-venv git redis-server

echo "[4/8] Cloning repository..."
if [[ -d "$INSTALL_DIR/app_src/.git" ]]; then
    echo "  Repository already present — pulling latest..."
    git -C "$INSTALL_DIR/app_src" pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR/app_src"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/app_src"

echo "[5/8] Creating virtualenv and installing dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/app_src/requirements.txt" --quiet
# LLM tabs and .msg upload require packages not in requirements.txt.
# Install them if not already present; failures are non-fatal.
"$INSTALL_DIR/venv/bin/pip" install "anthropic>=0.25" "extract-msg>=0.28" --quiet 2>/dev/null || \
    echo "  [NOTE] anthropic / extract-msg install failed — LLM tabs and .msg upload will be unavailable."

echo "[6/8] Initializing database..."
FALCONEYE_DB="$INSTALL_DIR/data/falconeye.db" \
    "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/app_src/scripts/db_init.py"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/data/falconeye.db"
chmod 600 "$INSTALL_DIR/data/falconeye.db"
chmod 700 "$INSTALL_DIR/data"

# Run pre-flight check against existing .env (if present)
preflight_warn

if [[ "$RUN_TESTS" == "true" ]]; then
    echo "[--test] Running test suite..."
    cd "$INSTALL_DIR/app_src"
    if ! "$INSTALL_DIR/venv/bin/python" -m pytest tests/ \
            --ignore=tests/image_search/test_routes.py \
            --ignore=tests/prospect/test_routes.py \
            -q 2>&1; then
        echo "[FAIL] Test suite did not pass. Service will NOT be enabled. Fix the failures and re-run." >&2
        exit 1
    fi
    echo "[--test] Tests passed."
fi

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
echo "Next steps:"
echo "  1. Copy and fill in: cp $INSTALL_DIR/app_src/.env.example $INSTALL_DIR/.env"
echo "  2. Secure it: chmod 600 $INSTALL_DIR/.env"
echo "  3. Restart: systemctl restart falconeye"
echo ""
echo "Health check:"
curl -sk https://falconeye.osintph.info/health || curl -s http://127.0.0.1:8000/health
