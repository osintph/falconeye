#!/bin/bash
# FalconEye provisioning script, Ubuntu 22.04 / 24.04
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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Install and upgrade share one implementation of every step they both do (log
# directory, systemd unit, nginx snippets, database, health check). Two copies of
# those steps is how they drifted: the upgrade path missed a unit change in
# v3.34.2, and this script installed one of the two nginx snippets the vhost
# includes, so "nginx -t" failed on a genuinely fresh box.
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

REPO_URL="$FE_REPO_URL"
INSTALL_DIR="$FE_INSTALL_DIR"
SERVICE_USER="$FE_SERVICE_USER"
RUN_TESTS=false

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --test) RUN_TESTS=true ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

echo "=== FalconEye Provisioning ==="

echo "[1/9] Creating directories..."
mkdir -p "$INSTALL_DIR/data"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
# The log directory gunicorn writes to, owned by the service user. The unit also
# declares LogsDirectory=falconeye, so systemd creates and re-owns it on every
# start; this stays because anyone running gunicorn by hand before the unit is
# installed has no systemd doing it. Same function the upgrade uses.
fe_ensure_log_dir

echo "[2/9] Updating package index..."
apt-get update -qq

echo "[3/9] Installing system dependencies..."
# Native dependencies, and why each is here. pip installs none of them.
#
# The wheels for lxml, Pillow and rapidfuzz statically link what they need
# (verified with ldd: their .so files resolve only libc, libm, libstdc++ and
# libz), so compiled extension modules are self-contained. The real gaps are
# the two mechanisms ldd cannot see: libraries dlopened at runtime through
# ctypes, and binaries invoked as subprocesses. Both fail late, and neither
# shows up as a pip error.
#
#   libzbar0  pyzbar dlopens it via ctypes.util.find_library("zbar") for the
#             QR Code tab. Without it, importing the app dies with
#             "ImportError: Unable to find zbar shared library".
#             On Ubuntu 24.04 the real package is libzbar0t64 after the time_t
#             transition, but it Provides: libzbar0, so this one name resolves
#             correctly on both 22.04 and 24.04.
#   whois     app/routers/domain_intel.py runs "whois <domain>" as the fallback
#             when RDAP returns nothing useful. Its absence is caught and
#             logged, so the tab silently loses that fallback rather than
#             erroring, which makes it easy to miss. Priority "standard", so it
#             is present on a full Ubuntu install but NOT on the minimal cloud
#             images most VPS and AWS instances use.
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    git redis-server \
    libzbar0 whois

echo "[4/9] Cloning repository..."
if [[ -d "$INSTALL_DIR/app_src/.git" ]]; then
    echo "  Repository already present, pulling latest..."
    git -C "$INSTALL_DIR/app_src" pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR/app_src"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/app_src"

echo "[5/9] Creating virtualenv and installing dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/app_src/requirements.txt" --quiet
# LLM tabs and .msg upload require packages not in requirements.txt.
# Install them if not already present; failures are non-fatal.
"$INSTALL_DIR/venv/bin/pip" install "anthropic>=0.25" "extract-msg>=0.28" --quiet 2>/dev/null || \
    echo "  [NOTE] anthropic / extract-msg install failed, LLM tabs and .msg upload will be unavailable."

echo "[6/9] Initializing database..."
fe_db_init
# A new database has nothing to migrate, so record every release action as
# already applied. Without this the first upgrade would replay flushes written
# for older schemas against a database that never had them.
fe_baseline_release_actions
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/data/falconeye.db"
chmod 600 "$INSTALL_DIR/data/falconeye.db"
chmod 700 "$INSTALL_DIR/data"

# Run pre-flight check against existing .env (if present)
fe_preflight_env

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

echo "[7/9] Smoke test: importing the application..."
# A missing native library does not fail "pip install". It fails at import, and
# without this check the first import happens inside a gunicorn worker, where
# systemd restarts it every 5 seconds and the real traceback scrolls past in the
# journal. Fail here instead, once, with the actual error in front of the
# operator and the service left disabled.
cd "$INSTALL_DIR/app_src"
if ! "$INSTALL_DIR/venv/bin/python" -c "import app.main"; then
    echo "" >&2
    echo "[FAIL] 'import app.main' failed. The service was NOT enabled." >&2
    echo "       An ImportError naming a shared library means a missing system" >&2
    echo "       package rather than a missing Python one. See the dependency" >&2
    echo "       list in step 3 above, and 'Prerequisites: system packages' in" >&2
    echo "       docs/deploy-runbook.md." >&2
    exit 1
fi
echo "  import app.main OK"

# Checked separately because it is a subprocess, not an import: nothing above
# would have caught it. Not fatal, because the app handles its absence.
if ! command -v whois >/dev/null 2>&1; then
    echo "  [WARNING] the 'whois' binary is missing, so Domain Intel's whois"
    echo "            fallback will quietly return nothing. Fix: apt-get install whois"
fi

echo "[8/9] Installing systemd service..."
fe_install_unit
fe_enable_service
fe_restart_service
sleep 2
systemctl status "$FE_SERVICE" --no-pager -l

echo "[9/9] Installing nginx config..."
# The vhost has two file dependencies. Install them BEFORE the vhost itself or
# "nginx -t" fails on an unresolved reference and provisioning aborts here.
#
# 1. EVERY file in nginx/snippets/ is installed, because the vhost includes more
#    than one of them: cloudflare-origin-allow.conf (which locks the origin to
#    Cloudflare edge ranges) and security-headers.conf (included at server level
#    and inside four locations). Until v3.34.3 this step named the first by hand
#    and a fresh box failed "nginx -t" on the second. Not behind Cloudflare? See
#    "Deploying without Cloudflare" in docs/deploy-runbook.md before going live:
#    as shipped the origin snippet denies everyone.
# 2. conf.d/goaccess-logformat.conf is OPTIONAL and is NOT installed. It defines
#    log_format goaccess_cf, which only makes sense behind Cloudflare. See
#    "GoAccess log format" in docs/deploy-runbook.md.
fe_install_nginx_snippets

# The vhost terminates TLS with a Cloudflare Origin CA certificate at these
# paths. Nothing in this script creates them, and "nginx -t" treats a missing
# certificate as a fatal error, so say so plainly rather than let nginx fail
# with a bare "cannot load certificate".
for cert in /etc/ssl/falconeye/origin.crt /etc/ssl/falconeye/origin.key; do
    if [[ ! -f "$cert" ]]; then
        echo "[WARNING] $cert is missing. nginx will refuse to start until it exists."
        echo "          Behind Cloudflare: issue an Origin CA certificate in the"
        echo "          dashboard (SSL/TLS > Origin Server) and save it there."
        echo "          Not behind Cloudflare: use a publicly trusted certificate"
        echo "          (certbot) and point ssl_certificate at it instead."
    fi
done

# The vhost is installed HERE and nowhere else. scripts/upgrade.sh never writes
# it: once a box is live, server_name and the certificate paths in that file are
# the operator's, not ours.
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
# Read the hostname from the vhost that was just installed rather than
# hardcoding the upstream operator's domain, which a self-hoster does not own
# and cannot reach. Falls back to the local origin, which is also the right
# answer before DNS is pointed at the box.
SERVER_NAME=$(awk '$1 == "server_name" { sub(/;$/, "", $2); print $2; exit }' \
    /etc/nginx/sites-available/falconeye 2>/dev/null || true)
if [[ -n "${SERVER_NAME:-}" && "$SERVER_NAME" != "_" && "$SERVER_NAME" != "localhost" ]]; then
    echo "  via $SERVER_NAME (from the installed vhost)"
    curl -sk "https://${SERVER_NAME}/health" || curl -s http://127.0.0.1:8000/health
else
    echo "  via the local origin (no usable server_name in the vhost)"
    curl -s http://127.0.0.1:8000/health
fi
