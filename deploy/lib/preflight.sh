#!/usr/bin/env bash
# Sourced by install-venv.sh, install-systemd.sh, install-nginx.sh, install-tls.sh.
# Each failing check prints what is missing and how to fix it, then exits non-zero.
# Set PREFLIGHT_SKIP_VENV_CHECK=1 before sourcing to skip the venv check
# (used by install-venv.sh, which is the script that creates the venv).

_preflight_fail() {
  echo "[PREFLIGHT FAIL] $1"
  exit 1
}

# --- Root ---
[ "$(id -u)" = "0" ] || _preflight_fail \
  "This script must be run as root. Re-run with: sudo bash $0"

# --- System user ---
id falconeye &>/dev/null || _preflight_fail \
  "System user 'falconeye' does not exist.
  Fix: sudo useradd --system --create-home --home-dir /opt/falconeye --shell /usr/sbin/nologin falconeye"

# --- Directory tree ownership ---
for _dir in src public db logs config; do
  _full="/opt/falconeye/${_dir}"
  if [ ! -d "${_full}" ]; then
    _preflight_fail "Directory missing: ${_full}
  Fix: sudo -u falconeye mkdir -p ${_full}"
  fi
  _owner="$(stat -c '%U' "${_full}")"
  if [ "${_owner}" != "falconeye" ]; then
    _preflight_fail "${_full} is owned by '${_owner}', expected 'falconeye'.
  Fix: sudo chown falconeye:falconeye ${_full}"
  fi
done

# --- Python venv (skipped when install-venv.sh sources this file) ---
if [ "${PREFLIGHT_SKIP_VENV_CHECK:-0}" != "1" ]; then
  [ -x /opt/falconeye/venv/bin/python ] || _preflight_fail \
    "Python venv not found at /opt/falconeye/venv.
  Fix: sudo bash deploy/install-venv.sh"
fi

# --- secrets.env exists ---
[ -f /opt/falconeye/config/secrets.env ] || _preflight_fail \
  "secrets.env not found at /opt/falconeye/config/secrets.env.
  Fix: sudo -u falconeye cp /opt/falconeye/src/config/secrets.env.example /opt/falconeye/config/secrets.env
       then fill in URLHAUS_AUTH_KEY and NVD_API_KEY"

# --- Required keys present ---
for _key in FALCONEYE_DB_PATH FALCONEYE_OUTPUT_DIR URLHAUS_AUTH_KEY NVD_API_KEY; do
  grep -q "^${_key}=" /opt/falconeye/config/secrets.env || _preflight_fail \
    "${_key} is missing from /opt/falconeye/config/secrets.env."
done

# --- /opt/falconeye/src is a git repo ---
git -C /opt/falconeye/src rev-parse --git-dir &>/dev/null || _preflight_fail \
  "/opt/falconeye/src is not a git repository.
  Fix: sudo -u falconeye git clone https://github.com/osintph/falconeye.git /opt/falconeye/src"

echo "[PREFLIGHT OK]"
