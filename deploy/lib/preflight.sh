#!/usr/bin/env bash
# Sourced by install-systemd.sh and install-nginx.sh.
# Exits 1 with a clear message if any pre-condition is not met.

_preflight_fail() {
  echo "[PREFLIGHT FAIL] $1"
  exit 1
}

# 1. falconeye system user exists
id falconeye &>/dev/null || _preflight_fail \
  "System user 'falconeye' does not exist. Run: sudo useradd --system --create-home --home-dir /opt/falconeye --shell /usr/sbin/nologin falconeye"

# 2. Python venv present
[ -x /opt/falconeye/venv/bin/python ] || _preflight_fail \
  "Python venv not found at /opt/falconeye/venv. Run: sudo bash deploy/install-venv.sh"

# 3. secrets.env exists and is readable
[ -f /opt/falconeye/config/secrets.env ] || _preflight_fail \
  "secrets.env not found at /opt/falconeye/config/secrets.env. Copy config/secrets.env.example and fill in the API keys."

# 4–6. All three required keys are present
grep -q "FALCONEYE_DB_PATH" /opt/falconeye/config/secrets.env || _preflight_fail \
  "FALCONEYE_DB_PATH is missing from /opt/falconeye/config/secrets.env."

grep -q "URLHAUS_AUTH_KEY" /opt/falconeye/config/secrets.env || _preflight_fail \
  "URLHAUS_AUTH_KEY is missing from /opt/falconeye/config/secrets.env."

grep -q "NVD_API_KEY" /opt/falconeye/config/secrets.env || _preflight_fail \
  "NVD_API_KEY is missing from /opt/falconeye/config/secrets.env."

# 7. /opt/falconeye/src is a git repo
git -C /opt/falconeye/src rev-parse --git-dir &>/dev/null || _preflight_fail \
  "/opt/falconeye/src is not a git repository. Clone the repo first: git clone https://github.com/osintph/falconeye.git /opt/falconeye/src"

echo "[PREFLIGHT OK]"
