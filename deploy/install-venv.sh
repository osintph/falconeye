#!/usr/bin/env bash
# Create the FalconEye Python venv and install the package. Run as root on the target VPS.
# Idempotent: re-running on a working system exits cleanly without making changes.
set -euo pipefail

VENV=/opt/falconeye/venv
SRC=/opt/falconeye/src

# Preflight: root, user, directory tree, secrets — skip venv check (we're creating it)
PREFLIGHT_SKIP_VENV_CHECK=1
# shellcheck source=lib/preflight.sh
source "$(dirname "$0")/lib/preflight.sh"

# --- Venv (idempotent) ---
if [ -x "${VENV}/bin/python" ]; then
  echo "venv already exists at ${VENV}, skipping creation."
else
  echo "Creating venv at ${VENV} ..."
  sudo -u falconeye python3 -m venv "${VENV}"
fi

echo "Upgrading pip ..."
sudo -u falconeye "${VENV}/bin/pip" install -U pip --quiet

echo "Installing falconeye package ..."
sudo -u falconeye "${VENV}/bin/pip" install -e "${SRC}" --quiet

echo "venv ready at ${VENV}"
