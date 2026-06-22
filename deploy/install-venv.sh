#!/usr/bin/env bash
# Create the FalconEye Python venv and install the package. Run as root on the target VPS.
# Idempotent: re-running on a working system exits cleanly without making changes.
set -euo pipefail

VENV=/opt/falconeye/venv
SRC=/opt/falconeye/src
DIRS=(src public db logs config)

# --- Root check ---
if [ "$(id -u)" != "0" ]; then
  echo "ERROR: Run as root: sudo bash deploy/install-venv.sh"
  exit 1
fi

# --- System user check ---
if ! id falconeye &>/dev/null; then
  echo "ERROR: System user 'falconeye' does not exist."
  echo "Create it with:"
  echo "  sudo useradd --system --create-home --home-dir /opt/falconeye --shell /usr/sbin/nologin falconeye"
  exit 1
fi

# --- Directory tree check ---
TREE_OK=1
for d in "${DIRS[@]}"; do
  FULL="/opt/falconeye/${d}"
  if [ ! -d "${FULL}" ]; then
    echo "ERROR: Directory missing: ${FULL}"
    echo "  Fix: sudo -u falconeye mkdir -p ${FULL}"
    TREE_OK=0
  elif [ "$(stat -c '%U' "${FULL}")" != "falconeye" ]; then
    echo "ERROR: ${FULL} is not owned by falconeye."
    echo "  Fix: sudo chown falconeye:falconeye ${FULL}"
    TREE_OK=0
  fi
done
if [ "${TREE_OK}" != "1" ]; then
  exit 1
fi

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
