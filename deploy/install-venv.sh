#!/usr/bin/env bash
# Create the FalconEye Python venv and install the package. Run as root on the target VPS.
set -euo pipefail

VENV=/opt/falconeye/venv
SRC=/opt/falconeye/src

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
