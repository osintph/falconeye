#!/usr/bin/env bash
# Install FalconEye systemd units. Run as root on the target VPS.
set -euo pipefail

UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "$0")/systemd" && pwd)"

UNITS=(
  falconeye-urlhaus.service  falconeye-urlhaus.timer
  falconeye-kev.service      falconeye-kev.timer
  falconeye-nvd.service      falconeye-nvd.timer
  falconeye-apnic.service    falconeye-apnic.timer
  falconeye-ssg.service      falconeye-ssg.timer
)

echo "Copying unit files to ${UNIT_DIR} ..."
for unit in "${UNITS[@]}"; do
  cp "${SRC_DIR}/${unit}" "${UNIT_DIR}/${unit}"
  chmod 644 "${UNIT_DIR}/${unit}"
done

systemctl daemon-reload

TIMERS=(
  falconeye-urlhaus.timer
  falconeye-kev.timer
  falconeye-nvd.timer
  falconeye-apnic.timer
  falconeye-ssg.timer
)

echo "Enabling and starting timers ..."
for timer in "${TIMERS[@]}"; do
  systemctl enable --now "${timer}"
done

echo ""
echo "Done. Timer status:"
systemctl list-timers --all | grep falconeye
