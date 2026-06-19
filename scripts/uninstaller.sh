#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/rahgozar"
SERVICE="/etc/systemd/system/rahgozar.service"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (use sudo)." >&2
  exit 1
fi

echo "Stopping and disabling the service..."
systemctl stop rahgozar 2>/dev/null || true
systemctl disable rahgozar 2>/dev/null || true
rm -f "$SERVICE"
systemctl daemon-reload 2>/dev/null || true

rm -f /usr/local/bin/rahgozar

read -r -p "Also delete the database and all tunnels in ${INSTALL_DIR}? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
  rm -rf "$INSTALL_DIR"
  echo "Removed ${INSTALL_DIR}."
else
  rm -f "$INSTALL_DIR/rahgozar"
  echo "Kept your data in ${INSTALL_DIR} (binary removed)."
fi

echo "RahGozar has been uninstalled."
