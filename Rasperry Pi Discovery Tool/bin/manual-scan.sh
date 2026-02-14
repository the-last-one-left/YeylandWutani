#!/usr/bin/env bash
# Yeyland Wutani - Network Discovery Pi
# manual-scan.sh - Trigger a manual network discovery scan
#
# Usage: sudo /opt/network-discovery/bin/manual-scan.sh

set -euo pipefail

INSTALL_DIR="/opt/network-discovery"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python3"

echo "Yeyland Wutani - Network Discovery Pi"
echo "======================================"
echo "Starting manual scan..."
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Note: Running without root. Some scan features (SYN scan, ARP) may require root."
fi

# Stop the systemd service if running to avoid lock conflict
if systemctl is-active --quiet network-discovery.service 2>/dev/null; then
    echo "Stopping running discovery service first..."
    systemctl stop network-discovery.service
fi

# Run discovery directly
exec "${VENV_PYTHON}" "${INSTALL_DIR}/bin/discovery-main.py"
