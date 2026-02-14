#!/usr/bin/env bash
# Yeyland Wutani - Network Discovery Pi
# view-last-report.sh - Display the last scan results in the terminal
#
# Usage: /opt/network-discovery/bin/view-last-report.sh

INSTALL_DIR="/opt/network-discovery"
DATA_DIR="${INSTALL_DIR}/data"

LATEST=$(ls -t "${DATA_DIR}"/scan_*.json 2>/dev/null | head -1)

if [[ -z "${LATEST}" ]]; then
    echo "No scan results found in ${DATA_DIR}."
    echo "Run a scan first with: sudo ${INSTALL_DIR}/bin/manual-scan.sh"
    exit 1
fi

echo "Yeyland Wutani - Network Discovery Pi"
echo "Last Scan: ${LATEST}"
echo "======================================"
echo ""

if command -v jq &>/dev/null; then
    echo "=== SUMMARY ==="
    jq '.summary' "${LATEST}"
    echo ""
    echo "=== DISCOVERED HOSTS ==="
    jq -r '.hosts[] | "\(.ip)\t\(.hostname // "N/A")\t\(.category)\t\(.mac // "N/A")\tports:\(.open_ports | length)"' "${LATEST}" | column -t
else
    echo "Install jq for formatted output: sudo apt-get install jq"
    cat "${LATEST}"
fi
