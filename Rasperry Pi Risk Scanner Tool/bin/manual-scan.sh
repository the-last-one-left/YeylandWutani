#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Manual Scan Trigger
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
LOCK_FILE="${INSTALL_DIR}/data/.scanner.lock"
SERVICE="risk-scanner-daily.service"

# Color helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║     Yeyland Wutani Risk Scanner — Manual Scan        ║"
    echo "║           Building Better Systems                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root." >&2
    exit 1
fi

print_header

# Check if scan is already running via lock file
if [[ -f "$LOCK_FILE" ]]; then
    LOCK_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
    if [[ "$LOCK_PID" != "unknown" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
        echo -e "${YELLOW}Warning:${NC} A scan is already running (PID: ${LOCK_PID})."
        echo "         Lock file: ${LOCK_FILE}"
        echo ""
        echo "If this is stale, remove it with: sudo rm -f ${LOCK_FILE}"
        exit 1
    else
        echo -e "${YELLOW}Notice:${NC} Stale lock file found (PID ${LOCK_PID} not running). Continuing..."
        rm -f "$LOCK_FILE"
    fi
fi

# Check if service is already active
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    echo -e "${YELLOW}Warning:${NC} ${SERVICE} is already active."
    echo "Use 'journalctl -u ${SERVICE} -f' to follow the running scan."
    exit 1
fi

echo -e "${GREEN}Starting scan...${NC}"
echo ""

# Start the service
if ! systemctl start "$SERVICE" 2>&1; then
    echo -e "${RED}Error:${NC} Failed to start ${SERVICE}." >&2
    echo "Check 'journalctl -u ${SERVICE} -n 50' for details." >&2
    exit 1
fi

echo -e "Service started. Following journal output (Ctrl+C to detach, scan continues)..."
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
echo ""

# Tail journal, detach on Ctrl+C without killing the service
journalctl -u "$SERVICE" -f --since now &
TAIL_PID=$!

# Wait for service to finish
set +e
systemctl wait "$SERVICE" 2>/dev/null || {
    # systemctl wait not available on older systemd; poll instead
    while systemctl is-active --quiet "$SERVICE" 2>/dev/null; do
        sleep 2
    done
}
set -e

# Give journal a moment to flush
sleep 1
kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true

echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"

# Determine exit status
EXIT_CODE=$(systemctl show "$SERVICE" --property=ExecMainStatus --value 2>/dev/null || echo "unknown")

if [[ "$EXIT_CODE" == "0" ]]; then
    echo -e "${GREEN}${BOLD}Scan completed successfully.${NC}"
    echo ""
    echo "View results: sudo view-risks.sh"
else
    echo -e "${RED}${BOLD}Scan finished with exit code: ${EXIT_CODE}${NC}"
    echo "Review logs: journalctl -u ${SERVICE} -n 100"
    exit 1
fi
