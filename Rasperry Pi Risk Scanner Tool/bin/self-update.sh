#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Self-update
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_DIR="${INSTALL_DIR}/venv"

# Color helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root." >&2
    exit 1
fi

echo -e "${CYAN}${BOLD}Yeyland Wutani Risk Scanner — Self-Update${NC}"
echo ""

echo "Checking for updates..."
cd "$INSTALL_DIR"

BEFORE=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

if ! git pull --ff-only origin main 2>&1; then
    echo -e "${YELLOW}git pull failed (non-fatal). Skipping update.${NC}" >&2
    exit 0
fi

# Pull any updated LFS objects (vuln-db.sqlite etc.)
git lfs pull 2>/dev/null || true

AFTER=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

if [[ "$BEFORE" != "$AFTER" ]]; then
    echo ""
    echo -e "${GREEN}Updated from ${BEFORE:0:8} to ${AFTER:0:8}${NC}"
    echo ""

    # Re-install Python dependencies
    echo "Updating Python dependencies..."
    "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q
    echo -e "${GREEN}Dependencies updated.${NC}"

    # Reload systemd if any unit files changed
    CHANGED_UNITS=$(git diff --name-only "$BEFORE" "$AFTER" 2>/dev/null | grep -E '\.service$|\.timer$' || true)
    if [[ -n "$CHANGED_UNITS" ]]; then
        echo ""
        echo "Systemd unit files changed:"
        echo "$CHANGED_UNITS" | while read -r UNIT; do
            echo "  - $UNIT"
        done
        echo ""
        echo "Copying updated unit files to /etc/systemd/system/..."
        cp "${INSTALL_DIR}/systemd/"*.service "${INSTALL_DIR}/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
        systemctl daemon-reload
        echo -e "${GREEN}Systemd units reloaded.${NC}"

        # If any timer files changed, re-apply schedule from config so the
        # __REPORT_DAY__ / __REPORT_TIME__ placeholders get real values written
        # back before systemd tries to parse them.
        if echo "$CHANGED_UNITS" | grep -q '\.timer$'; then
            echo "Re-applying schedule to updated timer files..."
            "${VENV_DIR}/bin/python3" "${INSTALL_DIR}/bin/apply-schedule.py" && \
                echo -e "${GREEN}Schedule re-applied.${NC}" || \
                echo -e "${YELLOW}Warning: apply-schedule.py failed — timers may need manual restart.${NC}"
        else
            # No timers changed; restart any active non-timer units that were updated
            echo "$CHANGED_UNITS" | grep '\.service$' | while read -r UNIT_PATH; do
                UNIT_NAME=$(basename "$UNIT_PATH")
                if systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then
                    systemctl restart "$UNIT_NAME" && \
                        echo -e "  Restarted ${UNIT_NAME}" || \
                        echo -e "  ${YELLOW}Could not restart ${UNIT_NAME}${NC}"
                fi
            done
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}Update complete.${NC}"
else
    echo -e "${GREEN}Already up to date.${NC}"
fi
