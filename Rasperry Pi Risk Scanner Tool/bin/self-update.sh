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

    # Reload systemd / polkit if any managed files changed
    CHANGED_UNITS_ALL=$(git diff --name-only "$BEFORE" "$AFTER" 2>/dev/null || true)
    CHANGED_UNITS=$(echo "$CHANGED_UNITS_ALL" | grep -E '\.service$|\.timer$' || true)
    if [[ -n "$CHANGED_UNITS" ]] || echo "$CHANGED_UNITS_ALL" | grep -qE '\.pkla$|\.rules$'; then
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

        # Copy updated polkit rules if present
        PKLA_SRC="${INSTALL_DIR}/systemd/risk-scanner.pkla"
        PKLA_DEST="/etc/polkit-1/localauthority/50-local.d/risk-scanner.pkla"
        RULES_SRC="${INSTALL_DIR}/systemd/50-risk-scanner.rules"
        RULES_DEST="/etc/polkit-1/rules.d/50-risk-scanner.rules"
        POLKIT_CHANGED=false
        if echo "$CHANGED_UNITS_ALL" | grep -q 'risk-scanner\.pkla'; then
            if [[ -f "$PKLA_SRC" && -d "$(dirname "$PKLA_DEST")" ]]; then
                cp "$PKLA_SRC" "$PKLA_DEST"
                echo -e "  Updated polkit .pkla rule"
                POLKIT_CHANGED=true
            fi
        fi
        if echo "$CHANGED_UNITS_ALL" | grep -q '50-risk-scanner\.rules'; then
            if [[ -f "$RULES_SRC" && -d "$(dirname "$RULES_DEST")" ]]; then
                cp "$RULES_SRC" "$RULES_DEST"
                echo -e "  Updated polkit .rules file"
                POLKIT_CHANGED=true
            fi
        fi
        if [[ "$POLKIT_CHANGED" == true ]]; then
            systemctl reload polkit 2>/dev/null || systemctl restart polkit 2>/dev/null || true
            echo -e "${GREEN}Polkit reloaded.${NC}"
        fi

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
