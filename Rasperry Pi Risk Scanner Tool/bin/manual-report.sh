#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Manual Report Generator
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python"
REPORT_SCRIPT="${INSTALL_DIR}/bin/generate-report.py"
SERVICE_USER="risk-scanner"

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
    echo "║     Yeyland Wutani Risk Scanner — Manual Report      ║"
    echo "║           Building Better Systems                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [--output DIR] [--no-email] [--type exec|detail|all]"
    echo ""
    echo "Options:"
    echo "  --output DIR       Write report files to DIR (default: /tmp/risk-scanner-report)"
    echo "  --no-email         Generate report but do not send email"
    echo "  --type exec        Executive summary only"
    echo "  --type detail      Detailed technical report only"
    echo "  --type all         Both executive and detailed reports (default)"
    echo ""
    exit 0
}

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root." >&2
    exit 1
fi

print_header

# Parse arguments
OUTPUT_DIR=""
NO_EMAIL=""
REPORT_TYPE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            if [[ -z "${2:-}" ]]; then
                echo -e "${RED}Error:${NC} --output requires a directory argument." >&2
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-email)
            NO_EMAIL="--no-email"
            shift
            ;;
        --type)
            if [[ -z "${2:-}" ]]; then
                echo -e "${RED}Error:${NC} --type requires exec, detail, or all." >&2
                exit 1
            fi
            case "$2" in
                exec|detail|all)
                    REPORT_TYPE="--type $2"
                    ;;
                *)
                    echo -e "${RED}Error:${NC} Invalid report type '$2'. Use exec, detail, or all." >&2
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo -e "${RED}Error:${NC} Unknown argument: $1" >&2
            usage
            ;;
    esac
done

# Default output dir
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="/tmp/risk-scanner-report-$(date +%Y%m%d-%H%M%S)"
fi

# Create output dir
mkdir -p "$OUTPUT_DIR"
chown "${SERVICE_USER}:${SERVICE_USER}" "$OUTPUT_DIR"

# Build argument list
ARGS="--output ${OUTPUT_DIR}"
[[ -n "$NO_EMAIL" ]]    && ARGS="${ARGS} ${NO_EMAIL}"
[[ -n "$REPORT_TYPE" ]] && ARGS="${ARGS} ${REPORT_TYPE}"

echo -e "Report type:   ${YELLOW}${REPORT_TYPE:-default (all)}${NC}"
echo -e "Output dir:    ${YELLOW}${OUTPUT_DIR}${NC}"
echo -e "Email:         ${YELLOW}${NO_EMAIL:-enabled}${NC}"
echo ""
echo "Generating report..."
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"

# Run the report generator as service user
# shellcheck disable=SC2086
if sudo -u "$SERVICE_USER" "$VENV_PYTHON" "$REPORT_SCRIPT" $ARGS; then
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}${BOLD}Report generation complete.${NC}"
    echo ""
    echo "Generated files:"
    find "$OUTPUT_DIR" -type f \( -name "*.html" -o -name "*.pdf" -o -name "*.json" \) \
        2>/dev/null | sort | while read -r f; do
        SIZE=$(du -sh "$f" 2>/dev/null | cut -f1)
        echo -e "  ${GREEN}${f}${NC}  (${SIZE})"
    done
else
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}${BOLD}Report generation failed.${NC}"
    echo "Check logs: journalctl -u risk-scanner-report.service -n 50"
    exit 1
fi
