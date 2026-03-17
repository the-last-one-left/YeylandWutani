#!/usr/bin/env bash
# =============================================================================
# Yeyland Wutani - Risk Scanner Pi
# uninstall.sh - Complete removal of Risk Scanner Pi
#
# Usage: sudo bash /opt/risk-scanner/uninstall.sh
# =============================================================================

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

INSTALL_DIR="/opt/risk-scanner"
SERVICE_USER="risk-scanner"
SYSTEMD_DIR="/etc/systemd/system"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/tmp/risk-scanner-backup-${TIMESTAMP}"

# The five unit files installed by install.sh
UNIT_FILES=(
    "risk-scanner-checkin.service"
    "risk-scanner-daily.service"
    "risk-scanner-daily.timer"
    "risk-scanner-report.service"
    "risk-scanner-report.timer"
)

# ── Color helpers ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

print_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
print_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
print_error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
info()        { echo -e "${CYAN}[INFO]${RESET}  $*"; }
die()         { print_error "$*"; exit 1; }

# Read from /dev/tty so the script works when piped through bash
read_tty() { local _v; IFS= read -r _v < /dev/tty; printf '%s' "${_v}"; }

# ── Root check ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root: sudo bash $0" >&2
    exit 1
fi

# ── Header ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         Yeyland Wutani LLC                               ║"
echo "  ║         Risk Scanner Pi — Uninstaller                    ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo ""
echo "  This will permanently remove:"
echo "    - All 5 systemd services and timers"
echo "    - ${INSTALL_DIR} (code, venv, config, scan history)"
echo "    - Service user: ${SERVICE_USER}"
echo "    - sudoers rules: /etc/sudoers.d/risk-scanner-tools"
echo "    - Log rotation: /etc/logrotate.d/risk-scanner"
echo ""
echo -e "  ${RED}${BOLD}WARNING: Scan history and vulnerability database will be lost"
echo -e "  unless you choose to back them up when prompted.${RESET}"
echo ""

# ── Confirmation ──────────────────────────────────────────────────────────────

echo -n "  Type YES (all caps) to confirm uninstall: "
CONFIRM="$(read_tty)"
echo ""
if [[ "${CONFIRM}" != "YES" ]]; then
    echo "  Uninstall cancelled."
    exit 0
fi

# ── History backup option ─────────────────────────────────────────────────────

echo -n "  Keep scan history archives? (Y/n): "
KEEP_HISTORY="$(read_tty)"
KEEP_HISTORY="${KEEP_HISTORY:-Y}"
echo ""

if [[ "${KEEP_HISTORY,,}" != "n" ]]; then
    # Backup data/history/ (scan results, reports, vuln-db snapshots)
    if [[ -d "${INSTALL_DIR}/data" ]]; then
        info "Backing up scan history to ${BACKUP_DIR} ..."
        mkdir -p "${BACKUP_DIR}"
        cp -a "${INSTALL_DIR}/data/." "${BACKUP_DIR}/" 2>/dev/null || true
        # Also preserve the config (minus secrets) for reference
        if [[ -d "${INSTALL_DIR}/config" ]]; then
            mkdir -p "${BACKUP_DIR}/config-backup"
            cp "${INSTALL_DIR}/config/config.json" \
               "${BACKUP_DIR}/config-backup/config.json" 2>/dev/null || true
        fi
        print_ok "Scan history backed up to: ${BACKUP_DIR}"
    else
        info "No data directory found — nothing to back up."
    fi
fi

# ── Step 1: Stop and disable systemd units ────────────────────────────────────

echo ""
info "Stopping and disabling systemd units..."

for unit in "${UNIT_FILES[@]}"; do
    if systemctl is-active --quiet "${unit}" 2>/dev/null; then
        systemctl stop "${unit}" 2>/dev/null && info "  Stopped:  ${unit}" || \
            print_warn "  Could not stop ${unit} (may already be inactive)."
    fi
    if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
        systemctl disable "${unit}" 2>/dev/null && info "  Disabled: ${unit}" || \
            print_warn "  Could not disable ${unit}."
    fi
done

print_ok "All units stopped and disabled."

# ── Step 2: Remove unit files ─────────────────────────────────────────────────

info "Removing unit files from ${SYSTEMD_DIR}..."
for unit in "${UNIT_FILES[@]}"; do
    local_unit="${SYSTEMD_DIR}/${unit}"
    if [[ -f "${local_unit}" ]]; then
        rm -f "${local_unit}"
        info "  Removed: ${local_unit}"
    fi
done

systemctl daemon-reload
print_ok "systemd daemon reloaded."

# ── Step 3: Remove sudoers and logrotate files ────────────────────────────────

if [[ -f /etc/sudoers.d/risk-scanner-tools ]]; then
    rm -f /etc/sudoers.d/risk-scanner-tools
    print_ok "Sudoers rules removed."
fi

if [[ -f /etc/logrotate.d/risk-scanner ]]; then
    rm -f /etc/logrotate.d/risk-scanner
    print_ok "Log rotation config removed."
fi

# ── Step 4: Remove service user ───────────────────────────────────────────────

if id "${SERVICE_USER}" &>/dev/null; then
    # Remove from supplementary groups before deletion to avoid uid-lingering issues
    if getent group netdev &>/dev/null; then
        gpasswd -d "${SERVICE_USER}" netdev 2>/dev/null && \
            info "  Removed '${SERVICE_USER}' from netdev group." || true
    fi

    userdel "${SERVICE_USER}" 2>/dev/null && \
        print_ok "Service user '${SERVICE_USER}' removed." || \
        print_warn "Could not remove user '${SERVICE_USER}' — remove manually if needed."
else
    info "Service user '${SERVICE_USER}' does not exist — skipping."
fi

# ── Step 5: Remove install directory ─────────────────────────────────────────

if [[ -d "${INSTALL_DIR}" ]]; then
    info "Removing ${INSTALL_DIR} ..."
    rm -rf "${INSTALL_DIR}"
    print_ok "${INSTALL_DIR} removed."
else
    info "${INSTALL_DIR} does not exist — nothing to remove."
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║   Risk Scanner Pi — Uninstall Complete                   ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

if [[ "${KEEP_HISTORY,,}" != "n" && -d "${BACKUP_DIR}" ]]; then
    echo -e "  Scan history preserved at: ${BOLD}${BACKUP_DIR}${RESET}"
    echo ""
fi

echo "  All Risk Scanner Pi components have been removed."
echo ""
echo -e "  ${BOLD}${CYAN}Yeyland Wutani LLC — Building Better Systems${RESET}"
echo ""
