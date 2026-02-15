#!/usr/bin/env bash
# Yeyland Wutani - Network Discovery Pi
# uninstall.sh - Complete removal of Network Discovery Pi
#
# Usage: sudo bash /opt/network-discovery/uninstall.sh

set -euo pipefail

INSTALL_DIR="/opt/network-discovery"
SERVICE_USER="network-discovery"

COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_GREEN='\033[0;32m'
COLOR_RESET='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root: sudo $0" >&2
    exit 1
fi

echo ""
echo "Yeyland Wutani - Network Discovery Pi"
echo "======================================"
echo -e "${COLOR_RED}UNINSTALL${COLOR_RESET}"
echo ""
echo "This will remove:"
echo "  - Systemd services (discovery, check-in, health check)"
echo "  - ${INSTALL_DIR} (except optionally logs/config)"
echo "  - System user: ${SERVICE_USER}"
echo "  - Logrotate configuration"
echo ""
echo -n "Are you sure you want to uninstall? (yes/no): "
read -r CONFIRM
if [[ "${CONFIRM}" != "yes" ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo ""
echo -n "Keep logs and configuration? (yes/no): "
read -r KEEP_DATA

# Stop and disable services
echo ""
echo "Stopping and disabling services..."
for svc in network-discovery.service initial-checkin.service \
           network-discovery-health.service network-discovery-health.timer; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl stop "${svc}" && echo "  Stopped: ${svc}"
    fi
    if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
        systemctl disable "${svc}" && echo "  Disabled: ${svc}"
    fi
    if [[ -f "/etc/systemd/system/${svc}" ]]; then
        rm -f "/etc/systemd/system/${svc}"
        echo "  Removed: /etc/systemd/system/${svc}"
    fi
done
systemctl daemon-reload
echo "  Services removed."

# Remove logrotate config
rm -f /etc/logrotate.d/network-discovery
echo "  Logrotate config removed."

# Remove files
if [[ "${KEEP_DATA}" == "yes" ]]; then
    echo ""
    echo "Keeping logs and config. Removing code files..."
    rm -rf \
        "${INSTALL_DIR}/bin" \
        "${INSTALL_DIR}/lib" \
        "${INSTALL_DIR}/venv" \
        "${INSTALL_DIR}/systemd" \
        "${INSTALL_DIR}/tests" \
        "${INSTALL_DIR}/install.sh" \
        "${INSTALL_DIR}/uninstall.sh" \
        "${INSTALL_DIR}/update-config.sh" \
        "${INSTALL_DIR}/reset-checkin.sh" \
        "${INSTALL_DIR}/self-update.sh" \
        "${INSTALL_DIR}/README.md" \
        "${INSTALL_DIR}/GRAPH_API_SETUP.md" \
        "${INSTALL_DIR}/TROUBLESHOOTING.md" \
        "${INSTALL_DIR}/.gitattributes" \
        "${INSTALL_DIR}/.gitignore"
    echo "  Code removed. Logs kept at: ${INSTALL_DIR}/logs/"
    echo "  Config kept at: ${INSTALL_DIR}/config/"
    echo "  Scan data kept at: ${INSTALL_DIR}/data/"
else
    echo ""
    echo "Removing ${INSTALL_DIR}..."
    rm -rf "${INSTALL_DIR}"
    echo "  ${INSTALL_DIR} removed."
fi

# Remove system user
if id -u "${SERVICE_USER}" &>/dev/null; then
    userdel "${SERVICE_USER}"
    echo "  System user '${SERVICE_USER}' removed."
fi

# Optionally remove installed system packages
echo ""
echo -e "${COLOR_YELLOW}The following system packages were installed for Network Discovery Pi:${COLOR_RESET}"
echo "  nmap arp-scan fping traceroute dnsutils net-tools snmp ldap-utils"
echo "  iw wireless-tools avahi-utils whois logrotate"
echo ""
echo -n "Remove these packages? (yes/no): "
read -r REMOVE_PKGS
if [[ "${REMOVE_PKGS}" == "yes" ]]; then
    echo "Removing packages..."
    apt-get remove -y --purge \
        nmap arp-scan fping traceroute dnsutils net-tools snmp ldap-utils \
        iw wireless-tools avahi-utils whois 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    echo -e "  ${COLOR_GREEN}Packages removed.${COLOR_RESET}"
else
    echo "  Keeping packages."
fi

echo ""
echo -e "${COLOR_GREEN}Uninstall complete.${COLOR_RESET}"
echo ""
