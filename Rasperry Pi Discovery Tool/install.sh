#!/usr/bin/env bash
# =============================================================================
# Yeyland Wutani - Network Discovery Pi
# install.sh - Complete Installer for Raspberry Pi OS
#
# Usage:
#   sudo bash install.sh
#
# This script:
#   1. Checks prerequisites (Pi OS, root, internet)
#   2. Installs system packages
#   3. Sparse-clones this tool from GitHub (only the subfolder)
#   4. Creates Python virtual environment + installs dependencies
#   5. Sets up directory structure and permissions
#   6. Installs and enables systemd services
#   7. Runs interactive configuration wizard
#   8. Tests Graph API authentication and sends a test email
#
# The Pi needs git, which ships by default on Raspberry Pi OS.
# =============================================================================

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/the-last-one-left/YeylandWutani.git"
REPO_SUBFOLDER="Rasperry Pi Discovery Tool"
INSTALL_DIR="/opt/network-discovery"
SERVICE_USER="network-discovery"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_FILE="${INSTALL_DIR}/config/config.json"
ENV_FILE="${INSTALL_DIR}/config/.env"
LOG_FILE="/tmp/nd-install-$(date +%Y%m%d_%H%M%S).log"

# Branding
BRAND="Yeyland Wutani"
PRODUCT="Network Discovery Pi"
COLOR_BLUE='\033[0;34m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_BOLD='\033[1m'
COLOR_RESET='\033[0m'

# ── Logging helpers ───────────────────────────────────────────────────────────

exec > >(tee -a "${LOG_FILE}") 2>&1

info()    { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET}  $*"; }
success() { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET}    $*"; }
warn()    { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET}   $*"; }
error()   { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
step()    { echo -e "\n${COLOR_BOLD}${COLOR_BLUE}══ $* ══${COLOR_RESET}"; }
prompt()  { echo -e "${COLOR_YELLOW}? ${COLOR_RESET}$*"; }

print_banner() {
    echo ""
    echo -e "${COLOR_BLUE}${COLOR_BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║         ${BRAND}                              ║"
    echo "  ║         ${PRODUCT}                     ║"
    echo "  ║         Installer v1.0                                   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}"
    echo "  Log file: ${LOG_FILE}"
    echo ""
}

# ── Prerequisite checks ───────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This installer must be run as root. Use: sudo bash install.sh"
    fi
    success "Running as root."
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot determine OS. This installer requires Raspberry Pi OS or compatible Debian-based Linux."
    fi
    source /etc/os-release
    info "Detected OS: ${PRETTY_NAME}"
    if [[ "${ID}" != "debian" && "${ID_LIKE:-}" != *"debian"* && "${ID}" != "raspbian" ]]; then
        warn "OS is not Debian-based. Proceeding anyway - some packages may differ."
    else
        success "Compatible OS detected."
    fi
}

check_internet() {
    info "Checking internet connectivity..."
    if curl -s --max-time 10 https://github.com > /dev/null 2>&1; then
        success "Internet connectivity confirmed."
    else
        die "No internet connectivity. Connect to the internet and retry."
    fi
}

check_git() {
    if command -v git &>/dev/null; then
        success "git is available: $(git --version)"
    else
        info "git not found - installing..."
        apt-get install -y git
    fi
}

# ── System package installation ───────────────────────────────────────────────

install_packages() {
    step "Installing system packages"
    apt-get update -qq
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        nmap \
        arp-scan \
        fping \
        traceroute \
        dnsutils \
        net-tools \
        curl \
        git \
        jq \
        logrotate \
        snmp \
        ldap-utils \
        iw \
        wireless-tools \
        avahi-utils \
        whois
    success "System packages installed."
}

# ── Sparse clone from GitHub ──────────────────────────────────────────────────

clone_repo() {
    step "Cloning ${BRAND} ${PRODUCT} from GitHub"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    info "Sparse-cloning '${REPO_SUBFOLDER}' from ${REPO_URL}..."

    cd "${tmp_dir}"
    git init
    git remote add origin "${REPO_URL}"

    # Sparse checkout - only pull the discovery tool subfolder
    git config core.sparseCheckout true
    echo "${REPO_SUBFOLDER}/" >> .git/info/sparse-checkout

    git pull --depth=1 origin main

    if [[ ! -d "${tmp_dir}/${REPO_SUBFOLDER}" ]]; then
        die "Sparse clone did not produce expected directory: '${REPO_SUBFOLDER}'"
    fi

    # Move files to install location
    info "Installing files to ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}"
    rsync -a --exclude='.git' "${tmp_dir}/${REPO_SUBFOLDER}/" "${INSTALL_DIR}/"

    cd /
    rm -rf "${tmp_dir}"
    success "Files installed to ${INSTALL_DIR}."
}

# ── Python virtual environment ────────────────────────────────────────────────

setup_venv() {
    step "Setting up Python virtual environment"
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet

    info "Installing Python dependencies..."
    "${VENV_DIR}/bin/pip" install --quiet \
        msal \
        requests \
        python-nmap \
        netifaces \
        scapy \
        dnspython \
        python-dotenv \
        jinja2

    success "Python virtual environment ready at ${VENV_DIR}."
}

# ── Directory permissions ─────────────────────────────────────────────────────

setup_directories() {
    step "Setting up directories and permissions"

    # Create system user for the service
    if ! id -u "${SERVICE_USER}" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
        success "Created system user: ${SERVICE_USER}"
    else
        info "System user '${SERVICE_USER}' already exists."
    fi

    # Ensure required directories exist
    mkdir -p \
        "${INSTALL_DIR}/bin" \
        "${INSTALL_DIR}/config" \
        "${INSTALL_DIR}/lib" \
        "${INSTALL_DIR}/logs" \
        "${INSTALL_DIR}/data"

    # Ownership: root owns install dir; service user can write logs + data
    chown -R root:root "${INSTALL_DIR}"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/data"

    # Config dir: root-owned, readable only by service user
    chown root:"${SERVICE_USER}" "${INSTALL_DIR}/config"
    chmod 750 "${INSTALL_DIR}/config"

    # Make bin scripts executable
    chmod +x "${INSTALL_DIR}/bin/"*.py 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/install.sh" 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true

    # nmap needs CAP_NET_RAW or setuid - grant to venv python3
    # (systemd service also grants AmbientCapabilities)
    setcap cap_net_raw+eip "${VENV_DIR}/bin/python3" 2>/dev/null || \
        warn "Could not set cap_net_raw on python3. nmap SYN scan may need root."

    # arp-scan needs setuid or capabilities
    if command -v arp-scan &>/dev/null; then
        chmod +s "$(which arp-scan)" 2>/dev/null || true
    fi

    success "Directory permissions configured."
}

# ── Systemd services ──────────────────────────────────────────────────────────

install_services() {
    step "Installing systemd services"

    local service_src="${INSTALL_DIR}/systemd"

    if [[ ! -d "${service_src}" ]]; then
        warn "systemd/ directory not found in install. Skipping service installation."
        return
    fi

    cp "${service_src}/initial-checkin.service" /etc/systemd/system/
    cp "${service_src}/network-discovery.service" /etc/systemd/system/

    # Health check timer (weekly)
    if [[ -f "${service_src}/network-discovery-health.service" ]]; then
        cp "${service_src}/network-discovery-health.service" /etc/systemd/system/
        cp "${service_src}/network-discovery-health.timer" /etc/systemd/system/
    fi

    systemctl daemon-reload
    systemctl enable initial-checkin.service
    systemctl enable network-discovery.service

    if [[ -f /etc/systemd/system/network-discovery-health.timer ]]; then
        systemctl enable --now network-discovery-health.timer
        success "Health check timer enabled (weekly)."
    fi

    # Make all shell scripts executable
    chmod +x "${INSTALL_DIR}/bin/"*.sh 2>/dev/null || true

    success "Systemd services installed and enabled."
    info "Services will start automatically on next boot after configuration."
}

# ── Logrotate config ──────────────────────────────────────────────────────────

setup_logrotate() {
    cat > /etc/logrotate.d/network-discovery << 'EOF'
/opt/network-discovery/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 network-discovery network-discovery
}
EOF
    success "Log rotation configured."
}

# ── Configuration wizard ──────────────────────────────────────────────────────

run_config_wizard() {
    step "Configuration Wizard"
    echo ""
    echo "  You will need the following from your Microsoft Azure App Registration:"
    echo "    - Tenant ID"
    echo "    - Client ID (Application ID)"
    echo "    - Client Secret"
    echo "    - A 'from' email address licensed for Microsoft 365"
    echo "    - A 'to' email address for receiving reports"
    echo ""
    echo "  See GRAPH_API_SETUP.md for step-by-step instructions."
    echo ""

    # Tenant ID
    prompt "Microsoft Tenant ID (Azure Directory ID):"
    read -r TENANT_ID
    [[ -z "${TENANT_ID}" ]] && die "Tenant ID is required."

    prompt "Application (Client) ID:"
    read -r CLIENT_ID
    [[ -z "${CLIENT_ID}" ]] && die "Client ID is required."

    prompt "Client Secret:"
    read -rs CLIENT_SECRET
    echo ""
    [[ -z "${CLIENT_SECRET}" ]] && die "Client Secret is required."

    prompt "From email address (M365 mailbox):"
    read -r FROM_EMAIL
    [[ -z "${FROM_EMAIL}" ]] && die "From email is required."

    prompt "To email address (receives reports):"
    read -r TO_EMAIL
    [[ -z "${TO_EMAIL}" ]] && die "To email is required."

    prompt "Device name (default: NetDiscovery-Pi):"
    read -r DEVICE_NAME
    DEVICE_NAME="${DEVICE_NAME:-NetDiscovery-Pi}"

    prompt "Company name for reports (default: Pacific Office Automation Inc.):"
    read -r COMPANY_NAME
    COMPANY_NAME="${COMPANY_NAME:-Pacific Office Automation Inc.}"

    # Escape JSON special characters in user input (backslash and double-quote)
    # to prevent invalid config.json from secrets containing these characters.
    json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
    TENANT_ID="$(json_escape "${TENANT_ID}")"
    CLIENT_ID="$(json_escape "${CLIENT_ID}")"
    CLIENT_SECRET="$(json_escape "${CLIENT_SECRET}")"
    FROM_EMAIL="$(json_escape "${FROM_EMAIL}")"
    TO_EMAIL="$(json_escape "${TO_EMAIL}")"
    DEVICE_NAME="$(json_escape "${DEVICE_NAME}")"
    COMPANY_NAME="$(json_escape "${COMPANY_NAME}")"

    # Write config.json from template + user input
    cat > "${CONFIG_FILE}" << EOF
{
  "graph_api": {
    "tenant_id": "${TENANT_ID}",
    "client_id": "${CLIENT_ID}",
    "client_secret": "${CLIENT_SECRET}",
    "from_email": "${FROM_EMAIL}",
    "to_email": "${TO_EMAIL}",
    "cc_emails": []
  },
  "network_discovery": {
    "scan_timeout": 600,
    "max_threads": 50,
    "port_scan_top_ports": 100,
    "enable_dns_enumeration": true,
    "enable_dhcp_detection": true,
    "enable_arp_scan": true,
    "enable_traceroute": true,
    "enable_service_versions": true,
    "enable_os_detection": true,
    "enable_nse_scripts": true,
    "nse_script_timeout": "15s",
    "enable_snmp_enhanced": true,
    "snmp_community_strings": ["public", "private", "community", "admin", "cisco", "snmp"],
    "snmp_timeout": 2,
    "snmp_retries": 1,
    "enable_banner_grab": true,
    "banner_grab_timeout": 3,
    "banner_grab_bytes": 256,
    "enable_multi_subnet": true,
    "multi_subnet_candidates": [
      "192.168.0.1", "192.168.1.1", "192.168.2.1",
      "10.0.0.1", "10.0.0.254", "10.0.1.1", "10.1.0.1",
      "172.16.0.1", "172.16.1.1"
    ],
    "enable_public_ip_lookup": true,
    "enable_gateway_fingerprint": true,
    "enable_ad_probing": true,
    "ad_probe_timeout": 10,
    "subnet_labels": {},
    "enable_wifi_scan": true,
    "wifi_interface": "auto",
    "wifi_scan_timeout": 30,
    "enable_mdns_discovery": true,
    "mdns_timeout": 10,
    "enable_ssdp_discovery": true,
    "ssdp_timeout": 5,
    "enable_dhcp_analysis": true,
    "dhcp_timeout": 10,
    "enable_ntp_detection": true,
    "ntp_timeout": 3,
    "enable_nac_detection": true,
    "enable_osint": true,
    "osint_timeout": 8,
    "enable_shodan_internetdb": true,
    "enable_crtsh_lookup": true,
    "enable_dns_security": true,
    "enable_whois_lookup": true
  },
  "reporting": {
    "company_name": "${COMPANY_NAME}",
    "company_color": "#00A0D9",
    "tagline": "Problem Solved.",
    "include_raw_data": false
  },
  "system": {
    "device_name": "${DEVICE_NAME}",
    "log_level": "INFO",
    "cleanup_old_scans_days": 7
  }
}
EOF

    # Lock down config (contains secret)
    chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"

    success "Configuration written to ${CONFIG_FILE}."
}

# ── Test Graph API authentication ─────────────────────────────────────────────

test_graph_api() {
    step "Testing Graph API Authentication"
    info "Attempting to acquire an OAuth2 token..."

    if "${VENV_DIR}/bin/python3" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}/lib')
from graph_auth import load_credentials_from_config
auth = load_credentials_from_config('${CONFIG_FILE}')
token = auth.get_token()
print('Token acquired successfully (first 20 chars): ' + token[:20] + '...')
"; then
        success "Graph API authentication working."
    else
        error "Graph API authentication FAILED."
        error "Check your tenant_id, client_id, and client_secret in ${CONFIG_FILE}"
        warn "Services have been enabled but will fail until credentials are fixed."
        warn "Run: sudo ${INSTALL_DIR}/bin/update-config.sh  to reconfigure."
        return 1
    fi
}

# ── Send test email ───────────────────────────────────────────────────────────

send_test_email() {
    step "Sending Test Email"
    info "Sending a test email to verify end-to-end delivery..."

    if "${VENV_DIR}/bin/python3" "${INSTALL_DIR}/bin/graph-mailer.py" \
        --config "${CONFIG_FILE}" \
        --subject "[Network Discovery Pi] Installation Test - ${DEVICE_NAME:-NetDiscovery-Pi}" \
        --body "<h2 style='color:#00A0D9;'>Installation Successful!</h2>
<p>The <strong>Yeyland Wutani Network Discovery Pi</strong> has been installed and configured successfully.</p>
<p>Device: <strong>${DEVICE_NAME:-NetDiscovery-Pi}</strong></p>
<p>Graph API email delivery is working. The device will begin network discovery on next boot.</p>
<hr>
<p style='color:#888; font-size:12px;'>Powered by Yeyland Wutani &bull; Building Better Systems</p>"; then
        success "Test email sent! Check your inbox."
    else
        warn "Test email failed. Check credentials and Mail.Send permission in Azure."
    fi
}

# ── Final instructions ────────────────────────────────────────────────────────

print_next_steps() {
    echo ""
    echo -e "${COLOR_GREEN}${COLOR_BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║   Installation Complete!                                 ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}"
    echo ""
    echo "  Next Steps:"
    echo ""
    echo "  1. Reboot the Pi to trigger automatic discovery on next boot:"
    echo "     sudo reboot"
    echo ""
    echo "  2. Or start services manually right now:"
    echo "     sudo systemctl start initial-checkin.service"
    echo "     sudo systemctl start network-discovery.service"
    echo ""
    echo "  3. Monitor logs:"
    echo "     sudo journalctl -u nd-checkin -f"
    echo "     sudo journalctl -u nd-discovery -f"
    echo "     tail -f ${INSTALL_DIR}/logs/discovery.log"
    echo ""
    echo "  4. Run a manual scan anytime:"
    echo "     sudo ${INSTALL_DIR}/bin/manual-scan.sh"
    echo ""
    echo "  5. Reconfigure credentials / settings:"
    echo "     sudo ${INSTALL_DIR}/bin/update-config.sh"
    echo ""
    echo "  6. Check for and apply updates from GitHub:"
    echo "     sudo bash ${INSTALL_DIR}/bin/self-update.sh"
    echo ""
    echo "  7. Reset initial check-in (for re-testing):"
    echo "     sudo ${INSTALL_DIR}/bin/reset-checkin.sh"
    echo ""
    echo "  8. Uninstall:"
    echo "     sudo ${INSTALL_DIR}/uninstall.sh"
    echo ""
    echo "  Full documentation: ${INSTALL_DIR}/README.md"
    echo "  Graph API setup guide: ${INSTALL_DIR}/GRAPH_API_SETUP.md"
    echo "  Install log: ${LOG_FILE}"
    echo ""
    echo -e "  ${COLOR_BLUE}${COLOR_BOLD}${BRAND} - Building Better Systems${COLOR_RESET}"
    echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    print_banner

    check_root
    check_os
    check_internet
    check_git

    install_packages
    clone_repo
    setup_venv
    setup_directories
    install_services
    setup_logrotate
    run_config_wizard
    test_graph_api && send_test_email

    print_next_steps
}

main "$@"
