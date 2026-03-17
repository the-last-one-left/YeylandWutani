#!/usr/bin/env bash
# =============================================================================
# Yeyland Wutani - Risk Scanner Pi
# install.sh - Complete Installer for Raspberry Pi OS
#
# Usage:
#   sudo bash install.sh
#
# This script:
#   1.  Checks prerequisites (root, OS, internet, git)
#   2.  Installs system packages
#   3.  Creates the risk-scanner service user
#   4.  Sparse-clones this tool from GitHub (only the subfolder)
#   5.  Creates Python virtual environment + installs dependencies
#   6.  Sets up directory structure and permissions
#   7.  Runs interactive configuration wizard
#   8.  Encrypts stored credentials
#   9.  Installs and enables systemd services / timers
#   10. Initializes the vulnerability database
#   11. Sends a test check-in email
#   12. Optionally runs an immediate first scan
# =============================================================================

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

INSTALL_DIR="/opt/risk-scanner"
REPO_URL="https://github.com/the-last-one-left/YeylandWutani"
REPO_SUBFOLDER="Rasperry Pi Risk Scanner Tool"
SERVICE_USER="risk-scanner"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="${INSTALL_DIR}/config"
DATA_DIR="${INSTALL_DIR}/data"
LOG_DIR="${INSTALL_DIR}/logs"
SYSTEMD_DIR="/etc/systemd/system"
LOG_FILE="/tmp/risk-scanner-install-$(date +%Y%m%d_%H%M%S).log"
TMP_CREDS="/tmp/.risk-scanner-creds-tmp.json"

# Branding
BRAND="Yeyland Wutani"
PRODUCT="Risk Scanner Pi"

# ── Color helpers ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

print_step()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }
print_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
print_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
print_error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()         { print_error "$*"; exit 1; }
info()        { echo -e "${CYAN}[INFO]${RESET}  $*"; }
prompt_msg()  { echo -e "${YELLOW}? ${RESET}$*"; }

# ── Log tee ───────────────────────────────────────────────────────────────────

exec > >(tee -a "${LOG_FILE}") 2>&1

# ── Banner ────────────────────────────────────────────────────────────────────

print_banner() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║         Yeyland Wutani LLC                               ║"
    echo "  ║         Risk Scanner Pi                                  ║"
    echo "  ║         Installer v1.0                                   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo "  Building Better Systems"
    echo "  Log file: ${LOG_FILE}"
    echo ""
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This installer must be run as root. Use: sudo bash install.sh"
    fi
    print_ok "Running as root."
}

check_os() {
    local os_name
    os_name="$(uname -s)"
    if [[ "${os_name}" != "Linux" ]]; then
        die "This installer requires Linux. Detected: ${os_name}"
    fi

    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        info "Detected OS: ${PRETTY_NAME:-unknown}"
        if [[ "${ID:-}" != "debian" && "${ID_LIKE:-}" != *"debian"* && "${ID:-}" != "raspbian" ]]; then
            print_warn "OS is not Debian/Ubuntu/Raspberry Pi OS. Some packages may differ."
        else
            print_ok "Compatible OS detected."
        fi
    else
        print_warn "Cannot read /etc/os-release — proceeding anyway."
    fi
}

check_internet() {
    info "Checking internet connectivity..."
    if curl -s --head --max-time 15 https://github.com > /dev/null 2>&1; then
        print_ok "Internet connectivity confirmed."
    else
        die "No internet connectivity. Connect to the internet and retry."
    fi
}

check_git() {
    if command -v git &>/dev/null; then
        print_ok "git available: $(git --version)"
    else
        die "git is not installed. Install git and retry: sudo apt-get install -y git"
    fi
}

# ── Step 1: System packages ───────────────────────────────────────────────────

install_packages() {
    print_step "Step 1: Installing system packages"

    apt-get update -qq
    apt-get install -y --no-install-recommends \
        nmap \
        arp-scan \
        fping \
        sshpass \
        snmp \
        python3-venv \
        python3-pip \
        openssl \
        curl \
        jq \
        git \
        net-tools \
        dnsutils \
        traceroute \
        whois \
        ldap-utils \
        iw \
        wireless-tools \
        logrotate \
        libcap2-bin
    print_ok "System packages installed."

    # snmp-mibs-downloader is only in Debian's non-free repo and is not available
    # on Raspberry Pi OS mirrors. Install it if possible; skip it if not — SNMP
    # scanning still works without it (OIDs appear as numbers instead of names).
    if apt-get install -y --no-install-recommends snmp-mibs-downloader 2>/dev/null; then
        print_ok "snmp-mibs-downloader installed (human-readable OID names enabled)."
    else
        print_warn "snmp-mibs-downloader not available on this OS — SNMP will use numeric OIDs. This is non-fatal."
    fi
}

# ── Step 2: Create service user ───────────────────────────────────────────────

create_service_user() {
    print_step "Step 2: Creating service user"
    if ! id "${SERVICE_USER}" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false "${SERVICE_USER}"
        print_ok "Service user '${SERVICE_USER}' created."
        # Add to netdev for network operations (non-fatal if group absent)
        if getent group netdev &>/dev/null; then
            usermod -aG netdev "${SERVICE_USER}"
            print_ok "Added '${SERVICE_USER}' to netdev group."
        else
            print_warn "Group 'netdev' not found — skipping group membership."
        fi
    else
        info "Service user '${SERVICE_USER}' already exists."
    fi
}

# ── Step 3: Sparse git clone ──────────────────────────────────────────────────

clone_repo() {
    print_step "Step 3: Cloning repository (sparse checkout)"

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        print_step "Updating existing installation..."
        git -C "${INSTALL_DIR}" fetch --depth=1 origin main 2>>"${LOG_FILE}" || true
        if ! git -C "${INSTALL_DIR}" merge --ff-only FETCH_HEAD 2>>"${LOG_FILE}"; then
            print_warn "Fast-forward merge failed (shallow history) — resetting to FETCH_HEAD."
            git -C "${INSTALL_DIR}" reset --hard FETCH_HEAD 2>>"${LOG_FILE}" || \
                print_warn "git reset failed; continuing with existing files."
        fi
        print_ok "Repository updated."
        return
    fi

    info "Sparse-cloning '${REPO_SUBFOLDER}' from ${REPO_URL}..."
    git clone --no-checkout --depth=1 --filter=blob:none "${REPO_URL}" "${INSTALL_DIR}"
    cd "${INSTALL_DIR}"
    git sparse-checkout init --cone
    git sparse-checkout set "${REPO_SUBFOLDER}"
    git checkout

    # Move files from the subfolder up to the install root
    if [[ -d "${INSTALL_DIR}/${REPO_SUBFOLDER}" ]]; then
        # Move regular files/dirs
        find "${INSTALL_DIR}/${REPO_SUBFOLDER}" -maxdepth 1 -mindepth 1 \
            -not -name '.' -not -name '..' \
            -exec mv -t "${INSTALL_DIR}/" {} + 2>/dev/null || true
        rmdir "${INSTALL_DIR}/${REPO_SUBFOLDER}" 2>/dev/null || true
    fi

    # Mark as safe git dir for the service user
    git config --system --add safe.directory "${INSTALL_DIR}" 2>/dev/null || \
        git config --global --add safe.directory "${INSTALL_DIR}" 2>/dev/null || true

    print_ok "Repository cloned to ${INSTALL_DIR}."
}

# ── Step 4: Python venv ───────────────────────────────────────────────────────

setup_venv() {
    print_step "Step 4: Setting up Python virtual environment"
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --upgrade pip -q
    if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
        info "Installing Python dependencies from requirements.txt..."
        "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q
    else
        print_warn "requirements.txt not found — installing base dependencies only."
        "${VENV_DIR}/bin/pip" install -q \
            msal requests python-nmap dnspython jinja2 cryptography \
            paramiko pysnmp impacket ldap3 reportlab weasyprint
    fi
    print_ok "Python virtual environment ready at ${VENV_DIR}."
}

# ── Step 5: Directory setup ───────────────────────────────────────────────────

setup_directories() {
    print_step "Step 5: Setting up directories and permissions"

    mkdir -p \
        "${CONFIG_DIR}" \
        "${DATA_DIR}/history" \
        "${DATA_DIR}/vuln-db" \
        "${DATA_DIR}/reports" \
        "${LOG_DIR}"

    # Root owns everything; service user owns runtime-writable dirs
    chown -R root:root "${INSTALL_DIR}"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}" "${DATA_DIR}"

    # Config: root-owned, readable by service user
    chown root:"${SERVICE_USER}" "${CONFIG_DIR}"
    chmod 750 "${CONFIG_DIR}"
    chmod 750 "${LOG_DIR}"
    chmod 750 "${DATA_DIR}"

    # Make scripts executable
    chmod +x "${INSTALL_DIR}/bin/"*.py 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/bin/"*.sh 2>/dev/null || true

    # nmap needs setuid for SYN scan
    if command -v nmap &>/dev/null; then
        local NMAP_BIN
        NMAP_BIN="$(readlink -f "$(command -v nmap)")"
        chmod +s "${NMAP_BIN}" 2>/dev/null && \
            print_ok "nmap setuid-root set — SYN scan enabled." || \
            print_warn "Could not set setuid-root on nmap; SYN scan may fall back to connect scan."
    fi

    if command -v arp-scan &>/dev/null; then
        chmod +s "$(command -v arp-scan)" 2>/dev/null || true
    fi

    # Sudoers for privileged tools
    local SUDOERS_FILE="/etc/sudoers.d/risk-scanner-tools"
    {
        local NMAP_BIN=""
        NMAP_BIN="$(command -v nmap 2>/dev/null || true)"
        [[ -n "${NMAP_BIN}" ]] && echo "${SERVICE_USER} ALL=(root) NOPASSWD: ${NMAP_BIN}"

        local ARPSCAN_BIN=""
        ARPSCAN_BIN="$(command -v arp-scan 2>/dev/null || true)"
        [[ -n "${ARPSCAN_BIN}" ]] && echo "${SERVICE_USER} ALL=(root) NOPASSWD: ${ARPSCAN_BIN}"
    } > "${SUDOERS_FILE}"
    chmod 0440 "${SUDOERS_FILE}"
    if visudo -c -f "${SUDOERS_FILE}" &>/dev/null; then
        print_ok "sudoers rules installed for risk-scanner tools."
    else
        print_warn "sudoers file failed validation — removing."
        rm -f "${SUDOERS_FILE}"
    fi

    # Logrotate
    cat > /etc/logrotate.d/risk-scanner <<'LOGROTATE'
/opt/risk-scanner/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 risk-scanner risk-scanner
}
LOGROTATE
    print_ok "Log rotation configured."

    print_ok "Directories and permissions configured."
}

# ── Step 6 & 7: Configuration wizard and config.json write ───────────────────

# Read from /dev/tty so the wizard works even when piped through: curl | sudo bash
read_tty()        { local _v; IFS= read -r  _v < /dev/tty; printf '%s' "${_v}"; }
read_tty_secret() { local _v; IFS= read -rs _v < /dev/tty; printf '%s' "${_v}"; }

# Escape characters that would break a JSON string literal
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Validate HH:MM time format
validate_time() {
    local t="$1"
    if [[ ! "${t}" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
        return 1
    fi
    return 0
}

# Validate day of week (case-insensitive)
validate_day() {
    local d
    d="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    case "${d}" in
        monday|tuesday|wednesday|thursday|friday|saturday|sunday) return 0 ;;
        *) return 1 ;;
    esac
}

# Capitalize first letter
cap_first() {
    local s="$1"
    echo "$(tr '[:lower:]' '[:upper:]' <<< "${s:0:1}")${s:1}"
}

run_config_wizard() {
    print_step "Step 6: Configuration Wizard"
    echo ""
    echo "  You will need the following from your Microsoft Azure App Registration:"
    echo "    - Tenant ID"
    echo "    - Client ID (Application ID)"
    echo "    - Client Secret"
    echo "    - A 'from' email address licensed for Microsoft 365"
    echo "    - A 'to' email address for receiving reports"
    echo ""

    # ── Graph API ──────────────────────────────────────────────────────────
    echo -e "  ${BOLD}${CYAN}── Graph API ──────────────────────────────────────────────────────${RESET}"

    local TENANT_ID="" CLIENT_ID="" CLIENT_SECRET="" FROM_EMAIL="" TO_EMAIL="" CC_EMAIL=""
    while [[ -z "${TENANT_ID}" ]]; do
        prompt_msg "Azure Tenant ID (required):"; TENANT_ID="$(read_tty)"
        [[ -z "${TENANT_ID}" ]] && print_error "Tenant ID is required."
    done
    while [[ -z "${CLIENT_ID}" ]]; do
        prompt_msg "Azure Client ID (required):"; CLIENT_ID="$(read_tty)"
        [[ -z "${CLIENT_ID}" ]] && print_error "Client ID is required."
    done
    while [[ -z "${CLIENT_SECRET}" ]]; do
        prompt_msg "Azure Client Secret (required, hidden):"; CLIENT_SECRET="$(read_tty_secret)"; echo ""
        [[ -z "${CLIENT_SECRET}" ]] && print_error "Client Secret is required."
    done
    while [[ -z "${FROM_EMAIL}" ]]; do
        prompt_msg "From email address (required):"; FROM_EMAIL="$(read_tty)"
        [[ -z "${FROM_EMAIL}" ]] && print_error "From email is required."
    done
    while [[ -z "${TO_EMAIL}" ]]; do
        prompt_msg "To email address (required):"; TO_EMAIL="$(read_tty)"
        [[ -z "${TO_EMAIL}" ]] && print_error "To email is required."
    done
    prompt_msg "CC email address (optional, press Enter to skip):"; CC_EMAIL="$(read_tty)"

    # ── Hatz AI ────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}${CYAN}── Hatz AI Integration (optional) ────────────────────────────────${RESET}"
    echo "  Hatz AI generates per-host risk narratives and executive summaries."
    echo "  Leave blank to skip — can be enabled later via update-config.sh"
    echo ""
    local HATZ_AI_KEY="" HATZ_NARRATIVES="false"
    prompt_msg "Hatz AI API key (press Enter to skip):"; HATZ_AI_KEY="$(read_tty)"
    if [[ -n "${HATZ_AI_KEY}" ]]; then
        prompt_msg "Enable per-host AI risk narratives? (y/N):"; local _yn; _yn="$(read_tty)"
        [[ "${_yn,,}" == "y" ]] && HATZ_NARRATIVES="true"
    fi

    # ── Reporting ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}${CYAN}── Reporting ──────────────────────────────────────────────────────${RESET}"
    local COMPANY_NAME="" CLIENT_NAME="" INCLUDE_EXEC_PDF="true" INCLUDE_TECH_PDF="true"
    prompt_msg "Company name (default: Yeyland Wutani LLC):"; COMPANY_NAME="$(read_tty)"
    [[ -z "${COMPANY_NAME}" ]] && COMPANY_NAME="Yeyland Wutani LLC"
    while [[ -z "${CLIENT_NAME}" ]]; do
        prompt_msg "Client name (required):"; CLIENT_NAME="$(read_tty)"
        [[ -z "${CLIENT_NAME}" ]] && print_error "Client name is required."
    done
    prompt_msg "Include Executive Summary PDF? (Y/n, default Y):"; local _exec; _exec="$(read_tty)"
    [[ "${_exec,,}" == "n" ]] && INCLUDE_EXEC_PDF="false"
    prompt_msg "Include Technical Detail PDF? (Y/n, default Y):"; local _tech; _tech="$(read_tty)"
    [[ "${_tech,,}" == "n" ]] && INCLUDE_TECH_PDF="false"

    # ── Scan schedule ──────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}${CYAN}── Scan Schedule ──────────────────────────────────────────────────${RESET}"
    local SCAN_TIME="" REPORT_DAY="" REPORT_TIME="" RUN_NOW="n"

    while true; do
        prompt_msg "Daily scan time in HH:MM 24-hour format (default: 02:00):"; SCAN_TIME="$(read_tty)"
        [[ -z "${SCAN_TIME}" ]] && SCAN_TIME="02:00"
        if validate_time "${SCAN_TIME}"; then
            print_ok "Scan time set to ${SCAN_TIME}"; break
        else
            print_error "Invalid time format. Use HH:MM (e.g. 02:00, 14:30)."
        fi
    done

    while true; do
        prompt_msg "Weekly report day (default: Monday):"; REPORT_DAY="$(read_tty)"
        [[ -z "${REPORT_DAY}" ]] && REPORT_DAY="Monday"
        if validate_day "${REPORT_DAY}"; then
            REPORT_DAY="$(cap_first "$(echo "${REPORT_DAY}" | tr '[:upper:]' '[:lower:]')")"
            print_ok "Report day set to ${REPORT_DAY}"; break
        else
            print_error "Invalid day name. Use full day name (e.g. Monday, Tuesday)."
        fi
    done

    while true; do
        prompt_msg "Weekly report time in HH:MM 24-hour format (default: 06:00):"; REPORT_TIME="$(read_tty)"
        [[ -z "${REPORT_TIME}" ]] && REPORT_TIME="06:00"
        if validate_time "${REPORT_TIME}"; then
            print_ok "Report time set to ${REPORT_TIME}"; break
        else
            print_error "Invalid time format. Use HH:MM (e.g. 06:00, 08:30)."
        fi
    done

    prompt_msg "Run first scan immediately after install? (y/N):"
    RUN_NOW="$(read_tty)"
    RUN_NOW="${RUN_NOW:-n}"

    # ── Credential profiles ────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}${CYAN}── Credential Profiles ────────────────────────────────────────────${RESET}"
    echo "  At least one credential profile is required."
    echo "  Profiles allow the scanner to authenticate to hosts during assessment."
    echo ""

    # Build a JSON array of credential profiles using a temp file
    local CREDS_JSON="[]"
    local ADD_MORE="y"
    local PROFILE_COUNT=0

    while [[ "${ADD_MORE,,}" == "y" ]]; do
        PROFILE_COUNT=$(( PROFILE_COUNT + 1 ))
        echo ""
        echo -e "  ${BOLD}── Credential Profile ${PROFILE_COUNT} ──${RESET}"

        local P_NAME="" P_TYPE="" P_SCOPE="" P_TARGETS="" P_USER="" P_PASS=""
        local P_SSHKEY="" P_SNMP_COMMUNITY="" P_SNMP_AUTH="" P_SNMP_PRIV=""
        local P_SNMP_AUTHPROTO="SHA" P_SNMP_PRIVPROTO="AES" P_PRIORITY="10"

        while [[ -z "${P_NAME}" ]]; do
            prompt_msg "Profile name (e.g. servers-ssh):"; P_NAME="$(read_tty)"
            [[ -z "${P_NAME}" ]] && print_error "Profile name is required."
        done

        while true; do
            prompt_msg "Type [ssh / wmi / snmp_v2c / snmp_v3]:"; P_TYPE="$(read_tty)"
            case "${P_TYPE,,}" in
                ssh|wmi|snmp_v2c|snmp_v3) P_TYPE="${P_TYPE,,}"; break ;;
                *) print_error "Invalid type. Choose: ssh, wmi, snmp_v2c, snmp_v3" ;;
            esac
        done

        while true; do
            prompt_msg "Scope [global / subnet / host]:"; P_SCOPE="$(read_tty)"
            case "${P_SCOPE,,}" in
                global|subnet|host) P_SCOPE="${P_SCOPE,,}"; break ;;
                *) print_error "Invalid scope. Choose: global, subnet, host" ;;
            esac
        done

        if [[ "${P_SCOPE}" != "global" ]]; then
            prompt_msg "Targets (comma-separated CIDRs or IPs, e.g. 192.168.1.0/24,10.0.0.5):"
            P_TARGETS="$(read_tty)"
        fi

        prompt_msg "Priority (default: 10, lower = higher priority):"; P_PRIORITY="$(read_tty)"
        [[ -z "${P_PRIORITY}" || ! "${P_PRIORITY}" =~ ^[0-9]+$ ]] && P_PRIORITY="10"

        case "${P_TYPE}" in
            ssh|wmi)
                while [[ -z "${P_USER}" ]]; do
                    prompt_msg "Username:"; P_USER="$(read_tty)"
                    [[ -z "${P_USER}" ]] && print_error "Username is required."
                done
                while [[ -z "${P_PASS}" ]]; do
                    prompt_msg "Password (hidden):"; P_PASS="$(read_tty_secret)"; echo ""
                    [[ -z "${P_PASS}" ]] && print_error "Password is required."
                done
                if [[ "${P_TYPE}" == "ssh" ]]; then
                    prompt_msg "SSH private key path (optional, press Enter to skip):"
                    P_SSHKEY="$(read_tty)"
                fi
                ;;
            snmp_v2c)
                while [[ -z "${P_SNMP_COMMUNITY}" ]]; do
                    prompt_msg "SNMP community string:"; P_SNMP_COMMUNITY="$(read_tty)"
                    [[ -z "${P_SNMP_COMMUNITY}" ]] && print_error "SNMP community string is required."
                done
                ;;
            snmp_v3)
                while [[ -z "${P_USER}" ]]; do
                    prompt_msg "SNMPv3 username:"; P_USER="$(read_tty)"
                    [[ -z "${P_USER}" ]] && print_error "Username is required."
                done
                prompt_msg "Auth protocol [SHA / MD5] (default: SHA):"; P_SNMP_AUTHPROTO="$(read_tty)"
                [[ -z "${P_SNMP_AUTHPROTO}" ]] && P_SNMP_AUTHPROTO="SHA"
                while [[ -z "${P_SNMP_AUTH}" ]]; do
                    prompt_msg "Auth passphrase (hidden):"; P_SNMP_AUTH="$(read_tty_secret)"; echo ""
                    [[ -z "${P_SNMP_AUTH}" ]] && print_error "Auth passphrase is required."
                done
                prompt_msg "Privacy protocol [AES / DES] (default: AES):"; P_SNMP_PRIVPROTO="$(read_tty)"
                [[ -z "${P_SNMP_PRIVPROTO}" ]] && P_SNMP_PRIVPROTO="AES"
                while [[ -z "${P_SNMP_PRIV}" ]]; do
                    prompt_msg "Privacy passphrase (hidden):"; P_SNMP_PRIV="$(read_tty_secret)"; echo ""
                    [[ -z "${P_SNMP_PRIV}" ]] && print_error "Privacy passphrase is required."
                done
                ;;
        esac

        # Build a single JSON object for this profile and append it to CREDS_JSON
        local TARGETS_JSON="[]"
        if [[ -n "${P_TARGETS:-}" ]]; then
            # Convert comma-separated list into a JSON array
            TARGETS_JSON="$(echo "${P_TARGETS}" | \
                python3 -c "import sys, json; parts=[s.strip() for s in sys.stdin.read().split(',') if s.strip()]; print(json.dumps(parts))")"
        fi

        local PROFILE_OBJ
        PROFILE_OBJ="$(jq -n \
            --arg name    "$(json_escape "${P_NAME}")" \
            --arg type    "${P_TYPE}" \
            --arg scope   "${P_SCOPE}" \
            --argjson targets "${TARGETS_JSON}" \
            --arg user    "$(json_escape "${P_USER:-}")" \
            --arg pass    "$(json_escape "${P_PASS:-}")" \
            --arg sshkey  "$(json_escape "${P_SSHKEY:-}")" \
            --arg community "$(json_escape "${P_SNMP_COMMUNITY:-}")" \
            --arg auth_proto "${P_SNMP_AUTHPROTO}" \
            --arg auth_pass "$(json_escape "${P_SNMP_AUTH:-}")" \
            --arg priv_proto "${P_SNMP_PRIVPROTO}" \
            --arg priv_pass "$(json_escape "${P_SNMP_PRIV:-}")" \
            --argjson priority "${P_PRIORITY}" \
            '{
                name:        $name,
                type:        $type,
                scope:       $scope,
                targets:     $targets,
                username:    $user,
                password:    $pass,
                ssh_key:     $sshkey,
                community:   $community,
                auth_proto:  $auth_proto,
                auth_pass:   $auth_pass,
                priv_proto:  $priv_proto,
                priv_pass:   $priv_pass,
                priority:    $priority
            }')"

        CREDS_JSON="$(echo "${CREDS_JSON}" | jq --argjson p "${PROFILE_OBJ}" '. + [$p]')"
        print_ok "Profile '${P_NAME}' added."

        echo ""
        prompt_msg "Add another credential profile? (y/N):"
        ADD_MORE="$(read_tty)"
        [[ -z "${ADD_MORE}" ]] && ADD_MORE="n"
    done

    if [[ "${PROFILE_COUNT}" -eq 0 ]]; then
        die "At least one credential profile is required."
    fi

    # Write credentials to temp file for encryption in Step 8
    echo "${CREDS_JSON}" > "${TMP_CREDS}"
    chmod 600 "${TMP_CREDS}"

    # ── Write config.json ──────────────────────────────────────────────────
    print_step "Step 7: Writing configuration"

    local SCAN_HOUR SCAN_MIN
    SCAN_HOUR="${SCAN_TIME%%:*}"
    SCAN_MIN="${SCAN_TIME##*:}"

    local REPORT_HOUR REPORT_MIN
    REPORT_HOUR="${REPORT_TIME%%:*}"
    REPORT_MIN="${REPORT_TIME##*:}"

    jq -n \
        --arg tenant_id       "$(json_escape "${TENANT_ID}")" \
        --arg client_id       "$(json_escape "${CLIENT_ID}")" \
        --arg client_secret   "$(json_escape "${CLIENT_SECRET}")" \
        --arg from_email      "$(json_escape "${FROM_EMAIL}")" \
        --arg to_email        "$(json_escape "${TO_EMAIL}")" \
        --arg cc_email        "$(json_escape "${CC_EMAIL:-}")" \
        --arg hatz_key        "$(json_escape "${HATZ_AI_KEY:-}")" \
        --argjson hatz_narr   "${HATZ_NARRATIVES}" \
        --arg company         "$(json_escape "${COMPANY_NAME}")" \
        --arg client          "$(json_escape "${CLIENT_NAME}")" \
        --argjson exec_pdf    "${INCLUDE_EXEC_PDF}" \
        --argjson tech_pdf    "${INCLUDE_TECH_PDF}" \
        --arg scan_time       "${SCAN_TIME}" \
        --arg scan_hour       "${SCAN_HOUR}" \
        --arg scan_min        "${SCAN_MIN}" \
        --arg report_day      "${REPORT_DAY}" \
        --arg report_time     "${REPORT_TIME}" \
        --arg report_hour     "${REPORT_HOUR}" \
        --arg report_min      "${REPORT_MIN}" \
        '{
            graph_api: {
                tenant_id:     $tenant_id,
                client_id:     $client_id,
                client_secret: $client_secret,
                from_email:    $from_email,
                to_email:      $to_email,
                cc_emails:     (if $cc_email != "" then [$cc_email] else [] end)
            },
            hatz_ai: {
                api_key:            $hatz_key,
                enable_narratives:  $hatz_narr
            },
            reporting: {
                company_name:        $company,
                client_name:         $client,
                company_color:       "#FF6600",
                tagline:             "Building Better Systems",
                include_exec_pdf:    $exec_pdf,
                include_tech_pdf:    $tech_pdf
            },
            schedule: {
                daily_scan_time:  $scan_time,
                daily_scan_hour:  $scan_hour,
                daily_scan_min:   $scan_min,
                report_day:       $report_day,
                report_time:      $report_time,
                report_hour:      $report_hour,
                report_min:       $report_min
            },
            risk_scanner: {
                scan_timeout:             900,
                max_threads:              40,
                port_scan_top_ports:      1000,
                enable_vuln_scan:         true,
                enable_cve_lookup:        true,
                enable_ssl_audit:         true,
                ssl_cert_warning_days:    30,
                ssl_cert_critical_days:   7,
                enable_snmp_audit:        true,
                enable_smb_audit:         true,
                enable_ssh_audit:         true,
                enable_wmi_audit:         true,
                enable_web_headers_check: true,
                enable_default_creds:     true,
                enable_open_ports_report: true,
                enable_os_detection:      true,
                enable_eol_detection:     true,
                eol_warning_months:       12,
                enable_delta_tracking:    true,
                risk_score_critical:      9,
                risk_score_high:          7,
                risk_score_medium:        4,
                risk_score_low:           1
            },
            system: {
                log_level:        "INFO",
                min_free_disk_mb: 500
            }
        }' > "${CONFIG_DIR}/config.json"

    chmod 640 "${CONFIG_DIR}/config.json"
    chown root:"${SERVICE_USER}" "${CONFIG_DIR}/config.json"
    print_ok "Configuration written to ${CONFIG_DIR}/config.json"

    # Export schedule vars for use in Step 9
    export SCAN_TIME REPORT_DAY REPORT_TIME RUN_NOW
}

# ── Step 8: Encrypt credentials ───────────────────────────────────────────────

encrypt_credentials() {
    print_step "Step 8: Encrypting credential profiles"

    if [[ ! -f "${TMP_CREDS}" ]]; then
        print_warn "No temporary credentials file found — skipping encryption step."
        return
    fi

    "${VENV_DIR}/bin/python" - <<'PYEOF'
import sys
sys.path.insert(0, '/opt/risk-scanner/lib')
try:
    from credential_store import save_credentials
    import json
    with open('/tmp/.risk-scanner-creds-tmp.json') as f:
        profiles = json.load(f)
    save_credentials(profiles, '/opt/risk-scanner/config/config.json')
    print("Credentials encrypted and stored successfully.")
except ImportError:
    # credential_store not yet present (first-time install before full clone)
    # Inline fallback: write encrypted blob using Fernet if available
    import json, os
    try:
        from cryptography.fernet import Fernet
        key_file = '/opt/risk-scanner/config/.cred_key'
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as kf:
                kf.write(key)
            os.chmod(key_file, 0o640)
        else:
            with open(key_file, 'rb') as kf:
                key = kf.read()
        f = Fernet(key)
        with open('/tmp/.risk-scanner-creds-tmp.json', 'rb') as cf:
            raw = cf.read()
        encrypted = f.encrypt(raw)
        out_path = '/opt/risk-scanner/config/.credentials.enc'
        with open(out_path, 'wb') as of:
            of.write(encrypted)
        os.chmod(out_path, 0o640)
        os.chown(out_path, 0, -1)
        print("Credentials encrypted (fallback Fernet) and stored at", out_path)
    except Exception as e:
        print("WARNING: Could not encrypt credentials:", e, file=sys.stderr)
        print("Credentials left in plaintext at /tmp/.risk-scanner-creds-tmp.json", file=sys.stderr)
        sys.exit(0)
except Exception as e:
    print("WARNING: Credential encryption error:", e, file=sys.stderr)
    sys.exit(1)
PYEOF

    rm -f "${TMP_CREDS}"
    print_ok "Temporary credential file removed."

    # Lock down config dir
    chown root:"${SERVICE_USER}" "${CONFIG_DIR}"
    chmod 750 "${CONFIG_DIR}"
    if [[ -f "${CONFIG_DIR}/.cred_key" ]]; then
        chown root:"${SERVICE_USER}" "${CONFIG_DIR}/.cred_key"
        chmod 640 "${CONFIG_DIR}/.cred_key"
    fi
    if [[ -f "${CONFIG_DIR}/.credentials.enc" ]]; then
        chown root:"${SERVICE_USER}" "${CONFIG_DIR}/.credentials.enc"
        chmod 640 "${CONFIG_DIR}/.credentials.enc"
    fi
    print_ok "Credentials encrypted successfully."
}

# ── Step 9: Install systemd units ────────────────────────────────────────────

install_services() {
    print_step "Step 9: Installing systemd units"

    local SRC_SYSTEMD="${INSTALL_DIR}/systemd"

    if [[ ! -d "${SRC_SYSTEMD}" ]]; then
        print_warn "systemd/ directory not found in install — skipping service installation."
        return
    fi

    # Copy all unit files
    for unit_file in "${SRC_SYSTEMD}/"*.service "${SRC_SYSTEMD}/"*.timer; do
        [[ -f "${unit_file}" ]] || continue
        local dest_name
        dest_name="$(basename "${unit_file}")"
        cp "${unit_file}" "${SYSTEMD_DIR}/${dest_name}"
        info "Installed ${dest_name}"
    done

    # Substitute schedule placeholders in timer unit files
    local SCAN_H SCAN_M REPORT_H REPORT_M
    SCAN_H="${SCAN_TIME%%:*}"
    SCAN_M="${SCAN_TIME##*:}"
    REPORT_H="${REPORT_TIME%%:*}"
    REPORT_M="${REPORT_TIME##*:}"

    for timer in "${SYSTEMD_DIR}/risk-scanner-"*.timer; do
        [[ -f "${timer}" ]] || continue
        sed -i \
            -e "s/__SCAN_TIME__/${SCAN_H}:${SCAN_M}/g" \
            -e "s/__REPORT_DAY__/${REPORT_DAY}/g" \
            -e "s/__REPORT_TIME__/${REPORT_H}:${REPORT_M}/g" \
            "${timer}"
    done

    systemctl daemon-reload

    systemctl enable risk-scanner-checkin.service 2>/dev/null || \
        print_warn "risk-scanner-checkin.service not found — check systemd/ directory."
    systemctl enable risk-scanner-daily.timer 2>/dev/null || \
        print_warn "risk-scanner-daily.timer not found — check systemd/ directory."
    systemctl enable risk-scanner-report.timer 2>/dev/null || \
        print_warn "risk-scanner-report.timer not found — check systemd/ directory."
    systemctl enable risk-scanner-web.service 2>/dev/null || \
        print_warn "risk-scanner-web.service not found — check systemd/ directory."

    systemctl start risk-scanner-daily.timer  2>/dev/null || \
        print_warn "Could not start risk-scanner-daily.timer — may need a reboot."
    systemctl start risk-scanner-report.timer 2>/dev/null || \
        print_warn "Could not start risk-scanner-report.timer — may need a reboot."
    systemctl start risk-scanner-web.service  2>/dev/null || \
        print_warn "Could not start risk-scanner-web.service — may need a reboot."

    print_ok "Systemd units installed and enabled."
}

# ── Step 10: Set web dashboard password ──────────────────────────────────────

set_dashboard_password() {
    print_step "Step 10: Set web dashboard password"
    echo ""
    echo "  The web dashboard runs on port 8080 and requires a password."
    echo "  Set it now, or press Enter to skip (use set-dashboard-password.sh later)."
    echo ""

    local DASHBOARD_JSON="${INSTALL_DIR}/config/dashboard.json"

    while true; do
        printf "  Dashboard password (min 8 chars, Enter to skip): "
        read -r -s DASH_PASS </dev/tty
        echo ""
        if [[ -z "${DASH_PASS}" ]]; then
            print_warn "Dashboard password not set. Run: sudo ${INSTALL_DIR}/bin/set-dashboard-password.sh"
            return
        fi
        if [[ ${#DASH_PASS} -lt 8 ]]; then
            print_error "Password must be at least 8 characters."
            continue
        fi
        printf "  Confirm password: "
        read -r -s DASH_PASS2 </dev/tty
        echo ""
        if [[ "${DASH_PASS}" != "${DASH_PASS2}" ]]; then
            print_error "Passwords do not match. Try again."
            continue
        fi
        break
    done

    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" - <<PYEOF
import json, os, sys
password = """${DASH_PASS}"""
try:
    import bcrypt
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    method = "bcrypt"
except ImportError:
    import hmac, hashlib, secrets
    salt = secrets.token_hex(16)
    digest = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    h = "hmac:{}:{}".format(salt, digest)
    method = "hmac-sha256"
data = {"password_hash": h, "auth_method": method}
with open("${DASHBOARD_JSON}", "w") as f:
    json.dump(data, f)
os.chmod("${DASHBOARD_JSON}", 0o600)
print("  Password hashed with " + method)
PYEOF

    print_ok "Dashboard password set. Access at http://$(hostname -s):8080"
}

# ── Step 11: Initialize vulnerability database ────────────────────────────────

init_vuln_db() {
    print_step "Step 11: Initializing vulnerability database"
    echo "  This may take several minutes on first run..."

    local VULN_SCRIPT="${INSTALL_DIR}/bin/update-vuln-db.py"
    if [[ ! -f "${VULN_SCRIPT}" ]]; then
        print_warn "update-vuln-db.py not found at ${VULN_SCRIPT} — skipping."
        return
    fi

    if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" "${VULN_SCRIPT}" --init; then
        print_ok "Vulnerability database initialized."
    else
        print_warn "Vulnerability database initialization failed. Run manually:"
        print_warn "  sudo -u ${SERVICE_USER} ${VENV_DIR}/bin/python ${VULN_SCRIPT} --init"
    fi
}

# ── Step 11: Send test check-in email ────────────────────────────────────────

send_checkin_email() {
    print_step "Step 12: Sending test check-in email"

    local CHECKIN_SCRIPT="${INSTALL_DIR}/bin/initial-checkin.py"
    if [[ ! -f "${CHECKIN_SCRIPT}" ]]; then
        print_warn "initial-checkin.py not found — skipping check-in email."
        return
    fi

    if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" "${CHECKIN_SCRIPT}"; then
        print_ok "Check-in email sent. Check your inbox."
    else
        print_warn "Check-in email failed. Verify credentials and Mail.Send Azure permission."
    fi
}

# ── Step 12: Optional immediate scan ─────────────────────────────────────────

run_first_scan() {
    if [[ "${RUN_NOW,,}" != "y" ]]; then
        return
    fi

    print_step "Step 13: Running first scan"
    info "Starting immediate scan in the background..."

    local MAIN_SCRIPT="${INSTALL_DIR}/bin/risk-scanner-main.py"
    if [[ ! -f "${MAIN_SCRIPT}" ]]; then
        print_warn "risk-scanner-main.py not found — skipping first scan."
        return
    fi

    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" "${MAIN_SCRIPT}" --scan-only &
    local SCAN_PID=$!
    print_ok "First scan launched (PID ${SCAN_PID}). Monitor with:"
    echo "     tail -f ${LOG_DIR}/risk-scanner.log"
}

# ── Final success banner ──────────────────────────────────────────────────────

print_success_banner() {
    local NEXT_SCAN_DATE
    NEXT_SCAN_DATE="$(date --date="tomorrow ${SCAN_TIME}" '+%A %Y-%m-%d at %H:%M' 2>/dev/null || \
                      echo "tomorrow at ${SCAN_TIME}")"

    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║   Risk Scanner Pi — Installation Complete!               ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo ""
    echo -e "  ${BOLD}Install path:${RESET}    ${INSTALL_DIR}"
    echo -e "  ${BOLD}Web dashboard:${RESET}   http://$(hostname -s):8080"
    echo -e "  ${BOLD}Next scan:${RESET}       ${NEXT_SCAN_DATE}"
    echo -e "  ${BOLD}Next report:${RESET}     ${REPORT_DAY}s at ${REPORT_TIME}"
    echo -e "  ${BOLD}Log location:${RESET}    ${LOG_DIR}/risk-scanner.log"
    echo ""
    echo "  ── Quick Reference ──────────────────────────────────────────────"
    echo ""
    echo "  Run a manual scan:"
    echo "     /opt/risk-scanner/bin/manual-scan.sh"
    echo ""
    echo "  View current risks:"
    echo "     /opt/risk-scanner/bin/view-risks.sh"
    echo ""
    echo "  Monitor logs:"
    echo "     tail -f ${LOG_DIR}/risk-scanner.log"
    echo "     sudo journalctl -u risk-scanner-daily -f"
    echo ""
    echo "  Web dashboard (open in any browser):"
    echo "     http://$(hostname -s):8080"
    echo ""
    echo "  Reset dashboard password:"
    echo "     sudo ${INSTALL_DIR}/bin/set-dashboard-password.sh"
    echo ""
    echo "  Reconfigure credentials / settings:"
    echo "     sudo ${INSTALL_DIR}/bin/update-config.sh"
    echo ""
    echo "  Update from GitHub:"
    echo "     sudo bash ${INSTALL_DIR}/bin/self-update.sh"
    echo ""
    echo "  Uninstall:"
    echo "     sudo bash ${INSTALL_DIR}/uninstall.sh"
    echo ""
    echo "  Install log: ${LOG_FILE}"
    echo ""
    echo -e "  ${BOLD}${CYAN}Yeyland Wutani LLC — Building Better Systems${RESET}"
    echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    print_banner

    # Pre-flight
    check_root
    check_os
    check_internet
    check_git

    # Installation steps
    install_packages       # Step 1
    create_service_user    # Step 2
    clone_repo             # Step 3
    setup_venv             # Step 4
    setup_directories      # Step 5
    run_config_wizard      # Steps 6 & 7
    encrypt_credentials    # Step 8
    install_services       # Step 9
    set_dashboard_password # Step 10
    init_vuln_db           # Step 11
    send_checkin_email     # Step 12
    run_first_scan         # Step 13 (conditional)

    print_success_banner
}

main "$@"
