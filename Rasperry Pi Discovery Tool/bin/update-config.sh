#!/usr/bin/env bash
# =============================================================================
# Yeyland Wutani - Network Discovery Pi
# update-config.sh - Interactive Configuration Editor
#
# Usage: sudo bash /opt/network-discovery/bin/update-config.sh
#
# Features:
#   - Menu-driven: update only what you need (non-destructive jq patching)
#   - Shows current values as defaults
#   - Supports all discovery feature flags and scan settings
#   - CC email list management
#   - Built-in OAuth test
#   - Manual GitHub update trigger
# =============================================================================

INSTALL_DIR="/opt/network-discovery"
CONFIG_FILE="${INSTALL_DIR}/config/config.json"
SERVICE_USER="network-discovery"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python3"
CHECKIN_FLAG="${INSTALL_DIR}/data/.checkin_complete"

# ── Colours ───────────────────────────────────────────────────────────────────
COLOR_ORANGE='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_GREEN='\033[0;32m'
COLOR_BOLD='\033[1m'
COLOR_RESET='\033[0m'

# ── Guards ────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0" >&2; exit 1; }
command -v jq &>/dev/null || { echo "jq not found. Install with: apt install jq"; exit 1; }
[[ -f "${CONFIG_FILE}" ]] || { echo "Config not found: ${CONFIG_FILE}"; exit 1; }

# ── jq patch helpers ──────────────────────────────────────────────────────────

# patch_config_str ".path.to.key" "string_value"
patch_config_str() {
    local KEY="$1" VAL="$2"
    local TMP
    TMP="$(mktemp)"
    jq --arg v "${VAL}" "${KEY} = \$v" "${CONFIG_FILE}" > "${TMP}" \
        && mv "${TMP}" "${CONFIG_FILE}" \
        || { echo "ERROR: jq update failed for ${KEY}"; rm -f "${TMP}"; }
    chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
}

# patch_config_bool ".path.to.key" "true"|"false"
patch_config_bool() {
    local KEY="$1" VAL="$2"
    local TMP
    TMP="$(mktemp)"
    jq "${KEY} = ${VAL}" "${CONFIG_FILE}" > "${TMP}" \
        && mv "${TMP}" "${CONFIG_FILE}" \
        || { echo "ERROR: jq update failed for ${KEY}"; rm -f "${TMP}"; }
    chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
}

# patch_config_int ".path.to.key" integer_value
patch_config_int() {
    local KEY="$1" VAL="$2"
    local TMP
    TMP="$(mktemp)"
    jq --argjson v "${VAL}" "${KEY} = \$v" "${CONFIG_FILE}" > "${TMP}" \
        && mv "${TMP}" "${CONFIG_FILE}" \
        || { echo "ERROR: jq update failed for ${KEY}"; rm -f "${TMP}"; }
    chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
}

# patch_config_arr ".path.to.key" '["a","b","c"]'
patch_config_arr() {
    local KEY="$1" JSON_ARR="$2"
    local TMP
    TMP="$(mktemp)"
    jq --argjson arr "${JSON_ARR}" "${KEY} = \$arr" "${CONFIG_FILE}" > "${TMP}" \
        && mv "${TMP}" "${CONFIG_FILE}" \
        || { echo "ERROR: jq update failed for ${KEY}"; rm -f "${TMP}"; }
    chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
}

# get_val ".path.to.key"  -> prints current value (jq -r), empty string if missing
get_val() {
    jq -r "${1} // empty" "${CONFIG_FILE}" 2>/dev/null || echo ""
}

# ── Display helpers ───────────────────────────────────────────────────────────

show_header() {
    clear
    echo -e "${COLOR_ORANGE}${COLOR_BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║     Yeyland Wutani - Network Discovery Pi               ║"
    echo "  ║     Configuration Editor                                 ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}"
}

show_current_summary() {
    local tenant client from_email to_email device company secret_set
    tenant="$(get_val '.graph_api.tenant_id')"
    client="$(get_val '.graph_api.client_id')"
    secret_set="$(jq -r 'if (.graph_api.client_secret // "" | length) > 0 then "***SET***" else "(not set)" end' "${CONFIG_FILE}" 2>/dev/null)"
    from_email="$(get_val '.graph_api.from_email')"
    to_email="$(get_val '.graph_api.to_email')"
    device="$(get_val '.system.device_name')"
    company="$(get_val '.reporting.company_name')"

    echo -e "${COLOR_BLUE}  Current Configuration:${COLOR_RESET}"
    echo "    Tenant ID:     ${tenant:0:40}${tenant:40:+…}"
    echo "    Client ID:     ${client:0:40}${client:40:+…}"
    echo "    Client Secret: ${secret_set}"
    echo "    From Email:    ${from_email}"
    echo "    To Email:      ${to_email}"
    echo "    Device Name:   ${device}"
    echo "    Company:       ${company}"
    echo ""
}

press_enter() {
    echo ""
    read -rp "  Press Enter to continue..."
}

# ── Menu handlers ─────────────────────────────────────────────────────────────

menu_graph_api() {
    show_header
    echo -e "${COLOR_BOLD}  1) Microsoft Graph API Credentials${COLOR_RESET}"
    echo "  (Leave blank to keep existing value)"
    echo ""

    local TENANT CLIENT V
    TENANT="$(get_val '.graph_api.tenant_id')"
    CLIENT="$(get_val '.graph_api.client_id')"

    read -rp "  Tenant ID [${TENANT}]: " V
    [[ -n "${V}" ]] && patch_config_str ".graph_api.tenant_id" "${V}"

    read -rp "  Client ID [${CLIENT}]: " V
    [[ -n "${V}" ]] && patch_config_str ".graph_api.client_id" "${V}"

    echo -n "  Client Secret (Enter to keep existing, or type new): "
    read -rs V
    echo ""
    [[ -n "${V}" ]] && patch_config_str ".graph_api.client_secret" "${V}"

    echo -e "  ${COLOR_GREEN}Saved.${COLOR_RESET}"
    press_enter
}

menu_email_addresses() {
    show_header
    echo -e "${COLOR_BOLD}  2) Email Addresses${COLOR_RESET}"
    echo "  (Leave blank to keep existing value)"
    echo ""

    local FROM TO V
    FROM="$(get_val '.graph_api.from_email')"
    TO="$(get_val '.graph_api.to_email')"

    read -rp "  From email (M365 mailbox) [${FROM}]: " V
    [[ -n "${V}" ]] && patch_config_str ".graph_api.from_email" "${V}"

    read -rp "  To email (receives reports) [${TO}]: " V
    [[ -n "${V}" ]] && patch_config_str ".graph_api.to_email" "${V}"

    echo -e "  ${COLOR_GREEN}Saved.${COLOR_RESET}"
    press_enter
}

menu_device_report() {
    show_header
    echo -e "${COLOR_BOLD}  3) Device & Report Settings${COLOR_RESET}"
    echo "  (Leave blank to keep existing value)"
    echo ""

    local DEVICE COMPANY COLOR LOG_LEVEL V
    DEVICE="$(get_val '.system.device_name')"
    COMPANY="$(get_val '.reporting.company_name')"
    COLOR="$(get_val '.reporting.company_color')"
    LOG_LEVEL="$(get_val '.system.log_level')"

    read -rp "  Device name [${DEVICE}]: " V
    [[ -n "${V}" ]] && patch_config_str ".system.device_name" "${V}"

    read -rp "  Company name for reports [${COMPANY}]: " V
    [[ -n "${V}" ]] && patch_config_str ".reporting.company_name" "${V}"

    read -rp "  Company color (hex, e.g. #00A0D9) [${COLOR}]: " V
    [[ -n "${V}" ]] && patch_config_str ".reporting.company_color" "${V}"

    read -rp "  Log level (DEBUG/INFO/WARNING/ERROR) [${LOG_LEVEL}]: " V
    if [[ -n "${V}" ]]; then
        V="${V^^}"  # uppercase
        [[ "${V}" =~ ^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$ ]] \
            && patch_config_str ".system.log_level" "${V}" \
            || echo "  (Invalid level — kept existing)"
    fi

    echo -e "  ${COLOR_GREEN}Saved.${COLOR_RESET}"
    press_enter
}

menu_discovery_settings() {
    show_header
    echo -e "${COLOR_BOLD}  4) Discovery Scan Settings${COLOR_RESET}"
    echo ""
    echo "  Current values:"
    jq -r '
      .network_discovery |
      "    scan_timeout               = " + (.scan_timeout | tostring),
      "    max_threads                = " + (.max_threads | tostring),
      "    port_scan_top_ports        = " + (.port_scan_top_ports | tostring),
      "    enable_snmp_enhanced       = " + ((.enable_snmp_enhanced // true) | tostring),
      "    enable_ad_probing          = " + ((.enable_ad_probing // true) | tostring),
      "    ad_probe_timeout           = " + ((.ad_probe_timeout // 10) | tostring),
      "    enable_gateway_fingerprint = " + ((.enable_gateway_fingerprint // true) | tostring),
      "    enable_public_ip_lookup    = " + ((.enable_public_ip_lookup // true) | tostring),
      "    enable_os_detection        = " + ((.enable_os_detection // true) | tostring),
      "    enable_nse_scripts         = " + ((.enable_nse_scripts // true) | tostring),
      "    enable_banner_grab         = " + ((.enable_banner_grab // true) | tostring)
    ' "${CONFIG_FILE}" 2>/dev/null || echo "  (could not read discovery settings)"
    echo ""
    echo "  (Leave blank to keep. Integers: just type number. Booleans: type true or false)"
    echo ""

    local CUR V

    CUR="$(get_val '.network_discovery.scan_timeout')"
    read -rp "  scan_timeout seconds [${CUR}]: " V
    [[ -n "${V}" && "${V}" =~ ^[0-9]+$ ]] && patch_config_int ".network_discovery.scan_timeout" "${V}"

    CUR="$(get_val '.network_discovery.max_threads')"
    read -rp "  max_threads [${CUR}]: " V
    [[ -n "${V}" && "${V}" =~ ^[0-9]+$ ]] && patch_config_int ".network_discovery.max_threads" "${V}"

    CUR="$(get_val '.network_discovery.port_scan_top_ports')"
    read -rp "  port_scan_top_ports [${CUR}]: " V
    [[ -n "${V}" && "${V}" =~ ^[0-9]+$ ]] && patch_config_int ".network_discovery.port_scan_top_ports" "${V}"

    CUR="$(get_val '.network_discovery.ad_probe_timeout')"
    read -rp "  ad_probe_timeout seconds [${CUR:-10}]: " V
    [[ -n "${V}" && "${V}" =~ ^[0-9]+$ ]] && patch_config_int ".network_discovery.ad_probe_timeout" "${V}"

    while IFS=: read -r LABEL KEY DEFAULT; do
        CUR="$(get_val "${KEY}")"
        read -rp "  ${LABEL} (true/false) [${CUR:-${DEFAULT}}]: " V
        [[ "${V}" == "true" || "${V}" == "false" ]] && patch_config_bool "${KEY}" "${V}"
    done << 'FLAGS'
enable_snmp_enhanced:.network_discovery.enable_snmp_enhanced:true
enable_ad_probing:.network_discovery.enable_ad_probing:true
enable_gateway_fingerprint:.network_discovery.enable_gateway_fingerprint:true
enable_public_ip_lookup:.network_discovery.enable_public_ip_lookup:true
enable_os_detection:.network_discovery.enable_os_detection:true
enable_nse_scripts:.network_discovery.enable_nse_scripts:true
enable_banner_grab:.network_discovery.enable_banner_grab:true
FLAGS

    echo -e "  ${COLOR_GREEN}Saved.${COLOR_RESET}"
    press_enter
}

menu_cc_emails() {
    show_header
    echo -e "${COLOR_BOLD}  5) CC Email List${COLOR_RESET}"
    echo ""

    local CURRENT_CC V JSON_ARR
    CURRENT_CC="$(jq -r '.graph_api.cc_emails // [] | join(", ")' "${CONFIG_FILE}" 2>/dev/null)"
    echo "  Current CC list: ${CURRENT_CC:-'(none)'}"
    echo ""
    echo "  Options:"
    echo "    - Enter comma-separated emails to set a new list"
    echo "    - Enter 'clear' to remove all CC addresses"
    echo "    - Leave blank to keep current list"
    echo ""
    read -rp "  CC emails: " V

    if [[ "${V}" == "clear" ]]; then
        patch_config_arr ".graph_api.cc_emails" "[]"
        echo -e "  ${COLOR_GREEN}CC list cleared.${COLOR_RESET}"
    elif [[ -n "${V}" ]]; then
        JSON_ARR="$(echo "${V}" | "${VENV_PYTHON}" -c "
import sys, json
raw = sys.stdin.read().strip()
parts = [x.strip() for x in raw.split(',') if x.strip()]
print(json.dumps(parts))
" 2>/dev/null || echo "[]")"
        patch_config_arr ".graph_api.cc_emails" "${JSON_ARR}"
        echo -e "  ${COLOR_GREEN}CC list updated.${COLOR_RESET}"
    else
        echo "  (No changes made)"
    fi
    press_enter
}

menu_test_oauth() {
    show_header
    echo -e "${COLOR_BOLD}  6) Test OAuth Connection${COLOR_RESET}"
    echo ""
    echo "  Testing Microsoft Graph API authentication..."
    echo ""

    if "${VENV_PYTHON}" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}/lib')
from graph_auth import load_credentials_from_config
auth = load_credentials_from_config('${CONFIG_FILE}')
token = auth.get_token()
print('  Token acquired (first 20 chars): ' + token[:20] + '...')
print('  Authentication: OK')
" 2>&1; then
        echo ""
        echo -e "  ${COLOR_GREEN}OAuth connection successful.${COLOR_RESET}"
    else
        echo ""
        echo -e "  ${COLOR_ORANGE}Authentication FAILED. Check tenant_id, client_id, and client_secret.${COLOR_RESET}"
    fi
    press_enter
}

menu_reset_checkin() {
    show_header
    echo -e "${COLOR_BOLD}  7) Reset Initial Check-In${COLOR_RESET}"
    echo ""

    if [[ -f "${CHECKIN_FLAG}" ]]; then
        echo "  Check-in was last completed at: $(cat "${CHECKIN_FLAG}" 2>/dev/null || echo 'unknown')"
        echo ""
        read -rp "  Remove flag to re-run check-in on next service start? (y/N): " V
        if [[ "${V}" =~ ^[Yy]$ ]]; then
            rm -f "${CHECKIN_FLAG}"
            echo -e "  ${COLOR_GREEN}Flag removed.${COLOR_RESET}"
            echo "  Restart check-in service when ready:"
            echo "    sudo systemctl restart initial-checkin.service"
        else
            echo "  (Cancelled)"
        fi
    else
        echo "  Check-in flag not found — check-in has not run yet or was already reset."
    fi
    press_enter
}

menu_self_update() {
    show_header
    echo -e "${COLOR_BOLD}  8) Check for Updates from GitHub${COLOR_RESET}"
    echo ""
    echo "  Pulling latest code from GitHub..."
    echo ""

    if [[ -x "${INSTALL_DIR}/bin/self-update.sh" ]]; then
        bash "${INSTALL_DIR}/bin/self-update.sh"
        echo ""
        echo -e "  ${COLOR_GREEN}Update check complete. See above for details.${COLOR_RESET}"
    else
        echo "  self-update.sh not found at ${INSTALL_DIR}/bin/self-update.sh"
    fi
    press_enter
}

menu_show_full_config() {
    show_header
    echo -e "${COLOR_BOLD}  9) Full Configuration (client_secret redacted)${COLOR_RESET}"
    echo ""
    jq '
      .graph_api.client_secret = if (.graph_api.client_secret // "" | length) > 0 then "***REDACTED***" else "(not set)" end
    ' "${CONFIG_FILE}" 2>/dev/null
    echo ""
    press_enter
}

# ── Main menu loop ────────────────────────────────────────────────────────────

while true; do
    show_header
    show_current_summary
    echo -e "${COLOR_BOLD}  Select an option:${COLOR_RESET}"
    echo ""
    echo "    1)  Update Microsoft Graph API credentials"
    echo "    2)  Update email addresses (from / to)"
    echo "    3)  Update device / report settings"
    echo "    4)  Update discovery scan settings & feature flags"
    echo "    5)  Update CC email list"
    echo "    6)  Test OAuth connection"
    echo "    7)  Reset initial check-in flag"
    echo "    8)  Check for updates from GitHub"
    echo "    9)  Show full configuration"
    echo "    10) Exit"
    echo ""
    read -rp "  Choice [1-10]: " CHOICE

    case "${CHOICE}" in
        1)  menu_graph_api ;;
        2)  menu_email_addresses ;;
        3)  menu_device_report ;;
        4)  menu_discovery_settings ;;
        5)  menu_cc_emails ;;
        6)  menu_test_oauth ;;
        7)  menu_reset_checkin ;;
        8)  menu_self_update ;;
        9)  menu_show_full_config ;;
       10)  echo ""; echo "  Goodbye."; echo ""; exit 0 ;;
        *)  echo "  Invalid choice '${CHOICE}'." ; sleep 1 ;;
    esac
done
