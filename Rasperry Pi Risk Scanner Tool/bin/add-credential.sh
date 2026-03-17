#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Interactive Credential Profile Wizard
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python"
CONFIG_FILE="${INSTALL_DIR}/config/config.json"
SERVICE_USER="risk-scanner"
TEMP_CRED="/tmp/.new-cred-profile.json"

# Color helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   Yeyland Wutani Risk Scanner — Credential Wizard    ║"
    echo "║           Building Better Systems                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

prompt_required() {
    local VAR_NAME="$1"
    local PROMPT_TEXT="$2"
    local VALUE=""
    while [[ -z "$VALUE" ]]; do
        read -rp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC}: ")" VALUE
        if [[ -z "$VALUE" ]]; then
            echo -e "${RED}  This field is required.${NC}"
        fi
    done
    printf -v "$VAR_NAME" '%s' "$VALUE"
}

prompt_optional() {
    local VAR_NAME="$1"
    local PROMPT_TEXT="$2"
    local DEFAULT="${3:-}"
    local VALUE=""
    if [[ -n "$DEFAULT" ]]; then
        read -rp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC} [${YELLOW}${DEFAULT}${NC}]: ")" VALUE
        VALUE="${VALUE:-$DEFAULT}"
    else
        read -rp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC} (optional): ")" VALUE
    fi
    printf -v "$VAR_NAME" '%s' "$VALUE"
}

prompt_secret() {
    local VAR_NAME="$1"
    local PROMPT_TEXT="$2"
    local VALUE=""
    while [[ -z "$VALUE" ]]; do
        read -rsp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC}: ")" VALUE
        echo ""
        if [[ -z "$VALUE" ]]; then
            echo -e "${RED}  This field is required.${NC}"
        fi
    done
    printf -v "$VAR_NAME" '%s' "$VALUE"
}

prompt_choice() {
    local VAR_NAME="$1"
    local PROMPT_TEXT="$2"
    shift 2
    local CHOICES=("$@")
    local VALUE=""
    local CHOICE_STR
    CHOICE_STR=$(printf '%s/' "${CHOICES[@]}")
    CHOICE_STR="${CHOICE_STR%/}"
    while true; do
        read -rp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC} [${YELLOW}${CHOICE_STR}${NC}]: ")" VALUE
        for C in "${CHOICES[@]}"; do
            if [[ "$VALUE" == "$C" ]]; then
                printf -v "$VAR_NAME" '%s' "$VALUE"
                return 0
            fi
        done
        echo -e "${RED}  Invalid choice. Enter one of: ${CHOICE_STR}${NC}"
    done
}

escape_json_string() {
    # Escape backslashes and double quotes for JSON
    local S="$1"
    S="${S//\\/\\\\}"
    S="${S//\"/\\\"}"
    printf '%s' "$S"
}

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root." >&2
    exit 1
fi

print_header
echo -e "This wizard adds a new credential profile to the Risk Scanner."
echo -e "Credentials are stored encrypted in the credential store."
echo ""

# ── Profile name ─────────────────────────────────────────────────────────────
prompt_required PROFILE_NAME "Profile name (e.g., servers-ssh, core-switches-snmp)"

# ── Credential type ───────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}Credential type:${NC}"
echo "  ssh       - SSH username/password or key-based"
echo "  wmi       - Windows WMI/WinRM (username/password)"
echo "  snmp_v2c  - SNMP v2c (community string)"
echo "  snmp_v3   - SNMP v3 (username, auth, privacy)"
echo ""
prompt_choice CRED_TYPE "Type" "ssh" "wmi" "snmp_v2c" "snmp_v3"

# ── Scope ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}Scope:${NC}"
echo "  global  - Apply to all hosts (used as fallback)"
echo "  subnet  - Apply to specific CIDRs"
echo "  host    - Apply to specific IPs"
echo ""
prompt_choice SCOPE "Scope" "global" "subnet" "host"

# ── Targets ───────────────────────────────────────────────────────────────────
TARGETS_JSON="[]"
if [[ "$SCOPE" != "global" ]]; then
    echo ""
    if [[ "$SCOPE" == "subnet" ]]; then
        echo -e "${BOLD}Enter target CIDRs${NC} (comma-separated, e.g., 192.168.1.0/24,10.0.0.0/8):"
    else
        echo -e "${BOLD}Enter target IPs${NC} (comma-separated, e.g., 192.168.1.10,192.168.1.11):"
    fi
    read -rp "> " TARGETS_RAW
    # Build JSON array from comma-separated list
    TARGETS_JSON="["
    IFS=',' read -ra TARGET_ARR <<< "$TARGETS_RAW"
    FIRST=true
    for T in "${TARGET_ARR[@]}"; do
        T="${T// /}"  # strip whitespace
        [[ -z "$T" ]] && continue
        if [[ "$FIRST" == "true" ]]; then
            TARGETS_JSON+="\"$(escape_json_string "$T")\""
            FIRST=false
        else
            TARGETS_JSON+=",\"$(escape_json_string "$T")\""
        fi
    done
    TARGETS_JSON+="]"
fi

# ── Priority ──────────────────────────────────────────────────────────────────
echo ""
prompt_optional PRIORITY "Priority (lower = tried first)" "10"
# Ensure numeric
if ! [[ "$PRIORITY" =~ ^[0-9]+$ ]]; then
    echo -e "${YELLOW}Non-numeric priority; defaulting to 10.${NC}"
    PRIORITY="10"
fi

# ── Type-specific fields ──────────────────────────────────────────────────────
USERNAME=""
PASSWORD=""
SSH_KEY_PATH=""
SNMP_COMMUNITY=""
SNMP_AUTH_PROTO=""
SNMP_AUTH_PASS=""
SNMP_PRIV_PROTO=""
SNMP_PRIV_PASS=""
SNMP_CONTEXT=""

echo ""
echo -e "${BLUE}Credentials for type: ${YELLOW}${CRED_TYPE}${NC}"

case "$CRED_TYPE" in
    ssh)
        prompt_required USERNAME "SSH username"
        echo ""
        echo -e "${BOLD}Authentication method:${NC}"
        echo "  1) Password"
        echo "  2) SSH key file"
        echo "  3) Both (try key first, fall back to password)"
        read -rp "Choice [1/2/3]: " AUTH_METHOD
        case "${AUTH_METHOD:-1}" in
            2)
                prompt_required SSH_KEY_PATH "Path to SSH private key (e.g., /opt/risk-scanner/config/keys/id_rsa)"
                ;;
            3)
                prompt_required SSH_KEY_PATH "Path to SSH private key"
                prompt_secret PASSWORD "SSH password (fallback)"
                ;;
            *)
                prompt_secret PASSWORD "SSH password"
                ;;
        esac
        ;;
    wmi)
        prompt_required USERNAME "Windows username (e.g., DOMAIN\\Administrator or .\\Administrator)"
        prompt_secret PASSWORD "Windows password"
        ;;
    snmp_v2c)
        prompt_required SNMP_COMMUNITY "SNMP community string"
        ;;
    snmp_v3)
        prompt_required USERNAME "SNMPv3 username"
        echo ""
        prompt_choice SNMP_AUTH_PROTO "Authentication protocol" "SHA" "MD5" "SHA256"
        prompt_secret SNMP_AUTH_PASS "Authentication passphrase"
        echo ""
        prompt_choice SNMP_PRIV_PROTO "Privacy (encryption) protocol" "AES" "DES" "AES256"
        prompt_secret SNMP_PRIV_PASS "Privacy passphrase"
        prompt_optional SNMP_CONTEXT "SNMP context name" ""
        ;;
esac

# ── Build JSON ────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
echo "Building credential profile..."

# Construct JSON carefully
JSON_USERNAME="$(escape_json_string "$USERNAME")"
JSON_PASSWORD="$(escape_json_string "$PASSWORD")"
JSON_SSH_KEY="$(escape_json_string "$SSH_KEY_PATH")"
JSON_COMMUNITY="$(escape_json_string "$SNMP_COMMUNITY")"
JSON_AUTH_PASS="$(escape_json_string "$SNMP_AUTH_PASS")"
JSON_PRIV_PASS="$(escape_json_string "$SNMP_PRIV_PASS")"
JSON_CONTEXT="$(escape_json_string "$SNMP_CONTEXT")"

cat > "$TEMP_CRED" <<EOF
{
  "profile_name": "$(escape_json_string "$PROFILE_NAME")",
  "type": "$(escape_json_string "$CRED_TYPE")",
  "scope": "$(escape_json_string "$SCOPE")",
  "targets": ${TARGETS_JSON},
  "priority": ${PRIORITY},
  "username": "${JSON_USERNAME}",
  "password": "${JSON_PASSWORD}",
  "ssh_key_path": "${JSON_SSH_KEY}",
  "snmp_community": "${JSON_COMMUNITY}",
  "snmp_auth_protocol": "$(escape_json_string "$SNMP_AUTH_PROTO")",
  "snmp_auth_passphrase": "${JSON_AUTH_PASS}",
  "snmp_priv_protocol": "$(escape_json_string "$SNMP_PRIV_PROTO")",
  "snmp_priv_passphrase": "${JSON_PRIV_PASS}",
  "snmp_context": "${JSON_CONTEXT}"
}
EOF

chmod 600 "$TEMP_CRED"

# ── Save to credential store ──────────────────────────────────────────────────
echo "Saving to credential store..."

sudo -u "$SERVICE_USER" "$VENV_PYTHON" - <<'PYEOF'
import sys, json
from pathlib import Path
sys.path.insert(0, '/opt/risk-scanner/lib')
from credential_store import add_credential
import os

with open('/tmp/.new-cred-profile.json') as f:
    profile = json.load(f)
add_credential(profile, Path('/opt/risk-scanner/config/credentials.enc'))
print("Credential profile added successfully.")
PYEOF

# Remove temp file
rm -f "$TEMP_CRED"

echo ""
echo -e "${GREEN}${BOLD}Profile '${PROFILE_NAME}' saved.${NC}"
echo ""

# ── Offer test ────────────────────────────────────────────────────────────────
read -rp "$(echo -e "${BOLD}Test this credential against a specific IP? (y/N):${NC} ")" TEST_NOW
TEST_NOW="${TEST_NOW,,}"

if [[ "$TEST_NOW" == "y" || "$TEST_NOW" == "yes" ]]; then
    SCRIPT_DIR="$(dirname "$(realpath "$0")")"
    if [[ -x "${SCRIPT_DIR}/test-credential.sh" ]]; then
        echo ""
        bash "${SCRIPT_DIR}/test-credential.sh"
    else
        echo -e "${YELLOW}Warning:${NC} test-credential.sh not found at ${SCRIPT_DIR}/"
        echo "Run manually: sudo test-credential.sh <IP>"
    fi
else
    echo "You can test later with: sudo test-credential.sh <IP>"
fi
