#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Test Credential Profile Against a Host
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python"
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
    echo "║   Yeyland Wutani Risk Scanner — Credential Test      ║"
    echo "║           Building Better Systems                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [IP_ADDRESS]"
    echo ""
    echo "  Tests the matching credential profile against the given IP."
    echo "  If no IP is provided, you will be prompted."
    echo ""
    exit 0
}

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root." >&2
    exit 1
fi

# Parse args
TARGET_IP=""
case "${1:-}" in
    --help|-h) usage ;;
    "")        ;;
    *)         TARGET_IP="$1" ;;
esac

print_header

# Prompt if not provided
if [[ -z "$TARGET_IP" ]]; then
    read -rp "$(echo -e "${BOLD}Target IP address:${NC} ")" TARGET_IP
    if [[ -z "$TARGET_IP" ]]; then
        echo -e "${RED}Error:${NC} IP address is required." >&2
        exit 1
    fi
fi

echo -e "Testing credentials for: ${YELLOW}${TARGET_IP}${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
echo ""

# Run credential test as service user
RESULT=0
sudo -u "$SERVICE_USER" "$VENV_PYTHON" - <<PYEOF || RESULT=$?
import sys
sys.path.insert(0, '/opt/risk-scanner/lib')

try:
    from credential_store import load_credentials, test_credential
    from network_utils import resolve_credential_profile
    import json
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(2)

config_path = '/opt/risk-scanner/config/config.json'
target_ip = '${TARGET_IP}'

try:
    creds = load_credentials(config_path)
except Exception as e:
    print(f"Failed to load credentials: {e}")
    sys.exit(2)

if not creds:
    print("No credential profiles defined. Use add-credential.sh to add one.")
    sys.exit(1)

profile = resolve_credential_profile(target_ip, creds)
if not profile:
    print(f"No matching credential profile found for {target_ip}.")
    print(f"Total profiles available: {len(creds)}")
    sys.exit(1)

print(f"Matched profile : {profile.get('profile_name', '?')}")
print(f"Type            : {profile.get('type', '?')}")
print(f"Scope           : {profile.get('scope', '?')}")
if profile.get('targets'):
    print(f"Targets         : {', '.join(profile['targets'])}")
print()
print(f"Testing connection to {target_ip}...")

try:
    result = test_credential(profile, target_ip)
except Exception as e:
    print(f"Test raised an exception: {e}")
    sys.exit(1)

if result:
    print(f"SUCCESS: Connected to {target_ip} using profile '{profile.get('profile_name', '?')}'")
    sys.exit(0)
else:
    print(f"FAILED: Could not connect to {target_ip} using profile '{profile.get('profile_name', '?')}'")
    sys.exit(1)
PYEOF

echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"

if [[ $RESULT -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Credential test passed.${NC}"
elif [[ $RESULT -eq 2 ]]; then
    echo -e "${RED}${BOLD}Configuration error. Check lib/ imports and config.json.${NC}"
    exit 2
else
    echo -e "${RED}${BOLD}Credential test failed.${NC}"
    echo "Check the credential profile with: sudo add-credential.sh"
    exit 1
fi
