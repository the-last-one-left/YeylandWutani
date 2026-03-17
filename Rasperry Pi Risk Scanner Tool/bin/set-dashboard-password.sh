#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Set / Reset Dashboard Password
# Writes bcrypt hash to /opt/risk-scanner/config/dashboard.json
# Falls back to HMAC-SHA256 if bcrypt unavailable.
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python3"
DASHBOARD_CONFIG="${INSTALL_DIR}/config/dashboard.json"
WEB_SERVICE="risk-scanner-web.service"

# ── Color helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_ok()    { echo -e "${GREEN}  [OK]${NC} $*"; }
print_error() { echo -e "${RED}  [ERROR]${NC} $*" >&2; }
print_warn()  { echo -e "${YELLOW}  [WARN]${NC} $*"; }
print_info()  { echo -e "${CYAN}  [INFO]${NC} $*"; }

# ── Header ────────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Yeyland Wutani Risk Scanner — Set Dashboard Password ║"
echo "║           Building Better Systems                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Must run as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root."
    exit 1
fi

# ── Check venv python exists ──────────────────────────────────────────────────
if [[ ! -x "$VENV_PYTHON" ]]; then
    print_error "Python venv not found at ${VENV_PYTHON}"
    print_info  "Run the installer first: sudo bash ${INSTALL_DIR}/install.sh"
    exit 1
fi

# ── Prompt for password ───────────────────────────────────────────────────────
while true; do
    echo -ne "${BOLD}New dashboard password:${NC} "
    read -rs PASSWORD1
    echo ""

    if [[ ${#PASSWORD1} -lt 8 ]]; then
        print_warn "Password must be at least 8 characters. Try again."
        echo ""
        continue
    fi

    echo -ne "${BOLD}Confirm password:${NC} "
    read -rs PASSWORD2
    echo ""

    if [[ "$PASSWORD1" != "$PASSWORD2" ]]; then
        print_warn "Passwords do not match. Try again."
        echo ""
        continue
    fi

    break
done

echo ""
print_info "Hashing password..."

# ── Write hash via Python ─────────────────────────────────────────────────────
export _DASH_PW="$PASSWORD1"

"$VENV_PYTHON" - <<'PYEOF'
import os
import json
import sys
import secrets
import hmac
import hashlib

password = os.environ.get('_DASH_PW', '')
if not password:
    print("ERROR: No password provided", file=sys.stderr)
    sys.exit(1)

dashboard_config = '/opt/risk-scanner/config/dashboard.json'

# Try bcrypt first
try:
    import bcrypt
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    method = 'bcrypt'
except ImportError:
    # Fallback: HMAC-SHA256 with random salt
    salt = secrets.token_hex(16)
    digest = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    pw_hash = f"hmac:{salt}:{digest}"
    method = 'hmac-sha256'

# Load or create dashboard config
try:
    with open(dashboard_config) as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}

data['password_hash'] = pw_hash

import os
os.makedirs(os.path.dirname(dashboard_config), exist_ok=True)
with open(dashboard_config, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')

print(f"Hash written ({method}).")
PYEOF

# Secure the file: only risk-scanner user should read it
chown risk-scanner:risk-scanner "$DASHBOARD_CONFIG" 2>/dev/null || true
chmod 600 "$DASHBOARD_CONFIG"

print_ok "Password hash saved to ${DASHBOARD_CONFIG}"

# ── Restart web service if active ─────────────────────────────────────────────
if systemctl is-active --quiet "$WEB_SERVICE" 2>/dev/null; then
    print_info "Restarting ${WEB_SERVICE}..."
    if systemctl restart "$WEB_SERVICE"; then
        print_ok "${WEB_SERVICE} restarted."
    else
        print_warn "Could not restart ${WEB_SERVICE}. Restart manually: systemctl restart ${WEB_SERVICE}"
    fi
else
    print_info "${WEB_SERVICE} is not currently running."
    print_info "To start it: systemctl start ${WEB_SERVICE}"
fi

echo ""
# Get hostname for display
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)
echo -e "${GREEN}${BOLD}Dashboard password updated.${NC}"
echo -e "Access the dashboard at: ${CYAN}http://${HOSTNAME_SHORT}:8080${NC}"
echo ""
