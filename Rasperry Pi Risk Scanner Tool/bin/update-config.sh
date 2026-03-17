#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - Re-run Configuration Wizard
# NOTE: Credential profiles are preserved — credentials.enc is NOT touched.
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python"
CONFIG_FILE="${INSTALL_DIR}/config/config.json"
SERVICE_USER="risk-scanner"

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
    echo "║  Yeyland Wutani Risk Scanner — Update Configuration  ║"
    echo "║           Building Better Systems                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

prompt_with_default() {
    local VAR_NAME="$1"
    local PROMPT_TEXT="$2"
    local DEFAULT="$3"
    local VALUE=""
    if [[ -n "$DEFAULT" ]]; then
        read -rp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC} [${YELLOW}${DEFAULT}${NC}]: ")" VALUE
        VALUE="${VALUE:-$DEFAULT}"
    else
        read -rp "$(echo -e "${BOLD}${PROMPT_TEXT}${NC}: ")" VALUE
    fi
    printf -v "$VAR_NAME" '%s' "$VALUE"
}

prompt_secret_with_skip() {
    local VAR_NAME="$1"
    local PROMPT_TEXT="$2"
    echo -ne "${BOLD}${PROMPT_TEXT}${NC} (press Enter to keep existing): "
    local VALUE=""
    read -rs VALUE
    echo ""
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

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root." >&2
    exit 1
fi

print_header

echo -e "${YELLOW}Note:${NC} Credential profiles are preserved — this wizard does NOT touch credentials.enc."
echo ""

# ── Read existing config ──────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}Error:${NC} Config file not found: ${CONFIG_FILE}" >&2
    echo "Run the installer to create an initial configuration."
    exit 1
fi

# Extract current values using Python (handles JSON properly)
read_cfg() {
    sudo -u "$SERVICE_USER" "$VENV_PYTHON" - "$1" <<'PYEOF' 2>/dev/null || echo ""
import sys, json
key = sys.argv[1]
try:
    with open('/opt/risk-scanner/config/config.json') as f:
        cfg = json.load(f)
    # Support dot notation: section.key
    parts = key.split('.')
    val = cfg
    for p in parts:
        val = val.get(p, '')
    print(val if val is not None else '')
except Exception:
    print('')
PYEOF
}

# Load current values as defaults
echo "Loading current configuration..."
CUR_TENANT_ID=$(read_cfg "graph_api.tenant_id")
CUR_CLIENT_ID=$(read_cfg "graph_api.client_id")
CUR_SENDER_EMAIL=$(read_cfg "reporting.sender_email")
CUR_REPORT_TO=$(read_cfg "reporting.report_to")
CUR_CLIENT_NAME=$(read_cfg "reporting.client_name")
CUR_SITE_NAME=$(read_cfg "reporting.site_name")
CUR_SCAN_NETWORKS=$(read_cfg "scanning.networks")
CUR_HATZ_ENABLED=$(read_cfg "hatz_ai.enabled")
CUR_HATZ_API_KEY=$(read_cfg "hatz_ai.api_key")
CUR_HATZ_MODEL=$(read_cfg "hatz_ai.model")
CUR_SCAN_TIME=$(read_cfg "schedule.scan_time")
CUR_REPORT_DAY=$(read_cfg "schedule.report_day")
CUR_REPORT_TIME=$(read_cfg "schedule.report_time")
CUR_PRESERVE_CREDS=$(read_cfg "credentials_file")

echo -e "${GREEN}Current configuration loaded.${NC}"
echo ""

# ── Section: Microsoft Graph API ─────────────────────────────────────────────
echo -e "${BLUE}${BOLD}[ 1/5 ] Microsoft Graph API (email delivery) ${NC}"
echo ""
prompt_with_default TENANT_ID   "Azure Tenant ID"   "$CUR_TENANT_ID"
prompt_with_default CLIENT_ID   "App Client ID"     "$CUR_CLIENT_ID"

# Secret: skip if empty input
prompt_secret_with_skip CLIENT_SECRET "App Client Secret"
if [[ -z "$CLIENT_SECRET" ]]; then
    CLIENT_SECRET="__KEEP__"
fi

echo ""

# ── Section: Reporting ────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}[ 2/5 ] Reporting Settings ${NC}"
echo ""
prompt_with_default SENDER_EMAIL "Sender email address (from)"  "$CUR_SENDER_EMAIL"
prompt_with_default REPORT_TO    "Report recipient email(s)"    "$CUR_REPORT_TO"
prompt_with_default CLIENT_NAME  "Client / organization name"   "$CUR_CLIENT_NAME"
prompt_with_default SITE_NAME    "Site name / location"         "$CUR_SITE_NAME"
echo ""

# ── Section: Scanning ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}[ 3/5 ] Scanning Settings ${NC}"
echo ""
echo "  Enter target networks as comma-separated CIDRs."
echo "  Example: 192.168.1.0/24,10.0.0.0/16"
echo ""
prompt_with_default SCAN_NETWORKS "Target networks (CIDRs)" "$CUR_SCAN_NETWORKS"
echo ""

# ── Section: Hatz AI ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}[ 4/5 ] Hatz AI Integration (optional) ${NC}"
echo ""
prompt_choice HATZ_ENABLED "Enable Hatz AI enrichment" "true" "false"
if [[ "$HATZ_ENABLED" == "true" ]]; then
    prompt_with_default HATZ_API_KEY "$CUR_HATZ_API_KEY" ""
    if [[ -z "${HATZ_API_KEY:-}" ]]; then
        prompt_secret_with_skip HATZ_API_KEY "Hatz AI API key"
        [[ -z "$HATZ_API_KEY" ]] && HATZ_API_KEY="__KEEP__"
    fi
    prompt_with_default HATZ_MODEL "Hatz AI model" "${CUR_HATZ_MODEL:-hatz-risk-v1}"
else
    HATZ_API_KEY="__KEEP__"
    HATZ_MODEL="${CUR_HATZ_MODEL:-hatz-risk-v1}"
fi
echo ""

# ── Section: Schedule ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}[ 5/5 ] Schedule ${NC}"
echo ""
echo "  Scan time format: HH:MM (24-hour). Example: 02:00"
prompt_with_default SCAN_TIME "Daily scan time" "${CUR_SCAN_TIME:-02:00}"

echo ""
echo "  Report day: Mon, Tue, Wed, Thu, Fri, Sat, or Sun"
prompt_with_default REPORT_DAY  "Weekly report day"  "${CUR_REPORT_DAY:-Mon}"
prompt_with_default REPORT_TIME "Weekly report time" "${CUR_REPORT_TIME:-06:00}"
echo ""

# ── Write new config via Python ───────────────────────────────────────────────
echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
echo "Writing updated configuration..."

export NEW_TENANT_ID="$TENANT_ID"
export NEW_CLIENT_ID="$CLIENT_ID"
export NEW_CLIENT_SECRET="$CLIENT_SECRET"
export NEW_SENDER_EMAIL="$SENDER_EMAIL"
export NEW_REPORT_TO="$REPORT_TO"
export NEW_CLIENT_NAME="$CLIENT_NAME"
export NEW_SITE_NAME="$SITE_NAME"
export NEW_SCAN_NETWORKS="$SCAN_NETWORKS"
export NEW_HATZ_ENABLED="$HATZ_ENABLED"
export NEW_HATZ_API_KEY="$HATZ_API_KEY"
export NEW_HATZ_MODEL="$HATZ_MODEL"
export NEW_SCAN_TIME="$SCAN_TIME"
export NEW_REPORT_DAY="$REPORT_DAY"
export NEW_REPORT_TIME="$REPORT_TIME"

sudo -u "$SERVICE_USER" "$VENV_PYTHON" - <<'PYEOF'
import sys, json, os

KEEP = '__KEEP__'
config_path = '/opt/risk-scanner/config/config.json'

with open(config_path) as f:
    cfg = json.load(f)

def env(key, fallback=''):
    return os.environ.get(key, fallback)

def set_unless_keep(obj, field, env_key):
    val = env(env_key)
    if val and val != KEEP:
        obj[field] = val

# Graph API
if 'graph_api' not in cfg:
    cfg['graph_api'] = {}
set_unless_keep(cfg['graph_api'], 'tenant_id',     'NEW_TENANT_ID')
set_unless_keep(cfg['graph_api'], 'client_id',     'NEW_CLIENT_ID')
set_unless_keep(cfg['graph_api'], 'client_secret', 'NEW_CLIENT_SECRET')

# Reporting
if 'reporting' not in cfg:
    cfg['reporting'] = {}
set_unless_keep(cfg['reporting'], 'sender_email', 'NEW_SENDER_EMAIL')
set_unless_keep(cfg['reporting'], 'report_to',    'NEW_REPORT_TO')
set_unless_keep(cfg['reporting'], 'client_name',  'NEW_CLIENT_NAME')
set_unless_keep(cfg['reporting'], 'site_name',    'NEW_SITE_NAME')

# Scanning
if 'scanning' not in cfg:
    cfg['scanning'] = {}
networks_raw = env('NEW_SCAN_NETWORKS')
if networks_raw:
    cfg['scanning']['networks'] = [n.strip() for n in networks_raw.split(',') if n.strip()]

# Hatz AI
if 'hatz_ai' not in cfg:
    cfg['hatz_ai'] = {}
hatz_enabled = env('NEW_HATZ_ENABLED', 'false').lower() == 'true'
cfg['hatz_ai']['enabled'] = hatz_enabled
if hatz_enabled:
    set_unless_keep(cfg['hatz_ai'], 'api_key', 'NEW_HATZ_API_KEY')
    set_unless_keep(cfg['hatz_ai'], 'model',   'NEW_HATZ_MODEL')

# Schedule
if 'schedule' not in cfg:
    cfg['schedule'] = {}
set_unless_keep(cfg['schedule'], 'scan_time',    'NEW_SCAN_TIME')
set_unless_keep(cfg['schedule'], 'report_day',   'NEW_REPORT_DAY')
set_unless_keep(cfg['schedule'], 'report_time',  'NEW_REPORT_TIME')

with open(config_path, 'w') as f:
    json.dump(cfg, f, indent=2)
    f.write('\n')

print("Configuration updated.")
PYEOF

echo -e "${GREEN}Config saved to ${CONFIG_FILE}${NC}"
echo ""

# ── Update systemd timer placeholders ─────────────────────────────────────────
echo "Updating systemd timer schedules..."

# Validate time format HH:MM
SCAN_HH_MM=$(echo "$SCAN_TIME" | grep -E '^([01][0-9]|2[0-3]):[0-5][0-9]$' || echo "")
REPORT_HH_MM=$(echo "$REPORT_TIME" | grep -E '^([01][0-9]|2[0-3]):[0-5][0-9]$' || echo "")

if [[ -z "$SCAN_HH_MM" ]]; then
    echo -e "${YELLOW}Warning:${NC} Invalid scan time format '${SCAN_TIME}'. Timer not updated."
else
    sed -i "s/__SCAN_TIME__/${SCAN_HH_MM}/g" /etc/systemd/system/risk-scanner-daily.timer 2>/dev/null || \
        echo -e "${YELLOW}  risk-scanner-daily.timer not found in /etc/systemd/system/. Install first.${NC}"
fi

if [[ -z "$REPORT_HH_MM" ]]; then
    echo -e "${YELLOW}Warning:${NC} Invalid report time format '${REPORT_TIME}'. Timer not updated."
else
    sed -i "s/__REPORT_DAY__/${REPORT_DAY}/g;s/__REPORT_TIME__/${REPORT_HH_MM}/g" \
        /etc/systemd/system/risk-scanner-report.timer 2>/dev/null || \
        echo -e "${YELLOW}  risk-scanner-report.timer not found in /etc/systemd/system/. Install first.${NC}"
fi

# ── Reload and restart timers ─────────────────────────────────────────────────
echo "Reloading systemd and restarting timers..."
systemctl daemon-reload 2>/dev/null || true

for TIMER in risk-scanner-daily.timer risk-scanner-report.timer; do
    if systemctl is-enabled --quiet "$TIMER" 2>/dev/null; then
        systemctl restart "$TIMER" && echo -e "  ${GREEN}Restarted${NC} ${TIMER}" || \
            echo -e "  ${YELLOW}Could not restart${NC} ${TIMER}"
    else
        echo -e "  ${YELLOW}Skipped${NC} ${TIMER} (not enabled — run installer to enable)"
    fi
done

echo ""
echo -e "${GREEN}${BOLD}Configuration update complete.${NC}"
echo "Credential profiles have been preserved."
