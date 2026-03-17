#!/usr/bin/env bash
# Yeyland Wutani Risk Scanner - View Latest Scan Results
set -euo pipefail

INSTALL_DIR="/opt/risk-scanner"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python"
HISTORY_DIR="${INSTALL_DIR}/data/history"
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
    echo "║     Yeyland Wutani Risk Scanner — View Results       ║"
    echo "║           Building Better Systems                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [--host IP_OR_HOSTNAME] [--file SCAN_FILE]"
    echo ""
    echo "  --host IP    Filter output to a specific host"
    echo "  --file PATH  Use a specific scan file (default: latest)"
    echo ""
    exit 0
}

# Must run as root or risk-scanner user
if [[ $EUID -ne 0 ]] && [[ "$(id -un)" != "$SERVICE_USER" ]]; then
    echo -e "${RED}Error:${NC} This script must be run as root or ${SERVICE_USER}." >&2
    exit 1
fi

# Parse args
HOST_IP=""
SCAN_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            if [[ -z "${2:-}" ]]; then
                echo -e "${RED}Error:${NC} --host requires an IP or hostname." >&2
                exit 1
            fi
            HOST_IP="$2"
            shift 2
            ;;
        --file)
            if [[ -z "${2:-}" ]]; then
                echo -e "${RED}Error:${NC} --file requires a path." >&2
                exit 1
            fi
            SCAN_FILE="$2"
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

print_header

# Find latest scan file if not specified
if [[ -z "$SCAN_FILE" ]]; then
    if [[ ! -d "$HISTORY_DIR" ]]; then
        echo -e "${RED}Error:${NC} History directory not found: ${HISTORY_DIR}"
        echo "No scans have been run yet. Use: sudo manual-scan.sh"
        exit 1
    fi

    LATEST_SCAN=$(ls -t "${HISTORY_DIR}"/*.json.gz 2>/dev/null | head -1 || true)

    if [[ -z "$LATEST_SCAN" ]]; then
        echo -e "${YELLOW}No scan results found in ${HISTORY_DIR}.${NC}"
        echo "Run a scan first with: sudo manual-scan.sh"
        exit 1
    fi
else
    LATEST_SCAN="$SCAN_FILE"
fi

if [[ ! -f "$LATEST_SCAN" ]]; then
    echo -e "${RED}Error:${NC} Scan file not found: ${LATEST_SCAN}" >&2
    exit 1
fi

echo -e "Scan file: ${YELLOW}${LATEST_SCAN}${NC}"
[[ -n "$HOST_IP" ]] && echo -e "Host filter: ${YELLOW}${HOST_IP}${NC}"
echo ""

# Run Python display as service user
RESULT=0
sudo -u "$SERVICE_USER" "$VENV_PYTHON" - <<PYEOF || RESULT=$?
import sys, json, gzip, os

sys.path.insert(0, '/opt/risk-scanner/lib')

scan_file = '${LATEST_SCAN}'
host_filter = '${HOST_IP}'

try:
    with gzip.open(scan_file) as f:
        results = json.load(f)
except Exception as e:
    print(f"Failed to read scan file: {e}", file=sys.stderr)
    sys.exit(1)

hosts   = results.get('hosts', [])
risk    = results.get('risk', {})
summary = results.get('summary', {})

print(f"\n=== RISK SCANNER — Latest Scan: {results.get('scan_start','?')[:19]} ===")
print(f"Environment Risk Score: {risk.get('score', '?')}/100  [{risk.get('level', '?')}]")
print(
    f"Total hosts: {summary.get('total_hosts','?')}  "
    f"CVEs matched: {summary.get('total_cves','?')}  "
    f"KEV matches: {summary.get('kev_matches','?')}"
)

if host_filter:
    # Filter by IP or hostname
    filtered = [
        h for h in hosts
        if h.get('ip') == host_filter or h.get('hostname','').lower() == host_filter.lower()
    ]
    if not filtered:
        print(f"\nNo host found matching: {host_filter}")
        sys.exit(1)
    h = filtered[0]
    print(f"\nHost:       {h.get('ip','?')} ({h.get('hostname','unknown')})")
    print(f"Category:   {h.get('category','?')}")
    print(f"OS Guess:   {h.get('os_guess','?')}")
    print(f"Risk Score: {h.get('risk_score','?')}/100  [{h.get('risk_level','?')}]")

    open_ports = h.get('open_ports', [])
    if open_ports:
        print(f"\nOpen Ports ({len(open_ports)}):")
        for p in open_ports[:30]:
            svc = p.get('service','')
            ver = p.get('version','')
            print(f"  {p.get('port','?')}/{p.get('protocol','tcp'):<4}  {svc:<20} {ver}")

    cves = h.get('cve_matches', [])
    if cves:
        print(f"\nCVEs ({len(cves)} matched):")
        for v in cves[:20]:
            kev = ' [KEV]' if v.get('kev') else ''
            cvss = v.get('cvss_v3_score', v.get('cvss_score', '?'))
            desc = (v.get('description') or '')[:80]
            print(f"  {v.get('cve_id','?'):<20}{kev:<7} CVSS:{cvss:<5} {desc}")
        if len(cves) > 20:
            print(f"  ... and {len(cves) - 20} more.")

    flags = h.get('security_flags', [])
    if flags:
        print(f"\nSecurity Findings ({len(flags)}):")
        for flag in flags[:15]:
            sev = flag.get('severity', '?')
            desc = (flag.get('description') or '')
            print(f"  [{sev:<8}] {desc}")
        if len(flags) > 15:
            print(f"  ... and {len(flags) - 15} more.")
else:
    # Summary table
    print()
    print(f"{'IP':<16} {'Hostname':<25} {'Category':<15} {'Risk':<12} {'Score':<6} {'CVEs':<6} {'KEV'}")
    print("-" * 88)
    sorted_hosts = sorted(hosts, key=lambda x: x.get('risk_score', 0), reverse=True)
    for h in sorted_hosts[:50]:
        cves     = h.get('cve_matches', [])
        kev_cnt  = sum(1 for v in cves if v.get('kev'))
        risk_lvl = h.get('risk_level', '?')
        score    = h.get('risk_score', '?')
        print(
            f"{h.get('ip','?'):<16} "
            f"{(h.get('hostname') or '?'):<25} "
            f"{(h.get('category') or '?'):<15} "
            f"{risk_lvl:<12} "
            f"{score:<6} "
            f"{len(cves):<6} "
            f"{kev_cnt}"
        )
    if len(hosts) > 50:
        print(f"\n  ... showing 50 of {len(hosts)} hosts. Use --host to inspect individual hosts.")
PYEOF

if [[ $RESULT -ne 0 ]]; then
    echo ""
    echo -e "${RED}Failed to display results.${NC}"
    echo "Check the scan file or run a new scan with: sudo manual-scan.sh"
    exit 1
fi
