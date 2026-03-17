# Yeyland Wutani - Network Discovery Pi

**IT Consulting & Cybersecurity Services** | *Building Better Systems*

---

A headless Raspberry Pi tool for MSP sales engineers. Deploy on a customer LAN, receive an instant check-in email, then get a comprehensive branded network discovery report—all with no monitor, keyboard, or manual intervention required.

---

## What It Does

| Phase | Description |
|-------|-------------|
| **Check-In** | Emails the Pi's IP, MAC, subnet, gateway, DNS, and public WAN IP within minutes of connecting |
| **Scan** | Full 17-phase network discovery: reconnaissance → host discovery → port scan → service enum → topology → security → WiFi → mDNS → UPnP/SSDP → DHCP → NTP → 802.1X/NAC → OSINT → SSL audit → backup/DR posture → EOL detection → AD discovery |
| **HTML Report** | Professional HTML email with configurable client branding, device table, WiFi analysis, DHCP/NTP infrastructure, external attack surface, email security posture, SSL certificate health, backup & DR assessment, end-of-life inventory, AI-generated insights (Hatz AI), operational statistics with per-phase timing, and compressed CSV + JSON attachments (up to 25 MB) |
| **PDF Reports** | Three client-facing PDF reports generated on demand via `generate-report.py`: Summary Report, Technical Detail Report, and Product Recommendations |

---

## Requirements

- Raspberry Pi (any model) running **Raspberry Pi OS** (Bullseye or later)
- DHCP-enabled customer LAN
- Microsoft 365 mailbox with an **Azure App Registration** (see [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md))
- Internet access during installation (for cloning this repo and installing packages)
- **Optional:** Built-in WiFi adapter (for WiFi network enumeration and channel analysis)
- **Optional:** `reportlab` Python package (for PDF report generation — `pip install reportlab`)
- **Optional:** Hatz AI API key (for AI-generated insights in HTML and PDF reports)

---

## Quick Start

```bash
# On a fresh Raspberry Pi OS installation, open a terminal and run:
sudo bash -c "curl -sL https://raw.githubusercontent.com/the-last-one-left/YeylandWutani/main/Rasperry%20Pi%20Discovery%20Tool/install.sh | bash"
```

Or clone manually:

```bash
git clone --depth=1 --filter=blob:none --sparse https://github.com/the-last-one-left/YeylandWutani.git
cd YeylandWutani
git sparse-checkout set "Rasperry Pi Discovery Tool"
cd "Rasperry Pi Discovery Tool"
sudo bash install.sh
```

The installer will:
1. Install required system packages (`nmap`, `arp-scan`, `fping`, `iw`, `avahi-utils`, etc.)
2. Create a Python virtual environment with all dependencies
3. Set up systemd services for automatic boot operation
4. Walk you through the configuration wizard
5. Send a test email to confirm everything works

---

## How It Works

```
Boot
 └─▶ initial-checkin.service  (one-shot, runs once)
      └─▶ initial-checkin.py
           ├─ Detect network interfaces + gateway
           ├─ Resolve public WAN IP
           └─ Send check-in email via Graph API

 └─▶ network-discovery.service
      └─▶ discovery-main.py
           ├─ Log system diagnostics (OS, disk, features)
           ├─ Manage disk space (prune oldest archives if low)
           ├─ Validate Graph API credentials
           ├─ Send "Scan Starting" notification
           ├─ Run network-scanner.py (17 phases, each timed)
           │   ├─ Phases 1–6:  Host discovery, ports, services, security
           │   ├─ Phase 7:     WiFi enumeration + channel analysis
           │   ├─ Phase 8:     mDNS / Bonjour service discovery
           │   ├─ Phase 9:     UPnP / SSDP device discovery
           │   ├─ Phase 10:    DHCP scope analysis (rogue detection)
           │   ├─ Phase 11:    NTP server detection
           │   ├─ Phase 12:    802.1X / NAC detection
           │   ├─ Phase 13:    OSINT / external reconnaissance
           │   ├─ Phase 14:    SSL/TLS certificate health audit
           │   ├─ Phase 15:    Backup & DR posture inference
           │   ├─ Phase 16:    End-of-life / end-of-support detection
           │   └─ Phase 17:    Active Directory discovery (if domain detected)
           ├─ Request Hatz AI insights (if API key configured)
           ├─ Store AI insights in scan JSON for PDF report consumers
           ├─ Build HTML report (with AI insights + operational statistics)
           ├─ Compress CSV/JSON (.gz) for attachment
           ├─ Send report email via Graph API (up to 25 MB)
           └─ Cleanup: remove uncompressed intermediaries on send success

 └─▶ generate-report.py  (on-demand CLI — run after scan)
      ├─ Load scan JSON (latest or specified)
      ├─ Use cached Hatz AI insights or request fresh (if API key set)
      ├─ Summary Report PDF   → executive overview, risk score, key findings, AI insights page
      ├─ Detail Report PDF    → technical deep-dive, per-device findings, CVE details
      └─ Product Recommendations PDF → hardware/software recommendations with cloud migration analysis
```

---

## Project Structure

```
/opt/network-discovery/          (install target)
├── bin/
│   ├── discovery-main.py        Main orchestration (disk mgmt, timing, cleanup, AI)
│   ├── network-scanner.py       17-phase discovery engine
│   ├── generate-report.py       On-demand PDF report generator CLI
│   ├── graph-mailer.py          Graph API email sender (sendMail + upload session)
│   ├── initial-checkin.py       First-boot check-in (WAN + LAN IP)
│   ├── health-check.py          Weekly health report
│   ├── self-update.sh           Auto-update from GitHub
│   ├── test-email.py            Email delivery test
│   ├── manual-scan.sh           Trigger manual scan
│   ├── view-last-report.sh      View last results in terminal
│   ├── update-config.sh         Reconfiguration wizard
│   └── reset-checkin.sh         Reset check-in flag
├── lib/
│   ├── graph_auth.py            OAuth2 authentication
│   ├── network_utils.py         Network/WiFi helpers + OUI lookup
│   ├── report_generator.py      HTML report builder (incl. AI insights + ops stats)
│   ├── hatz_ai.py               Hatz AI API integration (AI-generated security insights)
│   ├── client_report.py         PDF report builder: Summary + Detail reports
│   ├── product_recommendations.py  PDF report builder: Product Recommendations + cloud migration
│   ├── ad_discovery.py          Active Directory / LDAP discovery module
│   └── product_catalog.json     Hardware/software product catalog (Dell 16th-gen, Fortinet, M365)
├── config/
│   ├── config.json              Active configuration (created by installer)
│   ├── config.json.template     Configuration template
│   └── .env.template            Environment variables template
├── data/
│   └── eol-database.json        Curated EOL database (auto-updated via git)
├── systemd/
│   ├── initial-checkin.service
│   ├── network-discovery.service
│   ├── network-discovery-health.service
│   └── network-discovery-health.timer
├── logs/                        Rotating log files (10 MB, 5 backups)
├── install.sh                   Installer
└── uninstall.sh                 Uninstaller
```

---

## Configuration

All settings live in `/opt/network-discovery/config/config.json`.

| Setting | Default | Description |
|---------|---------|-------------|
| `graph_api.tenant_id` | — | Azure tenant (directory) ID |
| `graph_api.client_id` | — | App registration client ID |
| `graph_api.client_secret` | — | App registration secret |
| `graph_api.from_email` | — | M365 mailbox to send from |
| `graph_api.to_email` | — | Recipient for reports |
| `hatz_ai.api_key` | — | Hatz AI API key for AI-generated security insights (optional) |
| `network_discovery.scan_timeout` | 600 | Max scan time (seconds) |
| `network_discovery.max_threads` | 50 | Parallel scanning threads |
| `network_discovery.port_scan_top_ports` | 100 | nmap top-N ports |
| `network_discovery.subnet_labels` | {} | CIDR → label mapping (e.g. `{"10.0.1.0/24": "Server VLAN"}`) |
| `network_discovery.enable_wifi_scan` | true | Passive WiFi enumeration + channel analysis |
| `network_discovery.wifi_interface` | auto | WiFi interface (auto-detect or e.g. `wlan0`) |
| `network_discovery.enable_mdns_discovery` | true | mDNS / Bonjour service discovery |
| `network_discovery.enable_ssdp_discovery` | true | UPnP / SSDP device discovery |
| `network_discovery.enable_dhcp_analysis` | true | DHCP scope analysis + rogue detection |
| `network_discovery.enable_ntp_detection` | true | NTP server detection |
| `network_discovery.enable_nac_detection` | true | 802.1X / NAC detection |
| `network_discovery.enable_osint` | true | OSINT / external reconnaissance (WHOIS, Shodan, DNS, crt.sh) |
| `network_discovery.osint_timeout` | 8 | Per-query HTTP timeout for OSINT lookups (seconds) |
| `network_discovery.enable_shodan_internetdb` | true | Shodan InternetDB external attack surface (free, no API key) |
| `network_discovery.enable_crtsh_lookup` | true | crt.sh certificate transparency subdomain discovery |
| `network_discovery.enable_dns_security` | true | MX / SPF / DKIM / DMARC email security analysis |
| `network_discovery.enable_whois_lookup` | true | WHOIS / RDAP lookup on public IP |
| `network_discovery.enable_ssl_audit` | true | SSL/TLS certificate health audit (expiry, self-signed, weak keys) |
| `network_discovery.ssl_audit_timeout` | 5 | Per-host TLS connection timeout (seconds) |
| `network_discovery.ssl_cert_warning_days` | 30 | Warn when certificate expires within N days |
| `network_discovery.ssl_cert_critical_days` | 7 | Critical alert when certificate expires within N days |
| `network_discovery.enable_backup_posture` | true | Backup & DR posture inference (Veeam, Commvault, Acronis, NAS, etc.) |
| `network_discovery.enable_eol_detection` | true | End-of-life / end-of-support detection against curated EOL database |
| `network_discovery.eol_warning_months` | 12 | Flag products approaching EOL within N months |
| `reporting.company_name` | Yeyland Wutani LLC | Assessor brand name shown in report header, footer, and PDFs |
| `reporting.company_color` | #FF6600 | Report accent color (customize to match assessor branding) |
| `reporting.tagline` | Building Better Systems | Assessor tagline shown on PDF covers |
| `reporting.client_name` | *(inferred)* | Override the client/prospect name shown on PDF reports |
| `system.device_name` | NetDiscovery-Pi | Device identifier in emails |
| `system.min_free_disk_mb` | 200 | Prune oldest scan archives when free disk drops below N MB |

To update configuration: `sudo /opt/network-discovery/bin/update-config.sh`

---

## Usage

### Automatic (on boot)

Services start automatically. Just plug the Pi into the network and wait for emails.

### Manual scan

```bash
sudo /opt/network-discovery/bin/manual-scan.sh
```

### Generate PDF reports

PDF reports are generated from saved scan data using `generate-report.py`. This can be run any time after a scan completes — on the Pi itself, or by copying the scan JSON to any machine with `reportlab` installed.

```bash
# Generate all three reports from the most recent scan
sudo /opt/network-discovery/venv/bin/python generate-report.py

# Generate from a specific scan file with client name and brand color overrides
python generate-report.py \
    --json /opt/network-discovery/data/scan_20260316.json.gz \
    --client-name "Acme Corp" \
    --color "#00A0D9"

# Summary and Detail reports only (skip product recommendations)
python generate-report.py --summary --detail --output /tmp/reports/

# Product Recommendations only
python generate-report.py --products --output /tmp/reports/
```

**PDF report types:**

| Report | Contents |
|--------|----------|
| **Summary Report** | Executive cover with risk score gauge, methodology overview, key finding pages, device inventory table, AI Insights page (when Hatz AI configured), final observations with AI-generated recommended actions |
| **Detail Report** | Technical deep-dive with per-device findings, open ports, CVE matches, SSL details, EOL inventory |
| **Product Recommendations** | Environment-sized hardware/software recommendations (firewall, switches, APs, servers, security software) plus cloud migration analysis — branded for the client, powered by Yeyland Wutani |

The `--client-name` flag sets the **prospect** name (shown as "Prepared for" on the cover). The assessor brand (`reporting.company_name` in config) is unaffected.

If a Hatz AI API key is configured, the summary PDF automatically includes:
- An **AI Insights page** with AI-analyzed key findings, prioritized remediation steps, and positive observations specific to the scanned environment
- **AI-generated recommended actions** on the Final Observations page (replaces the generic static bullet list)

### View last results

```bash
/opt/network-discovery/bin/view-last-report.sh
```

### Test email delivery

```bash
/opt/network-discovery/venv/bin/python3 /opt/network-discovery/bin/test-email.py
```

### Monitor logs

```bash
# Systemd journal (real-time)
sudo journalctl -u nd-discovery -f
sudo journalctl -u nd-checkin -f

# Discovery log (detailed per-phase timing, subprocess results, errors)
tail -f /opt/network-discovery/logs/discovery.log

# Check-in log
tail -f /opt/network-discovery/logs/initial-checkin.log

# Rotated logs (auto-managed: 10 MB × 5 backups for discovery, 5 MB × 3 for check-in)
ls -la /opt/network-discovery/logs/
```

Logs include system diagnostics at startup (OS, Python version, disk space, enabled features), per-phase timing summaries, all subprocess results, HTTP request/response durations, and full stack traces on errors. The HTML report also includes an **Operational Statistics** section showing phase-by-phase timing and status.

### Re-run initial check-in

```bash
sudo /opt/network-discovery/bin/reset-checkin.sh
sudo systemctl start initial-checkin.service
```

---

## PDF Product Recommendations

The Product Recommendations PDF is sized and selected automatically based on the scanned environment:

| Category | Logic |
|----------|-------|
| **Firewall** | Sized by device count: SOHO / SMB / mid-market tiers |
| **Switches** | Recommended per subnet; PoE budget based on AP and device count |
| **Access Points** | Recommended based on wireless client count |
| **Servers** | VM-aware: detects virtualized environments (VMware/Hyper-V MAC OUIs, WMI data) and consolidates to 1 physical host per 5 VMs; recommends Dell 16th-gen DDR5 hardware |
| **Security Software** | EDR/XDR, MFA, email security sized by user count |
| **Cloud Migration** | AI-scored recommendation: evaluates user count, server age, Exchange presence, internet quality, and on-prem anchors (SQL, LOB apps) to recommend M365 Business Basic/Standard/Premium, Azure Virtual Desktop, or on-prem retention |

**Current server catalog (Dell PowerEdge 16th Gen, DDR5):**

| Role | Model | Form Factor |
|------|-------|-------------|
| Entry tower | T160 | Tower |
| Mid tower | T360 | Tower |
| Entry rack | R360 | 1U rack |
| Mid rack / hypervisor | R470 | 1U rack |
| Dual-socket / high density | R670 | 2U rack |

The report is MSP-agnostic: all client-facing text uses the `reporting.company_name` from config. The "Powered by Yeyland Wutani" footer is intentional and always present.

---

## Hatz AI Integration

When `hatz_ai.api_key` is set in `config.json`, the tool calls the Hatz AI API (`ai.hatz.ai/v1`) after each scan to generate environment-specific security insights.

AI insights are:
- **Stored in the scan JSON** (`scan_results["ai_insights"]`) for use by any downstream consumer
- **Embedded in the HTML email report** as a highlighted AI Insights section
- **Used in the Summary PDF** — a dedicated AI Insights page plus AI-generated recommended actions on the Final Observations page

When generating PDFs manually via `generate-report.py`, if the scan file already contains cached AI insights they are used directly. If not (e.g. for older scan files), a fresh API call is made automatically if the key is configured.

The AI analysis references actual IPs, device types, and service names from the scan data — not generic advice.

---

## Security Considerations

- Config file (`config.json`) is permission-restricted (mode `640`, readable only by the `network-discovery` service user and root)
- Client secret is stored in the config file — **never commit `config.json` to version control**
- The `network-discovery` system user has no login shell and no home directory
- Systemd service hardening: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, limited capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- Scanning is **non-intrusive** (no exploitation, no default-credential testing, observation only)
- WiFi scanning is **passive only** (no association or connection to discovered networks)
- DHCP analysis sends a single DISCOVER packet — does not disrupt existing leases
- Report attachments are gzip-compressed to reduce email size
- Email delivery supports up to 25 MB via Graph API chunked upload session
- OSINT lookups use only **free, public APIs** (Shodan InternetDB, RDAP, crt.sh) — no API keys stored or required
- OSINT queries are limited to the organization's own public IP and derived domains — no third-party reconnaissance
- DNS security checks query only public DNS records (MX, TXT for SPF/DKIM/DMARC)
- SSL certificate audit connects to internal HTTPS services to inspect certificates — **no data is exfiltrated**, only certificate metadata (CN, issuer, expiry, key size) is collected
- Backup/DR posture inference is **pure data analysis** of ports and banners already collected — no additional network traffic
- EOL detection uses a **curated JSON database** (`data/eol-database.json`) auto-distributed via `self-update.sh` — no external API calls, works fully offline with a minimal embedded fallback
- Hatz AI integration sends only anonymized scan summary data (no hostnames, no personally identifiable information beyond IP addresses) over HTTPS
- Reports include a disclaimer noting authorized use
- All Graph API communication is over TLS
- All external OSINT queries are over HTTPS

---

## Self-Maintenance

The Pi manages its own storage and stays up to date automatically:

| Feature | How It Works |
|---------|--------------|
| **Self-update** | On every check-in, `self-update.sh` runs `git pull --ff-only` to pick up code changes and updated EOL database entries from GitHub |
| **Disk management** | On startup, checks free disk space against `min_free_disk_mb` (default 200 MB). If low, prunes oldest `.gz` scan archives one at a time until the threshold is met |
| **Post-send cleanup** | After a successful email send, uncompressed intermediary files (`.csv`, `.json`) are deleted — the compressed `.gz` archives are retained for local reference |
| **Log rotation** | `RotatingFileHandler` keeps logs bounded: discovery log at 10 MB × 5 backups, check-in log at 5 MB × 3 backups |
| **Operational statistics** | Every scan records per-phase timing and status. The HTML report includes an Operational Statistics section with a visual timing breakdown, and the log file prints a structured timing summary table |

If an email send **fails**, uncompressed files are preserved so nothing is lost.

---

## Graph API Setup

See [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md) for step-by-step instructions on creating the Azure App Registration.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

---

## Uninstall

```bash
sudo /opt/network-discovery/uninstall.sh
```

---

## License

See repository root LICENSE file.

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
*Developed through real-world MSP field engagements.*
*For authorized use only. Always obtain permission before scanning customer networks.*
