# Yeyland Wutani - Network Discovery Pi

**IT Consulting & Cybersecurity Services** | *Building Better Systems*

---

A headless Raspberry Pi tool for MSP sales engineers. Deploy on a customer LAN, receive an instant check-in email, then get a comprehensive branded network discovery report—all with no monitor, keyboard, or manual intervention required.

---

## What It Does

| Phase | Description |
|-------|-------------|
| **Check-In** | Emails the Pi's IP, MAC, subnet, gateway, and DNS within minutes of connecting |
| **Scan** | Full 17-phase network discovery: reconnaissance → host discovery → port scan → service enum → topology → security → WiFi → mDNS → UPnP/SSDP → DHCP → NTP → 802.1X/NAC → OSINT → SSL audit → backup/DR posture → EOL detection |
| **Report** | Professional HTML email report with Pacific Office Automation branding, device table, WiFi analysis, DHCP/NTP infrastructure, external attack surface, email security posture, SSL certificate health, backup & DR assessment, end-of-life inventory, and compressed CSV + JSON attachments (up to 25 MB) |

---

## Requirements

- Raspberry Pi (any model) running **Raspberry Pi OS** (Bullseye or later)
- DHCP-enabled customer LAN
- Microsoft 365 mailbox with an **Azure App Registration** (see [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md))
- Internet access during installation (for cloning this repo and installing packages)
- **Optional:** Built-in WiFi adapter (for WiFi network enumeration and channel analysis)

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
           └─ Send check-in email via Graph API

 └─▶ network-discovery.service
      └─▶ discovery-main.py
           ├─ Validate Graph API credentials
           ├─ Send "Scan Starting" notification
           ├─ Run network-scanner.py (17 phases)
           │   ├─ Phases 1–6: Host discovery, ports, services, security
           │   ├─ Phase 7:    WiFi enumeration + channel analysis
           │   ├─ Phase 8:    mDNS / Bonjour service discovery
           │   ├─ Phase 9:    UPnP / SSDP device discovery
           │   ├─ Phase 10:   DHCP scope analysis (rogue detection)
           │   ├─ Phase 11:   NTP server detection
           │   ├─ Phase 12:   802.1X / NAC detection
           │   ├─ Phase 13:   OSINT / external reconnaissance
           │   ├─ Phase 14:   SSL/TLS certificate health audit
           │   ├─ Phase 15:   Backup & DR posture inference
           │   └─ Phase 16:   End-of-life / end-of-support detection
           ├─ Build HTML report + compressed CSV/JSON (.gz)
           └─ Send report email via Graph API (up to 25 MB)
```

---

## Project Structure

```
/opt/network-discovery/          (install target)
├── bin/
│   ├── discovery-main.py        Main orchestration
│   ├── network-scanner.py       13-phase discovery engine
│   ├── graph-mailer.py          Graph API email sender (sendMail + upload session)
│   ├── initial-checkin.py       First-boot check-in
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
│   └── report_generator.py      HTML report builder
├── config/
│   ├── config.json              Active configuration (created by installer)
│   ├── config.json.template     Configuration template
│   └── .env.template            Environment variables template
├── systemd/
│   ├── initial-checkin.service
│   ├── network-discovery.service
│   ├── network-discovery-health.service
│   └── network-discovery-health.timer
├── logs/                        Log files
├── data/                        Scan results (JSON/CSV, gzipped)
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
| `reporting.company_name` | Pacific Office Automation Inc. | Report branding |
| `reporting.company_color` | #00A0D9 | Report accent color |
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

# Log file
tail -f /opt/network-discovery/logs/discovery.log
```

### Re-run initial check-in

```bash
sudo /opt/network-discovery/bin/reset-checkin.sh
sudo systemctl start initial-checkin.service
```

---

## Security Considerations

- Config file (`config.json`) is permission-restricted (mode `640`, readable only by the `network-discovery` service user and root)
- Client secret is stored in the config file—**never commit `config.json` to version control**
- The `network-discovery` system user has no login shell and no home directory
- Systemd service hardening: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, limited capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- Scanning is **non-intrusive** (no exploitation, no default-credential testing, observation only)
- WiFi scanning is **passive only** (no association or connection to discovered networks)
- DHCP analysis sends a single DISCOVER packet—does not disrupt existing leases
- Report attachments are gzip-compressed to reduce email size
- Email delivery supports up to 25 MB via Graph API chunked upload session
- OSINT lookups use only **free, public APIs** (Shodan InternetDB, RDAP, crt.sh)—no API keys stored or required
- OSINT queries are limited to the organization's own public IP and derived domains—no third-party reconnaissance
- DNS security checks query only public DNS records (MX, TXT for SPF/DKIM/DMARC)
- SSL certificate audit connects to internal HTTPS services to inspect certificates—**no data is exfiltrated**, only certificate metadata (CN, issuer, expiry, key size) is collected
- Backup/DR posture inference is **pure data analysis** of ports and banners already collected—no additional network traffic
- EOL detection uses an **embedded, curated database** — no external API calls, works fully offline
- Reports include a disclaimer noting authorized use
- All Graph API communication is over TLS
- All external OSINT queries are over HTTPS

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
