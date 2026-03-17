# Yeyland Wutani — Raspberry Pi Risk Scanner

**Yeyland Wutani LLC** | *Building Better Systems*

---

> Authorized credentialed vulnerability scanner for managed network environments.
> For authorized use only. Always obtain written customer permission before deploying.

---

A headless Raspberry Pi (or VM) left permanently on a client network. Runs daily credentialed scans against Linux, Windows, and network equipment — correlates findings against NVD, CISA KEV, and OSV vulnerability databases — tracks risk posture over time — and delivers weekly Executive Summary and Technical Detail PDF reports via Microsoft 365 Graph API.

---

## What It Does

Daily credentialed scans provide visibility far beyond passive network discovery:

- **Daily credentialed scans** — SSH (Linux/Unix), WMI/WinRM (Windows), SNMP v2c/v3 (network equipment)
- **CVE correlation** — cross-references installed software and firmware versions against NVD, CISA Known Exploited Vulnerabilities (KEV), and OSV databases
- **Risk scoring 0–100** — per-host and environment-wide scores weighted by finding severity; CRITICAL/HIGH/MEDIUM/LOW bands
- **Delta tracking** — scan-to-scan diff showing new findings, resolved items, recurring issues, and newly matched KEV CVEs
- **Weekly PDF reports** — Executive Summary (non-technical leadership) and Technical Detail (IT/security team), delivered via Graph API
- **HTML email digest** — inline weekly summary with risk score, delta callouts, KEV alerts, and top findings table
- **Hatz AI insights** — AI-generated executive narrative and prioritized remediation steps when Hatz AI API key is configured
- **Configuration audit** — SSH hardening checks, Windows Firewall state, antivirus coverage, SMB share exposure, patch currency
- **Self-maintenance** — daily vuln DB updates, automatic log rotation, disk space management, self-update via GitHub

---

## How It Differs From the Discovery Tool

Both tools are deployed by Yeyland Wutani on client networks, but they serve different purposes:

| Capability | Discovery Tool | Risk Scanner |
|---|---|---|
| **Primary purpose** | Network mapping / asset inventory | Vulnerability assessment / risk scoring |
| **Credentials required** | No — passive/unauthenticated | Yes — SSH, WMI/WinRM, SNMP |
| **Scan frequency** | One-shot (or manual) | Daily automated scans |
| **CVE correlation** | No | Yes — NVD + KEV + OSV |
| **Risk scoring** | Basic EOL/exposure flags | Full 0–100 weighted risk score |
| **Delta tracking** | No | Yes — new/resolved/recurring findings |
| **Report types** | HTML email + 3 PDF types (Discovery, Detail, Products) | HTML digest + Executive PDF + Technical PDF |
| **Install path** | `/opt/network-discovery/` | `/opt/risk-scanner/` |
| **Service user** | `network-discovery` | `risk-scanner` |
| **Typical deployment** | Temporary (leave for a day, collect report) | Permanent (ongoing managed service) |
| **Best for** | Sales engineering, initial assessment | Ongoing MSP monitoring, compliance evidence |

Both tools can coexist on the same device and share the same Azure App Registration.

---

## Requirements

### Hardware

- **Raspberry Pi 4** (4 GB RAM recommended) or Pi 5; Pi 3B+ will work for smaller networks
- 16 GB+ storage (32 GB recommended — vuln DB takes ~400 MB; scan history grows over time)
- Wired Ethernet connection (recommended over WiFi for reliability)
- Or any Linux VM with equivalent resources

### Operating System

- Raspberry Pi OS Lite (64-bit, Bookworm or later)
- Ubuntu 22.04 LTS / 24.04 LTS
- Debian 12

### Network

- Wired connection with DHCP
- Routable to all target subnets (VLANs must be reachable from the scanner's IP)
- Internet access during installation and for daily vuln DB updates
- Outbound HTTPS (443) to Microsoft Graph API and NVD/CISA/OSV APIs

### Microsoft 365

- Azure AD App Registration with `Mail.Send` application permission
- Admin consent granted for the permission
- A licensed or shared mailbox as the `from_email` sender
- See [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md) for step-by-step setup

### Python and System Packages

- Python 3.11 or later (installed automatically by the installer)
- System packages installed by the installer:
  - `nmap`, `arp-scan`, `fping` — host and port scanning
  - `sshpass` — SSH credentialed scanning
  - `snmp`, `snmp-mibs-downloader` — SNMP scanning
  - `openssl` — certificate inspection
  - `curl`, `jq`, `git` — API calls and self-update
  - `python3-venv`, `python3-pip`

---

## Quick Start / Installation

On a fresh Raspberry Pi OS or Ubuntu installation:

```bash
sudo bash -c "curl -sL https://raw.githubusercontent.com/the-last-one-left/YeylandWutani/main/Rasperry%20Pi%20Risk%20Scanner%20Tool/install.sh | bash"
```

Or clone manually and run the installer:

```bash
git clone --depth=1 --filter=blob:none --sparse https://github.com/the-last-one-left/YeylandWutani.git
cd YeylandWutani
git sparse-checkout set "Rasperry Pi Risk Scanner Tool"
cd "Rasperry Pi Risk Scanner Tool"
sudo bash install.sh
```

The installer will:

1. Install all required system packages
2. Create the `risk-scanner` service user (no shell, no home directory)
3. Create a Python virtual environment with all dependencies
4. Walk you through the configuration wizard (Graph API credentials, scan schedule, reporting options)
5. Prompt for at least one credential profile (SSH, WMI/WinRM, or SNMP)
6. Seed the vulnerability database (NVD + KEV + OSV) — this may take 10–60 minutes depending on whether an NVD API key is provided
7. Install and enable all systemd services and timers
8. Send a test check-in email to confirm everything works
9. Optionally run an initial scan immediately

---

## Architecture Diagram

```
/opt/risk-scanner/                   (install target)
├── bin/
│   ├── risk-scanner-main.py         Main orchestration (lock, disk, AI, email)
│   ├── scan-engine.py               Credentialed 11-phase scan engine
│   ├── generate-report.py           On-demand PDF/HTML report generator CLI
│   ├── update-vuln-db.py            CVE/KEV/OSV database updater
│   ├── initial-checkin.py           First-boot check-in email
│   ├── manual-scan.sh               Trigger ad-hoc scan
│   ├── manual-report.sh             Generate reports from latest scan
│   ├── add-credential.sh            Credential wizard (add/update profiles)
│   ├── test-credential.sh           Test a stored credential against a host
│   ├── view-risks.sh                Terminal risk summary from last scan
│   ├── update-config.sh             Reconfiguration wizard
│   └── self-update.sh               Git pull + restart services
├── lib/
│   ├── graph_auth.py                OAuth2 MSAL client credentials
│   ├── graph_mailer.py              Graph API email sender
│   ├── network_utils.py             IP/MAC/OUI/interface helpers
│   ├── credential_store.py          Encrypted credential profiles
│   ├── ssh_scanner.py               Credentialed SSH host interrogation
│   ├── wmi_scanner.py               Credentialed Windows WMI/WinRM interrogation
│   ├── snmp_scanner.py              SNMP v1/v2c/v3 network equipment audit
│   ├── vuln_db.py                   Local NVD/KEV/OSV cache + CVSS scoring
│   ├── risk_scorer.py               Per-host + environment risk scoring
│   ├── delta_tracker.py             Scan-to-scan diff engine
│   ├── hatz_ai.py                   Hatz AI API integration
│   ├── report_generator.py          HTML email report builder
│   ├── executive_report.py          Executive Summary PDF builder
│   └── detail_report.py             Technical Detail PDF builder
├── config/
│   ├── config.json                  Active configuration (created by installer)
│   ├── config.json.template         Configuration template
│   └── credentials.enc              AES-256 encrypted credential store
├── data/
│   ├── vuln-db/
│   │   ├── nvd-cache.json           NVD CVE cache (auto-updated daily)
│   │   ├── kev-catalog.json         CISA Known Exploited Vulnerabilities
│   │   └── osv-cache.json           OSV open-source vulnerability cache
│   ├── history/
│   │   └── scan_YYYYMMDD_HHMMSS.json.gz   Daily scan archives
│   └── .scanner.lock                Prevents concurrent scan runs
├── systemd/
│   ├── risk-scanner-checkin.service
│   ├── risk-scanner-daily.service
│   ├── risk-scanner-daily.timer     (daily at configurable time, default 02:00)
│   ├── risk-scanner-report.service
│   └── risk-scanner-report.timer    (weekly, configurable day/time, default Mon 06:00)
├── logs/
│   ├── risk-scanner.log             Rotating 10 MB x 5 backups
│   └── initial-checkin.log          Rotating 5 MB x 3 backups
├── install.sh
└── uninstall.sh
```

---

## Configuration Reference

All settings live in `/opt/risk-scanner/config/config.json`. Run `sudo /opt/risk-scanner/bin/update-config.sh` to reconfigure interactively.

| Key | Type | Default | Description |
|---|---|---|---|
| `system.device_name` | string | `RiskScanner-Pi` | Device identifier shown in emails |
| `system.log_level` | string | `INFO` | Logging verbosity: DEBUG / INFO / WARNING / ERROR |
| `system.min_free_disk_mb` | int | `500` | Prune oldest scan archives when free disk drops below this threshold |
| `graph_api.tenant_id` | string | — | Azure tenant (directory) ID |
| `graph_api.client_id` | string | — | App registration client ID |
| `graph_api.client_secret` | string | — | App registration client secret |
| `graph_api.from_email` | string | — | M365 mailbox to send reports from |
| `graph_api.to_email` | string | — | Primary recipient for all reports |
| `graph_api.cc_emails` | array | `[]` | Optional additional recipients |
| `hatz_ai.api_key` | string | — | Hatz AI API key for AI-generated insights (optional) |
| `hatz_ai.enable_per_host_narrative` | bool | `false` | Generate AI narrative for each high-risk host in detail PDF |
| `hatz_ai.max_hosts_for_narrative` | int | `20` | Cap on per-host AI calls per scan |
| `scan_schedule.daily_scan_time` | string | `02:00` | Daily scan start time (HH:MM, 24-hour local time) |
| `scan_schedule.weekly_report_day` | string | `Monday` | Day of week for weekly report delivery |
| `scan_schedule.weekly_report_time` | string | `06:00` | Time for weekly report delivery |
| `scan_schedule.scan_on_install` | bool | `true` | Run an initial scan immediately after install |
| `scan.scan_timeout` | int | `3600` | Max scan duration in seconds (3600 = 1 hour) |
| `scan.max_threads` | int | `30` | Parallel scanning threads |
| `scan.port_scan_top_ports` | int | `1000` | nmap top-N ports to scan |
| `scan.port_scan_full` | bool | `false` | Enable full 65535-port scan (slow — adds 30–90 min) |
| `scan.subnet_labels` | object | `{}` | CIDR to label mapping, e.g. `{"10.0.1.0/24": "Server VLAN"}` |
| `scan.excluded_hosts` | array | `[]` | IPs or CIDRs to exclude from all scan phases |
| `scan.enable_ssh_scan` | bool | `true` | Enable credentialed SSH scanning |
| `scan.enable_wmi_scan` | bool | `true` | Enable credentialed WMI/WinRM scanning |
| `scan.enable_snmp_scan` | bool | `true` | Enable SNMP v2c/v3 scanning |
| `scan.enable_ssl_audit` | bool | `true` | Enable SSL/TLS certificate audit |
| `scan.enable_smb_audit` | bool | `true` | Enable SMB security checks via nmap NSE |
| `scan.enable_nse_vulners` | bool | `true` | Enable nmap vulners/vulscan NSE scripts |
| `scan.enable_cve_correlation` | bool | `true` | Enable CVE correlation against local vuln DB |
| `scan.enable_delta_tracking` | bool | `true` | Enable scan-to-scan delta analysis |
| `scan.ssh_timeout` | int | `15` | SSH connection and per-command timeout (seconds) |
| `scan.wmi_timeout` | int | `30` | WMI/WinRM per-query timeout (seconds) |
| `scan.snmp_timeout` | int | `5` | SNMP per-query timeout (seconds) |
| `vulnerability.nvd_api_key` | string | — | NVD API key for faster DB updates (free at nvd.nist.gov/developers) |
| `vulnerability.auto_update_vuln_db` | bool | `true` | Automatically update CVE DB before each daily scan |
| `vulnerability.vuln_db_update_interval_days` | int | `1` | How often to refresh the CVE DB |
| `vulnerability.vuln_db_max_age_years` | int | `5` | Only cache CVEs published within this many years |
| `vulnerability.cvss_critical_threshold` | float | `9.0` | CVSS score threshold for CRITICAL classification |
| `vulnerability.cvss_high_threshold` | float | `7.0` | CVSS score threshold for HIGH classification |
| `vulnerability.cvss_medium_threshold` | float | `4.0` | CVSS score threshold for MEDIUM classification |
| `vulnerability.prioritize_kev` | bool | `true` | Always surface CISA KEV CVEs at the top of findings |
| `vulnerability.max_cves_per_host` | int | `50` | Cap on CVE entries stored per host |
| `reporting.company_name` | string | `Yeyland Wutani LLC` | Assessor name on PDF covers and report headers |
| `reporting.company_color` | string | `#FF6600` | PDF accent color |
| `reporting.tagline` | string | `Building Better Systems` | Assessor tagline on PDF covers |
| `reporting.client_name` | string | — | Client/prospect name shown as "Prepared for" on PDF covers |
| `reporting.include_executive_pdf` | bool | `true` | Attach Executive Summary PDF to weekly email |
| `reporting.include_detail_pdf` | bool | `true` | Attach Technical Detail PDF to weekly email |
| `reporting.risk_score_history_weeks` | int | `12` | Weeks of risk score history shown in trend chart |

---

## Credential Profile Setup

Credentials are stored in `credentials.enc` — AES-256 encrypted using a key derived from the device's `/etc/machine-id`. Credentials are machine-bound and cannot be transferred to another device.

### Adding Credentials

```bash
sudo /opt/risk-scanner/bin/add-credential.sh
```

The wizard prompts for credential type, scope (global / subnet-specific / host-specific), and credentials. Run it once per profile. Testing is done automatically on completion.

### SSH Credentials (Linux/Unix hosts)

**Password-based** (simpler, suitable for most environments):

```bash
# The add-credential.sh wizard handles this interactively.
# Ensure the account can sudo without a password for full package enumeration:
echo "scanuser ALL=(ALL) NOPASSWD: /usr/bin/dpkg, /usr/bin/rpm, /usr/bin/apt" \
  | sudo tee /etc/sudoers.d/risk-scanner-readonly
```

**Key-based** (recommended for production):

```bash
# Generate a dedicated Ed25519 key pair on the scanner Pi:
sudo -u risk-scanner ssh-keygen -t ed25519 -f /opt/risk-scanner/config/scanner_ed25519 -N ""

# Deploy the public key to each target host:
ssh-copy-id -i /opt/risk-scanner/config/scanner_ed25519.pub scanuser@target-host

# Then provide the key path when prompted by add-credential.sh.
```

### WMI/WinRM Credentials (Windows hosts)

WinRM must be enabled on each target Windows host. Run these commands in an elevated PowerShell prompt on the target:

```powershell
# Enable WinRM (allows remote management):
Enable-PSRemoting -Force
winrm quickconfig -force

# Allow the scanner account in Remote Management Users:
Add-LocalGroupMember -Group "Remote Management Users" -Member "DOMAIN\scanaccount"

# If using local accounts, enable LocalAccountTokenFilterPolicy:
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord

# Allow WinRM through Windows Firewall (if not already open):
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985
```

The scanner tries WinRM (port 5985) first. If WinRM is not available, it falls back to WMI DCOM (port 135 / RPC). Both paths are supported.

Use `DOMAIN\username` format for domain accounts, or `username` (no domain) for local accounts.

### SNMP v3 Credentials (Network Equipment)

SNMP v3 with authentication and privacy is recommended over v2c. Configure on the target device per its documentation, then register the credentials:

```bash
sudo /opt/risk-scanner/bin/add-credential.sh
# Select: SNMP v3
# Enter: username, auth protocol (SHA), auth key, priv protocol (AES), priv key
# Scope: the subnets containing network equipment
```

For legacy devices that only support SNMP v2c, the scanner accepts a community string profile.

Verify SNMP is reachable:

```bash
snmpwalk -v2c -c public <device-ip> sysDescr
```

### Testing a Credential Profile

```bash
sudo /opt/risk-scanner/bin/test-credential.sh 10.0.1.10
```

This resolves the best-matching credential profile for the given IP, attempts the connection, and prints the collected OS/firmware info or a detailed error.

---

## Report Types

### HTML Email Digest (Weekly)

Sent as the email body with all CSS inline for email client compatibility. Contains:

- Risk score hero with delta arrow (improving / stable / worsening) and trend chart
- Delta summary box: new issues, resolved, recurring, new CISA KEV matches
- KEV alert block: red highlighted callout for newly matched CISA Known Exploited Vulnerabilities
- Top 10 risks table with host, finding, CVE ID, CVSS score, severity, and KEV/New badges
- Critical and high-risk host cards with top findings
- Credential coverage summary (which hosts were reached via SSH / WMI / SNMP)
- New hosts detected and resolved findings callouts
- AI insights block (when Hatz AI is configured)
- Full device inventory table sorted by risk score

### Executive Summary PDF (Weekly Attachment)

Designed for non-technical leadership. Includes:

- Cover page with risk score gauge (0–100 radial dial), "Prepared for: Client Name", and report date range
- Risk score trend chart: 12 weeks of history, each week color-coded by severity band, KEV weeks annotated
- Key findings in plain language: "ACTIVELY EXPLOITED" badge for KEV CVEs, "NEW THIS WEEK" badges, resolved items in green
- AI Executive Summary page: narrative overview, critical actions this week, positive security controls (when Hatz AI configured)
- Risk by host category: bar chart across Servers / Workstations / Network Gear / Printers / IoT
- Security posture summary: traffic-light table (GREEN/AMBER/RED) across 10 control areas (patch management, authentication, firewall, antivirus, backup, encryption, remote access, network segmentation, email security, EOL devices)

### Technical Detail PDF (Weekly Attachment)

Designed for IT staff and security engineers. Includes:

- Scan coverage and methodology: subnets scanned, credential coverage rates, CVE DB version, phases completed
- Environment risk summary: CRITICAL/HIGH/MEDIUM/LOW host counts, total CVEs by severity, full CISA KEV match table
- Per-host finding pages: CVE table with CVSS scores and KEV flags, configuration findings, patch status, open ports, optional AI narrative for high-risk hosts
- Appendix A: Full host inventory sorted by risk score
- Appendix B: All CVEs detected, deduplicated across all hosts, sorted by KEV status then CVSS

---

## Management Scripts Reference

| Script | Usage | Description |
|---|---|---|
| `manual-scan.sh` | `sudo /opt/risk-scanner/bin/manual-scan.sh` | Trigger an immediate ad-hoc scan; tails logs and prints risk summary on completion |
| `manual-report.sh` | `sudo /opt/risk-scanner/bin/manual-report.sh [--output DIR] [--no-email]` | Generate reports from the most recent scan without running a new scan |
| `add-credential.sh` | `sudo /opt/risk-scanner/bin/add-credential.sh` | Interactive wizard to add or update a credential profile (SSH/WMI/SNMP) |
| `test-credential.sh` | `sudo /opt/risk-scanner/bin/test-credential.sh [IP]` | Test the best-matching credential profile against a given host IP |
| `view-risks.sh` | `sudo /opt/risk-scanner/bin/view-risks.sh [--host IP]` | Print a terminal risk summary from the latest scan; use `--host` for per-host detail |
| `update-config.sh` | `sudo /opt/risk-scanner/bin/update-config.sh` | Re-run the configuration wizard (preserves existing credential profiles) |
| `update-vuln-db.py` | `sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --update` | Manually update the CVE/KEV/OSV database; use `--init` for first-time seed, `--stats` to show DB status |
| `self-update.sh` | `sudo /opt/risk-scanner/bin/self-update.sh` | Pull latest code from GitHub, update Python packages, reload systemd if unit files changed |

---

## Understanding Risk Scores

### Environment and Host Scores

Risk scores range from 0 to 100. Each host receives an individual score; the environment score is a weighted aggregate across all hosts (servers and network gear weighted higher than workstations and IoT devices).

| Score Range | Classification | Color |
|---|---|---|
| 80 – 100 | CRITICAL | Red |
| 60 – 79 | HIGH | Orange |
| 40 – 59 | MEDIUM | Yellow |
| 0 – 39 | LOW | Green |

### Finding Weight Table

| Finding | Points |
|---|---|
| CISA KEV CVE matched | 100 pts each (cap 3 per host) |
| CVSS 9.0–10.0 CVE | 80 pts each (cap 5 per host) |
| CVSS 7.0–8.9 CVE | 50 pts each (cap 10 per host) |
| CVSS 4.0–6.9 CVE | 20 pts each (cap 20 per host) |
| Default credentials confirmed | 90 pts |
| EOL OS or firmware | 60 pts |
| Telnet open (port 23) | 55 pts |
| Exposed management interface over HTTP | 40 pts |
| Weak SSH config (root login enabled) | 35 pts |
| Windows patches more than 90 days old | 30 pts |
| Open SMB shares (unauthenticated access) | 30 pts |
| Expired SSL certificate | 25 pts |
| Antivirus missing or definitions stale | 25 pts |
| Windows Firewall profile disabled | 20 pts |
| Self-signed SSL certificate | 15 pts |

Per-host scores are capped at 100. The environment score adds a breadth penalty based on the percentage of hosts with at least one HIGH or CRITICAL finding.

---

## CVE Database

The scanner maintains a local vulnerability database — no internet access is required at scan time once the DB is seeded.

### Data Sources

| Source | Coverage | Update Frequency |
|---|---|---|
| **NVD** (NIST National Vulnerability Database) | All public CVEs with CVSS v3 scores | Daily incremental |
| **CISA KEV** (Known Exploited Vulnerabilities) | ~1,200 CVEs confirmed actively exploited in the wild | Daily full refresh |
| **OSV** (Open Source Vulnerabilities) | Linux, PyPI, npm package vulnerabilities | Daily incremental |

### NVD API Key (Strongly Recommended)

Without an API key, NVD rate-limits requests to 5 per 30 seconds. The initial database seed may take 60 minutes or more. With a free API key (50 req/30 sec), the initial seed takes 10–15 minutes.

Register for a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

Add the key to `config.json`:

```json
"vulnerability": {
    "nvd_api_key": "your-key-here"
}
```

Or provide it during initial install when the wizard prompts for it.

### Manual Database Commands

```bash
# Check database status (CVE count, KEV count, last updated):
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --stats

# Run a manual incremental update:
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --update

# Re-seed the full database (takes 10–60 min depending on API key):
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --init --nvd-api-key YOUR_KEY
```

### Storage

The default 5-year CVE window uses approximately 400 MB. If disk space is constrained, reduce `vuln_db_max_age_years` in `config.json`. The vast majority of actively exploited CVEs are within the last 5 years.

---

## Security Considerations

- **Credential encryption**: All credential profiles are AES-256 encrypted in `credentials.enc`. The encryption key is derived at runtime from `/etc/machine-id` + `device_name` via PBKDF2 — the key is never stored. Credentials are machine-bound and unreadable on any other device.
- **No brute-force**: The scanner makes a single connection attempt per host per credential profile. There are no password-guessing loops.
- **No exploitation**: The scanner performs enumeration and observation only. It reads configuration and software inventory via authenticated sessions — it does not exploit vulnerabilities it finds.
- **Authorized use only**: A scan disclaimer is logged at the start of every scan: "Authorized credentialed scan — client: {client_name}". Deploy only on networks where you have written authorization.
- **File permissions**: `config.json` is mode 640 (readable only by `risk-scanner` and root). `credentials.enc` is mode 600 (readable only by root and the service user). `logs/` is mode 750.
- **Service hardening**: The systemd service runs as `risk-scanner` (no shell, no home directory) with `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, and minimal capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN` for scanning).
- **Never commit `config.json` or `credentials.enc`**: Both are listed in `.gitignore`. They contain credentials and must never be pushed to version control.
- **Log sanitization**: All passwords, API keys, community strings, and auth keys are masked as `***` in all log output.
- **Graph API**: All communication with Microsoft Graph API is over TLS. The client secret is stored in `config.json` — protect that file accordingly.

---

## Self-Maintenance

| Feature | How It Works |
|---|---|
| **Vuln DB updates** | Before each daily scan, `update-vuln-db.py` checks when the DB was last updated. If it is due (based on `vuln_db_update_interval_days`), it runs an incremental NVD/KEV/OSV update. |
| **Self-update** | `self-update.sh` runs `git pull --ff-only` to pick up code changes from GitHub. Run manually or call `bin/initial-checkin.py` which invokes it on each boot. |
| **Disk management** | On startup, `risk-scanner-main.py` checks free disk space against `min_free_disk_mb` (default 500 MB). If low, it prunes the oldest `.json.gz` scan archives one at a time until the threshold is met. |
| **Log rotation** | `RotatingFileHandler` keeps logs bounded: `risk-scanner.log` at 10 MB x 5 backups; `initial-checkin.log` at 5 MB x 3 backups. |
| **Post-send cleanup** | After a successful weekly email send, uncompressed temporary files are removed. The compressed `.json.gz` scan archives in `data/history/` are always retained. |

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed guidance on:

- SSH authentication failures and host key issues
- WMI/WinRM access denied errors and Windows Firewall configuration
- SNMP no-response and v3 auth failures
- NVD API rate limiting and initial seed timing
- Credential decryption failure after OS reinstall (machine-id change)
- Graph API token failures and clock skew issues
- Lock file cleanup and general service diagnostics

---

## Uninstall

```bash
sudo /opt/risk-scanner/uninstall.sh
```

The uninstaller prompts whether to keep scan history and logs before removing all files and systemd units.

---

## Graph API Setup

See [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md) for step-by-step instructions on creating the Azure App Registration and configuring `Mail.Send` permissions.

---

## License / Legal

See repository root LICENSE file.

**For authorized use only.** This tool performs credentialed access to network hosts and must only be deployed on networks where you have explicit written permission from the network owner. Unauthorized deployment may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in other jurisdictions.

Always obtain written customer authorization before deploying a credentialed scanner on their network.

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
*Companion tool to the Raspberry Pi Network Discovery Tool.*
*Developed through real-world MSP field engagements.*
