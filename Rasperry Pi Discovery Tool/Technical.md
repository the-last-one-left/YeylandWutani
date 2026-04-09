# Technical Reference — Yeyland Wutani Network Discovery Pi

> **AI Quick-Start:** This document is the authoritative reference for this codebase. Read this before exploring individual files. **Keep this file up to date** whenever you add/rename files, change config schema, add scan phases, modify service behavior, or change major function signatures.

---

## 1. Project Overview

A Raspberry Pi appliance that performs automated network discovery, generates branded security assessment reports (HTML email + PDF), and emails them via Microsoft Graph API. Intended for MSP use at client sites.

- **Install target:** `/opt/network-discovery/`
- **Service user:** `network-discovery` (no shell, no home dir)
- **Python runtime:** virtualenv at `/opt/network-discovery/venv/`
- **GitHub repo:** `https://github.com/the-last-one-left/YeylandWutani`
- **Sparse checkout:** Pi clones only the `Rasperry Pi Discovery Tool/` subfolder (note typo: one `r`)

---

## 2. Directory Structure

```
Rasperry Pi Discovery Tool/
├── bin/                          # Executable scripts
│   ├── discovery-main.py         # Main orchestration (703 L)
│   ├── network-scanner.py        # 17+ phase discovery engine (6,062 L)
│   ├── generate-report.py        # On-demand PDF report CLI (305 L)
│   ├── initial-checkin.py        # First-boot check-in email (525 L)
│   ├── graph-mailer.py           # Graph API email CLI wrapper (47 L)
│   ├── health-check.py           # Weekly system health monitor (447 L)
│   ├── test-email.py             # Email delivery test utility (56 L)
│   ├── update-oui-db.py          # IEEE OUI vendor DB downloader (87 L)
│   ├── update-vuln-db.py         # NVD vulnerability DB updater (332 L)
│   ├── manual-scan.sh            # Shell wrapper: trigger manual scan
│   ├── reset-checkin.sh          # Remove .checkin_complete flag
│   ├── self-update.sh            # git pull from GitHub
│   ├── update-config.sh          # Interactive config wizard
│   └── view-last-report.sh       # Print last scan to terminal
│
├── lib/                          # Python modules (imported by bin/)
│   ├── graph_auth.py             # OAuth2 / MSAL token management (214 L)
│   ├── graph_mailer.py           # Graph API email sender (545 L)
│   ├── network_utils.py          # Network helpers, OUI, DNS (961 L)
│   ├── report_generator.py       # HTML email report builder (3,667 L)
│   ├── client_report.py          # PDF report builder - Summary + Detail (1,934 L)
│   ├── product_recommendations.py# PDF recommendations builder (2,496 L)
│   ├── hatz_ai.py                # Hatz AI API integration (378 L)
│   ├── ad_discovery.py           # Active Directory / LDAP enum (968 L)
│   ├── vuln_db.py                # NVD vulnerability DB handler (1,054 L)
│   ├── topology_generator.py     # D3.js HTML topology map builder
│   └── product_catalog.json      # Hardware/software catalog (Dell, WatchGuard, Datto)
│
├── config/
│   ├── config.json               # Active config (created by installer, mode 640)
│   ├── config.json.template      # Defaults template
│   └── .env.template             # Environment variables template
│
├── data/                         # Runtime data (created by installer)
│   ├── scan_YYYYMMDD_HHMMSS.json[.gz]  # Full scan results
│   ├── scan_YYYYMMDD_HHMMSS.csv[.gz]   # Device table (CSV)
│   ├── scan_YYYYMMDD_HHMMSS_*.pdf      # Generated PDF reports
│   ├── eol-database.json               # End-of-Life database (~2,000 entries)
│   ├── oui.json                         # IEEE OUI vendor mapping
│   ├── vuln-db/vuln-db.sqlite           # SQLite NVD vulnerability DB
│   ├── .checkin_complete                # Flag: initial check-in has run
│   ├── .discovery.lock                  # Lock: prevent concurrent scans
│   └── .token_cache.json                # MSAL OAuth2 token cache (mode 600)
│
├── logs/
│   ├── discovery.log             # Main log (10 MB × 5 backups)
│   └── initial-checkin.log       # Check-in log (5 MB × 3 backups)
│
├── systemd/
│   ├── initial-checkin.service   # Type=oneshot, first-boot check-in
│   ├── network-discovery.service # Type=simple, main discovery
│   ├── network-discovery-health.service  # Weekly health check
│   └── network-discovery-health.timer    # Mon 08:00, Persistent=true
│
├── install.sh                    # Full installer (~850 L)
├── uninstall.sh
├── requirements.txt              # Python pip dependencies
├── README.md
├── TROUBLESHOOTING.md
├── GRAPH_API_SETUP.md            # Azure App Registration guide
└── .gitattributes                # LF enforcement for .sh/.py/.service
```

> **Imports:** All Python scripts insert `../lib` into `sys.path` at the top — no package installation needed.

---

## 3. End-to-End Data Flow

```
systemd boot
  └─ initial-checkin.service (oneshot, After=network-online.target time-sync.target)
      └─ initial-checkin.py
          ├─ Wait for default gateway
          ├─ self-update.sh (git pull)
          ├─ Gather: hostname, Pi model, OS, interfaces, gateway, WAN IP
          ├─ Send "Initial Check-In" HTML email via Graph API
          └─ Write data/.checkin_complete  ← prevents re-run on reboot

  └─ network-discovery.service (simple, After=initial-checkin.service)
      └─ discovery-main.py
          ├─ Acquire data/.discovery.lock
          ├─ Disk pruning (delete oldest .gz if free < min_free_disk_mb)
          ├─ Vulnerability DB update (if age > interval_days)
          ├─ Validate Graph API credentials
          ├─ Send "Discovery Starting" email
          ├─ Start p0f daemon (if enabled)
          │
          ├─ network-scanner.py → run_discovery(progress_callback)
          │   [17+ phases — see §5]
          │
          ├─ Stop p0f daemon
          ├─ Hatz AI insights (optional, if api_key set)
          ├─ report_generator.py → HTML email + gzipped CSV
          ├─ client_report.py → Summary PDF + Detail PDF (optional)
          ├─ product_recommendations.py → Recommendations PDF (optional)
          ├─ graph_mailer.py → Send email
          │   ├─ < 3 MB: sendMail endpoint
          │   └─ ≥ 3 MB: draft + createUploadSession + 320 KB chunked upload
          ├─ On success: delete uncompressed .csv/.json/.pdf (keep .gz)
          ├─ On failure: preserve all intermediaries
          └─ Release lock, exit 0/1/2
```

---

## 4. Key Modules — Signatures & Purpose

### `lib/graph_auth.py`
```python
class GraphAuth:
    def __init__(tenant_id, client_id, client_secret)
    def get_token() -> str                    # Acquire/refresh; auto-caches
    def validate_credentials() -> bool
def load_credentials_from_config(config_path, _preloaded_config=None) -> GraphAuth
```
- Token scope: `https://graph.microsoft.com/.default`
- Cache: `data/.token_cache.json` (mode 0o600)
- Env var overrides: `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`

### `lib/graph_mailer.py`
```python
class GraphMailer:
    def send_email(subject, body_html, attachment_paths=[], cc_emails=[]) -> bool
```
- `LARGE_ATTACHMENT_THRESHOLD` = 3 MB → switches to upload session strategy
- `UPLOAD_CHUNK_SIZE` = 327,680 bytes (320 KB — Graph API requirement)
- `MAX_RETRIES` = 4, `RETRY_BASE_DELAY` = 2s (exponential backoff)
- Handles 429 throttling (Retry-After header) and NTP clock skew (15s retry)

### `lib/network_utils.py`
Key functions:
- `get_network_interfaces() -> list` — IP, netmask, MAC, CIDR per interface
- `get_default_gateway() -> str`
- `lookup_oui(mac) -> dict` — Vendor from oui.json (fallback: ~500 embedded)
- `detect_dhcp_server(iface, timeout) -> str | None` — Non-destructive DISCOVER
- `get_pi_model() -> str` — From `/proc/cpuinfo` or `/proc/device-tree`

### `lib/hatz_ai.py`
```python
def get_hatz_insights(scan_results, api_key) -> Optional[str]
```
- Endpoint: `https://ai.hatz.ai/v1/chat/completions`
- Model: `anthropic.claude-opus-4-6`
- Timeout: 120s; non-fatal (report continues without insights)
- Returns markdown ~700 words: Key Findings, Recommended Actions, Positive Observations
- Data sent: anonymized summary (no employee names, no full banners)

### `lib/client_report.py`
```python
def compute_risk_score(scan_results) -> int            # 0–100
def build_client_summary_pdf(scan_results, config, ai_insights=None) -> bytes
def build_client_detail_pdf(scan_results, config) -> bytes
```

### `lib/ad_discovery.py`
- Full credentialed LDAP enumeration: DCs, users, computers, GPOs, SPNs, trusts, BitLocker
- Only runs if `enable_ad_enrichment: true` and credentials are configured

### `lib/topology_generator.py`
```python
def build_topology_html(scan_results: dict, config: dict) -> str
```
- Generates a self-contained D3.js HTML topology map from scan results
- Adapts the Network Topology Agent v4 approach — uses ARP/IP scan data instead of switch MAC tables
- Topology inference: gateway identified by `recon['default_gateway']` IP; switches by `category == 'Network Switch'`; devices assigned to switch nodes via /24 subnet proximity (round-robin when multiple switches share a /24)
- Output: single HTML file (~15–30 KB), no external dependencies except D3 from cdnjs
- Saved to `data/scan_TIMESTAMP_Topology.html` — NOT emailed (interactive HTML won't render in email clients; open in browser)
- Note: uses `host['vendor']` field (not `oui_vendor`), and `recon['subnets']` (not `subnets_to_scan`)

### `lib/vuln_db.py`
- SQLite-backed NVD CVE database at `data/vuln-db/vuln-db.sqlite`
- Updated by `bin/update-vuln-db.py` (incremental; first run seeds full DB, ~30-60 min)

---

## 5. Network Scanner Phases

`bin/network-scanner.py` — entry point: `run_discovery(progress_callback) -> dict`

| Phase | Function | Description |
|-------|----------|-------------|
| 1 | `phase1_reconnaissance` | Interfaces, gateways, DNS, public IP, gateway fingerprint |
| 1b | `phase1b_alternate_subnet_detection` | Probe common gateway IPs for extra subnets |
| 1c | `phase1c_dhcp_subnet_seeding` | DHCP DISCOVER → extract subnets |
| 1d | `phase1d_snmp_gateway_harvest` | SNMP walk gateway ARP table (ipNetToMediaTable OID 1.3.6.1.2.1.4.22) + routing table (ipRouteTable OID 1.3.6.1.2.1.4.21) → seed IP+MAC pairs into `recon["snmp_seeded_hosts"]`, add new CIDRs to `recon["additional_subnets"]` |
| 1e | `phase1e_cdp_lldp_discovery` | Passively sniff CDP (01:00:0c:cc:cc:cc) and LLDP (01:80:c2:00:00:0e) for `cdp_lldp_timeout` seconds → store in `recon["cdp_lldp_neighbors"]`, add neighbor /24s to `recon["additional_subnets"]` |
| 2 | `phase2_host_discovery` | Direct: arp-scan + netdiscover + fping; Additional subnets: SNMP seeds + fping + nmap -sn + DNS PTR walk |
| 2b | `phase2b_llmnr_capture` | Background thread: LLMNR/NBT-NS passive hostname capture |
| 3 | `phase3_port_scan` | RustScan (if available) → nmap -sS → fallback nmap -sT |
| 4 | `phase4_service_enumeration` | HTTP headers, SMB/NetBIOS, SNMP, banner grab, NSE |
| 5 | `phase5_topology` | traceroute per host |
| 6 | `phase6_security` | SSH version, SSL expiry, self-signed, AD probing |
| 7 | `phase7_wifi_scan` | iw/iwlist scan → SSIDs, BSSIDs, signal, channel heatmap |
| 8 | `phase8_mdns_discovery` | avahi-browse: printers, AirPlay, media servers |
| 9 | `phase9_ssdp_discovery` | UPnP M-SEARCH multicast + description XML fetch |
| 10 | `phase10_dhcp_analysis` | DHCP scope, rogue server detection |
| 11 | `phase11_ntp_detection` | NTP stratum/reference for hosts on port 123/UDP |
| 12 | `phase12_nac_detection` | 802.1X EAPOL frame detection |
| 13 | `phase13_osint` | WHOIS, crt.sh, Shodan InternetDB, MX/SPF/DKIM/DMARC |
| 14 | `phase14_ssl_audit` | TLS cert expiry, key size, self-signed |
| 15 | `phase15_backup_posture` | Port-based inference: Veeam, Commvault, rsync, NAS |
| 16 | `phase16_eol_detection` | Regex match against eol-database.json |
| 17 | `phase17_testssl` | testssl.sh deep TLS (if binary present) |
| 18 | `phase18_nikto` | Nikto web scanner (if binary present) |
| 19 | `phase19_speedtest` | speedtest-cli WAN baseline (if enabled) |
| 20 | `phase20_enum4linux` | enum4linux-ng deep SMB enum (if binary present) |
| 21 | `phase21_ad_enrichment` | Credentialed AD via ad_discovery.py (if enabled) |

---

## 6. Configuration Schema (`config/config.json`)

```json
{
  "graph_api": {
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "from_email": "",
    "to_email": "",
    "cc_emails": []
  },
  "network_discovery": {
    "scan_timeout": 600,
    "max_threads": 50,
    "port_scan_top_ports": 100,
    "enable_wifi_scan": true,       "wifi_interface": "auto",
    "enable_mdns_discovery": true,  "mdns_timeout": 10,
    "enable_ssdp_discovery": true,  "ssdp_timeout": 5,
    "enable_dhcp_analysis": true,   "dhcp_timeout": 10,
    "enable_ntp_detection": true,
    "enable_nac_detection": true,
    "enable_osint": true,           "osint_timeout": 8,
    "enable_shodan_internetdb": true,
    "enable_crtsh_lookup": true,
    "enable_dns_security": true,
    "enable_ssl_audit": true,       "ssl_cert_warning_days": 30, "ssl_cert_critical_days": 7,
    "enable_backup_posture": true,
    "enable_eol_detection": true,   "eol_warning_months": 12,
    "enable_testssl": true,         "testssl_ports": [443, 8443, 636, 993, 995],
    "enable_nikto": true,
    "enable_speedtest": true,
    "enable_enum4linux": true,
    "enable_ad_enrichment": false,
    "enable_hatz_osint_enrichment": true,               // Phase 13: AI company profile + exposure brief
    "enable_snmp_gateway_harvest": true,                 // Phase 1d: walk gateway ARP+route tables
    "enable_cdp_lldp_discovery": true,                  // Phase 1e: passive CDP/LLDP sniff
    "cdp_lldp_timeout": 65,                             // seconds to listen (CDP every 60s)
    "enable_nmap_remote_discovery": true,               // nmap -sn on additional subnets
    "enable_dns_ptr_walk": true,                        // DNS PTR walk on additional subnets
    "subnet_labels": { "192.168.1.0/24": "Main LAN" }
  },
  "reporting": {
    "company_name": "Yeyland Wutani LLC",
    "company_color": "#FF6600",
    "tagline": "Building Better Systems",
    "client_name": "",
    "enable_pdf_reports": true,
    "enable_pdf_reports": true,
    "enable_product_recommendations": true,
    "enable_topology_map": true           // D3.js HTML topology map (saved to data/, not emailed)
  },
  "hatz_ai": {
    "api_key": ""
  },
  "system": {
    "device_name": "NetDiscovery-Pi",
    "log_level": "INFO",
    "min_free_disk_mb": 200,
    "vuln_db_update_interval_days": 1
  }
}
```

**Environment variable overrides** (take precedence over config.json):
`GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`, `GRAPH_FROM_EMAIL`, `GRAPH_TO_EMAIL`

---

## 7. Systemd Services

| Service | Type | User | Key Behavior |
|---------|------|------|-------------|
| `initial-checkin.service` | oneshot | network-discovery | Runs once (flag file gate); After=time-sync.target to avoid NTP clock skew on Azure AD |
| `network-discovery.service` | simple | network-discovery | Restart=no; AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN; **NoNewPrivileges intentionally omitted** (nmap setuid) |
| `network-discovery-health.service` | oneshot | network-discovery | Triggered by timer; disk/RAM/temp/service health check |
| `network-discovery-health.timer` | — | — | OnCalendar=Mon 08:00; Persistent=true; RandomizedDelaySec=600 |

---

## 8. Scan Results JSON Shape

```json
{
  "timestamp": "ISO-8601",
  "device_name": "string",
  "scan_duration_seconds": 0.0,
  "summary": {
    "total_hosts": 0,
    "total_open_ports": 0,
    "security_observations": 0,
    "subnets_scanned": [],
    "category_breakdown": {}
  },
  "reconnaissance": {
    "interfaces": [], "subnets": [], "default_gateway": "", "dns_servers": [],
    "public_ip_info": { "public_ip": "", "isp": "" },
    "additional_subnets": [ { "cidr": "", "discovered_via": "" } ],
    "snmp_seeded_hosts": { "ip": "mac" },
    "cdp_lldp_neighbors": [ { "protocol": "CDP|LLDP", "device_id": "", "mgmt_ip": "", "port_id": "" } ]
  },
  "hosts": [
    {
      "ip": "", "mac": "", "vendor": "", "hostname": "",
      "hostname_source": "",
      "category": "", "os_guess": "",
      "open_ports": [], "services": { "PORT": { "name": "", "version": "", "product": "" } },
      "security_flags": [ { "severity": "HIGH|MEDIUM|LOW|CRITICAL", "description": "", "category": "" } ],
      "snmp": {}, "ssl_certs": [], "backup_indicators": [], "eol_matches": [],
      "p0f_fingerprint": ""
    }
  ],
  "wifi_results": { "networks": [], "channel_analysis": {} },
  "mdns_services": [], "ssdp_devices": [], "dhcp_analysis": {},
  "ntp_servers": [], "osint": {}, "ssl_audit": {}, "backup_posture": {},
  "eol_detection": {}, "ai_insights": "markdown string or null",
  "operational_stats": { "phase_timings": [ { "phase": "", "duration_seconds": 0.0 } ] }
}
```

---

## 9. External Dependencies

### Python Packages (`requirements.txt`)
`msal`, `requests`, `python-nmap`, `netifaces`, `scapy`, `dnspython`, `python-dotenv`, `jinja2`, `speedtest-cli`, `impacket`, `ldap3`, `reportlab`

### System Packages (installed by `install.sh`)
`nmap`, `arp-scan`, `fping`, `traceroute`, `netdiscover`, `dnsutils`, `whois`, `ldap-utils`, `iw`, `wireless-tools`, `avahi-utils`, `openssl`, `p0f`

### Optional Binaries (downloaded/cloned by `install.sh`)
- `testssl.sh` — deep TLS analysis
- `RustScan` — fast TCP scanner (arch-specific binary: aarch64, armv7l, x86_64)
- `enum4linux-ng` — SMB enumeration (git cloned)

### External APIs (no key required except Hatz AI)
- Shodan InternetDB, crt.sh, WHOIS/RDAP, HackerTarget, Hatz AI (`ai.hatz.ai`)

---

## 10. Security Notes

- `config.json` permissions: mode 640 (owner: network-discovery, group: root)
- `.token_cache.json` permissions: mode 600
- Client secret never logged
- OSINT: scans only the organization's own public IP + derived domains
- DHCP analysis: single DISCOVER packet — does NOT accept lease
- WiFi scanning: passive only — no association

---

## 11. Branding

| Field | Value |
|-------|-------|
| Assessor company | Yeyland Wutani LLC |
| Primary color | `#FF6600` (orange) |
| Tagline | "Building Better Systems" |
| Client report branding | Pacific Office Automation, Blue `#00A0D9`, "Problem Solved." |

---

## 12. Known Limitations

- **IPv4 only** — no IPv6 scanning
- nmap cannot reliably distinguish Windows 10 from Windows 11 — phrase as "Windows 10/11"
- Multi-OS nmap guesses are low-confidence; prefer `category` field
- RustScan falls back to nmap if architecture binary unavailable
- AD enrichment (Phase 21) requires manual credential configuration
- NVD DB initial seed takes 30–60 min without an NVD API key

---

## 13. Maintenance This Doc

**Update this file when you:**
- Add, rename, or remove any file in `bin/` or `lib/`
- Add or remove a scan phase in `network-scanner.py`
- Change any `config.json` key (add §6 entry)
- Change a major function signature in any lib module
- Change systemd service behavior or dependencies
- Add/remove an external API or dependency
- Change branding values or install paths

**Do not duplicate** information already in `README.md`, `TROUBLESHOOTING.md`, or `GRAPH_API_SETUP.md` — cross-reference instead.
