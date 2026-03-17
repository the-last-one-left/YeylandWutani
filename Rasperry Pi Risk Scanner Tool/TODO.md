# Raspberry Pi Risk Scanner Tool — Build TODO

**Yeyland Wutani LLC** | *Building Better Systems*

A credentialed, scheduled vulnerability and risk scanner deployed as a headless Raspberry Pi (or VM) left permanently on a client network. Unlike the one-shot Discovery Tool, this runs daily scans, tracks risk over time, and delivers weekly executive and technical PDF reports via Microsoft 365 Graph API.

---

## Architecture Overview

```
/opt/risk-scanner/               ← install target (separate from discovery tool)
├── bin/
│   ├── risk-scanner-main.py     orchestration (scheduler, disk, AI, email)
│   ├── scan-engine.py           credentialed multi-phase scan engine
│   ├── generate-report.py       on-demand PDF/HTML report generator CLI
│   ├── update-vuln-db.py        CVE/KEV database updater
│   ├── initial-checkin.py       first-boot check-in email
│   ├── manual-scan.sh           trigger ad-hoc scan
│   ├── manual-report.sh         generate reports from latest scan
│   ├── add-credential.sh        credential wizard (add/update creds)
│   ├── test-credential.sh       test a stored credential against a host
│   ├── view-risks.sh            terminal risk summary from last scan
│   ├── update-config.sh         reconfiguration wizard
│   └── self-update.sh           git pull + restart services
├── lib/
│   ├── graph_auth.py            OAuth2 MSAL client credentials
│   ├── graph_mailer.py          Graph API email (copy + adapt from discovery)
│   ├── network_utils.py         IP/MAC/OUI/interface helpers (copy + adapt)
│   ├── credential_store.py      encrypted credential profiles (SSH/WMI/SNMP)
│   ├── ssh_scanner.py           credentialed SSH host interrogation
│   ├── wmi_scanner.py           credentialed Windows WMI/WinRM interrogation
│   ├── snmp_scanner.py          SNMP v1/v2c/v3 network equipment audit
│   ├── vuln_db.py               local NVD/KEV/OSV cache + CVSS scoring
│   ├── risk_scorer.py           per-host + environment risk scoring
│   ├── delta_tracker.py         scan-to-scan diff (new/resolved/recurring)
│   ├── hatz_ai.py               Hatz AI API (risk-focused prompt variant)
│   ├── report_generator.py      HTML email report builder
│   ├── executive_report.py      Executive Summary PDF builder
│   └── detail_report.py         Technical Detail PDF builder
├── config/
│   ├── config.json              active config (created by installer)
│   ├── config.json.template     template
│   └── credentials.enc          AES-encrypted credential store
├── data/
│   ├── vuln-db/
│   │   ├── nvd-cache.json       NVD CVE cache (auto-updated)
│   │   ├── kev-catalog.json     CISA Known Exploited Vulnerabilities
│   │   └── osv-cache.json       OSV open-source vulnerability cache
│   ├── history/
│   │   └── scan_YYYYMMDD_HHMMSS.json.gz   daily scan archives
│   └── .scanner.lock            prevents concurrent runs
├── systemd/
│   ├── risk-scanner-checkin.service
│   ├── risk-scanner-daily.service
│   ├── risk-scanner-daily.timer     (daily at configurable time)
│   ├── risk-scanner-report.service
│   └── risk-scanner-report.timer    (weekly on configurable day/time)
├── logs/
│   ├── risk-scanner.log         rotating 10 MB x 5 backups
│   └── initial-checkin.log      rotating 5 MB x 3 backups
├── install.sh
├── uninstall.sh
└── README.md
```

**Service user:** `risk-scanner` (no shell, no home)
**Install target:** `/opt/risk-scanner/`
**Venv:** `/opt/risk-scanner/venv/`

---

## Phase 0 — Repository Scaffolding

- [ ] Create `Rasperry Pi Risk Scanner Tool/` folder in repo root
- [ ] Create `.gitattributes` with LF enforcement for `*.sh`, `*.py`, `*.service`, `*.timer`
- [ ] Add `credentials.enc` and `config.json` to `.gitignore` (never commit)
- [ ] Create `README.md` (placeholder — fill in after tool is built)
- [ ] Create `TROUBLESHOOTING.md` (placeholder)
- [ ] Create all `bin/`, `lib/`, `config/`, `data/vuln-db/`, `data/history/`, `systemd/`, `logs/` directories with `.gitkeep` files

---

## Phase 1 — Installer (`install.sh`)

- [ ] **System package installation**
  - [ ] `nmap` (port + service scanning)
  - [ ] `arp-scan`, `fping` (host discovery)
  - [ ] `sshpass` (SSH credentialed scan without interactive prompt)
  - [ ] `snmp`, `snmp-mibs-downloader` (SNMP scanning)
  - [ ] `python3-venv`, `python3-pip`
  - [ ] `openssl` (certificate inspection)
  - [ ] `curl`, `jq` (API calls + JSON parsing in shell scripts)
  - [ ] `git` (self-update)
  - [ ] Python packages into venv: `msal`, `reportlab`, `cryptography`, `paramiko`, `pysnmp`, `impacket`, `pypsrp`, `requests`, `python-dateutil`

- [ ] **Service user creation**
  - [ ] `useradd --system --no-create-home --shell /bin/false risk-scanner`
  - [ ] Add to `netdev` group for network operations

- [ ] **Directory setup**
  - [ ] Create all directories listed in architecture overview
  - [ ] Set ownership: `chown -R risk-scanner:risk-scanner /opt/risk-scanner/`
  - [ ] Set `config/` to mode `750`, `credentials.enc` to mode `600`

- [ ] **Configuration wizard** (interactive prompts)
  - [ ] Graph API: tenant_id, client_id, client_secret, from_email, to_email
  - [ ] Hatz AI: api_key (optional, skip-able)
  - [ ] Reporting: company_name, company_color, tagline, client_name
  - [ ] Scan schedule: daily scan time (default `02:00`), weekly report day (default `Monday`) + time (default `06:00`)
  - [ ] Credential profiles — collect at least one:
    - [ ] SSH: username + password (or path to private key) + applicable subnets/hosts
    - [ ] Windows (WMI/WinRM): domain\username + password + applicable subnets/hosts
    - [ ] SNMP: community string (v2c) or auth/priv credentials (v3) + applicable subnets/hosts
    - [ ] Scope options: "apply to all hosts" vs subnet-specific vs host-specific
  - [ ] Confirm settings, write `config.json`
  - [ ] Encrypt credentials into `credentials.enc` with machine-derived key (see Phase 3c)

- [ ] **Systemd service/timer installation**
  - [ ] Write all five `.service` and `.timer` unit files with correct `OnCalendar` values from wizard
  - [ ] `systemctl daemon-reload && systemctl enable --now <all units>`

- [ ] **Vuln DB initial population**
  - [ ] Run `update-vuln-db.py --init` to seed NVD/KEV/OSV caches

- [ ] **Test email** — send a formatted check-in email confirming install success

- [ ] **First-run scan** — optional prompt to run initial scan immediately post-install

---

## Phase 2 — Configuration Schema (`config.json`)

- [ ] Write `config.json.template` with all keys, defaults, and inline comments
- [ ] Validate all required keys on startup; log warnings for missing optional keys
- [ ] Support `--config PATH` CLI override in all bin scripts

Complete schema:

```json
{
  "system": {
    "device_name": "RiskScanner-Pi",
    "log_level": "INFO",
    "min_free_disk_mb": 500
  },
  "graph_api": {
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "from_email": "",
    "to_email": "",
    "cc_emails": []
  },
  "hatz_ai": {
    "api_key": "",
    "enable_per_host_narrative": false,
    "max_hosts_for_narrative": 20
  },
  "scan_schedule": {
    "daily_scan_time": "02:00",
    "weekly_report_day": "Monday",
    "weekly_report_time": "06:00",
    "scan_on_install": true
  },
  "scan": {
    "scan_timeout": 3600,
    "max_threads": 30,
    "port_scan_top_ports": 1000,
    "port_scan_full": false,
    "subnet_labels": {},
    "excluded_hosts": [],
    "enable_service_version": true,
    "enable_ssh_scan": true,
    "enable_wmi_scan": true,
    "enable_snmp_scan": true,
    "enable_ssl_audit": true,
    "enable_smb_audit": true,
    "enable_nse_vulners": true,
    "enable_cve_correlation": true,
    "enable_delta_tracking": true,
    "snmp_timeout": 5,
    "ssh_timeout": 15,
    "wmi_timeout": 30
  },
  "vulnerability": {
    "nvd_api_key": "",
    "auto_update_vuln_db": true,
    "vuln_db_update_interval_days": 1,
    "vuln_db_max_age_years": 5,
    "cvss_critical_threshold": 9.0,
    "cvss_high_threshold": 7.0,
    "cvss_medium_threshold": 4.0,
    "prioritize_kev": true,
    "max_cves_per_host": 50
  },
  "reporting": {
    "company_name": "Yeyland Wutani LLC",
    "company_color": "#FF6600",
    "tagline": "Building Better Systems",
    "client_name": "",
    "include_executive_pdf": true,
    "include_detail_pdf": true,
    "include_html_email": true,
    "attach_scan_json": false,
    "risk_score_history_weeks": 12
  }
}
```

---

## Phase 3 — Core Library (`lib/`)

### 3a. `lib/graph_auth.py` and `lib/graph_mailer.py`
- [ ] Copy and adapt from Discovery Tool — same Graph API / MSAL pattern
- [ ] Update default install paths to `/opt/risk-scanner/`

### 3b. `lib/network_utils.py`
- [ ] Copy and adapt from Discovery Tool
- [ ] Add `get_subnets_from_interfaces()` — enumerate all local subnets to scan
- [ ] Add `resolve_credential_profile(ip, profiles) -> dict` — return best-matching credential profile for a given host IP (most-specific subnet match wins; fall back to global default)

### 3c. `lib/credential_store.py`
- [ ] **Machine-derived encryption key** — derive 256-bit AES key from `/etc/machine-id` + device_name using PBKDF2; never store the key, re-derive at runtime
- [ ] **Credential profile schema**:
  ```python
  {
    "profile_name": "servers-ssh",
    "type": "ssh",          # ssh | wmi | snmp_v2c | snmp_v3
    "scope": "subnet",      # subnet | host | global
    "targets": ["10.0.1.0/24"],
    "username": "",
    "password": "",         # AES-encrypted at rest
    "ssh_key_path": None,
    "snmp_community": None,
    "snmp_auth_key": None,
    "snmp_priv_key": None,
    "snmp_auth_protocol": "SHA",
    "snmp_priv_protocol": "AES",
    "priority": 10          # lower = higher priority for conflict resolution
  }
  ```
- [ ] `load_credentials(config_path) -> list[dict]` — decrypt and return all profiles
- [ ] `save_credentials(profiles, config_path)` — encrypt and write `credentials.enc`
- [ ] `add_credential(profile)` — append + re-save
- [ ] `test_credential(profile, target_ip) -> bool` — attempt connection, return success/fail
- [ ] Mask all passwords/keys in log output (show `***`)

### 3d. `lib/vuln_db.py`
- [ ] **NVD (NIST National Vulnerability Database)**
  - [ ] `update_nvd_cache(api_key=None)` — fetch via NVD 2.0 REST API
    - Without API key: 5 req/30s rate limit (workable for daily incremental updates)
    - With API key: 50 req/30s (recommended for initial seed)
  - [ ] Incremental updates only — fetch CVEs modified since last update timestamp
  - [ ] Filter to last `vuln_db_max_age_years` years (default 5) to constrain storage
  - [ ] Store as `nvd-cache.json` keyed by CPE pattern
  - [ ] Fields per CVE: `cve_id`, `description`, `cvss_v3_score`, `cvss_v3_vector`, `cvss_v3_severity`, `cvss_v2_score`, `affected_cpe`, `published`, `last_modified`, `references`

- [ ] **CISA Known Exploited Vulnerabilities (KEV)**
  - [ ] `update_kev_catalog()` — fetch from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - [ ] Store as `kev-catalog.json` keyed by `cve_id`
  - [ ] Fields: `cve_id`, `product`, `vendor`, `short_description`, `required_action`, `due_date`

- [ ] **OSV (Open Source Vulnerabilities)**
  - [ ] `update_osv_cache(ecosystems=["Linux", "PyPI", "npm"])` — batch query OSV API
  - [ ] Cache keyed by `package:version`

- [ ] **Lookup functions**
  - [ ] `lookup_cves(vendor, product, version) -> list[dict]` — query local cache, fuzzy version matching
  - [ ] `lookup_cpe(cpe_string) -> list[dict]` — CPE-based lookup
  - [ ] `is_kev(cve_id) -> bool` — CISA KEV membership check
  - [ ] `get_cvss_score(cve_id) -> float` — return CVSS v3 score, fall back to v2
  - [ ] `format_cvss_severity(score) -> str` — CRITICAL / HIGH / MEDIUM / LOW / INFO
  - [ ] `get_db_stats() -> dict` — CVE count, KEV count, last update timestamps

- [ ] **Embedded minimal fallback** — ship a static `vuln-db-fallback.json` with ~200 most common CVEs (SMB/RDP/SSH/Apache/Cisco) so the tool works offline before the DB is seeded

### 3e. `lib/risk_scorer.py`
- [ ] **Per-finding point weights**:
  ```
  KEV CVE matched:               100 pts each (cap at 3)
  CVSS 9.0-10.0 CVE:              80 pts each (cap at 5)
  CVSS 7.0-8.9 CVE:               50 pts each (cap at 10)
  CVSS 4.0-6.9 CVE:               20 pts each (cap at 20)
  Default credentials confirmed:  90 pts
  EOL OS or firmware:             60 pts
  Telnet open (port 23):          55 pts
  Exposed management over HTTP:   40 pts
  Weak SSH config (root login):   35 pts
  Windows patches > 90 days old: 30 pts
  Open SMB shares (unauthenticated): 30 pts
  Expired SSL certificate:        25 pts
  Antivirus missing or stale:     25 pts
  Windows firewall disabled:      20 pts
  Self-signed certificate:        15 pts
  ```
- [ ] `score_host(host_data) -> int` — 0–100 per host (cap at 100)
- [ ] `score_environment(all_hosts) -> int` — weighted environment score 0–100
  - Weight by host criticality tier: servers (3x) > workstations (2x) > network gear (2x) > printers/IoT (1x)
  - Add breadth penalty: percentage of hosts with at least one HIGH+ finding
- [ ] `classify_host_risk(score) -> str` — CRITICAL (80+) / HIGH (60+) / MEDIUM (40+) / LOW (<40)
- [ ] `get_risk_summary(all_hosts) -> dict` — counts by severity, top 10 risk items across environment

### 3f. `lib/delta_tracker.py`
- [ ] `load_previous_scan(data_dir) -> dict | None` — load most recent prior `.json.gz` (excluding current)
- [ ] `compute_delta(current_results, previous_results) -> dict`
  - `new_hosts` — IPs present now but not in previous scan
  - `removed_hosts` — IPs in previous scan, not in current (gone offline)
  - `new_findings` — security flags / CVEs not present in previous scan
  - `resolved_findings` — findings in previous not in current (remediated)
  - `recurring_findings` — present in both scans (never addressed)
  - `risk_score_delta` — signed int (positive = environment got worse)
  - `new_kev_cves` — newly matched CISA KEV CVEs (always top of report)
- [ ] `format_delta_summary(delta) -> str` — one-line summary for email subject
- [ ] `get_trend_data(data_dir, weeks=12) -> list[dict]` — return `[{date, risk_score, critical_count, high_count}, ...]` for trend chart rendering

### 3g. `lib/hatz_ai.py`
- [ ] Copy base structure from Discovery Tool's `hatz_ai.py`
- [ ] **Risk-focused system prompt** (replace discovery prompt):
  - Analyze CVE findings by severity and CVSS score
  - Highlight CISA KEV CVEs as requiring immediate action
  - Reference actual CVE IDs, IP addresses, service names from the data
  - Include delta context: what is new, what is recurring, what was fixed
  - Output sections (markdown headers):
    - `## Executive Summary` — 2–3 sentence non-technical overview
    - `## Critical Actions (This Week)` — numbered list, most critical first
    - `## Risk Trend` — 1–2 sentences on whether posture is improving or worsening
    - `## Positive Security Controls` — what the environment is doing well
- [ ] `get_risk_insights(scan_results, delta, api_key) -> str | None`
  - Include top 10 CVEs by CVSS score in prompt payload
  - Include risk score trend (last 4 weeks if available)
  - Include delta summary (new/resolved counts + new KEV matches)
- [ ] `get_host_narrative(host_data, api_key) -> str | None`
  - Optional per-host AI blurb for high-risk hosts in detail PDF
  - Only called when `enable_per_host_narrative: true`
  - Guarded by `max_hosts_for_narrative` to limit API usage

---

## Phase 4 — Scan Engine (`bin/scan-engine.py`)

### `scan_results` dict schema (extending Discovery Tool format)
```python
{
  "scan_start": "ISO8601",
  "scan_end":   "ISO8601",
  "scanner_version": "1.0.0",
  "hosts": [...],             # host dicts — same base as discovery, extended
  "summary": {...},
  "reconnaissance": {...},
  "delta": {...},              # NEW: from delta_tracker
  "risk": {...},               # NEW: environment risk score + breakdown
  "credential_coverage": {     # NEW: credentialed scan coverage stats
    "ssh_success": [list of IPs],
    "ssh_failed": [list of IPs],
    "wmi_success": [...],
    "wmi_failed": [...],
    "snmp_success": [...],
    "no_credential": [...]
  },
  "vuln_db_stats": {...},      # NEW: CVE DB currency info for report
  "ai_insights": None          # populated post-scan if Hatz AI configured
}
```

Per-host extended fields (added on top of Discovery Tool base fields):
```python
{
  # ... all Discovery Tool host fields ...
  "credential_type": "ssh | wmi | snmp | none",
  "os_version": "Ubuntu 22.04.3 LTS",
  "kernel_version": "5.15.0-91-generic",
  "installed_packages": [{"name": "...", "version": "..."}],
  "running_services": ["sshd", "nginx", "postgresql"],
  "cve_matches": [{
    "cve_id": "CVE-2024-1234",
    "cvss_v3_score": 9.8,
    "severity": "CRITICAL",
    "kev": True,
    "kev_required_action": "...",
    "product": "OpenSSH 8.2",
    "description": "...",
    "fix_available": True
  }],
  "patch_status": {
    "last_update": "2024-11-15",
    "pending_updates": 12,
    "days_since_update": 94,
    "update_manager": "apt | yum | Windows Update"
  },
  "user_accounts": [{"username": "...", "last_login": "..."}],
  "ssh_config_audit": {
    "permit_root_login": True,
    "password_auth": True,
    "weak_ciphers": ["arcfour"],
    "protocol_v1": False
  },
  "smb_shares": [{"name": "...", "path": "...", "access": "Everyone"}],
  "windows_firewall": {"domain": "enabled", "private": "disabled", "public": "enabled"},
  "antivirus": {"product": "...", "definition_age_days": 12, "status": "current | stale | missing"},
  "snmp_data": {"firmware": "...", "model": "...", "interface_count": 24},
  "risk_score": 0,
  "risk_level": "HIGH",
  "top_risks": [...]
}
```

### Scan phases

- [ ] **Phase 1: Reconnaissance**
  - [ ] Detect local subnets (all active interfaces, exclude loopback/docker/virtual)
  - [ ] Identify default gateway, DNS servers
  - [ ] Public IP lookup (`ipify.org`)
  - [ ] Apply subnet labels from config

- [ ] **Phase 2: Host Discovery**
  - [ ] ARP scan (`arp-scan --localnet`) for local subnet
  - [ ] fping sweep across all detected subnets
  - [ ] nmap `-sn` ping scan as fallback
  - [ ] Merge + deduplicate by IP, record MAC + OUI vendor

- [ ] **Phase 3: Port Scanning**
  - [ ] nmap `-sV --version-intensity 5 --top-ports N` (N from config, default 1000)
  - [ ] `--script=banner` for basic banner grabbing
  - [ ] Full scan (`-p-`) when `port_scan_full: true`
  - [ ] Parse nmap XML output (`-oX`) into structured service dicts
  - [ ] Assign `category` (Server / Workstation / Network / Printer / IoT / etc.)

- [ ] **Phase 4: Service Version Detection + NSE CVE Scripts**
  - [ ] Run `--script=vulners,vulscan` if `enable_nse_vulners: true`
  - [ ] Parse NSE CVE output — seed `host["cve_matches"]`
  - [ ] Extract `{vendor, product, version}` tuples from service banners (Apache, nginx, OpenSSH, IIS, etc.) for Phase 8 CVE lookup

- [ ] **Phase 5: Credentialed SSH Scan** (`lib/ssh_scanner.py`)
  - [ ] `scan_host_ssh(ip, credential_profile) -> dict`
  - [ ] Connect via `paramiko` (username/password or key)
  - [ ] Collect with 15-second per-command timeout:
    - [ ] `uname -a` + `cat /etc/os-release` → OS, kernel, distro
    - [ ] `dpkg -l` / `rpm -qa` / `apk list` → installed packages with versions
    - [ ] `systemctl list-units --state=running` → active services
    - [ ] `ss -tlnp` → listening ports (cross-validate against nmap)
    - [ ] `cat /etc/ssh/sshd_config` → SSH configuration audit
      - [ ] Flag: `PermitRootLogin yes`
      - [ ] Flag: `PasswordAuthentication yes` (keys preferred)
      - [ ] Flag: weak ciphers (arcfour, 3des, blowfish present in Ciphers line)
      - [ ] Flag: `Protocol 1` still listed
    - [ ] `last -n 20` → recent login history
    - [ ] `awk -F: '($3 >= 1000) {print $1}' /etc/passwd` → non-system local users
    - [ ] `apt list --upgradable 2>/dev/null | wc -l` OR `yum check-update --quiet | wc -l` → pending update count
    - [ ] Check for unattended-upgrades / automatic security updates config
    - [ ] `find /tmp /var/tmp -perm -0002 -maxdepth 1 2>/dev/null` → world-writable dirs
    - [ ] `crontab -l` + `ls /etc/cron.d/` → suspicious scheduled entries
  - [ ] Partial results are acceptable — log each step individually; skip and continue on error

- [ ] **Phase 6: Credentialed Windows Scan** (`lib/wmi_scanner.py`)
  - [ ] `scan_host_wmi(ip, credential_profile) -> dict`
  - [ ] Try WinRM (port 5985/5986 via `pypsrp`) first; fall back to WMI DCOM (`impacket`) if WinRM unavailable
  - [ ] Collect with 30-second timeout:
    - [ ] `Win32_OperatingSystem` → OS version, build, install date, last boot
    - [ ] `Win32_QuickFixEngineering` → installed KBs + install dates; flag if newest KB > 90 days old
    - [ ] Registry fallback for installed software (faster than `Win32_Product`)
    - [ ] `Win32_ComputerSystem` → domain membership, manufacturer, model
    - [ ] `Win32_UserAccount WHERE LocalAccount=True` → local accounts; flag enabled built-in Administrator
    - [ ] `Win32_Service WHERE State='Running'` → running services; flag known-suspicious names
    - [ ] Windows Firewall profiles via `Get-NetFirewallProfile` (WinRM) or `NetFwPolicy2` (WMI) — flag any disabled profile
    - [ ] Antivirus via `SecurityCenter2\AntiVirusProduct` — flag missing AV or definitions > 7 days old
    - [ ] Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` → autorun entries; flag non-Microsoft/non-vendor entries
    - [ ] SMB shares via `Win32_Share` — flag non-admin shares accessible without auth
    - [ ] RDP enabled status via registry `fDenyTSConnections`
    - [ ] UAC status via registry `EnableLUA` — flag if disabled

- [ ] **Phase 7: SNMP Network Equipment Scan** (`lib/snmp_scanner.py`)
  - [ ] `scan_host_snmp(ip, credential_profile) -> dict`
  - [ ] Use `pysnmp` for SNMP v2c and v3
  - [ ] Collect standard MIBs:
    - [ ] `sysDescr` → firmware/OS description string for CVE extraction
    - [ ] `sysName`, `sysContact`, `sysLocation`
    - [ ] `ifTable` → interface table (name, speed, status, in/out error counters)
    - [ ] `ipAddrTable` → IP address table
    - [ ] `ipNetToMediaTable` → ARP table (topology enrichment)
  - [ ] **Cisco-specific** (when `sysDescr` contains "Cisco"):
    - [ ] Attempt `CISCO-VERSION-MIB::ciscoImageString` → IOS/IOS-XE version string
  - [ ] **Fortinet-specific** (when `sysDescr` contains "FortiOS"):
    - [ ] Attempt `fnSysVersion` → firmware version
  - [ ] **Aruba/HPE-specific** (when `sysDescr` contains "Aruba" or "ArubaOS"):
    - [ ] Attempt `wlsxSystemSoftwareVersion` → ArubaOS version
  - [ ] Parse firmware version string → `{vendor, product, version}` for Phase 8 CVE lookup
  - [ ] Flag: SNMP v1 or v2c in use (recommend v3)
  - [ ] Flag: default community strings `public` or `private` accepted

- [ ] **Phase 8: CVE Correlation**
  - [ ] Collect all `{vendor, product, version}` tuples from: nmap banners, SSH packages, WMI software, SNMP firmware
  - [ ] Call `vuln_db.lookup_cves()` for each tuple
  - [ ] Deduplicate by CVE ID (same CVE from multiple sources = one entry)
  - [ ] Set `kev=True` for each CVE ID found in CISA KEV catalog
  - [ ] Sort: KEV CVEs first, then by CVSS score descending
  - [ ] Cap at `max_cves_per_host` from config
  - [ ] Store in `host["cve_matches"]`

- [ ] **Phase 9: Configuration Audit**
  - [ ] SSL/TLS audit (adapt from Discovery Tool)
    - [ ] Add TLS 1.0/1.1 still-enabled detection
    - [ ] Add certificate chain validation
  - [ ] SMB audit via nmap NSE scripts:
    - [ ] `smb-security-mode` → signing required?
    - [ ] `smb-vuln-ms17-010` (EternalBlue) → CRITICAL if positive
    - [ ] `smb2-security-mode`
  - [ ] Web admin interface detection:
    - [ ] Flag HTTP (non-TLS) admin pages on network gear (ports 80, 8080)
    - [ ] Flag default login pages accessible without credentials (401/200 probe)
  - [ ] Default credential passive probes (single HTTP request only — no brute force):
    - [ ] Flag Telnet open (port 23) — always HIGH severity
    - [ ] Flag FTP with anonymous login allowed
    - [ ] Flag HTTP admin page responding 200 to unauthenticated request

- [ ] **Phase 10: Risk Scoring**
  - [ ] Call `risk_scorer.score_host(host)` for every host
  - [ ] Call `risk_scorer.score_environment(all_hosts)` for environment score
  - [ ] Store `risk_score` and `risk_level` on each host dict
  - [ ] Sort `hosts` list by `risk_score` descending

- [ ] **Phase 11: Delta Analysis**
  - [ ] Load previous scan via `delta_tracker.load_previous_scan()`
  - [ ] Compute `delta = delta_tracker.compute_delta(current, previous)`
  - [ ] Store `scan_results["delta"] = delta`

---

## Phase 5 — Orchestration (`bin/risk-scanner-main.py`)

- [ ] `load_config(path) -> dict`
- [ ] `apply_log_level(config)`
- [ ] `acquire_lock()` / `release_lock()` — prevent concurrent scans
- [ ] `manage_disk_space(config)` — prune oldest `data/history/*.json.gz` if free disk < threshold
- [ ] `update_vuln_db_if_due(config)` — compare `vuln_db_stats.last_updated` to `vuln_db_update_interval_days`; update if due
- [ ] `run_scan(config) -> dict` — import and execute scan engine
- [ ] `save_scan_results(results, data_dir)` — gzip JSON to `data/history/scan_TIMESTAMP.json.gz`
- [ ] `get_hatz_insights(results, delta, config)` — call hatz_ai, store in `results["ai_insights"]`
- [ ] `generate_reports(results, config) -> list[Path]` — call all three report generators, return PDF paths
- [ ] `send_weekly_report(results, report_paths, config)` — email HTML body + attach PDFs via graph_mailer
- [ ] `cleanup_after_send(data_dir)` — keep `.gz` history archives; remove temp uncompressed files
- [ ] `main()` — full orchestrated workflow with try/except and graceful degradation at each stage
- [ ] Support `--scan-only` flag (scan + save, no report generation or email)
- [ ] Support `--report-only` flag (load latest scan, generate reports, send email)
- [ ] Handle `SIGTERM` / `SIGINT` cleanly (release lock, log shutdown reason)

---

## Phase 6 — Report Generators

### 6a. `lib/report_generator.py` — HTML Email Report

Build a weekly HTML digest email (all CSS inline for email client compatibility):

- [ ] **Header band** — brand color, company name, "Weekly Risk Report", date range
- [ ] **Risk score hero** — large current environment score with delta arrow (↑ worse / ↓ better / → stable), color-coded by severity band
- [ ] **Delta summary box** — "X new issues | Y resolved | Z recurring | W new KEV CVEs"
- [ ] **CISA KEV alert block** — red highlighted box listing newly matched KEV CVEs: CVE ID, affected host, CISA required action, due date
- [ ] **Top 10 risks table** — columns: Host | Finding | CVE ID | CVSS | Severity | KEV flag | New/Recurring badge
- [ ] **Critical & High hosts** — summary card per host: IP, hostname, category, risk level badge, top 3 risk items
- [ ] **Credential coverage summary** — table: Host | SSH | WMI | SNMP result icons (checkmark / X / dash)
- [ ] **New hosts detected** — green callout listing any hosts appearing for the first time
- [ ] **Resolved findings** — green list of items fixed since last scan
- [ ] **AI insights block** — Hatz AI narrative (skip gracefully if not configured)
- [ ] **Device inventory table** — all hosts sorted by risk score (truncate inline if >50; full list in JSON attachment)
- [ ] **Vulnerability DB status** — NVD version date, CVE count, KEV count, last updated
- [ ] **Operational stats** — scan duration, phases completed, credential coverage percentage
- [ ] Limit total HTML to ~3 MB (Graph API attachment limits)

### 6b. `lib/executive_report.py` — Executive Summary PDF

Designed for non-technical leadership. ReportLab canvas drawing (same style as Discovery Tool):

- [ ] **Page 1: Cover**
  - [ ] "Prepared for: {client_name}" + report date range
  - [ ] Title: "Weekly Cyber Risk Assessment — Executive Summary"
  - [ ] Risk score gauge (radial dial 0–100, same ReportLab style as Discovery Tool)
  - [ ] Assessor branding (company_name, tagline, brand color)

- [ ] **Page 2: Risk Score Trend**
  - [ ] Bar or line chart: risk score per week for last 12 weeks (ReportLab drawing API — no matplotlib dependency)
  - [ ] Color each bar by severity band (red/orange/yellow/green)
  - [ ] Annotate any week with a new KEV CVE match
  - [ ] Summary line: "Trend: improving / stable / worsening over last 4 weeks"

- [ ] **Page 3: Key Findings This Week**
  - [ ] Top 5 findings in non-technical plain language
  - [ ] "ACTIVELY EXPLOITED" badge for any KEV CVE
  - [ ] "NEW THIS WEEK" badge on newly introduced findings
  - [ ] Resolved items in green with checkmark

- [ ] **Page 4: AI Executive Summary** (when Hatz AI configured)
  - [ ] Render `## Executive Summary` section as body text
  - [ ] Render `## Critical Actions (This Week)` as numbered steps
  - [ ] Render `## Positive Security Controls` as green bullet points
  - [ ] Skip page gracefully when AI not available

- [ ] **Page 5: Risk by Host Category**
  - [ ] Horizontal bar chart: Servers / Workstations / Network Gear / Printers / IoT
  - [ ] Each bar colored by max risk level of hosts in that category
  - [ ] Device count + risk score average per category

- [ ] **Page 6: Security Posture Summary**
  - [ ] Traffic-light table (GREEN / AMBER / RED) across 10 control areas, derived from scan data:
    - Patch Management (days since last update, pending count)
    - Authentication (MFA/RDP exposure, default creds detected)
    - Firewall (coverage, rules, disabled profiles)
    - Antivirus / EDR (coverage, definition age)
    - Backup & DR (detected backup software, NAS presence)
    - Encryption (TLS versions, self-signed certs, expired certs)
    - Remote Access (RDP exposed, Telnet open, VPN present)
    - Network Segmentation (VLAN presence, guest network)
    - Email Security (SPF/DKIM/DMARC posture)
    - EOL Devices (count, most critical EOL item)

- [ ] Standard footer on every page: brand name, date, page number, "CONFIDENTIAL"

### 6c. `lib/detail_report.py` — Technical Detail PDF

- [ ] **Page 1: Cover** — titled "Weekly Cyber Risk Assessment — Technical Detail"

- [ ] **Page 2: Scan Coverage & Methodology**
  - [ ] Subnets scanned, total hosts, scan duration
  - [ ] Credential coverage table (SSH/WMI/SNMP counts + success rates)
  - [ ] CVE DB version (NVD date, KEV count, last updated)
  - [ ] Phases completed, any phases skipped (with reason)
  - [ ] Exclusions applied

- [ ] **Page 3: Environment Risk Summary**
  - [ ] Risk score breakdown: CRITICAL/HIGH/MEDIUM/LOW host counts
  - [ ] Total CVE matches by severity
  - [ ] CISA KEV matches — full detail table: CVE ID | Host | Product | Required Action | Due Date
  - [ ] Delta summary: X new findings, Y resolved, Z recurring

- [ ] **Pages 4+: Per-Host Finding Pages** (one page per CRITICAL/HIGH host; MEDIUM hosts grouped)
  - [ ] Host header bar: IP | Hostname | OS | Category | Risk score badge
  - [ ] CVE table: CVE ID | CVSS v3 | Severity | KEV | Affected Product | Description | Fix Available
  - [ ] Configuration findings: bulleted list (SSH issues, missing patches, open shares, firewall, AV status)
  - [ ] Patch status: last update date, pending count, days stale (flag red if > 90)
  - [ ] Open ports table: Port | Service | Version | Notes
  - [ ] Per-host AI narrative block (when `enable_per_host_narrative: true`)

- [ ] **Appendix A: Full Host Inventory**
  - [ ] Table: IP | Hostname | Category | OS | Risk Level | CVE Count | Top CVE ID
  - [ ] Sorted by risk score descending

- [ ] **Appendix B: All CVEs Detected**
  - [ ] Deduplicated across all hosts
  - [ ] Columns: CVE ID | CVSS | Severity | KEV | Affected Hosts | Product | Fix Available
  - [ ] Sorted: KEV first, then CVSS descending

---

## Phase 7 — Systemd Units

- [ ] **`risk-scanner-checkin.service`**
  - [ ] Type=oneshot, runs once on boot after `network-online.target`
  - [ ] Sends check-in email: device info, local/WAN IP, next scan time, CVE DB status
  - [ ] Sets `checkin_sent` flag file after first successful send

- [ ] **`risk-scanner-daily.service`**
  - [ ] Type=simple; started by timer
  - [ ] `ExecStart=/opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/risk-scanner-main.py --scan-only`
  - [ ] `User=risk-scanner`
  - [ ] `TimeoutStartSec=7200` (up to 2 hours for full credentialed scan)
  - [ ] Hardening: `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`

- [ ] **`risk-scanner-daily.timer`**
  - [ ] `OnCalendar=*-*-* 02:00:00` (time written by installer from wizard input)
  - [ ] `RandomizedDelaySec=600`
  - [ ] `Persistent=true` (catch up if device was offline at scheduled time)

- [ ] **`risk-scanner-report.service`**
  - [ ] `ExecStart=... risk-scanner-main.py --report-only`
  - [ ] Reads most recent scan JSON, generates PDFs, sends email

- [ ] **`risk-scanner-report.timer`**
  - [ ] `OnCalendar=Monday 06:00:00` (configurable day/time written by installer)
  - [ ] `Persistent=true`

---

## Phase 8 — Management Scripts

- [ ] **`bin/manual-scan.sh`** — start daily service, tail logs, print findings summary on exit
- [ ] **`bin/manual-report.sh`** — run `--report-only`; support `--output DIR` and `--no-email`
- [ ] **`bin/add-credential.sh`** — interactive wizard to add/update credential profile; runs `test-credential.sh` on completion
- [ ] **`bin/test-credential.sh [IP]`** — resolve and test best-matching credential for given IP; print connection result + collected OS info
- [ ] **`bin/view-risks.sh`** — terminal risk summary from latest scan; support `--host IP` for per-host detail
- [ ] **`bin/update-config.sh`** — re-run config wizard (preserves credential profiles)
- [ ] **`bin/update-vuln-db.py`** — `--init`, `--update`, `--stats` modes; `--nvd-api-key KEY` override
- [ ] **`bin/self-update.sh`** — `git pull --ff-only`, `pip install -r requirements.txt`, `systemctl daemon-reload` if unit files changed

---

## Phase 9 — `bin/initial-checkin.py`

- [ ] Copy pattern from Discovery Tool's `initial-checkin.py`
- [ ] Email content:
  - [ ] Device hostname, all interface IPs, MAC, public WAN IP
  - [ ] Next scheduled daily scan time
  - [ ] Next scheduled weekly report time
  - [ ] CVE database status (CVE count, KEV count, last updated, stale warning if > 3 days)
  - [ ] Credential profiles loaded (count + types — never show passwords)
  - [ ] Config feature flags summary
- [ ] Run `self-update.sh` before check-in (non-fatal)
- [ ] Set `data/.checkin_sent` flag file — only sends once per install

---

## Phase 10 — Security Hardening

- [ ] **Credential encryption**: AES-256 via Python `cryptography` library; key derived from `/etc/machine-id` + device_name via PBKDF2; credentials non-portable between devices
- [ ] **SSH keypair option**: Installer can generate an Ed25519 keypair for the service user; print public key for customer to deploy to target hosts
- [ ] **Log sanitization**: Mask all passwords, API keys, community strings in all log lines; redact with `***`
- [ ] **Scan guardrails** (enforce in code, document in README):
  - [ ] No brute-force attempts — single-probe passive checks only
  - [ ] No exploitation — enumeration and observation only
  - [ ] `excluded_hosts` from config is respected in every scan phase
  - [ ] Log disclaimer at scan start: "Authorized credentialed scan — client: {client_name}"
- [ ] **File permissions**: `config.json` mode 640, `credentials.enc` mode 600, `logs/` mode 750

---

## Phase 11 — Testing Checklist

- [ ] **Unit tests** (`test/`)
  - [ ] `test_vuln_db.py` — CVE lookup, CVSS scoring, KEV flag, DB stats
  - [ ] `test_risk_scorer.py` — score calculation, severity classification, environment scoring
  - [ ] `test_delta_tracker.py` — diff computation, new/resolved/recurring detection, trend extraction
  - [ ] `test_credential_store.py` — encrypt/decrypt roundtrip, profile resolution by IP/subnet
  - [ ] `test_hatz_ai.py` — mock API response, section parsing, graceful failure on None return

- [ ] **Integration tests** (manual, run on Pi against test lab)
  - [ ] SSH scan vs known Linux host — verify package list, pending updates, and SSH config flags collected
  - [ ] WMI scan vs known Windows host — verify KB list, AV status, firewall status collected
  - [ ] SNMP scan vs known switch — verify sysDescr and ifTable collected; firmware CVE matched
  - [ ] CVE correlation vs host with known-vulnerable service version (e.g. OpenSSH 8.2 — should match CVEs)
  - [ ] Delta: run two scans; second scan should show delta with added/removed host
  - [ ] Full workflow end-to-end: scan → delta → AI → HTML email → Executive PDF → Detail PDF
  - [ ] `--report-only` from saved JSON generates identical output to scan-triggered report

- [ ] **Report rendering validation**
  - [ ] Executive PDF renders cleanly (no ReportLab canvas overflow, no text overlap)
  - [ ] Detail PDF renders all per-host pages without content overflowing footers
  - [ ] Trend chart renders correctly for 1 week, 4 weeks, 12 weeks of data
  - [ ] HTML email is < 3 MB on a 100-host environment
  - [ ] All three attachments send successfully via Graph API
  - [ ] Reports render correctly with zero previous scans (no delta available)
  - [ ] Reports render correctly with AI insights absent (static fallback text)

---

## Phase 12 — Documentation

- [ ] **`README.md`** (full documentation, mirror Discovery Tool README style)
  - [ ] What it does, how it differs from the Discovery Tool, requirements
  - [ ] Quick start / installation
  - [ ] Architecture diagram
  - [ ] Configuration reference table (all config.json keys)
  - [ ] Credential profile setup guide (SSH key, WMI/WinRM enabling, SNMP v3 setup)
  - [ ] Report types description
  - [ ] Management scripts reference
  - [ ] Security considerations (credential encryption, scan ethics)
  - [ ] Self-maintenance section

- [ ] **`GRAPH_API_SETUP.md`** — link to or copy from Discovery Tool (same Azure App Registration setup)
- [ ] **`TROUBLESHOOTING.md`**
  - [ ] SSH: wrong credentials / host key verification failure / port 22 blocked
  - [ ] WMI: access denied / WinRM not enabled / Windows Firewall blocking RPC
  - [ ] SNMP: no response / wrong community string / SNMP disabled on device
  - [ ] NVD API: rate limiting / no API key configured
  - [ ] CVE DB stale: manual update command
  - [ ] Credential decryption failure after Pi OS reinstall (machine-id changed)
  - [ ] Graph API auth failure / token expiry

---

## Dependency Reference (`requirements.txt`)

```
msal>=1.28.0
reportlab>=4.2.0
cryptography>=42.0.0
paramiko>=3.4.0
pysnmp>=4.4.12
impacket>=0.12.0
pypsrp>=0.8.0
requests>=2.31.0
python-dateutil>=2.9.0
```

---

## Key Design Decisions to Validate Before Building

- [ ] **WMI vs WinRM strategy**: Try WinRM (port 5985) first — faster and more reliable. Fall back to WMI DCOM via impacket (port 135) for hosts where WinRM is not enabled. Document both paths in TROUBLESHOOTING.md.
- [ ] **NVD API key**: Strongly recommend customers register for a free NVD API key (50 req/30s vs 5 req/30s without). Initial seed without a key may take 30–60 minutes due to rate limiting. Document in README.
- [ ] **CVE DB storage size**: Full NVD cache is ~2 GB. Default filter to last 5 years (~400 MB) via `vuln_db_max_age_years`. This covers nearly all actively exploited CVEs. Make it configurable.
- [ ] **Scan duration**: A full credentialed scan of 50 hosts (SSH + WMI + CVE correlation) typically takes 30–90 minutes. Default `scan_timeout: 3600`. Communicate this clearly in README.
- [ ] **Report-only mode**: `--report-only` must regenerate reports from saved scan JSON without any network activity. This allows re-running report generation after template changes without needing to re-scan.
- [ ] **MSP-agnostic branding**: All client-facing PDF text must use `reporting.company_name` from config. "Powered by Yeyland Wutani" footer in PDFs is intentional and always present (same pattern as Discovery Tool).
- [ ] **Separate install path from Discovery Tool**: Using `/opt/risk-scanner/` avoids any collision with `/opt/network-discovery/` if both tools are deployed on the same Pi.

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
*For authorized use only. Always obtain customer written permission before deploying a credentialed scanner on their network.*
