# Additional Tools Research — Raspberry Pi Network Discovery

**Yeyland Wutani LLC** | Network Discovery Pi | Research Document
*Date: 2026-02-18*

---

## Overview

This document evaluates additional open-source and third-party tools that can be
integrated into or run alongside the Raspberry Pi Network Discovery system to
produce a more comprehensive scan and richer reporting. Each entry includes:

- What it does and why it adds value
- Licensing and Raspberry Pi compatibility
- Integration approach (native Python, subprocess, or standalone agent)
- Installer prerequisites
- Effort estimate (Low / Medium / High)

The current scanner already handles: ARP/ping sweep, nmap port+service+OS
detection, SNMP, SMB/NetBIOS, HTTP banner, mDNS/Bonjour, SSDP/UPnP, DHCP
analysis, NTP, 802.1X detection, OSINT (Shodan InternetDB, crt.sh, DNS security),
SSL/TLS audit, backup posture inference, and EOL detection.

---

## 1. Netdiscover

**What it does:** ARP-based active/passive host discovery. Very fast subnet
sweeps that complement nmap's ARP ping. Particularly useful on busy networks
where fping misses hosts that rate-limit ICMP.

**Value:** Passive mode captures ARP broadcasts *without sending packets*,
enabling completely silent host detection on the local subnet.

**License:** GPL-2.0
**Pi compatibility:** Full (ARM), available in Raspberry Pi OS repo
**Integration:** subprocess call, parse stdout for IP/MAC pairs, merge with
existing ARP table
**Prereqs:** `apt-get install netdiscover`
**Effort:** Low

---

## 2. Masscan

**What it does:** Asynchronous TCP port scanner. Capable of scanning the
internet at 10 Gbps; on a local /24 completes in seconds. Uses raw packet
injection (root required).

**Value:** Dramatically faster than nmap for large subnets (/16 or multiple
subnets). Can pre-scan all 65535 ports to build a target list, then hand off to
nmap only for service/version detection on live ports.

**License:** AGPL-3.0
**Pi compatibility:** Full (ARM); must build from source — no apt package for
Raspberry Pi OS
**Integration:** subprocess; parse JSON output; merge open-port lists into
existing host records before nmap phase
**Prereqs:** `apt-get install build-essential libpcap-dev git`, then
`git clone + make + make install`
**Effort:** Medium (build from source + merge logic)

---

## 3. RustScan

**What it does:** Ultra-fast port scanner written in Rust. Opens ports using
async I/O, then passes confirmed open ports to nmap for service detection.
Often 100× faster than nmap alone for port discovery.

**Value:** Reduces total scan time significantly on large networks. Acts as a
"pre-filter" — only confirmed open ports reach nmap's slower service probe.

**License:** GPL-3.0
**Pi compatibility:** ARM64 binary available; 32-bit (armhf) requires Rust
toolchain build
**Integration:** subprocess; parse `--greppable` output; inject open port list
into nmap `-p` argument
**Prereqs:** Download arm64 release binary from GitHub releases, or
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` + cargo build
**Effort:** Medium (binary fetch + integration)

---

## 4. Nikto

**What it does:** Web server vulnerability scanner. Tests for 6700+ dangerous
files, outdated software, misconfigurations (directory listing, default creds,
outdated headers), and known CVEs on HTTP/HTTPS services.

**Value:** The current scanner only grabs HTTP banners and titles. Nikto
provides actual vulnerability assessment of every web-enabled device — routers,
cameras, NAS boxes, printers, etc.

**License:** GPL-2.0
**Pi compatibility:** Full (Perl-based, runs on all Pi OS variants)
**Integration:** subprocess per HTTP/HTTPS host; parse text output for findings;
add `nikto_findings` field to host record; surface CRITICAL/HIGH findings in
security observations
**Prereqs:** `apt-get install nikto`
**Effort:** Medium (rate-limiting needed; can be slow; add timeout guard)

---

## 5. testssl.sh

**What it does:** Comprehensive TLS/SSL testing script. Tests cipher suites,
protocol versions (SSLv3, TLS 1.0, 1.1, 1.2, 1.3), certificate chain validity,
HSTS, OCSP stapling, known TLS vulnerabilities (POODLE, BEAST, HEARTBLEED,
ROBOT, LUCKY13, etc.).

**Value:** The current SSL audit only checks certificate expiry and self-signed
status via Python's `ssl` module. testssl.sh reveals actual cipher weaknesses
and deprecated protocol support — actionable security findings.

**License:** GPL-2.0
**Pi compatibility:** Full (bash script; no compilation needed)
**Integration:** subprocess per TLS-enabled host/port; parse JSON output (`--jsonfile`);
add `tls_audit` field with cipher/protocol/vulnerability data; new report section
**Prereqs:** `apt-get install openssl bsdmainutils`; download testssl.sh script
to `/opt/network-discovery/bin/testssl.sh`
**Effort:** Medium

---

## 6. enum4linux-ng

**What it does:** Next-generation SMB/LDAP enumeration tool (Python rewrite of
enum4linux). Enumerates: shares, users, groups, password policy, printers, OS
info, domain/workgroup info. Works against Windows, Samba, and domain-joined
systems.

**Value:** The current SMB phase only grabs `smb_computer` name from NBT.
enum4linux-ng provides full Windows domain mapping — users, groups, share
inventory — enormously valuable for MSP assessments.

**License:** GPL-3.0
**Pi compatibility:** Full (Python 3)
**Integration:** subprocess per SMB host (port 139/445); parse JSON output;
add `smb_enumeration` field; new "SMB / Windows Environment" report section
**Prereqs:** `pip install impacket ldap3 msldap`; clone from GitHub
**Effort:** Medium-High (parsing + report section)

---

## 7. arp-fingerprint (p0f / p0f3)

**What it does:** Passive OS fingerprinting by analyzing TCP/IP stack
characteristics without sending any probes. p0f identifies OS type, distance
(TTL hops), link type, and uptime purely from observed traffic.

**Value:** Completely passive — zero additional packets sent. Provides OS
identification for devices that block active nmap OS detection (cameras, IoT
devices, printers). Can run continuously alongside the scanner.

**License:** BSD
**Pi compatibility:** Full (C, compiles on ARM)
**Integration:** Run p0f in daemon mode (`-d`) throughout the scan; read its
socket or log file after scanning; merge OS guesses into host records
**Prereqs:** `apt-get install p0f`
**Effort:** Medium (daemon lifecycle management)

---

## 8. Zeek (formerly Bro) — Lightweight Network Monitor

**What it does:** Passive network traffic analysis framework. Logs: DNS queries,
HTTP requests, SSL connections, DHCP leases, SMB sessions, SSH attempts, and
many more protocols. Creates structured JSON logs.

**Value:** Captures traffic the Pi sees during normal operation — a continuous
passive inventory that fills gaps between active scans. Particularly useful for
discovering devices that only appear briefly (VoIP phones, mobile devices,
IoT beacons).

**License:** BSD
**Pi compatibility:** Zeek is heavy (not recommended for Pi Zero/1); suitable
for Pi 4/5 (4GB+ RAM). Lite alternative: `netsniff-ng` or `tcpdump` + Python
parser.
**Integration:** Run Zeek as a service; periodically parse `conn.log`,
`dhcp.log`, `dns.log`; merge observed hosts into discovery data
**Prereqs:** `apt-get install zeek` (may require backports); 2+ GB free RAM
**Effort:** High (heavy dependency; not viable for Pi 3 or earlier)

---

## 9. Nmap NSE Script Expansion

**What it does:** Nmap's scripting engine (NSE) has 600+ scripts for specific
vulnerability checks, service enumeration, and brute-force detection.

**Recommended additions to current scanner:**

| Script | What it checks |
|--------|---------------|
| `http-default-accounts` | Default credentials on common web devices |
| `smb-vuln-ms17-010` | EternalBlue (MS17-010) — WannaCry vector |
| `smb-vuln-ms08-067` | Conficker-era SMB vulnerability |
| `rdp-enum-encryption` | RDP encryption level and NLA enforcement |
| `ftp-anon` | Anonymous FTP login |
| `mysql-empty-password` | MySQL with blank root password |
| `telnet-ntlm-info` | Telnet service fingerprinting |
| `broadcast-dhcp-discover` | DHCP server enumeration (already done natively) |
| `snmp-brute` | Common SNMP community string brute-force |
| `http-shellshock` | Shellshock CGI vulnerability |
| `ssl-poodle` | POODLE vulnerability check |
| `ssl-heartbleed` | Heartbleed check |

**Value:** These are already bundled with nmap — zero new installs. Just extend
the `--script` argument in Phase 3/4.

**License:** nmap NSE (custom open license)
**Pi compatibility:** Full
**Integration:** Extend nmap subprocess arguments; add script output to service
records; flag findings in security observations
**Prereqs:** None (nmap already installed)
**Effort:** Low

---

## 10. Vulners NSE / Vulnerability Correlation

**What it does:** `vulners` NSE script queries the Vulners.com API (free tier
available) to look up CVEs matching detected service versions. Returns CVE IDs,
CVSS scores, and exploit availability.

**Value:** Transforms service version detection into actionable CVE data without
requiring Shodan. Complements the existing Shodan InternetDB lookup with
*internal* device CVE mapping.

**License:** MIT (script); Vulners API (free tier)
**Pi compatibility:** Full
**Integration:** Add `--script vulners` to nmap Phase 3; parse script output;
add `cves` list to service records; surface CVSS ≥ 7.0 findings in security
observations
**Prereqs:** nmap already installed; script auto-fetches from Vulners API
**Effort:** Low

---

## 11. netdata (Lightweight Performance Monitoring)

**What it does:** Real-time performance monitoring for the Pi itself and network
metrics. Collects: CPU, RAM, disk I/O, network throughput, and can alert on
anomalies.

**Value:** Operational visibility into the Pi's health. Helps diagnose slow
scans (CPU throttling, memory pressure) and confirms the Pi is healthy between
scheduled runs. Optional web dashboard.

**License:** GPL-3.0 + Apache-2.0
**Pi compatibility:** Full; Pi 4 recommended
**Integration:** Standalone service; Pi health metrics added to "Operational
Statistics" report section
**Prereqs:** `bash <(curl -Ss https://my-netdata.io/kickstart.sh)` or
`apt-get install netdata`
**Effort:** Low (optional; no scan integration required)

---

## 12. SpeedTest CLI (network baseline)

**What it does:** Measures WAN download/upload speeds and latency to the
nearest Speedtest.net server.

**Value:** Adds ISP bandwidth baseline to the report — relevant for MSP
assessments where the client's internet performance is under evaluation.

**License:** Apache-2.0 (official Ookla CLI)
**Pi compatibility:** Full (ARM binary available)
**Integration:** Run once per scan during Phase 13 (OSINT); add
`bandwidth_test` to `reconnaissance` data; display in Network Overview section
**Prereqs:** Download arm binary from Speedtest CLI GitHub releases
**Effort:** Low

---

## 13. iperf3 (LAN Throughput Testing)

**What it does:** Measures TCP/UDP throughput between two endpoints. Requires a
server on the network or a known iperf3 public server.

**Value:** Validates that the LAN can sustain expected throughput — identifies
bottlenecks (bad cables, duplex mismatch, overloaded switches).

**License:** BSD
**Pi compatibility:** Full
**Integration:** Optional phase; requires target IP from config; add
`lan_throughput` to results; display in Network Overview
**Prereqs:** `apt-get install iperf3`; target must also run iperf3 in server mode
**Effort:** Low-Medium (config + optional execution)

---

## 14. Bloodhound / SharpHound (AD Path Analysis)

**What it does:** Active Directory attack path visualizer. Maps relationships
between users, groups, computers, and permissions to identify privilege
escalation paths (e.g., "User X can reach Domain Admin in 3 hops").

**Value:** The current AD section enumerates domain structure via LDAP. Bloodhound
reveals *exploitable paths* — a critical MSP security deliverable.

**License:** GPL-3.0 (Bloodhound CE — Community Edition)
**Pi compatibility:** Bloodhound CE requires Neo4j (not practical on Pi). The
data *collection* (SharpHound / BloodHound.py) can run from the Pi; analysis
runs on a separate workstation.
**Integration:** Run `bloodhound-python` against detected DCs; save JSON output
files to `/opt/network-discovery/data/bloodhound/`; include download link in
report
**Prereqs:** `pip install bloodhound`; domain user credentials required (not
fully passive)
**Effort:** High (requires credentials; output not easily embedded in email
report)

---

## 15. Wireless IDS Detection (Kismet)

**What it does:** Passive wireless network detector and packet sniffer. Detects
rogue access points, deauth attacks, WPS vulnerabilities, hidden SSIDs, and
clients probing for known networks.

**Value:** The current WiFi phase uses `iw scan` — active scanning that only
sees broadcast SSIDs. Kismet provides passive deep analysis and anomaly
detection, including evil twin detection and aircrack-style vulnerability checks.

**License:** GPL-2.0
**Pi compatibility:** Full (natively supports Pi WiFi chipsets)
**Integration:** Run Kismet briefly (~60 seconds) per scan; export to JSON;
add `wireless_ids` section to report with detected anomalies
**Prereqs:** `apt-get install kismet`; WiFi adapter must support monitor mode
(built-in Pi WiFi does; may need `iw phy0 interface add mon0 type monitor`)
**Effort:** High (monitor mode setup, Kismet config, output parsing)

---

## Recommended Priority Implementation Order

| Priority | Tool | Reason |
|----------|------|---------|
| 1 | **Nmap NSE expansion** (EternalBlue, Heartbleed, etc.) | Zero new prereqs; immediate security value |
| 2 | **Vulners NSE** | Zero new prereqs; internal CVE mapping |
| 3 | **testssl.sh** | High-value TLS findings; easy integration |
| 4 | **Nikto** | Web vuln scanning; single apt install |
| 5 | **SpeedTest CLI** | WAN baseline; easy; MSP-relevant |
| 6 | **enum4linux-ng** | Deep Windows/SMB inventory |
| 7 | **Netdiscover** | Passive ARP; complements ARP sweep |
| 8 | **Masscan / RustScan** | Speed for large networks |
| 9 | **p0f** | Passive OS fingerprinting |
| 10 | **Kismet** | Deep wireless IDS (Pi 4+ only) |

---

## Notes on Pi Hardware Constraints

- **Pi Zero / Pi 1 / Pi 2:** Limited to lightweight tools (NSE, testssl.sh,
  Netdiscover, SpeedTest). Avoid Masscan (raw packets stress limited CPU) and
  Zeek (memory).
- **Pi 3:** Suitable for all "Low" and "Medium" effort tools. Zeek not
  recommended.
- **Pi 4 / Pi 5 (4GB+):** All tools viable including Kismet and enum4linux-ng
  for larger networks.

All tools are installable automatically via `apt-get` or
`pip install` / binary download — no manual compilation needed except Masscan.
