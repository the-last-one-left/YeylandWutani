# Network

Network discovery, VLAN identification, connectivity testing, SMTP validation, and documentation tools for MSP environments.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-NetworkDiscovery.ps1` | Comprehensive network discovery with auto-subnet detection, device classification, MAC vendor lookup, and port scanning |
| `Get-VLANDiscovery.ps1` | Multi-method VLAN identification using packet capture, DHCP, AD Sites, ARP analysis, and subnet probing |
| `Test-NetworkConnectivity.ps1` | Advanced connectivity testing with ping, port checks, DNS resolution, and traceroute |
| `Test-SMTPConfiguration.ps1` | **NEW** — SMTP relay validation for MFPs, scanners, and applications with M365/Google Workspace/Graph API support |

---

## Test-SMTPConfiguration.ps1

Interactive SMTP testing tool designed for MSP technicians configuring multi-function printers, scanners, and line-of-business applications. Validates settings before deployment to avoid common pitfalls.

### Supported Providers & Methods

| Provider | Method | Server | Port | Auth | Use Case |
|----------|--------|--------|------|------|----------|
| **Microsoft 365** | SMTP AUTH | smtp.office365.com | 587 | User/Pass | Licensed mailbox, simple setup |
| **Microsoft 365** | SMTP Relay | {tenant}.mail.protection.outlook.com | 25 | IP-based | No mailbox license, connector required |
| **Microsoft 365** | Direct Send | {tenant}.mail.protection.outlook.com | 25 | None | Internal recipients only |
| **Microsoft 365** | Graph API | graph.microsoft.com | 443 | OAuth | Modern auth, future-proof |
| **Google Workspace** | SMTP AUTH | smtp.gmail.com | 587 | App Password | Standard, 2000/day limit |
| **Google Workspace** | SMTP Relay | smtp-relay.gmail.com | 587 | IP or Auth | Admin configured, 10K/day limit |
| **Google Workspace** | Restricted | aspmx.l.google.com | 25 | IP allowlist | Gmail/Workspace recipients only |
| **Generic** | Standard | (user specified) | 25/587/465 | Optional | Any SMTP server |

### Test Phases

1. **Port Connectivity** — Validates outbound access to SMTP ports (25, 587, 465)
2. **TLS/Security** — Tests STARTTLS upgrade and TLS version support
3. **SMTP Capabilities** — Enumerates AUTH methods, verifies post-TLS capabilities
4. **DNS Validation** — Confirms MX records point to expected endpoints
5. **Email Delivery** — Sends test message to verify end-to-end functionality

### Usage Examples

```powershell
# Interactive guided mode (recommended for technicians)
.\Test-SMTPConfiguration.ps1 -Interactive

# Microsoft 365 SMTP AUTH
.\Test-SMTPConfiguration.ps1 -Provider Microsoft365 -Method SmtpAuth `
    -FromAddress "scanner@contoso.com" -ToAddress "admin@contoso.com" `
    -Credential (Get-Credential) -GenerateReport

# Microsoft 365 Graph API (modern auth)
.\Test-SMTPConfiguration.ps1 -Provider Microsoft365 -Method GraphApi `
    -FromAddress "noreply@contoso.com" -ToAddress "admin@contoso.com" `
    -TenantId "xxxx" -ClientId "xxxx" -ClientSecret "xxxx"

# Google Workspace with app password
.\Test-SMTPConfiguration.ps1 -Provider GoogleWorkspace -Method SmtpAuth `
    -FromAddress "scanner@company.com" -ToAddress "admin@company.com" `
    -AppPassword "xxxx xxxx xxxx xxxx"

# Port connectivity test only
.\Test-SMTPConfiguration.ps1 -Interactive
# Then select option 4: "Port Connectivity Test Only"
```

### Common Pitfall Detection

| Issue | Detection | Recommendation |
|-------|-----------|----------------|
| SMTP AUTH disabled | Auth capability check | Enable per-mailbox in M365 Admin or EAC |
| Security defaults blocking | 5.7.57 error parsing | Disable security defaults or use CA exclusion |
| Port 25 blocked | Connectivity timeout | Use port 587, or contact ISP |
| App password required | Google 2FA detected | Generate at myaccount.google.com |
| Graph API permission denied | ErrorAccessDenied | Grant Mail.Send + admin consent |
| Sender address mismatch | 5.7.60 error | From must match authenticated user |

### Important Dates

- **M365 Basic Auth Deprecation**: March 2026 (full enforcement April 30, 2026)
- **Google Less Secure Apps**: Deprecated May 2025 — app passwords required

### Output

Generates HTML report with:
- Test results summary (pass/fail/warning counts)
- Server configuration details
- Detailed test results with recommendations
- Ready-to-use MFP/device settings block

---

## Get-VLANDiscovery.ps1

Identifies VLANs in use across an environment using multiple native Windows methods. Since 802.1Q VLAN tags are typically stripped by NIC drivers before Windows sees them, this tool combines several inference techniques for comprehensive discovery.

### Discovery Methods

| Method | Description | Confidence | Requirements |
|--------|-------------|------------|--------------|
| **pktmon** | Captures 802.1Q tagged packets at driver level | 95% | Windows 10 2004+, Admin, trunk port |
| **DHCP** | Enumerates scopes from Windows DHCP servers | 90% | RSAT-DHCP, DHCP access |
| **ADSites** | Reads subnet definitions from AD Sites & Services | 85% | Domain-joined, AD module |
| **ARP** | Analyzes neighbor cache to identify unique subnets | 60% | Network access |
| **Routes** | Examines routing table for connected networks | 80% | None |
| **Adapters** | Checks for VLAN-tagged virtual NICs, Hyper-V, NIC teams | 100% | None |
| **Probe** | ICMP probes common gateway addresses (.1, .254) | 70% | Network access |

### Usage Examples

```powershell
# Run all discovery methods
.\Get-VLANDiscovery.ps1

# Quick discovery without packet capture
.\Get-VLANDiscovery.ps1 -Method DHCP,ADSites,ARP,Routes

# Packet capture for 60 seconds (requires trunk port or VLAN-aware NIC)
.\Get-VLANDiscovery.ps1 -Method Pktmon -PktmonDuration 60

# Query specific DHCP server
.\Get-VLANDiscovery.ps1 -Method DHCP -DHCPServer "dhcp01.contoso.com"

# Include remote hosts for broader ARP visibility
.\Get-VLANDiscovery.ps1 -Method ARP -RemoteHosts "dc01","fileserver"

# Probe custom subnet ranges
.\Get-VLANDiscovery.ps1 -Method Probe -ProbeRanges @("10.50.0.0/16", "172.20.0.0/16")

# Export to HTML report
.\Get-VLANDiscovery.ps1 -ExportPath "C:\Reports\VLANs.html"
```

### How It Works

**Why VLAN discovery is tricky on Windows:**
- 802.1Q VLAN tags are Layer 2 constructs
- Most NICs strip VLAN tags before the OS sees the packet
- Windows only sees tagged frames on trunk ports or with VLAN-aware NIC drivers
- Intel/Broadcom NICs may have registry settings to preserve tags (MonitorModeEnabled)

**Best results when:**
- Running from a Domain Controller or server with DHCP module
- AD Sites and Subnets are properly configured
- You have access to multiple hosts for ARP aggregation
- Using a trunk port or promiscuous capture NIC

### Output

The tool produces a consolidated list of discovered VLANs/subnets with:
- VLAN ID (when determinable from scope names, packet tags, or adapter config)
- Subnet in CIDR notation
- Gateway address
- Source of discovery
- Confidence score (higher = more reliable)
- Active host count (from DHCP leases or ARP entries)

---

## Get-NetworkDiscovery.ps1

Comprehensive network discovery with device classification and MAC vendor identification.

### Key Features

- Auto-detects local subnets when no parameters provided
- Parallel scanning (1-500 threads)
- MAC vendor lookup via macvendors.com API
- Device classification: Server, Workstation, Printer, Network Device, Mobile, IoT, Container
- Docker container detection (02:42:xx MAC prefix)
- Smart IoT identification (WiZ, Espressif, Google Home, eero, etc.)
- HTML reports with clickable service links

### Usage Examples

```powershell
# Auto-detect and scan local network
.\Get-NetworkDiscovery.ps1

# Full scan with MAC vendor lookup
.\Get-NetworkDiscovery.ps1 -UseMacVendorAPI -ExportPath "C:\Reports\Network.html"

# Scan specific subnet
.\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -ThrottleLimit 150

# Quick ping-only scan
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -QuickScan

# Scan IP range
.\Get-NetworkDiscovery.ps1 -IPRange "192.168.1.1-192.168.1.50"
```

---

## Test-NetworkConnectivity.ps1

Advanced connectivity testing with multiple diagnostic methods.

### Key Features

- ICMP ping with latency statistics
- TCP port connectivity testing
- DNS resolution and reverse lookup
- Traceroute analysis
- Continuous monitoring mode

### Usage Examples

```powershell
# Basic ping test
.\Test-NetworkConnectivity.ps1 -Target "8.8.8.8"

# Test web server ports with DNS
.\Test-NetworkConnectivity.ps1 -Target "www.company.com" -Port 80,443 -IncludeDNS

# Troubleshoot with traceroute
.\Test-NetworkConnectivity.ps1 -Target "server01" -Port 3389 -IncludeTraceroute

# Continuous monitoring
.\Test-NetworkConnectivity.ps1 -Target "critical-app.company.com" -ContinuousMonitoring -RefreshInterval 30
```

---

## Quick Reference

### SMTP Method Selection

```
Which SMTP method should I use?
    │
    ├─► Need to send to external recipients?
    │       │
    │       ├─► Have a licensed M365 mailbox?
    │       │       YES ──► SMTP AUTH (simplest)
    │       │
    │       ├─► Have static IP + can configure connector?
    │       │       YES ──► SMTP Relay (no mailbox needed)
    │       │
    │       └─► Building an application?
    │               YES ──► Graph API (modern, future-proof)
    │
    └─► Only sending to internal recipients?
            ──► Direct Send (no auth required)
```

### VLAN Discovery Decision Tree

```
Start Here
    │
    ├─► Do you have DHCP admin access?
    │       YES ──► Use -Method DHCP (most reliable, shows scope names)
    │
    ├─► Is this a domain-joined environment?
    │       YES ──► Use -Method ADSites (shows documented subnets)
    │
    ├─► Do you have multiple servers to query?
    │       YES ──► Use -Method ARP -RemoteHosts (aggregates visibility)
    │
    ├─► Is your NIC on a trunk port?
    │       YES ──► Use -Method Pktmon (can see actual VLAN tags)
    │
    └─► None of the above?
            ──► Use -Method Routes,Adapters,Probe (works anywhere)
```

---

## Requirements

| Script | Requirements |
|--------|-------------|
| All scripts | PowerShell 5.1+ |
| Get-NetworkDiscovery | ICMP allowed, Internet for MAC API (optional) |
| Get-VLANDiscovery | RSAT-DHCP, AD module, Admin for pktmon |
| Test-NetworkConnectivity | ICMP/TCP access to targets |
| Test-SMTPConfiguration | Outbound 25/587/465/443, valid credentials |

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
