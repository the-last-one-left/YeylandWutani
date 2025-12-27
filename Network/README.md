# Network

Network discovery, connectivity testing, and documentation tools for MSP environments.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-NetworkDiscovery.ps1` | Comprehensive network discovery with auto-subnet detection, device classification, MAC vendor lookup, and port scanning |
| `Test-NetworkConnectivity.ps1` | Advanced connectivity testing with ping, port checks, DNS resolution, and traceroute |

---

## Get-NetworkDiscovery.ps1

**Key Features:**
- Auto-detects local subnets when no parameters provided
- Parallel scanning (1-500 threads)
- MAC vendor lookup via macvendors.com API
- Device classification: Server, Workstation, Printer, Network Device, Mobile, IoT, Container
- Docker container detection (02:42:xx MAC prefix)
- Smart IoT identification (WiZ, Espressif, Google Home, eero, etc.)
- HTML reports with clickable service links

**Usage Examples:**
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

**Key Features:**
- ICMP ping with latency statistics
- TCP port connectivity testing
- DNS resolution and reverse lookup
- Traceroute analysis
- Continuous monitoring mode

**Usage Examples:**
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

## Requirements

- PowerShell 5.1+
- Network access to target subnets
- ICMP allowed through firewalls
- Internet access for MAC Vendor API (optional)

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
