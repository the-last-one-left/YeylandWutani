# Network

Network discovery, connectivity testing, and documentation tools for MSP client networks.

## Available Scripts

### Network Discovery & Inventory

#### Get-NetworkDiscovery.ps1 (v1.9)
Comprehensive network discovery tool for MSP client onboarding and network documentation.

**Key Features:**
- **Auto-detection**: Automatically discovers and scans all local subnets when no input provided
- Parallel subnet scanning with configurable thread limits (1-500 threads)
- CIDR notation support (e.g., 192.168.1.0/24)
- IP range scanning (e.g., 192.168.1.1-192.168.1.254)
- Batch scanning from IP list files
- Device type identification (Server, Workstation, Printer, Network Device, Mobile, IoT, Container)
- Operating system detection
- **MAC Vendor API**: Online vendor lookup via macvendors.com for comprehensive device identification
- **Docker Container Detection**: Identifies Docker containers by MAC prefix (02:42:xx)
- **Locally Administered MAC Detection**: Identifies VMs and randomized mobile MACs
- **Smart IoT Classification**: Recognizes smart home devices (WiZ, Espressif, Google Home, eero, etc.)
- Port scanning for service identification
- DNS hostname resolution
- Multiple export formats (CSV, JSON, HTML)
- Clickable service links in HTML reports
- Device type icons in HTML reports

**Device Type Detection:**
The script intelligently identifies device types based on:
- **Servers**: Windows Server OS detection, RDP (3389) + SMB (445) open, motherboard vendors with SSH/HTTPS
- **Workstations**: Windows desktop OS, SMB/NetBIOS ports, Dell/HP/Lenovo MACs
- **Printers**: Printer-specific ports (515 LPD, 631 IPP, 9100 raw) + printer vendor MACs
- **Network Devices**: SSH/Telnet/HTTPS with vendor identification (Aruba, WatchGuard, Ubiquiti, eero, etc.)
- **Containers**: Docker containers identified by 02:42:xx MAC prefix
- **IoT Devices**: Smart home vendors (WiZ, Espressif, Google, Nest, Sonos, Ring, etc.)
- **Mobile Devices**: Apple iOS, Samsung, LG, Motorola mobile device MACs
- **Unknown**: Responds to ping but insufficient data for classification

**MAC Vendor Classification:**
| Vendor Pattern | Device Type | Example Devices |
|----------------|-------------|-----------------|
| Docker (02:42:xx) | Container | Docker containers |
| eero, Linksys, MikroTik | Network Device | Mesh WiFi, routers |
| WiZ, Espressif, Tuya | IoT Device | Smart bulbs, ESP32 devices |
| Google, Nest | IoT Device | Chromecast, Nest thermostats |
| Samsung | IoT Device | Smart TVs, appliances |
| ASRock, ASUS, Gigabyte | Server/Workstation | Custom-built systems |
| Dell, Lenovo, HP | Workstation | Business computers |
| Apple | Workstation/Mobile | Macs, iPhones, iPads |

**Common Ports Scanned:**
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 80 (HTTP), 135 (RPC), 139 (NetBIOS)
- 443 (HTTPS), 445 (SMB)
- 3389 (RDP), 8080 (HTTP-Alt)

**Usage Examples:**

```powershell
# Auto-detect and scan local network (NEW!)
.\Get-NetworkDiscovery.ps1

# Auto-scan with MAC vendor API for best device identification
.\Get-NetworkDiscovery.ps1 -UseMacVendorAPI

# Auto-scan with HTML export
.\Get-NetworkDiscovery.ps1 -UseMacVendorAPI -ExportPath "C:\Reports\Network.html"

# Scan specific subnet
.\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24"

# Full scan with MAC vendor lookup
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -UseMacVendorAPI -ExportPath "C:\Reports\Network.html"

# Fast scan multiple subnets (100 threads)
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24","10.0.1.0/24","10.0.2.0/24" -ThrottleLimit 100 -ExportPath "C:\Discovery\MultiSubnet.csv"

# Quick ping-only scan (no port scanning)
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -QuickScan

# Scan specific IP range
.\Get-NetworkDiscovery.ps1 -IPRange "192.168.1.1-192.168.1.50"

# Batch scan from file
Get-Content subnets.txt | .\Get-NetworkDiscovery.ps1 -Quiet -ExportPath "C:\Reports\AllNetworks.json"

# Include offline IPs in report (for IP allocation tracking)
.\Get-NetworkDiscovery.ps1 -Subnet "172.16.0.0/24" -IncludeOffline -ExportPath "C:\IPTracking\Subnet.csv"
```

**Real-World MSP Scenarios:**

**Scenario 1: Quick Network Assessment (NEW!)**
```powershell
# Walk into client site, plug in, auto-discover everything
.\Get-NetworkDiscovery.ps1 -UseMacVendorAPI -ExportPath "C:\Reports\QuickScan.html"

# Script automatically:
# - Detects local subnet(s) from NIC configuration
# - Scans all connected networks
# - Identifies device types including IoT, containers, VMs
# - Exports professional HTML report
```

**Scenario 2: New Client Onboarding**
```powershell
# Day 1 - Initial discovery with full vendor lookup
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24" `
    -UseMacVendorAPI `
    -ThrottleLimit 100 `
    -ExportPath "C:\Clients\ABC_Corp\Initial_Discovery_$(Get-Date -Format 'yyyyMMdd').html"

# Review HTML report with client
# Identify:
# - Servers that need monitoring
# - Workstations for patching
# - Printers for managed print services
# - Network devices (including mesh WiFi like eero)
# - IoT devices (smart home, Google Home, etc.)
# - Docker containers
# - Unknown devices for further investigation
```

**Scenario 3: Docker/Container Environment Discovery**
```powershell
# Scan development network with Docker hosts
.\Get-NetworkDiscovery.ps1 `
    -Subnet "172.16.0.0/24" `
    -UseMacVendorAPI `
    -ExportPath "C:\Reports\ContainerNetwork.html"

# Report will show:
# - Docker containers with blue highlighting (📦 icon)
# - Host servers running containers
# - Differentiate containers from VMs/randomized MACs
```

**Scenario 4: Smart Home/IoT Audit**
```powershell
# Identify all IoT devices on home/small business network
.\Get-NetworkDiscovery.ps1 -UseMacVendorAPI

# Automatically classifies:
# - WiZ smart bulbs → IoT Device
# - Google Home/Chromecast → IoT Device  
# - eero mesh nodes → Network Device
# - Nest thermostats → IoT Device
# - Ring doorbells → IoT Device
# - Espressif/Tuya devices → IoT Device
```

**Scenario 5: Network Audit for Compliance**
```powershell
# Scan all subnets with full device classification
$subnets = "10.0.0.0/24","10.0.1.0/24","10.0.2.0/24","10.0.10.0/24"

$subnets | .\Get-NetworkDiscovery.ps1 `
    -UseMacVendorAPI `
    -ThrottleLimit 200 `
    -IncludeOffline `
    -ExportPath "C:\Audits\Network_Inventory_$(Get-Date -Format 'yyyy-MM-dd').csv"

# Import CSV for analysis
$devices = Import-Csv "C:\Audits\Network_Inventory_2025-12-26.csv"

# Find potential security issues
$devices | Where-Object { $_.Services -match 'Telnet|FTP' }      # Insecure protocols
$devices | Where-Object { $_.DeviceType -eq 'Unknown' }          # Unidentified devices
$devices | Where-Object { $_.DeviceType -eq 'IoT Device' }       # IoT devices (often unsecured)
$devices | Where-Object { $_.Vendor -eq 'Randomized/VM' }        # VMs or randomized MACs
```

**HTML Report Features:**
- Visual dashboard with device type statistics
- Color-coded device categorization:
  - 🖥️ Blue: Servers
  - 💻 Green: Workstations
  - 🖨️ Yellow: Printers
  - 📡 Orange: Network Devices
  - 📱 Purple: Mobile Devices
  - 🔌 Deep Orange: IoT Devices
  - 📦 Light Blue: Containers
- Clickable HTTP/HTTPS/SSH links
- Sortable device inventory table
- IP address, hostname, MAC, vendor, services
- Yeyland Wutani branding (orange/grey)
- Professional client-deliverable format

**Performance Optimization:**
- Default: 100 parallel threads (balanced)
- Fast LANs: 150-200 threads (faster, higher network load)
- Slow/WAN links: 25-50 threads (slower, gentler on network)
- Massive networks: 200-500 threads (very fast, requires powerful hardware)

**MAC Vendor API Notes:**
- Uses macvendors.com free API
- Rate limited: 1 request/second (automatically throttled)
- Results cached to avoid duplicate lookups
- Fallback to local 150+ vendor OUI database if API unavailable

---

### Network Connectivity Testing

#### Test-NetworkConnectivity.ps1
Advanced connectivity testing and diagnostics for troubleshooting.

**Key Features:**
- ICMP ping with latency statistics (min/max/avg)
- TCP port connectivity testing
- DNS resolution and reverse DNS lookup
- Traceroute with hop-by-hop analysis
- Continuous monitoring mode
- Batch testing from file or pipeline
- Email alerting for failures
- Multiple export formats

**Usage Examples:**
```powershell
# Basic ping test
.\Test-NetworkConnectivity.ps1 -Target "8.8.8.8"

# Test web server connectivity
.\Test-NetworkConnectivity.ps1 -Target "www.company.com" -Port 80,443 -IncludeDNS

# Troubleshoot RDP connectivity
.\Test-NetworkConnectivity.ps1 -Target "server01" -Port 3389 -IncludeTraceroute

# Continuous monitoring
.\Test-NetworkConnectivity.ps1 `
    -Target "critical-app.company.com" `
    -Port 443,8080 `
    -ContinuousMonitoring `
    -RefreshInterval 30

# Batch test multiple targets
Get-Content servers.txt | .\Test-NetworkConnectivity.ps1 `
    -Port 80,443,3389 `
    -ExportPath "C:\Reports\Connectivity.html"
```

---

## Common Workflows

### Quick Network Assessment (NEW!)
```powershell
# Fastest way to discover a network - just run the script!
.\Get-NetworkDiscovery.ps1 -UseMacVendorAPI -ExportPath "C:\Reports\Discovery.html"

# The script will:
# 1. Auto-detect your local subnet(s) from NIC configuration
# 2. Scan all detected networks in parallel
# 3. Identify all device types including IoT and containers
# 4. Generate a professional HTML report
```

### New Client Onboarding
```powershell
# Day 1 - Network Discovery with full classification
$clientName = "ABC Corporation"
$timestamp = Get-Date -Format "yyyyMMdd"

# Discover all subnets with MAC vendor lookup
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24","192.168.2.0/24","192.168.10.0/24" `
    -UseMacVendorAPI `
    -ThrottleLimit 150 `
    -ExportPath "C:\Clients\$clientName\Discovery_$timestamp.html"

# Test connectivity to critical servers
$criticalServers = Import-Csv "C:\Clients\$clientName\critical_systems.csv"
$criticalServers | .\Test-NetworkConnectivity.ps1 `
    -Port 80,443,3389,445 `
    -ExportPath "C:\Clients\$clientName\Connectivity_Report.html"
```

### Monthly Network Audit
```powershell
# Scheduled task - runs monthly
$month = Get-Date -Format "yyyy-MM"

# Rediscover network with full vendor classification
.\Get-NetworkDiscovery.ps1 `
    -Subnet "10.0.0.0/16" `
    -UseMacVendorAPI `
    -ThrottleLimit 200 `
    -IncludeOffline `
    -ExportPath "C:\Audits\Monthly\Discovery_$month.json"

# Compare to last month - find new/removed devices
$thisMonth = Get-Content "C:\Audits\Monthly\Discovery_$month.json" | ConvertFrom-Json
$lastMonth = Get-Content "C:\Audits\Monthly\Discovery_$((Get-Date).AddMonths(-1).ToString('yyyy-MM')).json" | ConvertFrom-Json

# Find new devices
$newDevices = $thisMonth | Where-Object { 
    $_.IPAddress -notin $lastMonth.IPAddress -and $_.Status -eq 'Online' 
}

# Find new IoT devices (security concern)
$newIoT = $newDevices | Where-Object { $_.DeviceType -eq 'IoT Device' }
if ($newIoT) {
    Write-Host "WARNING: New IoT devices detected!" -ForegroundColor Yellow
    $newIoT | Format-Table IPAddress, Vendor, OS
}
```

### IP Address Management
```powershell
# Track IP allocation
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24" `
    -IncludeOffline `
    -QuickScan `
    -ExportPath "C:\IPAM\Current_Allocation.csv"

# Find available IPs for new server
$allocation = Import-Csv "C:\IPAM\Current_Allocation.csv"
$available = $allocation | Where-Object { $_.Status -eq 'Offline' }

Write-Host "`nAvailable IP Addresses in 192.168.1.0/24:"
Write-Host "Total IPs: $($allocation.Count)"
Write-Host "In Use: $(($allocation | Where-Object { $_.Status -eq 'Online' }).Count)"
Write-Host "Available: $($available.Count)"
```

---

## Best Practices

### Network Discovery
- **Just run it**: No parameters needed - auto-detects local subnets
- **Use MAC Vendor API**: Provides best device classification (`-UseMacVendorAPI`)
- **Start small**: Test with small IP range first (/28 or /27)
- **Adjust threads**: Start with 100, increase to 150-200 for large scans
- **Use timeouts wisely**: LAN=1-2s, VPN=3-5s, WAN=5-10s
- **Schedule scans**: Monthly discovery to track changes
- **Export JSON**: Preserve full data for post-processing
- **Client deliverables**: Use HTML exports for professional reports

### IoT Security
- Enable MAC Vendor API to identify all IoT devices
- Review IoT devices for security implications
- Segment IoT devices on separate VLANs
- Monitor for new IoT devices monthly

### Container Environments
- Docker containers are automatically identified
- Differentiated from VMs and randomized mobile MACs
- Useful for tracking container sprawl

---

## Requirements

- **PowerShell 5.1 or later**
- **Network access** to target subnets
- **ICMP allowed** through firewalls (for ping)
- **Internet access** (optional, for MAC Vendor API)

---

## Version History

| Version | Features |
|---------|----------|
| 1.9 | Auto-detection of local subnets, no parameters required |
| 1.8 | Docker container detection, IoT vendor classification, Container device type |
| 1.7 | Locally administered MAC detection (Randomized/VM), enhanced vendor matching |
| 1.6 | MAC Vendor API integration with rate limiting and caching |
| 1.5 | HTML reports with clickable links and device icons |
| 1.0 | Initial release with parallel scanning and basic device classification |

---

[← Back to Main Repository](../README.md)
