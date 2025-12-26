# Network

Network discovery, connectivity testing, and documentation tools for MSP client networks.

## Available Scripts

### Network Discovery & Inventory

#### Get-NetworkDiscovery.ps1
Comprehensive network discovery tool for MSP client onboarding and network documentation.

**Key Features:**
- Parallel subnet scanning with configurable thread limits (1-500 threads)
- CIDR notation support (e.g., 192.168.1.0/24)
- IP range scanning (e.g., 192.168.1.1-192.168.1.254)
- Batch scanning from IP list files
- Device type identification (Server, Workstation, Printer, Network Device)
- Operating system detection
- MAC address and vendor lookup
- Port scanning for service identification
- DNS hostname resolution
- Multiple export formats (CSV, JSON, HTML)

**Device Type Detection:**
The script intelligently identifies device types based on:
- **Servers**: Windows Server OS detection, RDP (3389) + SMB (445) open
- **Workstations**: Windows desktop OS, SMB/NetBIOS ports
- **Printers**: Printer-specific ports (515 LPD, 631 IPP, 9100 raw)
- **Network Devices**: SSH/Telnet/HTTPS with vendor identification (Aruba, WatchGuard, Ubiquiti)
- **Unknown**: Responds to ping but insufficient data for classification

**Common Ports Scanned:**
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3)
- 135 (RPC), 139 (NetBIOS), 143 (IMAP)
- 443 (HTTPS), 445 (SMB)
- 515 (LPD), 631 (IPP), 9100 (Printer)
- 3306 (MySQL), 3389 (RDP), 5900 (VNC)
- 8080 (HTTP-Alt), 8443 (HTTPS-Alt)

**Usage Examples:**
```powershell
# New client - discover entire network
.\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -ExportPath "C:\Clients\NewClient\Discovery.html"

# Fast scan multiple subnets (100 threads)
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24","10.0.1.0/24","10.0.2.0/24" -ThrottleLimit 100 -ExportPath "C:\Discovery\MultiSubnet.csv"

# Scan specific IP range
.\Get-NetworkDiscovery.ps1 -IPRange "192.168.1.1-192.168.1.50" -ScanPorts $true

# Batch scan from file
Get-Content subnets.txt | .\Get-NetworkDiscovery.ps1 -Quiet -ExportPath "C:\Reports\AllNetworks.json"

# Include offline IPs in report (for IP allocation tracking)
.\Get-NetworkDiscovery.ps1 -Subnet "172.16.0.0/24" -IncludeOffline -ExportPath "C:\IPTracking\Subnet.csv"

# Quick ping-only scan (no port scanning)
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -ScanPorts $false -Quiet
```

**Real-World MSP Scenarios:**

**Scenario 1: New Client Onboarding**
```powershell
# Day 1 - Initial discovery
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24" `
    -ThrottleLimit 100 `
    -ExportPath "C:\Clients\ABC_Corp\Initial_Discovery_$(Get-Date -Format 'yyyyMMdd').html"

# Review HTML report with client
# Identify:
# - Servers that need monitoring
# - Workstations for patching
# - Printers for managed print services
# - Network devices for backup configs
# - Unknown devices for further investigation
```

**Scenario 2: Network Audit for Compliance**
```powershell
# Scan all subnets
$subnets = "10.0.0.0/24","10.0.1.0/24","10.0.2.0/24","10.0.10.0/24"

$subnets | .\Get-NetworkDiscovery.ps1 `
    -ThrottleLimit 200 `
    -IncludeOffline `
    -ExportPath "C:\Audits\Network_Inventory_$(Get-Date -Format 'yyyy-MM-dd').csv"

# Import CSV for analysis
$devices = Import-Csv "C:\Audits\Network_Inventory_2025-12-26.csv"

# Find potential security issues
$devices | Where-Object { $_.Services -match 'Telnet|FTP' }  # Insecure protocols
$devices | Where-Object { $_.DeviceType -eq 'Unknown' }      # Unidentified devices
```

**Scenario 3: IP Address Management**
```powershell
# Track IP allocation in growing network
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24" `
    -IncludeOffline `
    -ScanPorts $false `
    -ExportPath "C:\IPAM\Subnet_192.168.1.csv"

# Identify available IPs for new devices
$scan = Import-Csv "C:\IPAM\Subnet_192.168.1.csv"
$available = $scan | Where-Object { $_.Status -eq 'Offline' }
Write-Host "Available IPs: $($available.Count)"
$available | Select-Object -First 10 -ExpandProperty IPAddress
```

**Scenario 4: Troubleshooting Network Issues**
```powershell
# Quick scan to find missing server
.\Get-NetworkDiscovery.ps1 `
    -Subnet "10.0.0.0/24" `
    -ScanPorts $true `
    -Quiet | Where-Object { $_.Hostname -match 'SERVER' }

# Identify rogue DHCP servers
$discovery = .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -Quiet
$discovery | Where-Object { $_.Services -match 'DHCP' }
```

**HTML Report Features:**
- Visual dashboard with device type statistics
- Color-coded device categorization
  - Blue: Servers
  - Green: Workstations
  - Yellow: Printers
  - Red: Network Devices
- Sortable device inventory table
- IP address, hostname, MAC, vendor, services
- Yeyland Wutani branding (orange/grey)
- Professional client-deliverable format

**Performance Optimization:**
- Default: 50 parallel threads (balanced)
- Fast LANs: 100-200 threads (faster, higher network load)
- Slow/WAN links: 10-25 threads (slower, gentler on network)
- Massive networks: 200-500 threads (very fast, requires powerful hardware)

**Timeout Recommendations:**
- Local LAN: 1-2 seconds
- Cross-site VPN: 3-5 seconds
- Slow WAN: 5-10 seconds

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

# Monitor with email alerts
.\Test-NetworkConnectivity.ps1 `
    -Target "vpn.company.com" `
    -Port 443,1194 `
    -AlertOnFailure `
    -EmailTo "alerts@company.com" `
    -EmailFrom "monitor@company.com" `
    -SmtpServer "smtp.company.com"
```

**Troubleshooting Scenarios:**

**Scenario 1: Can't RDP to Server**
```powershell
.\Test-NetworkConnectivity.ps1 `
    -Target "server01.domain.local" `
    -Port 3389 `
    -IncludeTraceroute `
    -IncludeDNS

# Check results:
# - Ping: OK = Network layer good
# - Port 3389: Closed = RDP service issue
# - Traceroute: Shows path, identify network hops
# - DNS: Resolves correctly = DNS working
```

**Scenario 2: Website Not Loading**
```powershell
.\Test-NetworkConnectivity.ps1 `
    -Target "www.company.com" `
    -Port 80,443 `
    -IncludeDNS

# Check results:
# - DNS: Failed = DNS resolution issue
# - Ping: Failed = Hosting/connectivity issue
# - Port 80: Closed, Port 443: Open = HTTP redirect to HTTPS
```

**Scenario 3: Inter-Site Connectivity**
```powershell
# Test connectivity to branch office
.\Test-NetworkConnectivity.ps1 `
    -Target "10.1.0.1" `
    -Port 445,3389 `
    -IncludeTraceroute `
    -Count 10

# Traceroute shows:
# - Number of hops between sites
# - Latency at each hop
# - Identify where delays occur
```

---

## Common Workflows

### New Client Onboarding
```powershell
# Day 1 - Network Discovery
$clientName = "ABC Corporation"
$timestamp = Get-Date -Format "yyyyMMdd"

# Discover all subnets
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24","192.168.2.0/24","192.168.10.0/24" `
    -ThrottleLimit 150 `
    -ExportPath "C:\Clients\$clientName\Discovery_$timestamp.json"

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

# Rediscover network
.\Get-NetworkDiscovery.ps1 `
    -Subnet "10.0.0.0/16" `
    -ThrottleLimit 200 `
    -IncludeOffline `
    -ExportPath "C:\Audits\Monthly\Discovery_$month.json"

# Compare to last month
$thisMonth = Import-Csv "C:\Audits\Monthly\Discovery_$month.json"
$lastMonth = Import-Csv "C:\Audits\Monthly\Discovery_$(Get-Date (Get-Date).AddMonths(-1) -Format 'yyyy-MM').json"

# Find new devices
$newDevices = $thisMonth | Where-Object { 
    $_.IPAddress -notin $lastMonth.IPAddress -and $_.Status -eq 'Online' 
}

# Find removed devices
$removedDevices = $lastMonth | Where-Object { 
    $_.IPAddress -notin $thisMonth.IPAddress -and $_.Status -eq 'Online' 
}

# Report changes
if ($newDevices) {
    Write-Host "New devices detected: $($newDevices.Count)" -ForegroundColor Yellow
    $newDevices | Format-Table IPAddress, Hostname, DeviceType
}

if ($removedDevices) {
    Write-Host "Devices no longer detected: $($removedDevices.Count)" -ForegroundColor Red
    $removedDevices | Format-Table IPAddress, Hostname, DeviceType
}
```

### IP Address Management
```powershell
# Track IP allocation
.\Get-NetworkDiscovery.ps1 `
    -Subnet "192.168.1.0/24" `
    -IncludeOffline `
    -ScanPorts $false `
    -ExportPath "C:\IPAM\Current_Allocation.csv"

# Find available IPs for new server
$allocation = Import-Csv "C:\IPAM\Current_Allocation.csv"
$available = $allocation | Where-Object { $_.Status -eq 'Offline' }

Write-Host "`nAvailable IP Addresses in 192.168.1.0/24:"
Write-Host "Total IPs: $($allocation.Count)"
Write-Host "In Use: $(($allocation | Where-Object { $_.Status -eq 'Online' }).Count)"
Write-Host "Available: $($available.Count)"
Write-Host "`nFirst 10 available IPs:"
$available | Select-Object -First 10 -ExpandProperty IPAddress
```

### Troubleshooting Workflow
```powershell
# Step 1: Can we ping it?
.\Test-NetworkConnectivity.ps1 -Target "problem-server"

# Step 2: Is DNS working?
.\Test-NetworkConnectivity.ps1 -Target "problem-server" -IncludeDNS

# Step 3: What ports are open?
.\Test-NetworkConnectivity.ps1 -Target "problem-server" -Port 22,80,443,3389,445

# Step 4: Where is the network path issue?
.\Test-NetworkConnectivity.ps1 -Target "problem-server" -IncludeTraceroute

# Step 5: Scan entire subnet to see what else is affected
.\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -Quiet
```

---

## Best Practices

### Network Discovery
- **Start small**: Test with small IP range first (/28 or /27)
- **Adjust threads**: Start with 50, increase to 100-200 for large scans
- **Use timeouts wisely**: LAN=1-2s, VPN=3-5s, WAN=5-10s
- **Schedule scans**: Monthly discovery to track changes
- **Export JSON**: Preserve full data for post-processing
- **Client deliverables**: Use HTML exports for professional reports

### IP Management
- Include offline IPs in scans to track full allocation
- Maintain historical CSV files for trend analysis
- Reserve static IP ranges (exclude from DHCP scope)
- Document IP assignments in discovery exports
- Track MAC addresses for device identification

### Performance
- **Small networks (<100 IPs)**: 25-50 threads
- **Medium networks (100-500 IPs)**: 50-150 threads
- **Large networks (500+ IPs)**: 150-500 threads
- Monitor network load during scans
- Schedule intensive scans during off-hours
- Use -Quiet for scheduled/automated scans

### Security Considerations
- Obtain authorization before scanning client networks
- Avoid scanning public IP ranges
- Use -ScanPorts $false for quick/non-intrusive scans
- Secure exported data (contains network topology)
- Don't include deep scan credentials in scripts

---

## Requirements

- **PowerShell 5.1 or later**
- **Network access** to target subnets
- **ICMP allowed** through firewalls (for ping)
- **Administrative credentials** (for deep scans, optional)
- **Adequate bandwidth** for parallel scanning

---

## Troubleshooting

### No Devices Found
```powershell
# Verify network connectivity
Test-Connection -ComputerName "192.168.1.1" -Count 4

# Check if ICMP is blocked
# Try single IP with verbose
.\Get-NetworkDiscovery.ps1 -IPRange "192.168.1.1-192.168.1.1" -ScanPorts $false

# Verify CIDR notation
# Correct: 192.168.1.0/24
# Wrong: 192.168.1.0-24 or 192.168.1.1/255.255.255.0
```

### Slow Scanning
```powershell
# Increase parallel threads
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -ThrottleLimit 200

# Reduce timeout
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -Timeout 1

# Disable port scanning
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -ScanPorts $false
```

### Memory Issues
```powershell
# Reduce parallel threads
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/16" -ThrottleLimit 25

# Scan in smaller chunks
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24"
.\Get-NetworkDiscovery.ps1 -Subnet "10.0.1.0/24"
# Combine results after
```

---

## Future Enhancements

Planned additions to Network tools:
- WatchGuard firewall configuration backup via SSH
- Aruba switch configuration backup via SSH/SCP
- SNMP-based device polling
- Network device config diff/change detection
- Automated network diagram generation (Visio/Graphviz)
- VLAN discovery and documentation
- Bandwidth utilization monitoring

---

[← Back to Main Repository](../README.md)
