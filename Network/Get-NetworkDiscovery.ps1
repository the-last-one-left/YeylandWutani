<#
.SYNOPSIS
    Network discovery and inventory tool for MSP client networks.

.DESCRIPTION
    Comprehensive network discovery tool that scans IP ranges to identify active devices,
    gather system information, identify device types, and generate detailed inventory reports.
    Designed for MSP client onboarding and network documentation.
    
    Compatible with PowerShell 5.1+ for maximum Windows Server compatibility.
    Uses runspace pools for fast parallel scanning.
    
    Features:
    - Automatic local subnet detection (scans all connected networks if no input provided)
    - Subnet/IP range scanning with parallel processing
    - Device type identification (server, workstation, printer, network device, mobile, IoT, container)
    - Operating system detection
    - MAC address and vendor lookup (local + online API)
    - 150+ vendor OUI database with smart device classification
    - Docker container detection
    - Locally administered MAC identification (VMs, randomized mobile MACs)
    - Open port scanning
    - Multi-method hostname resolution (DNS, NetBIOS, DNS Cache)
    - Console table output showing top 10 devices by services
    - Multiple export formats (CSV, JSON, HTML)
    - Clickable service links in HTML reports
    - Device type icons in reports

.PARAMETER Subnet
    Network subnet(s) to scan in CIDR notation (e.g., "192.168.1.0/24").
    Accepts multiple subnets via comma separation or pipeline.
    If not specified, automatically detects and scans all local subnets.

.PARAMETER IPRange
    IP range to scan using start-end format (e.g., "192.168.1.1-192.168.1.254").

.PARAMETER IPList
    Path to text file containing list of IP addresses (one per line).

.PARAMETER ScanPorts
    Scan common ports to identify services. Default: True

.PARAMETER QuickScan
    Fast ping-only scan (no port scanning, no DNS lookup).

.PARAMETER UseMacVendorAPI
    Enable online MAC vendor lookup via macvendors.com API.
    Provides comprehensive vendor identification for unknown MACs.
    Respects API rate limits (1 req/sec). Results are cached.

.PARAMETER ThrottleLimit
    Maximum parallel scanning threads. Default: 100

.PARAMETER Timeout
    Connection timeout in milliseconds per device. Default: 1000

.PARAMETER ExportPath
    Path to export discovery report. Supports CSV, JSON, or HTML formats.

.PARAMETER IncludeOffline
    Include unreachable IP addresses in report as "Offline" entries.

.PARAMETER Quiet
    Suppress progress output. Shows only final summary.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1
    
    Auto-detect local subnet(s) and scan all connected networks.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -UseMacVendorAPI
    
    Auto-scan local networks with enhanced MAC vendor lookup.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24"
    
    Scan specific /24 subnet, identify all active devices.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "172.16.0.0/24" -QuickScan
    
    Fast ping-only scan (5-15 seconds for /24).

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -UseMacVendorAPI -ExportPath "C:\Reports\Network.html"
    
    Full scan with online MAC vendor lookup, export to HTML with clickable links.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24","192.168.2.0/24" -ExportPath "C:\Reports\MultiSite.html"
    
    Scan multiple subnets and combine results into single report.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+
    Version: 2.3
    
    AUTO-DETECTION:
    - Detects all active network adapters with valid IPv4 addresses
    - Calculates subnet from IP address and subnet mask
    - Excludes loopback (127.x.x.x) and APIPA (169.254.x.x) addresses
    - Supports multiple NICs (scans all detected subnets)
    
    HOSTNAME RESOLUTION (Multi-Method):
    - Phase 1 (parallel): Reverse DNS lookup with domain stripping
    - Phase 2 (post-scan): NetBIOS query for Windows devices with SMB/RDP ports
    - NetBIOS uses job-based timeout (3 sec max per host) for reliability
    - Only queries devices likely to respond (port 139/445/135/3389 open)
    
    MAC VENDOR API:
    - Uses macvendors.com free API
    - Rate limit: 1 request/second (automatically throttled)
    - Results cached to avoid duplicate lookups
    - Fallback to local vendor database if API unavailable
    
    DEVICE CLASSIFICATION:
    - Docker containers detected by 02:42:xx MAC prefix
    - Locally administered MACs labeled as Randomized/VM
    - Smart home devices (WiZ, Espressif, Google, etc.) classified as IoT
    - Mesh WiFi (eero, etc.) classified as Network Device
    
    CONSOLE OUTPUT:
    - Displays top 10 devices sorted by most services when no export path specified
    - Color-coded by device type (Blue=Server, Green=Workstation, etc.)
    - Use -ExportPath for complete results in CSV, JSON, or HTML format
#>

[CmdletBinding(DefaultParameterSetName='Subnet')]
param(
    [Parameter(ParameterSetName='Subnet', ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]]$Subnet,
    
    [Parameter(ParameterSetName='IPRange')]
    [string]$IPRange,
    
    [Parameter(ParameterSetName='IPList')]
    [ValidateScript({ Test-Path $_ })]
    [string]$IPList,
    
    [bool]$ScanPorts = $true,
    
    [switch]$QuickScan,
    
    [switch]$UseMacVendorAPI,
    
    [ValidateRange(1, 500)]
    [int]$ThrottleLimit = 100,
    
    [ValidateRange(100, 5000)]
    [int]$Timeout = 1000,
    
    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Export directory does not exist: $parent"
        }
        $true
    })]
    [string]$ExportPath,
    
    [switch]$IncludeOffline,
    
    [switch]$Quiet
)

begin {
    $ScriptVersion = "2.3"
    $ScriptName = "Get-NetworkDiscovery"
    
    if (-not $Quiet) {
        Write-Host "[$ScriptName v$ScriptVersion] - Yeyland Wutani LLC - Building Better Systems" -ForegroundColor Cyan
        Write-Host "Starting network discovery..." -ForegroundColor Cyan
    }
    
    # Override settings for QuickScan
    if ($QuickScan) {
        $ScanPorts = $false
        if (-not $Quiet) {
            Write-Host "QuickScan mode enabled (ping only, no port/DNS scanning)" -ForegroundColor Yellow
        }
    }
    
    # Common ports for service identification
    $CommonPorts = @{
        21   = "FTP"
        22   = "SSH"
        23   = "Telnet"
        80   = "HTTP"
        135  = "RPC"
        139  = "NetBIOS"
        443  = "HTTPS"
        445  = "SMB"
        3389 = "RDP"
        8080 = "HTTP-Alt"
    }
    
    # Comprehensive MAC vendor database with device type hints
    $MacVendors = @{
        # Network Equipment Vendors
        '00:1B:D5' = 'Cisco|Network|IOS'
        '00:1E:BD' = 'Cisco|Network|IOS'
        '00:24:97' = 'Cisco|Network|IOS'
        '00:0C:85' = 'Cisco|Network|IOS'
        '00:1D:A2' = 'Cisco|Network|IOS'
        '00:26:0A' = 'Cisco|Network|IOS'
        'D4:C9:EF' = 'Aruba Networks|Network|ArubaOS'
        'B4:75:0E' = 'Aruba Networks|Network|ArubaOS'
        '00:0B:86' = 'Aruba Networks|Network|ArubaOS'
        '24:DE:C6' = 'Aruba Networks|Network|ArubaOS'
        '6C:F3:7F' = 'Aruba Networks|Network|ArubaOS'
        '00:1A:1E' = 'WatchGuard|Network|Fireware'
        '00:90:7F' = 'WatchGuard|Network|Fireware'
        'F0:9F:C2' = 'Ubiquiti|Network|EdgeOS'
        '04:18:D6' = 'Ubiquiti|Network|EdgeOS'
        '24:A4:3C' = 'Ubiquiti|Network|EdgeOS'
        '68:D7:9A' = 'Ubiquiti|Network|EdgeOS'
        '00:0F:B5' = 'Netgear|Network|Unknown'
        '00:09:5B' = 'Netgear|Network|Unknown'
        'A0:63:91' = 'Netgear|Network|Unknown'
        '00:0D:88' = 'D-Link|Network|Unknown'
        '00:17:9A' = 'D-Link|Network|Unknown'
        '00:1C:F0' = 'D-Link|Network|Unknown'
        '00:04:76' = '3Com|Network|Unknown'
        '00:50:04' = '3Com|Network|Unknown'
        '00:01:02' = '3Com|Network|Unknown'
        '00:19:06' = 'Fortinet|Network|FortiOS'
        '00:09:0F' = 'Fortinet|Network|FortiOS'
        '70:4C:A5' = 'Fortinet|Network|FortiOS'
        '00:13:C4' = 'TP-Link|Network|Unknown'
        '50:C7:BF' = 'TP-Link|Network|Unknown'
        'F4:F2:6D' = 'TP-Link|Network|Unknown'
        '00:E0:4C' = 'Realtek|Network|Unknown'
        '00:E0:4D' = 'Realtek|Network|Unknown'
        '52:54:00' = 'Realtek|Network|Unknown'
        '00:1F:33' = 'Netgear|Network|Unknown'
        'E0:46:9A' = 'Netgear|Network|Unknown'
        '00:22:6B' = 'Netgear|Network|Unknown'
        # HP Printers
        '00:0C:76' = 'HP|Printer|Printer'
        '00:14:38' = 'HP|Printer|Printer'
        '00:1E:0B' = 'HP|Printer|Printer'
        '00:21:5A' = 'HP|Printer|Printer'
        '3C:D9:2B' = 'HP|Printer|Printer'
        'B4:99:BA' = 'HP|Printer|Printer'
        'D4:85:64' = 'HP|Printer|Printer'
        # Canon Printers
        '00:00:85' = 'Canon|Printer|Printer'
        '00:1E:8F' = 'Canon|Printer|Printer'
        '9C:E6:E7' = 'Canon|Printer|Printer'
        # Epson Printers
        '00:00:48' = 'Epson|Printer|Printer'
        '00:26:AB' = 'Epson|Printer|Printer'
        '64:EB:8C' = 'Epson|Printer|Printer'
        # Brother Printers
        '00:80:77' = 'Brother|Printer|Printer'
        '00:1B:A9' = 'Brother|Printer|Printer'
        '30:05:5C' = 'Brother|Printer|Printer'
        # Xerox Printers
        '00:00:AA' = 'Xerox|Printer|Printer'
        '08:00:03' = 'Xerox|Printer|Printer'
        # Dell Computers/Servers
        '00:1B:78' = 'Dell|Computer|Windows'
        '00:14:22' = 'Dell|Computer|Windows'
        'D4:BE:D9' = 'Dell|Computer|Windows'
        '00:1E:4F' = 'Dell|Computer|Windows'
        '00:21:70' = 'Dell|Computer|Windows'
        '00:24:E8' = 'Dell|Computer|Windows'
        '18:03:73' = 'Dell|Computer|Windows'
        'B8:2A:72' = 'Dell|Server|Windows Server'
        'D0:67:E5' = 'Dell|Server|Windows Server'
        # HP Computers/Servers
        '00:50:8B' = 'HP|Computer|Windows'
        '00:1F:29' = 'HP|Computer|Windows'
        '00:23:7D' = 'HP|Computer|Windows'
        '00:26:55' = 'HP|Computer|Windows'
        '2C:27:D7' = 'HP|Server|Windows Server'
        '9C:B6:54' = 'HP|Server|Windows Server'
        # Lenovo/IBM
        '00:1A:6B' = 'Lenovo|Computer|Windows'
        '54:EE:75' = 'Lenovo|Computer|Windows'
        '00:21:CC' = 'Lenovo|Computer|Windows'
        '40:F2:E9' = 'Lenovo|Computer|Windows'
        # Apple Devices
        '00:25:84' = 'Apple|Computer|macOS'
        '00:26:BB' = 'Apple|Computer|macOS'
        '3C:07:54' = 'Apple|Computer|macOS'
        '68:5B:35' = 'Apple|Computer|macOS'
        '98:01:A7' = 'Apple|Computer|macOS'
        'A4:5E:60' = 'Apple|Computer|macOS'
        'BC:92:6B' = 'Apple|Computer|macOS'
        'F0:99:BF' = 'Apple|Computer|macOS'
        '00:23:DF' = 'Apple|Mobile|iOS'
        '10:40:F3' = 'Apple|Mobile|iOS'
        '28:E1:4C' = 'Apple|Mobile|iOS'
        'DC:2B:2A' = 'Apple|Mobile|iOS'
        # Microsoft
        '00:03:FF' = 'Microsoft|Computer|Windows'
        '00:50:F2' = 'Microsoft|Computer|Windows'
        '7C:ED:8D' = 'Microsoft|Computer|Windows'
        '00:15:5D' = 'Microsoft|Computer|Hyper-V'
        # Virtualization
        '00:50:56' = 'VMware|Computer|Virtual'
        '00:0C:29' = 'VMware|Computer|Virtual'
        '00:05:69' = 'VMware|Computer|Virtual'
        '00:1C:14' = 'VMware|Computer|Virtual'
        '00:1C:42' = 'Parallels|Computer|Virtual'
        '08:00:27' = 'VirtualBox|Computer|Virtual'
        'DE:AD:BE' = 'VirtualBox|Computer|Virtual'
        # Raspberry Pi & IoT
        'DC:A6:32' = 'Raspberry Pi|IoT|Linux'
        'B8:27:EB' = 'Raspberry Pi|IoT|Linux'
        'E4:5F:01' = 'Raspberry Pi|IoT|Linux'
        '28:CD:C1' = 'Raspberry Pi|IoT|Linux'
        # Samsung
        '00:12:FB' = 'Samsung|Computer|Unknown'
        '00:1B:98' = 'Samsung|Mobile|Android'
        '34:23:BA' = 'Samsung|Mobile|Android'
        '38:AA:3C' = 'Samsung|Mobile|Android'
        '88:30:8A' = 'Samsung|Mobile|Android'
        # LG
        '00:1C:62' = 'LG|Mobile|Android'
        '10:68:3F' = 'LG|Mobile|Android'
        # Motorola
        '00:26:BA' = 'Motorola|Mobile|Android'
        '48:2C:EA' = 'Motorola|Mobile|Android'
        # Intel NICs
        '00:1B:21' = 'Intel|Computer|Unknown'
        '00:1E:67' = 'Intel|Computer|Unknown'
        '00:23:15' = 'Intel|Computer|Unknown'
        'A0:36:9F' = 'Intel|Computer|Unknown'
        # APC (UPS/PDU)
        '00:C0:B7' = 'APC|IoT|Embedded'
        # Synology NAS
        '00:11:32' = 'Synology|Server|DSM'
        # QNAP NAS
        '00:08:9B' = 'QNAP|Server|QTS'
        '24:5E:BE' = 'QNAP|Server|QTS'
        # Amazon/Ring
        '74:C2:46' = 'Amazon|IoT|Linux'
        '00:FC:8B' = 'Amazon|IoT|Linux'
        # Google
        '00:1A:11' = 'Google|IoT|Android'
        'F4:F5:D8' = 'Google|IoT|Android'
        # Sonos
        '00:0E:58' = 'Sonos|IoT|Embedded'
        '5C:AA:FD' = 'Sonos|IoT|Embedded'
        # Nest
        '18:B4:30' = 'Nest|IoT|Embedded'
        '64:16:66' = 'Nest|IoT|Embedded'
    }
    
    # MAC vendor API cache
    $script:MacVendorCache = [hashtable]::Synchronized(@{})
    $script:LastApiCall = [DateTime]::MinValue
    $script:ApiCallCount = 0
    
    # Function to lookup MAC vendor via API
    function Get-MacVendorFromAPI {
        param(
            [string]$MacAddress,
            [string]$MacPrefix,
            [hashtable]$Cache
        )
        
        if ($Cache.ContainsKey($MacPrefix)) {
            return $Cache[$MacPrefix]
        }
        
        # Detect locally administered MACs
        $firstOctet = $MacPrefix.Split(':')[0]
        if ($firstOctet -and $firstOctet.Length -eq 2) {
            $secondNibble = $firstOctet[1]
            if ($secondNibble -match '[26AEae]') {
                if ($MacAddress -match '^02-42-') {
                    $Cache[$MacPrefix] = "Docker Container"
                    return "Docker Container"
                }
                else {
                    $Cache[$MacPrefix] = "Randomized/VM"
                    return "Randomized/VM"
                }
            }
        }
        
        try {
            $timeSinceLastCall = (Get-Date) - $script:LastApiCall
            if ($timeSinceLastCall.TotalMilliseconds -lt 1100) {
                Start-Sleep -Milliseconds (1100 - [int]$timeSinceLastCall.TotalMilliseconds)
            }
            
            $apiMac = $MacAddress.Replace(':', '-')
            $apiUrl = "https://api.macvendors.com/$apiMac"
            $response = Invoke-RestMethod -Uri $apiUrl -Method Get -TimeoutSec 5 -ErrorAction Stop
            
            $script:LastApiCall = Get-Date
            $script:ApiCallCount++
            $Cache[$MacPrefix] = $response
            
            return $response
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Response.StatusCode -eq 404) {
                $Cache[$MacPrefix] = "Unknown"
                return "Unknown"
            }
            return "Unknown"
        }
        catch {
            $Cache[$MacPrefix] = "Unknown"
            return "Unknown"
        }
    }
    
    $AllResults = @()
    $AllIPs = @()
    
    # Function to auto-detect local subnets
    function Get-LocalSubnets {
        $subnets = @()
        
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
            Where-Object { 
                $_.IPAddress -notmatch '^127\.' -and
                $_.IPAddress -notmatch '^169\.254\.' -and
                $_.PrefixLength -ge 8 -and
                $_.PrefixLength -le 30
            }
        
        foreach ($adapter in $adapters) {
            $ip = $adapter.IPAddress
            $prefix = $adapter.PrefixLength
            
            $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
            [Array]::Reverse($ipBytes)
            $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
            
            $maskInt = [Convert]::ToUInt32(('1' * $prefix + '0' * (32 - $prefix)), 2)
            $networkInt = $ipInt -band $maskInt
            
            $networkBytes = [System.BitConverter]::GetBytes($networkInt)
            [Array]::Reverse($networkBytes)
            $networkAddr = [System.Net.IPAddress]::new($networkBytes).ToString()
            
            $cidr = "$networkAddr/$prefix"
            
            if ($cidr -notin $subnets) {
                $subnets += $cidr
            }
        }
        
        return $subnets
    }
    
    # Function to convert subnet to IP list
    function Get-SubnetIPs {
        param([string]$CIDR)
        
        if ($CIDR -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
            throw "Invalid CIDR notation: $CIDR"
        }
        
        $networkAddr = $CIDR.Split('/')[0]
        $maskBits = [int]$CIDR.Split('/')[1]
        
        $ipBytes = [System.Net.IPAddress]::Parse($networkAddr).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
        
        $maskInt = [Convert]::ToUInt32(('1' * $maskBits + '0' * (32 - $maskBits)), 2)
        $networkInt = $ipInt -band $maskInt
        $broadcastInt = $networkInt -bor (-bnot $maskInt)
        
        $ips = @()
        for ($i = $networkInt + 1; $i -lt $broadcastInt; $i++) {
            $bytes = [System.BitConverter]::GetBytes($i)
            [Array]::Reverse($bytes)
            $ips += [System.Net.IPAddress]::new($bytes).ToString()
        }
        
        return $ips
    }
    
    # Scriptblock for scanning (runs in runspace)
    $ScanScriptBlock = {
        param($IP, $DoPortScan, $TimeoutMs, $PortMap, $MacVendorMap)
        
        # Quick ping test
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $pingReply = $ping.Send($IP, $TimeoutMs)
            $isOnline = ($pingReply.Status -eq 'Success')
        }
        catch {
            $isOnline = $false
        }
        finally {
            $ping.Dispose()
        }
        
        if (-not $isOnline) {
            return [PSCustomObject]@{
                IPAddress  = $IP
                Status     = 'Offline'
                Hostname   = $null
                DeviceType = 'Unknown'
                OS         = $null
                MACAddress = $null
                MACPrefix  = $null
                Vendor     = $null
                OpenPorts  = @()
                Services   = @()
                LastSeen   = $null
            }
        }
        
        # Device is online - Quick hostname resolution (DNS only in runspace)
        # NetBIOS is done in post-processing for speed
        $hostname = $null
        
        if (-not $DoPortScan) {
            $hostname = "N/A"
        }
        else {
            # Method 1: Reverse DNS lookup (requires PTR records)
            try {
                $dnsResult = [System.Net.Dns]::GetHostEntry($IP)
                if ($dnsResult.HostName -and $dnsResult.HostName -ne $IP) {
                    # Extract computer name (strip domain suffix)
                    $fullName = $dnsResult.HostName
                    if ($fullName -match '\.') {
                        # Has domain - extract first part (computer name)
                        $hostname = $fullName.Split('.')[0]
                    }
                    else {
                        $hostname = $fullName
                    }
                }
            }
            catch { }
            
            # Set default if DNS failed (NetBIOS done in post-processing)
            if (-not $hostname) {
                $hostname = "N/A"
            }
        }
        
        # Get MAC address using ARP
        $macAddress = $null
        $macPrefix = $null
        $vendor = "Unknown"
        $vendorHint = $null
        try {
            $arpOutput = & arp -a 2>$null
            $arpLine = $arpOutput | Where-Object { $_ -match "\b$([regex]::Escape($IP))\b" }
            
            if ($arpLine -and $arpLine -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                $macAddress = $matches[0].ToUpper().Replace(':', '-')
                $macPrefix = ($macAddress -split '-')[0..2] -join ':'
                
                if ($MacVendorMap.ContainsKey($macPrefix)) {
                    $macData = $MacVendorMap[$macPrefix] -split '\|'
                    $vendor = $macData[0]
                    if ($macData.Count -ge 3) {
                        $vendorHint = "$($macData[1])|$($macData[2])"
                    }
                }
            }
        }
        catch { }
        
        if (-not $macAddress) {
            $macAddress = "N/A"
        }
        
        # Port scanning
        $openPorts = @()
        $services = @()
        
        if ($DoPortScan) {
            foreach ($port in $PortMap.Keys) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connect = $tcpClient.BeginConnect($IP, $port, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                    
                    if ($wait) {
                        try {
                            $tcpClient.EndConnect($connect)
                            $openPorts += $port
                            $services += $PortMap[$port]
                        }
                        catch { }
                    }
                    $tcpClient.Close()
                    $tcpClient.Dispose()
                }
                catch { }
            }
        }
        
        # Determine device type
        $deviceType = "Unknown"
        $os = "Unknown"
        
        if ($vendorHint) {
            $hintParts = $vendorHint -split '\|'
            $macDeviceType = $hintParts[0]
            $macOS = $hintParts[1]
            
            switch ($macDeviceType) {
                'Printer' {
                    $deviceType = "Printer"
                    $os = "$vendor Printer"
                }
                'Network' {
                    $deviceType = "Network Device"
                    $os = if ($macOS -ne 'Unknown') { $macOS } else { "$vendor Device" }
                }
                'Server' {
                    $deviceType = "Server"
                    $os = if ($macOS -ne 'Unknown') { $macOS } else { "Server" }
                }
                'Computer' {
                    $deviceType = "Workstation"
                    $os = if ($macOS -ne 'Unknown') { $macOS } else { "Unknown" }
                }
                'Mobile' {
                    $deviceType = "Mobile Device"
                    $os = if ($macOS -ne 'Unknown') { $macOS } else { "Mobile" }
                }
                'IoT' {
                    $deviceType = "IoT Device"
                    $os = if ($macOS -ne 'Unknown') { $macOS } else { "$vendor" }
                }
            }
        }
        
        # Port-based detection fallback
        if ($deviceType -eq "Unknown" -and $openPorts.Count -gt 0) {
            if ($openPorts -contains 445 -and $openPorts -contains 3389) {
                $deviceType = "Server"
                $os = "Windows Server"
            }
            elseif ($openPorts -contains 445 -or $openPorts -contains 139) {
                $deviceType = "Workstation"
                $os = "Windows"
            }
            elseif ($openPorts -contains 515 -or $openPorts -contains 631 -or $openPorts -contains 9100) {
                $deviceType = "Printer"
                $os = "Printer Firmware"
            }
            elseif ($openPorts -contains 22 -or $openPorts -contains 23 -or $openPorts -contains 443) {
                if ($vendor -match 'Aruba|WatchGuard|Ubiquiti|3Com|Cisco|Netgear|D-Link|Fortinet|TP-Link') {
                    $deviceType = "Network Device"
                    $os = "$vendor Device"
                }
                else {
                    $deviceType = "Network Device"
                }
            }
        }
        
        return [PSCustomObject]@{
            IPAddress  = $IP
            Status     = 'Online'
            Hostname   = $hostname
            DeviceType = $deviceType
            OS         = $os
            MACAddress = $macAddress
            MACPrefix  = $macPrefix
            Vendor     = $vendor
            OpenPorts  = $openPorts
            Services   = ($services | Select-Object -Unique) -join ', '
            LastSeen   = Get-Date
        }
    }
}

process {
    switch ($PSCmdlet.ParameterSetName) {
        'Subnet' {
            if (-not $Subnet -or $Subnet.Count -eq 0) {
                if (-not $Quiet) {
                    Write-Host "No subnet specified - auto-detecting local networks..." -ForegroundColor Yellow
                }
                $Subnet = Get-LocalSubnets
                
                if ($Subnet.Count -eq 0) {
                    throw "Could not detect any local subnets. Please specify -Subnet parameter."
                }
                
                if (-not $Quiet) {
                    Write-Host "Detected $($Subnet.Count) local subnet(s):" -ForegroundColor Green
                    foreach ($net in $Subnet) {
                        Write-Host "  - $net" -ForegroundColor Gray
                    }
                }
            }
            
            foreach ($net in $Subnet) {
                if (-not $Quiet) {
                    Write-Host "Expanding subnet: $net" -ForegroundColor Yellow
                }
                $AllIPs += Get-SubnetIPs -CIDR $net
            }
        }
        
        'IPRange' {
            if ($IPRange -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})$') {
                $startNum = [int]$matches[2]
                $endNum = [int]$matches[4]
                for ($i = $startNum; $i -le $endNum; $i++) {
                    $AllIPs += $matches[1] + $i
                }
            }
            else {
                throw "Invalid IP range format. Use: 192.168.1.1-192.168.1.254"
            }
        }
        
        'IPList' {
            $AllIPs = Get-Content $IPList | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }
        }
    }
    
    if ($AllIPs.Count -eq 0) {
        throw "No valid IP addresses to scan"
    }
    
    if (-not $Quiet) {
        $scanType = if ($QuickScan) { "Quick" } else { "Full" }
        $apiStatus = if ($UseMacVendorAPI) { "with MAC Vendor API" } else { "local MAC DB" }
        Write-Host "`nScanning $($AllIPs.Count) IPs ($scanType mode, $ThrottleLimit threads, $apiStatus)..." -ForegroundColor Cyan
        $startTime = Get-Date
    }
    
    # Create runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $runspacePool.Open()
    $runspaces = @()
    
    foreach ($IP in $AllIPs) {
        $powershell = [powershell]::Create()
        $powershell.RunspacePool = $runspacePool
        
        [void]$powershell.AddScript($ScanScriptBlock)
        [void]$powershell.AddArgument($IP)
        [void]$powershell.AddArgument($ScanPorts)
        [void]$powershell.AddArgument($Timeout)
        [void]$powershell.AddArgument($CommonPorts)
        [void]$powershell.AddArgument($MacVendors)
        
        $runspaces += [PSCustomObject]@{
            Pipe   = $powershell
            Handle = $powershell.BeginInvoke()
        }
    }
    
    # Collect results
    $completed = 0
    $Results = @()
    
    while ($runspaces.Handle.IsCompleted -contains $false) {
        $runspaces | Where-Object { $_.Handle.IsCompleted -eq $true } | ForEach-Object {
            $Results += $_.Pipe.EndInvoke($_.Handle)
            $_.Pipe.Dispose()
            $completed++
            
            if (-not $Quiet -and $completed % 20 -eq 0) {
                $percentComplete = [math]::Round(($completed / $AllIPs.Count) * 100, 1)
                Write-Progress -Activity "Network Discovery" -Status "$completed of $($AllIPs.Count) IPs scanned ($percentComplete%)" -PercentComplete $percentComplete
            }
        }
        
        $runspaces = $runspaces | Where-Object { $_.Handle.IsCompleted -eq $false }
        Start-Sleep -Milliseconds 50
    }
    
    $runspacePool.Close()
    $runspacePool.Dispose()
    Write-Progress -Activity "Network Discovery" -Completed
    
    # Enhanced MAC vendor lookup via API
    if ($UseMacVendorAPI) {
        if (-not $Quiet) {
            $onlineWithMac = $Results | Where-Object { $_.Status -eq 'Online' -and $_.MACAddress -ne 'N/A' }
            $unknownInLocal = $onlineWithMac | Where-Object { $_.Vendor -eq 'Unknown' }
            
            Write-Host "`nMAC Vendor Analysis:" -ForegroundColor Cyan
            Write-Host "  Online devices with MAC: $($onlineWithMac.Count)"
            Write-Host "  Unknown vendors: $($unknownInLocal.Count)"
        }
        
        $unknownVendors = $Results | Where-Object { 
            $_.Status -eq 'Online' -and 
            $_.MACAddress -ne 'N/A' -and
            $_.Vendor -eq 'Unknown' -and 
            $_.MACPrefix -ne $null -and
            $_.MACPrefix -ne ''
        }
        
        if ($unknownVendors.Count -gt 0) {
            $prefixToMac = @{}
            $unknownVendors | ForEach-Object {
                if (-not $prefixToMac.ContainsKey($_.MACPrefix)) {
                    $prefixToMac[$_.MACPrefix] = $_.MACAddress
                }
            }
            $uniquePrefixes = $prefixToMac.Keys
            
            if (-not $Quiet) {
                Write-Host "  Unique MAC prefixes to lookup: $($uniquePrefixes.Count)" -ForegroundColor Yellow
                Write-Host "`nLooking up MAC vendors via API..." -ForegroundColor Yellow
            }
            
            $lookupCount = 0
            foreach ($prefix in $uniquePrefixes) {
                $fullMac = $prefixToMac[$prefix]
                $vendor = Get-MacVendorFromAPI -MacAddress $fullMac -MacPrefix $prefix -Cache $script:MacVendorCache
                
                $Results | Where-Object { $_.MACPrefix -eq $prefix } | ForEach-Object {
                    $_.Vendor = $vendor
                    
                    # Re-evaluate device type based on vendor
                    if ($vendor -eq 'Docker Container') {
                        $_.DeviceType = "Container"
                        $_.OS = "Docker"
                    }
                    elseif ($vendor -eq 'Randomized/VM') {
                        if ($_.DeviceType -eq "Unknown") {
                            $_.OS = "Virtual/Mobile"
                        }
                    }
                    elseif ($vendor -match 'eero|Aruba|WatchGuard|Ubiquiti|3Com|Cisco|Netgear|D-Link|Fortinet|TP-Link|Linksys|ASUS|MikroTik') {
                        $_.DeviceType = "Network Device"
                        $_.OS = "$vendor"
                    }
                    elseif ($vendor -match 'WiZ|Espressif|Tuya|Signify|Philips Hue|LIFX|Wyze|Ring|Nest|ecobee|Honeywell|Chamberlain|Lutron|Sonos|Roku|Amazon|FireTV') {
                        $_.DeviceType = "IoT Device"
                        $_.OS = "Smart Home"
                    }
                    elseif ($vendor -match 'Google') {
                        $_.DeviceType = "IoT Device"
                        $_.OS = "Google Home"
                    }
                    elseif ($vendor -match 'Samsung') {
                        if ($_.DeviceType -eq "Unknown") {
                            $_.DeviceType = "IoT Device"
                            $_.OS = "Samsung Smart"
                        }
                    }
                    elseif ($vendor -match 'ASRock|ASUS|Gigabyte|MSI|Supermicro|ASUSTeK') {
                        if ($_.OpenPorts -contains 22 -or $_.OpenPorts -contains 443 -or $_.OpenPorts -contains 80) {
                            $_.DeviceType = "Server"
                            $_.OS = "Linux/BSD"
                        }
                        elseif ($_.DeviceType -eq "Unknown") {
                            $_.DeviceType = "Workstation"
                            $_.OS = "Unknown"
                        }
                    }
                    elseif ($vendor -match 'HP Inc|Canon|Epson|Brother|Xerox|Lexmark|Ricoh|Kyocera' -and 
                            ($_.OpenPorts -contains 515 -or $_.OpenPorts -contains 631 -or $_.OpenPorts -contains 9100)) {
                        $_.DeviceType = "Printer"
                        $_.OS = "$vendor Printer"
                    }
                    elseif ($vendor -match 'Dell|Lenovo|Microsoft|Intel Corporate|Hewlett Packard') {
                        if ($_.DeviceType -eq "Unknown") {
                            $_.DeviceType = "Workstation"
                            $_.OS = "Windows"
                        }
                    }
                    elseif ($vendor -match 'Apple' -and $_.DeviceType -eq "Unknown") {
                        $_.DeviceType = "Workstation"
                        $_.OS = "macOS"
                    }
                }
                
                $lookupCount++
                if (-not $Quiet -and $lookupCount % 5 -eq 0) {
                    Write-Progress -Activity "MAC Vendor Lookup" -Status "$lookupCount of $($uniquePrefixes.Count) vendors" -PercentComplete (($lookupCount / $uniquePrefixes.Count) * 100)
                }
            }
            
            Write-Progress -Activity "MAC Vendor Lookup" -Completed
            
            if (-not $Quiet) {
                $cacheHits = $uniquePrefixes.Count - $script:ApiCallCount
                $successfulLookups = ($Results | Where-Object { $_.MACPrefix -and $_.Vendor -ne 'Unknown' }).Count
                Write-Host "API lookups completed: $script:ApiCallCount new requests, $cacheHits from cache" -ForegroundColor Green
                Write-Host "Vendors identified: $successfulLookups devices" -ForegroundColor Green
            }
        }
        elseif (-not $Quiet) {
            Write-Host "`nNo unknown MAC vendors found - all identified from local database" -ForegroundColor Green
        }
    }
    
    # NetBIOS hostname resolution (post-processing for devices with N/A hostname)
    # Debug: Check what ports are detected
    $windowsDevices = $Results | Where-Object { 
        $_.Status -eq 'Online' -and 
        $_.Hostname -eq 'N/A'
    }
    
    $unresolvedHosts = @()
    foreach ($dev in $windowsDevices) {
        $ports = @($dev.OpenPorts)
        if ($ports -contains 445 -or $ports -contains 139 -or $ports -contains 135 -or $ports -contains 3389) {
            $unresolvedHosts += $dev
        }
    }
    
    if ($unresolvedHosts.Count -gt 0 -and -not $QuickScan) {
        if (-not $Quiet) {
            Write-Host "`nNetBIOS Hostname Resolution:" -ForegroundColor Cyan
            Write-Host "  Windows devices without DNS hostname: $($unresolvedHosts.Count)" -ForegroundColor Yellow
        }
        
        $nbResolved = 0
        $nbCount = 0
        foreach ($device in $unresolvedHosts) {
            $nbCount++
            
            if (-not $Quiet) {
                Write-Progress -Activity "NetBIOS Hostname Resolution" -Status "$nbCount of $($unresolvedHosts.Count): $($device.IPAddress)" -PercentComplete (($nbCount / $unresolvedHosts.Count) * 100)
            }
            
            try {
                # nbtstat with short timeout
                $nbtJob = Start-Job -ScriptBlock {
                    param($IP)
                    & nbtstat -A $IP 2>$null
                } -ArgumentList $device.IPAddress
                
                # Wait max 3 seconds
                $completed = Wait-Job -Job $nbtJob -Timeout 3
                
                if ($completed) {
                    $nbtOutput = Receive-Job -Job $nbtJob
                    Remove-Job -Job $nbtJob -Force
                    
                    if ($nbtOutput) {
                        foreach ($line in $nbtOutput) {
                            # Match computer name: NAME <00> UNIQUE (first entry is usually computer name)
                            if ($line -match '^\s*([A-Z0-9\-]+)\s+<00>\s+UNIQUE') {
                                $nbName = $matches[1].Trim()
                                if ($nbName -and $nbName.Length -ge 1 -and $nbName.Length -le 15) {
                                    $device.Hostname = $nbName
                                    $nbResolved++
                                    break
                                }
                            }
                        }
                    }
                }
                else {
                    # Timeout - kill the job
                    Stop-Job -Job $nbtJob -ErrorAction SilentlyContinue
                    Remove-Job -Job $nbtJob -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                # Silently continue on errors
            }
        }
        
        Write-Progress -Activity "NetBIOS Hostname Resolution" -Completed
        
        if (-not $Quiet) {
            Write-Host "  Resolved via NetBIOS: $nbResolved hostnames" -ForegroundColor Green
        }
    }
    
    # Filter results
    if ($IncludeOffline) {
        $AllResults = $Results
    }
    else {
        $AllResults = $Results | Where-Object { $_.Status -eq 'Online' }
    }
}

end {
    if (-not $Quiet) {
        $onlineCount = ($AllResults | Where-Object { $_.Status -eq 'Online' }).Count
        $offlineCount = ($AllResults | Where-Object { $_.Status -eq 'Offline' }).Count
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        
        # Count hostname resolution success (ensure 0 if none found)
        $hostnameResolved = @($AllResults | Where-Object { $_.Status -eq 'Online' -and $_.Hostname -and $_.Hostname -ne 'N/A' }).Count
        
        Write-Host "`n================================================================" -ForegroundColor Cyan
        Write-Host " Network Discovery Summary" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "Total IPs Scanned:    $($AllIPs.Count)"
        Write-Host "Online Devices:       " -NoNewline
        Write-Host "$onlineCount" -ForegroundColor Green
        Write-Host "Hostnames Resolved:   $hostnameResolved of $onlineCount"
        if ($IncludeOffline) {
            Write-Host "Offline Addresses:    $offlineCount"
        }
        Write-Host "Scan Duration:        $([math]::Round($elapsed, 1)) seconds"
        
        if ($UseMacVendorAPI) {
            $identifiedVendors = @($AllResults | Where-Object { $_.Status -eq 'Online' -and $_.Vendor -and $_.Vendor -ne 'Unknown' }).Count
            $unknownVendors = @($AllResults | Where-Object { $_.Status -eq 'Online' -and ($_.Vendor -eq 'Unknown' -or -not $_.Vendor) }).Count
            Write-Host "MAC Vendors:          $identifiedVendors identified, $unknownVendors unknown ($script:ApiCallCount API calls)"
        }
        
        $deviceTypes = $AllResults | Where-Object { $_.Status -eq 'Online' } | 
                       Group-Object DeviceType | 
                       Sort-Object Count -Descending
        
        if ($deviceTypes) {
            Write-Host "`nDevice Types Discovered:"
            foreach ($type in $deviceTypes) {
                Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor Gray
            }
        }
        
        Write-Host "================================================================`n" -ForegroundColor Cyan
        
        # Display top 10 devices when no export
        if (-not $ExportPath) {
            $onlineDevices = $AllResults | Where-Object { $_.Status -eq 'Online' }
            
            if ($onlineDevices.Count -gt 0) {
                $top10 = $onlineDevices | 
                    Sort-Object { @($_.OpenPorts).Count } -Descending | 
                    Select-Object -First 10
                
                Write-Host "Top 10 Devices by Services:" -ForegroundColor Cyan
                Write-Host "-" * 120 -ForegroundColor Gray
                
                $header = "{0,-16} {1,-25} {2,-18} {3,-20} {4,-30}" -f "IP Address", "Hostname", "Device Type", "Vendor", "Services"
                Write-Host $header -ForegroundColor Yellow
                Write-Host "-" * 120 -ForegroundColor Gray
                
                foreach ($device in $top10) {
                    $hostname = if ($device.Hostname.Length -gt 23) { $device.Hostname.Substring(0, 20) + "..." } else { $device.Hostname }
                    $deviceType = if ($device.DeviceType.Length -gt 16) { $device.DeviceType.Substring(0, 13) + "..." } else { $device.DeviceType }
                    $vendor = if ($device.Vendor.Length -gt 18) { $device.Vendor.Substring(0, 15) + "..." } else { $device.Vendor }
                    $services = if ($device.Services.Length -gt 28) { $device.Services.Substring(0, 25) + "..." } else { $device.Services }
                    if (-not $services) { $services = "-" }
                    
                    $color = switch ($device.DeviceType) {
                        'Server' { 'Blue' }
                        'Workstation' { 'Green' }
                        'Printer' { 'Yellow' }
                        'Network Device' { 'DarkYellow' }
                        'Mobile Device' { 'Magenta' }
                        'IoT Device' { 'Red' }
                        'Container' { 'Cyan' }
                        default { 'White' }
                    }
                    
                    $row = "{0,-16} {1,-25} {2,-18} {3,-20} {4,-30}" -f $device.IPAddress, $hostname, $deviceType, $vendor, $services
                    Write-Host $row -ForegroundColor $color
                }
                
                Write-Host "-" * 120 -ForegroundColor Gray
                
                $remaining = $onlineDevices.Count - 10
                if ($remaining -gt 0) {
                    Write-Host "... and $remaining more devices. Use -ExportPath for full report." -ForegroundColor Gray
                }
                Write-Host ""
            }
        }
    }
    
    # Export results
    if ($ExportPath) {
        $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
        
        try {
            switch ($extension) {
                '.csv' {
                    $csvData = $AllResults | Select-Object IPAddress, Status, Hostname, DeviceType, 
                        OS, MACAddress, Vendor, Services, LastSeen
                    $csvData | Export-Csv -Path $ExportPath -NoTypeInformation
                    
                    if (-not $Quiet) {
                        Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.json' {
                    $AllResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExportPath -Encoding UTF8
                    
                    if (-not $Quiet) {
                        Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.html' {
                    $onlineDevices = $AllResults | Where-Object { $_.Status -eq 'Online' }
                    $deviceGroups = $onlineDevices | Group-Object DeviceType
                    
                    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Discovery Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #6B7280; }
        .header { background: linear-gradient(135deg, #FF6600 0%, #6B7280 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; font-size: 36px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .tagline { font-size: 14px; margin-top: 5px; opacity: 0.9; font-style: italic; }
        h2 { color: #FF6600; margin-top: 30px; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        .summary { background-color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #FF6600; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat-box { background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%); padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #6B7280; transition: transform 0.2s; }
        .stat-box:hover { transform: translateY(-5px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        .stat-number { font-size: 36px; font-weight: bold; color: #FF6600; text-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
        .stat-label { color: #6B7280; margin-top: 8px; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        th { background: linear-gradient(135deg, #6B7280 0%, #4a5568 100%); color: white; padding: 12px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        td { padding: 12px; border-bottom: 1px solid #e0e0e0; }
        tr:hover { background-color: #fff5f0; }
        tr:last-child td { border-bottom: none; }
        .device-server { border-left: 4px solid #0066cc; background-color: #e8f4fd; }
        .device-workstation { border-left: 4px solid #28a745; background-color: #e8f5e9; }
        .device-printer { border-left: 4px solid #ffc107; background-color: #fff8e1; }
        .device-network { border-left: 4px solid #FF6600; background-color: #fff0e6; }
        .device-mobile { border-left: 4px solid #9C27B0; background-color: #f3e5f5; }
        .device-iot { border-left: 4px solid #FF5722; background-color: #fbe9e7; }
        .device-container { border-left: 4px solid #2196F3; background-color: #e3f2fd; }
        .footer { margin-top: 40px; text-align: center; color: #6B7280; padding: 20px; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer .company { font-size: 20px; font-weight: bold; color: #FF6600; margin-bottom: 5px; }
        .footer .tagline { font-style: italic; color: #6B7280; margin-bottom: 10px; }
        a { text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Discovery Report</h1>
        <div class="tagline">Comprehensive Network Infrastructure Analysis</div>
    </div>
    
    <div class="summary">
        <strong style="color: #FF6600;">Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong style="color: #FF6600;">Scan Range:</strong> $($AllIPs.Count) IP addresses<br>
        <strong style="color: #FF6600;">Discovery Method:</strong> ICMP Ping $(if($ScanPorts){"+ Port Scan"}) $(if($UseMacVendorAPI){"+ MAC Vendor API"})
        
        <div class="summary-grid">
"@
                    foreach ($group in $deviceGroups) {
                        $html += "            <div class='stat-box'><div class='stat-number'>$($group.Count)</div><div class='stat-label'>$($group.Name)</div></div>`n"
                    }
                    
                    $html += @"
        </div>
    </div>
    
    <h2>Discovered Devices</h2>
    <table>
        <tr><th>IP Address</th><th>Hostname</th><th>Device Type</th><th>OS</th><th>MAC Address</th><th>Vendor</th><th>Services</th></tr>
"@
                    
                    foreach ($device in ($onlineDevices | Sort-Object { 
                        $octets = $_.IPAddress.Split('.')
                        [int]$octets[0] * 16777216 + [int]$octets[1] * 65536 + [int]$octets[2] * 256 + [int]$octets[3]
                    })) {
                        $rowClass = switch ($device.DeviceType) {
                            'Server' { 'device-server' }
                            'Workstation' { 'device-workstation' }
                            'Printer' { 'device-printer' }
                            'Network Device' { 'device-network' }
                            'Mobile Device' { 'device-mobile' }
                            'IoT Device' { 'device-iot' }
                            'Container' { 'device-container' }
                            default { '' }
                        }
                        
                        $deviceIcon = switch ($device.DeviceType) {
                            'Server' { '&#128187;' }
                            'Workstation' { '&#128421;' }
                            'Printer' { '&#128424;' }
                            'Network Device' { '&#128225;' }
                            'Mobile Device' { '&#128241;' }
                            'IoT Device' { '&#128268;' }
                            'Container' { '&#128230;' }
                            default { '&#10067;' }
                        }
                        
                        $servicesHtml = ""
                        if ($device.Services) {
                            $serviceLinks = @()
                            $serviceList = $device.Services -split ', '
                            foreach ($svc in $serviceList) {
                                $link = switch -Regex ($svc) {
                                    'HTTP-Alt' { "<a href='http://$($device.IPAddress):8080' target='_blank' style='color: #FF6600;'>HTTP-Alt</a>" }
                                    '^HTTPS$' { "<a href='https://$($device.IPAddress)' target='_blank' style='color: #FF6600;'>HTTPS</a>" }
                                    '^HTTP$' { "<a href='http://$($device.IPAddress)' target='_blank' style='color: #FF6600;'>HTTP</a>" }
                                    'RDP' { "<span style='color: #FF6600;'>RDP</span>" }
                                    'SSH' { "<span style='color: #FF6600;'>SSH</span>" }
                                    default { $svc }
                                }
                                $serviceLinks += $link
                            }
                            $servicesHtml = $serviceLinks -join ', '
                        }
                        
                        $html += "        <tr class='$rowClass'><td><strong>$($device.IPAddress)</strong></td><td>$($device.Hostname)</td><td>$deviceIcon $($device.DeviceType)</td><td>$($device.OS)</td><td>$($device.MACAddress)</td><td>$($device.Vendor)</td><td>$servicesHtml</td></tr>`n"
                    }
                    
                    $html += @"
    </table>
    <div class="footer">
        <div class="company">Yeyland Wutani LLC</div>
        <div class="tagline">Building Better Systems</div>
        <div style="font-size: 11px; color: #999;">Network Discovery Report | Powered by Advanced Infrastructure Analysis</div>
    </div>
</body>
</html>
"@
                    
                    $html | Out-File -FilePath $ExportPath -Encoding UTF8
                    
                    if (-not $Quiet) {
                        Write-Host "Results exported to HTML: $ExportPath" -ForegroundColor Green
                    }
                }
                
                default {
                    Write-Warning "Unsupported export format: $extension (use .csv, .json, or .html)"
                }
            }
        }
        catch {
            Write-Error "Failed to export results: $_"
        }
    }
    
    if (-not $Quiet) {
        Write-Host "Network discovery completed.`n" -ForegroundColor Cyan
    }
}
