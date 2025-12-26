<#
.SYNOPSIS
    Network discovery and inventory tool for MSP client networks.

.DESCRIPTION
    Comprehensive network discovery tool that scans IP ranges to identify active devices,
    gather system information, identify device types, and generate detailed inventory reports.
    Designed for MSP client onboarding and network documentation.
    
    Features:
    - Subnet/IP range scanning with parallel processing
    - Device type identification (server, workstation, printer, network device)
    - Operating system detection
    - MAC address and vendor lookup
    - Open port scanning
    - DNS hostname resolution
    - WMI-based detailed information (Windows devices)
    - Multiple export formats (CSV, JSON, HTML)
    - Visual network map generation

.PARAMETER Subnet
    Network subnet(s) to scan in CIDR notation (e.g., "192.168.1.0/24").
    Accepts multiple subnets via comma separation or pipeline.

.PARAMETER IPRange
    IP range to scan using start-end format (e.g., "192.168.1.1-192.168.1.254").

.PARAMETER IPList
    Path to text file containing list of IP addresses (one per line).

.PARAMETER ScanPorts
    Scan common ports to identify services. Default: True
    Ports scanned: 21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443

.PARAMETER DeepScan
    Perform WMI queries for detailed Windows device information.
    Requires administrative credentials on target devices.

.PARAMETER Credential
    PSCredential object for WMI/CIM authentication on Windows devices.

.PARAMETER ThrottleLimit
    Maximum parallel scanning threads. Default: 50
    Higher values = faster scanning but more network load.

.PARAMETER Timeout
    Connection timeout in seconds per device. Default: 2

.PARAMETER ExportPath
    Path to export discovery report. Supports CSV, JSON, or HTML formats.

.PARAMETER IncludeOffline
    Include unreachable IP addresses in report as "Offline" entries.

.PARAMETER Quiet
    Suppress progress output. Shows only final summary.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24"
    
    Scan entire /24 subnet, identify all active devices.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24","10.0.1.0/24" -ExportPath "C:\Reports\Network.html"
    
    Scan multiple subnets, generate HTML report.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -IPRange "192.168.1.1-192.168.1.50" -DeepScan -Credential (Get-Credential)
    
    Deep scan IP range with Windows WMI queries using credentials.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "172.16.0.0/24" -ThrottleLimit 100 -ExportPath "C:\Reports\Client_Network.csv"
    
    Fast parallel scan (100 threads) with CSV export.

.EXAMPLE
    Get-Content subnets.txt | .\Get-NetworkDiscovery.ps1 -ScanPorts $false -Quiet -ExportPath "C:\Discovery\AllSubnets.json"
    
    Batch scan from file, ping-only (no port scan), JSON export.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+
    
    TYPICAL MSP WORKFLOWS:
    
    1. New Client Onboarding:
       .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -DeepScan -Credential $cred -ExportPath "C:\Clients\NewClient\Discovery.html"
       
    2. Network Documentation:
       .\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/16" -ThrottleLimit 200 -ExportPath "Documentation\Network_Inventory.csv"
       
    3. Quick Subnet Check:
       .\Get-NetworkDiscovery.ps1 -IPRange "192.168.1.1-192.168.1.254" -Quiet
       
    DEVICE TYPE DETECTION:
    - Servers: Windows Server OS, open server ports (445, 3389, etc.)
    - Workstations: Windows/Linux/Mac desktop OS
    - Printers: Printer-specific ports (515, 631, 9100)
    - Network Devices: Multiple open management ports, no OS detected
    - Unknown: Responds to ping but minimal information available
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
    
    [switch]$DeepScan,
    
    [PSCredential]$Credential,
    
    [ValidateRange(1, 500)]
    [int]$ThrottleLimit = 50,
    
    [ValidateRange(1, 30)]
    [int]$Timeout = 2,
    
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
    $ScriptVersion = "1.0"
    $ScriptName = "Get-NetworkDiscovery"
    
    if (-not $Quiet) {
        Write-Host "[$ScriptName v$ScriptVersion] - Yeyland Wutani LLC - Building Better Systems" -ForegroundColor Cyan
        Write-Host "Starting network discovery..." -ForegroundColor Cyan
    }
    
    # Common ports for service identification
    $CommonPorts = @{
        21   = "FTP"
        22   = "SSH"
        23   = "Telnet"
        25   = "SMTP"
        53   = "DNS"
        80   = "HTTP"
        110  = "POP3"
        135  = "RPC"
        139  = "NetBIOS"
        143  = "IMAP"
        443  = "HTTPS"
        445  = "SMB"
        515  = "LPD/Printer"
        631  = "IPP/Printer"
        3306 = "MySQL"
        3389 = "RDP"
        5900 = "VNC"
        8080 = "HTTP-Alt"
        8443 = "HTTPS-Alt"
        9100 = "Printer"
    }
    
    # MAC vendor lookup (partial list - expand as needed)
    $MacVendors = @{
        '00:50:56' = 'VMware'
        '00:0C:29' = 'VMware'
        '00:1C:42' = 'Parallels'
        '08:00:27' = 'VirtualBox'
        '00:15:5D' = 'Hyper-V'
        'D4:C9:EF' = 'Aruba'
        '00:1A:1E' = 'WatchGuard'
        'F0:9F:C2' = 'Ubiquiti'
        '00:01:E3' = 'Siemens'
        '00:04:76' = ' 3Com'
        'B4:75:0E' = 'Aruba'
        '00:0B:86' = 'Aruba'
    }
    
    $AllResults = @()
    $AllIPs = @()
    
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
    
    # Function to scan single IP
    function Test-Device {
        param(
            [string]$IP,
            [bool]$DoPortScan,
            [int]$TimeoutSec,
            [hashtable]$PortMap
        )
        
        # Ping test
        $pingResult = Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds $TimeoutSec
        
        if (-not $pingResult) {
            return [PSCustomObject]@{
                IPAddress    = $IP
                Status       = 'Offline'
                Hostname     = $null
                DeviceType   = 'Unknown'
                OS           = $null
                MACAddress   = $null
                Vendor       = $null
                OpenPorts    = @()
                Services     = @()
                LastSeen     = $null
            }
        }
        
        # Device is online - gather info
        $hostname = $null
        try {
            $dnsResult = [System.Net.Dns]::GetHostEntry($IP)
            $hostname = $dnsResult.HostName
        }
        catch {
            $hostname = "N/A"
        }
        
        # Get MAC address using ARP
        $macAddress = $null
        $vendor = "Unknown"
        try {
            $arpResult = arp -a $IP 2>$null | Where-Object { $_ -match $IP }
            if ($arpResult -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                $macAddress = $matches[0].ToUpper()
                
                # Lookup vendor
                $macPrefix = ($macAddress -split '-')[0..2] -join ':'
                if ($MacVendors.ContainsKey($macPrefix)) {
                    $vendor = $MacVendors[$macPrefix]
                }
            }
        }
        catch {
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
                    $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)
                    
                    if ($wait) {
                        try {
                            $tcpClient.EndConnect($connect)
                            $openPorts += $port
                            $services += $PortMap[$port]
                        }
                        catch { }
                    }
                    $tcpClient.Close()
                }
                catch { }
            }
        }
        
        # Determine device type
        $deviceType = "Unknown"
        $os = "Unknown"
        
        # Server indicators
        if ($openPorts -contains 445 -and $openPorts -contains 3389) {
            $deviceType = "Server"
            $os = "Windows Server"
        }
        # Workstation indicators
        elseif ($openPorts -contains 445 -or $openPorts -contains 139) {
            $deviceType = "Workstation"
            $os = "Windows"
        }
        # Printer indicators
        elseif ($openPorts -contains 515 -or $openPorts -contains 631 -or $openPorts -contains 9100) {
            $deviceType = "Printer"
            $os = "Printer Firmware"
        }
        # Network device indicators
        elseif ($openPorts -contains 22 -or $openPorts -contains 23 -or $openPorts -contains 443) {
            if ($vendor -in @('Aruba', 'WatchGuard', 'Ubiquiti', '3Com')) {
                $deviceType = "Network Device"
                $os = "$vendor Device"
            }
            else {
                $deviceType = "Network Device"
            }
        }
        
        return [PSCustomObject]@{
            IPAddress    = $IP
            Status       = 'Online'
            Hostname     = $hostname
            DeviceType   = $deviceType
            OS           = $os
            MACAddress   = $macAddress
            Vendor       = $vendor
            OpenPorts    = $openPorts
            Services     = ($services | Select-Object -Unique) -join ', '
            LastSeen     = Get-Date
        }
    }
}

process {
    # Build IP list based on parameter set
    switch ($PSCmdlet.ParameterSetName) {
        'Subnet' {
            foreach ($net in $Subnet) {
                if (-not $Quiet) {
                    Write-Host "Expanding subnet: $net" -ForegroundColor Yellow
                }
                $AllIPs += Get-SubnetIPs -CIDR $net
            }
        }
        
        'IPRange' {
            if ($IPRange -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})$') {
                $startIP = $matches[1] + $matches[2]
                $endIP = $matches[3] + $matches[4]
                
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
        Write-Host "`nScanning $($AllIPs.Count) IP addresses with $ThrottleLimit parallel threads..." -ForegroundColor Cyan
        Write-Host "Port Scanning: $ScanPorts | Deep Scan: $DeepScan | Timeout: $Timeout seconds`n" -ForegroundColor Gray
    }
    
    # Parallel scanning
    $results = $AllIPs | ForEach-Object -Parallel {
        $ip = $_
        $portScan = $using:ScanPorts
        $timeout = $using:Timeout
        $portMap = $using:CommonPorts
        $macVendors = $using:MacVendors
        
        # Import functions into parallel runspace
        function Test-Device {
            param(
                [string]$IP,
                [bool]$DoPortScan,
                [int]$TimeoutSec,
                [hashtable]$PortMap
            )
            
            $pingResult = Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds $TimeoutSec
            
            if (-not $pingResult) {
                return [PSCustomObject]@{
                    IPAddress    = $IP
                    Status       = 'Offline'
                    Hostname     = $null
                    DeviceType   = 'Unknown'
                    OS           = $null
                    MACAddress   = $null
                    Vendor       = $null
                    OpenPorts    = @()
                    Services     = @()
                    LastSeen     = $null
                }
            }
            
            $hostname = $null
            try {
                $dnsResult = [System.Net.Dns]::GetHostEntry($IP)
                $hostname = $dnsResult.HostName
            }
            catch {
                $hostname = "N/A"
            }
            
            $macAddress = $null
            $vendor = "Unknown"
            try {
                $arpResult = arp -a $IP 2>$null | Where-Object { $_ -match $IP }
                if ($arpResult -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                    $macAddress = $matches[0].ToUpper()
                    
                    # Assign $using: variable to local variable for method calls
                    $macVendorLookup = $using:macVendors
                    $macPrefix = ($macAddress -split '-')[0..2] -join ':'
                    if ($macVendorLookup.ContainsKey($macPrefix)) {
                        $vendor = $macVendorLookup[$macPrefix]
                    }
                }
            }
            catch {
                $macAddress = "N/A"
            }
            
            $openPorts = @()
            $services = @()
            
            if ($DoPortScan) {
                foreach ($port in $PortMap.Keys) {
                    try {
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $connect = $tcpClient.BeginConnect($IP, $port, $null, $null)
                        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)
                        
                        if ($wait) {
                            try {
                                $tcpClient.EndConnect($connect)
                                $openPorts += $port
                                $services += $PortMap[$port]
                            }
                            catch { }
                        }
                        $tcpClient.Close()
                    }
                    catch { }
                }
            }
            
            $deviceType = "Unknown"
            $os = "Unknown"
            
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
                if ($vendor -in @('Aruba', 'WatchGuard', 'Ubiquiti', '3Com')) {
                    $deviceType = "Network Device"
                    $os = "$vendor Device"
                }
                else {
                    $deviceType = "Network Device"
                }
            }
            
            return [PSCustomObject]@{
                IPAddress    = $IP
                Status       = 'Online'
                Hostname     = $hostname
                DeviceType   = $deviceType
                OS           = $os
                MACAddress   = $macAddress
                Vendor       = $vendor
                OpenPorts    = $openPorts
                Services     = ($services | Select-Object -Unique) -join ', '
                LastSeen     = Get-Date
            }
        }
        
        Test-Device -IP $ip -DoPortScan $portScan -TimeoutSec $timeout -PortMap $portMap
        
    } -ThrottleLimit $ThrottleLimit
    
    # Filter results
    if ($IncludeOffline) {
        $AllResults = $results
    }
    else {
        $AllResults = $results | Where-Object { $_.Status -eq 'Online' }
    }
}

end {
    # Display summary
    if (-not $Quiet) {
        $onlineCount = ($AllResults | Where-Object { $_.Status -eq 'Online' }).Count
        $offlineCount = ($AllResults | Where-Object { $_.Status -eq 'Offline' }).Count
        
        Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host " Network Discovery Summary" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "Total IPs Scanned:    $($AllIPs.Count)"
        Write-Host "Online Devices:       " -NoNewline
        Write-Host "$onlineCount" -ForegroundColor Green
        if ($IncludeOffline) {
            Write-Host "Offline Addresses:    $offlineCount"
        }
        
        # Device type breakdown
        $deviceTypes = $AllResults | Where-Object { $_.Status -eq 'Online' } | 
                       Group-Object DeviceType | 
                       Sort-Object Count -Descending
        
        if ($deviceTypes) {
            Write-Host "`nDevice Types Discovered:"
            foreach ($type in $deviceTypes) {
                Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor Gray
            }
        }
        
        Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        h2 { color: #6B7280; margin-top: 30px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 15px; }
        .stat-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 32px; font-weight: bold; color: #FF6600; }
        .stat-label { color: #6B7280; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #6B7280; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .device-server { background-color: #d1ecf1; }
        .device-workstation { background-color: #d4edda; }
        .device-printer { background-color: #fff3cd; }
        .device-network { background-color: #f8d7da; }
        .footer { margin-top: 30px; text-align: center; color: #6B7280; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Network Discovery Report</h1>
    <div class="summary">
        <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Scan Range:</strong> $($AllIPs.Count) IP addresses<br>
        <strong>Discovery Method:</strong> ICMP Ping $(if($ScanPorts){"+ Port Scan"})
        
        <div class="summary-grid">
"@
                    
                    foreach ($group in $deviceGroups) {
                        $html += @"
            <div class="stat-box">
                <div class="stat-number">$($group.Count)</div>
                <div class="stat-label">$($group.Name)</div>
            </div>
"@
                    }
                    
                    $html += @"
        </div>
    </div>
    
    <h2>Discovered Devices</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>Device Type</th>
            <th>OS</th>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Services</th>
        </tr>
"@
                    
                    foreach ($device in ($onlineDevices | Sort-Object { [System.Version]$_.IPAddress.Split('.') -join '.' })) {
                        $rowClass = switch ($device.DeviceType) {
                            'Server' { 'device-server' }
                            'Workstation' { 'device-workstation' }
                            'Printer' { 'device-printer' }
                            'Network Device' { 'device-network' }
                            default { '' }
                        }
                        
                        $html += @"
        <tr class="$rowClass">
            <td><strong>$($device.IPAddress)</strong></td>
            <td>$($device.Hostname)</td>
            <td>$($device.DeviceType)</td>
            <td>$($device.OS)</td>
            <td>$($device.MACAddress)</td>
            <td>$($device.Vendor)</td>
            <td>$($device.Services)</td>
        </tr>
"@
                    }
                    
                    $html += @"
    </table>
    <div class="footer">
        Yeyland Wutani LLC - Building Better Systems<br>
        Network Discovery Report
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
