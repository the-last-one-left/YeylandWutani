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
    - Subnet/IP range scanning with parallel processing
    - Device type identification (server, workstation, printer, network device)
    - Operating system detection
    - MAC address and vendor lookup (local + online API)
    - Open port scanning
    - DNS hostname resolution
    - Multiple export formats (CSV, JSON, HTML)

.PARAMETER Subnet
    Network subnet(s) to scan in CIDR notation (e.g., "192.168.1.0/24").
    Accepts multiple subnets via comma separation or pipeline.

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
    .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24"
    
    Scan entire /24 subnet, identify all active devices.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "172.16.0.0/24" -QuickScan
    
    Fast ping-only scan (5-15 seconds for /24).

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "10.0.0.0/24" -UseMacVendorAPI -ExportPath "C:\Reports\Network.html"
    
    Full scan with online MAC vendor lookup, export to HTML.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+
    
    MAC VENDOR API:
    - Uses macvendors.com free API
    - Rate limit: 1 request/second (automatically throttled)
    - Results cached to avoid duplicate lookups
    - Fallback to local vendor database if API unavailable
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
    $ScriptVersion = "1.3"
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
    
    # Local MAC vendor database (fallback/cache accelerator)
    $MacVendors = @{
        '00:50:56' = 'VMware'
        '00:0C:29' = 'VMware'
        '00:05:69' = 'VMware'
        '00:1C:14' = 'VMware'
        '00:1C:42' = 'Parallels'
        '08:00:27' = 'VirtualBox'
        '00:15:5D' = 'Microsoft (Hyper-V)'
        '00:03:FF' = 'Microsoft'
        'D4:C9:EF' = 'Aruba Networks'
        '00:1A:1E' = 'WatchGuard'
        'F0:9F:C2' = 'Ubiquiti'
        '00:01:E3' = 'Siemens'
        '00:04:76' = '3Com'
        'B4:75:0E' = 'Aruba Networks'
        '00:0B:86' = 'Aruba Networks'
        '24:DE:C6' = 'Aruba Networks'
        '00:1B:D5' = 'Cisco'
        '00:1E:BD' = 'Cisco'
        '00:25:84' = 'Apple'
        '00:26:BB' = 'Apple'
        'DC:A6:32' = 'Raspberry Pi'
        'B8:27:EB' = 'Raspberry Pi'
        '00:0C:76' = 'Hewlett Packard'
        '00:14:38' = 'Hewlett Packard'
        '00:50:8B' = 'Hewlett Packard'
        '00:1B:78' = 'Dell'
        '00:14:22' = 'Dell'
        'D4:BE:D9' = 'Dell'
        '00:0D:88' = 'D-Link'
        '00:17:9A' = 'D-Link'
        '00:1C:F0' = 'D-Link'
        '00:0F:B5' = 'Netgear'
        '00:09:5B' = 'Netgear'
        'A0:63:91' = 'Netgear'
    }
    
    # MAC vendor API cache (shared across all lookups)
    $script:MacVendorCache = [hashtable]::Synchronized(@{})
    $script:LastApiCall = [DateTime]::MinValue
    $script:ApiCallCount = 0
    
    # Function to lookup MAC vendor via API
    function Get-MacVendorFromAPI {
        param(
            [string]$MacPrefix,
            [hashtable]$Cache
        )
        
        # Check cache first
        if ($Cache.ContainsKey($MacPrefix)) {
            return $Cache[$MacPrefix]
        }
        
        try {
            # Rate limiting: 1 request per second
            $timeSinceLastCall = (Get-Date) - $script:LastApiCall
            if ($timeSinceLastCall.TotalMilliseconds -lt 1000) {
                Start-Sleep -Milliseconds (1000 - [int]$timeSinceLastCall.TotalMilliseconds)
            }
            
            # API call
            $apiUrl = "https://api.macvendors.com/$MacPrefix"
            $response = Invoke-RestMethod -Uri $apiUrl -Method Get -TimeoutSec 3 -ErrorAction Stop
            
            $script:LastApiCall = Get-Date
            $script:ApiCallCount++
            
            # Cache the result
            $Cache[$MacPrefix] = $response
            
            return $response
        }
        catch {
            # API failed, cache as "Unknown" to avoid repeated lookups
            $Cache[$MacPrefix] = "Unknown"
            return "Unknown"
        }
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
        
        # Device is online - gather info
        $hostname = "N/A"
        if (-not $DoPortScan) {
            # QuickScan - skip DNS lookup for speed
            $hostname = "N/A"
        }
        else {
            try {
                $dnsResult = [System.Net.Dns]::GetHostEntry($IP)
                $hostname = $dnsResult.HostName
            }
            catch {
                $hostname = "N/A"
            }
        }
        
        # Get MAC address using ARP
        $macAddress = $null
        $macPrefix = $null
        $vendor = "Unknown"
        try {
            $arpOutput = & arp -a $IP 2>$null
            if ($arpOutput -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                $macAddress = $matches[0].ToUpper()
                $macPrefix = ($macAddress -split '-')[0..2] -join ':'
                
                # Check local database first
                if ($MacVendorMap.ContainsKey($macPrefix)) {
                    $vendor = $MacVendorMap[$macPrefix]
                }
                # If not in local DB, vendor remains "Unknown" and will be looked up via API if enabled
            }
        }
        catch { }
        
        # Set display value for MAC if not found
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
        
        if ($openPorts -contains 445 -and $openPorts -contains 3389) {
            $deviceType = "Server"
            $os = "Windows Server"
        }
        elseif ($openPorts -contains 445 -or $openPorts -contains 139) {
            $deviceType = "Workstation"
            $os = "Windows"
        }
        elseif ($openPorts -contains 22 -or $openPorts -contains 23 -or $openPorts -contains 443) {
            if ($vendor -match 'Aruba|WatchGuard|Ubiquiti|3Com|Cisco|Netgear|D-Link') {
                $deviceType = "Network Device"
                $os = "$vendor Device"
            }
            else {
                $deviceType = "Network Device"
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
    # Build IP list
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
    
    # Create runspace pool for parallel execution
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $runspacePool.Open()
    $runspaces = @()
    
    # Start scanning jobs
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
    
    # Cleanup runspaces
    $runspacePool.Close()
    $runspacePool.Dispose()
    Write-Progress -Activity "Network Discovery" -Completed
    
    # Enhanced MAC vendor lookup via API (post-processing)
    if ($UseMacVendorAPI) {
        $unknownVendors = $Results | Where-Object { 
            $_.Status -eq 'Online' -and 
            $_.Vendor -eq 'Unknown' -and 
            $_.MACPrefix 
        }
        
        if ($unknownVendors.Count -gt 0) {
            if (-not $Quiet) {
                Write-Host "`nLooking up $($unknownVendors.Count) unknown MAC vendors via API..." -ForegroundColor Yellow
            }
            
            # Get unique MAC prefixes to lookup
            $uniquePrefixes = $unknownVendors | 
                Select-Object -ExpandProperty MACPrefix -Unique
            
            $lookupCount = 0
            foreach ($prefix in $uniquePrefixes) {
                $vendor = Get-MacVendorFromAPI -MacPrefix $prefix -Cache $script:MacVendorCache
                
                # Update all results with this MAC prefix
                $Results | Where-Object { $_.MACPrefix -eq $prefix } | ForEach-Object {
                    $_.Vendor = $vendor
                }
                
                $lookupCount++
                if (-not $Quiet -and $lookupCount % 5 -eq 0) {
                    Write-Progress -Activity "MAC Vendor Lookup" -Status "$lookupCount of $($uniquePrefixes.Count) vendors" -PercentComplete (($lookupCount / $uniquePrefixes.Count) * 100)
                }
            }
            
            Write-Progress -Activity "MAC Vendor Lookup" -Completed
            
            if (-not $Quiet) {
                Write-Host "API lookups completed: $script:ApiCallCount requests (cached: $($uniquePrefixes.Count - $script:ApiCallCount))" -ForegroundColor Green
            }
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
    # Display summary
    if (-not $Quiet) {
        $onlineCount = ($AllResults | Where-Object { $_.Status -eq 'Online' }).Count
        $offlineCount = ($AllResults | Where-Object { $_.Status -eq 'Offline' }).Count
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        
        Write-Host "`n================================================================" -ForegroundColor Cyan
        Write-Host " Network Discovery Summary" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "Total IPs Scanned:    $($AllIPs.Count)"
        Write-Host "Online Devices:       " -NoNewline
        Write-Host "$onlineCount" -ForegroundColor Green
        if ($IncludeOffline) {
            Write-Host "Offline Addresses:    $offlineCount"
        }
        Write-Host "Scan Duration:        $([math]::Round($elapsed, 1)) seconds"
        
        if ($UseMacVendorAPI) {
            Write-Host "MAC Vendor Lookups:   $script:ApiCallCount API calls"
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
        <strong>Discovery Method:</strong> ICMP Ping $(if($ScanPorts){"+ Port Scan"}) $(if($UseMacVendorAPI){"+ MAC Vendor API"})
        
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
                    
                    foreach ($device in ($onlineDevices | Sort-Object { 
                        $octets = $_.IPAddress.Split('.')
                        [int]$octets[0] * 16777216 + [int]$octets[1] * 65536 + [int]$octets[2] * 256 + [int]$octets[3]
                    })) {
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
