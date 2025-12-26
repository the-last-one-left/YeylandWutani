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
    $ScriptVersion = "1.4"
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
            # Use arp -a without IP filter, then parse for our specific IP
            $arpOutput = & arp -a 2>$null
            
            # Find the line containing our IP address
            $arpLine = $arpOutput | Where-Object { $_ -match "\b$([regex]::Escape($IP))\b" }
            
            if ($arpLine -and $arpLine -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                $macAddress = $matches[0].ToUpper().Replace(':', '-')
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
        # Debug: Show what we're working with
        if (-not $Quiet) {
            $onlineWithMac = $Results | Where-Object { $_.Status -eq 'Online' -and $_.MACAddress -ne 'N/A' }
            $unknownInLocal = $onlineWithMac | Where-Object { $_.Vendor -eq 'Unknown' }
            
            Write-Host "`nMAC Vendor Analysis:" -ForegroundColor Cyan
            Write-Host "  Online devices with MAC: $($onlineWithMac.Count)"
            Write-Host "  Unknown vendors: $($unknownInLocal.Count)"
            
            # Show sample device for debugging
            if ($unknownInLocal.Count -gt 0) {
                $sample = $unknownInLocal | Select-Object -First 1
                Write-Host "  Sample unknown device:" -ForegroundColor Gray
                Write-Host "    IP: $($sample.IPAddress)" -ForegroundColor Gray
                Write-Host "    MAC: $($sample.MACAddress)" -ForegroundColor Gray
                Write-Host "    Prefix: $($sample.MACPrefix)" -ForegroundColor Gray
                Write-Host "    Vendor: $($sample.Vendor)" -ForegroundColor Gray
            }
        }
        
        $unknownVendors = $Results | Where-Object { 
            $_.Status -eq 'Online' -and 
            $_.MACAddress -ne 'N/A' -and
            $_.Vendor -eq 'Unknown' -and 
            $_.MACPrefix -ne $null -and
            $_.MACPrefix -ne ''
        }
        
        if ($unknownVendors.Count -gt 0) {
            # Get unique MAC prefixes to lookup
            $uniquePrefixes = $unknownVendors | 
                Select-Object -ExpandProperty MACPrefix -Unique
            
            if (-not $Quiet) {
                Write-Host "  Unique MAC prefixes to lookup: $($uniquePrefixes.Count)" -ForegroundColor Yellow
                Write-Host "`nLooking up MAC vendors via API..." -ForegroundColor Yellow
            }
            
            $lookupCount = 0
            foreach ($prefix in $uniquePrefixes) {
                $vendor = Get-MacVendorFromAPI -MacPrefix $prefix -Cache $script:MacVendorCache
                
                # Update all results with this MAC prefix
                $Results | Where-Object { $_.MACPrefix -eq $prefix } | ForEach-Object {
                    $_.Vendor = $vendor
                    
                    # Re-evaluate device type based on new vendor information
                    if ($vendor -match 'Aruba|WatchGuard|Ubiquiti|3Com|Cisco|Netgear|D-Link') {
                        if ($_.OpenPorts -contains 22 -or $_.OpenPorts -contains 23 -or $_.OpenPorts -contains 443) {
                            $_.DeviceType = "Network Device"
                            $_.OS = "$vendor Device"
                        }
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
        elseif ($UseMacVendorAPI -and -not $Quiet) {
            Write-Host "`nNo unknown MAC vendors found - all identified from local database" -ForegroundColor Green
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
            $identifiedVendors = ($AllResults | Where-Object { $_.Status -eq 'Online' -and $_.Vendor -ne 'Unknown' }).Count
            $unknownVendors = ($AllResults | Where-Object { $_.Status -eq 'Online' -and $_.Vendor -eq 'Unknown' }).Count
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
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background: linear-gradient(135deg, #f5f5f5 0%, #e0e0e0 100%);
        }
        .header {
            background: linear-gradient(135deg, #FF6600 0%, #6B7280 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { 
            margin: 0; 
            font-size: 36px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header .tagline {
            font-size: 14px;
            margin-top: 5px;
            opacity: 0.9;
            font-style: italic;
        }
        h2 { 
            color: #FF6600; 
            margin-top: 30px;
            border-bottom: 3px solid #6B7280;
            padding-bottom: 10px;
        }
        .summary { 
            background-color: white; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 5px solid #FF6600;
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin-top: 15px; 
        }
        .stat-box { 
            background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
            padding: 20px; 
            border-radius: 8px; 
            text-align: center;
            border: 2px solid #6B7280;
            transition: transform 0.2s;
        }
        .stat-box:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .stat-number { 
            font-size: 36px; 
            font-weight: bold; 
            color: #FF6600;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.1);
        }
        .stat-label { 
            color: #6B7280; 
            margin-top: 8px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 15px; 
            background-color: white; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th { 
            background: linear-gradient(135deg, #6B7280 0%, #4a5568 100%);
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }
        td { 
            padding: 12px; 
            border-bottom: 1px solid #e0e0e0;
        }
        tr:hover { 
            background-color: #fff5f0;
        }
        tr:last-child td {
            border-bottom: none;
        }
        .device-server { 
            border-left: 4px solid #0066cc;
            background-color: #e8f4fd;
        }
        .device-workstation { 
            border-left: 4px solid #28a745;
            background-color: #e8f5e9;
        }
        .device-printer { 
            border-left: 4px solid #ffc107;
            background-color: #fff8e1;
        }
        .device-network { 
            border-left: 4px solid #FF6600;
            background-color: #fff0e6;
        }
        .footer { 
            margin-top: 40px; 
            text-align: center; 
            color: #6B7280;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .footer .company { 
            font-size: 20px;
            font-weight: bold;
            color: #FF6600;
            margin-bottom: 5px;
        }
        .footer .tagline {
            font-style: italic;
            color: #6B7280;
            margin-bottom: 10px;
        }
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
