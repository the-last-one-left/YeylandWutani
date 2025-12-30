<#
.SYNOPSIS
    Advanced network connectivity testing and diagnostics tool.

.DESCRIPTION
    Comprehensive network diagnostics for MSP environments. Tests multiple connectivity
    methods including ICMP ping, TCP port testing, DNS resolution, traceroute, and
    latency analysis. Supports batch testing of multiple targets with detailed reporting.
    
    Features:
    - ICMP ping with packet loss and latency statistics
    - TCP port connectivity testing
    - DNS resolution and reverse DNS lookup
    - Traceroute with hop-by-hop analysis
    - Continuous monitoring mode
    - Batch testing from file or pipeline
    - Multiple export formats (CSV, JSON, HTML)
    - Email alerting for failures

.PARAMETER Target
    Target hostname(s) or IP address(es) to test. Accepts multiple values.
    Can be used with pipeline input from text files.

.PARAMETER Port
    TCP port(s) to test. Default: 80,443,3389 (HTTP, HTTPS, RDP)
    Common ports: 22 (SSH), 25 (SMTP), 53 (DNS), 445 (SMB), 3306 (MySQL), 1433 (MSSQL)

.PARAMETER Count
    Number of ICMP ping packets to send. Default: 4

.PARAMETER Timeout
    Timeout in seconds for connectivity tests. Default: 5

.PARAMETER IncludeTraceroute
    Include traceroute/tracert analysis to show network path.

.PARAMETER IncludeDNS
    Include DNS resolution and reverse DNS lookup.

.PARAMETER ContinuousMonitoring
    Run continuous monitoring until Ctrl+C. Updates every refresh interval.

.PARAMETER RefreshInterval
    Seconds between checks in continuous monitoring mode. Default: 60

.PARAMETER ExportPath
    Path to export results. Supports CSV, JSON, or HTML formats.

.PARAMETER EmailTo
    Email address(es) to send alerts for failed connectivity tests.

.PARAMETER EmailFrom
    Sender email address for alerts.

.PARAMETER SmtpServer
    SMTP server for sending email alerts.

.PARAMETER SmtpPort
    SMTP server port. Default: 25

.PARAMETER AlertOnFailure
    Send email alerts only when connectivity fails.

.PARAMETER Quiet
    Suppress console output. Useful for scheduled tasks.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -Target "8.8.8.8"
    
    Basic ping test to Google DNS with 4 packets.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -Target "server01.contoso.com" -Port 443,3389 -IncludeDNS
    
    Test HTTPS and RDP connectivity with DNS resolution.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -Target "192.168.1.1" -IncludeTraceroute
    
    Ping test with full traceroute to show network path.

.EXAMPLE
    Get-Content servers.txt | .\Test-NetworkConnectivity.ps1 -Port 80,443 -ExportPath "C:\Reports\Connectivity.html"
    
    Batch test multiple servers from file, export HTML report.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -Target "critical-server.com" -ContinuousMonitoring -RefreshInterval 30
    
    Continuous monitoring every 30 seconds until stopped.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -Target "vpn.company.com" -Port 443,1194 -AlertOnFailure -EmailTo "alerts@company.com" -EmailFrom "monitor@company.com" -SmtpServer "smtp.company.com"
    
    Monitor VPN connectivity, email alerts on failures.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+
    
    COMMON USE CASES:
    - Troubleshooting connectivity issues
    - Monitoring critical services (VPN, web servers, databases)
    - Network path analysis with traceroute
    - Batch connectivity validation
    - Scheduled uptime monitoring
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('ComputerName', 'Host', 'IP')]
    [string[]]$Target,
    
    [int[]]$Port = @(80, 443, 3389),
    
    [ValidateRange(1, 100)]
    [int]$Count = 4,
    
    [ValidateRange(1, 300)]
    [int]$Timeout = 5,
    
    [switch]$IncludeTraceroute,
    
    [switch]$IncludeDNS,
    
    [switch]$ContinuousMonitoring,
    
    [ValidateRange(5, 3600)]
    [int]$RefreshInterval = 60,
    
    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Export directory does not exist: $parent"
        }
        $true
    })]
    [string]$ExportPath,
    
    [string[]]$EmailTo,
    
    [string]$EmailFrom,
    
    [string]$SmtpServer,
    
    [int]$SmtpPort = 25,
    
    [switch]$AlertOnFailure,
    
    [switch]$Quiet
)

begin {
    # Script metadata
    $ScriptVersion = "1.0"
    $ScriptName = "Test-NetworkConnectivity"
    
    #region Banner
    function Show-YWBanner {
        $logo = @(
            "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
            "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
            "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
            "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
        )
        $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
        $border  = "=" * 81
        Write-Host ""
        Write-Host $border -ForegroundColor Gray
        foreach ($line in $logo) { Write-Host $line -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host $tagline.PadLeft(62) -ForegroundColor Gray
        Write-Host $border -ForegroundColor Gray
        Write-Host ""
    }
    #endregion Banner
    
    if (-not $Quiet) {
        Show-YWBanner
        Write-Host "  Network Connectivity Tester" -ForegroundColor Cyan
        Write-Host ""
        Write-Verbose "[$ScriptName v$ScriptVersion] - Yeyland Wutani LLC - Building Better Systems"
    }
    
    # Validate email parameters
    if ($EmailTo -and (-not $EmailFrom -or -not $SmtpServer)) {
        throw "EmailTo requires both EmailFrom and SmtpServer parameters"
    }
    
    # Initialize results collection
    $AllResults = @()
    $FailedTests = @()
    
    # Function to test ICMP ping
    function Test-ICMPConnectivity {
        param(
            [string]$Target,
            [int]$Count,
            [int]$Timeout
        )
        
        try {
            $pingResults = Test-Connection -ComputerName $Target -Count $Count -ErrorAction SilentlyContinue
            
            if ($pingResults) {
                $successCount = ($pingResults | Where-Object { $_.StatusCode -eq 0 }).Count
                $failCount = $Count - $successCount
                $avgLatency = ($pingResults | Where-Object { $_.ResponseTime } | Measure-Object -Property ResponseTime -Average).Average
                $minLatency = ($pingResults | Where-Object { $_.ResponseTime } | Measure-Object -Property ResponseTime -Minimum).Minimum
                $maxLatency = ($pingResults | Where-Object { $_.ResponseTime } | Measure-Object -Property ResponseTime -Maximum).Maximum
                
                return [PSCustomObject]@{
                    Status        = if ($successCount -gt 0) { 'Success' } else { 'Failed' }
                    Sent          = $Count
                    Received      = $successCount
                    Lost          = $failCount
                    LossPercent   = [math]::Round(($failCount / $Count) * 100, 2)
                    AvgLatencyMs  = if ($avgLatency) { [math]::Round($avgLatency, 2) } else { $null }
                    MinLatencyMs  = if ($minLatency) { [math]::Round($minLatency, 2) } else { $null }
                    MaxLatencyMs  = if ($maxLatency) { [math]::Round($maxLatency, 2) } else { $null }
                }
            }
            else {
                return [PSCustomObject]@{
                    Status        = 'Failed'
                    Sent          = $Count
                    Received      = 0
                    Lost          = $Count
                    LossPercent   = 100
                    AvgLatencyMs  = $null
                    MinLatencyMs  = $null
                    MaxLatencyMs  = $null
                }
            }
        }
        catch {
            Write-Warning "ICMP test failed for $Target : $_"
            return $null
        }
    }
    
    # Function to test TCP port connectivity
    function Test-TCPPort {
        param(
            [string]$Target,
            [int]$Port,
            [int]$Timeout
        )
        
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($Target, $Port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)
            
            if ($wait) {
                try {
                    $tcpClient.EndConnect($connect)
                    $result = 'Open'
                }
                catch {
                    $result = 'Closed'
                }
            }
            else {
                $result = 'Timeout'
            }
            
            $tcpClient.Close()
            return $result
        }
        catch {
            return 'Error'
        }
    }
    
    # Function to perform DNS lookup
    function Get-DNSInfo {
        param([string]$Target)
        
        try {
            # Forward lookup
            $dnsResult = [System.Net.Dns]::GetHostEntry($Target)
            $ipAddresses = $dnsResult.AddressList | Select-Object -ExpandProperty IPAddressToString
            $hostName = $dnsResult.HostName
            
            # Reverse lookup on first IP
            $reverseHostname = $null
            if ($ipAddresses) {
                try {
                    $reverseResult = [System.Net.Dns]::GetHostEntry($ipAddresses[0])
                    $reverseHostname = $reverseResult.HostName
                }
                catch {
                    $reverseHostname = "N/A"
                }
            }
            
            return [PSCustomObject]@{
                Status          = 'Success'
                ResolvedIPs     = $ipAddresses -join ', '
                Hostname        = $hostName
                ReverseHostname = $reverseHostname
            }
        }
        catch {
            return [PSCustomObject]@{
                Status          = 'Failed'
                ResolvedIPs     = $null
                Hostname        = $null
                ReverseHostname = $null
            }
        }
    }
    
    # Function to perform traceroute
    function Get-Traceroute {
        param(
            [string]$Target,
            [int]$MaxHops = 30
        )
        
        try {
            $tracertOutput = tracert -h $MaxHops -w 1000 $Target 2>&1
            $hops = @()
            
            foreach ($line in $tracertOutput) {
                if ($line -match '^\s+(\d+)\s+') {
                    $hops += $line.Trim()
                }
            }
            
            return [PSCustomObject]@{
                Status = if ($hops.Count -gt 0) { 'Success' } else { 'Failed' }
                Hops   = $hops -join "`n"
                HopCount = $hops.Count
            }
        }
        catch {
            return [PSCustomObject]@{
                Status = 'Error'
                Hops   = $null
                HopCount = 0
            }
        }
    }
}

process {
    do {
        foreach ($TargetHost in $Target) {
            if (-not $Quiet) {
                Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host " Network Connectivity Test: $TargetHost" -ForegroundColor Cyan
                Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            }
            
            # ICMP Ping Test
            if (-not $Quiet) {
                Write-Host "`n--- ICMP Ping Test ---" -ForegroundColor Gray
            }
            
            $pingResult = Test-ICMPConnectivity -Target $TargetHost -Count $Count -Timeout $Timeout
            
            if ($pingResult) {
                if (-not $Quiet) {
                    $pingColor = if ($pingResult.Status -eq 'Success') { 'Green' } else { 'Red' }
                    Write-Host "Status:      " -NoNewline
                    Write-Host "$($pingResult.Status)" -ForegroundColor $pingColor
                    Write-Host "Packets:     Sent=$($pingResult.Sent), Received=$($pingResult.Received), Lost=$($pingResult.Lost) ($($pingResult.LossPercent)% loss)"
                    
                    if ($pingResult.AvgLatencyMs) {
                        Write-Host "Latency:     Min=$($pingResult.MinLatencyMs)ms, Max=$($pingResult.MaxLatencyMs)ms, Avg=$($pingResult.AvgLatencyMs)ms"
                    }
                }
            }
            
            # DNS Resolution
            $dnsResult = $null
            if ($IncludeDNS) {
                if (-not $Quiet) {
                    Write-Host "`n--- DNS Resolution ---" -ForegroundColor Gray
                }
                
                $dnsResult = Get-DNSInfo -Target $TargetHost
                
                if (-not $Quiet) {
                    $dnsColor = if ($dnsResult.Status -eq 'Success') { 'Green' } else { 'Red' }
                    Write-Host "Status:      " -NoNewline
                    Write-Host "$($dnsResult.Status)" -ForegroundColor $dnsColor
                    
                    if ($dnsResult.ResolvedIPs) {
                        Write-Host "IP Addresses: $($dnsResult.ResolvedIPs)"
                        Write-Host "Hostname:     $($dnsResult.Hostname)"
                        Write-Host "Reverse DNS:  $($dnsResult.ReverseHostname)"
                    }
                }
            }
            
            # TCP Port Tests
            if (-not $Quiet) {
                Write-Host "`n--- TCP Port Connectivity ---" -ForegroundColor Gray
            }
            
            $portResults = @()
            foreach ($PortNumber in $Port) {
                $portStatus = Test-TCPPort -Target $TargetHost -Port $PortNumber -Timeout $Timeout
                
                $portResults += [PSCustomObject]@{
                    Port   = $PortNumber
                    Status = $portStatus
                }
                
                if (-not $Quiet) {
                    $portColor = if ($portStatus -eq 'Open') { 'Green' } else { 'Red' }
                    Write-Host "Port $PortNumber" -NoNewline
                    Write-Host " - " -NoNewline
                    Write-Host "$portStatus" -ForegroundColor $portColor
                }
            }
            
            # Traceroute
            $tracerouteResult = $null
            if ($IncludeTraceroute) {
                if (-not $Quiet) {
                    Write-Host "`n--- Traceroute ---" -ForegroundColor Gray
                }
                
                $tracerouteResult = Get-Traceroute -Target $TargetHost
                
                if (-not $Quiet) {
                    if ($tracerouteResult.Status -eq 'Success') {
                        Write-Host "Hops to destination: $($tracerouteResult.HopCount)"
                        Write-Host "`n$($tracerouteResult.Hops)" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "Traceroute failed" -ForegroundColor Red
                    }
                }
            }
            
            # Determine overall status
            $overallStatus = 'Success'
            if ($pingResult -and $pingResult.Status -eq 'Failed') {
                $overallStatus = 'Failed'
            }
            
            $anyPortOpen = $portResults | Where-Object { $_.Status -eq 'Open' }
            if (-not $anyPortOpen) {
                $overallStatus = 'Failed'
            }
            
            # Create result object
            $result = [PSCustomObject]@{
                Target           = $TargetHost
                Timestamp        = Get-Date
                OverallStatus    = $overallStatus
                PingStatus       = if ($pingResult) { $pingResult.Status } else { 'N/A' }
                PacketLoss       = if ($pingResult) { $pingResult.LossPercent } else { $null }
                AvgLatencyMs     = if ($pingResult) { $pingResult.AvgLatencyMs } else { $null }
                DNSStatus        = if ($dnsResult) { $dnsResult.Status } else { 'N/A' }
                ResolvedIPs      = if ($dnsResult) { $dnsResult.ResolvedIPs } else { $null }
                PortResults      = $portResults
                TracerouteHops   = if ($tracerouteResult) { $tracerouteResult.HopCount } else { $null }
            }
            
            $AllResults += $result
            
            # Track failures
            if ($overallStatus -eq 'Failed') {
                $FailedTests += $result
            }
            
            if (-not $Quiet) {
                Write-Host "`n--- Overall Status ---" -ForegroundColor Gray
                $statusColor = if ($overallStatus -eq 'Success') { 'Green' } else { 'Red' }
                Write-Host "Result: " -NoNewline
                Write-Host "$overallStatus" -ForegroundColor $statusColor
                Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
            }
        }
        
        # Continuous monitoring
        if ($ContinuousMonitoring) {
            if (-not $Quiet) {
                Write-Host "Next check in $RefreshInterval seconds... (Press Ctrl+C to stop)" -ForegroundColor Yellow
            }
            Start-Sleep -Seconds $RefreshInterval
        }
        
    } while ($ContinuousMonitoring)
}

end {
    # Export results if requested
    if ($ExportPath) {
        $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
        
        try {
            switch ($extension) {
                '.csv' {
                    # Flatten for CSV
                    $csvData = $AllResults | Select-Object Target, Timestamp, OverallStatus, PingStatus,
                        PacketLoss, AvgLatencyMs, DNSStatus, ResolvedIPs, TracerouteHops
                    $csvData | Export-Csv -Path $ExportPath -NoTypeInformation
                    
                    if (-not $Quiet) {
                        Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.json' {
                    $AllResults | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportPath -Encoding UTF8
                    
                    if (-not $Quiet) {
                        Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.html' {
                    $successCount = ($AllResults | Where-Object { $_.OverallStatus -eq 'Success' }).Count
                    $failCount = ($AllResults | Where-Object { $_.OverallStatus -eq 'Failed' }).Count
                    
                    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Connectivity Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 15px; }
        .stat-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 32px; font-weight: bold; }
        .stat-label { color: #6B7280; margin-top: 5px; }
        .success .stat-number { color: #28a745; }
        .failed .stat-number { color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #6B7280; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .status-success { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .footer { margin-top: 30px; text-align: center; color: #6B7280; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Network Connectivity Report</h1>
    <div class="summary">
        <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Targets Tested:</strong> $($AllResults.Count)
        
        <div class="summary-grid">
            <div class="stat-box success">
                <div class="stat-number">$successCount</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-box failed">
                <div class="stat-number">$failCount</div>
                <div class="stat-label">Failed</div>
            </div>
        </div>
    </div>
    
    <table>
        <tr>
            <th>Target</th>
            <th>Timestamp</th>
            <th>Overall Status</th>
            <th>Ping Status</th>
            <th>Packet Loss %</th>
            <th>Avg Latency (ms)</th>
            <th>DNS Status</th>
        </tr>
"@
                    
                    foreach ($result in $AllResults) {
                        $statusClass = "status-$($result.OverallStatus.ToLower())"
                        
                        $html += @"
        <tr>
            <td><strong>$($result.Target)</strong></td>
            <td>$($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
            <td class="$statusClass">$($result.OverallStatus)</td>
            <td>$($result.PingStatus)</td>
            <td>$($result.PacketLoss)%</td>
            <td>$($result.AvgLatencyMs)</td>
            <td>$($result.DNSStatus)</td>
        </tr>
"@
                    }
                    
                    $html += @"
    </table>
    <div class="footer">
        Yeyland Wutani LLC - Building Better Systems<br>
        Network Connectivity Report
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
    
    # Send email alerts if configured and failures exist
    if ($EmailTo -and $FailedTests.Count -gt 0 -and $AlertOnFailure) {
        $emailBody = "Network Connectivity Failures Detected`n`n"
        $emailBody += "The following targets failed connectivity tests:`n`n"
        
        foreach ($failed in $FailedTests) {
            $emailBody += "Target: $($failed.Target)`n"
            $emailBody += "  Timestamp: $($failed.Timestamp)`n"
            $emailBody += "  Ping Status: $($failed.PingStatus)`n"
            $emailBody += "  Packet Loss: $($failed.PacketLoss)%`n"
            
            if ($failed.PortResults) {
                $closedPorts = $failed.PortResults | Where-Object { $_.Status -ne 'Open' }
                if ($closedPorts) {
                    $emailBody += "  Closed/Timeout Ports: $(($closedPorts | Select-Object -ExpandProperty Port) -join ', ')`n"
                }
            }
            $emailBody += "`n"
        }
        
        $emailBody += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $emailBody += "`n--`nYeyland Wutani LLC - Building Better Systems"
        
        try {
            $mailParams = @{
                To         = $EmailTo
                From       = $EmailFrom
                Subject    = "Network Connectivity Alert - $($FailedTests.Count) target(s) unreachable"
                Body       = $emailBody
                SmtpServer = $SmtpServer
                Port       = $SmtpPort
            }
            
            Send-MailMessage @mailParams
            
            if (-not $Quiet) {
                Write-Host "`nAlert email sent to $($EmailTo -join ', ')" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to send email alert: $_"
        }
    }
    
    if (-not $Quiet -and -not $ContinuousMonitoring) {
        Write-Host "`nConnectivity tests completed. Tested $($AllResults.Count) target(s)." -ForegroundColor Cyan
    }
}
