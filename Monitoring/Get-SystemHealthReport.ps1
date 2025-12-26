<#
.SYNOPSIS
    Comprehensive system health monitoring and reporting tool.

.DESCRIPTION
    Collects and analyzes system health metrics including CPU, memory, disk space, 
    critical services, system uptime, network connectivity, and recent event log errors.
    
    Designed for MSP environments to provide quick health assessments during 
    troubleshooting or as part of regular monitoring routines. Supports threshold-based 
    alerting, multiple output formats, and email notifications.

.PARAMETER ComputerName
    Target computer(s) to monitor. Defaults to local computer.
    Supports multiple computers via comma-separated list or pipeline input.

.PARAMETER CPUThreshold
    CPU usage percentage threshold for warnings. Default: 85%

.PARAMETER MemoryThreshold
    Memory usage percentage threshold for warnings. Default: 90%

.PARAMETER DiskThreshold
    Disk space usage percentage threshold for warnings. Default: 85%

.PARAMETER ExportPath
    Path to export report. Supports CSV, JSON, HTML, or XML formats based on extension.

.PARAMETER EmailTo
    Email address(es) to send alerts. Requires EmailFrom and SmtpServer parameters.

.PARAMETER EmailFrom
    Sender email address for alerts.

.PARAMETER SmtpServer
    SMTP server for sending email alerts.

.PARAMETER SmtpPort
    SMTP server port. Default: 25

.PARAMETER IncludeEventLogs
    Include recent critical/error events from System and Application logs.

.PARAMETER EventLogHours
    Hours of event logs to analyze. Default: 24

.PARAMETER TestConnectivity
    Test network connectivity to critical endpoints (DNS, gateway, internet).

.PARAMETER WarningOnly
    Only report items that exceed thresholds (suppress healthy items).

.EXAMPLE
    .\Get-SystemHealthReport.ps1
    
    Performs health check on local computer and displays results in console.

.EXAMPLE
    .\Get-SystemHealthReport.ps1 -ComputerName "SERVER01" -ExportPath "C:\Reports\Health.html"
    
    Checks SERVER01 and exports detailed HTML report.

.EXAMPLE
    .\Get-SystemHealthReport.ps1 -IncludeEventLogs -EventLogHours 48 -WarningOnly
    
    Full health check with 48 hours of event logs, showing only warnings.

.EXAMPLE
    .\Get-SystemHealthReport.ps1 -EmailTo "alerts@contoso.com" -EmailFrom "monitor@contoso.com" -SmtpServer "smtp.contoso.com"
    
    Performs health check and emails results if thresholds are exceeded.

.EXAMPLE
    Get-Content servers.txt | .\Get-SystemHealthReport.ps1 -ExportPath "C:\Reports\MultiServer.csv"
    
    Monitors multiple servers from file and exports consolidated CSV report.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, Administrative privileges for remote computers
    
    TESTING RECOMMENDATIONS:
    - Test email alerting with -WhatIf before production use
    - Verify remote access and WinRM configuration for remote monitoring
    - Establish baselines before setting threshold values
    - Schedule via Task Scheduler for continuous monitoring
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('CN', 'Server')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [ValidateRange(1, 100)]
    [int]$CPUThreshold = 85,
    
    [ValidateRange(1, 100)]
    [int]$MemoryThreshold = 90,
    
    [ValidateRange(1, 100)]
    [int]$DiskThreshold = 85,
    
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
    
    [switch]$IncludeEventLogs,
    
    [ValidateRange(1, 720)]
    [int]$EventLogHours = 24,
    
    [switch]$TestConnectivity,
    
    [switch]$WarningOnly
)

begin {
    # Script metadata
    $ScriptVersion = "1.0"
    $ScriptName = "Get-SystemHealthReport"
    
    Write-Verbose "[$ScriptName v$ScriptVersion] - Yeyland Wutani LLC - Building Better Systems"
    Write-Verbose "Starting health check with thresholds: CPU=$CPUThreshold%, Memory=$MemoryThreshold%, Disk=$DiskThreshold%"
    
    # Validate email parameters
    if ($EmailTo -and (-not $EmailFrom -or -not $SmtpServer)) {
        throw "EmailTo requires both EmailFrom and SmtpServer parameters"
    }
    
    # Critical services to monitor (common across Windows systems)
    $CriticalServices = @(
        'Dhcp',              # DHCP Client
        'Dnscache',          # DNS Client
        'EventLog',          # Windows Event Log
        'LanmanServer',      # Server (file sharing)
        'LanmanWorkstation', # Workstation (network access)
        'RpcSs',             # Remote Procedure Call
        'W32Time',           # Windows Time
        'WinRM',             # Windows Remote Management
        'Netlogon',          # Netlogon (DCs only, will skip if not present)
        'NTDS'               # Active Directory Domain Services (DCs only)
    )
    
    # Initialize results collection
    $AllResults = @()
    
    # Function to get CPU usage
    function Get-CPUUsage {
        param([string]$Computer)
        
        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $Computer -ErrorAction Stop |
                   Measure-Object -Property LoadPercentage -Average |
                   Select-Object -ExpandProperty Average
            return [math]::Round($cpu, 2)
        }
        catch {
            Write-Warning "Failed to retrieve CPU information from $Computer : $_"
            return $null
        }
    }
    
    # Function to get memory usage
    function Get-MemoryUsage {
        param([string]$Computer)
        
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
            $totalMemory = $os.TotalVisibleMemorySize / 1MB
            $freeMemory = $os.FreePhysicalMemory / 1MB
            $usedMemory = $totalMemory - $freeMemory
            $percentUsed = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
            
            return [PSCustomObject]@{
                TotalGB      = [math]::Round($totalMemory, 2)
                UsedGB       = [math]::Round($usedMemory, 2)
                FreeGB       = [math]::Round($freeMemory, 2)
                PercentUsed  = $percentUsed
            }
        }
        catch {
            Write-Warning "Failed to retrieve memory information from $Computer : $_"
            return $null
        }
    }
    
    # Function to get disk usage
    function Get-DiskUsage {
        param([string]$Computer)
        
        try {
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop |
                     Where-Object { $_.DriveType -eq 3 } # Fixed disks only
            
            $diskInfo = foreach ($disk in $disks) {
                if ($disk.Size -gt 0) {
                    $percentUsed = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
                    
                    [PSCustomObject]@{
                        Drive        = $disk.DeviceID
                        Label        = $disk.VolumeName
                        TotalGB      = [math]::Round($disk.Size / 1GB, 2)
                        UsedGB       = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                        FreeGB       = [math]::Round($disk.FreeSpace / 1GB, 2)
                        PercentUsed  = $percentUsed
                        Status       = if ($percentUsed -ge $DiskThreshold) { 'Warning' } else { 'Healthy' }
                    }
                }
            }
            return $diskInfo
        }
        catch {
            Write-Warning "Failed to retrieve disk information from $Computer : $_"
            return $null
        }
    }
    
    # Function to get service status
    function Get-ServiceStatus {
        param([string]$Computer, [string[]]$Services)
        
        try {
            $serviceInfo = foreach ($serviceName in $Services) {
                try {
                    $service = Get-Service -Name $serviceName -ComputerName $Computer -ErrorAction SilentlyContinue
                    
                    if ($service) {
                        [PSCustomObject]@{
                            ServiceName  = $service.Name
                            DisplayName  = $service.DisplayName
                            Status       = $service.Status
                            StartType    = $service.StartType
                            Health       = if ($service.Status -ne 'Running' -and $service.StartType -eq 'Automatic') { 'Warning' } else { 'Healthy' }
                        }
                    }
                }
                catch {
                    # Service doesn't exist on this system (normal for DC-specific services on member servers)
                    continue
                }
            }
            return $serviceInfo
        }
        catch {
            Write-Warning "Failed to retrieve service information from $Computer : $_"
            return $null
        }
    }
    
    # Function to get system uptime
    function Get-SystemUptime {
        param([string]$Computer)
        
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
            $uptime = (Get-Date) - $os.LastBootUpTime
            
            return [PSCustomObject]@{
                LastBootTime = $os.LastBootUpTime
                UptimeDays   = [math]::Round($uptime.TotalDays, 2)
                UptimeHours  = [math]::Round($uptime.TotalHours, 2)
            }
        }
        catch {
            Write-Warning "Failed to retrieve uptime information from $Computer : $_"
            return $null
        }
    }
    
    # Function to get recent event log errors
    function Get-RecentEventErrors {
        param([string]$Computer, [int]$Hours)
        
        try {
            $startTime = (Get-Date).AddHours(-$Hours)
            $events = @()
            
            # System log critical/errors
            $systemEvents = Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                LogName = 'System'
                Level = 1,2  # Critical and Error
                StartTime = $startTime
            } -MaxEvents 50 -ErrorAction SilentlyContinue
            
            if ($systemEvents) {
                $events += $systemEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 25
            }
            
            # Application log critical/errors
            $appEvents = Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                LogName = 'Application'
                Level = 1,2  # Critical and Error
                StartTime = $startTime
            } -MaxEvents 50 -ErrorAction SilentlyContinue
            
            if ($appEvents) {
                $events += $appEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 25
            }
            
            return $events | Sort-Object TimeCreated -Descending | Select-Object -First 50
        }
        catch {
            Write-Warning "Failed to retrieve event logs from $Computer : $_"
            return $null
        }
    }
    
    # Function to test network connectivity
    function Test-NetworkHealth {
        param([string]$Computer)
        
        try {
            $results = @()
            
            # Test DNS resolution
            $dnsTest = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
            $results += [PSCustomObject]@{
                Target = "Internet (8.8.8.8)"
                Status = if ($dnsTest) { 'Reachable' } else { 'Unreachable' }
                Health = if ($dnsTest) { 'Healthy' } else { 'Warning' }
            }
            
            # Test local DNS
            try {
                $dnsConfig = Get-DnsClientServerAddress -AddressFamily IPv4 | 
                             Where-Object { $_.ServerAddresses.Count -gt 0 } | 
                             Select-Object -First 1
                
                if ($dnsConfig -and $dnsConfig.ServerAddresses[0]) {
                    $dnsServerTest = Test-Connection -ComputerName $dnsConfig.ServerAddresses[0] -Count 1 -Quiet -ErrorAction SilentlyContinue
                    $results += [PSCustomObject]@{
                        Target = "DNS Server ($($dnsConfig.ServerAddresses[0]))"
                        Status = if ($dnsServerTest) { 'Reachable' } else { 'Unreachable' }
                        Health = if ($dnsServerTest) { 'Healthy' } else { 'Warning' }
                    }
                }
            }
            catch {
                # DNS config unavailable
            }
            
            # Test default gateway
            try {
                $gateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
                          Select-Object -First 1 -ExpandProperty NextHop
                
                if ($gateway) {
                    $gwTest = Test-Connection -ComputerName $gateway -Count 1 -Quiet -ErrorAction SilentlyContinue
                    $results += [PSCustomObject]@{
                        Target = "Default Gateway ($gateway)"
                        Status = if ($gwTest) { 'Reachable' } else { 'Unreachable' }
                        Health = if ($gwTest) { 'Healthy' } else { 'Warning' }
                    }
                }
            }
            catch {
                # Gateway unavailable
            }
            
            return $results
        }
        catch {
            Write-Warning "Failed to test network connectivity from $Computer : $_"
            return $null
        }
    }
}

process {
    foreach ($Computer in $ComputerName) {
        Write-Verbose "Processing computer: $Computer"
        
        # Test connectivity to computer
        if ($Computer -ne $env:COMPUTERNAME -and $Computer -ne 'localhost' -and $Computer -ne '.') {
            if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
                Write-Warning "Cannot reach $Computer - skipping"
                continue
            }
        }
        
        Write-Progress -Activity "System Health Check" -Status "Analyzing $Computer" -PercentComplete 0
        
        # Collect all metrics
        Write-Progress -Activity "System Health Check" -Status "CPU Usage - $Computer" -PercentComplete 10
        $cpuUsage = Get-CPUUsage -Computer $Computer
        
        Write-Progress -Activity "System Health Check" -Status "Memory Usage - $Computer" -PercentComplete 25
        $memoryUsage = Get-MemoryUsage -Computer $Computer
        
        Write-Progress -Activity "System Health Check" -Status "Disk Usage - $Computer" -PercentComplete 40
        $diskUsage = Get-DiskUsage -Computer $Computer
        
        Write-Progress -Activity "System Health Check" -Status "Service Status - $Computer" -PercentComplete 55
        $serviceStatus = Get-ServiceStatus -Computer $Computer -Services $CriticalServices
        
        Write-Progress -Activity "System Health Check" -Status "System Uptime - $Computer" -PercentComplete 70
        $uptime = Get-SystemUptime -Computer $Computer
        
        # Optional: Event logs
        $eventErrors = $null
        if ($IncludeEventLogs) {
            Write-Progress -Activity "System Health Check" -Status "Event Logs - $Computer" -PercentComplete 80
            $eventErrors = Get-RecentEventErrors -Computer $Computer -Hours $EventLogHours
        }
        
        # Optional: Network connectivity
        $networkHealth = $null
        if ($TestConnectivity -and ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost' -or $Computer -eq '.')) {
            Write-Progress -Activity "System Health Check" -Status "Network Connectivity - $Computer" -PercentComplete 90
            $networkHealth = Test-NetworkHealth -Computer $Computer
        }
        
        Write-Progress -Activity "System Health Check" -Status "Compiling Results - $Computer" -PercentComplete 95
        
        # Determine overall health status
        $warningCount = 0
        $healthStatus = 'Healthy'
        
        if ($cpuUsage -and $cpuUsage -ge $CPUThreshold) { $warningCount++; $healthStatus = 'Warning' }
        if ($memoryUsage -and $memoryUsage.PercentUsed -ge $MemoryThreshold) { $warningCount++; $healthStatus = 'Warning' }
        if ($diskUsage -and ($diskUsage | Where-Object { $_.Status -eq 'Warning' })) { $warningCount++; $healthStatus = 'Warning' }
        if ($serviceStatus -and ($serviceStatus | Where-Object { $_.Health -eq 'Warning' })) { $warningCount++; $healthStatus = 'Warning' }
        if ($networkHealth -and ($networkHealth | Where-Object { $_.Health -eq 'Warning' })) { $warningCount++; $healthStatus = 'Warning' }
        
        # Create result object
        $result = [PSCustomObject]@{
            ComputerName     = $Computer
            Timestamp        = Get-Date
            OverallHealth    = $healthStatus
            WarningCount     = $warningCount
            CPUPercent       = $cpuUsage
            CPUStatus        = if ($cpuUsage -ge $CPUThreshold) { 'Warning' } else { 'Healthy' }
            MemoryPercent    = if ($memoryUsage) { $memoryUsage.PercentUsed } else { $null }
            MemoryUsedGB     = if ($memoryUsage) { $memoryUsage.UsedGB } else { $null }
            MemoryTotalGB    = if ($memoryUsage) { $memoryUsage.TotalGB } else { $null }
            MemoryStatus     = if ($memoryUsage -and $memoryUsage.PercentUsed -ge $MemoryThreshold) { 'Warning' } else { 'Healthy' }
            DiskInfo         = $diskUsage
            ServiceInfo      = $serviceStatus
            UptimeDays       = if ($uptime) { $uptime.UptimeDays } else { $null }
            LastBootTime     = if ($uptime) { $uptime.LastBootTime } else { $null }
            EventErrors      = $eventErrors
            NetworkHealth    = $networkHealth
        }
        
        # Add to collection
        $AllResults += $result
        
        # Display results
        if (-not $WarningOnly -or $healthStatus -eq 'Warning') {
            Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host " System Health Report: $Computer" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "Timestamp:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            
            # Overall status
            $statusColor = if ($healthStatus -eq 'Warning') { 'Yellow' } else { 'Green' }
            Write-Host "Overall Health:  " -NoNewline
            Write-Host $healthStatus -ForegroundColor $statusColor
            
            if ($warningCount -gt 0) {
                Write-Host "Warnings:        $warningCount" -ForegroundColor Yellow
            }
            
            # CPU
            Write-Host "`n--- CPU ---" -ForegroundColor Gray
            $cpuColor = if ($cpuUsage -ge $CPUThreshold) { 'Yellow' } else { 'Green' }
            Write-Host "Usage:           " -NoNewline
            Write-Host "$cpuUsage%" -ForegroundColor $cpuColor
            
            # Memory
            if ($memoryUsage) {
                Write-Host "`n--- Memory ---" -ForegroundColor Gray
                $memColor = if ($memoryUsage.PercentUsed -ge $MemoryThreshold) { 'Yellow' } else { 'Green' }
                Write-Host "Usage:           " -NoNewline
                Write-Host "$($memoryUsage.PercentUsed)%" -ForegroundColor $memColor
                Write-Host "Used:            $($memoryUsage.UsedGB) GB / $($memoryUsage.TotalGB) GB"
            }
            
            # Disks
            if ($diskUsage) {
                Write-Host "`n--- Disk Space ---" -ForegroundColor Gray
                foreach ($disk in $diskUsage) {
                    $diskColor = if ($disk.Status -eq 'Warning') { 'Yellow' } else { 'Green' }
                    Write-Host "$($disk.Drive) " -NoNewline
                    Write-Host "$($disk.PercentUsed)% used" -ForegroundColor $diskColor -NoNewline
                    Write-Host " ($($disk.FreeGB) GB free / $($disk.TotalGB) GB total)"
                }
            }
            
            # Services
            if ($serviceStatus) {
                $stoppedServices = $serviceStatus | Where-Object { $_.Health -eq 'Warning' }
                if ($stoppedServices -or -not $WarningOnly) {
                    Write-Host "`n--- Critical Services ---" -ForegroundColor Gray
                    if ($WarningOnly -and $stoppedServices) {
                        foreach ($svc in $stoppedServices) {
                            Write-Host "$($svc.DisplayName): " -NoNewline
                            Write-Host "$($svc.Status)" -ForegroundColor Yellow
                        }
                    }
                    elseif (-not $WarningOnly) {
                        $running = ($serviceStatus | Where-Object { $_.Status -eq 'Running' }).Count
                        $total = $serviceStatus.Count
                        Write-Host "Running:         $running / $total services"
                        if ($stoppedServices) {
                            Write-Host "Stopped:         " -NoNewline
                            Write-Host "$($stoppedServices.Count)" -ForegroundColor Yellow
                            foreach ($svc in $stoppedServices) {
                                Write-Host "  - $($svc.DisplayName): $($svc.Status)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
            }
            
            # Uptime
            if ($uptime) {
                Write-Host "`n--- System Uptime ---" -ForegroundColor Gray
                Write-Host "Last Boot:       $($uptime.LastBootTime)"
                Write-Host "Uptime:          $($uptime.UptimeDays) days"
            }
            
            # Network
            if ($networkHealth) {
                $networkIssues = $networkHealth | Where-Object { $_.Health -eq 'Warning' }
                if ($networkIssues -or -not $WarningOnly) {
                    Write-Host "`n--- Network Connectivity ---" -ForegroundColor Gray
                    foreach ($net in $networkHealth) {
                        $netColor = if ($net.Health -eq 'Warning') { 'Yellow' } else { 'Green' }
                        Write-Host "$($net.Target): " -NoNewline
                        Write-Host "$($net.Status)" -ForegroundColor $netColor
                    }
                }
            }
            
            # Event errors
            if ($eventErrors) {
                $criticalCount = ($eventErrors | Where-Object { $_.LevelDisplayName -eq 'Critical' }).Count
                $errorCount = ($eventErrors | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
                
                if ($criticalCount -gt 0 -or $errorCount -gt 0) {
                    Write-Host "`n--- Recent Event Log Issues (Last $EventLogHours hours) ---" -ForegroundColor Gray
                    if ($criticalCount -gt 0) {
                        Write-Host "Critical Events: " -NoNewline
                        Write-Host "$criticalCount" -ForegroundColor Red
                    }
                    if ($errorCount -gt 0) {
                        Write-Host "Error Events:    " -NoNewline
                        Write-Host "$errorCount" -ForegroundColor Yellow
                    }
                    
                    Write-Host "`nMost Recent Issues:"
                    $eventErrors | Select-Object -First 5 | ForEach-Object {
                        $eventColor = if ($_.LevelDisplayName -eq 'Critical') { 'Red' } else { 'Yellow' }
                        Write-Host "[$($_.TimeCreated)] Event ID $($_.Id)" -ForegroundColor $eventColor
                        Write-Host "  $($_.Message.Substring(0, [Math]::Min(150, $_.Message.Length)))..."
                    }
                }
            }
            
            Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
        }
        
        Write-Progress -Activity "System Health Check" -Completed
    }
}

end {
    # Export results if requested
    if ($ExportPath) {
        Write-Verbose "Exporting results to: $ExportPath"
        
        $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
        
        try {
            switch ($extension) {
                '.csv' {
                    # Flatten for CSV export
                    $csvData = $AllResults | Select-Object ComputerName, Timestamp, OverallHealth, WarningCount,
                        CPUPercent, CPUStatus, MemoryPercent, MemoryUsedGB, MemoryTotalGB, MemoryStatus,
                        UptimeDays, LastBootTime
                    $csvData | Export-Csv -Path $ExportPath -NoTypeInformation
                    Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green
                }
                
                '.json' {
                    $AllResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Encoding UTF8
                    Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green
                }
                
                '.html' {
                    # Generate HTML report
                    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Health Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        h2 { color: #6B7280; margin-top: 30px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .computer { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .healthy { color: #28a745; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .critical { color: #dc3545; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background-color: white; }
        th { background-color: #6B7280; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .footer { margin-top: 30px; text-align: center; color: #6B7280; font-size: 12px; }
    </style>
</head>
<body>
    <h1>System Health Report</h1>
    <div class="summary">
        <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Systems Monitored:</strong> $($AllResults.Count)<br>
        <strong>Healthy Systems:</strong> $(($AllResults | Where-Object { $_.OverallHealth -eq 'Healthy' }).Count)<br>
        <strong>Systems with Warnings:</strong> $(($AllResults | Where-Object { $_.OverallHealth -eq 'Warning' }).Count)
    </div>
"@
                    
                    foreach ($result in $AllResults) {
                        $statusClass = if ($result.OverallHealth -eq 'Warning') { 'warning' } else { 'healthy' }
                        
                        $html += @"
    <div class="computer">
        <h2>$($result.ComputerName) - <span class="$statusClass">$($result.OverallHealth)</span></h2>
        <p><strong>Last Check:</strong> $($result.Timestamp)</p>
        
        <table>
            <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
            <tr><td>CPU Usage</td><td>$($result.CPUPercent)%</td><td class="$($result.CPUStatus.ToLower())">$($result.CPUStatus)</td></tr>
            <tr><td>Memory Usage</td><td>$($result.MemoryPercent)% ($($result.MemoryUsedGB) GB / $($result.MemoryTotalGB) GB)</td><td class="$($result.MemoryStatus.ToLower())">$($result.MemoryStatus)</td></tr>
            <tr><td>Uptime</td><td>$($result.UptimeDays) days</td><td>-</td></tr>
        </table>
"@
                        
                        if ($result.DiskInfo) {
                            $html += "<h3>Disk Space</h3><table><tr><th>Drive</th><th>Total</th><th>Used</th><th>Free</th><th>Status</th></tr>"
                            foreach ($disk in $result.DiskInfo) {
                                $diskStatusClass = if ($disk.Status -eq 'Warning') { 'warning' } else { 'healthy' }
                                $html += "<tr><td>$($disk.Drive)</td><td>$($disk.TotalGB) GB</td><td>$($disk.UsedGB) GB</td><td>$($disk.FreeGB) GB</td><td class='$diskStatusClass'>$($disk.Status)</td></tr>"
                            }
                            $html += "</table>"
                        }
                        
                        $html += "</div>"
                    }
                    
                    $html += @"
    <div class="footer">
        Yeyland Wutani LLC - Building Better Systems<br>
        System Health Monitoring Report
    </div>
</body>
</html>
"@
                    
                    $html | Out-File -FilePath $ExportPath -Encoding UTF8
                    Write-Host "Results exported to HTML: $ExportPath" -ForegroundColor Green
                }
                
                '.xml' {
                    $AllResults | Export-Clixml -Path $ExportPath
                    Write-Host "Results exported to XML: $ExportPath" -ForegroundColor Green
                }
                
                default {
                    Write-Warning "Unsupported export format: $extension (use .csv, .json, .html, or .xml)"
                }
            }
        }
        catch {
            Write-Error "Failed to export results: $_"
        }
    }
    
    # Send email if configured and warnings exist
    if ($EmailTo -and ($AllResults | Where-Object { $_.OverallHealth -eq 'Warning' })) {
        $warningComputers = $AllResults | Where-Object { $_.OverallHealth -eq 'Warning' }
        
        $emailBody = "System Health Warnings Detected`n`n"
        $emailBody += "The following systems have health warnings:`n`n"
        
        foreach ($comp in $warningComputers) {
            $emailBody += "Computer: $($comp.ComputerName)`n"
            $emailBody += "  Overall Health: $($comp.OverallHealth)`n"
            $emailBody += "  Warning Count: $($comp.WarningCount)`n"
            if ($comp.CPUStatus -eq 'Warning') { $emailBody += "  - CPU Usage: $($comp.CPUPercent)%`n" }
            if ($comp.MemoryStatus -eq 'Warning') { $emailBody += "  - Memory Usage: $($comp.MemoryPercent)%`n" }
            $emailBody += "`n"
        }
        
        $emailBody += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $emailBody += "`n--`nYeyland Wutani LLC - Building Better Systems"
        
        if ($PSCmdlet.ShouldProcess("$EmailTo", "Send health warning email")) {
            try {
                $mailParams = @{
                    To         = $EmailTo
                    From       = $EmailFrom
                    Subject    = "System Health Warning - $($warningComputers.Count) system(s) require attention"
                    Body       = $emailBody
                    SmtpServer = $SmtpServer
                    Port       = $SmtpPort
                }
                
                Send-MailMessage @mailParams
                Write-Host "Alert email sent to $($EmailTo -join ', ')" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to send email alert: $_"
            }
        }
    }
    
    Write-Verbose "Health check completed. Processed $($AllResults.Count) computer(s)."
}
