<#
.SYNOPSIS
    Monitors disk space usage with threshold-based alerting and email notifications.

.DESCRIPTION
    Comprehensive disk space monitoring tool for MSP environments. Monitors local and 
    network drives, tracks historical usage, provides threshold-based alerting, and 
    supports email notifications for proactive capacity management.
    
    Features:
    - Multi-level thresholds (Warning/Critical)
    - Historical trend tracking
    - Growth rate analysis
    - Network share monitoring
    - Email alerting
    - Multiple export formats
    - Scheduled task integration

.PARAMETER ComputerName
    Target computer(s) to monitor. Defaults to local computer.
    Supports multiple computers via comma-separated list or pipeline input.

.PARAMETER WarningThreshold
    Percentage used threshold for warning alerts. Default: 80%

.PARAMETER CriticalThreshold
    Percentage used threshold for critical alerts. Default: 90%

.PARAMETER MinimumSizeGB
    Minimum drive size in GB to monitor. Skips smaller drives. Default: 1 GB

.PARAMETER IncludeNetworkDrives
    Include network-mapped drives in monitoring. Default: False (local drives only)

.PARAMETER ExportPath
    Path to export report. Supports CSV, JSON, HTML, or XML formats.

.PARAMETER HistoryPath
    Path to CSV file for tracking historical disk usage trends.
    If file exists, appends new data. If not, creates new file.

.PARAMETER CalculateGrowth
    Calculate growth rate based on historical data. Requires HistoryPath parameter.

.PARAMETER EmailTo
    Email address(es) to send alerts. Requires EmailFrom and SmtpServer.

.PARAMETER EmailFrom
    Sender email address for alerts.

.PARAMETER SmtpServer
    SMTP server for sending email alerts.

.PARAMETER SmtpPort
    SMTP server port. Default: 25

.PARAMETER AlertOnWarning
    Send email alerts for Warning threshold breaches. Default: Critical only

.PARAMETER Quiet
    Suppress console output. Useful for scheduled tasks.

.EXAMPLE
    .\Get-DiskSpaceMonitor.ps1
    
    Monitors local drives on current computer with default thresholds.

.EXAMPLE
    .\Get-DiskSpaceMonitor.ps1 -ComputerName "SERVER01" -WarningThreshold 75 -CriticalThreshold 85
    
    Monitors SERVER01 with custom thresholds.

.EXAMPLE
    .\Get-DiskSpaceMonitor.ps1 -IncludeNetworkDrives -ExportPath "C:\Reports\DiskSpace.html"
    
    Monitors all drives including network shares, exports HTML report.

.EXAMPLE
    .\Get-DiskSpaceMonitor.ps1 -HistoryPath "C:\Monitoring\DiskHistory.csv" -CalculateGrowth
    
    Tracks historical usage and calculates growth rates.

.EXAMPLE
    .\Get-DiskSpaceMonitor.ps1 -EmailTo "alerts@contoso.com" -EmailFrom "monitor@contoso.com" -SmtpServer "smtp.contoso.com" -AlertOnWarning
    
    Sends email alerts for both Warning and Critical thresholds.

.EXAMPLE
    Get-Content servers.txt | .\Get-DiskSpaceMonitor.ps1 -Quiet -ExportPath "C:\Reports\AllServers.csv"
    
    Silent monitoring of multiple servers from file with consolidated report.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, WMI/CIM access to target computers
    
    SCHEDULED MONITORING SETUP:
    Create scheduled task to run daily/hourly for proactive monitoring:
    
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Get-DiskSpaceMonitor.ps1 -Quiet -HistoryPath C:\Monitoring\History.csv -EmailTo alerts@company.com -EmailFrom monitor@company.com -SmtpServer smtp.company.com"
    
    $trigger = New-ScheduledTaskTrigger -Daily -At 8am
    
    Register-ScheduledTask -TaskName "DiskSpaceMonitor" -Action $action -Trigger $trigger -RunLevel Highest
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('CN', 'Server')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [ValidateRange(1, 99)]
    [int]$WarningThreshold = 80,
    
    [ValidateRange(1, 100)]
    [int]$CriticalThreshold = 90,
    
    [ValidateRange(0, 1000)]
    [int]$MinimumSizeGB = 1,
    
    [switch]$IncludeNetworkDrives,
    
    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Export directory does not exist: $parent"
        }
        $true
    })]
    [string]$ExportPath,
    
    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "History directory does not exist: $parent"
        }
        $true
    })]
    [string]$HistoryPath,
    
    [switch]$CalculateGrowth,
    
    [string[]]$EmailTo,
    
    [string]$EmailFrom,
    
    [string]$SmtpServer,
    
    [int]$SmtpPort = 25,
    
    [switch]$AlertOnWarning,
    
    [switch]$Quiet
)

begin {
    # Script metadata
    $ScriptVersion = "1.0"
    $ScriptName = "Get-DiskSpaceMonitor"
    
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
        Write-Host "  Disk Space Monitor" -ForegroundColor Cyan
        Write-Host ""
        Write-Verbose "[$ScriptName v$ScriptVersion] - Yeyland Wutani LLC - Building Better Systems"
        Write-Verbose "Monitoring with thresholds: Warning=$WarningThreshold%, Critical=$CriticalThreshold%"
    }
    
    # Validate thresholds
    if ($CriticalThreshold -le $WarningThreshold) {
        throw "CriticalThreshold must be greater than WarningThreshold"
    }
    
    # Validate email parameters
    if ($EmailTo -and (-not $EmailFrom -or -not $SmtpServer)) {
        throw "EmailTo requires both EmailFrom and SmtpServer parameters"
    }
    
    # Validate growth calculation
    if ($CalculateGrowth -and -not $HistoryPath) {
        throw "CalculateGrowth requires HistoryPath parameter"
    }
    
    # Load historical data if available
    $historicalData = @{}
    if ($HistoryPath -and (Test-Path $HistoryPath)) {
        try {
            $history = Import-Csv -Path $HistoryPath
            foreach ($record in $history) {
                $key = "$($record.ComputerName)-$($record.Drive)"
                if (-not $historicalData.ContainsKey($key)) {
                    $historicalData[$key] = @()
                }
                $historicalData[$key] += $record
            }
            if (-not $Quiet) {
                Write-Verbose "Loaded $($history.Count) historical records from $HistoryPath"
            }
        }
        catch {
            Write-Warning "Failed to load historical data: $_"
        }
    }
    
    # Initialize results collection
    $AllResults = @()
    $AlertResults = @()
}

process {
    foreach ($Computer in $ComputerName) {
        if (-not $Quiet) {
            Write-Verbose "Processing computer: $Computer"
        }
        
        # Test connectivity to computer
        if ($Computer -ne $env:COMPUTERNAME -and $Computer -ne 'localhost' -and $Computer -ne '.') {
            if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
                Write-Warning "Cannot reach $Computer - skipping"
                continue
            }
        }
        
        try {
            # Get all logical disks
            $driveTypes = @(3)  # Local drives (fixed disks)
            if ($IncludeNetworkDrives) {
                $driveTypes += 4  # Network drives
            }
            
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop |
                     Where-Object { 
                         $driveTypes -contains $_.DriveType -and 
                         $_.Size -gt 0 -and 
                         ($_.Size / 1GB) -ge $MinimumSizeGB 
                     }
            
            if (-not $disks) {
                Write-Warning "No qualifying disks found on $Computer"
                continue
            }
            
            foreach ($disk in $disks) {
                # Calculate usage metrics
                $totalGB = [math]::Round($disk.Size / 1GB, 2)
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $usedGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                $percentUsed = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
                $percentFree = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
                
                # Determine status
                $status = 'Healthy'
                $alertLevel = 'None'
                if ($percentUsed -ge $CriticalThreshold) {
                    $status = 'Critical'
                    $alertLevel = 'Critical'
                }
                elseif ($percentUsed -ge $WarningThreshold) {
                    $status = 'Warning'
                    $alertLevel = 'Warning'
                }
                
                # Calculate growth rate if historical data available
                $growthRate = $null
                $daysToFull = $null
                
                if ($CalculateGrowth -and $HistoryPath) {
                    $key = "$Computer-$($disk.DeviceID)"
                    if ($historicalData.ContainsKey($key)) {
                        $historyRecords = $historicalData[$key] | Sort-Object { [DateTime]$_.Timestamp }
                        
                        if ($historyRecords.Count -ge 2) {
                            # Compare to oldest record
                            $oldest = $historyRecords[0]
                            $oldestDate = [DateTime]$oldest.Timestamp
                            $oldestUsedGB = [double]$oldest.UsedGB
                            
                            $daysDiff = ((Get-Date) - $oldestDate).TotalDays
                            if ($daysDiff -gt 0) {
                                $gbGrowth = $usedGB - $oldestUsedGB
                                $growthRate = [math]::Round($gbGrowth / $daysDiff, 4)  # GB per day
                                
                                # Calculate days until full (if growing)
                                if ($growthRate -gt 0) {
                                    $remainingGB = $freeGB
                                    $daysToFull = [math]::Round($remainingGB / $growthRate, 0)
                                }
                            }
                        }
                    }
                }
                
                # Create result object
                $result = [PSCustomObject]@{
                    ComputerName   = $Computer
                    Timestamp      = Get-Date
                    Drive          = $disk.DeviceID
                    Label          = $disk.VolumeName
                    DriveType      = if ($disk.DriveType -eq 3) { 'Local' } else { 'Network' }
                    TotalGB        = $totalGB
                    UsedGB         = $usedGB
                    FreeGB         = $freeGB
                    PercentUsed    = $percentUsed
                    PercentFree    = $percentFree
                    Status         = $status
                    AlertLevel     = $alertLevel
                    GrowthRateGBDay = $growthRate
                    DaysToFull     = $daysToFull
                }
                
                $AllResults += $result
                
                # Add to alert list if threshold exceeded
                if ($alertLevel -ne 'None') {
                    if ($alertLevel -eq 'Critical' -or ($alertLevel -eq 'Warning' -and $AlertOnWarning)) {
                        $AlertResults += $result
                    }
                }
                
                # Display result if not quiet
                if (-not $Quiet) {
                    $statusColor = switch ($status) {
                        'Critical' { 'Red' }
                        'Warning' { 'Yellow' }
                        default { 'Green' }
                    }
                    
                    Write-Host "[$Computer] " -NoNewline -ForegroundColor Cyan
                    Write-Host "$($disk.DeviceID) " -NoNewline
                    Write-Host "$percentUsed% used " -ForegroundColor $statusColor -NoNewline
                    Write-Host "($freeGB GB free / $totalGB GB) - " -NoNewline
                    Write-Host $status -ForegroundColor $statusColor
                    
                    if ($growthRate) {
                        $growthColor = if ($growthRate -gt 1) { 'Yellow' } elseif ($growthRate -gt 0) { 'Gray' } else { 'Green' }
                        Write-Host "  Growth: " -NoNewline
                        Write-Host "$growthRate GB/day" -ForegroundColor $growthColor
                        
                        if ($daysToFull) {
                            $daysColor = if ($daysToFull -lt 30) { 'Red' } elseif ($daysToFull -lt 90) { 'Yellow' } else { 'Gray' }
                            Write-Host "  Est. Full: " -NoNewline
                            Write-Host "$daysToFull days" -ForegroundColor $daysColor
                        }
                    }
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve disk information from $Computer : $_"
        }
    }
}

end {
    # Update history file if specified
    if ($HistoryPath) {
        try {
            # Prepare history records (simplified for CSV)
            $historyRecords = $AllResults | Select-Object ComputerName, Timestamp, Drive, Label, 
                TotalGB, UsedGB, FreeGB, PercentUsed, Status
            
            if (Test-Path $HistoryPath) {
                # Append to existing file
                $historyRecords | Export-Csv -Path $HistoryPath -NoTypeInformation -Append
                if (-not $Quiet) {
                    Write-Host "`nHistory updated: $HistoryPath" -ForegroundColor Green
                }
            }
            else {
                # Create new file
                $historyRecords | Export-Csv -Path $HistoryPath -NoTypeInformation
                if (-not $Quiet) {
                    Write-Host "`nHistory file created: $HistoryPath" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Error "Failed to update history file: $_"
        }
    }
    
    # Export results if requested
    if ($ExportPath) {
        if (-not $Quiet) {
            Write-Verbose "Exporting results to: $ExportPath"
        }
        
        $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
        
        try {
            switch ($extension) {
                '.csv' {
                    $AllResults | Export-Csv -Path $ExportPath -NoTypeInformation
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
                    # Generate HTML report
                    $criticalCount = ($AllResults | Where-Object { $_.Status -eq 'Critical' }).Count
                    $warningCount = ($AllResults | Where-Object { $_.Status -eq 'Warning' }).Count
                    $healthyCount = ($AllResults | Where-Object { $_.Status -eq 'Healthy' }).Count
                    
                    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Disk Space Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        h2 { color: #6B7280; margin-top: 30px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }
        .stat-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 32px; font-weight: bold; }
        .stat-label { color: #6B7280; margin-top: 5px; }
        .critical .stat-number { color: #dc3545; }
        .warning .stat-number { color: #ffc107; }
        .healthy .stat-number { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #6B7280; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-healthy { color: #28a745; }
        .progress-bar { width: 100%; background-color: #e9ecef; border-radius: 3px; height: 20px; position: relative; }
        .progress-fill { background-color: #28a745; height: 100%; border-radius: 3px; transition: width 0.3s; }
        .progress-fill.warning { background-color: #ffc107; }
        .progress-fill.critical { background-color: #dc3545; }
        .progress-text { position: absolute; width: 100%; text-align: center; line-height: 20px; color: white; font-weight: bold; font-size: 12px; }
        .footer { margin-top: 30px; text-align: center; color: #6B7280; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Disk Space Monitoring Report</h1>
    <div class="summary">
        <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Systems Monitored:</strong> $(($AllResults | Select-Object -Unique ComputerName).Count)<br>
        <strong>Total Drives:</strong> $($AllResults.Count)
        
        <div class="summary-grid">
            <div class="stat-box critical">
                <div class="stat-number">$criticalCount</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box warning">
                <div class="stat-number">$warningCount</div>
                <div class="stat-label">Warning</div>
            </div>
            <div class="stat-box healthy">
                <div class="stat-number">$healthyCount</div>
                <div class="stat-label">Healthy</div>
            </div>
        </div>
    </div>
    
    <h2>Drive Details</h2>
    <table>
        <tr>
            <th>Computer</th>
            <th>Drive</th>
            <th>Label</th>
            <th>Type</th>
            <th>Total</th>
            <th>Used</th>
            <th>Free</th>
            <th>Usage</th>
            <th>Status</th>
        </tr>
"@
                    
                    foreach ($result in ($AllResults | Sort-Object Status -Descending)) {
                        $statusClass = "status-$($result.Status.ToLower())"
                        $barClass = if ($result.Status -eq 'Critical') { 'critical' } 
                                   elseif ($result.Status -eq 'Warning') { 'warning' } 
                                   else { '' }
                        
                        $html += @"
        <tr>
            <td>$($result.ComputerName)</td>
            <td><strong>$($result.Drive)</strong></td>
            <td>$($result.Label)</td>
            <td>$($result.DriveType)</td>
            <td>$($result.TotalGB) GB</td>
            <td>$($result.UsedGB) GB</td>
            <td>$($result.FreeGB) GB</td>
            <td>
                <div class="progress-bar">
                    <div class="progress-fill $barClass" style="width: $($result.PercentUsed)%"></div>
                    <div class="progress-text">$($result.PercentUsed)%</div>
                </div>
            </td>
            <td class="$statusClass">$($result.Status)</td>
        </tr>
"@
                    }
                    
                    $html += @"
    </table>
    <div class="footer">
        Yeyland Wutani LLC - Building Better Systems<br>
        Disk Space Monitoring Report
    </div>
</body>
</html>
"@
                    
                    $html | Out-File -FilePath $ExportPath -Encoding UTF8
                    if (-not $Quiet) {
                        Write-Host "Results exported to HTML: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.xml' {
                    $AllResults | Export-Clixml -Path $ExportPath
                    if (-not $Quiet) {
                        Write-Host "Results exported to XML: $ExportPath" -ForegroundColor Green
                    }
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
    
    # Send email alerts if configured and alerts exist
    if ($EmailTo -and $AlertResults.Count -gt 0) {
        $criticalAlerts = $AlertResults | Where-Object { $_.AlertLevel -eq 'Critical' }
        $warningAlerts = $AlertResults | Where-Object { $_.AlertLevel -eq 'Warning' }
        
        $emailSubject = "Disk Space Alert - $($AlertResults.Count) drive(s) require attention"
        if ($criticalAlerts.Count -gt 0) {
            $emailSubject = "CRITICAL: Disk Space Alert - $($criticalAlerts.Count) drive(s) critical"
        }
        
        $emailBody = "Disk Space Alerts`n"
        $emailBody += "===============================================`n`n"
        
        if ($criticalAlerts.Count -gt 0) {
            $emailBody += "CRITICAL ALERTS ($($criticalAlerts.Count)):`n"
            $emailBody += "-----------------------------------------------`n"
            foreach ($alert in $criticalAlerts) {
                $emailBody += "Computer: $($alert.ComputerName)`n"
                $emailBody += "  Drive: $($alert.Drive) ($($alert.Label))`n"
                $emailBody += "  Usage: $($alert.PercentUsed)% ($($alert.FreeGB) GB free / $($alert.TotalGB) GB)`n"
                $emailBody += "  Status: CRITICAL (>= $CriticalThreshold%)`n"
                if ($alert.DaysToFull) {
                    $emailBody += "  Est. Full: $($alert.DaysToFull) days`n"
                }
                $emailBody += "`n"
            }
        }
        
        if ($warningAlerts.Count -gt 0) {
            $emailBody += "WARNING ALERTS ($($warningAlerts.Count)):`n"
            $emailBody += "-----------------------------------------------`n"
            foreach ($alert in $warningAlerts) {
                $emailBody += "Computer: $($alert.ComputerName)`n"
                $emailBody += "  Drive: $($alert.Drive) ($($alert.Label))`n"
                $emailBody += "  Usage: $($alert.PercentUsed)% ($($alert.FreeGB) GB free / $($alert.TotalGB) GB)`n"
                $emailBody += "  Status: WARNING (>= $WarningThreshold%)`n"
                if ($alert.DaysToFull) {
                    $emailBody += "  Est. Full: $($alert.DaysToFull) days`n"
                }
                $emailBody += "`n"
            }
        }
        
        $emailBody += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $emailBody += "`n--`nYeyland Wutani LLC - Building Better Systems"
        
        if ($PSCmdlet.ShouldProcess("$EmailTo", "Send disk space alert email")) {
            try {
                $mailParams = @{
                    To         = $EmailTo
                    From       = $EmailFrom
                    Subject    = $emailSubject
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
    }
    
    # Summary
    if (-not $Quiet) {
        Write-Host "`n===========================================================" -ForegroundColor Cyan
        Write-Host " Disk Space Monitoring Summary" -ForegroundColor Cyan
        Write-Host "===========================================================" -ForegroundColor Cyan
        Write-Host "Total Drives Monitored: $($AllResults.Count)"
        
        $criticalCount = ($AllResults | Where-Object { $_.Status -eq 'Critical' }).Count
        $warningCount = ($AllResults | Where-Object { $_.Status -eq 'Warning' }).Count
        $healthyCount = ($AllResults | Where-Object { $_.Status -eq 'Healthy' }).Count
        
        if ($criticalCount -gt 0) {
            Write-Host "Critical: " -NoNewline
            Write-Host "$criticalCount" -ForegroundColor Red
        }
        if ($warningCount -gt 0) {
            Write-Host "Warning:  " -NoNewline
            Write-Host "$warningCount" -ForegroundColor Yellow
        }
        Write-Host "Healthy:  " -NoNewline
        Write-Host "$healthyCount" -ForegroundColor Green
        Write-Host "===========================================================`n" -ForegroundColor Cyan
    }
}
