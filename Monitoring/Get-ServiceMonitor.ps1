<#
.SYNOPSIS
    Monitors critical Windows services with auto-restart and email alerting.

.DESCRIPTION
    Comprehensive service monitoring tool for MSP environments. Monitors predefined 
    critical services, custom service lists, and supports automatic restart of 
    failed services. Includes dependency checking, startup type validation, and 
    email notifications for service failures.
    
    Features:
    - Predefined critical service lists
    - Custom service monitoring
    - Automatic service restart
    - Dependency chain validation
    - Startup type verification
    - Historical failure tracking
    - Email alerting
    - Multiple output formats

.PARAMETER ComputerName
    Target computer(s) to monitor. Defaults to local computer.
    Supports multiple computers via comma-separated list or pipeline input.

.PARAMETER ServiceName
    Specific service(s) to monitor. Can be used alone or in addition to profile.
    Accepts service name (not display name).

.PARAMETER Profile
    Predefined service profile to monitor. Options:
    - Essential: Core Windows services (RPC, DNS, Event Log, etc.)
    - DomainController: DC-specific services (NTDS, Netlogon, DFSR, etc.)
    - FileServer: File/Print services (Server, Workstation, DFS, etc.)
    - WebServer: IIS and related services
    - SQLServer: SQL Server services (all instances)
    - All: Monitors all automatic services
    
.PARAMETER AutoRestart
    Automatically restart stopped services that should be running.
    Applies only to services with StartType 'Automatic'.

.PARAMETER MaxRestartAttempts
    Maximum number of restart attempts per service. Default: 3

.PARAMETER CheckDependencies
    Verify service dependencies and start dependent services if needed.

.PARAMETER ExportPath
    Path to export report. Supports CSV, JSON, HTML, or XML formats.

.PARAMETER HistoryPath
    Path to CSV file for tracking service failure history.

.PARAMETER EmailTo
    Email address(es) to send alerts. Requires EmailFrom and SmtpServer.

.PARAMETER EmailFrom
    Sender email address for alerts.

.PARAMETER SmtpServer
    SMTP server for sending email alerts.

.PARAMETER SmtpPort
    SMTP server port. Default: 25

.PARAMETER IncludeHealthy
    Include healthy services in report. Default: Only show issues.

.PARAMETER Quiet
    Suppress console output. Useful for scheduled tasks.

.EXAMPLE
    .\Get-ServiceMonitor.ps1 -Profile Essential
    
    Monitors essential Windows services on local computer.

.EXAMPLE
    .\Get-ServiceMonitor.ps1 -ServiceName "Spooler","W32Time" -AutoRestart
    
    Monitors specific services and auto-restarts if stopped.

.EXAMPLE
    .\Get-ServiceMonitor.ps1 -Profile DomainController -CheckDependencies -AutoRestart
    
    Monitors DC services, checks dependencies, auto-restarts failures.

.EXAMPLE
    .\Get-ServiceMonitor.ps1 -ComputerName "SERVER01" -Profile FileServer -ExportPath "C:\Reports\Services.html"
    
    Monitors file server services on SERVER01, exports HTML report.

.EXAMPLE
    .\Get-ServiceMonitor.ps1 -Profile All -EmailTo "alerts@contoso.com" -EmailFrom "monitor@contoso.com" -SmtpServer "smtp.contoso.com"
    
    Monitors all automatic services, sends email alerts on failures.

.EXAMPLE
    Get-Content servers.txt | .\Get-ServiceMonitor.ps1 -Profile Essential -Quiet -HistoryPath "C:\Monitoring\ServiceHistory.csv"
    
    Silent monitoring of multiple servers with historical tracking.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, Administrative privileges for remote computers and restart
    
    SCHEDULED MONITORING SETUP:
    Create scheduled task for continuous service monitoring:
    
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Get-ServiceMonitor.ps1 -Profile DomainController -AutoRestart -Quiet -HistoryPath C:\Monitoring\ServiceHistory.csv -EmailTo alerts@company.com -EmailFrom monitor@company.com -SmtpServer smtp.company.com"
    
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
    
    Register-ScheduledTask -TaskName "ServiceMonitor" -Action $action -Trigger $trigger -RunLevel Highest
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('CN', 'Server')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [string[]]$ServiceName,
    
    [ValidateSet('Essential', 'DomainController', 'FileServer', 'WebServer', 'SQLServer', 'All')]
    [string]$Profile,
    
    [switch]$AutoRestart,
    
    [ValidateRange(1, 10)]
    [int]$MaxRestartAttempts = 3,
    
    [switch]$CheckDependencies,
    
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
    
    [string[]]$EmailTo,
    
    [string]$EmailFrom,
    
    [string]$SmtpServer,
    
    [int]$SmtpPort = 25,
    
    [switch]$IncludeHealthy,
    
    [switch]$Quiet
)

begin {
    # Script metadata
    $ScriptVersion = "1.0"
    $ScriptName = "Get-ServiceMonitor"
    
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
        Write-Host "  Service Monitor" -ForegroundColor Cyan
        Write-Host ""
        Write-Verbose "[$ScriptName v$ScriptVersion] - Yeyland Wutani LLC - Building Better Systems"
    }
    
    # Validate parameters
    if (-not $ServiceName -and -not $Profile) {
        throw "Must specify either ServiceName or Profile parameter"
    }
    
    if ($EmailTo -and (-not $EmailFrom -or -not $SmtpServer)) {
        throw "EmailTo requires both EmailFrom and SmtpServer parameters"
    }
    
    # Define service profiles
    $ServiceProfiles = @{
        Essential = @(
            'RpcSs',              # Remote Procedure Call
            'Dhcp',               # DHCP Client
            'Dnscache',           # DNS Client  
            'EventLog',           # Windows Event Log
            'LanmanServer',       # Server (file sharing)
            'LanmanWorkstation',  # Workstation
            'W32Time',            # Windows Time
            'WinRM',              # Windows Remote Management
            'PlugPlay',           # Plug and Play
            'BITS'                # Background Intelligent Transfer
        )
        
        DomainController = @(
            'NTDS',               # Active Directory Domain Services
            'Netlogon',           # Netlogon
            'DFSR',               # DFS Replication
            'DNS',                # DNS Server
            'KDC',                # Kerberos Key Distribution Center
            'W32Time',            # Windows Time
            'EventLog',           # Windows Event Log
            'RpcSs',              # Remote Procedure Call
            'IsmServ'             # Intersite Messaging
        )
        
        FileServer = @(
            'LanmanServer',       # Server
            'LanmanWorkstation',  # Workstation
            'DFS',                # DFS Namespace
            'DFSR',               # DFS Replication
            'SRV',                # SMB 1.0/CIFS File Sharing Support
            'SRV2',               # SMB 2.0 Server
            'SamSs',              # Security Accounts Manager
            'CryptSvc'            # Cryptographic Services
        )
        
        WebServer = @(
            'W3SVC',              # World Wide Web Publishing Service
            'WAS',                # Windows Process Activation Service
            'IISADMIN',           # IIS Admin Service
            'W3LOGSVC',           # W3C Logging Service
            'FTPSVC'              # Microsoft FTP Service
        )
        
        SQLServer = @(
            'MSSQLSERVER',        # SQL Server (default instance)
            'SQLSERVERAGENT',     # SQL Server Agent
            'SQLBrowser',         # SQL Server Browser
            'MSSQLFDLauncher',    # SQL Full-text Filter Daemon Launcher
            'SQLTELEMETRY'        # SQL Server CEIP service
        )
    }
    
    # Build service list based on profile and custom services
    $ServicesToMonitor = @()
    
    if ($Profile) {
        if ($Profile -eq 'All') {
            # Will handle differently - get all automatic services
            $ServicesToMonitor = @('__ALL__')
        }
        else {
            $ServicesToMonitor += $ServiceProfiles[$Profile]
        }
    }
    
    if ($ServiceName) {
        $ServicesToMonitor += $ServiceName
    }
    
    # Remove duplicates
    $ServicesToMonitor = $ServicesToMonitor | Select-Object -Unique
    
    if (-not $Quiet) {
        if ($ServicesToMonitor -contains '__ALL__') {
            Write-Verbose "Monitoring: All automatic services"
        }
        else {
            Write-Verbose "Monitoring $($ServicesToMonitor.Count) services: $($ServicesToMonitor -join ', ')"
        }
    }
    
    # Initialize collections
    $AllResults = @()
    $FailedServices = @()
    $RestartedServices = @()
}

process {
    foreach ($Computer in $ComputerName) {
        if (-not $Quiet) {
            Write-Verbose "Processing computer: $Computer"
        }
        
        # Test connectivity
        if ($Computer -ne $env:COMPUTERNAME -and $Computer -ne 'localhost' -and $Computer -ne '.') {
            if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
                Write-Warning "Cannot reach $Computer - skipping"
                continue
            }
        }
        
        try {
            # Get services based on profile
            if ($ServicesToMonitor -contains '__ALL__') {
                # Get all automatic services
                $services = Get-Service -ComputerName $Computer -ErrorAction Stop |
                           Where-Object { $_.StartType -eq 'Automatic' }
            }
            else {
                # Get specific services
                $services = foreach ($svcName in $ServicesToMonitor) {
                    try {
                        Get-Service -Name $svcName -ComputerName $Computer -ErrorAction SilentlyContinue
                    }
                    catch {
                        # Service doesn't exist on this system
                        continue
                    }
                }
            }
            
            if (-not $services) {
                Write-Warning "No qualifying services found on $Computer"
                continue
            }
            
            foreach ($service in $services) {
                # Determine expected state
                $shouldBeRunning = $service.StartType -eq 'Automatic'
                $isHealthy = $true
                $status = 'Healthy'
                $action = 'None'
                
                # Check if service is in expected state
                if ($shouldBeRunning -and $service.Status -ne 'Running') {
                    $isHealthy = $false
                    $status = 'Stopped'
                    $FailedServices += $service
                    
                    # Auto-restart if enabled
                    if ($AutoRestart) {
                        $restartSuccess = $false
                        $restartAttempt = 0
                        
                        while ($restartAttempt -lt $MaxRestartAttempts -and -not $restartSuccess) {
                            $restartAttempt++
                            
                            if (-not $Quiet) {
                                Write-Warning "[$Computer] Service '$($service.DisplayName)' is stopped. Attempting restart ($restartAttempt/$MaxRestartAttempts)..."
                            }
                            
                            if ($PSCmdlet.ShouldProcess("$Computer\$($service.Name)", "Restart service")) {
                                try {
                                    # Check dependencies if requested
                                    if ($CheckDependencies) {
                                        $dependencies = $service.DependentServices | Where-Object { $_.Status -ne 'Running' }
                                        foreach ($dep in $dependencies) {
                                            if (-not $Quiet) {
                                                Write-Verbose "  Starting dependency: $($dep.Name)"
                                            }
                                            Start-Service -Name $dep.Name -ErrorAction SilentlyContinue
                                        }
                                    }
                                    
                                    # Start the service
                                    Start-Service -InputObject $service -ErrorAction Stop
                                    Start-Sleep -Seconds 3
                                    
                                    # Verify service started
                                    $service.Refresh()
                                    if ($service.Status -eq 'Running') {
                                        $restartSuccess = $true
                                        $status = 'Restarted'
                                        $action = "Restarted (attempt $restartAttempt)"
                                        $RestartedServices += $service
                                        
                                        if (-not $Quiet) {
                                            Write-Host "  ✓ Service restarted successfully" -ForegroundColor Green
                                        }
                                    }
                                    else {
                                        if (-not $Quiet) {
                                            Write-Warning "  Service did not start properly. Current status: $($service.Status)"
                                        }
                                    }
                                }
                                catch {
                                    if (-not $Quiet) {
                                        Write-Warning "  Failed to restart service: $_"
                                    }
                                    
                                    if ($restartAttempt -lt $MaxRestartAttempts) {
                                        Start-Sleep -Seconds 5
                                    }
                                }
                            }
                        }
                        
                        if (-not $restartSuccess) {
                            $status = 'Failed to Restart'
                            $action = "Restart failed after $MaxRestartAttempts attempts"
                        }
                    }
                }
                elseif (-not $shouldBeRunning -and $service.Status -eq 'Running') {
                    # Service running but shouldn't be (manual or disabled)
                    $status = 'Running (Unexpected)'
                    $isHealthy = $false
                }
                
                # Get additional service information
                try {
                    $svcDetails = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ComputerName $Computer -ErrorAction Stop
                    $startMode = $svcDetails.StartMode
                    $pathName = $svcDetails.PathName
                    $processId = $svcDetails.ProcessId
                }
                catch {
                    $startMode = $service.StartType
                    $pathName = $null
                    $processId = $null
                }
                
                # Create result object
                $result = [PSCustomObject]@{
                    ComputerName    = $Computer
                    Timestamp       = Get-Date
                    ServiceName     = $service.Name
                    DisplayName     = $service.DisplayName
                    Status          = $service.Status
                    StartType       = $service.StartType
                    StartMode       = $startMode
                    ProcessId       = $processId
                    PathName        = $pathName
                    Health          = $status
                    Action          = $action
                    IsHealthy       = $isHealthy
                    DependentOn     = ($service.ServicesDependedOn | Select-Object -ExpandProperty Name) -join ', '
                    Dependents      = ($service.DependentServices | Select-Object -ExpandProperty Name) -join ', '
                }
                
                $AllResults += $result
                
                # Display result if not quiet
                if (-not $Quiet -and (-not $isHealthy -or $IncludeHealthy)) {
                    $displayColor = if ($isHealthy) { 'Green' } 
                                   elseif ($status -eq 'Restarted') { 'Yellow' }
                                   else { 'Red' }
                    
                    Write-Host "[$Computer] " -NoNewline -ForegroundColor Cyan
                    Write-Host "$($service.DisplayName): " -NoNewline
                    Write-Host "$status" -ForegroundColor $displayColor
                    
                    if ($action -ne 'None') {
                        Write-Host "  Action: $action" -ForegroundColor Gray
                    }
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve services from $Computer : $_"
        }
    }
}

end {
    # Update history file if specified
    if ($HistoryPath) {
        try {
            # Only log failures to history
            $historyRecords = $AllResults | Where-Object { -not $_.IsHealthy } | 
                             Select-Object ComputerName, Timestamp, ServiceName, DisplayName, 
                                          Status, StartType, Health, Action
            
            if ($historyRecords) {
                if (Test-Path $HistoryPath) {
                    $historyRecords | Export-Csv -Path $HistoryPath -NoTypeInformation -Append
                }
                else {
                    $historyRecords | Export-Csv -Path $HistoryPath -NoTypeInformation
                }
                
                if (-not $Quiet) {
                    Write-Host "`nHistory updated: $HistoryPath ($($historyRecords.Count) failure(s) logged)" -ForegroundColor Green
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
        
        # Filter results if not including healthy
        $exportData = if ($IncludeHealthy) { $AllResults } else { $AllResults | Where-Object { -not $_.IsHealthy } }
        
        try {
            switch ($extension) {
                '.csv' {
                    $exportData | Export-Csv -Path $ExportPath -NoTypeInformation
                    if (-not $Quiet) {
                        Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.json' {
                    $exportData | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExportPath -Encoding UTF8
                    if (-not $Quiet) {
                        Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green
                    }
                }
                
                '.html' {
                    # Generate HTML report
                    $failedCount = ($AllResults | Where-Object { -not $_.IsHealthy -and $_.Health -ne 'Restarted' }).Count
                    $restartedCount = ($AllResults | Where-Object { $_.Health -eq 'Restarted' }).Count
                    $healthyCount = ($AllResults | Where-Object { $_.IsHealthy }).Count
                    
                    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Service Monitor Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        h2 { color: #6B7280; margin-top: 30px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }
        .stat-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 32px; font-weight: bold; }
        .stat-label { color: #6B7280; margin-top: 5px; }
        .failed .stat-number { color: #dc3545; }
        .restarted .stat-number { color: #ffc107; }
        .healthy .stat-number { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #6B7280; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-restarted { color: #ffc107; font-weight: bold; }
        .status-healthy { color: #28a745; }
        .footer { margin-top: 30px; text-align: center; color: #6B7280; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Service Monitoring Report</h1>
    <div class="summary">
        <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Systems Monitored:</strong> $(($AllResults | Select-Object -Unique ComputerName).Count)<br>
        <strong>Total Services:</strong> $($AllResults.Count)
        
        <div class="summary-grid">
            <div class="stat-box failed">
                <div class="stat-number">$failedCount</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-box restarted">
                <div class="stat-number">$restartedCount</div>
                <div class="stat-label">Restarted</div>
            </div>
            <div class="stat-box healthy">
                <div class="stat-number">$healthyCount</div>
                <div class="stat-label">Healthy</div>
            </div>
        </div>
    </div>
"@
                    
                    if ($exportData) {
                        $html += @"
    <h2>Service Details</h2>
    <table>
        <tr>
            <th>Computer</th>
            <th>Service</th>
            <th>Display Name</th>
            <th>Status</th>
            <th>Start Type</th>
            <th>Health</th>
            <th>Action</th>
        </tr>
"@
                        
                        foreach ($result in ($exportData | Sort-Object Health, ComputerName, DisplayName)) {
                            $statusClass = if (-not $result.IsHealthy -and $result.Health -ne 'Restarted') { 'status-failed' }
                                          elseif ($result.Health -eq 'Restarted') { 'status-restarted' }
                                          else { 'status-healthy' }
                            
                            $html += @"
        <tr>
            <td>$($result.ComputerName)</td>
            <td><strong>$($result.ServiceName)</strong></td>
            <td>$($result.DisplayName)</td>
            <td>$($result.Status)</td>
            <td>$($result.StartType)</td>
            <td class="$statusClass">$($result.Health)</td>
            <td>$($result.Action)</td>
        </tr>
"@
                        }
                        
                        $html += "</table>"
                    }
                    else {
                        $html += "<p style='text-align: center; padding: 40px; color: #28a745; font-size: 18px;'>✓ All services healthy</p>"
                    }
                    
                    $html += @"
    <div class="footer">
        Yeyland Wutani LLC - Building Better Systems<br>
        Service Monitoring Report
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
                    $exportData | Export-Clixml -Path $ExportPath
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
    
    # Send email alerts if configured and failures exist
    if ($EmailTo -and $FailedServices.Count -gt 0) {
        $stillFailed = $FailedServices | Where-Object { 
            $svc = $_
            -not ($RestartedServices | Where-Object { $_.Name -eq $svc.Name })
        }
        
        if ($stillFailed.Count -gt 0 -or $RestartedServices.Count -gt 0) {
            $emailSubject = "Service Alert - $($FailedServices.Count) service(s) require attention"
            
            $emailBody = "Service Monitoring Alerts`n"
            $emailBody += "===============================================`n`n"
            
            if ($stillFailed.Count -gt 0) {
                $emailBody += "FAILED SERVICES ($($stillFailed.Count)):`n"
                $emailBody += "-----------------------------------------------`n"
                
                $groupedFailures = $AllResults | Where-Object { 
                    -not $_.IsHealthy -and $_.Health -ne 'Restarted' 
                } | Group-Object ComputerName
                
                foreach ($group in $groupedFailures) {
                    $emailBody += "Computer: $($group.Name)`n"
                    foreach ($svc in $group.Group) {
                        $emailBody += "  Service: $($svc.DisplayName) ($($svc.ServiceName))`n"
                        $emailBody += "  Status: $($svc.Status) - $($svc.Health)`n"
                        if ($svc.Action -ne 'None') {
                            $emailBody += "  Action: $($svc.Action)`n"
                        }
                        $emailBody += "`n"
                    }
                }
            }
            
            if ($RestartedServices.Count -gt 0) {
                $emailBody += "RESTARTED SERVICES ($($RestartedServices.Count)):`n"
                $emailBody += "-----------------------------------------------`n"
                
                $groupedRestarts = $AllResults | Where-Object { 
                    $_.Health -eq 'Restarted' 
                } | Group-Object ComputerName
                
                foreach ($group in $groupedRestarts) {
                    $emailBody += "Computer: $($group.Name)`n"
                    foreach ($svc in $group.Group) {
                        $emailBody += "  Service: $($svc.DisplayName) ($($svc.ServiceName))`n"
                        $emailBody += "  Action: $($svc.Action)`n"
                        $emailBody += "  Status: Now Running`n`n"
                    }
                }
            }
            
            $emailBody += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
            $emailBody += "`n--`nYeyland Wutani LLC - Building Better Systems"
            
            if ($PSCmdlet.ShouldProcess("$EmailTo", "Send service alert email")) {
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
    }
    
    # Summary
    if (-not $Quiet) {
        Write-Host "`n===========================================================" -ForegroundColor Cyan
        Write-Host " Service Monitoring Summary" -ForegroundColor Cyan
        Write-Host "===========================================================" -ForegroundColor Cyan
        Write-Host "Total Services Monitored: $($AllResults.Count)"
        
        $failedCount = ($AllResults | Where-Object { -not $_.IsHealthy -and $_.Health -ne 'Restarted' }).Count
        $restartedCount = ($AllResults | Where-Object { $_.Health -eq 'Restarted' }).Count
        $healthyCount = ($AllResults | Where-Object { $_.IsHealthy }).Count
        
        if ($failedCount -gt 0) {
            Write-Host "Failed:    " -NoNewline
            Write-Host "$failedCount" -ForegroundColor Red
        }
        if ($restartedCount -gt 0) {
            Write-Host "Restarted: " -NoNewline
            Write-Host "$restartedCount" -ForegroundColor Yellow
        }
        Write-Host "Healthy:   " -NoNewline
        Write-Host "$healthyCount" -ForegroundColor Green
        Write-Host "===========================================================`n" -ForegroundColor Cyan
    }
}
