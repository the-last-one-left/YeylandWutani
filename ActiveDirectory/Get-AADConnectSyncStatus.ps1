<#
.SYNOPSIS
    Azure AD Connect synchronization status checker.

.DESCRIPTION
    Monitors Azure AD Connect sync health for hybrid identity environments:
    - Sync service status
    - Last sync cycle time and status
    - Sync errors and warnings
    - Connection to Azure AD status
    - Pending sync operations
    - Sync rules configuration
    - Export/Import statistics

.PARAMETER AADConnectServer
    Server name where Azure AD Connect is installed. Defaults to local computer.

.PARAMETER ShowSyncRules
    Display configured synchronization rules.

.PARAMETER ExportPath
    Path to export detailed results to CSV.

.EXAMPLE
    .\Get-AADConnectSyncStatus.ps1
    Check sync status on local server.

.EXAMPLE
    .\Get-AADConnectSyncStatus.ps1 -AADConnectServer "AADCONNECT01" -ShowSyncRules
    Check sync status on remote server with sync rules.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: Run on Azure AD Connect server or with remote access to it
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$AADConnectServer = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowSyncRules,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

Write-Host "`n=== Azure AD Connect Sync Status Monitor ===" -ForegroundColor DarkYellow
Write-Host "Yeyland Wutani - Building Better Systems" -ForegroundColor Gray
Write-Host "Target Server: $AADConnectServer" -ForegroundColor Gray
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

$results = [PSCustomObject]@{
    Server = $AADConnectServer
    CheckTime = Get-Date
    SyncServiceRunning = $false
    SchedulerEnabled = $false
    LastSyncCycle = $null
    LastSyncResult = 'Unknown'
    PendingExports = 0
    PendingImports = 0
    ConnectorErrors = 0
    Issues = @()
}

# Check if ADSync module is available
$moduleCheck = if ($AADConnectServer -eq $env:COMPUTERNAME) {
    Get-Module -Name ADSync -ListAvailable
} else {
    Invoke-Command -ComputerName $AADConnectServer -ScriptBlock {
        Get-Module -Name ADSync -ListAvailable
    } -ErrorAction SilentlyContinue
}

if (-not $moduleCheck) {
    Write-Host "[FAIL] ADSync module not found on $AADConnectServer" -ForegroundColor Red
    Write-Host "This script must be run on a server with Azure AD Connect installed." -ForegroundColor Red
    exit 1
}

# Function to execute commands locally or remotely
function Invoke-AADConnectCommand {
    param(
        [scriptblock]$ScriptBlock
    )
    
    if ($AADConnectServer -eq $env:COMPUTERNAME) {
        & $ScriptBlock
    } else {
        Invoke-Command -ComputerName $AADConnectServer -ScriptBlock $ScriptBlock
    }
}

# Check sync service status
Write-Host "=== Sync Service Status ===" -ForegroundColor DarkYellow

try {
    $syncService = Invoke-AADConnectCommand -ScriptBlock {
        Get-Service -Name "ADSync" -ErrorAction Stop
    }
    
    if ($syncService.Status -eq 'Running') {
        Write-Host "[OK] ADSync Service: Running" -ForegroundColor Green
        $results.SyncServiceRunning = $true
    } else {
        Write-Host "[FAIL] ADSync Service: $($syncService.Status)" -ForegroundColor Red
        $results.Issues += "ADSync service not running"
    }
} catch {
    Write-Host "[FAIL] Could not query ADSync service: $($_.Exception.Message)" -ForegroundColor Red
    $results.Issues += "Cannot query ADSync service"
}

# Check scheduler configuration
Write-Host "`n=== Sync Scheduler Configuration ===" -ForegroundColor DarkYellow

try {
    $scheduler = Invoke-AADConnectCommand -ScriptBlock {
        Import-Module ADSync
        Get-ADSyncScheduler
    }
    
    if ($scheduler.SyncCycleEnabled) {
        Write-Host "[OK] Scheduler: Enabled" -ForegroundColor Green
        $results.SchedulerEnabled = $true
        Write-Host "  Sync Interval: $($scheduler.CustomizedSyncCycleInterval)" -ForegroundColor Gray
        Write-Host "  Next Sync: $($scheduler.NextSyncCyclePolicyType) at $($scheduler.NextSyncCycleStartTimeInUTC)" -ForegroundColor Gray
    } else {
        Write-Host "[WARN] Scheduler: Disabled" -ForegroundColor Yellow
        $results.Issues += "Sync scheduler disabled"
    }
    
    if ($scheduler.MaintenanceEnabled) {
        Write-Host "  Maintenance Mode: Enabled" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[FAIL] Could not query scheduler: $($_.Exception.Message)" -ForegroundColor Red
    $results.Issues += "Cannot query scheduler"
}

# Get last sync cycle information
Write-Host "`n=== Last Synchronization Cycle ===" -ForegroundColor DarkYellow

try {
    $syncHistory = Invoke-AADConnectCommand -ScriptBlock {
        Import-Module ADSync
        Get-ADSyncRunProfileResult | 
            Select-Object -First 1
    }
    
    if ($syncHistory) {
        $results.LastSyncCycle = $syncHistory.EndDate
        $results.LastSyncResult = $syncHistory.Result
        
        Write-Host "Start Time: $($syncHistory.StartDate)"
        Write-Host "End Time:   $($syncHistory.EndDate)"
        
        $syncDuration = $syncHistory.EndDate - $syncHistory.StartDate
        Write-Host "Duration:   $($syncDuration.TotalSeconds) seconds"
        
        if ($syncHistory.Result -eq 'Success') {
            Write-Host "[OK] Result: Success" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] Result: $($syncHistory.Result)" -ForegroundColor Red
            $results.Issues += "Last sync failed: $($syncHistory.Result)"
        }
        
        # Time since last sync
        $timeSinceSync = (Get-Date) - $syncHistory.EndDate
        if ($timeSinceSync.TotalHours -gt 2) {
            Write-Host "[WARN] Last sync was $([math]::Round($timeSinceSync.TotalHours, 1)) hours ago" -ForegroundColor Yellow
        } else {
            Write-Host "Last sync was $([math]::Round($timeSinceSync.TotalMinutes, 0)) minutes ago" -ForegroundColor Gray
        }
    } else {
        Write-Host "[WARN] No sync history found" -ForegroundColor Yellow
        $results.Issues += "No sync history available"
    }
    
} catch {
    Write-Host "[FAIL] Could not query sync history: $($_.Exception.Message)" -ForegroundColor Red
    $results.Issues += "Cannot query sync history"
}

# Check connector status
Write-Host "`n=== Connector Status ===" -ForegroundColor DarkYellow

try {
    $connectors = Invoke-AADConnectCommand -ScriptBlock {
        Import-Module ADSync
        Get-ADSyncConnector
    }
    
    foreach ($connector in $connectors) {
        Write-Host "`nConnector: $($connector.Name)" -ForegroundColor Gray
        Write-Host "  Type: $($connector.Type)"
        Write-Host "  Subtype: $($connector.SubType)"
        
        # Get connector statistics
        $connectorStats = Invoke-AADConnectCommand -ScriptBlock {
            param($connectorId)
            Import-Module ADSync
            Get-ADSyncCSObject -ConnectorIdentifier $connectorId | 
                Measure-Object
        } -ArgumentList $connector.Identifier
        
        if ($connectorStats) {
            Write-Host "  Objects in Connector Space: $($connectorStats.Count)"
        }
        
        # Check for pending exports/imports
        $pendingExports = Invoke-AADConnectCommand -ScriptBlock {
            param($connectorId)
            Import-Module ADSync
            Get-ADSyncCSObject -ConnectorIdentifier $connectorId | 
                Where-Object { $_.PendingExportType -ne 'None' } |
                Measure-Object
        } -ArgumentList $connector.Identifier
        
        if ($pendingExports.Count -gt 0) {
            Write-Host "  [INFO] Pending Exports: $($pendingExports.Count)" -ForegroundColor Yellow
            $results.PendingExports += $pendingExports.Count
        }
        
        # Check for errors
        $connectorErrors = Invoke-AADConnectCommand -ScriptBlock {
            param($connectorId)
            Import-Module ADSync
            Get-ADSyncCSObject -ConnectorIdentifier $connectorId | 
                Where-Object { $_.ErrorObject } |
                Measure-Object
        } -ArgumentList $connector.Identifier
        
        if ($connectorErrors.Count -gt 0) {
            Write-Host "  [FAIL] Errors: $($connectorErrors.Count)" -ForegroundColor Red
            $results.ConnectorErrors += $connectorErrors.Count
            $results.Issues += "Connector $($connector.Name) has $($connectorErrors.Count) error(s)"
        } else {
            Write-Host "  [OK] No Errors" -ForegroundColor Green
        }
    }
    
} catch {
    Write-Host "[FAIL] Could not query connectors: $($_.Exception.Message)" -ForegroundColor Red
    $results.Issues += "Cannot query connectors"
}

# Show sync errors if any exist
if ($results.ConnectorErrors -gt 0) {
    Write-Host "`n=== Synchronization Errors ===" -ForegroundColor DarkYellow
    Write-Host "[FAIL] $($results.ConnectorErrors) total error(s) detected" -ForegroundColor Red
    Write-Host "`nTo view detailed errors, run:" -ForegroundColor Gray
    Write-Host "  Get-ADSyncCSObject | Where-Object { `$_.ErrorObject } | Select-Object DistinguishedName, ErrorObject" -ForegroundColor Gray
}

# Show sync rules if requested
if ($ShowSyncRules) {
    Write-Host "`n=== Synchronization Rules ===" -ForegroundColor DarkYellow
    
    try {
        $syncRules = Invoke-AADConnectCommand -ScriptBlock {
            Import-Module ADSync
            Get-ADSyncRule | 
                Where-Object { $_.Disabled -eq $false } |
                Sort-Object Direction, Precedence
        }
        
        $inboundRules = $syncRules | Where-Object { $_.Direction -eq 'Inbound' }
        $outboundRules = $syncRules | Where-Object { $_.Direction -eq 'Outbound' }
        
        Write-Host "`nInbound Rules (AD -> AAD): $($inboundRules.Count)" -ForegroundColor Gray
        foreach ($rule in $inboundRules | Select-Object -First 10) {
            Write-Host "  [$($rule.Precedence)] $($rule.Name)" -ForegroundColor Gray
        }
        
        Write-Host "`nOutbound Rules (AAD -> AD): $($outboundRules.Count)" -ForegroundColor Gray
        foreach ($rule in $outboundRules | Select-Object -First 10) {
            Write-Host "  [$($rule.Precedence)] $($rule.Name)" -ForegroundColor Gray
        }
        
        if ($syncRules.Count -gt 20) {
            Write-Host "`n  ... and $($syncRules.Count - 20) more rules" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "[FAIL] Could not query sync rules: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Overall Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor DarkYellow

if ($results.Issues.Count -eq 0) {
    Write-Host "[OK] Azure AD Connect sync is healthy" -ForegroundColor Green
} else {
    Write-Host "[ISSUES DETECTED]" -ForegroundColor Red
    foreach ($issue in $results.Issues) {
        Write-Host "  • $issue" -ForegroundColor Red
    }
    
    # Troubleshooting recommendations
    Write-Host "`n=== Troubleshooting Commands ===" -ForegroundColor DarkYellow
    Write-Host "Start sync cycle manually:" -ForegroundColor Gray
    Write-Host "  Start-ADSyncSyncCycle -PolicyType Delta" -ForegroundColor Gray
    Write-Host "`nView sync errors:" -ForegroundColor Gray
    Write-Host "  Get-ADSyncCSObject | Where-Object { `$_.ErrorObject }" -ForegroundColor Gray
    Write-Host "`nRestart sync service:" -ForegroundColor Gray
    Write-Host "  Restart-Service ADSync" -ForegroundColor Gray
    Write-Host "`nView detailed connector stats:" -ForegroundColor Gray
    Write-Host "  Get-ADSyncConnector | Get-ADSyncConnectorStatistics" -ForegroundColor Gray
}

# Export results if requested
if ($ExportPath) {
    try {
        $results | ConvertTo-Json | Out-File -FilePath $ExportPath -Force
        Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export results: $($_.Exception.Message)"
    }
}

Write-Host "`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Return results
return $results
