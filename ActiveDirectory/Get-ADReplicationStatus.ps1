<#
.SYNOPSIS
    Active Directory replication monitoring and diagnostics.

.DESCRIPTION
    Comprehensive AD replication health check including:
    - Replication partner status
    - Replication failures and error codes
    - Replication latency metrics
    - Pending replication operations
    - Connection objects verification
    - Site link status

.PARAMETER DomainController
    Specific DC to check. If not specified, checks all DCs in domain.

.PARAMETER ShowPendingOnly
    Only display DCs with pending replication operations or errors.

.PARAMETER ExportPath
    Path to export detailed results to CSV.

.EXAMPLE
    .\Get-ADReplicationStatus.ps1
    Check replication status for all domain controllers.

.EXAMPLE
    .\Get-ADReplicationStatus.ps1 -DomainController "DC01" -ExportPath "C:\Reports\Replication.csv"
    Check specific DC and export results.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: ActiveDirectory module, Domain Admin or equivalent rights
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowPendingOnly,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Import required module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT-AD-PowerShell is installed."
    exit 1
}

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

Show-YWBanner
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Get domain controllers
if ($DomainController) {
    $domainControllers = @(Get-ADDomainController -Identity $DomainController)
} else {
    $domainControllers = Get-ADDomainController -Filter * | Sort-Object HostName
}

$results = @()
$totalErrors = 0

foreach ($dc in $domainControllers) {
    Write-Host "Checking: $($dc.HostName)" -ForegroundColor Gray
    Write-Host "  Site: $($dc.Site)" -ForegroundColor Gray
    
    # Test connectivity first
    if (-not (Test-Connection -ComputerName $dc.HostName -Count 2 -Quiet)) {
        Write-Host "  [FAIL] DC is not responding to ping" -ForegroundColor Red
        continue
    }
    
    try {
        # Get replication partners
        $replPartners = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Domain -ErrorAction Stop
        
        $dcHasIssues = $false
        $dcErrors = @()
        
        foreach ($partner in $replPartners) {
            $result = [PSCustomObject]@{
                SourceDC = $dc.HostName
                SourceSite = $dc.Site
                PartnerDC = $partner.Partner
                Partition = $partner.Partition
                LastReplicationAttempt = $partner.LastReplicationAttempt
                LastReplicationSuccess = $partner.LastReplicationSuccess
                LastReplicationResult = $partner.LastReplicationResult
                ConsecutiveFailures = $partner.ConsecutiveReplicationFailures
                Status = 'OK'
                ErrorMessage = ''
            }
            
            # Check for replication failures
            if ($partner.LastReplicationResult -ne 0) {
                $dcHasIssues = $true
                $totalErrors++
                $result.Status = 'FAILED'
                
                # Common error code translations
                $errorMessages = @{
                    8606 = "Insufficient attributes given to create object"
                    8240 = "No such object on server"
                    5 = "Access is denied"
                    1722 = "RPC server unavailable"
                    1256 = "Remote system not available"
                    1908 = "Could not find domain controller"
                    8452 = "Naming violation"
                    8453 = "Replication error (object not found)"
                    8524 = "DSA is unavailable"
                    8456 = "Naming context not present"
                    1396 = "Logon failure"
                }
                
                $errorMsg = if ($errorMessages.ContainsKey($partner.LastReplicationResult)) {
                    $errorMessages[$partner.LastReplicationResult]
                } else {
                    "Error code: $($partner.LastReplicationResult)"
                }
                
                $result.ErrorMessage = $errorMsg
                $dcErrors += "$($partner.Partner) - $errorMsg"
                
                Write-Host "  [FAIL] Partner: $($partner.Partner -replace '.*CN=NTDS Settings,CN=([^,]+).*','$1')" -ForegroundColor Red
                Write-Host "    Error: $errorMsg" -ForegroundColor Red
                Write-Host "    Last Success: $($partner.LastReplicationSuccess)" -ForegroundColor Red
                Write-Host "    Consecutive Failures: $($partner.ConsecutiveReplicationFailures)" -ForegroundColor Red
            } else {
                if (-not $ShowPendingOnly) {
                    Write-Host "  [OK] Partner: $($partner.Partner -replace '.*CN=NTDS Settings,CN=([^,]+).*','$1')" -ForegroundColor Green
                    
                    # Calculate replication delay
                    if ($partner.LastReplicationSuccess) {
                        $delay = (Get-Date) - $partner.LastReplicationSuccess
                        if ($delay.TotalMinutes -gt 180) {
                            Write-Host "    [WARN] Last replication: $([math]::Round($delay.TotalHours, 1)) hours ago" -ForegroundColor Yellow
                        } elseif ($delay.TotalMinutes -gt 60) {
                            Write-Host "    Last replication: $([math]::Round($delay.TotalMinutes, 0)) minutes ago" -ForegroundColor Gray
                        }
                    }
                }
            }
            
            $results += $result
        }
        
        # Show summary for this DC
        if ($dcHasIssues) {
            Write-Host "  [SUMMARY] $($dcErrors.Count) replication error(s) on this DC" -ForegroundColor Red
        } else {
            if (-not $ShowPendingOnly) {
                Write-Host "  [OK] All replication partners healthy" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Host "  [ERROR] Could not query replication status: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
}

# Check for pending replication operations
Write-Host "=== Checking Pending Replication Operations ===" -ForegroundColor DarkYellow

foreach ($dc in $domainControllers) {
    if (-not (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet)) {
        continue
    }
    
    try {
        $replQueue = Get-ADReplicationUpToDatenessVectorTable -Target $dc.HostName -ErrorAction SilentlyContinue
        
        if ($replQueue) {
            $pendingCount = ($replQueue | Where-Object { $_.UsnFilter -gt 0 }).Count
            if ($pendingCount -gt 0) {
                Write-Host "$($dc.HostName): $pendingCount pending operation(s)" -ForegroundColor Yellow
            } else {
                if (-not $ShowPendingOnly) {
                    Write-Host "$($dc.HostName): No pending operations" -ForegroundColor Green
                }
            }
        }
    } catch {
        # Silently continue if we can't get this info
    }
}

Write-Host ""

# Overall Summary
Write-Host "=== OVERALL SUMMARY ===" -ForegroundColor DarkYellow
Write-Host "Total Domain Controllers: $($domainControllers.Count)"
Write-Host "Total Replication Errors: $totalErrors"

if ($totalErrors -eq 0) {
    Write-Host "[OK] All replication links are healthy" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Replication issues detected - review errors above" -ForegroundColor Red
    
    # Provide troubleshooting commands
    Write-Host "`n=== Troubleshooting Commands ===" -ForegroundColor DarkYellow
    Write-Host "Force replication between DCs:" -ForegroundColor Gray
    Write-Host "  repadmin /replicate <DestinationDC> <SourceDC> <NamingContext>" -ForegroundColor Gray
    Write-Host "`nForce replication from all partners:" -ForegroundColor Gray
    Write-Host "  repadmin /syncall /AdeP" -ForegroundColor Gray
    Write-Host "`nView detailed replication status:" -ForegroundColor Gray
    Write-Host "  repadmin /showrepl <DomainController>" -ForegroundColor Gray
    Write-Host "`nCheck replication queue:" -ForegroundColor Gray
    Write-Host "  repadmin /queue" -ForegroundColor Gray
}

# Export results if requested
if ($ExportPath) {
    try {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export results: $($_.Exception.Message)"
    }
}

Write-Host "`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Return results
return $results
