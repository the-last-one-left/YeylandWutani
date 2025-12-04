<#
.SYNOPSIS
    Performs a comprehensive Active Directory health check.

.DESCRIPTION
    This script performs a multi-point health check of Active Directory infrastructure including:
    - Domain Controller availability and response times
    - FSMO role holder verification
    - AD replication status
    - DNS service health
    - Critical AD services status
    - Sysvol/Netlogon share accessibility
    - Time synchronization across DCs

.PARAMETER DomainController
    Specific DC to check. If not specified, checks all DCs in the domain.

.PARAMETER ExportPath
    Path to export results to CSV. If not specified, displays in console only.

.EXAMPLE
    .\Get-ADHealthCheck.ps1
    Runs health check on all domain controllers in current domain.

.EXAMPLE
    .\Get-ADHealthCheck.ps1 -DomainController "DC01" -ExportPath "C:\Reports\ADHealth.csv"
    Runs health check on specific DC and exports results.

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
    [string]$ExportPath
)

# Import required module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT-AD-PowerShell is installed."
    exit 1
}

# Initialize results array
$results = @()

# Get domain information
$domain = Get-ADDomain
$forest = Get-ADForest

Write-Host "`n=== Active Directory Health Check ===" -ForegroundColor DarkYellow
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Gray
Write-Host "Forest: $($forest.Name)" -ForegroundColor Gray
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Get domain controllers to check
if ($DomainController) {
    $domainControllers = @(Get-ADDomainController -Identity $DomainController)
} else {
    $domainControllers = Get-ADDomainController -Filter *
}

# FSMO Role Holders
Write-Host "FSMO Role Holders:" -ForegroundColor DarkYellow
$fsmoRoles = @{
    'Schema Master' = $forest.SchemaMaster
    'Domain Naming Master' = $forest.DomainNamingMaster
    'PDC Emulator' = $domain.PDCEmulator
    'RID Master' = $domain.RIDMaster
    'Infrastructure Master' = $domain.InfrastructureMaster
}

foreach ($role in $fsmoRoles.GetEnumerator()) {
    Write-Host "  $($role.Key): $($role.Value)" -ForegroundColor Gray
}

Write-Host "`nDomain Controller Health:" -ForegroundColor DarkYellow

# Critical AD services to check
$criticalServices = @(
    'NTDS',           # Active Directory Domain Services
    'DNS',            # DNS Server
    'DFSR',           # DFS Replication
    'KDC',            # Kerberos Key Distribution Center
    'W32Time',        # Windows Time
    'Netlogon'        # Net Logon
)

foreach ($dc in $domainControllers) {
    Write-Host "`n  Checking: $($dc.HostName)" -ForegroundColor Gray
    
    $dcResult = [PSCustomObject]@{
        DomainController = $dc.HostName
        Site = $dc.Site
        IPv4Address = $dc.IPv4Address
        OperatingSystem = $dc.OperatingSystem
        Pingable = $false
        DNSResolution = $false
        LDAPResponse = $false
        ServicesHealthy = $false
        SysvolAccessible = $false
        NetlogonAccessible = $false
        TimeSync = $false
        ReplicationStatus = 'Unknown'
        Issues = @()
    }
    
    # Test network connectivity
    if (Test-Connection -ComputerName $dc.HostName -Count 2 -Quiet) {
        $dcResult.Pingable = $true
        Write-Host "    [OK] Pingable" -ForegroundColor Green
    } else {
        $dcResult.Issues += "Not pingable"
        Write-Host "    [FAIL] Not Pingable" -ForegroundColor Red
    }
    
    # Test DNS resolution
    try {
        $null = Resolve-DnsName -Name $dc.HostName -ErrorAction Stop
        $dcResult.DNSResolution = $true
        Write-Host "    [OK] DNS Resolution" -ForegroundColor Green
    } catch {
        $dcResult.Issues += "DNS resolution failed"
        Write-Host "    [FAIL] DNS Resolution" -ForegroundColor Red
    }
    
    # Test LDAP connectivity
    try {
        $null = Get-ADDomainController -Identity $dc.HostName -ErrorAction Stop
        $dcResult.LDAPResponse = $true
        Write-Host "    [OK] LDAP Response" -ForegroundColor Green
    } catch {
        $dcResult.Issues += "LDAP not responding"
        Write-Host "    [FAIL] LDAP Response" -ForegroundColor Red
    }
    
    # Check critical services
    if ($dcResult.Pingable) {
        $serviceIssues = @()
        foreach ($service in $criticalServices) {
            try {
                $svc = Get-Service -Name $service -ComputerName $dc.HostName -ErrorAction SilentlyContinue
                if ($svc.Status -ne 'Running') {
                    $serviceIssues += "$service not running"
                }
            } catch {
                $serviceIssues += "$service status unknown"
            }
        }
        
        if ($serviceIssues.Count -eq 0) {
            $dcResult.ServicesHealthy = $true
            Write-Host "    [OK] All Critical Services Running" -ForegroundColor Green
        } else {
            $dcResult.Issues += $serviceIssues
            Write-Host "    [FAIL] Service Issues: $($serviceIssues -join ', ')" -ForegroundColor Red
        }
        
        # Check Sysvol share
        try {
            $sysvolPath = "\\$($dc.HostName)\Sysvol"
            if (Test-Path -Path $sysvolPath -ErrorAction Stop) {
                $dcResult.SysvolAccessible = $true
                Write-Host "    [OK] Sysvol Accessible" -ForegroundColor Green
            } else {
                $dcResult.Issues += "Sysvol not accessible"
                Write-Host "    [FAIL] Sysvol Not Accessible" -ForegroundColor Red
            }
        } catch {
            $dcResult.Issues += "Sysvol access error"
            Write-Host "    [FAIL] Sysvol Access Error" -ForegroundColor Red
        }
        
        # Check Netlogon share
        try {
            $netlogonPath = "\\$($dc.HostName)\Netlogon"
            if (Test-Path -Path $netlogonPath -ErrorAction Stop) {
                $dcResult.NetlogonAccessible = $true
                Write-Host "    [OK] Netlogon Accessible" -ForegroundColor Green
            } else {
                $dcResult.Issues += "Netlogon not accessible"
                Write-Host "    [FAIL] Netlogon Not Accessible" -ForegroundColor Red
            }
        } catch {
            $dcResult.Issues += "Netlogon access error"
            Write-Host "    [FAIL] Netlogon Access Error" -ForegroundColor Red
        }
        
        # Check time synchronization
        try {
            $w32tm = w32tm /monitor /computers:$($dc.HostName) /nowarn
            if ($LASTEXITCODE -eq 0) {
                $dcResult.TimeSync = $true
                Write-Host "    [OK] Time Synchronization" -ForegroundColor Green
            } else {
                $dcResult.Issues += "Time sync issues"
                Write-Host "    [FAIL] Time Synchronization" -ForegroundColor Red
            }
        } catch {
            $dcResult.Issues += "Time sync check failed"
            Write-Host "    [FAIL] Time Sync Check Failed" -ForegroundColor Red
        }
    }
    
    # Convert issues array to string for export
    $dcResult.Issues = $dcResult.Issues -join '; '
    $results += $dcResult
}

# Check AD Replication
Write-Host "`nAD Replication Status:" -ForegroundColor DarkYellow
try {
    $replSummary = Get-ADReplicationPartnerMetadata -Target * -Scope Domain | 
        Where-Object { $_.LastReplicationResult -ne 0 }
    
    if ($replSummary.Count -eq 0) {
        Write-Host "  [OK] All replication partners healthy" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Replication issues detected:" -ForegroundColor Red
        foreach ($issue in $replSummary) {
            Write-Host "    $($issue.Server) -> $($issue.Partner): Error $($issue.LastReplicationResult)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  [WARN] Could not check replication status: $($_.Exception.Message)" -ForegroundColor Yellow
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

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor DarkYellow
$healthyDCs = ($results | Where-Object { 
    $_.Pingable -and $_.LDAPResponse -and $_.ServicesHealthy -and $_.SysvolAccessible 
}).Count
$totalDCs = $results.Count

Write-Host "Healthy DCs: $healthyDCs/$totalDCs" -ForegroundColor $(if ($healthyDCs -eq $totalDCs) { 'Green' } else { 'Red' })
Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# Return results object
return $results
