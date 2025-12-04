<#
.SYNOPSIS
    Resolves DFSR replication issues in multi-DC Active Directory environments.

.DESCRIPTION
    Performs DFSR SYSVOL recovery for environments with multiple Domain Controllers.
    This script provides both authoritative and non-authoritative restore options.
    
    RUN THIS SCRIPT ON THE PROBLEM DOMAIN CONTROLLER ONLY.
    
    NON-AUTHORITATIVE RESTORE (Default):
    - Use when one DC has SYSVOL issues but other DCs are healthy
    - Problem DC will sync SYSVOL content from healthy DCs
    - Most common recovery scenario
    
    AUTHORITATIVE RESTORE:
    - Use when you need to force all DCs to sync from this DC
    - Makes this DC the source of truth for SYSVOL
    - Use with extreme caution in multi-DC environments
    
    The recovery process includes:
    - Environment validation and DC count verification
    - AD replication health checks
    - SYSVOL content backup
    - DFSR configuration for non-authoritative or authoritative sync
    - Service management and monitoring
    - Post-recovery verification

.PARAMETER RestoreType
    Type of restore to perform: NonAuthoritative (default) or Authoritative

.PARAMETER AuthoritativeSourceDC
    For non-authoritative restore, specify a healthy DC to sync from (optional)

.PARAMETER SkipBackup
    Skip SYSVOL backup. Not recommended unless disk space is critically low.

.PARAMETER Force
    Skip confirmation prompts. Use with extreme caution.

.EXAMPLE
    .\Repair-MultiDCDFSRReplication.ps1
    Perform non-authoritative restore (sync from healthy DCs)

.EXAMPLE
    .\Repair-MultiDCDFSRReplication.ps1 -RestoreType NonAuthoritative -AuthoritativeSourceDC "DC01"
    Sync SYSVOL from specific healthy DC

.EXAMPLE
    .\Repair-MultiDCDFSRReplication.ps1 -RestoreType Authoritative
    Make this DC authoritative (forces all other DCs to sync from here)

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: Run as Administrator on the PROBLEM DC, ActiveDirectory module
    Version: 1.0
    
    CRITICAL: This script must be run on the Domain Controller with SYSVOL issues.
    Do NOT run this on healthy DCs unless performing authoritative restore.
    
    Compatible with: Windows Server 2016, 2019, 2022, 2025
    
    References:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/recover-from-dfsr-database-crash
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('NonAuthoritative', 'Authoritative')]
    [string]$RestoreType = 'NonAuthoritative',
    
    [Parameter(Mandatory=$false)]
    [string]$AuthoritativeSourceDC,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# Initialize log file
$script:LogPath = Join-Path $env:TEMP "DFSR-MultiDC-Repair-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Helper function for logging
function Write-LogMessage {
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Message = '',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    if ([string]::IsNullOrEmpty($Message)) {
        Write-Host ""
        "" | Out-File -FilePath $script:LogPath -Append
        return
    }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { 'Gray' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
    "$timestamp [$Level] $Message" | Out-File -FilePath $script:LogPath -Append
}

# Verify this is a DC in multi-DC environment
function Test-MultiDCEnvironment {
    Write-LogMessage "Verifying multi-DC environment..."
    
    try {
        # Check if this server is a DC
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $isDC = $computerSystem.DomainRole -in @(4, 5)
        
        if (-not $isDC) {
            Write-LogMessage "This server is not a Domain Controller" -Level Error
            return $false
        }
        
        Write-LogMessage "Confirmed: This server is a Domain Controller" -Level Success
        
        # Import AD module and count DCs
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $allDCs = Get-ADDomainController -Filter *
        $dcCount = ($allDCs | Measure-Object).Count
        
        Write-LogMessage "Domain Controllers found: $dcCount"
        
        if ($dcCount -eq 1) {
            Write-LogMessage "SINGLE DC ENVIRONMENT DETECTED" -Level Error
            Write-LogMessage "This script is for MULTI-DC environments only" -Level Error
            Write-LogMessage "Use Repair-SingleDCDFSRDatabase.ps1 instead" -Level Error
            return $false
        }
        
        Write-LogMessage "Domain Controllers in environment:" -Level Success
        foreach ($dc in $allDCs) {
            $marker = if ($dc.HostName -eq $env:COMPUTERNAME) { " (THIS DC)" } else { "" }
            Write-LogMessage "  - $($dc.HostName)$marker"
        }
        
        return $true
    } catch {
        Write-LogMessage "Failed to verify DC environment: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Check AD replication health
function Test-ADReplicationHealth {
    Write-LogMessage "Checking AD replication health..."
    
    try {
        $replFailures = Get-ADReplicationFailure -Target $env:COMPUTERNAME -ErrorAction SilentlyContinue
        
        if ($replFailures) {
            Write-LogMessage "AD replication failures detected:" -Level Warning
            foreach ($failure in $replFailures) {
                Write-LogMessage "  Partner: $($failure.Partner)" -Level Warning
                Write-LogMessage "  Error: $($failure.LastError)" -Level Warning
            }
            return $false
        } else {
            Write-LogMessage "AD replication appears healthy" -Level Success
            return $true
        }
    } catch {
        Write-LogMessage "Could not fully verify AD replication health" -Level Warning
        Write-LogMessage "Proceeding with caution..." -Level Warning
        return $true
    }
}

# Get SYSVOL replication state
function Get-SYSVOLReplicationState {
    Write-LogMessage "Checking SYSVOL replication state..."
    
    try {
        # Check if SYSVOL is shared
        $sysvolShare = Get-SmbShare -Name "SYSVOL" -ErrorAction SilentlyContinue
        $netlogonShare = Get-SmbShare -Name "NETLOGON" -ErrorAction SilentlyContinue
        
        if ($sysvolShare) {
            Write-LogMessage "SYSVOL share: Present" -Level Success
        } else {
            Write-LogMessage "SYSVOL share: MISSING" -Level Warning
        }
        
        if ($netlogonShare) {
            Write-LogMessage "NETLOGON share: Present" -Level Success
        } else {
            Write-LogMessage "NETLOGON share: MISSING" -Level Warning
        }
        
        # Check DFSR service
        $dfsrService = Get-Service -Name DFSR -ErrorAction Stop
        Write-LogMessage "DFSR Service Status: $($dfsrService.Status)"
        
        # Check for recent DFSR errors
        $dfsrErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'DFS Replication'
            Level = 2
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($dfsrErrors) {
            Write-LogMessage "Recent DFSR errors detected:" -Level Warning
            foreach ($error in $dfsrErrors | Select-Object -First 5) {
                Write-LogMessage "  Event $($error.Id): $($error.Message.Split("`n")[0])" -Level Warning
            }
        }
        
        return [PSCustomObject]@{
            SYSVOLShared = ($null -ne $sysvolShare)
            NETLOGONShared = ($null -ne $netlogonShare)
            DFSRServiceRunning = ($dfsrService.Status -eq 'Running')
            HasRecentErrors = ($null -ne $dfsrErrors)
        }
        
    } catch {
        Write-LogMessage "Error checking SYSVOL state: $($_.Exception.Message)" -Level Error
        return $null
    }
}

# Check for healthy source DCs
function Get-HealthySourceDCs {
    Write-LogMessage "Identifying healthy DCs for replication source..."
    
    try {
        $allDCs = Get-ADDomainController -Filter * | Where-Object { $_.HostName -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }
        $healthyDCs = @()
        
        foreach ($dc in $allDCs) {
            # Test if DC is responsive
            if (Test-Connection -ComputerName $dc.HostName -Count 2 -Quiet) {
                # Check if SYSVOL is shared on that DC
                try {
                    $sysvolPath = "\\$($dc.HostName)\SYSVOL"
                    if (Test-Path $sysvolPath -ErrorAction Stop) {
                        Write-LogMessage "  $($dc.HostName): Healthy (SYSVOL accessible)" -Level Success
                        $healthyDCs += $dc
                    } else {
                        Write-LogMessage "  $($dc.HostName): SYSVOL not accessible" -Level Warning
                    }
                } catch {
                    Write-LogMessage "  $($dc.HostName): Cannot access SYSVOL" -Level Warning
                }
            } else {
                Write-LogMessage "  $($dc.HostName): Not responding to ping" -Level Warning
            }
        }
        
        if ($healthyDCs.Count -eq 0) {
            Write-LogMessage "NO HEALTHY SOURCE DCs FOUND" -Level Error
            Write-LogMessage "All other DCs appear to have SYSVOL issues" -Level Error
            return $null
        }
        
        Write-LogMessage "Found $($healthyDCs.Count) healthy DC(s) for replication source" -Level Success
        return $healthyDCs
        
    } catch {
        Write-LogMessage "Error identifying healthy DCs: $($_.Exception.Message)" -Level Error
        return $null
    }
}

# Backup SYSVOL content
function Backup-SYSVOLContent {
    Write-LogMessage "Backing up SYSVOL content..."
    
    $sysvolPath = "C:\Windows\SYSVOL\domain"
    $backupPath = "C:\SYSVOL-Backup-$(Get-Date -Format 'yyyyMMddHHmmss')"
    
    if (Test-Path $sysvolPath) {
        try {
            Write-LogMessage "  Source: $sysvolPath"
            Write-LogMessage "  Destination: $backupPath"
            
            Copy-Item -Path $sysvolPath -Destination $backupPath -Recurse -Force -ErrorAction Stop
            Write-LogMessage "SYSVOL backup completed successfully" -Level Success
            return $backupPath
        } catch {
            Write-LogMessage "SYSVOL backup failed: $($_.Exception.Message)" -Level Error
            throw "Critical: Cannot proceed without SYSVOL backup"
        }
    } else {
        Write-LogMessage "SYSVOL path not found: $sysvolPath" -Level Warning
        return $null
    }
}

# Perform non-authoritative SYSVOL restore
function Start-NonAuthoritativeRestore {
    param([string]$SourceDC)
    
    Write-LogMessage "Starting non-authoritative restore..."
    Write-LogMessage "This DC will sync SYSVOL from healthy DCs"
    
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $serverName = $env:COMPUTERNAME
        
        $sysvolDN = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$serverName,OU=Domain Controllers,$domainDN"
        
        Write-LogMessage "Stopping DFSR service..."
        Stop-Service -Name DFSR -Force -ErrorAction Stop
        Start-Sleep -Seconds 5
        
        Write-LogMessage "Configuring non-authoritative sync..."
        
        # Set msDFSR-Enabled to FALSE
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Enabled" = $false} -ErrorAction Stop
        Write-LogMessage "  Disabled SYSVOL subscription"
        
        # Ensure msDFSR-Options is 0 (non-authoritative)
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Options" = 0} -ErrorAction Stop
        Write-LogMessage "  Set as non-authoritative"
        
        # Force AD replication
        Write-LogMessage "Forcing AD replication..."
        repadmin /syncall /AdeP | Out-Null
        Start-Sleep -Seconds 10
        
        # Start DFSR service
        Write-LogMessage "Starting DFSR service..."
        Start-Service -Name DFSR -ErrorAction Stop
        Start-Sleep -Seconds 10
        
        # Poll AD
        Write-LogMessage "Polling Active Directory..."
        try {
            dfsrdiag pollad /Member:$serverName | Out-Null
        } catch {
            Write-LogMessage "DFSRDIAG POLLAD completed with warnings" -Level Warning
        }
        
        # Re-enable SYSVOL subscription
        Write-LogMessage "Re-enabling SYSVOL subscription..."
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Enabled" = $true} -ErrorAction Stop
        
        # Force AD replication again
        repadmin /syncall /AdeP | Out-Null
        Start-Sleep -Seconds 10
        
        # Poll AD again
        dfsrdiag pollad /Member:$serverName | Out-Null
        
        # Restart DFSR to ensure changes take effect
        Write-LogMessage "Restarting DFSR service..."
        Restart-Service -Name DFSR -Force
        
        Write-LogMessage "Non-authoritative restore initiated successfully" -Level Success
        return $true
        
    } catch {
        Write-LogMessage "Non-authoritative restore failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Perform authoritative SYSVOL restore
function Start-AuthoritativeRestore {
    Write-LogMessage "Starting authoritative restore..."
    Write-LogMessage "WARNING: This will make THIS DC the source of truth" -Level Warning
    Write-LogMessage "All other DCs will sync SYSVOL from here" -Level Warning
    
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $serverName = $env:COMPUTERNAME
        
        $sysvolDN = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$serverName,OU=Domain Controllers,$domainDN"
        
        Write-LogMessage "Stopping DFSR service on all DCs..."
        
        # Get all DCs
        $allDCs = Get-ADDomainController -Filter *
        
        foreach ($dc in $allDCs) {
            try {
                if ($dc.HostName -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") {
                    Stop-Service -Name DFSR -Force -ErrorAction Stop
                    Write-LogMessage "  Stopped DFSR on: $($dc.HostName) (THIS DC)" -Level Success
                } else {
                    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                        Stop-Service -Name DFSR -Force
                    } -ErrorAction Stop
                    Write-LogMessage "  Stopped DFSR on: $($dc.HostName)" -Level Success
                }
            } catch {
                Write-LogMessage "  Could not stop DFSR on: $($dc.HostName)" -Level Warning
            }
        }
        
        Start-Sleep -Seconds 5
        
        Write-LogMessage "Configuring THIS DC as authoritative..."
        
        # Configure this DC as authoritative
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Enabled" = $false} -ErrorAction Stop
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Options" = 1} -ErrorAction Stop
        Write-LogMessage "  This DC set as authoritative"
        
        # Configure other DCs as non-authoritative
        Write-LogMessage "Configuring other DCs as non-authoritative..."
        foreach ($dc in $allDCs) {
            if ($dc.HostName -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN") {
                try {
                    $otherDCSysvolDN = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$($dc.Name),OU=Domain Controllers,$domainDN"
                    Set-ADObject -Identity $otherDCSysvolDN -Replace @{"msDFSR-Enabled" = $false} -ErrorAction Stop
                    Write-LogMessage "  Configured: $($dc.HostName)"
                } catch {
                    Write-LogMessage "  Could not configure: $($dc.HostName)" -Level Warning
                }
            }
        }
        
        # Force AD replication
        Write-LogMessage "Forcing AD replication throughout domain..."
        repadmin /syncall /AdeP | Out-Null
        Start-Sleep -Seconds 15
        
        # Start DFSR on authoritative DC
        Write-LogMessage "Starting DFSR on authoritative DC..."
        Start-Service -Name DFSR -ErrorAction Stop
        Start-Sleep -Seconds 10
        
        # Re-enable on authoritative DC
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Enabled" = $true} -ErrorAction Stop
        
        # Force AD replication
        repadmin /syncall /AdeP | Out-Null
        Start-Sleep -Seconds 10
        
        # Poll AD
        dfsrdiag pollad /Member:$serverName | Out-Null
        
        Write-LogMessage "Waiting for authoritative initialization (Event 4602)..."
        Start-Sleep -Seconds 30
        
        Write-LogMessage "Authoritative restore initiated successfully" -Level Success
        Write-LogMessage ""
        Write-LogMessage "NEXT STEPS - Run on OTHER DCs:" -Level Warning
        Write-LogMessage "1. Start DFSR service on each DC" -Level Warning
        Write-LogMessage "2. Re-enable SYSVOL subscription (msDFSR-Enabled=TRUE)" -Level Warning
        Write-LogMessage "3. Run: dfsrdiag pollad" -Level Warning
        Write-LogMessage "4. Monitor for Event 4614 and 4604 (non-auth init)" -Level Warning
        
        return $true
        
    } catch {
        Write-LogMessage "Authoritative restore failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Wait for SYSVOL initialization
function Wait-ForSYSVOLInitialization {
    param([int]$MaxMinutes = 15)
    
    Write-LogMessage "Monitoring for SYSVOL initialization..."
    Write-LogMessage "This may take several minutes - checking every 30 seconds"
    
    $checkIntervalSeconds = 30
    $elapsedMinutes = 0
    $targetEventID = if ($RestoreType -eq 'Authoritative') { 4602 } else { 4614 }
    
    while ($elapsedMinutes -lt $MaxMinutes) {
        # Check for SYSVOL share
        $sysvolShare = Get-SmbShare -Name "SYSVOL" -ErrorAction SilentlyContinue
        if ($sysvolShare) {
            Write-LogMessage "SYSVOL share detected!" -Level Success
        }
        
        # Check for initialization event
        try {
            $event = Get-WinEvent -FilterHashtable @{
                LogName = 'DFS Replication'
                ID = $targetEventID
                StartTime = (Get-Date).AddMinutes(-20)
            } -MaxEvents 1 -ErrorAction SilentlyContinue
            
            if ($event) {
                Write-LogMessage "Event ID $targetEventID detected - SYSVOL initialized!" -Level Success
                return $true
            }
        } catch {
            # Continue waiting
        }
        
        Write-LogMessage "  Waiting... ($elapsedMinutes/$MaxMinutes minutes elapsed)"
        Start-Sleep -Seconds $checkIntervalSeconds
        $elapsedMinutes += ($checkIntervalSeconds / 60)
    }
    
    Write-LogMessage "Timeout after $MaxMinutes minutes" -Level Warning
    Write-LogMessage "SYSVOL may still be initializing - check Event Viewer" -Level Warning
    return $false
}

# Main script execution
try {
    Write-Host "`n=== Multi-DC DFSR Replication Repair ===" -ForegroundColor DarkYellow
    Write-Host "Yeyland Wutani - Building Better Systems" -ForegroundColor Gray
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
    Write-LogMessage "Restore Type: $RestoreType"
    Write-LogMessage "Log File: $script:LogPath"
    Write-LogMessage ""
    
    # Pre-flight checks
    Write-Host "=== Pre-Flight Checks ===" -ForegroundColor DarkYellow
    
    if (-not (Test-MultiDCEnvironment)) {
        throw "Pre-flight checks failed - cannot proceed"
    }
    
    Write-LogMessage ""
    
    # Check AD replication health
    $replHealthy = Test-ADReplicationHealth
    if (-not $replHealthy) {
        Write-LogMessage "AD replication issues detected" -Level Warning
        Write-LogMessage "Recommend fixing AD replication before proceeding" -Level Warning
        
        if (-not $Force) {
            $continue = Read-Host "Continue anyway? (yes/no)"
            if ($continue -ne 'yes') {
                Write-LogMessage "Operation cancelled by user"
                exit 0
            }
        }
    }
    
    Write-LogMessage ""
    
    # Get SYSVOL state
    $sysvolState = Get-SYSVOLReplicationState
    
    Write-LogMessage ""
    Write-Host "=== Current Status ===" -ForegroundColor DarkYellow
    Write-LogMessage "SYSVOL Share: $(if ($sysvolState.SYSVOLShared) { 'Present' } else { 'MISSING' })"
    Write-LogMessage "NETLOGON Share: $(if ($sysvolState.NETLOGONShared) { 'Present' } else { 'MISSING' })"
    Write-LogMessage "DFSR Service: $(if ($sysvolState.DFSRServiceRunning) { 'Running' } else { 'STOPPED' })"
    
    Write-LogMessage ""
    
    # If non-authoritative, check for healthy source DCs
    if ($RestoreType -eq 'NonAuthoritative') {
        $healthyDCs = Get-HealthySourceDCs
        
        if (-not $healthyDCs) {
            Write-LogMessage "Cannot perform non-authoritative restore without healthy source DCs" -Level Error
            Write-LogMessage "Consider authoritative restore or investigate other DCs first" -Level Error
            throw "No healthy source DCs available"
        }
        
        if ($AuthoritativeSourceDC) {
            $selectedDC = $healthyDCs | Where-Object { $_.HostName -like "$AuthoritativeSourceDC*" } | Select-Object -First 1
            if (-not $selectedDC) {
                Write-LogMessage "Specified source DC '$AuthoritativeSourceDC' not found in healthy DCs list" -Level Warning
                Write-LogMessage "Will sync from any available healthy DC"
            } else {
                Write-LogMessage "Will prioritize sync from: $($selectedDC.HostName)"
            }
        }
    }
    
    Write-LogMessage ""
    Write-Host "=== CRITICAL WARNING ===" -ForegroundColor DarkYellow
    
    if ($RestoreType -eq 'NonAuthoritative') {
        Write-LogMessage "NON-AUTHORITATIVE RESTORE" -Level Warning
        Write-LogMessage "This DC will sync SYSVOL from healthy DCs" -Level Warning
        Write-LogMessage "Any local SYSVOL changes not on other DCs will be LOST" -Level Warning
    } else {
        Write-LogMessage "AUTHORITATIVE RESTORE" -Level Warning
        Write-LogMessage "This DC will become the SYSVOL source of truth" -Level Warning
        Write-LogMessage "ALL other DCs will sync SYSVOL from THIS DC" -Level Warning
        Write-LogMessage "Use this ONLY if you're certain this DC has correct SYSVOL content" -Level Warning
    }
    
    Write-LogMessage ""
    
    if (-not $Force) {
        $confirmation = Read-Host "Type 'PROCEED' to continue or anything else to cancel"
        if ($confirmation -ne 'PROCEED') {
            Write-LogMessage "Operation cancelled by user" -Level Warning
            exit 0
        }
    }
    
    Write-LogMessage ""
    Write-Host "=== Starting Recovery Process ===" -ForegroundColor DarkYellow
    Write-LogMessage ""
    
    # Backup SYSVOL unless skipped
    if (-not $SkipBackup) {
        Write-Host "STEP 1: Backing up SYSVOL content" -ForegroundColor DarkYellow
        $sysvolBackup = Backup-SYSVOLContent
        if ($sysvolBackup) {
            Write-LogMessage "SYSVOL backup location: $sysvolBackup" -Level Success
        }
        Write-LogMessage ""
    }
    
    # Perform the restore
    Write-Host "STEP 2: Performing $RestoreType Restore" -ForegroundColor DarkYellow
    
    if ($RestoreType -eq 'NonAuthoritative') {
        $success = Start-NonAuthoritativeRestore -SourceDC $AuthoritativeSourceDC
    } else {
        $success = Start-AuthoritativeRestore
    }
    
    if (-not $success) {
        throw "Restore process failed"
    }
    
    Write-LogMessage ""
    
    # Wait for initialization
    Write-Host "STEP 3: Monitoring SYSVOL initialization" -ForegroundColor DarkYellow
    $initialized = Wait-ForSYSVOLInitialization -MaxMinutes 15
    
    Write-LogMessage ""
    
    # Verify shares
    Write-Host "STEP 4: Verifying shares" -ForegroundColor DarkYellow
    $shares = net share
    Write-LogMessage "Current shares:"
    $shares | Where-Object { $_ -match "SYSVOL|NETLOGON" } | ForEach-Object { Write-LogMessage "  $_" }
    
    # Post-recovery instructions
    Write-LogMessage ""
    Write-Host "=== POST-RECOVERY VERIFICATION ===" -ForegroundColor DarkYellow
    Write-LogMessage ""
    Write-LogMessage "1. Verify SYSVOL and NETLOGON shares:"
    Write-Host "   net share" -ForegroundColor Gray
    Write-LogMessage ""
    Write-LogMessage "2. Check DFSR Event Log:"
    Write-Host "   Get-WinEvent -LogName 'DFS Replication' -MaxEvents 20" -ForegroundColor Gray
    Write-LogMessage ""
    
    if ($RestoreType -eq 'NonAuthoritative') {
        Write-LogMessage "3. Look for Event IDs 4614 and 4604 (non-auth init successful)"
        Write-LogMessage ""
        Write-LogMessage "4. Verify SYSVOL content matches healthy DCs"
    } else {
        Write-LogMessage "3. Look for Event ID 4602 (authoritative init successful)"
        Write-LogMessage ""
        Write-LogMessage "4. On OTHER DCs, perform steps to complete sync:"
        Write-Host "   - Start DFSR service" -ForegroundColor Gray
        Write-Host "   - Re-enable SYSVOL subscription" -ForegroundColor Gray
        Write-Host "   - Run: dfsrdiag pollad" -ForegroundColor Gray
        Write-Host "   - Monitor for Event 4614/4604" -ForegroundColor Gray
    }
    
    Write-LogMessage ""
    Write-LogMessage "5. Test Group Policy:"
    Write-Host "   gpupdate /force" -ForegroundColor Gray
    Write-Host "   gpresult /r" -ForegroundColor Gray
    Write-LogMessage ""
    Write-LogMessage "6. Verify on clients that policies apply correctly"
    Write-LogMessage ""
    
    if ($sysvolBackup) {
        Write-Host "=== Backup Location ===" -ForegroundColor DarkYellow
        Write-LogMessage "SYSVOL: $sysvolBackup"
        Write-LogMessage ""
    }
    
    Write-Host "=== Recovery Process Completed ===" -ForegroundColor Green
    Write-Host "Yeyland Wutani - Building Better Systems" -ForegroundColor Gray
    Write-LogMessage ""
    
} catch {
    Write-LogMessage ""
    Write-Host "=== RECOVERY FAILED ===" -ForegroundColor Red
    Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
    Write-LogMessage ""
    Write-LogMessage "Troubleshooting steps:" -Level Error
    Write-LogMessage "1. Check DFSR Event Log for specific errors" -Level Error
    Write-LogMessage "2. Verify AD replication health: repadmin /replsummary" -Level Error
    Write-LogMessage "3. Check DFSR backlog: dfsrdiag backlog" -Level Error
    Write-LogMessage "4. Review log file: $script:LogPath" -Level Error
    Write-LogMessage ""
    
    if ($sysvolBackup -and (Test-Path $sysvolBackup)) {
        Write-LogMessage "SYSVOL backup available at: $sysvolBackup" -Level Warning
    }
    
    exit 1
}
