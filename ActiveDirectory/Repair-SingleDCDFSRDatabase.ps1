<#
.SYNOPSIS
    Repairs corrupted DFSR database on a single Domain Controller.

.DESCRIPTION
    CRITICAL: This script is designed for SINGLE DC ENVIRONMENTS ONLY.
    
    Performs an authoritative DFSR restore, making this DC the source of truth for SYSVOL.
    Since there are no other DCs to replicate from, the script rebuilds the database and 
    marks this DC as authoritative.
    
    The recovery process includes:
    - Automatic Volume GUID detection from event logs (optional manual specification)
    - Verification of single DC environment (safety check)
    - Complete backup of SYSVOL content
    - DFSR database rebuild
    - Configuration of DC as authoritative for SYSVOL
    - Forced SYSVOL re-initialization
    - Service restart and verification

.PARAMETER VolumeGUID
    The volume GUID from the DFSR error message. If not specified, script will attempt 
    to auto-detect from recent Event ID 2212 or 2213 entries.

.PARAMETER VolumeLetter
    The drive letter of the affected volume. Default: C

.PARAMETER SkipDCCountCheck
    Skip the safety check for multiple DCs. Use with extreme caution.

.EXAMPLE
    .\Repair-SingleDCDFSRDatabase.ps1
    Auto-detect Volume GUID and repair DFSR database with safety checks.

.EXAMPLE
    .\Repair-SingleDCDFSRDatabase.ps1 -VolumeGUID '021FA783-34D8-415C-9C7C-B9473701A259'
    Repair DFSR database using specified GUID.

.EXAMPLE
    .\Repair-SingleDCDFSRDatabase.ps1 -VolumeLetter 'D'
    Repair DFSR database on D: drive with auto-detection.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: Run as Administrator, ActiveDirectory module
    Version: 2.1
    
    WARNING: This script is ONLY for single DC environments!
    For multi-DC environments, use Repair-MultiDCDFSRReplication.ps1 instead.
    
    Compatible with: Windows Server 2016, 2019, 2022, 2025
    
    References:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [string]$VolumeGUID,
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[A-Z]$')]
    [string]$VolumeLetter = 'C',
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDCCountCheck
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# Initialize log file
$script:LogPath = Join-Path $env:TEMP "DFSR-SingleDC-Repair-$(Get-Date -Format 'yyyyMMdd').log"

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

# Auto-detect Volume GUID from event logs
function Get-VolumeGUIDFromEvents {
    param([string]$Volume)
    
    Write-LogMessage "Attempting to auto-detect Volume GUID from event logs..."
    
    try {
        # Look for Event ID 2212 (recovery process) or 2213 (dirty shutdown)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'DFS Replication'
            ID = 2212, 2213
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($events) {
            foreach ($event in $events) {
                # Extract GUID from event message
                if ($event.Message -match 'GUID:\s*([0-9A-Fa-f\-]+)') {
                    $detectedGUID = $matches[1]
                    Write-LogMessage "Found Volume GUID in Event ID $($event.Id): $detectedGUID" -Level Success
                    return $detectedGUID
                }
            }
        }
        
        # Alternative: Try to get GUID from volume info
        Write-LogMessage "No GUID found in event logs, querying volume information..."
        
        $vol = Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveLetter -eq "${Volume}:" }
        if ($vol -and $vol.DeviceID) {
            # Extract GUID from device ID (format: \\?\Volume{GUID}\)
            if ($vol.DeviceID -match '\{([0-9A-Fa-f\-]+)\}') {
                $detectedGUID = $matches[1]
                Write-LogMessage "Detected Volume GUID from WMI: $detectedGUID" -Level Success
                return $detectedGUID
            }
        }
        
        Write-LogMessage "Could not auto-detect Volume GUID" -Level Warning
        return $null
        
    } catch {
        Write-LogMessage "Error during GUID detection: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

# Verify this is a single DC environment
function Test-SingleDCEnvironment {
    Write-LogMessage "Verifying Domain Controller environment..."
    
    try {
        # Check if this server is a DC
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $isDC = $computerSystem.DomainRole -in @(4, 5)
        
        if (-not $isDC) {
            Write-LogMessage "This server is not a Domain Controller" -Level Error
            return $false
        }
        
        Write-LogMessage "Confirmed: This server is a Domain Controller" -Level Success
        
        # Count domain controllers in the environment
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $allDCs = Get-ADDomainController -Filter * | Measure-Object
        $dcCount = $allDCs.Count
        
        Write-LogMessage "Domain Controllers found: $dcCount"
        
        if ($dcCount -gt 1) {
            Write-LogMessage "MULTIPLE DOMAIN CONTROLLERS DETECTED" -Level Warning
            Write-LogMessage "This script is designed for SINGLE DC environments only" -Level Warning
            Write-LogMessage "For multi-DC environments, use Repair-MultiDCDFSRReplication.ps1" -Level Warning
            
            if (-not $SkipDCCountCheck) {
                return $false
            } else {
                Write-LogMessage "DC count check skipped by user - proceeding with caution" -Level Warning
            }
        } else {
            Write-LogMessage "Confirmed: Single DC environment" -Level Success
        }
        
        return $true
    } catch {
        Write-LogMessage "Failed to verify DC environment: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Backup SYSVOL content before making changes
function Backup-SYSVOLContent {
    Write-LogMessage "Backing up SYSVOL content..."
    
    $domain = (Get-ADDomain).DNSRoot
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

# Backup the DFSR database
function Backup-DFSRDatabase {
    param([string]$Volume)
    
    Write-LogMessage "Backing up DFSR database..."
    
    $dfsrPath = "${Volume}:\System Volume Information\DFSR"
    $backupPath = "${Volume}:\DFSR-DB-Backup-$(Get-Date -Format 'yyyyMMddHHmmss')"
    
    if (Test-Path $dfsrPath) {
        try {
            # Take ownership and grant permissions
            takeown /F "$dfsrPath" /R /D Y 2>&1 | Out-Null
            icacls "$dfsrPath" /grant "${env:USERNAME}:(F)" /T /C 2>&1 | Out-Null
            
            Copy-Item -Path $dfsrPath -Destination $backupPath -Recurse -Force -ErrorAction Stop
            Write-LogMessage "DFSR database backup completed" -Level Success
            return $backupPath
        } catch {
            Write-LogMessage "DFSR backup failed: $($_.Exception.Message)" -Level Warning
            return $null
        }
    } else {
        Write-LogMessage "DFSR path not found: $dfsrPath" -Level Warning
        return $null
    }
}

# Remove corrupted DFSR database
function Remove-DFSRDatabase {
    param([string]$Volume)
    
    Write-LogMessage "Removing corrupted DFSR database..."
    
    $dfsrPath = "${Volume}:\System Volume Information\DFSR"
    
    if (-not (Test-Path $dfsrPath)) {
        Write-LogMessage "DFSR path not found - may already be removed"
        return $true
    }
    
    try {
        # Take ownership and grant full permissions
        takeown /F "$dfsrPath" /R /D Y 2>&1 | Out-Null
        icacls "$dfsrPath" /grant "${env:USERNAME}:(OI)(CI)F" /T /C 2>&1 | Out-Null
        
        Write-LogMessage "Attempting deletion..."
        Remove-Item -Path $dfsrPath -Recurse -Force -ErrorAction Stop
        Write-LogMessage "DFSR database removed successfully" -Level Success
        return $true
    } catch {
        Write-LogMessage "Failed to remove DFSR database: $($_.Exception.Message)" -Level Error
        Write-LogMessage "Attempting alternative removal method..." -Level Warning
        
        try {
            # Try using cmd.exe as fallback
            cmd.exe /c "rd /s /q `"$dfsrPath`"" 2>&1 | Out-Null
            
            if (-not (Test-Path $dfsrPath)) {
                Write-LogMessage "DFSR database removed using alternative method" -Level Success
                return $true
            } else {
                Write-LogMessage "Alternative removal method failed" -Level Error
                return $false
            }
        } catch {
            Write-LogMessage "All removal attempts failed" -Level Error
            return $false
        }
    }
}

# Restore SYSTEM account permissions on the volume
function Restore-SystemPermissions {
    param([string]$Volume)
    
    Write-LogMessage "Restoring SYSTEM account permissions..."
    
    $sviPath = "${Volume}:\System Volume Information"
    
    try {
        icacls "$sviPath" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /C 2>&1 | Out-Null
        Write-LogMessage "SYSTEM permissions restored" -Level Success
    } catch {
        Write-LogMessage "Warning: Could not restore all SYSTEM permissions" -Level Warning
    }
}

# Configure DC as authoritative for SYSVOL
function Set-AuthoritativeSYSVOL {
    Write-LogMessage "Configuring authoritative SYSVOL settings..."
    
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        
        # Get the SYSVOL subscription object
        $sysvolDN = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$($env:COMPUTERNAME),OU=Domain Controllers,$domainDN"
        
        # Set msDFSR-Enabled to FALSE to stop replication temporarily
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Enabled" = $false} -ErrorAction Stop
        Write-LogMessage "SYSVOL subscription disabled"
        
        # Set msDFSR-Options to 1 (authoritative)
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Options" = 1} -ErrorAction Stop
        Write-LogMessage "DC configured as authoritative for SYSVOL" -Level Success
        
        return $true
    } catch {
        Write-LogMessage "Failed to configure authoritative SYSVOL: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Start the authoritative restore process
function Start-AuthoritativeRestore {
    Write-LogMessage "Starting authoritative restore..."
    
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $sysvolDN = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$($env:COMPUTERNAME),OU=Domain Controllers,$domainDN"
        
        # Re-enable SYSVOL subscription (will trigger authoritative sync)
        Set-ADObject -Identity $sysvolDN -Replace @{"msDFSR-Enabled" = $true} -ErrorAction Stop
        Write-LogMessage "SYSVOL subscription re-enabled" -Level Success
        
        return $true
    } catch {
        Write-LogMessage "Failed to start authoritative restore: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Wait for SYSVOL share to become available
function Wait-ForSYSVOLShare {
    Write-LogMessage "Monitoring SYSVOL initialization (this may take several minutes)..."
    
    $maxWaitMinutes = 15
    $checkIntervalSeconds = 30
    $elapsedMinutes = 0
    
    while ($elapsedMinutes -lt $maxWaitMinutes) {
        # Check if SYSVOL share exists
        $shares = net share | Select-String "SYSVOL"
        if ($shares) {
            Write-LogMessage "SYSVOL share detected" -Level Success
            return $true
        }
        
        # Check for Event ID 4602 (SYSVOL initialized)
        try {
            $event = Get-WinEvent -FilterHashtable @{
                LogName = 'DFS Replication'
                ID = 4602
                StartTime = (Get-Date).AddMinutes(-10)
            } -MaxEvents 1 -ErrorAction SilentlyContinue
            
            if ($event) {
                Write-LogMessage "Event ID 4602 detected - SYSVOL initialized" -Level Success
                return $true
            }
        } catch {
            # Continue waiting
        }
        
        Write-LogMessage "  Waiting... ($elapsedMinutes/$maxWaitMinutes minutes elapsed)"
        Start-Sleep -Seconds $checkIntervalSeconds
        $elapsedMinutes += ($checkIntervalSeconds / 60)
    }
    
    Write-LogMessage "Timeout waiting for SYSVOL share after $maxWaitMinutes minutes" -Level Warning
    return $false
}

# Main script execution
try {
    # Show YW Banner
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
    Write-Host "        Single DC DFSR Database Recovery" -ForegroundColor Gray
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
    # Auto-detect Volume GUID if not provided
    if (-not $VolumeGUID) {
        Write-Host "=== Auto-Detecting Volume GUID ===" -ForegroundColor DarkYellow
        $VolumeGUID = Get-VolumeGUIDFromEvents -Volume $VolumeLetter
        
        if (-not $VolumeGUID) {
            Write-LogMessage "Could not auto-detect Volume GUID" -Level Error
            Write-LogMessage ""
            Write-LogMessage "Please check Event Viewer for Event ID 2212 or 2213 and run again with:" -Level Error
            Write-LogMessage "  .\Repair-SingleDCDFSRDatabase.ps1 -VolumeGUID '<GUID-from-event>'" -Level Error
            throw "Volume GUID required but could not be auto-detected"
        }
        Write-LogMessage ""
    }
    
    Write-LogMessage "Volume GUID: $VolumeGUID"
    Write-LogMessage "Volume Letter: ${VolumeLetter}:"
    Write-LogMessage "Log File: $script:LogPath"
    Write-LogMessage ""
    
    # Pre-flight checks
    Write-Host "=== Pre-Flight Checks ===" -ForegroundColor DarkYellow
    
    if (-not (Test-SingleDCEnvironment)) {
        throw "Pre-flight checks failed - cannot proceed"
    }
    
    Write-LogMessage ""
    Write-Host "=== CRITICAL WARNING ===" -ForegroundColor DarkYellow
    Write-LogMessage "This is a SINGLE Domain Controller environment" -Level Warning
    Write-LogMessage ""
    Write-LogMessage "This script will:" -Level Warning
    Write-LogMessage "  1. Rebuild the DFSR database" -Level Warning
    Write-LogMessage "  2. Configure this DC as AUTHORITATIVE for SYSVOL" -Level Warning
    Write-LogMessage "  3. Force SYSVOL to re-initialize" -Level Warning
    Write-LogMessage ""
    Write-LogMessage "IMPORTANT:" -Level Warning
    Write-LogMessage "  - All current SYSVOL content will be backed up first" -Level Warning
    Write-LogMessage "  - Group policies will remain intact (stored in SYSVOL)" -Level Warning
    Write-LogMessage "  - This DC will be the source of truth for SYSVOL" -Level Warning
    Write-LogMessage ""
    
    $confirmation = Read-Host "Type 'PROCEED' to continue or anything else to cancel"
    if ($confirmation -ne 'PROCEED') {
        Write-LogMessage "Operation cancelled by user" -Level Warning
        exit 0
    }
    
    Write-LogMessage ""
    Write-Host "=== Starting Recovery Process ===" -ForegroundColor DarkYellow
    Write-LogMessage ""
    
    # Step 1: Backup SYSVOL
    Write-Host "STEP 1: Backing up SYSVOL content" -ForegroundColor DarkYellow
    $sysvolBackup = Backup-SYSVOLContent
    if ($sysvolBackup) {
        Write-LogMessage "SYSVOL backup location: $sysvolBackup" -Level Success
    }
    
    # Step 2: Backup DFSR database
    Write-LogMessage ""
    Write-Host "STEP 2: Backing up DFSR database" -ForegroundColor DarkYellow
    $dfsrBackup = Backup-DFSRDatabase -Volume $VolumeLetter
    if ($dfsrBackup) {
        Write-LogMessage "DFSR backup location: $dfsrBackup" -Level Success
    }
    
    # Step 3: Stop DFSR service
    Write-LogMessage ""
    Write-Host "STEP 3: Stopping DFSR service" -ForegroundColor DarkYellow
    Stop-Service -Name DFSR -Force -ErrorAction Stop
    Write-LogMessage "DFSR service stopped" -Level Success
    Start-Sleep -Seconds 5
    
    # Step 4: Remove corrupted database
    Write-LogMessage ""
    Write-Host "STEP 4: Removing corrupted DFSR database" -ForegroundColor DarkYellow
    $removalSuccess = Remove-DFSRDatabase -Volume $VolumeLetter
    if (-not $removalSuccess) {
        throw "Failed to remove DFSR database"
    }
    
    # Step 5: Restore SYSTEM permissions
    Write-LogMessage ""
    Write-Host "STEP 5: Restoring SYSTEM permissions" -ForegroundColor DarkYellow
    Restore-SystemPermissions -Volume $VolumeLetter
    
    # Step 6: Configure authoritative SYSVOL
    Write-LogMessage ""
    Write-Host "STEP 6: Configuring authoritative SYSVOL" -ForegroundColor DarkYellow
    Set-AuthoritativeSYSVOL | Out-Null
    
    # Step 7: Start DFSR service
    Write-LogMessage ""
    Write-Host "STEP 7: Starting DFSR service" -ForegroundColor DarkYellow
    Start-Service -Name DFSR -ErrorAction Stop
    Write-LogMessage "DFSR service started" -Level Success
    Start-Sleep -Seconds 10
    
    # Step 8: Poll Active Directory
    Write-LogMessage ""
    Write-Host "STEP 8: Polling Active Directory" -ForegroundColor DarkYellow
    try {
        Invoke-CimMethod -Namespace 'Root\MicrosoftDfs' -ClassName DfsrConfig -MethodName PollDsNow -ErrorAction Stop | Out-Null
        Write-LogMessage "AD poll completed" -Level Success
    } catch {
        Write-LogMessage "AD poll via WMI failed, trying dfsrdiag..." -Level Warning
        dfsrdiag pollad 2>&1 | Out-Null
    }
    
    # Step 9: Initiate authoritative restore
    Write-LogMessage ""
    Write-Host "STEP 9: Initiating authoritative restore" -ForegroundColor DarkYellow
    Start-AuthoritativeRestore | Out-Null
    
    Write-LogMessage "Waiting for AD to process changes..."
    Start-Sleep -Seconds 30
    
    # Step 10: Restart DFSR to apply settings
    Write-LogMessage ""
    Write-Host "STEP 10: Restarting DFSR to apply authoritative settings" -ForegroundColor DarkYellow
    Restart-Service -Name DFSR -Force
    Start-Sleep -Seconds 10
    
    # Poll AD again
    try {
        Invoke-CimMethod -Namespace 'Root\MicrosoftDfs' -ClassName DfsrConfig -MethodName PollDsNow -ErrorAction Stop | Out-Null
    } catch {
        dfsrdiag pollad 2>&1 | Out-Null
    }
    
    # Step 11: Wait for SYSVOL initialization
    Write-LogMessage ""
    Write-Host "STEP 11: Waiting for SYSVOL initialization" -ForegroundColor DarkYellow
    $sysvolReady = Wait-ForSYSVOLShare
    
    # Step 12: Verify shares
    Write-LogMessage ""
    Write-Host "STEP 12: Verifying shares" -ForegroundColor DarkYellow
    $shares = net share
    Write-LogMessage "Current shares:"
    $shares | ForEach-Object { Write-LogMessage "  $_" }
    
    # Post-recovery summary and instructions
    Write-LogMessage ""
    Write-Host "=== POST-RECOVERY INSTRUCTIONS ===" -ForegroundColor DarkYellow
    Write-LogMessage ""
    Write-LogMessage "1. Verify SYSVOL and NETLOGON shares are present:"
    Write-Host "   net share" -ForegroundColor Gray
    Write-LogMessage ""
    Write-LogMessage "2. Check Event Viewer for Event ID 4602:"
    Write-Host "   Get-WinEvent -LogName 'DFS Replication' -MaxEvents 20" -ForegroundColor Gray
    Write-LogMessage ""
    Write-LogMessage "3. Test Group Policy application:"
    Write-Host "   gpupdate /force" -ForegroundColor Gray
    Write-Host "   gpresult /r" -ForegroundColor Gray
    Write-LogMessage ""
    Write-LogMessage "4. Verify clients can authenticate and apply policies"
    Write-LogMessage ""
    Write-LogMessage "5. Schedule disk check during next maintenance window:"
    Write-Host "   chkdsk ${VolumeLetter}: /F /R" -ForegroundColor Gray
    Write-LogMessage ""
    Write-LogMessage "6. STRONGLY RECOMMEND: Add a second DC for redundancy" -Level Warning
    Write-LogMessage ""
    Write-Host "=== Backup Locations ===" -ForegroundColor DarkYellow
    if ($sysvolBackup) {
        Write-LogMessage "SYSVOL: $sysvolBackup"
    }
    if ($dfsrBackup) {
        Write-LogMessage "DFSR Database: $dfsrBackup"
    }
    Write-LogMessage ""
    
    Write-Host "=== Recovery Process Completed ===" -ForegroundColor Green
    Write-Host "Yeyland Wutani - Building Better Systems" -ForegroundColor Gray
    Write-LogMessage ""
    
} catch {
    Write-LogMessage ""
    Write-Host "=== RECOVERY FAILED ===" -ForegroundColor Red
    Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
    Write-LogMessage ""
    Write-LogMessage "Recovery steps to try:" -Level Error
    Write-LogMessage "1. Check Event Viewer for specific DFSR errors" -Level Error
    Write-LogMessage "2. Verify disk health with chkdsk" -Level Error
    Write-LogMessage "3. Ensure AD replication is healthy" -Level Error
    Write-LogMessage "4. Contact Microsoft Support if issue persists" -Level Error
    Write-LogMessage ""
    
    # Show backup locations
    if ($sysvolBackup -and (Test-Path $sysvolBackup)) {
        Write-LogMessage "SYSVOL backup available at: $sysvolBackup" -Level Warning
    }
    if ($dfsrBackup -and (Test-Path $dfsrBackup)) {
        Write-LogMessage "DFSR backup available at: $dfsrBackup" -Level Warning
    }
    
    exit 1
}
