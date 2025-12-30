<#
.SYNOPSIS
    Identifies stale and inactive computer and user accounts in Active Directory.

.DESCRIPTION
    Audits Active Directory for potentially stale objects:
    - Computer accounts that haven't logged on in specified days
    - User accounts that haven't logged on in specified days
    - Disabled accounts in non-disabled OUs
    - Accounts with expired passwords
    - Accounts that have never logged on
    - Pre-Windows 2000 compatible access group members
    
    Generates detailed reports for cleanup planning.

.PARAMETER InactiveDays
    Number of days of inactivity to consider an account stale. Default: 90

.PARAMETER ExportPath
    Path to export results to CSV files. Creates separate files for users and computers.

.PARAMETER IncludeNeverLoggedOn
    Include accounts that have never logged on.

.PARAMETER ExcludeDisabled
    Exclude already disabled accounts from results.

.PARAMETER ExcludeOUs
    Array of OU Distinguished Names to exclude from scan.

.EXAMPLE
    .\Get-StaleADObjects.ps1
    Find objects inactive for 90+ days.

.EXAMPLE
    .\Get-StaleADObjects.ps1 -InactiveDays 180 -ExportPath "C:\Reports" -ExcludeDisabled
    Find objects inactive for 180+ days, exclude disabled accounts, export to CSV.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: ActiveDirectory module, appropriate AD permissions
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$InactiveDays = 90,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNeverLoggedOn,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExcludeDisabled,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeOUs = @()
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
Write-Host "Inactivity Threshold: $InactiveDays days" -ForegroundColor Gray
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Calculate cutoff date
$cutoffDate = (Get-Date).AddDays(-$InactiveDays)
Write-Host "Cutoff Date: $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

# Get domain info
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName

# Build filter for exclusions
$exclusionFilter = ""
if ($ExcludeOUs.Count -gt 0) {
    Write-Host "`nExcluding OUs:" -ForegroundColor Gray
    foreach ($ou in $ExcludeOUs) {
        Write-Host "  - $ou" -ForegroundColor Gray
    }
}

# Scan for stale computers
Write-Host "`n=== Scanning Computer Accounts ===" -ForegroundColor DarkYellow

$staleComputers = @()
$totalComputers = 0

try {
    # Get all computer accounts with relevant properties
    $allComputers = Get-ADComputer -Filter * -Properties Name, OperatingSystem, LastLogonDate, 
        PasswordLastSet, whenCreated, Enabled, DistinguishedName, Description
    
    $totalComputers = $allComputers.Count
    Write-Host "Total Computer Accounts: $totalComputers" -ForegroundColor Gray
    
    foreach ($computer in $allComputers) {
        # Check if in excluded OU
        $isExcluded = $false
        foreach ($excludeOU in $ExcludeOUs) {
            if ($computer.DistinguishedName -like "*$excludeOU*") {
                $isExcluded = $true
                break
            }
        }
        
        if ($isExcluded) { continue }
        
        # Skip disabled if requested
        if ($ExcludeDisabled -and -not $computer.Enabled) { continue }
        
        $isStale = $false
        $reason = @()
        
        # Check last logon date
        if ($computer.LastLogonDate) {
            if ($computer.LastLogonDate -lt $cutoffDate) {
                $isStale = $true
                $daysSinceLogon = ((Get-Date) - $computer.LastLogonDate).Days
                $reason += "Inactive for $daysSinceLogon days"
            }
        } else {
            if ($IncludeNeverLoggedOn) {
                $isStale = $true
                $reason += "Never logged on"
            }
        }
        
        # Check if disabled
        if (-not $computer.Enabled) {
            $reason += "Disabled"
        }
        
        if ($isStale) {
            $staleComputers += [PSCustomObject]@{
                Name = $computer.Name
                DistinguishedName = $computer.DistinguishedName
                OperatingSystem = $computer.OperatingSystem
                LastLogonDate = $computer.LastLogonDate
                PasswordLastSet = $computer.PasswordLastSet
                Created = $computer.whenCreated
                Enabled = $computer.Enabled
                Description = $computer.Description
                Reason = $reason -join '; '
                DaysInactive = if ($computer.LastLogonDate) { 
                    ((Get-Date) - $computer.LastLogonDate).Days 
                } else { 
                    'Never' 
                }
            }
        }
    }
    
    Write-Host "Stale Computer Accounts: $($staleComputers.Count)" -ForegroundColor $(
        if ($staleComputers.Count -eq 0) { 'Green' } else { 'Yellow' }
    )
    
    if ($staleComputers.Count -gt 0) {
        # Group by operating system
        $osByCount = $staleComputers | Group-Object OperatingSystem | 
            Sort-Object Count -Descending | 
            Select-Object -First 5
        
        Write-Host "`nTop Stale Computer OS Types:" -ForegroundColor Gray
        foreach ($os in $osByCount) {
            $osName = if ($os.Name) { $os.Name } else { 'Unknown' }
            Write-Host "  ${osName}: $($os.Count)" -ForegroundColor Gray
        }
    }
    
} catch {
    Write-Host "[FAIL] Error scanning computers: $($_.Exception.Message)" -ForegroundColor Red
}

# Scan for stale users
Write-Host "`n=== Scanning User Accounts ===" -ForegroundColor DarkYellow

$staleUsers = @()
$totalUsers = 0

try {
    # Get all user accounts with relevant properties
    $allUsers = Get-ADUser -Filter * -Properties Name, UserPrincipalName, LastLogonDate, 
        PasswordLastSet, PasswordExpired, whenCreated, Enabled, DistinguishedName, 
        Description, Department, Title, Manager
    
    $totalUsers = $allUsers.Count
    Write-Host "Total User Accounts: $totalUsers" -ForegroundColor Gray
    
    foreach ($user in $allUsers) {
        # Check if in excluded OU
        $isExcluded = $false
        foreach ($excludeOU in $ExcludeOUs) {
            if ($user.DistinguishedName -like "*$excludeOU*") {
                $isExcluded = $true
                break
            }
        }
        
        if ($isExcluded) { continue }
        
        # Skip disabled if requested
        if ($ExcludeDisabled -and -not $user.Enabled) { continue }
        
        $isStale = $false
        $reason = @()
        
        # Check last logon date
        if ($user.LastLogonDate) {
            if ($user.LastLogonDate -lt $cutoffDate) {
                $isStale = $true
                $daysSinceLogon = ((Get-Date) - $user.LastLogonDate).Days
                $reason += "Inactive for $daysSinceLogon days"
            }
        } else {
            if ($IncludeNeverLoggedOn) {
                $isStale = $true
                $reason += "Never logged on"
            }
        }
        
        # Check if disabled
        if (-not $user.Enabled) {
            $reason += "Disabled"
        }
        
        # Check if password expired
        if ($user.PasswordExpired) {
            $reason += "Password expired"
        }
        
        if ($isStale) {
            $staleUsers += [PSCustomObject]@{
                Name = $user.Name
                SamAccountName = $user.SamAccountName
                UserPrincipalName = $user.UserPrincipalName
                DistinguishedName = $user.DistinguishedName
                LastLogonDate = $user.LastLogonDate
                PasswordLastSet = $user.PasswordLastSet
                PasswordExpired = $user.PasswordExpired
                Created = $user.whenCreated
                Enabled = $user.Enabled
                Department = $user.Department
                Title = $user.Title
                Manager = $user.Manager
                Description = $user.Description
                Reason = $reason -join '; '
                DaysInactive = if ($user.LastLogonDate) { 
                    ((Get-Date) - $user.LastLogonDate).Days 
                } else { 
                    'Never' 
                }
            }
        }
    }
    
    Write-Host "Stale User Accounts: $($staleUsers.Count)" -ForegroundColor $(
        if ($staleUsers.Count -eq 0) { 'Green' } else { 'Yellow' }
    )
    
    if ($staleUsers.Count -gt 0) {
        # Group by department
        $deptByCount = $staleUsers | 
            Where-Object { $_.Department } |
            Group-Object Department | 
            Sort-Object Count -Descending | 
            Select-Object -First 5
        
        if ($deptByCount) {
            Write-Host "`nTop Departments with Stale Users:" -ForegroundColor Gray
            foreach ($dept in $deptByCount) {
                Write-Host "  $($dept.Name): $($dept.Count)" -ForegroundColor Gray
            }
        }
    }
    
} catch {
    Write-Host "[FAIL] Error scanning users: $($_.Exception.Message)" -ForegroundColor Red
}

# Check for security concerns
Write-Host "`n=== Security Checks ===" -ForegroundColor DarkYellow

# Check Pre-Windows 2000 Compatible Access group
try {
    $preWin2kGroup = Get-ADGroup "Pre-Windows 2000 Compatible Access" -Properties Members
    $memberCount = $preWin2kGroup.Members.Count
    
    if ($memberCount -gt 0) {
        Write-Host "[WARN] Pre-Windows 2000 Compatible Access has $memberCount member(s)" -ForegroundColor Yellow
        Write-Host "  This group should typically be empty in modern environments" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Pre-Windows 2000 Compatible Access group is empty" -ForegroundColor Green
    }
} catch {
    Write-Host "[INFO] Could not check Pre-Windows 2000 Compatible Access group" -ForegroundColor Gray
}

# Overall Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor DarkYellow
Write-Host "Total Computers Scanned:    $totalComputers"
Write-Host "Stale Computers Found:      $($staleComputers.Count) ($([math]::Round(($staleComputers.Count / $totalComputers) * 100, 1))%)"
Write-Host "Total Users Scanned:        $totalUsers"
Write-Host "Stale Users Found:          $($staleUsers.Count) ($([math]::Round(($staleUsers.Count / $totalUsers) * 100, 1))%)"

# Export results if requested
if ($ExportPath) {
    try {
        # Ensure export path exists
        if (-not (Test-Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $computerPath = Join-Path $ExportPath "StaleComputers_$timestamp.csv"
        $userPath = Join-Path $ExportPath "StaleUsers_$timestamp.csv"
        
        if ($staleComputers.Count -gt 0) {
            $staleComputers | Export-Csv -Path $computerPath -NoTypeInformation -Force
            Write-Host "`nStale computers exported to: $computerPath" -ForegroundColor Green
        }
        
        if ($staleUsers.Count -gt 0) {
            $staleUsers | Export-Csv -Path $userPath -NoTypeInformation -Force
            Write-Host "Stale users exported to: $userPath" -ForegroundColor Green
        }
        
    } catch {
        Write-Warning "Failed to export results: $($_.Exception.Message)"
    }
}

# Recommendations
if ($staleComputers.Count -gt 0 -or $staleUsers.Count -gt 0) {
    Write-Host "`n=== Recommendations ===" -ForegroundColor DarkYellow
    Write-Host "1. Review stale accounts with business units before taking action" -ForegroundColor Gray
    Write-Host "2. Consider disabling accounts first, then delete after grace period" -ForegroundColor Gray
    Write-Host "3. Move stale accounts to a 'Disabled Objects' OU for easier tracking" -ForegroundColor Gray
    Write-Host "4. Document cleanup actions for compliance purposes" -ForegroundColor Gray
    Write-Host "`nSample cleanup commands:" -ForegroundColor Gray
    Write-Host "  Disable account: Disable-ADAccount -Identity '<SamAccountName>'" -ForegroundColor Gray
    Write-Host "  Remove account:  Remove-ADObject -Identity '<DistinguishedName>' -Confirm:`$false" -ForegroundColor Gray
}

Write-Host "`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Return results as object
return [PSCustomObject]@{
    TotalComputers = $totalComputers
    StaleComputers = $staleComputers
    TotalUsers = $totalUsers
    StaleUsers = $staleUsers
    InactiveDays = $InactiveDays
    CutoffDate = $cutoffDate
}
