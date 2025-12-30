<#
.SYNOPSIS
    Comprehensive Active Directory security and account audit tool.

.DESCRIPTION
    This script performs a thorough audit of Active Directory accounts, generating
    detailed reports on users, computers, groups, and security configurations. It
    consolidates common AD audit tasks into a single tool with HTML report output.
    
    Audit Categories:
    - User Account Analysis (active, disabled, inactive, never logged on, locked)
    - Recently Created Accounts (potential unauthorized creation)
    - Password Security (expired, expiring soon, never expires, stale)
    - Service Account Detection (naming patterns, non-expiring passwords)
    - Computer Account Analysis (active, stale, disabled, by OS, legacy OS)
    - Privileged Group Membership (Domain Admins, Enterprise Admins, etc.)
    - VPN and Special Group Membership
    
    Features:
    - AD Health Score (0-100) based on security metrics
    - Interactive Table of Contents for easy navigation
    - Visual charts (user status, password health, OS distribution, etc.)
    - CSV exports for each audit category
    - Professional HTML report suitable for client presentation
    
    All data is exported to both CSV files and a consolidated HTML report for
    easy review and client presentation.

.PARAMETER OutputPath
    Directory where audit reports will be saved. Defaults to current directory.

.PARAMETER InactiveDays
    Number of days without logon to consider an account inactive. Default is 90.

.PARAMETER PasswordAgeDays
    Number of days to consider a password stale. Default is 90.

.PARAMETER PasswordExpiringDays
    Number of days to check for soon-to-expire passwords. Default is 14.

.PARAMETER RecentlyCreatedDays
    Number of days to check for recently created accounts. Default is 30.

.PARAMETER SearchBase
    Optional OU distinguished name to limit the search scope.

.PARAMETER IncludeDisabled
    Include disabled accounts in inactive reports. Default is $false.

.PARAMETER SkipComputerAudit
    Skip computer account auditing to speed up execution.

.PARAMETER SkipGroupAudit
    Skip privileged group membership auditing.

.PARAMETER ExportCSV
    Export individual CSV files for each audit category. Default is $true.

.PARAMETER Quiet
    Suppress console output except for errors.

.EXAMPLE
    .\Get-ADSecurityAudit.ps1
    Runs a full audit with default settings, outputting to current directory.

.EXAMPLE
    .\Get-ADSecurityAudit.ps1 -OutputPath "C:\AuditReports" -InactiveDays 60
    Runs audit with 60-day inactivity threshold, saves to specified path.

.EXAMPLE
    .\Get-ADSecurityAudit.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -SkipComputerAudit
    Audits only user accounts in a specific OU, skips computer audit.

.NOTES
    Author:         Yeyland Wutani LLC
    Version:        1.0.0
    Required:       Active Directory PowerShell Module (RSAT)
    Compatibility:  PowerShell 5.1+, Windows Server 2012 R2+

.LINK
    https://github.com/YeylandWutani/ActiveDirectory
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$InactiveDays = 90,
    
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$PasswordAgeDays = 90,
    
    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$PasswordExpiringDays = 14,
    
    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$RecentlyCreatedDays = 30,
    
    [Parameter()]
    [string]$SearchBase,
    
    [Parameter()]
    [switch]$IncludeDisabled,
    
    [Parameter()]
    [switch]$SkipComputerAudit,
    
    [Parameter()]
    [switch]$SkipGroupAudit,
    
    [Parameter()]
    [bool]$ExportCSV = $true,
    
    [Parameter()]
    [switch]$Quiet
)

#region Banner and Functions
function Show-YWBanner {
    <#
    .SYNOPSIS
        Displays the Yeyland Wutani ASCII banner with brand colors.
    #>
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | `` | |) |  \ \/\/ /| |_| | | |/ _ \| `` || | "
        "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
    )
    
    $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
    $border  = "=" * 81
    
    Write-Host ""
    Write-Host $border -ForegroundColor Gray
    foreach ($line in $logo) {
        Write-Host $line -ForegroundColor DarkYellow
    }
    Write-Host ""
    Write-Host $tagline.PadLeft(62) -ForegroundColor Gray
    Write-Host $border -ForegroundColor Gray
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Progress')]
        [string]$Type = 'Info'
    )
    
    if ($script:Quiet) { return }
    
    $prefix = switch ($Type) {
        'Info'     { "[*]"; $color = 'Cyan' }
        'Success'  { "[+]"; $color = 'Green' }
        'Warning'  { "[!]"; $color = 'Yellow' }
        'Error'    { "[-]"; $color = 'Red' }
        'Progress' { "[>]"; $color = 'DarkYellow' }
    }
    
    Write-Host "$prefix " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Get-TrueLastLogon {
    <#
    .SYNOPSIS
        Gets the most accurate LastLogonDate available for an AD object.
    .DESCRIPTION
        Uses LastLogonDate (replicated) as the primary source since querying
        all DCs for LastLogon is impractical in most environments.
    #>
    param([Microsoft.ActiveDirectory.Management.ADAccount]$ADObject)
    
    if ($ADObject.LastLogonDate) {
        return $ADObject.LastLogonDate
    }
    elseif ($ADObject.LastLogonTimestamp) {
        return [DateTime]::FromFileTime($ADObject.LastLogonTimestamp)
    }
    return $null
}

function ConvertTo-HtmlSafeString {
    <#
    .SYNOPSIS
        Encodes a string for safe HTML output without requiring System.Web assembly.
    #>
    param([string]$Text)
    
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    
    # Replace HTML special characters with entities
    $Text = $Text.Replace('&', '&amp;')
    $Text = $Text.Replace('<', '&lt;')
    $Text = $Text.Replace('>', '&gt;')
    $Text = $Text.Replace('"', '&quot;')
    $Text = $Text.Replace("'", '&#39;')
    
    return $Text
}

function ConvertTo-HTMLReport {
    <#
    .SYNOPSIS
        Converts audit data to a formatted HTML report section.
    #>
    param(
        [string]$Title,
        [string]$Description,
        [array]$Data,
        [string[]]$Columns,
        [string]$EmptyMessage = "No items found.",
        [string]$SectionId = ""
    )
    
    $idAttr = if ($SectionId) { " id=`"$SectionId`"" } else { "" }
    
    $html = @"
    <div class="section"$idAttr>
        <h2>$Title</h2>
        <p class="description">$Description</p>
"@
    
    if ($Data -and $Data.Count -gt 0) {
        $html += @"
        <p class="count">Found: <strong>$($Data.Count)</strong> item(s)</p>
        <table>
            <thead>
                <tr>
"@
        foreach ($col in $Columns) {
            $html += "                    <th>$col</th>`n"
        }
        $html += @"
                </tr>
            </thead>
            <tbody>
"@
        foreach ($item in $Data) {
            $html += "                <tr>`n"
            foreach ($col in $Columns) {
                $value = $item.$col
                if ($null -eq $value) { $value = "-" }
                elseif ($value -is [DateTime]) { $value = $value.ToString("yyyy-MM-dd HH:mm") }
                elseif ($value -is [bool]) { $value = if ($value) { "Yes" } else { "No" } }
                $html += "                    <td>$(ConvertTo-HtmlSafeString $value)</td>`n"
            }
            $html += "                </tr>`n"
        }
        $html += @"
            </tbody>
        </table>
"@
    }
    else {
        $html += "        <p class='empty'>$EmptyMessage</p>`n"
    }
    
    $html += "    </div>`n"
    return $html
}

function Export-AuditCSV {
    <#
    .SYNOPSIS
        Exports audit data to a CSV file with consistent naming.
    #>
    param(
        [string]$Name,
        [array]$Data,
        [string]$OutputPath
    )
    
    if (-not $script:ExportCSV -or -not $Data -or $Data.Count -eq 0) { return }
    
    $filename = Join-Path $OutputPath "$($script:ReportPrefix)_$Name.csv"
    $Data | Export-Csv -Path $filename -NoTypeInformation -Encoding UTF8
    Write-Status "Exported: $filename" -Type Success
}
#endregion

#region Main Script
# Display banner
if (-not $Quiet) { Show-YWBanner }

Write-Status "Active Directory Security Audit" -Type Info
Write-Status "===============================" -Type Info

# Validate prerequisites
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Status "Active Directory module loaded" -Type Success
}
catch {
    Write-Status "Failed to load Active Directory module. Ensure RSAT is installed." -Type Error
    exit 1
}

# Validate output path
if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Status "Created output directory: $OutputPath" -Type Success
    }
    catch {
        Write-Status "Failed to create output directory: $OutputPath" -Type Error
        exit 1
    }
}

# Get domain information
try {
    $domain = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $domainName = $domain.DNSRoot
    $dcCount = (Get-ADDomainController -Filter *).Count
    Write-Status "Connected to domain: $domainName ($dcCount DC(s))" -Type Success
}
catch {
    Write-Status "Failed to connect to Active Directory: $_" -Type Error
    exit 1
}

# Set search base
$searchParams = @{}
if ($SearchBase) {
    $searchParams['SearchBase'] = $SearchBase
    Write-Status "Search scope limited to: $SearchBase" -Type Info
}

# Initialize report variables
$script:ReportPrefix = "AD_Audit_$($domainName -replace '\.', '_')_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$script:ExportCSV = $ExportCSV
$script:Quiet = $Quiet

# Calculate date thresholds
$inactiveDate = (Get-Date).AddDays(-$InactiveDays)
$passwordStaleDate = (Get-Date).AddDays(-$PasswordAgeDays)
$passwordExpiringDate = (Get-Date).AddDays($PasswordExpiringDays)

Write-Status "Audit Parameters:" -Type Info
Write-Status "  Inactive threshold: $InactiveDays days (since $($inactiveDate.ToString('yyyy-MM-dd')))" -Type Info
Write-Status "  Password stale threshold: $PasswordAgeDays days" -Type Info
Write-Status "  Password expiring check: Next $PasswordExpiringDays days" -Type Info
Write-Status "  Recently created check: Last $RecentlyCreatedDays days" -Type Info

# Initialize results storage
$auditResults = @{}
$auditStartTime = Get-Date

#region User Account Audit
Write-Host ""
Write-Status "=== USER ACCOUNT AUDIT ===" -Type Progress

# Get all user properties needed for audit
$userProperties = @(
    'SamAccountName', 'Name', 'GivenName', 'Surname', 'DisplayName',
    'UserPrincipalName', 'Mail', 'Enabled', 'LockedOut',
    'LastLogonDate', 'LastLogonTimestamp', 'Created', 'Modified',
    'PasswordLastSet', 'PasswordExpired', 'PasswordNeverExpires',
    'LastBadPasswordAttempt', 'BadLogonCount', 'AccountExpirationDate',
    'Description', 'DistinguishedName', 'MemberOf', 'Department', 'Title'
)

Write-Status "Retrieving user accounts..." -Type Progress
$allUsers = @(Get-ADUser -Filter * -Properties $userProperties @searchParams)
Write-Status "Found $($allUsers.Count) total user accounts" -Type Success

# Total user count
$auditResults['TotalUsers'] = $allUsers.Count

# Active users (enabled)
Write-Status "Analyzing active users..." -Type Progress
$activeUsers = @($allUsers | Where-Object { $_.Enabled -eq $true })
$auditResults['ActiveUsers'] = $activeUsers | Select-Object `
    SamAccountName, Name, UserPrincipalName, Mail, LastLogonDate, `
    PasswordLastSet, Created, Department, Title, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Active users: $($activeUsers.Count)" -Type Info

# Disabled users
Write-Status "Analyzing disabled users..." -Type Progress
$disabledUsers = @($allUsers | Where-Object { $_.Enabled -eq $false })
$auditResults['DisabledUsers'] = $disabledUsers | Select-Object `
    SamAccountName, Name, UserPrincipalName, LastLogonDate, Modified, `
    Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Disabled users: $($disabledUsers.Count)" -Type Info

# Inactive users (enabled but not logged on within threshold)
Write-Status "Analyzing inactive users..." -Type Progress
$inactiveFilter = if ($IncludeDisabled) {
    { $_.LastLogonDate -and $_.LastLogonDate -lt $inactiveDate }
} else {
    { $_.Enabled -eq $true -and $_.LastLogonDate -and $_.LastLogonDate -lt $inactiveDate }
}
$inactiveUsers = @($allUsers | Where-Object $inactiveFilter)
$auditResults['InactiveUsers'] = $inactiveUsers | Select-Object `
    SamAccountName, Name, Enabled, LastLogonDate, `
    @{N='DaysSinceLogon';E={[int]((Get-Date) - $_.LastLogonDate).TotalDays}}, `
    PasswordLastSet, Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Inactive users ($InactiveDays+ days): $($inactiveUsers.Count)" -Type $(if ($inactiveUsers.Count -gt 0) { 'Warning' } else { 'Info' })

# Users who have never logged on
Write-Status "Finding users who never logged on..." -Type Progress
$neverLoggedOn = @($allUsers | Where-Object { $_.Enabled -eq $true -and -not $_.LastLogonDate })
$auditResults['NeverLoggedOn'] = $neverLoggedOn | Select-Object `
    SamAccountName, Name, UserPrincipalName, Created, `
    @{N='DaysSinceCreated';E={[int]((Get-Date) - $_.Created).TotalDays}}, `
    Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Never logged on: $($neverLoggedOn.Count)" -Type $(if ($neverLoggedOn.Count -gt 0) { 'Warning' } else { 'Info' })

# Locked out users
Write-Status "Finding locked out users..." -Type Progress
$lockedUsers = @($allUsers | Where-Object { $_.LockedOut -eq $true })
$auditResults['LockedUsers'] = $lockedUsers | Select-Object `
    SamAccountName, Name, LastBadPasswordAttempt, BadLogonCount, `
    Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Locked out users: $($lockedUsers.Count)" -Type $(if ($lockedUsers.Count -gt 0) { 'Warning' } else { 'Info' })
#endregion

#region Password Security Audit
Write-Host ""
Write-Status "=== PASSWORD SECURITY AUDIT ===" -Type Progress

# Users with expired passwords
Write-Status "Finding users with expired passwords..." -Type Progress
$expiredPasswords = @($allUsers | Where-Object { $_.Enabled -eq $true -and $_.PasswordExpired -eq $true })
$auditResults['ExpiredPasswords'] = $expiredPasswords | Select-Object `
    SamAccountName, Name, UserPrincipalName, PasswordLastSet, LastLogonDate, `
    @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Expired passwords: $($expiredPasswords.Count)" -Type $(if ($expiredPasswords.Count -gt 0) { 'Warning' } else { 'Info' })

# Users with passwords that never expire
Write-Status "Finding users with non-expiring passwords..." -Type Progress
$neverExpires = @($allUsers | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true })
$auditResults['PasswordNeverExpires'] = $neverExpires | Select-Object `
    SamAccountName, Name, UserPrincipalName, PasswordLastSet, LastLogonDate, `
    Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Password never expires: $($neverExpires.Count)" -Type $(if ($neverExpires.Count -gt 10) { 'Warning' } else { 'Info' })

# Users with stale passwords (not changed in X days)
Write-Status "Finding users with stale passwords..." -Type Progress
$stalePasswords = @($allUsers | Where-Object { 
    $_.Enabled -eq $true -and 
    $_.PasswordLastSet -and 
    $_.PasswordLastSet -lt $passwordStaleDate -and
    $_.PasswordNeverExpires -ne $true
})
$auditResults['StalePasswords'] = $stalePasswords | Select-Object `
    SamAccountName, Name, PasswordLastSet, `
    @{N='PasswordAge';E={[int]((Get-Date) - $_.PasswordLastSet).TotalDays}}, `
    LastLogonDate, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
Write-Status "Stale passwords ($PasswordAgeDays+ days): $($stalePasswords.Count)" -Type $(if ($stalePasswords.Count -gt 0) { 'Warning' } else { 'Info' })

# Password expiration stats
Write-Status "Compiling password expiration statistics..." -Type Progress
$passwordStats = $allUsers | Where-Object { $_.Enabled -eq $true } | Select-Object `
    SamAccountName, Name, UserPrincipalName, PasswordExpired, PasswordLastSet, `
    PasswordNeverExpires, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
$auditResults['PasswordStats'] = $passwordStats

# Upcoming password expirations
Write-Status "Finding passwords expiring soon..." -Type Progress
try {
    # Get domain password policy for max password age
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    $maxPwdAge = $domainPolicy.MaxPasswordAge.Days
    
    if ($maxPwdAge -gt 0) {
        $upcomingExpirations = @($allUsers | Where-Object { 
            $_.Enabled -eq $true -and 
            $_.PasswordNeverExpires -ne $true -and
            $_.PasswordLastSet -and
            $_.PasswordExpired -ne $true
        } | ForEach-Object {
            $expirationDate = $_.PasswordLastSet.AddDays($maxPwdAge)
            $daysUntilExpire = [int]($expirationDate - (Get-Date)).TotalDays
            if ($daysUntilExpire -ge 0 -and $daysUntilExpire -le $PasswordExpiringDays) {
                $_ | Select-Object `
                    SamAccountName, Name, UserPrincipalName, PasswordLastSet, `
                    @{N='ExpirationDate';E={$expirationDate}}, `
                    @{N='DaysUntilExpire';E={$daysUntilExpire}}, `
                    @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
            }
        })
        $auditResults['UpcomingExpirations'] = $upcomingExpirations | Sort-Object DaysUntilExpire
        Write-Status "Passwords expiring in $PasswordExpiringDays days: $($upcomingExpirations.Count)" -Type $(if ($upcomingExpirations.Count -gt 0) { 'Warning' } else { 'Info' })
    } else {
        $auditResults['UpcomingExpirations'] = @()
        Write-Status "Password expiration not enforced (MaxPasswordAge = 0)" -Type Info
    }
}
catch {
    $auditResults['UpcomingExpirations'] = @()
    Write-Status "Could not determine password policy: $_" -Type Warning
}
#endregion

#region Recently Created & Service Accounts
Write-Host ""
Write-Status "=== ACCOUNT SECURITY AUDIT ===" -Type Progress

# Recently created accounts
Write-Status "Finding recently created accounts..." -Type Progress
$recentlyCreatedDate = (Get-Date).AddDays(-$RecentlyCreatedDays)
$recentlyCreated = @($allUsers | Where-Object { $_.Created -ge $recentlyCreatedDate })
$auditResults['RecentlyCreated'] = $recentlyCreated | Select-Object `
    SamAccountName, Name, UserPrincipalName, Created, Enabled, `
    @{N='DaysSinceCreated';E={[int]((Get-Date) - $_.Created).TotalDays}}, `
    LastLogonDate, Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}} |
    Sort-Object Created -Descending
Write-Status "Recently created ($RecentlyCreatedDays days): $($recentlyCreated.Count)" -Type $(if ($recentlyCreated.Count -gt 5) { 'Warning' } else { 'Info' })

# Service account detection
Write-Status "Detecting service accounts..." -Type Progress
$serviceAccountPatterns = @(
    'svc[-_]', '^svc', '[-_]svc$', 'service',
    '^sql', '[-_]sql', 'sql[-_]',
    '^app[-_]', '[-_]app$',
    '^batch', '^task', '^job',
    '^backup', '^scan', '^print',
    '^admin[-_]', '[-_]admin$',
    'automation', 'scheduled', 'system'
)
$patternRegex = ($serviceAccountPatterns -join '|')

$serviceAccounts = @($allUsers | Where-Object { 
    $_.SamAccountName -match $patternRegex -or 
    $_.Description -match 'service|application|automated|system account|svc' -or
    ($_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true)
})

$auditResults['ServiceAccounts'] = $serviceAccounts | Select-Object `
    SamAccountName, Name, Enabled, PasswordNeverExpires, `
    PasswordLastSet, `
    @{N='PasswordAge';E={if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays } else { 'Never Set' }}}, `
    LastLogonDate, Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}} |
    Sort-Object PasswordNeverExpires, SamAccountName -Descending

Write-Status "Potential service accounts: $($serviceAccounts.Count)" -Type Info

#region Computer Account Audit
if (-not $SkipComputerAudit) {
    Write-Host ""
    Write-Status "=== COMPUTER ACCOUNT AUDIT ===" -Type Progress
    
    $computerProperties = @(
        'Name', 'DNSHostName', 'Enabled', 'OperatingSystem', 'OperatingSystemVersion',
        'OperatingSystemServicePack', 'LastLogonDate', 'LastLogonTimestamp',
        'Created', 'Modified', 'IPv4Address', 'Description', 'DistinguishedName'
    )
    
    Write-Status "Retrieving computer accounts..." -Type Progress
    $allComputers = @(Get-ADComputer -Filter * -Properties $computerProperties @searchParams)
    Write-Status "Found $($allComputers.Count) total computer accounts" -Type Success
    
    $auditResults['TotalComputers'] = $allComputers.Count
    
    # Active computers
    $activeComputers = @($allComputers | Where-Object { $_.Enabled -eq $true })
    $auditResults['ActiveComputers'] = $activeComputers | Select-Object `
        Name, DNSHostName, OperatingSystem, LastLogonDate, IPv4Address, `
        @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
    Write-Status "Active computers: $($activeComputers.Count)" -Type Info
    
    # Disabled computers
    $disabledComputers = @($allComputers | Where-Object { $_.Enabled -eq $false })
    $auditResults['DisabledComputers'] = $disabledComputers | Select-Object `
        Name, OperatingSystem, LastLogonDate, Modified, Description, `
        @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
    Write-Status "Disabled computers: $($disabledComputers.Count)" -Type Info
    
    # Inactive/stale computers
    $staleComputers = @($allComputers | Where-Object { 
        $_.Enabled -eq $true -and $_.LastLogonDate -and $_.LastLogonDate -lt $inactiveDate 
    })
    $auditResults['StaleComputers'] = $staleComputers | Select-Object `
        Name, DNSHostName, OperatingSystem, LastLogonDate, `
        @{N='DaysSinceLogon';E={[int]((Get-Date) - $_.LastLogonDate).TotalDays}}, `
        @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
    Write-Status "Stale computers ($InactiveDays+ days): $($staleComputers.Count)" -Type $(if ($staleComputers.Count -gt 0) { 'Warning' } else { 'Info' })
    
    # Computers by Operating System
    Write-Status "Categorizing computers by OS..." -Type Progress
    $osSummary = $allComputers | Where-Object { $_.Enabled -eq $true } | 
        Group-Object OperatingSystem | 
        Select-Object @{N='OperatingSystem';E={if ($_.Name) { $_.Name } else { 'Unknown' }}}, Count |
        Sort-Object Count -Descending
    $auditResults['ComputersByOS'] = $osSummary
    
    # Windows Server inventory
    $windowsServers = @($allComputers | Where-Object { 
        $_.Enabled -eq $true -and $_.OperatingSystem -like "*Windows Server*" 
    })
    $auditResults['WindowsServers'] = $windowsServers | Select-Object `
        Name, DNSHostName, OperatingSystem, OperatingSystemVersion, `
        LastLogonDate, IPv4Address, Description, @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
    Write-Status "Windows Servers: $($windowsServers.Count)" -Type Info
    
    # Legacy OS detection (XP, Server 2003, Server 2008)
    $legacyOS = @($allComputers | Where-Object { 
        $_.Enabled -eq $true -and (
            $_.OperatingSystem -like "*XP*" -or
            $_.OperatingSystem -like "*2003*" -or
            $_.OperatingSystem -like "*2008*" -or
            $_.OperatingSystem -like "*Windows 7*" -or
            $_.OperatingSystem -like "*Vista*"
        )
    })
    $auditResults['LegacyOS'] = $legacyOS | Select-Object `
        Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, `
        @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}
    Write-Status "Legacy OS systems: $($legacyOS.Count)" -Type $(if ($legacyOS.Count -gt 0) { 'Warning' } else { 'Info' })
}
#endregion

#region Privileged Group Audit
if (-not $SkipGroupAudit) {
    Write-Host ""
    Write-Status "=== PRIVILEGED GROUP AUDIT ===" -Type Progress
    
    # Define privileged groups to audit
    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Server Operators',
        'Backup Operators',
        'Print Operators',
        'DnsAdmins',
        'Group Policy Creator Owners'
    )
    
    $groupMembers = @()
    
    foreach ($groupName in $privilegedGroups) {
        Write-Status "Auditing group: $groupName" -Type Progress
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue |
                Where-Object { $_.objectClass -eq 'user' }
            
            foreach ($member in $members) {
                $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties `
                    LastLogonDate, PasswordLastSet, Enabled, Description -ErrorAction SilentlyContinue
                
                $groupMembers += [PSCustomObject]@{
                    GroupName = $groupName
                    SamAccountName = $member.SamAccountName
                    Name = $member.Name
                    Enabled = $userDetails.Enabled
                    LastLogonDate = $userDetails.LastLogonDate
                    PasswordLastSet = $userDetails.PasswordLastSet
                    Description = $userDetails.Description
                }
            }
            Write-Status "  $groupName`: $($members.Count) member(s)" -Type Info
        }
        catch {
            Write-Status "  Could not audit $groupName`: $_" -Type Warning
        }
    }
    
    $auditResults['PrivilegedGroupMembers'] = $groupMembers
    Write-Status "Total privileged group memberships: $($groupMembers.Count)" -Type Info
    
    # VPN Users group (WatchGuard and common group names)
    Write-Status "Checking for VPN user groups..." -Type Progress
    try {
        $vpnGroupNames = @('SSLVPN-Users', 'IKEv2-users', 'WG_VPN_ACCESS', 'WG-SSLVPN-Users', 'VPN-Users', 'VPN Users', 'Remote Access Users')
        $vpnUsers = @()
        
        foreach ($vpnGroup in $vpnGroupNames) {
            try {
                $members = Get-ADGroupMember -Identity $vpnGroup -ErrorAction SilentlyContinue
                if ($members) {
                    foreach ($member in $members) {
                        $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties `
                            LastLogonDate, Enabled, UserPrincipalName -ErrorAction SilentlyContinue
                        $vpnUsers += [PSCustomObject]@{
                            GroupName = $vpnGroup
                            SamAccountName = $member.SamAccountName
                            Name = $member.Name
                            UserPrincipalName = $userDetails.UserPrincipalName
                            Enabled = $userDetails.Enabled
                            LastLogonDate = $userDetails.LastLogonDate
                        }
                    }
                    Write-Status "Found $($members.Count) members in $vpnGroup" -Type Info
                }
            }
            catch { }
        }
        
        $auditResults['VPNUsers'] = $vpnUsers
    }
    catch {
        Write-Status "No standard VPN groups found" -Type Info
    }
}
#endregion

#region User Creation and Last Logon Report
Write-Host ""
Write-Status "=== ACCOUNT TIMELINE ANALYSIS ===" -Type Progress

# User creation and last logon comprehensive list
$userTimeline = $allUsers | Select-Object `
    SamAccountName, DisplayName, UserPrincipalName, `
    Created, LastLogonDate, PasswordLastSet, `
    @{N='DaysSinceCreated';E={if ($_.Created) { [int]((Get-Date) - $_.Created).TotalDays } else { $null }}}, `
    @{N='DaysSinceLogon';E={if ($_.LastLogonDate) { [int]((Get-Date) - $_.LastLogonDate).TotalDays } else { $null }}}, `
    Enabled, Description

$auditResults['UserTimeline'] = $userTimeline
Write-Status "Compiled timeline for $($userTimeline.Count) users" -Type Success
#endregion

#region Export CSV Files
if ($ExportCSV) {
    Write-Host ""
    Write-Status "=== EXPORTING CSV FILES ===" -Type Progress
    
    Export-AuditCSV -Name "ActiveUsers" -Data $auditResults['ActiveUsers'] -OutputPath $OutputPath
    Export-AuditCSV -Name "DisabledUsers" -Data $auditResults['DisabledUsers'] -OutputPath $OutputPath
    Export-AuditCSV -Name "InactiveUsers" -Data $auditResults['InactiveUsers'] -OutputPath $OutputPath
    Export-AuditCSV -Name "NeverLoggedOn" -Data $auditResults['NeverLoggedOn'] -OutputPath $OutputPath
    Export-AuditCSV -Name "LockedUsers" -Data $auditResults['LockedUsers'] -OutputPath $OutputPath
    Export-AuditCSV -Name "ExpiredPasswords" -Data $auditResults['ExpiredPasswords'] -OutputPath $OutputPath
    Export-AuditCSV -Name "PasswordNeverExpires" -Data $auditResults['PasswordNeverExpires'] -OutputPath $OutputPath
    Export-AuditCSV -Name "StalePasswords" -Data $auditResults['StalePasswords'] -OutputPath $OutputPath
    Export-AuditCSV -Name "UpcomingExpirations" -Data $auditResults['UpcomingExpirations'] -OutputPath $OutputPath
    Export-AuditCSV -Name "RecentlyCreated" -Data $auditResults['RecentlyCreated'] -OutputPath $OutputPath
    Export-AuditCSV -Name "ServiceAccounts" -Data $auditResults['ServiceAccounts'] -OutputPath $OutputPath
    Export-AuditCSV -Name "UserTimeline" -Data $auditResults['UserTimeline'] -OutputPath $OutputPath
    
    if (-not $SkipComputerAudit) {
        Export-AuditCSV -Name "ActiveComputers" -Data $auditResults['ActiveComputers'] -OutputPath $OutputPath
        Export-AuditCSV -Name "DisabledComputers" -Data $auditResults['DisabledComputers'] -OutputPath $OutputPath
        Export-AuditCSV -Name "StaleComputers" -Data $auditResults['StaleComputers'] -OutputPath $OutputPath
        Export-AuditCSV -Name "WindowsServers" -Data $auditResults['WindowsServers'] -OutputPath $OutputPath
        Export-AuditCSV -Name "LegacyOS" -Data $auditResults['LegacyOS'] -OutputPath $OutputPath
    }
    
    if (-not $SkipGroupAudit) {
        Export-AuditCSV -Name "PrivilegedGroupMembers" -Data $auditResults['PrivilegedGroupMembers'] -OutputPath $OutputPath
        Export-AuditCSV -Name "VPNUsers" -Data $auditResults['VPNUsers'] -OutputPath $OutputPath
    }
}
#endregion

#region Generate HTML Report
Write-Host ""
Write-Status "=== GENERATING HTML REPORT ===" -Type Progress

$auditEndTime = Get-Date
$auditDuration = $auditEndTime - $auditStartTime

# Build HTML report
$htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Audit - $domainName</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1F2937;
            color: #F9FAFB;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #374151 0%, #1F2937 100%);
            border-left: 4px solid #FF6600;
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        
        .header h1 {
            color: #FF6600;
            font-size: 28px;
            margin-bottom: 5px;
        }
        
        .header .tagline {
            color: #6B7280;
            font-size: 14px;
            letter-spacing: 2px;
        }
        
        .header .meta {
            margin-top: 15px;
            color: #6B7280;
            font-size: 13px;
        }
        
        /* Stats Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: #374151;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .summary-card .number {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
            color: #FF6600;
        }
        
        .summary-card .label {
            color: #6B7280;
            font-size: 13px;
            text-transform: uppercase;
        }
        
        .summary-card.success .number { color: #10B981; }
        .summary-card.warning .number { color: #F59E0B; }
        .summary-card.danger .number { color: #EF4444; }
        
        /* Charts Grid */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-card {
            background: #374151;
            padding: 20px;
            border-radius: 8px;
        }
        
        .chart-card h3 {
            color: #FF6600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #1F2937;
        }
        
        .chart-container {
            position: relative;
            height: 250px;
        }
        
        .chart-container.large {
            height: 300px;
        }
        
        /* Sections */
        .section {
            background: #374151;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }
        
        .section h2 {
            padding: 20px;
            border-bottom: 1px solid #1F2937;
            color: #FF6600;
            font-size: 16px;
        }
        
        .section .description {
            padding: 15px 20px 0;
            color: #6B7280;
            font-size: 13px;
        }
        
        .section .count {
            padding: 10px 20px;
            color: #F9FAFB;
            font-size: 14px;
        }
        
        .section .empty {
            padding: 30px 20px;
            color: #10B981;
            font-style: italic;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #1F2937;
            padding: 12px 15px;
            text-align: left;
            color: #6B7280;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #1F2937;
            font-size: 13px;
        }
        
        tr:hover { background: rgba(255,255,255,0.02); }
        
        /* Status Badges */
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success { background: rgba(16, 185, 129, 0.2); color: #10B981; }
        .badge-error { background: rgba(239, 68, 68, 0.2); color: #EF4444; }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: #F59E0B; }
        .badge-info { background: rgba(255, 102, 0, 0.2); color: #FF6600; }
        
        /* Health Score */
        .health-section {
            background: #374151;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .health-score {
            display: inline-block;
            width: 150px;
            height: 150px;
            border-radius: 50%;
            position: relative;
            margin-bottom: 15px;
        }
        
        .health-score .score-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 42px;
            font-weight: bold;
        }
        
        .health-score.excellent { background: conic-gradient(#10B981 var(--score), #1F2937 0); }
        .health-score.good { background: conic-gradient(#3B82F6 var(--score), #1F2937 0); }
        .health-score.warning { background: conic-gradient(#F59E0B var(--score), #1F2937 0); }
        .health-score.critical { background: conic-gradient(#EF4444 var(--score), #1F2937 0); }
        
        .health-score .inner {
            position: absolute;
            top: 15px; left: 15px; right: 15px; bottom: 15px;
            background: #374151;
            border-radius: 50%;
        }
        
        .health-label {
            font-size: 18px;
            color: #6B7280;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .health-details {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        .health-detail {
            text-align: center;
        }
        
        .health-detail .value {
            font-size: 24px;
            font-weight: bold;
        }
        
        .health-detail .label {
            font-size: 11px;
            color: #6B7280;
            text-transform: uppercase;
        }
        
        .health-detail.good .value { color: #10B981; }
        .health-detail.warning .value { color: #F59E0B; }
        .health-detail.danger .value { color: #EF4444; }
        
        /* Table of Contents */
        .toc {
            background: #374151;
            border-radius: 8px;
            padding: 20px 30px;
            margin-bottom: 30px;
        }
        
        .toc h3 {
            color: #FF6600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #1F2937;
        }
        
        .toc-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 10px 30px;
        }
        
        .toc-section {
            margin-bottom: 10px;
        }
        
        .toc-section-title {
            color: #9CA3AF;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }
        
        .toc a {
            color: #F9FAFB;
            text-decoration: none;
            font-size: 13px;
            display: block;
            padding: 4px 0;
            transition: color 0.2s;
        }
        
        .toc a:hover {
            color: #FF6600;
        }
        
        .toc .count {
            color: #6B7280;
            font-size: 12px;
        }
        
        .toc .warning { color: #F59E0B; }
        .toc .danger { color: #EF4444; }
        .toc .success { color: #10B981; }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: #6B7280;
            font-size: 12px;
        }
        
        .footer a { color: #FF6600; text-decoration: none; }
        .footer .brand { color: #FF6600; font-weight: 600; }
        
        @media print {
            body { background: #1F2937; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .section { break-inside: avoid; }
            .charts-grid { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Active Directory Security Audit</h1>
            <div class="tagline">YEYLAND WUTANI - BUILDING BETTER SYSTEMS</div>
            <div class="meta">
                <strong>Domain:</strong> $domainName<br>
                <strong>Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")<br>
                <strong>Duration:</strong> $([math]::Round($auditDuration.TotalMinutes, 1)) minutes
            </div>
        </div>
"@

# Calculate health score (0-100)
$healthDeductions = 0
$totalUsers = [Math]::Max($auditResults['TotalUsers'], 1)
$activeUserCount = $auditResults['ActiveUsers'].Count

# Deduct for inactive users (up to 25 points)
$inactivePercent = ($auditResults['InactiveUsers'].Count / [Math]::Max($activeUserCount, 1)) * 100
$healthDeductions += [Math]::Min(25, [Math]::Round($inactivePercent / 2))

# Deduct for expired passwords (up to 20 points)
$expiredPercent = ($auditResults['ExpiredPasswords'].Count / [Math]::Max($activeUserCount, 1)) * 100
$healthDeductions += [Math]::Min(20, [Math]::Round($expiredPercent))

# Deduct for stale passwords (up to 15 points)
$stalePercent = ($auditResults['StalePasswords'].Count / [Math]::Max($activeUserCount, 1)) * 100
$healthDeductions += [Math]::Min(15, [Math]::Round($stalePercent / 3))

# Deduct for never-expire passwords (up to 15 points)
$neverExpirePercent = ($auditResults['PasswordNeverExpires'].Count / [Math]::Max($activeUserCount, 1)) * 100
$healthDeductions += [Math]::Min(15, [Math]::Round($neverExpirePercent / 2))

# Deduct for locked accounts (up to 10 points)
$healthDeductions += [Math]::Min(10, $auditResults['LockedUsers'].Count * 2)

# Deduct for legacy OS (up to 15 points)
if (-not $SkipComputerAudit -and $auditResults['LegacyOS']) {
    $healthDeductions += [Math]::Min(15, $auditResults['LegacyOS'].Count * 3)
}

$healthScore = [Math]::Max(0, 100 - $healthDeductions)
$healthClass = if ($healthScore -ge 80) { 'excellent' } elseif ($healthScore -ge 60) { 'good' } elseif ($healthScore -ge 40) { 'warning' } else { 'critical' }
$healthColor = if ($healthScore -ge 80) { '#10B981' } elseif ($healthScore -ge 60) { '#3B82F6' } elseif ($healthScore -ge 40) { '#F59E0B' } else { '#EF4444' }

# Add health score section
$htmlReport += @"
        
        <!-- Health Score Section -->
        <div class="health-section">
            <div class="health-score $healthClass" style="--score: $($healthScore * 3.6)deg">
                <div class="inner"></div>
                <div class="score-value" style="color: $healthColor">$healthScore</div>
            </div>
            <div class="health-label">AD Health Score</div>
            <div class="health-details">
                <div class="health-detail good">
                    <div class="value">$($auditResults['ActiveUsers'].Count)</div>
                    <div class="label">Active Users</div>
                </div>
                <div class="health-detail $(if ($auditResults['InactiveUsers'].Count -gt 0) { 'warning' } else { 'good' })">
                    <div class="value">$($auditResults['InactiveUsers'].Count)</div>
                    <div class="label">Inactive</div>
                </div>
                <div class="health-detail $(if ($auditResults['ExpiredPasswords'].Count -gt 0) { 'warning' } else { 'good' })">
                    <div class="value">$($auditResults['ExpiredPasswords'].Count)</div>
                    <div class="label">Expired PWD</div>
                </div>
                <div class="health-detail $(if ($auditResults['LockedUsers'].Count -gt 0) { 'danger' } else { 'good' })">
                    <div class="value">$($auditResults['LockedUsers'].Count)</div>
                    <div class="label">Locked</div>
                </div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">$($auditResults['TotalUsers'])</div>
                <div class="label">Total Users</div>
            </div>
            <div class="summary-card success">
                <div class="number">$($auditResults['ActiveUsers'].Count)</div>
                <div class="label">Active Users</div>
            </div>
            <div class="summary-card $(if ($auditResults['InactiveUsers'].Count -gt 0) { 'warning' })">
                <div class="number">$($auditResults['InactiveUsers'].Count)</div>
                <div class="label">Inactive Users</div>
            </div>
            <div class="summary-card">
                <div class="number">$($auditResults['DisabledUsers'].Count)</div>
                <div class="label">Disabled Users</div>
            </div>
            <div class="summary-card $(if ($auditResults['LockedUsers'].Count -gt 0) { 'danger' })">
                <div class="number">$($auditResults['LockedUsers'].Count)</div>
                <div class="label">Locked Users</div>
            </div>
            <div class="summary-card $(if ($auditResults['ExpiredPasswords'].Count -gt 0) { 'warning' })">
                <div class="number">$($auditResults['ExpiredPasswords'].Count)</div>
                <div class="label">Expired Passwords</div>
            </div>
            <div class="summary-card $(if ($auditResults['RecentlyCreated'].Count -gt 5) { 'warning' })">
                <div class="number">$($auditResults['RecentlyCreated'].Count)</div>
                <div class="label">Recently Created</div>
            </div>
            <div class="summary-card">
                <div class="number">$($auditResults['ServiceAccounts'].Count)</div>
                <div class="label">Service Accounts</div>
            </div>
"@

if (-not $SkipComputerAudit) {
    $htmlReport += @"
            <div class="summary-card">
                <div class="number">$($auditResults['TotalComputers'])</div>
                <div class="label">Total Computers</div>
            </div>
            <div class="summary-card $(if ($auditResults['StaleComputers'].Count -gt 0) { 'warning' })">
                <div class="number">$($auditResults['StaleComputers'].Count)</div>
                <div class="label">Stale Computers</div>
            </div>
"@
}

if (-not $SkipGroupAudit) {
    $htmlReport += @"
            <div class="summary-card">
                <div class="number">$($auditResults['PrivilegedGroupMembers'].Count)</div>
                <div class="label">Privileged Members</div>
            </div>
"@
}

$htmlReport += @"
        </div>
        
        <!-- Charts Section -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3>User Account Status</h3>
                <div class="chart-container">
                    <canvas id="userStatusChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Password Health</h3>
                <div class="chart-container">
                    <canvas id="passwordHealthChart"></canvas>
                </div>
            </div>
"@

if (-not $SkipComputerAudit) {
    $htmlReport += @"
            <div class="chart-card">
                <h3>Computer Status</h3>
                <div class="chart-container">
                    <canvas id="computerStatusChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Operating Systems</h3>
                <div class="chart-container">
                    <canvas id="osDistributionChart"></canvas>
                </div>
            </div>
"@
}

if (-not $SkipGroupAudit) {
    $htmlReport += @"
            <div class="chart-card">
                <h3>Privileged Group Members</h3>
                <div class="chart-container large">
                    <canvas id="privilegedGroupsChart"></canvas>
                </div>
            </div>
"@
}

# Calculate inactivity breakdown
$inactive30 = @($auditResults['InactiveUsers'] | Where-Object { $_.DaysSinceLogon -le 120 }).Count
$inactive120 = @($auditResults['InactiveUsers'] | Where-Object { $_.DaysSinceLogon -gt 120 -and $_.DaysSinceLogon -le 180 }).Count
$inactive180 = @($auditResults['InactiveUsers'] | Where-Object { $_.DaysSinceLogon -gt 180 -and $_.DaysSinceLogon -le 365 }).Count
$inactive365 = @($auditResults['InactiveUsers'] | Where-Object { $_.DaysSinceLogon -gt 365 }).Count

$htmlReport += @"
            <div class="chart-card">
                <h3>Inactivity Breakdown</h3>
                <div class="chart-container">
                    <canvas id="inactivityChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Table of Contents -->
        <div class="toc">
            <h3>Table of Contents</h3>
            <div class="toc-grid">
                <div class="toc-section">
                    <div class="toc-section-title">User Accounts</div>
                    <a href="#sec-inactive">Inactive Users <span class="count $(if ($auditResults['InactiveUsers'].Count -gt 0) { 'warning' })">($($auditResults['InactiveUsers'].Count))</span></a>
                    <a href="#sec-neverlogon">Never Logged On <span class="count $(if ($auditResults['NeverLoggedOn'].Count -gt 0) { 'warning' })">($($auditResults['NeverLoggedOn'].Count))</span></a>
                    <a href="#sec-locked">Locked Out <span class="count $(if ($auditResults['LockedUsers'].Count -gt 0) { 'danger' })">($($auditResults['LockedUsers'].Count))</span></a>
                    <a href="#sec-disabled">Disabled Accounts <span class="count">($($auditResults['DisabledUsers'].Count))</span></a>
                    <a href="#sec-recent">Recently Created <span class="count $(if ($auditResults['RecentlyCreated'].Count -gt 5) { 'warning' })">($($auditResults['RecentlyCreated'].Count))</span></a>
                </div>
                <div class="toc-section">
                    <div class="toc-section-title">Password Security</div>
                    <a href="#sec-expired">Expired Passwords <span class="count $(if ($auditResults['ExpiredPasswords'].Count -gt 0) { 'danger' })">($($auditResults['ExpiredPasswords'].Count))</span></a>
                    <a href="#sec-expiring">Expiring Soon <span class="count $(if ($auditResults['UpcomingExpirations'].Count -gt 0) { 'warning' })">($($auditResults['UpcomingExpirations'].Count))</span></a>
                    <a href="#sec-neverexpire">Never Expires <span class="count">($($auditResults['PasswordNeverExpires'].Count))</span></a>
                    <a href="#sec-stale">Stale Passwords <span class="count $(if ($auditResults['StalePasswords'].Count -gt 0) { 'warning' })">($($auditResults['StalePasswords'].Count))</span></a>
                    <a href="#sec-service">Service Accounts <span class="count">($($auditResults['ServiceAccounts'].Count))</span></a>
                </div>
"@

if (-not $SkipComputerAudit) {
    $htmlReport += @"
                <div class="toc-section">
                    <div class="toc-section-title">Computer Accounts</div>
                    <a href="#sec-stalecomp">Stale Computers <span class="count $(if ($auditResults['StaleComputers'].Count -gt 0) { 'warning' })">($($auditResults['StaleComputers'].Count))</span></a>
                    <a href="#sec-legacy">Legacy OS <span class="count $(if ($auditResults['LegacyOS'].Count -gt 0) { 'danger' })">($($auditResults['LegacyOS'].Count))</span></a>
                    <a href="#sec-servers">Windows Servers <span class="count">($($auditResults['WindowsServers'].Count))</span></a>
                    <a href="#sec-osdist">OS Distribution <span class="count">($($auditResults['ComputersByOS'].Count))</span></a>
                </div>
"@
}

if (-not $SkipGroupAudit) {
    $vpnCount = if ($auditResults['VPNUsers']) { $auditResults['VPNUsers'].Count } else { 0 }
    $htmlReport += @"
                <div class="toc-section">
                    <div class="toc-section-title">Security Groups</div>
                    <a href="#sec-privileged">Privileged Groups <span class="count">($($auditResults['PrivilegedGroupMembers'].Count))</span></a>
                    <a href="#sec-vpn">VPN Users <span class="count">($vpnCount)</span></a>
                </div>
"@
}

$htmlReport += @"
            </div>
        </div>
"@

# Add sections for each audit category
$htmlReport += ConvertTo-HTMLReport -Title "Recently Created Accounts ($RecentlyCreatedDays Days)" `
    -Description "User accounts created within the specified period. Review for unauthorized account creation." `
    -Data $auditResults['RecentlyCreated'] `
    -Columns @('SamAccountName', 'Name', 'Created', 'DaysSinceCreated', 'Enabled', 'LastLogonDate', 'Description', 'OU') `
    -SectionId "sec-recent" `
    -EmptyMessage "No accounts created in the last $RecentlyCreatedDays days."

$htmlReport += ConvertTo-HTMLReport -Title "Inactive Users ($InactiveDays+ Days)" `
    -Description "User accounts that have not logged on within the specified threshold and may need review for disabling or removal." `
    -Data $auditResults['InactiveUsers'] `
    -Columns @('SamAccountName', 'Name', 'Enabled', 'LastLogonDate', 'DaysSinceLogon', 'Description', 'OU') `
    -SectionId "sec-inactive" `
    -EmptyMessage "No inactive users found - excellent!"

$htmlReport += ConvertTo-HTMLReport -Title "Users Never Logged On" `
    -Description "Enabled user accounts that have never authenticated to the domain." `
    -Data $auditResults['NeverLoggedOn'] `
    -Columns @('SamAccountName', 'Name', 'Created', 'DaysSinceCreated', 'Description', 'OU') `
    -SectionId "sec-neverlogon"

$htmlReport += ConvertTo-HTMLReport -Title "Locked Out Users" `
    -Description "User accounts currently in a locked-out state." `
    -Data $auditResults['LockedUsers'] `
    -Columns @('SamAccountName', 'Name', 'LastBadPasswordAttempt', 'BadLogonCount', 'Description') `
    -SectionId "sec-locked"

$htmlReport += ConvertTo-HTMLReport -Title "Upcoming Password Expirations ($PasswordExpiringDays Days)" `
    -Description "User accounts with passwords expiring within the specified period. Consider notifying these users." `
    -Data $auditResults['UpcomingExpirations'] `
    -Columns @('SamAccountName', 'Name', 'PasswordLastSet', 'ExpirationDate', 'DaysUntilExpire', 'OU') `
    -SectionId "sec-expiring" `
    -EmptyMessage "No passwords expiring in the next $PasswordExpiringDays days."

$htmlReport += ConvertTo-HTMLReport -Title "Expired Passwords" `
    -Description "Enabled user accounts with expired passwords." `
    -Data $auditResults['ExpiredPasswords'] `
    -Columns @('SamAccountName', 'Name', 'UserPrincipalName', 'PasswordLastSet', 'LastLogonDate') `
    -SectionId "sec-expired"

$htmlReport += ConvertTo-HTMLReport -Title "Passwords That Never Expire" `
    -Description "User accounts configured with non-expiring passwords. Review for service accounts vs. regular users." `
    -Data $auditResults['PasswordNeverExpires'] `
    -Columns @('SamAccountName', 'Name', 'PasswordLastSet', 'LastLogonDate', 'Description', 'OU') `
    -SectionId "sec-neverexpire"

$htmlReport += ConvertTo-HTMLReport -Title "Stale Passwords ($PasswordAgeDays+ Days)" `
    -Description "Passwords that have not been changed within the threshold period." `
    -Data $auditResults['StalePasswords'] `
    -Columns @('SamAccountName', 'Name', 'PasswordLastSet', 'PasswordAge', 'LastLogonDate', 'OU') `
    -SectionId "sec-stale"

$htmlReport += ConvertTo-HTMLReport -Title "Potential Service Accounts" `
    -Description "Accounts detected as potential service accounts based on naming patterns, descriptions, or password settings. Verify and document these accounts." `
    -Data $auditResults['ServiceAccounts'] `
    -Columns @('SamAccountName', 'Name', 'Enabled', 'PasswordNeverExpires', 'PasswordAge', 'LastLogonDate', 'Description', 'OU') `
    -SectionId "sec-service"

$htmlReport += ConvertTo-HTMLReport -Title "Disabled User Accounts" `
    -Description "All currently disabled user accounts in the domain." `
    -Data $auditResults['DisabledUsers'] `
    -Columns @('SamAccountName', 'Name', 'LastLogonDate', 'Modified', 'Description', 'OU') `
    -SectionId "sec-disabled"

if (-not $SkipComputerAudit) {
    $htmlReport += ConvertTo-HTMLReport -Title "Stale Computers ($InactiveDays+ Days)" `
        -Description "Computer accounts that have not authenticated to the domain within the threshold period." `
        -Data $auditResults['StaleComputers'] `
        -Columns @('Name', 'DNSHostName', 'OperatingSystem', 'LastLogonDate', 'DaysSinceLogon', 'OU') `
        -SectionId "sec-stalecomp"
    
    $htmlReport += ConvertTo-HTMLReport -Title "Legacy Operating Systems" `
        -Description "Computers running unsupported or end-of-life operating systems (XP, Vista, 7, Server 2003/2008)." `
        -Data $auditResults['LegacyOS'] `
        -Columns @('Name', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'OU') `
        -SectionId "sec-legacy" `
        -EmptyMessage "No legacy operating systems detected - excellent!"
    
    $htmlReport += ConvertTo-HTMLReport -Title "Windows Servers" `
        -Description "Inventory of all Windows Server operating systems in the domain." `
        -Data $auditResults['WindowsServers'] `
        -Columns @('Name', 'DNSHostName', 'OperatingSystem', 'LastLogonDate', 'IPv4Address', 'Description') `
        -SectionId "sec-servers"
    
    $htmlReport += ConvertTo-HTMLReport -Title "Computers by Operating System" `
        -Description "Distribution of computer accounts by operating system." `
        -Data $auditResults['ComputersByOS'] `
        -Columns @('OperatingSystem', 'Count') `
        -SectionId "sec-osdist"
}

if (-not $SkipGroupAudit) {
    $htmlReport += ConvertTo-HTMLReport -Title "Privileged Group Membership" `
        -Description "Members of security-sensitive groups including Domain Admins, Enterprise Admins, and other administrative groups." `
        -Data $auditResults['PrivilegedGroupMembers'] `
        -Columns @('GroupName', 'SamAccountName', 'Name', 'Enabled', 'LastLogonDate', 'PasswordLastSet') `
        -SectionId "sec-privileged"
    
    if ($auditResults['VPNUsers'] -and $auditResults['VPNUsers'].Count -gt 0) {
        $htmlReport += ConvertTo-HTMLReport -Title "VPN Users" `
            -Description "Members of VPN access groups (WatchGuard SSL-VPN, IKEv2, and similar)." `
            -Data $auditResults['VPNUsers'] `
            -Columns @('GroupName', 'SamAccountName', 'Name', 'UserPrincipalName', 'Enabled', 'LastLogonDate') `
            -SectionId "sec-vpn"
    }
}

# Footer and Charts JavaScript
$htmlReport += @"
    </div>
    
    <div class="footer">
        <p>Generated by <a href="https://github.com/YeylandWutani">Yeyland Wutani</a> AD Security Audit Tool v1.0.0</p>
        <p>Building Better Systems</p>
        <p style="margin-top: 10px; font-size: 11px; color: #4B5563;">
            Review all findings and validate before taking action on accounts.
        </p>
    </div>
    
    <script>
        // Chart.js default configuration for dark theme
        Chart.defaults.color = '#9CA3AF';
        Chart.defaults.borderColor = '#374151';
        
        // Color palette
        const colors = {
            orange: '#FF6600',
            green: '#10B981',
            yellow: '#F59E0B',
            red: '#EF4444',
            blue: '#3B82F6',
            purple: '#8B5CF6',
            pink: '#EC4899',
            cyan: '#06B6D4',
            gray: '#6B7280'
        };
        
        // User Status Pie Chart
        const userStatusCtx = document.getElementById('userStatusChart');
        if (userStatusCtx) {
            new Chart(userStatusCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Active', 'Disabled', 'Inactive', 'Never Logged On'],
                    datasets: [{
                        data: [$($auditResults['ActiveUsers'].Count - $auditResults['InactiveUsers'].Count - $auditResults['NeverLoggedOn'].Count), $($auditResults['DisabledUsers'].Count), $($auditResults['InactiveUsers'].Count), $($auditResults['NeverLoggedOn'].Count)],
                        backgroundColor: [colors.green, colors.gray, colors.yellow, colors.red],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { padding: 15, usePointStyle: true }
                        }
                    }
                }
            });
        }
        
        // Password Health Pie Chart
        const passwordHealthCtx = document.getElementById('passwordHealthChart');
        if (passwordHealthCtx) {
            const healthyPasswords = $($auditResults['ActiveUsers'].Count) - $($auditResults['ExpiredPasswords'].Count) - $($auditResults['StalePasswords'].Count) - $($auditResults['PasswordNeverExpires'].Count);
            new Chart(passwordHealthCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Healthy', 'Expired', 'Stale ($PasswordAgeDays+ days)', 'Never Expires'],
                    datasets: [{
                        data: [Math.max(0, healthyPasswords), $($auditResults['ExpiredPasswords'].Count), $($auditResults['StalePasswords'].Count), $($auditResults['PasswordNeverExpires'].Count)],
                        backgroundColor: [colors.green, colors.red, colors.yellow, colors.orange],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { padding: 15, usePointStyle: true }
                        }
                    }
                }
            });
        }
        
        // Inactivity Breakdown Bar Chart
        const inactivityCtx = document.getElementById('inactivityChart');
        if (inactivityCtx) {
            new Chart(inactivityCtx, {
                type: 'bar',
                data: {
                    labels: ['$InactiveDays-120 days', '121-180 days', '181-365 days', '365+ days'],
                    datasets: [{
                        label: 'Inactive Users',
                        data: [$inactive30, $inactive120, $inactive180, $inactive365],
                        backgroundColor: [colors.yellow, colors.orange, colors.red, colors.purple],
                        borderWidth: 0,
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { stepSize: 1 }
                        }
                    }
                }
            });
        }
"@

# Add computer charts if not skipped
if (-not $SkipComputerAudit) {
    $activeComputerCount = $auditResults['ActiveComputers'].Count - $auditResults['StaleComputers'].Count
    
    # Build OS distribution data
    $osLabels = @()
    $osData = @()
    $osColors = @('colors.blue', 'colors.green', 'colors.purple', 'colors.cyan', 'colors.pink', 'colors.orange', 'colors.yellow')
    $colorIndex = 0
    
    foreach ($os in ($auditResults['ComputersByOS'] | Select-Object -First 7)) {
        $osName = if ($os.OperatingSystem) { $os.OperatingSystem } else { 'Unknown' }
        $osName = $osName -replace "'", ""
        if ($osName.Length -gt 25) { $osName = $osName.Substring(0, 22) + '...' }
        $osLabels += "'$osName'"
        $osData += $os.Count
        $colorIndex++
    }
    
    $osLabelsJs = $osLabels -join ', '
    $osDataJs = $osData -join ', '
    
    $htmlReport += @"
        
        // Computer Status Pie Chart
        const computerStatusCtx = document.getElementById('computerStatusChart');
        if (computerStatusCtx) {
            new Chart(computerStatusCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Active', 'Disabled', 'Stale'],
                    datasets: [{
                        data: [$activeComputerCount, $($auditResults['DisabledComputers'].Count), $($auditResults['StaleComputers'].Count)],
                        backgroundColor: [colors.green, colors.gray, colors.yellow],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { padding: 15, usePointStyle: true }
                        }
                    }
                }
            });
        }
        
        // OS Distribution Pie Chart
        const osDistributionCtx = document.getElementById('osDistributionChart');
        if (osDistributionCtx) {
            new Chart(osDistributionCtx, {
                type: 'doughnut',
                data: {
                    labels: [$osLabelsJs],
                    datasets: [{
                        data: [$osDataJs],
                        backgroundColor: [colors.blue, colors.green, colors.purple, colors.cyan, colors.pink, colors.orange, colors.yellow],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { 
                                padding: 10, 
                                usePointStyle: true,
                                font: { size: 10 }
                            }
                        }
                    }
                }
            });
        }
"@
}

# Add privileged groups chart if not skipped
if (-not $SkipGroupAudit) {
    # Build group membership data
    $groupCounts = $auditResults['PrivilegedGroupMembers'] | Group-Object GroupName | Sort-Object Count -Descending | Select-Object -First 10
    $groupLabels = @()
    $groupData = @()
    
    foreach ($group in $groupCounts) {
        $groupName = $group.Name -replace "'", ""
        $groupLabels += "'$groupName'"
        $groupData += $group.Count
    }
    
    $groupLabelsJs = $groupLabels -join ', '
    $groupDataJs = $groupData -join ', '
    
    $htmlReport += @"
        
        // Privileged Groups Bar Chart
        const privilegedGroupsCtx = document.getElementById('privilegedGroupsChart');
        if (privilegedGroupsCtx) {
            new Chart(privilegedGroupsCtx, {
                type: 'bar',
                data: {
                    labels: [$groupLabelsJs],
                    datasets: [{
                        label: 'Members',
                        data: [$groupDataJs],
                        backgroundColor: colors.orange,
                        borderWidth: 0,
                        borderRadius: 4
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: { stepSize: 1 }
                        }
                    }
                }
            });
        }
"@
}

$htmlReport += @"
    </script>
</body>
</html>
"@

# Save HTML report
$htmlPath = Join-Path $OutputPath "$($script:ReportPrefix)_Report.html"
$htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Status "HTML report saved: $htmlPath" -Type Success
#endregion

#region Summary Output
Write-Host ""
Write-Status "=== AUDIT COMPLETE ===" -Type Success
Write-Host ""
Write-Host "  Domain:           " -NoNewline -ForegroundColor Gray
Write-Host $domainName -ForegroundColor Cyan
Write-Host "  Total Users:      " -NoNewline -ForegroundColor Gray
Write-Host $auditResults['TotalUsers'] -ForegroundColor White
Write-Host "  Active Users:     " -NoNewline -ForegroundColor Gray
Write-Host $auditResults['ActiveUsers'].Count -ForegroundColor Green
Write-Host "  Disabled Users:   " -NoNewline -ForegroundColor Gray
Write-Host $auditResults['DisabledUsers'].Count -ForegroundColor Yellow
Write-Host "  Inactive Users:   " -NoNewline -ForegroundColor Gray
Write-Host "$($auditResults['InactiveUsers'].Count)" -ForegroundColor $(if ($auditResults['InactiveUsers'].Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Recently Created: " -NoNewline -ForegroundColor Gray
Write-Host "$($auditResults['RecentlyCreated'].Count)" -ForegroundColor $(if ($auditResults['RecentlyCreated'].Count -gt 5) { 'Yellow' } else { 'White' })
Write-Host "  Service Accounts: " -NoNewline -ForegroundColor Gray
Write-Host "$($auditResults['ServiceAccounts'].Count)" -ForegroundColor White

if (-not $SkipComputerAudit) {
    Write-Host "  Total Computers:  " -NoNewline -ForegroundColor Gray
    Write-Host $auditResults['TotalComputers'] -ForegroundColor White
    Write-Host "  Stale Computers:  " -NoNewline -ForegroundColor Gray
    Write-Host "$($auditResults['StaleComputers'].Count)" -ForegroundColor $(if ($auditResults['StaleComputers'].Count -gt 0) { 'Yellow' } else { 'Green' })
}

Write-Host ""
Write-Host "  Output Directory: " -NoNewline -ForegroundColor Gray
Write-Host $OutputPath -ForegroundColor Cyan
Write-Host "  Health Score:     " -NoNewline -ForegroundColor Gray
$scoreColor = if ($healthScore -ge 80) { 'Green' } elseif ($healthScore -ge 60) { 'Cyan' } elseif ($healthScore -ge 40) { 'Yellow' } else { 'Red' }
Write-Host "$healthScore/100" -ForegroundColor $scoreColor
Write-Host "  Duration:         " -NoNewline -ForegroundColor Gray
Write-Host "$([math]::Round($auditDuration.TotalMinutes, 2)) minutes" -ForegroundColor White
Write-Host ""

# Return summary object for pipeline use
[PSCustomObject]@{
    Domain = $domainName
    TotalUsers = $auditResults['TotalUsers']
    ActiveUsers = $auditResults['ActiveUsers'].Count
    DisabledUsers = $auditResults['DisabledUsers'].Count
    InactiveUsers = $auditResults['InactiveUsers'].Count
    NeverLoggedOn = $auditResults['NeverLoggedOn'].Count
    LockedUsers = $auditResults['LockedUsers'].Count
    RecentlyCreated = $auditResults['RecentlyCreated'].Count
    ServiceAccounts = $auditResults['ServiceAccounts'].Count
    ExpiredPasswords = $auditResults['ExpiredPasswords'].Count
    UpcomingExpirations = $auditResults['UpcomingExpirations'].Count
    PasswordNeverExpires = $auditResults['PasswordNeverExpires'].Count
    StalePasswords = $auditResults['StalePasswords'].Count
    TotalComputers = if ($SkipComputerAudit) { 'Skipped' } else { $auditResults['TotalComputers'] }
    StaleComputers = if ($SkipComputerAudit) { 'Skipped' } else { $auditResults['StaleComputers'].Count }
    LegacyOSSystems = if ($SkipComputerAudit) { 'Skipped' } else { $auditResults['LegacyOS'].Count }
    PrivilegedMembers = if ($SkipGroupAudit) { 'Skipped' } else { $auditResults['PrivilegedGroupMembers'].Count }
    HealthScore = $healthScore
    ReportPath = $htmlPath
    Duration = $auditDuration
}
#endregion
