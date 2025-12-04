<#
.SYNOPSIS
    Comprehensive Active Directory user account troubleshooting tool.

.DESCRIPTION
    Performs detailed diagnostics on AD user accounts to identify common issues:
    - Account status (enabled/disabled, locked)
    - Password status and expiration
    - Last logon information across all DCs
    - Group memberships and nested groups
    - Account attributes and flags
    - Kerberos ticket issues
    - Replication status for user object
    - Azure AD Connect sync status (if applicable)

.PARAMETER Identity
    User's SamAccountName, UserPrincipalName, or DistinguishedName.

.PARAMETER IncludeGroupDetails
    Include detailed group membership analysis including nested groups.

.PARAMETER CheckAzureADSync
    Check if user is synced to Azure AD (requires Azure AD Connect on accessible server).

.EXAMPLE
    .\Get-ADUserTroubleshooter.ps1 -Identity "jdoe"
    Basic troubleshooting for user jdoe.

.EXAMPLE
    .\Get-ADUserTroubleshooter.ps1 -Identity "john.doe@contoso.com" -IncludeGroupDetails
    Full troubleshooting with detailed group analysis.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: ActiveDirectory module, appropriate AD permissions
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Identity,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeGroupDetails,
    
    [Parameter(Mandatory=$false)]
    [switch]$CheckAzureADSync
)

# Import required module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT-AD-PowerShell is installed."
    exit 1
}

Write-Host "`n=== AD User Account Troubleshooter ===" -ForegroundColor DarkYellow
Write-Host "Yeyland Wutani - Building Better Systems`n" -ForegroundColor Gray

# Attempt to retrieve user
Write-Host "Searching for user: $Identity" -ForegroundColor Gray
try {
    $user = Get-ADUser -Identity $Identity -Properties * -ErrorAction Stop
    Write-Host "[OK] User found: $($user.SamAccountName)`n" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] User not found or access denied" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Basic Information
Write-Host "=== Basic Information ===" -ForegroundColor DarkYellow
Write-Host "Display Name:        $($user.DisplayName)"
Write-Host "SamAccountName:      $($user.SamAccountName)"
Write-Host "UserPrincipalName:   $($user.UserPrincipalName)"
Write-Host "Email:               $($user.EmailAddress)"
Write-Host "Distinguished Name:  $($user.DistinguishedName)"
Write-Host "Created:             $($user.whenCreated)"
Write-Host "Modified:            $($user.whenChanged)"

# Account Status
Write-Host "`n=== Account Status ===" -ForegroundColor DarkYellow

$accountStatus = @()

if ($user.Enabled -eq $true) {
    Write-Host "[OK] Account: Enabled" -ForegroundColor Green
} else {
    Write-Host "[ISSUE] Account: DISABLED" -ForegroundColor Red
    $accountStatus += "Account is disabled"
}

if ($user.LockedOut -eq $true) {
    Write-Host "[ISSUE] Account: LOCKED OUT" -ForegroundColor Red
    Write-Host "  Lockout Time: $($user.AccountLockoutTime)"
    $accountStatus += "Account is locked out"
    
    # Show how to unlock
    Write-Host "  To unlock: Unlock-ADAccount -Identity '$($user.SamAccountName)'" -ForegroundColor Yellow
} else {
    Write-Host "[OK] Account: Not Locked" -ForegroundColor Green
}

# Account expiration
if ($user.AccountExpirationDate) {
    if ($user.AccountExpirationDate -lt (Get-Date)) {
        Write-Host "[ISSUE] Account: EXPIRED on $($user.AccountExpirationDate)" -ForegroundColor Red
        $accountStatus += "Account expired"
    } else {
        Write-Host "[INFO] Account Expires: $($user.AccountExpirationDate)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] Account: Never Expires" -ForegroundColor Green
}

# Password Status
Write-Host "`n=== Password Status ===" -ForegroundColor DarkYellow

if ($user.PasswordNeverExpires -eq $true) {
    Write-Host "[INFO] Password: Never Expires" -ForegroundColor Yellow
} else {
    Write-Host "Password Expires:    $(if ($user.PasswordExpired) { 'YES - EXPIRED' } else { 'No' })"
    if ($user.PasswordLastSet) {
        Write-Host "Password Last Set:   $($user.PasswordLastSet)"
        
        # Calculate password age and expiration
        $domain = Get-ADDomain
        $maxPasswordAge = $domain.MaxPasswordAge.Days
        if ($maxPasswordAge -gt 0) {
            $passwordAge = (Get-Date) - $user.PasswordLastSet
            $daysUntilExpiration = $maxPasswordAge - $passwordAge.Days
            
            if ($daysUntilExpiration -le 0) {
                Write-Host "[ISSUE] Password: EXPIRED" -ForegroundColor Red
                $accountStatus += "Password expired"
            } elseif ($daysUntilExpiration -le 7) {
                Write-Host "[WARN] Password expires in: $daysUntilExpiration days" -ForegroundColor Yellow
            } else {
                Write-Host "[OK] Password expires in: $daysUntilExpiration days" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "[ISSUE] Password: Never set (must change at next logon)" -ForegroundColor Red
        $accountStatus += "Password never set"
    }
}

Write-Host "Password Not Required: $(if ($user.PasswordNotRequired) { 'Yes' } else { 'No' })"
Write-Host "Cannot Change Password: $(if ($user.CannotChangePassword) { 'Yes' } else { 'No' })"
Write-Host "Must Change Password: $(if ($user.PasswordExpired) { 'Yes' } else { 'No' })"

# Logon Information
Write-Host "`n=== Logon Information ===" -ForegroundColor DarkYellow

if ($user.LastLogonDate) {
    $daysSinceLogon = ((Get-Date) - $user.LastLogonDate).Days
    Write-Host "Last Logon (Replicated): $($user.LastLogonDate) ($daysSinceLogon days ago)"
} else {
    Write-Host "Last Logon (Replicated): Never"
}

Write-Host "Logon Count:            $($user.logonCount)"
Write-Host "Bad Password Count:     $($user.badPwdCount)"

if ($user.LastBadPasswordAttempt) {
    Write-Host "Last Bad Password:      $($user.LastBadPasswordAttempt)"
}

# Get last logon from all DCs
Write-Host "`nChecking last logon across all Domain Controllers..."
$allDCs = Get-ADDomainController -Filter *
$lastLogons = @()

foreach ($dc in $allDCs) {
    try {
        $dcUser = Get-ADUser -Identity $user.SamAccountName -Server $dc.HostName -Properties LastLogon -ErrorAction Stop
        if ($dcUser.LastLogon) {
            $lastLogonDate = [DateTime]::FromFileTime($dcUser.LastLogon)
            $lastLogons += [PSCustomObject]@{
                DomainController = $dc.HostName
                LastLogon = $lastLogonDate
            }
        }
    } catch {
        Write-Host "  [WARN] Could not query $($dc.HostName)" -ForegroundColor Yellow
    }
}

if ($lastLogons.Count -gt 0) {
    $mostRecentLogon = ($lastLogons | Sort-Object LastLogon -Descending)[0]
    Write-Host "[INFO] Most recent logon: $($mostRecentLogon.LastLogon) on $($mostRecentLogon.DomainController)" -ForegroundColor Cyan
}

# Group Memberships
Write-Host "`n=== Group Memberships ===" -ForegroundColor DarkYellow
$groups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Sort-Object Name

Write-Host "Direct Group Count: $($groups.Count)"
Write-Host "`nDirect Groups:"
foreach ($group in $groups) {
    Write-Host "  - $($group.Name)"
}

if ($IncludeGroupDetails) {
    Write-Host "`n=== Nested Group Analysis ===" -ForegroundColor DarkYellow
    $allGroups = @()
    $processedGroups = @()
    
    function Get-NestedGroups {
        param($GroupDN, $Level = 0)
        
        if ($processedGroups -contains $GroupDN) { return }
        $processedGroups += $GroupDN
        
        try {
            $group = Get-ADGroup -Identity $GroupDN -Properties MemberOf
            $indent = "  " * $Level
            Write-Host "$indent- $($group.Name)" -ForegroundColor Gray
            
            foreach ($parentGroup in $group.MemberOf) {
                Get-NestedGroups -GroupDN $parentGroup -Level ($Level + 1)
            }
        } catch {
            Write-Host "$indent[WARN] Could not process group" -ForegroundColor Yellow
        }
    }
    
    foreach ($group in $groups) {
        Get-NestedGroups -GroupDN $group.DistinguishedName
    }
}

# Account Attributes and Flags
Write-Host "`n=== Account Attributes ===" -ForegroundColor DarkYellow
Write-Host "Smart Card Required:           $(if ($user.SmartcardLogonRequired) { 'Yes' } else { 'No' })"
Write-Host "Trusted for Delegation:        $(if ($user.TrustedForDelegation) { 'Yes' } else { 'No' })"
Write-Host "Use DES Key Only:              $(if ($user.UseDESKeyOnly) { 'Yes' } else { 'No' })"
Write-Host "Does Not Require Pre-Auth:     $(if ($user.DoesNotRequirePreAuth) { 'Yes' } else { 'No' })"
Write-Host "Password Reversible Encryption: $(if ($user.AllowReversiblePasswordEncryption) { 'Yes' } else { 'No' })"

# Logon Workstations
if ($user.LogonWorkstations) {
    Write-Host "`nLogon Workstations Restricted To:"
    Write-Host "  $($user.LogonWorkstations)"
}

# Logon Hours
if ($user.LogonHours) {
    Write-Host "`n[INFO] Logon hours are restricted" -ForegroundColor Yellow
}

# Manager Information
if ($user.Manager) {
    try {
        $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName
        Write-Host "`nManager: $($manager.DisplayName)"
    } catch {
        Write-Host "`nManager: $($user.Manager) (Could not retrieve details)"
    }
}

# Check replication status
Write-Host "`n=== Replication Status ===" -ForegroundColor DarkYellow
Write-Host "Checking if user object is properly replicated..."

$userOnDCs = @()
foreach ($dc in $allDCs) {
    try {
        $null = Get-ADUser -Identity $user.SamAccountName -Server $dc.HostName -ErrorAction Stop
        Write-Host "[OK] User exists on: $($dc.HostName)" -ForegroundColor Green
        $userOnDCs += $dc.HostName
    } catch {
        Write-Host "[ISSUE] User NOT found on: $($dc.HostName)" -ForegroundColor Red
        $accountStatus += "User not replicated to $($dc.HostName)"
    }
}

# Azure AD Connect Sync Status
if ($CheckAzureADSync) {
    Write-Host "`n=== Azure AD Connect Sync Status ===" -ForegroundColor DarkYellow
    
    # Check if user has Azure AD sync attributes
    if ($user.'msDS-ExternalDirectoryObjectId') {
        Write-Host "[OK] User is synced to Azure AD" -ForegroundColor Green
        Write-Host "Azure AD Object ID: $($user.'msDS-ExternalDirectoryObjectId')"
        
        if ($user.OnPremisesSyncEnabled) {
            Write-Host "Sync Enabled: Yes"
        }
    } else {
        Write-Host "[INFO] User does not appear to be synced to Azure AD" -ForegroundColor Yellow
    }
    
    # Check if in sync scope
    if ($user.DistinguishedName -like "*OU=*") {
        Write-Host "`nUser OU: $($user.DistinguishedName -replace '^CN=[^,]+,')"
    }
}

# Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor DarkYellow

if ($accountStatus.Count -eq 0) {
    Write-Host "[OK] No major issues detected with this account" -ForegroundColor Green
} else {
    Write-Host "[ISSUES DETECTED]" -ForegroundColor Red
    foreach ($issue in $accountStatus) {
        Write-Host "  • $issue" -ForegroundColor Red
    }
}

# Common Troubleshooting Commands
Write-Host "`n=== Quick Troubleshooting Commands ===" -ForegroundColor DarkYellow
Write-Host "Unlock Account:        Unlock-ADAccount -Identity '$($user.SamAccountName)'" -ForegroundColor Gray
Write-Host "Enable Account:        Enable-ADAccount -Identity '$($user.SamAccountName)'" -ForegroundColor Gray
Write-Host "Reset Password:        Set-ADAccountPassword -Identity '$($user.SamAccountName)' -Reset" -ForegroundColor Gray
Write-Host "Clear Bad Pwd Count:   Set-ADUser -Identity '$($user.SamAccountName)' -Clear badPwdCount" -ForegroundColor Gray
Write-Host "Force Password Change: Set-ADUser -Identity '$($user.SamAccountName)' -ChangePasswordAtLogon `$true" -ForegroundColor Gray

Write-Host "`n"
