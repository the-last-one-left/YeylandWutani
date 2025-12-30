<#
.SYNOPSIS
    Resets a Windows user profile by renaming the old profile folder and clearing registry entries.

.DESCRIPTION
    This script automates the process of recreating a corrupted user profile without data loss.
    It renames the existing profile folder (preserving all data) and removes the profile registry
    entry, causing Windows to generate a fresh profile on the user's next login.
    
    The old profile folder is renamed to: Username.old.YYYYMMDD-HHMMSS
    
    IMPORTANT: The target user MUST be logged off before running this script.
    
    Common scenarios this resolves:
    - "We can't sign into your account" errors
    - Temporary profile (TEMP) login issues  
    - Profile corruption after failed Windows updates
    - Missing desktop, taskbar, or Start menu customizations
    - Application settings not persisting

.PARAMETER Username
    The username of the profile to reset. This should match the folder name in C:\Users.

.PARAMETER ComputerName
    Target computer name. Defaults to local computer. Requires admin access to remote machine.

.PARAMETER UsersPath
    Base path for user profiles. Defaults to C:\Users.

.PARAMETER BackupSuffix
    Custom suffix for the renamed folder. Defaults to "old.YYYYMMDD-HHMMSS".

.PARAMETER Force
    Bypasses confirmation prompts. Use with caution.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\Reset-UserProfile.ps1 -Username "jsmith"
    Resets the profile for user jsmith on the local computer.

.EXAMPLE
    .\Reset-UserProfile.ps1 -Username "jsmith" -ComputerName "WORKSTATION01"
    Resets the profile for jsmith on a remote computer.

.EXAMPLE
    .\Reset-UserProfile.ps1 -Username "jsmith" -WhatIf
    Shows what would happen without making any changes.

.EXAMPLE
    .\Reset-UserProfile.ps1 -Username "jsmith" -Force
    Resets the profile without confirmation prompts.

.NOTES
    Author:         Yeyland Wutani LLC
    Version:        1.0.0
    Required:       PowerShell 5.1+, Local Administrator rights
    
    After running this script:
    1. Have the user log in to generate a fresh profile
    2. Copy needed data from the .old folder to the new profile
    3. Common folders to migrate: Desktop, Documents, Downloads, Favorites, Pictures
    4. AppData migration may be needed for specific applications
    
.LINK
    https://github.com/YeylandWutani/Security

#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$UsersPath = "C:\Users",
    
    [Parameter(Mandatory = $false)]
    [string]$BackupSuffix,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#region Banner
function Show-YWBanner {
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
#endregion

#region Helper Functions
function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $colors = @{
        'Info'    = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
    }
    
    $prefixes = @{
        'Info'    = '[*]'
        'Success' = '[+]'
        'Warning' = '[!]'
        'Error'   = '[-]'
    }
    
    Write-Host "$($prefixes[$Type]) " -ForegroundColor $colors[$Type] -NoNewline
    Write-Host $Message
}

function Get-UserSID {
    param(
        [string]$Username,
        [string]$ComputerName
    )
    
    try {
        # Try to resolve username to SID using Win32_UserProfile
        $profile = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $ComputerName -ErrorAction Stop | 
            Where-Object { $_.LocalPath -like "*\$Username" }
        
        if ($profile) {
            return $profile.SID
        }
        
        # Fallback: Try to resolve via NTAccount
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($Username)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            return $sid.Value
        }
        catch {
            # Try with computer name prefix
            $ntAccount = New-Object System.Security.Principal.NTAccount("$ComputerName\$Username")
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            return $sid.Value
        }
    }
    catch {
        return $null
    }
}

function Test-ProfileLoaded {
    param(
        [string]$SID,
        [string]$ComputerName
    )
    
    try {
        $profile = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $ComputerName -ErrorAction Stop | 
            Where-Object { $_.SID -eq $SID }
        
        if ($profile) {
            return $profile.Loaded
        }
        return $false
    }
    catch {
        Write-StatusMessage "Unable to check profile load status: $_" -Type Warning
        return $null
    }
}

function Get-ProfileInfo {
    param(
        [string]$Username,
        [string]$ComputerName,
        [string]$UsersPath
    )
    
    $info = [PSCustomObject]@{
        Username       = $Username
        ComputerName   = $ComputerName
        ProfilePath    = $null
        ProfileExists  = $false
        SID            = $null
        Loaded         = $null
        LastUseTime    = $null
        RegistryPath   = $null
        RegistryExists = $false
        FolderSize     = $null
    }
    
    # Check profile folder
    if ($ComputerName -eq $env:COMPUTERNAME) {
        $profilePath = Join-Path -Path $UsersPath -ChildPath $Username
    }
    else {
        $profilePath = "\\$ComputerName\$($UsersPath -replace ':', '$')\$Username"
    }
    
    $info.ProfilePath = $profilePath
    $info.ProfileExists = Test-Path -Path $profilePath -PathType Container
    
    # Get SID and profile details
    $info.SID = Get-UserSID -Username $Username -ComputerName $ComputerName
    
    if ($info.SID) {
        $info.RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($info.SID)"
        
        # Check registry entry
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $info.RegistryExists = Test-Path -Path $info.RegistryPath
        }
        else {
            try {
                $regPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($info.SID)"
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $key = $reg.OpenSubKey($regPath)
                $info.RegistryExists = ($null -ne $key)
                if ($key) { $key.Close() }
                $reg.Close()
            }
            catch {
                $info.RegistryExists = $false
            }
        }
        
        # Get profile load status and last use time
        $profile = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $ComputerName -ErrorAction SilentlyContinue | 
            Where-Object { $_.SID -eq $info.SID }
        
        if ($profile) {
            $info.Loaded = $profile.Loaded
            $info.LastUseTime = $profile.LastUseTime
        }
    }
    
    # Calculate folder size if exists
    if ($info.ProfileExists) {
        try {
            $folderSize = (Get-ChildItem -Path $profilePath -Recurse -Force -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum).Sum
            $info.FolderSize = $folderSize
        }
        catch {
            $info.FolderSize = $null
        }
    }
    
    return $info
}

function Format-FileSize {
    param([long]$Size)
    
    if ($Size -ge 1GB) {
        return "{0:N2} GB" -f ($Size / 1GB)
    }
    elseif ($Size -ge 1MB) {
        return "{0:N2} MB" -f ($Size / 1MB)
    }
    elseif ($Size -ge 1KB) {
        return "{0:N2} KB" -f ($Size / 1KB)
    }
    else {
        return "$Size bytes"
    }
}

function Remove-ProfileRegistry {
    param(
        [string]$SID,
        [string]$ComputerName
    )
    
    $regPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            # Local computer
            $fullPath = "HKLM:\$regPath"
            if (Test-Path -Path $fullPath) {
                Remove-Item -Path $fullPath -Recurse -Force -ErrorAction Stop
                return $true
            }
        }
        else {
            # Remote computer
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $parentPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            $parentKey = $reg.OpenSubKey($parentPath, $true)
            
            if ($parentKey) {
                $parentKey.DeleteSubKeyTree($SID, $false)
                $parentKey.Close()
            }
            $reg.Close()
            return $true
        }
    }
    catch {
        Write-StatusMessage "Failed to remove registry entry: $_" -Type Error
        return $false
    }
    
    return $false
}

function Rename-ProfileFolder {
    param(
        [string]$SourcePath,
        [string]$NewName
    )
    
    try {
        $parentPath = Split-Path -Path $SourcePath -Parent
        $destinationPath = Join-Path -Path $parentPath -ChildPath $NewName
        
        # Check if destination already exists
        if (Test-Path -Path $destinationPath) {
            Write-StatusMessage "Destination path already exists: $destinationPath" -Type Error
            return $null
        }
        
        Rename-Item -Path $SourcePath -NewName $NewName -Force -ErrorAction Stop
        return $destinationPath
    }
    catch {
        Write-StatusMessage "Failed to rename profile folder: $_" -Type Error
        return $null
    }
}
#endregion

#region Main Execution
Show-YWBanner

Write-Host "  Reset-UserProfile v1.0.0" -ForegroundColor DarkYellow
Write-Host "  Windows Profile Recreation Tool" -ForegroundColor Gray
Write-Host ""

# Generate backup suffix if not provided
if ([string]::IsNullOrEmpty($BackupSuffix)) {
    $BackupSuffix = "old.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

$newFolderName = "$Username.$BackupSuffix"

Write-StatusMessage "Target: $Username on $ComputerName" -Type Info

# Gather profile information
Write-StatusMessage "Gathering profile information..." -Type Info
$profileInfo = Get-ProfileInfo -Username $Username -ComputerName $ComputerName -UsersPath $UsersPath

# Display profile information
Write-Host ""
Write-Host "  Profile Information" -ForegroundColor DarkYellow
Write-Host "  -------------------" -ForegroundColor Gray

$infoTable = @(
    @{ Label = "Username"; Value = $profileInfo.Username }
    @{ Label = "Computer"; Value = $profileInfo.ComputerName }
    @{ Label = "Profile Path"; Value = $profileInfo.ProfilePath }
    @{ Label = "Folder Exists"; Value = if ($profileInfo.ProfileExists) { "Yes" } else { "No" } }
    @{ Label = "SID"; Value = if ($profileInfo.SID) { $profileInfo.SID } else { "Not Found" } }
    @{ Label = "Profile Loaded"; Value = if ($null -eq $profileInfo.Loaded) { "Unknown" } elseif ($profileInfo.Loaded) { "Yes (USER LOGGED IN)" } else { "No" } }
    @{ Label = "Last Used"; Value = if ($profileInfo.LastUseTime) { $profileInfo.LastUseTime.ToString() } else { "Unknown" } }
    @{ Label = "Registry Entry"; Value = if ($profileInfo.RegistryExists) { "Exists" } else { "Not Found" } }
    @{ Label = "Folder Size"; Value = if ($profileInfo.FolderSize) { Format-FileSize $profileInfo.FolderSize } else { "Unknown" } }
)

foreach ($item in $infoTable) {
    Write-Host "  $($item.Label.PadRight(16)): " -ForegroundColor Gray -NoNewline
    
    $valueColor = 'White'
    if ($item.Label -eq "Profile Loaded" -and $profileInfo.Loaded -eq $true) {
        $valueColor = 'Red'
    }
    elseif ($item.Label -eq "Folder Exists" -and $profileInfo.ProfileExists) {
        $valueColor = 'Green'
    }
    elseif ($item.Label -eq "Registry Entry" -and $profileInfo.RegistryExists) {
        $valueColor = 'Green'
    }
    
    Write-Host $item.Value -ForegroundColor $valueColor
}

Write-Host ""

# Validation checks
$canProceed = $true
$errors = @()

if (-not $profileInfo.ProfileExists) {
    $errors += "Profile folder does not exist at: $($profileInfo.ProfilePath)"
    $canProceed = $false
}

if (-not $profileInfo.SID) {
    $errors += "Could not resolve SID for user: $Username"
    $canProceed = $false
}

if ($profileInfo.Loaded -eq $true) {
    $errors += "Profile is currently loaded - user must be logged off"
    $canProceed = $false
}

if (-not $profileInfo.RegistryExists -and $profileInfo.SID) {
    Write-StatusMessage "Registry entry not found - profile may already be partially reset" -Type Warning
}

# Display errors if any
if ($errors.Count -gt 0) {
    Write-Host ""
    Write-Host "  Validation Errors" -ForegroundColor Red
    Write-Host "  -----------------" -ForegroundColor Gray
    foreach ($error in $errors) {
        Write-StatusMessage $error -Type Error
    }
    Write-Host ""
    Write-StatusMessage "Cannot proceed with profile reset. Please resolve the above issues." -Type Error
    exit 1
}

# Show planned actions
Write-Host ""
Write-Host "  Planned Actions" -ForegroundColor DarkYellow
Write-Host "  ---------------" -ForegroundColor Gray
Write-StatusMessage "Rename folder: $($profileInfo.ProfilePath)" -Type Info
Write-StatusMessage "        to: $(Split-Path $profileInfo.ProfilePath -Parent)\$newFolderName" -Type Info
if ($profileInfo.RegistryExists) {
    Write-StatusMessage "Remove registry entry: $($profileInfo.RegistryPath)" -Type Info
}
Write-Host ""

# WhatIf handling
if ($WhatIfPreference) {
    Write-StatusMessage "WhatIf: No changes made" -Type Warning
    exit 0
}

# Confirmation prompt
if (-not $Force) {
    Write-Host ""
    Write-Host "  WARNING: This will reset the user profile for '$Username'" -ForegroundColor Yellow
    Write-Host "  The old profile folder will be preserved as: $newFolderName" -ForegroundColor Yellow
    Write-Host ""
    
    $confirmation = Read-Host "  Type 'RESET' to confirm, or press Enter to cancel"
    
    if ($confirmation -ne 'RESET') {
        Write-Host ""
        Write-StatusMessage "Operation cancelled by user" -Type Warning
        exit 0
    }
}

# Execute profile reset
Write-Host ""
Write-Host "  Executing Profile Reset" -ForegroundColor DarkYellow
Write-Host "  -----------------------" -ForegroundColor Gray

$success = $true

# Step 1: Rename profile folder
Write-StatusMessage "Renaming profile folder..." -Type Info
$newPath = Rename-ProfileFolder -SourcePath $profileInfo.ProfilePath -NewName $newFolderName

if ($newPath) {
    Write-StatusMessage "Folder renamed to: $newPath" -Type Success
}
else {
    Write-StatusMessage "Failed to rename profile folder" -Type Error
    $success = $false
}

# Step 2: Remove registry entry (only if folder rename succeeded)
if ($success -and $profileInfo.RegistryExists) {
    Write-StatusMessage "Removing profile registry entry..." -Type Info
    
    if ($PSCmdlet.ShouldProcess($profileInfo.RegistryPath, "Remove registry key")) {
        $regRemoved = Remove-ProfileRegistry -SID $profileInfo.SID -ComputerName $ComputerName
        
        if ($regRemoved) {
            Write-StatusMessage "Registry entry removed successfully" -Type Success
        }
        else {
            Write-StatusMessage "Failed to remove registry entry - manual cleanup may be required" -Type Warning
        }
    }
}

# Summary
Write-Host ""
Write-Host "  Summary" -ForegroundColor DarkYellow
Write-Host "  -------" -ForegroundColor Gray

if ($success) {
    Write-StatusMessage "Profile reset completed successfully!" -Type Success
    Write-Host ""
    Write-Host "  Next Steps:" -ForegroundColor Gray
    Write-Host "  1. Have the user log in to generate a fresh profile" -ForegroundColor White
    Write-Host "  2. Copy needed data from the .old folder:" -ForegroundColor White
    Write-Host "     - Desktop, Documents, Downloads, Pictures, Videos" -ForegroundColor Gray
    Write-Host "     - Favorites, Links" -ForegroundColor Gray
    Write-Host "     - AppData (for application-specific settings)" -ForegroundColor Gray
    Write-Host "  3. Verify applications work correctly" -ForegroundColor White
    Write-Host "  4. Once confirmed working, the .old folder can be archived or deleted" -ForegroundColor White
    Write-Host ""
    Write-Host "  Old profile location: $newPath" -ForegroundColor Cyan
}
else {
    Write-StatusMessage "Profile reset encountered errors - review output above" -Type Error
    
    # Attempt rollback if folder was renamed but registry failed
    if ($newPath -and -not $regRemoved) {
        Write-Host ""
        Write-StatusMessage "The profile folder was renamed but registry removal failed." -Type Warning
        Write-StatusMessage "You may need to manually remove the registry entry at:" -Type Warning
        Write-Host "  $($profileInfo.RegistryPath)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=" * 81 -ForegroundColor Gray
#endregion
