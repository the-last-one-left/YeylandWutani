<#
.SYNOPSIS
    Repairs and resets NTFS permissions on redirected folder shares.

.DESCRIPTION
    Configures NTFS permissions on redirected folders according to Microsoft best practices.
    
    This script automatically:
    - Discovers redirected folder locations from GPO settings or manual specification
    - Identifies users from folder names with intelligent AD lookup
    - Sets proper Microsoft-recommended permissions on root and user folders
    - Optionally adds administrative security groups with appropriate access
    - Backs up existing permissions before making changes
    - Processes folders in parallel for performance
    - Provides comprehensive logging and validation
    
    MICROSOFT RECOMMENDED PERMISSIONS:
    
    Root Folder:
    - CREATOR OWNER: Full Control (subfolders and files only)
    - SYSTEM: Full Control (this folder, subfolders, files)
    - Domain Admins: Full Control (optional)
    - Authenticated Users: List/Read, Create folders (this folder only)
    
    User Folders:
    - User (Owner): Full Control (this folder, subfolders, files)
    - SYSTEM: Full Control (this folder, subfolders, files)
    - Admin Group: Full Control (optional)

.PARAMETER RootPath
    UNC path to the root redirected folders share (e.g., \\server\redirectedfolders).
    If not specified, attempts to auto-detect from GPO settings.

.PARAMETER DomainName
    Domain name for user/group lookups (FQDN or NetBIOS). Default: Current domain.

.PARAMETER AdminGroup
    Security group to grant administrative access. Default: Domain Admins

.PARAMETER AdditionalAdminGroups
    Additional security groups to grant full control access (e.g., IT Support, Help Desk).

.PARAMETER GrantAdminAccess
    Grant admin groups access to user folders. Default: $false (Microsoft best practice)

.PARAMETER BackupPermissions
    Create backup of current permissions before making changes. Default: $true

.PARAMETER ProcessInParallel
    Process user folders in parallel for better performance. Default: $true

.PARAMETER ThrottleLimit
    Maximum parallel threads when ProcessInParallel is enabled. Default: 10

.PARAMETER ExcludeFolders
    Array of folder names to exclude from processing.

.PARAMETER TestMode
    Run in test mode (validate only, don't make changes).

.PARAMETER ExportPath
    Path to export permissions backup and reports.

.EXAMPLE
    .\Set-RedirectedFolderPermissions.ps1
    Auto-detect redirected folders and apply default permissions.

.EXAMPLE
    .\Set-RedirectedFolderPermissions.ps1 -RootPath "\\server\users" -GrantAdminAccess
    Process specific path and grant admin access to all folders.

.EXAMPLE
    .\Set-RedirectedFolderPermissions.ps1 -AdditionalAdminGroups @("Help Desk","IT Support") -BackupPermissions
    Add multiple admin groups and create permission backup.

.EXAMPLE
    .\Set-RedirectedFolderPermissions.ps1 -TestMode -ExportPath "C:\Reports"
    Test mode - validate settings and export report without making changes.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: Run as Administrator, ActiveDirectory module
    Version: 3.0
    
    Compatible with: Windows Server 2016, 2019, 2022, 2025
    
    IMPORTANT: Always test in a non-production environment first.
    Use -TestMode to validate before applying changes.
    
    References:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/create-security-enhanced-redirected-folder
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { $true }
        else { throw "Path does not exist or is not accessible: $_" }
    })]
    [string]$RootPath,
    
    [Parameter(Mandatory=$false)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$false)]
    [string]$AdminGroup = "Domain Admins",
    
    [Parameter(Mandatory=$false)]
    [string[]]$AdditionalAdminGroups = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$GrantAdminAccess,
    
    [Parameter(Mandatory=$false)]
    [bool]$BackupPermissions = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ProcessInParallel = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 50)]
    [int]$ThrottleLimit = 10,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeFolders = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = $env:TEMP
)

#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

$ErrorActionPreference = 'Continue'
$script:LogPath = Join-Path $ExportPath "RedirectedFolderPermissions-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:ErrorCount = 0
$script:WarningCount = 0
$script:ProcessedCount = 0

# Helper function for logging
function Write-LogMessage {
    param(
        [Parameter(Mandatory=$false)]
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
    
    # Track counts
    switch ($Level) {
        'Error'   { $script:ErrorCount++ }
        'Warning' { $script:WarningCount++ }
    }
}

# Auto-detect redirected folder path from GPO
function Get-RedirectedFolderPath {
    Write-LogMessage "Attempting to auto-detect redirected folder path..."
    
    try {
        # Try to find from GPO settings
        $gpoReport = Get-GPOReport -All -ReportType Xml -ErrorAction SilentlyContinue
        
        if ($gpoReport) {
            # Parse GPO XML for folder redirection settings
            [xml]$xmlReport = $gpoReport
            $folderRedirSettings = $xmlReport.SelectNodes("//FolderRedirection")
            
            if ($folderRedirSettings) {
                foreach ($setting in $folderRedirSettings) {
                    $path = $setting.RedirectedPath
                    if ($path -match '\\\\[^\\]+\\[^\\]+') {
                        # Extract root path (everything up to username placeholder)
                        $rootPath = $path -replace '\\%username%.*$', ''
                        Write-LogMessage "Found redirected folder path from GPO: $rootPath" -Level Success
                        return $rootPath
                    }
                }
            }
        }
        
        # Alternative: Check common locations
        $commonPaths = @(
            "\\$env:USERDNSDOMAIN\Users",
            "\\$env:USERDNSDOMAIN\RedirectedFolders",
            "\\$env:USERDNSDOMAIN\Home"
        )
        
        foreach ($path in $commonPaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                Write-LogMessage "Found potential redirected folder path: $path" -Level Success
                return $path
            }
        }
        
        Write-LogMessage "Could not auto-detect redirected folder path" -Level Warning
        return $null
        
    } catch {
        Write-LogMessage "Error during auto-detection: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

# Resolve user from folder name
function Resolve-UserFromFolder {
    param([string]$FolderName)
    
    try {
        # Try exact match first
        $user = Get-ADUser -Identity $FolderName -ErrorAction SilentlyContinue
        if ($user) {
            return $user
        }
        
        # Try samAccountName match
        $user = Get-ADUser -Filter "SamAccountName -eq '$FolderName'" -ErrorAction SilentlyContinue
        if ($user) {
            return $user
        }
        
        # Try DisplayName match
        $user = Get-ADUser -Filter "DisplayName -eq '$FolderName'" -ErrorAction SilentlyContinue
        if ($user) {
            return $user
        }
        
        # Try wildcard samAccountName (for domain\username folders)
        if ($FolderName -match '\\') {
            $username = ($FolderName -split '\\')[-1]
            $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
            if ($user) {
                return $user
            }
        }
        
        Write-LogMessage "  Could not resolve user for folder: $FolderName" -Level Warning
        return $null
        
    } catch {
        Write-LogMessage "  Error resolving user for $FolderName: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

# Backup current permissions
function Backup-FolderPermissions {
    param([string]$Path)
    
    if (-not $BackupPermissions) {
        return $null
    }
    
    Write-LogMessage "Creating permissions backup..."
    
    try {
        $backupFile = Join-Path $ExportPath "PermissionsBackup-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $permissions = @()
        
        # Get all folders
        $folders = Get-ChildItem -Path $Path -Directory -Force -ErrorAction SilentlyContinue
        
        foreach ($folder in $folders) {
            try {
                $acl = Get-Acl -Path $folder.FullName -ErrorAction Stop
                
                foreach ($access in $acl.Access) {
                    $permissions += [PSCustomObject]@{
                        Path = $folder.FullName
                        Owner = $acl.Owner
                        IdentityReference = $access.IdentityReference
                        FileSystemRights = $access.FileSystemRights
                        AccessControlType = $access.AccessControlType
                        IsInherited = $access.IsInherited
                        InheritanceFlags = $access.InheritanceFlags
                        PropagationFlags = $access.PropagationFlags
                    }
                }
            } catch {
                Write-LogMessage "  Could not backup permissions for: $($folder.FullName)" -Level Warning
            }
        }
        
        $permissions | Export-Csv -Path $backupFile -NoTypeInformation -Force
        Write-LogMessage "Permissions backup saved to: $backupFile" -Level Success
        return $backupFile
        
    } catch {
        Write-LogMessage "Error creating backup: $($_.Exception.Message)" -Level Error
        return $null
    }
}

# Configure root folder permissions
function Set-RootFolderPermissions {
    param(
        [string]$Path,
        [System.Security.Principal.NTAccount[]]$AdminGroups,
        [string]$Domain
    )
    
    Write-LogMessage "Configuring root folder permissions..."
    
    try {
        # Take ownership
        Write-LogMessage "  Taking ownership of root folder..."
        takeown /F "$Path" /A /D Y 2>&1 | Out-Null
        
        # Get ACL
        $acl = Get-Acl -Path $Path
        
        # Set admin group as owner
        $acl.SetOwner($AdminGroups[0])
        Set-Acl -Path $Path -AclObject $acl
        Write-LogMessage "  Owner set to: $($AdminGroups[0].Value)" -Level Success
        
        # Disable inheritance and remove all existing permissions
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        Set-Acl -Path $Path -AclObject $acl
        Write-LogMessage "  Inheritance disabled, existing permissions removed"
        
        # Add admin groups - Full Control
        foreach ($adminGroup in $AdminGroups) {
            $acl = Get-Acl -Path $Path
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminGroup,
                'FullControl',
                'ContainerInherit,ObjectInherit',
                'None',
                'Allow'
            )
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path $Path -AclObject $acl
            Write-LogMessage "  Added: $($adminGroup.Value) - Full Control" -Level Success
        }
        
        # Add SYSTEM - Full Control
        $acl = Get-Acl -Path $Path
        $systemAccount = New-Object System.Security.Principal.NTAccount('SYSTEM')
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemAccount,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $Path -AclObject $acl
        Write-LogMessage "  Added: SYSTEM - Full Control" -Level Success
        
        # Add CREATOR OWNER - Full Control (subfolders and files only)
        $acl = Get-Acl -Path $Path
        $creatorOwner = New-Object System.Security.Principal.NTAccount('CREATOR OWNER')
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $creatorOwner,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'InheritOnly',
            'Allow'
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $Path -AclObject $acl
        Write-LogMessage "  Added: CREATOR OWNER - Full Control (inherit only)" -Level Success
        
        # Add Authenticated Users - List/Create (this folder only)
        $acl = Get-Acl -Path $Path
        $authUsers = New-Object System.Security.Principal.NTAccount('Authenticated Users')
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $authUsers,
            'ListDirectory,CreateDirectories',
            'None',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $Path -AclObject $acl
        Write-LogMessage "  Added: Authenticated Users - List/Create (this folder only)" -Level Success
        
        return $true
        
    } catch {
        Write-LogMessage "Error configuring root folder: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Configure individual user folder permissions
function Set-UserFolderPermissions {
    param(
        [string]$FolderPath,
        [string]$Username,
        [System.Security.Principal.NTAccount[]]$AdminGroups,
        [bool]$GrantAdmin,
        [string]$Domain
    )
    
    try {
        Write-LogMessage "  Processing: $FolderPath"
        
        # Resolve user from folder name
        $adUser = Resolve-UserFromFolder -FolderName $Username
        
        if (-not $adUser) {
            Write-LogMessage "    Could not resolve AD user - skipping" -Level Warning
            return $false
        }
        
        $userAccount = New-Object System.Security.Principal.NTAccount("$Domain\$($adUser.SamAccountName)")
        Write-LogMessage "    Resolved user: $($adUser.SamAccountName)"
        
        # Take ownership
        takeown /F "$FolderPath" /R /A /D Y 2>&1 | Out-Null
        
        # Get ACL and disable inheritance
        $acl = Get-Acl -Path $FolderPath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        Set-Acl -Path $FolderPath -AclObject $acl
        
        # Add admin groups (temporarily or permanently)
        if ($GrantAdmin -or $true) {  # Always add temporarily for setup
            foreach ($adminGroup in $AdminGroups) {
                $acl = Get-Acl -Path $FolderPath
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $adminGroup,
                    'FullControl',
                    'ContainerInherit,ObjectInherit',
                    'None',
                    'Allow'
                )
                $acl.AddAccessRule($accessRule)
                Set-Acl -Path $FolderPath -AclObject $acl
            }
        }
        
        # Add SYSTEM - Full Control
        $acl = Get-Acl -Path $FolderPath
        $systemAccount = New-Object System.Security.Principal.NTAccount('SYSTEM')
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemAccount,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $FolderPath -AclObject $acl
        
        # Set user as owner
        $acl = Get-Acl -Path $FolderPath
        $acl.SetOwner($userAccount)
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-LogMessage "    Owner set to: $($userAccount.Value)"
        
        # Add user - Full Control
        $acl = Get-Acl -Path $FolderPath
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $userAccount,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-LogMessage "    User granted: Full Control"
        
        # Set ownership on all subfolders and files
        Get-ChildItem -Path $FolderPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $itemAcl = Get-Acl -Path $_.FullName
                $itemAcl.SetOwner($userAccount)
                Set-Acl -Path $_.FullName -AclObject $itemAcl
            } catch {
                # Silent continue for locked files
            }
        }
        
        # Enable inheritance on subfolders and files
        Get-ChildItem -Path $FolderPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $itemAcl = Get-Acl -Path $_.FullName
                $itemAcl.SetAccessRuleProtection($false, $true)
                Set-Acl -Path $_.FullName -AclObject $itemAcl
            } catch {
                # Silent continue for locked files
            }
        }
        
        # Remove admin access if not wanted permanently
        if (-not $GrantAdmin) {
            foreach ($adminGroup in $AdminGroups) {
                $acl = Get-Acl -Path $FolderPath
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $adminGroup,
                    'FullControl',
                    'ContainerInherit,ObjectInherit',
                    'None',
                    'Allow'
                )
                $acl.RemoveAccessRule($accessRule) | Out-Null
                Set-Acl -Path $FolderPath -AclObject $acl
            }
        }
        
        Write-LogMessage "    Completed successfully" -Level Success
        $script:ProcessedCount++
        return $true
        
    } catch {
        Write-LogMessage "    Error: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Main script execution
try {
    Write-Host "`n=== Redirected Folder Permissions Reset ===" -ForegroundColor DarkYellow
    Write-Host "Yeyland Wutani - Building Better Systems" -ForegroundColor Gray
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
    Write-LogMessage "Log file: $script:LogPath"
    
    if ($TestMode) {
        Write-Host "[TEST MODE] No changes will be made" -ForegroundColor Yellow
        Write-LogMessage "Running in TEST MODE - validation only"
    }
    
    Write-LogMessage ""
    
    # Get domain name
    if (-not $DomainName) {
        try {
            $DomainName = (Get-ADDomain).NetBIOSName
            Write-LogMessage "Using domain: $DomainName"
        } catch {
            throw "Could not determine domain name. Specify with -DomainName parameter."
        }
    }
    
    # Get root path
    if (-not $RootPath) {
        Write-Host "=== Auto-Detecting Redirected Folder Path ===" -ForegroundColor DarkYellow
        $RootPath = Get-RedirectedFolderPath
        
        if (-not $RootPath) {
            throw "Could not auto-detect redirected folder path. Specify with -RootPath parameter."
        }
    }
    
    Write-LogMessage ""
    Write-LogMessage "Root Path: $RootPath"
    
    # Validate path accessibility
    if (-not (Test-Path $RootPath)) {
        throw "Cannot access root path: $RootPath"
    }
    
    # Build admin groups array
    $adminGroupAccounts = @()
    
    try {
        $adminGroupAccounts += New-Object System.Security.Principal.NTAccount("$DomainName\$AdminGroup")
        Write-LogMessage "Primary admin group: $AdminGroup"
    } catch {
        throw "Could not resolve admin group: $AdminGroup"
    }
    
    if ($AdditionalAdminGroups.Count -gt 0) {
        Write-LogMessage "Additional admin groups:"
        foreach ($group in $AdditionalAdminGroups) {
            try {
                $adminGroupAccounts += New-Object System.Security.Principal.NTAccount("$DomainName\$group")
                Write-LogMessage "  - $group"
            } catch {
                Write-LogMessage "  - $group (could not resolve)" -Level Warning
            }
        }
    }
    
    Write-LogMessage ""
    Write-LogMessage "Grant admin access to user folders: $GrantAdminAccess"
    Write-LogMessage "Process in parallel: $ProcessInParallel"
    if ($ProcessInParallel) {
        Write-LogMessage "Throttle limit: $ThrottleLimit"
    }
    
    # Get user folders
    Write-LogMessage ""
    Write-Host "=== Scanning User Folders ===" -ForegroundColor DarkYellow
    
    $userFolders = Get-ChildItem -Path $RootPath -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $ExcludeFolders -notcontains $_.Name }
    
    Write-LogMessage "Found $($userFolders.Count) user folder(s)"
    
    if ($userFolders.Count -eq 0) {
        Write-LogMessage "No user folders found to process" -Level Warning
        exit 0
    }
    
    # Backup existing permissions
    if ($BackupPermissions -and -not $TestMode) {
        Write-LogMessage ""
        Write-Host "=== Backing Up Permissions ===" -ForegroundColor DarkYellow
        $backupFile = Backup-FolderPermissions -Path $RootPath
    }
    
    # Display summary and confirm
    Write-LogMessage ""
    Write-Host "=== Summary ===" -ForegroundColor DarkYellow
    Write-LogMessage "Root Path: $RootPath"
    Write-LogMessage "User Folders: $($userFolders.Count)"
    Write-LogMessage "Admin Groups: $($adminGroupAccounts.Count)"
    Write-LogMessage "Grant Admin Access: $GrantAdminAccess"
    Write-LogMessage ""
    
    if (-not $TestMode) {
        Write-Host "WARNING: This will modify permissions on $($userFolders.Count) folders" -ForegroundColor Yellow
        $confirmation = Read-Host "Type 'PROCEED' to continue or anything else to cancel"
        
        if ($confirmation -ne 'PROCEED') {
            Write-LogMessage "Operation cancelled by user" -Level Warning
            exit 0
        }
    }
    
    Write-LogMessage ""
    Write-Host "=== Processing ===" -ForegroundColor DarkYellow
    
    # Configure root folder
    if (-not $TestMode) {
        Write-Host "`nConfiguring Root Folder" -ForegroundColor DarkYellow
        $rootSuccess = Set-RootFolderPermissions -Path $RootPath -AdminGroups $adminGroupAccounts -Domain $DomainName
        
        if (-not $rootSuccess) {
            throw "Failed to configure root folder permissions"
        }
    } else {
        Write-LogMessage "TEST MODE: Would configure root folder permissions"
    }
    
    # Process user folders
    Write-LogMessage ""
    Write-Host "Processing User Folders" -ForegroundColor DarkYellow
    
    if ($TestMode) {
        foreach ($folder in $userFolders) {
            Write-LogMessage "TEST MODE: Would process $($folder.Name)"
            $adUser = Resolve-UserFromFolder -FolderName $folder.Name
            if ($adUser) {
                Write-LogMessage "  Resolved to: $($adUser.SamAccountName)"
            }
        }
    } elseif ($ProcessInParallel) {
        # Parallel processing
        $userFolders | ForEach-Object -Parallel {
            $folder = $_
            $adminGroups = $using:adminGroupAccounts
            $grantAdmin = $using:GrantAdminAccess
            $domain = $using:DomainName
            
            # Import functions (they're not available in parallel scope)
            ${function:Resolve-UserFromFolder} = $using:funcResolveUser
            ${function:Set-UserFolderPermissions} = $using:funcSetUserPerms
            ${function:Write-LogMessage} = $using:funcWriteLog
            
            Set-UserFolderPermissions -FolderPath $folder.FullName -Username $folder.Name `
                -AdminGroups $adminGroups -GrantAdmin $grantAdmin -Domain $domain
                
        } -ThrottleLimit $ThrottleLimit
    } else {
        # Sequential processing
        foreach ($folder in $userFolders) {
            Set-UserFolderPermissions -FolderPath $folder.FullName -Username $folder.Name `
                -AdminGroups $adminGroupAccounts -GrantAdmin $GrantAdminAccess -Domain $DomainName
        }
    }
    
    # Summary
    Write-LogMessage ""
    Write-Host "=== COMPLETED ===" -ForegroundColor Green
    Write-LogMessage "Total folders processed: $script:ProcessedCount"
    Write-LogMessage "Warnings: $script:WarningCount"
    Write-LogMessage "Errors: $script:ErrorCount"
    
    if ($backupFile) {
        Write-LogMessage ""
        Write-LogMessage "Permissions backup: $backupFile"
    }
    
    Write-LogMessage ""
    Write-LogMessage "Log file: $script:LogPath"
    Write-Host "`nYeyland Wutani - Building Better Systems" -ForegroundColor Gray
    Write-LogMessage ""
    
} catch {
    Write-LogMessage ""
    Write-Host "=== OPERATION FAILED ===" -ForegroundColor Red
    Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
    Write-LogMessage ""
    Write-LogMessage "Check log file for details: $script:LogPath"
    exit 1
}
