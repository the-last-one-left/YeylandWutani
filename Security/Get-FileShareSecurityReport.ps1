<#
.SYNOPSIS
    Comprehensive Windows File Share Security Report Tool v1.1
    
.DESCRIPTION
    MSP-friendly reporting tool for auditing Windows file shares and directories.
    Generates detailed reports on NTFS permissions, share permissions, inheritance,
    and potential security concerns.
    
    Generates detailed reports including:
    - NTFS permission analysis for all scanned paths
    - Share permission analysis (for UNC paths or local shares)
    - Permission inheritance tracking (broken inheritance detection)
    - Orphaned SID detection (deleted accounts still in ACLs)
    - High-risk permission detection (Everyone, Authenticated Users, etc.)
    - Folder size distribution with visual charts
    - Owner analysis
    - Permission complexity scoring
    - Visual charts for storage and permission distribution
    - Exports to CSV files and branded HTML report
    
.PARAMETER Path
    The root path(s) to scan. Can be local paths (C:\Shares\Data) or UNC paths (\\Server\Share).
    Accepts multiple paths as an array.
    
.PARAMETER OutputPath
    Directory path for output files. Defaults to current directory
    
.PARAMETER MaxDepth
    Maximum folder depth to scan for permissions and sizes.
    Range: 1-15. Default: 5
    - Lower values (1-3): Faster, less thorough
    - Higher values (6-10): Slower, more comprehensive

.PARAMETER IncludeInherited
    Switch to include inherited permissions in the report. By default, only explicit (non-inherited)
    permissions are flagged for review since inherited permissions follow normal policy.
    
.PARAMETER SkipSizeCalculation
    Switch to skip folder size calculations. Significantly speeds up scans on large shares.
    
.PARAMETER ExcludePaths
    Array of path patterns to exclude from scanning. Supports wildcards.
    Default excludes: $RECYCLE.BIN, System Volume Information, DfsrPrivate
    
.PARAMETER Credential
    PSCredential object for accessing remote shares. If not provided, uses current user context.

.EXAMPLE
    .\Get-FileShareSecurityReport.ps1 -Path "D:\Shares"
    Basic report of a local share folder
    
.EXAMPLE
    .\Get-FileShareSecurityReport.ps1 -Path "\\FileServer\Data" -MaxDepth 8 -OutputPath "C:\Reports"
    Deep scan of a remote share with output to specific folder

.EXAMPLE
    .\Get-FileShareSecurityReport.ps1 -Path @("D:\Finance", "D:\HR") -IncludeInherited
    Scan multiple paths including inherited permissions

.NOTES
    Author: Yeyland Wutani LLC
    Version: 1.1
    Website: https://github.com/YeylandWutani
    
    Key Features:
    - NTFS and Share permission analysis
    - Broken inheritance detection
    - Orphaned SID identification
    - High-risk permission flagging (Everyone, Auth Users, Domain Users)
    - Folder size visualization
    - Permission complexity scoring
    
    Requirements:
    - PowerShell 5.1 or later
    - Admin rights for full access to ACLs
    - Network access for remote shares
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path(s) to scan (local or UNC)")]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false, HelpMessage = "Maximum folder depth to scan (1-15, default: 5)")]
    [ValidateRange(1, 15)]
    [int]$MaxDepth = 5,
    
    [Parameter(Mandatory = $false, HelpMessage = "Include inherited permissions in report")]
    [switch]$IncludeInherited,
    
    [Parameter(Mandatory = $false, HelpMessage = "Skip folder size calculations for faster scans")]
    [switch]$SkipSizeCalculation,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePaths = @('$RECYCLE.BIN', 'System Volume Information', 'DfsrPrivate', '.snapshot'),
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential
)

#region Script Configuration
$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

# Yeyland Wutani LLC branding
$Script:Branding = @{
    PrimaryOrange = "#FF6600"
    Grey          = "#6B7280"
    White         = "#FFFFFF"
    Black         = "#1F2937"
    LightOrange   = "#FFF3E6"
    DarkOrange    = "#CC5200"
    Tagline       = "Building Better Systems"
    CompanyName   = "Yeyland Wutani LLC"
}

# Chart colors for visualizations (orange-first palette)
$Script:ChartColors = @(
    "#FF6600", "#CC5200", "#28a745", "#ffc107", "#dc3545", 
    "#6B7280", "#20c997", "#fd7e14", "#4B5563", "#17a2b8",
    "#e83e8c", "#374151", "#7952b3", "#F97316", "#51cf66"
)

# URLs and timestamps
$Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"
$Script:ComputerName = $env:COMPUTERNAME

# High-risk security principals to flag
$Script:HighRiskPrincipals = @(
    'Everyone',
    'EVERYONE',
    'Authenticated Users',
    'NT AUTHORITY\Authenticated Users',
    'BUILTIN\Users',
    'Domain Users',
    'ANONYMOUS LOGON',
    'NT AUTHORITY\ANONYMOUS LOGON'
)

# Medium-risk principals (broader than necessary but not fully open)
$Script:MediumRiskPrincipals = @(
    'Domain Computers',
    'INTERACTIVE',
    'NETWORK'
)

# Rights that are concerning when granted to risky principals
$Script:HighRiskRights = @(
    'FullControl',
    'Modify',
    'Write',
    'Delete',
    'ChangePermissions',
    'TakeOwnership',
    'CreateFiles',
    'CreateDirectories',
    'WriteData',
    'AppendData',
    'DeleteSubdirectoriesAndFiles'
)

# Data collections
$Script:Data = @{
    ScanInfo            = $null
    FolderPermissions   = [System.Collections.Generic.List[PSObject]]::new()
    SharePermissions    = [System.Collections.Generic.List[PSObject]]::new()
    BrokenInheritance   = [System.Collections.Generic.List[PSObject]]::new()
    HighRiskPermissions = [System.Collections.Generic.List[PSObject]]::new()
    OrphanedSIDs        = [System.Collections.Generic.List[PSObject]]::new()
    FolderSizes         = [System.Collections.Generic.List[PSObject]]::new()
    Owners              = [System.Collections.Generic.List[PSObject]]::new()
    Errors              = [System.Collections.Generic.List[PSObject]]::new()
}
#endregion

#region Logging Functions
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("Info", "Warning", "Error", "Success", "Debug")][string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{ Info = "Cyan"; Warning = "Yellow"; Error = "Red"; Success = "Green"; Debug = "Gray" }
    $symbols = @{ Info = "[*]"; Warning = "[!]"; Error = "[X]"; Success = "[+]"; Debug = "[-]" }
    
    Write-Host "$timestamp " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($symbols[$Level]) " -NoNewline -ForegroundColor $colors[$Level]
    Write-Host $Message -ForegroundColor $colors[$Level]
}

function Add-Error {
    param([string]$Operation, [string]$Target, [string]$ErrorMessage)
    $Script:Data.Errors.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operation = $Operation
        Target    = $Target
        Error     = $ErrorMessage
    })
}
#endregion

#region Utility Functions
function Convert-BytesToReadable {
    param([long]$Bytes)
    if ($null -eq $Bytes -or $Bytes -eq 0) { return "0 Bytes" }
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes Bytes"
}

function Get-HtmlSafeString {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-RelativePath {
    param([string]$FullPath, [string]$BasePath)
    if ($FullPath -eq $BasePath) { return "\" }
    $relativePath = $FullPath.Substring($BasePath.Length)
    if (-not $relativePath.StartsWith('\')) { $relativePath = '\' + $relativePath }
    return $relativePath
}

function Test-IsOrphanedSID {
    param([string]$IdentityReference)
    # Orphaned SIDs appear as S-1-5-21-... without resolution to a name
    return $IdentityReference -match '^S-1-\d+-\d+(-\d+)+'
}

function Test-IsHighRiskPrincipal {
    param([string]$IdentityReference)
    foreach ($risky in $Script:HighRiskPrincipals) {
        if ($IdentityReference -like "*$risky*") { return $true }
    }
    return $false
}

function Test-IsMediumRiskPrincipal {
    param([string]$IdentityReference)
    foreach ($risky in $Script:MediumRiskPrincipals) {
        if ($IdentityReference -like "*$risky*") { return $true }
    }
    return $false
}

function Get-RiskLevel {
    param([string]$IdentityReference, [string]$Rights)
    $hasHighRiskRights = $false
    foreach ($right in $Script:HighRiskRights) {
        if ($Rights -like "*$right*") { $hasHighRiskRights = $true; break }
    }
    
    if (Test-IsHighRiskPrincipal $IdentityReference) {
        if ($hasHighRiskRights) { return "Critical" }
        return "High"
    }
    if (Test-IsMediumRiskPrincipal $IdentityReference) {
        if ($hasHighRiskRights) { return "Medium" }
        return "Low"
    }
    return "Normal"
}

function Get-PermissionComplexity {
    param([int]$AceCount, [bool]$HasBrokenInheritance, [int]$UniqueIdentityCount)
    $score = 0
    
    # Base score from ACE count
    if ($AceCount -gt 15) { $score += 3 }
    elseif ($AceCount -gt 8) { $score += 2 }
    elseif ($AceCount -gt 4) { $score += 1 }
    
    # Broken inheritance adds complexity
    if ($HasBrokenInheritance) { $score += 2 }
    
    # Many unique identities adds complexity
    if ($UniqueIdentityCount -gt 10) { $score += 2 }
    elseif ($UniqueIdentityCount -gt 5) { $score += 1 }
    
    switch ($score) {
        { $_ -ge 5 } { return "High" }
        { $_ -ge 3 } { return "Medium" }
        default { return "Low" }
    }
}

function Test-ShouldExcludePath {
    param([string]$PathToTest)
    foreach ($exclude in $ExcludePaths) {
        if ($PathToTest -like "*$exclude*") { return $true }
    }
    return $false
}

function Convert-AccessMaskToString {
    <#
    .SYNOPSIS
        Converts raw access mask values to readable permission strings
    #>
    param([System.Security.AccessControl.FileSystemRights]$Rights)
    
    $rightsString = $Rights.ToString()
    
    # If it's already readable (contains letters), return as-is
    if ($rightsString -match '[a-zA-Z]') {
        return $rightsString
    }
    
    # Otherwise translate the numeric value
    $value = [int]$Rights
    $permissions = @()
    
    # Common permission combinations
    if (($value -band 0x1F01FF) -eq 0x1F01FF) { $permissions += "FullControl" }
    elseif (($value -band 0x1301BF) -eq 0x1301BF) { $permissions += "Modify" }
    elseif (($value -band 0x1200A9) -eq 0x1200A9) { $permissions += "ReadAndExecute" }
    elseif (($value -band 0x120089) -eq 0x120089) { $permissions += "Read" }
    elseif (($value -band 0x100116) -eq 0x100116) { $permissions += "Write" }
    
    # Check for generic rights (often appear as negative numbers)
    if ($value -lt 0) {
        # Convert to unsigned for comparison
        $unsigned = [uint32]$value
        
        # Generic rights mapping
        if (($unsigned -band 0x10000000) -ne 0) { $permissions += "GenericAll" }
        if (($unsigned -band 0x20000000) -ne 0) { $permissions += "GenericExecute" }
        if (($unsigned -band 0x40000000) -ne 0) { $permissions += "GenericWrite" }
        if (($unsigned -band 0x80000000) -ne 0) { $permissions += "GenericRead" }
    }
    
    # Check individual flags if no combination matched
    if ($permissions.Count -eq 0) {
        if (($value -band 0x1) -ne 0) { $permissions += "ReadData" }
        if (($value -band 0x2) -ne 0) { $permissions += "WriteData" }
        if (($value -band 0x4) -ne 0) { $permissions += "AppendData" }
        if (($value -band 0x8) -ne 0) { $permissions += "ReadEA" }
        if (($value -band 0x10) -ne 0) { $permissions += "WriteEA" }
        if (($value -band 0x20) -ne 0) { $permissions += "Execute" }
        if (($value -band 0x40) -ne 0) { $permissions += "DeleteChild" }
        if (($value -band 0x80) -ne 0) { $permissions += "ReadAttributes" }
        if (($value -band 0x100) -ne 0) { $permissions += "WriteAttributes" }
        if (($value -band 0x10000) -ne 0) { $permissions += "Delete" }
        if (($value -band 0x20000) -ne 0) { $permissions += "ReadPermissions" }
        if (($value -band 0x40000) -ne 0) { $permissions += "ChangePermissions" }
        if (($value -band 0x80000) -ne 0) { $permissions += "TakeOwnership" }
    }
    
    if ($permissions.Count -gt 0) {
        return $permissions -join ", "
    }
    
    # Fallback to showing the hex value if we couldn't decode it
    return "Custom (0x{0:X})" -f [uint32]$value
}

function Get-FolderDepth {
    param([string]$FolderPath, [string]$BasePath)
    $relative = Get-RelativePath -FullPath $FolderPath -BasePath $BasePath
    $depth = ($relative.Split('\') | Where-Object { $_ }).Count
    return $depth
}
#endregion

#region Share Permission Functions
function Get-SharePermissions {
    param([string]$SharePath)
    
    $results = [System.Collections.Generic.List[PSObject]]::new()
    
    # Check if this is a UNC path
    if ($SharePath -match '^\\\\([^\\]+)\\([^\\]+)') {
        $server = $Matches[1]
        $shareName = $Matches[2]
        
        Write-Log "  Checking share permissions for \\$server\$shareName..." -Level Debug
        
        try {
            # Try to get share permissions via WMI
            $share = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -ComputerName $server -Filter "Name='$shareName'" -ErrorAction Stop
            
            if ($share) {
                $secDesc = $share.GetSecurityDescriptor()
                
                if ($secDesc.ReturnValue -eq 0 -and $secDesc.Descriptor.DACL) {
                    foreach ($ace in $secDesc.Descriptor.DACL) {
                        $trustee = $ace.Trustee.Name
                        if (-not $trustee) { $trustee = $ace.Trustee.SIDString }
                        
                        $accessMask = $ace.AccessMask
                        $accessType = if ($ace.AceType -eq 0) { "Allow" } else { "Deny" }
                        
                        # Translate access mask to readable rights
                        $rights = @()
                        if ($accessMask -band 0x1F01FF) { $rights += "FullControl" }
                        elseif ($accessMask -band 0x1301BF) { $rights += "Change" }
                        elseif ($accessMask -band 0x1200A9) { $rights += "Read" }
                        else { $rights += "Custom ($accessMask)" }
                        
                        $results.Add([PSCustomObject]@{
                            SharePath     = $SharePath
                            Server        = $server
                            ShareName     = $shareName
                            Identity      = $trustee
                            AccessType    = $accessType
                            Rights        = $rights -join ", "
                            RiskLevel     = Get-RiskLevel -IdentityReference $trustee -Rights ($rights -join ", ")
                        })
                    }
                }
            }
        } catch {
            Write-Log "  Could not retrieve share permissions: $($_.Exception.Message)" -Level Debug
            Add-Error -Operation "Get-SharePermissions" -Target $SharePath -ErrorMessage $_.Exception.Message
        }
    }
    
    # Also check if this is a local path that's shared
    if ($SharePath -match '^([A-Za-z]):\\(.*)') {
        $driveLetter = $Matches[1]
        $localPath = $SharePath
        
        try {
            $shares = Get-WmiObject -Class Win32_Share -Filter "Type=0" -ErrorAction Stop
            foreach ($share in $shares) {
                if ($localPath -like "$($share.Path)*") {
                    Write-Log "  Found local share: $($share.Name) at $($share.Path)" -Level Debug
                    
                    $shareSec = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$($share.Name)'" -ErrorAction SilentlyContinue
                    if ($shareSec) {
                        $secDesc = $shareSec.GetSecurityDescriptor()
                        if ($secDesc.ReturnValue -eq 0 -and $secDesc.Descriptor.DACL) {
                            foreach ($ace in $secDesc.Descriptor.DACL) {
                                $trustee = $ace.Trustee.Name
                                if (-not $trustee) { $trustee = $ace.Trustee.SIDString }
                                
                                $accessMask = $ace.AccessMask
                                $accessType = if ($ace.AceType -eq 0) { "Allow" } else { "Deny" }
                                
                                $rights = @()
                                if ($accessMask -band 0x1F01FF) { $rights += "FullControl" }
                                elseif ($accessMask -band 0x1301BF) { $rights += "Change" }
                                elseif ($accessMask -band 0x1200A9) { $rights += "Read" }
                                else { $rights += "Custom ($accessMask)" }
                                
                                $results.Add([PSCustomObject]@{
                                    SharePath     = $share.Path
                                    Server        = $env:COMPUTERNAME
                                    ShareName     = $share.Name
                                    Identity      = $trustee
                                    AccessType    = $accessType
                                    Rights        = $rights -join ", "
                                    RiskLevel     = Get-RiskLevel -IdentityReference $trustee -Rights ($rights -join ", ")
                                })
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log "  Could not check local shares: $($_.Exception.Message)" -Level Debug
        }
    }
    
    return $results
}
#endregion

#region NTFS Permission Functions
function Get-FolderACL {
    param(
        [string]$FolderPath,
        [string]$BasePath,
        [int]$Depth
    )
    
    try {
        $acl = Get-Acl -Path $FolderPath -ErrorAction Stop
        $relativePath = Get-RelativePath -FullPath $FolderPath -BasePath $BasePath
        
        # Check inheritance status
        $inheritanceEnabled = -not $acl.AreAccessRulesProtected
        
        # Get owner
        $owner = $acl.Owner
        $isOrphanedOwner = Test-IsOrphanedSID $owner
        
        # Process each ACE
        $aceList = [System.Collections.Generic.List[PSObject]]::new()
        $identities = @{}
        $hasHighRisk = $false
        $hasOrphaned = $false
        
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value
            $rights = Convert-AccessMaskToString -Rights $ace.FileSystemRights
            $isInherited = $ace.IsInherited
            $accessType = $ace.AccessControlType.ToString()
            
            # Skip inherited unless specifically requested
            if ($isInherited -and -not $IncludeInherited) { continue }
            
            # Track unique identities
            $identities[$identity] = $true
            
            # Check for orphaned SIDs
            $isOrphanedSID = Test-IsOrphanedSID $identity
            if ($isOrphanedSID) { $hasOrphaned = $true }
            
            # Determine risk level
            $riskLevel = Get-RiskLevel -IdentityReference $identity -Rights $rights
            if ($riskLevel -in @("Critical", "High")) { $hasHighRisk = $true }
            
            $aceRecord = [PSCustomObject]@{
                FolderPath       = $FolderPath
                RelativePath     = $relativePath
                Depth            = $Depth
                Identity         = $identity
                Rights           = $rights
                AccessType       = $accessType
                IsInherited      = $isInherited
                IsOrphanedSID    = $isOrphanedSID
                RiskLevel        = $riskLevel
                InheritanceFlags = $ace.InheritanceFlags.ToString()
                PropagationFlags = $ace.PropagationFlags.ToString()
            }
            
            $aceList.Add($aceRecord)
            
            # Add to high-risk collection if applicable
            if ($riskLevel -in @("Critical", "High", "Medium")) {
                $Script:Data.HighRiskPermissions.Add([PSCustomObject]@{
                    FolderPath   = $FolderPath
                    RelativePath = $relativePath
                    Depth        = $Depth
                    Identity     = $identity
                    Rights       = $rights
                    AccessType   = $accessType
                    RiskLevel    = $riskLevel
                    IsInherited  = $isInherited
                })
            }
            
            # Add to orphaned collection if applicable
            if ($isOrphanedSID) {
                $Script:Data.OrphanedSIDs.Add([PSCustomObject]@{
                    FolderPath   = $FolderPath
                    RelativePath = $relativePath
                    Depth        = $Depth
                    SID          = $identity
                    Rights       = $rights
                    AccessType   = $accessType
                    IsInherited  = $isInherited
                })
            }
        }
        
        # Calculate complexity
        $complexity = Get-PermissionComplexity -AceCount $aceList.Count -HasBrokenInheritance (-not $inheritanceEnabled) -UniqueIdentityCount $identities.Count
        
        # Add folder summary to collection
        foreach ($ace in $aceList) {
            $Script:Data.FolderPermissions.Add($ace)
        }
        
        # Track broken inheritance
        if (-not $inheritanceEnabled) {
            $Script:Data.BrokenInheritance.Add([PSCustomObject]@{
                FolderPath        = $FolderPath
                RelativePath      = $relativePath
                Depth             = $Depth
                Owner             = $owner
                IsOrphanedOwner   = $isOrphanedOwner
                AceCount          = $aceList.Count
                UniqueIdentities  = $identities.Count
                HasHighRisk       = $hasHighRisk
                HasOrphanedSIDs   = $hasOrphaned
                Complexity        = $complexity
            })
        }
        
        # Track owner
        $Script:Data.Owners.Add([PSCustomObject]@{
            FolderPath        = $FolderPath
            RelativePath      = $relativePath
            Depth             = $Depth
            Owner             = $owner
            IsOrphanedOwner   = $isOrphanedOwner
            InheritanceEnabled = $inheritanceEnabled
        })
        
    } catch {
        Add-Error -Operation "Get-FolderACL" -Target $FolderPath -ErrorMessage $_.Exception.Message
    }
}

function Get-FolderSize {
    param(
        [string]$FolderPath,
        [string]$BasePath,
        [int]$Depth
    )
    
    try {
        $items = Get-ChildItem -Path $FolderPath -Force -ErrorAction SilentlyContinue
        $fileCount = ($items | Where-Object { -not $_.PSIsContainer }).Count
        $folderCount = ($items | Where-Object { $_.PSIsContainer }).Count
        
        # Calculate total size (files in this folder only, not recursive for speed)
        $directSize = ($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $directSize) { $directSize = 0 }
        
        $relativePath = Get-RelativePath -FullPath $FolderPath -BasePath $BasePath
        
        $Script:Data.FolderSizes.Add([PSCustomObject]@{
            FolderPath     = $FolderPath
            RelativePath   = $relativePath
            Depth          = $Depth
            DirectSizeBytes = $directSize
            DirectSize     = Convert-BytesToReadable $directSize
            FileCount      = $fileCount
            SubfolderCount = $folderCount
        })
    } catch {
        Add-Error -Operation "Get-FolderSize" -Target $FolderPath -ErrorMessage $_.Exception.Message
    }
}
#endregion

#region Scan Functions
function Start-FolderScan {
    param(
        [string]$RootPath,
        [int]$CurrentDepth = 0
    )
    
    if ($CurrentDepth -gt $MaxDepth) { return }
    if (Test-ShouldExcludePath $RootPath) { return }
    
    # Process current folder
    Get-FolderACL -FolderPath $RootPath -BasePath $Script:CurrentBasePath -Depth $CurrentDepth
    
    if (-not $SkipSizeCalculation) {
        Get-FolderSize -FolderPath $RootPath -BasePath $Script:CurrentBasePath -Depth $CurrentDepth
    }
    
    # Get subfolders for recursion
    try {
        $subfolders = Get-ChildItem -Path $RootPath -Directory -Force -ErrorAction SilentlyContinue
        foreach ($subfolder in $subfolders) {
            if (Test-ShouldExcludePath $subfolder.FullName) { continue }
            Start-FolderScan -RootPath $subfolder.FullName -CurrentDepth ($CurrentDepth + 1)
        }
    } catch {
        Add-Error -Operation "Enumerate-Subfolders" -Target $RootPath -ErrorMessage $_.Exception.Message
    }
}

function Get-ScanSummary {
    param([string]$ScanPath)
    
    try {
        $pathItem = Get-Item -Path $ScanPath -ErrorAction Stop
        
        return [PSCustomObject]@{
            Path             = $ScanPath
            Name             = $pathItem.Name
            IsUNC            = $ScanPath.StartsWith('\\')
            Exists           = $true
            LastWriteTime    = $pathItem.LastWriteTime
            CreationTime     = $pathItem.CreationTime
        }
    } catch {
        return [PSCustomObject]@{
            Path             = $ScanPath
            Name             = Split-Path $ScanPath -Leaf
            IsUNC            = $ScanPath.StartsWith('\\')
            Exists           = $false
            LastWriteTime    = $null
            CreationTime     = $null
        }
    }
}
#endregion

#region Export Functions
function Export-ToCsv {
    Write-Log "Exporting data to CSV files..." -Level Info
    $csvFiles = @()
    
    if ($Script:Data.FolderPermissions.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_Permissions_$Script:Timestamp.csv"
        $Script:Data.FolderPermissions | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.SharePermissions.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_SharePermissions_$Script:Timestamp.csv"
        $Script:Data.SharePermissions | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.BrokenInheritance.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_BrokenInheritance_$Script:Timestamp.csv"
        $Script:Data.BrokenInheritance | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.HighRiskPermissions.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_HighRiskPermissions_$Script:Timestamp.csv"
        $Script:Data.HighRiskPermissions | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.OrphanedSIDs.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_OrphanedSIDs_$Script:Timestamp.csv"
        $Script:Data.OrphanedSIDs | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.FolderSizes.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_FolderSizes_$Script:Timestamp.csv"
        $Script:Data.FolderSizes | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.Owners.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_Owners_$Script:Timestamp.csv"
        $Script:Data.Owners | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.Errors.Count -gt 0) {
        $path = Join-Path $OutputPath "FS_Errors_$Script:Timestamp.csv"
        $Script:Data.Errors | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Warning
    }
    
    return $csvFiles
}

function Export-ToHtml {
    Write-Log "Generating HTML report..." -Level Info
    
    # Calculate summary statistics
    $totalFolders = $Script:Data.Owners.Count
    $brokenInheritanceCount = $Script:Data.BrokenInheritance.Count
    $highRiskCount = $Script:Data.HighRiskPermissions.Count
    $criticalCount = ($Script:Data.HighRiskPermissions | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $orphanedCount = $Script:Data.OrphanedSIDs.Count
    $sharePermCount = $Script:Data.SharePermissions.Count
    
    # Storage summary - sum all folder sizes for total
    $totalSizeBytes = ($Script:Data.FolderSizes | Measure-Object -Property DirectSizeBytes -Sum).Sum
    if ($null -eq $totalSizeBytes) { $totalSizeBytes = 0 }
    
    $htmlPath = Join-Path $OutputPath "FS_SecurityReport_$Script:Timestamp.html"
    
    $pathsScanned = ($Script:ScanInfo | ForEach-Object { $_.Path }) -join ", "
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>File Share Security Report</title>
<style>
:root { --yw-orange: #FF6600; --yw-dark-orange: #CC5200; --yw-light-orange: #FFF3E6; --yw-grey: #6B7280; --yw-dark-grey: #4B5563; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
.header { background: linear-gradient(135deg, var(--yw-orange), var(--yw-dark-orange)); color: #fff; padding: 25px 40px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 26px; font-weight: 300; }
.header .tagline { font-size: 13px; opacity: 0.9; margin-top: 4px; }
.header .company { text-align: right; }
.header .company-name { font-size: 16px; font-weight: 600; }
.header .report-date { font-size: 11px; opacity: 0.8; }
.container { max-width: 1400px; margin: 0 auto; padding: 25px; }
.scan-info { background: #fff; border-radius: 8px; padding: 15px 20px; margin-bottom: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
.scan-info h3 { color: var(--yw-dark-orange); font-size: 14px; margin-bottom: 8px; }
.scan-info .paths { font-family: 'Consolas', monospace; font-size: 12px; color: #555; word-break: break-all; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 25px; }
.summary-card { background: white; border-radius: 8px; padding: 18px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); border-left: 4px solid var(--yw-orange); }
.summary-card.warning { border-left-color: #f0ad4e; }
.summary-card.danger { border-left-color: #dc3545; }
.summary-card.success { border-left-color: #28a745; }
.summary-card .value { font-size: 28px; font-weight: 600; color: var(--yw-orange); }
.summary-card.warning .value { color: #f0ad4e; }
.summary-card.danger .value { color: #dc3545; }
.summary-card.success .value { color: #28a745; }
.summary-card .label { font-size: 12px; color: #666; margin-top: 4px; }
.section { background: #fff; border-radius: 8px; margin-bottom: 25px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); overflow: hidden; }
.section-header { background: var(--yw-light-orange); padding: 14px 20px; border-bottom: 2px solid var(--yw-orange); cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none; }
.section-header:hover { background: #FFE8D4; }
.section-header h2 { font-size: 16px; color: var(--yw-dark-orange); font-weight: 600; }
.section-header .count { background: var(--yw-orange); color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px; }
.section-header .count.danger { background: #dc3545; }
.section-header .count.warning { background: #f0ad4e; }
.section-header .toggle { font-size: 11px; color: #666; margin-left: 10px; }
.section-content { padding: 0; max-height: 500px; overflow: auto; }
.section-content.collapsed { display: none; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #f8f9fa; padding: 10px 12px; text-align: left; font-weight: 600; color: var(--yw-dark-orange); border-bottom: 2px solid #dee2e6; position: sticky; top: 0; }
td { padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:hover { background: #f8f9fa; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; white-space: nowrap; }
.badge-success { background: #d4edda; color: #155724; }
.badge-warning { background: #fff3cd; color: #856404; }
.badge-danger { background: #f8d7da; color: #721c24; }
.badge-critical { background: #721c24; color: #fff; }
.badge-info { background: #d1ecf1; color: #0c5460; }
.badge-normal { background: #e9ecef; color: #495057; }
.progress-bar { width: 100%; height: 6px; background: #e9ecef; border-radius: 3px; overflow: hidden; }
.progress-bar-fill { height: 100%; background: var(--yw-orange); }
.progress-bar-fill.warning { background: #f0ad4e; }
.progress-bar-fill.danger { background: #dc3545; }
.truncate { max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle; }
.path-display { font-family: 'Consolas', monospace; font-size: 11px; }
.footer { text-align: center; padding: 20px; color: #666; font-size: 11px; }
.footer .tagline { color: var(--yw-orange); font-weight: 600; font-size: 13px; }
.depth-indicator { display: inline-block; width: 8px; height: 8px; background: var(--yw-grey); border-radius: 50%; margin-right: 4px; opacity: 0.5; }
.depth-indicator.active { opacity: 1; background: var(--yw-orange); }
a { color: var(--yw-orange); text-decoration: none; }
a:hover { text-decoration: underline; }
.chart-container { padding: 20px; }
.chart-title { font-size: 14px; font-weight: 600; color: #333; margin-bottom: 15px; }
.bar-chart { display: flex; flex-direction: column; gap: 8px; }
.bar-item { display: flex; align-items: center; gap: 10px; }
.bar-label { width: 200px; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 500; }
.bar-container { flex: 1; height: 20px; background: #e9ecef; border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; justify-content: flex-end; padding-right: 8px; }
.bar-value { font-size: 10px; color: white; font-weight: 600; text-shadow: 0 1px 2px rgba(0,0,0,0.3); }
.bar-size { width: 80px; text-align: right; font-size: 11px; color: #666; font-weight: 600; }
.expandable-block { margin-bottom: 15px; border: 1px solid #dee2e6; border-radius: 6px; overflow: hidden; }
.expandable-header { background: #f8f9fa; padding: 10px 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #dee2e6; }
.expandable-header:hover { background: #f0f0f0; }
@media print { .section-content { max-height: none !important; } }
</style>
</head>
<body>
<div class="header">
<div>
<h1>File Share Security Report</h1>
<div class="tagline">NTFS Permission Analysis</div>
</div>
<div class="company">
<div class="company-name">$($Script:Branding.CompanyName)</div>
<div class="report-date">$($Script:ReportDate)</div>
<div class="tagline">$($Script:Branding.Tagline)</div>
</div>
</div>
<div class="container">

<div class="scan-info">
<h3>Paths Scanned</h3>
<div class="paths">$(Get-HtmlSafeString $pathsScanned)</div>
</div>

<div class="summary-grid">
<div class="summary-card"><div class="value">$totalFolders</div><div class="label">Folders Scanned</div></div>
<div class="summary-card$(if ($brokenInheritanceCount -gt 0) { ' warning' })"><div class="value">$brokenInheritanceCount</div><div class="label">Broken Inheritance</div></div>
<div class="summary-card$(if ($criticalCount -gt 0) { ' danger' } elseif ($highRiskCount -gt 0) { ' warning' })"><div class="value">$highRiskCount</div><div class="label">High-Risk Permissions</div></div>
<div class="summary-card$(if ($orphanedCount -gt 0) { ' warning' })"><div class="value">$orphanedCount</div><div class="label">Orphaned SIDs</div></div>
<div class="summary-card"><div class="value">$sharePermCount</div><div class="label">Share Permissions</div></div>
<div class="summary-card"><div class="value">$(Convert-BytesToReadable $totalSizeBytes)</div><div class="label">Total Size Scanned</div></div>
</div>
"@

    # HIGH-RISK PERMISSIONS SECTION
    if ($Script:Data.HighRiskPermissions.Count -gt 0) {
        $criticalPerms = $Script:Data.HighRiskPermissions | Where-Object { $_.RiskLevel -eq "Critical" }
        $highPerms = $Script:Data.HighRiskPermissions | Where-Object { $_.RiskLevel -eq "High" }
        $mediumPerms = $Script:Data.HighRiskPermissions | Where-Object { $_.RiskLevel -eq "Medium" }
        
        $countClass = if ($criticalPerms.Count -gt 0) { "danger" } elseif ($highPerms.Count -gt 0) { "warning" } else { "" }
        
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>Security Concerns - High-Risk Permissions</h2>
<span class="count $countClass">$($Script:Data.HighRiskPermissions.Count) entries</span>
<span class="toggle">&#9660;</span>
</div>
<div class="section-content">
<table>
<tr><th>Path</th><th>Identity</th><th>Rights</th><th>Type</th><th>Risk</th><th>Inherited</th></tr>
"@
        # Sort by risk level
        $sortedRisk = $Script:Data.HighRiskPermissions | Sort-Object @{E={switch ($_.RiskLevel) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } default { 3 } }}}, RelativePath
        
        foreach ($perm in ($sortedRisk | Select-Object -First 200)) {
            $riskBadge = switch ($perm.RiskLevel) {
                "Critical" { "<span class='badge badge-critical'>CRITICAL</span>" }
                "High"     { "<span class='badge badge-danger'>HIGH</span>" }
                "Medium"   { "<span class='badge badge-warning'>MEDIUM</span>" }
                default    { "<span class='badge badge-normal'>$($perm.RiskLevel)</span>" }
            }
            $inheritBadge = if ($perm.IsInherited) { "<span class='badge badge-info'>Yes</span>" } else { "<span class='badge badge-warning'>No</span>" }
            
            $html += "<tr>"
            $html += "<td class='path-display truncate' title='$(Get-HtmlSafeString $perm.FolderPath)'>$(Get-HtmlSafeString $perm.RelativePath)</td>"
            $html += "<td>$(Get-HtmlSafeString $perm.Identity)</td>"
            $html += "<td class='truncate' title='$(Get-HtmlSafeString $perm.Rights)'>$(Get-HtmlSafeString $perm.Rights)</td>"
            $html += "<td>$($perm.AccessType)</td>"
            $html += "<td>$riskBadge</td>"
            $html += "<td>$inheritBadge</td>"
            $html += "</tr>"
        }
        
        if ($Script:Data.HighRiskPermissions.Count -gt 200) {
            $html += "<tr><td colspan='6' style='text-align:center;color:#666;'>... and $($Script:Data.HighRiskPermissions.Count - 200) more entries (see CSV for complete list)</td></tr>"
        }
        
        $html += "</table></div></div>"
    }

    # ORPHANED SIDS SECTION
    if ($Script:Data.OrphanedSIDs.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>Orphaned SIDs (Deleted Accounts)</h2>
<span class="count warning">$($Script:Data.OrphanedSIDs.Count) entries</span>
<span class="toggle">&#9660;</span>
</div>
<div class="section-content">
<table>
<tr><th>Path</th><th>SID</th><th>Rights</th><th>Type</th><th>Inherited</th></tr>
"@
        foreach ($orphan in ($Script:Data.OrphanedSIDs | Select-Object -First 100)) {
            $inheritBadge = if ($orphan.IsInherited) { "<span class='badge badge-info'>Yes</span>" } else { "<span class='badge badge-warning'>No</span>" }
            
            $html += "<tr>"
            $html += "<td class='path-display truncate' title='$(Get-HtmlSafeString $orphan.FolderPath)'>$(Get-HtmlSafeString $orphan.RelativePath)</td>"
            $html += "<td><code>$(Get-HtmlSafeString $orphan.SID)</code></td>"
            $html += "<td class='truncate'>$(Get-HtmlSafeString $orphan.Rights)</td>"
            $html += "<td>$($orphan.AccessType)</td>"
            $html += "<td>$inheritBadge</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # BROKEN INHERITANCE SECTION
    if ($Script:Data.BrokenInheritance.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>Folders with Broken Inheritance</h2>
<span class="count warning">$($Script:Data.BrokenInheritance.Count) folders</span>
<span class="toggle">&#9660;</span>
</div>
<div class="section-content">
<table>
<tr><th>Path</th><th>Depth</th><th>Owner</th><th>ACEs</th><th>Identities</th><th>High Risk</th><th>Orphaned</th><th>Complexity</th></tr>
"@
        foreach ($folder in ($Script:Data.BrokenInheritance | Sort-Object Depth, RelativePath | Select-Object -First 100)) {
            $riskBadge = if ($folder.HasHighRisk) { "<span class='badge badge-danger'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
            $orphanBadge = if ($folder.HasOrphanedSIDs) { "<span class='badge badge-warning'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
            $complexBadge = switch ($folder.Complexity) {
                "High"   { "<span class='badge badge-danger'>High</span>" }
                "Medium" { "<span class='badge badge-warning'>Medium</span>" }
                default  { "<span class='badge badge-success'>Low</span>" }
            }
            $ownerDisplay = if ($folder.IsOrphanedOwner) { "<span class='badge badge-warning'>$(Get-HtmlSafeString $folder.Owner)</span>" } else { Get-HtmlSafeString $folder.Owner }
            
            $depthIndicators = ""
            for ($i = 0; $i -lt [Math]::Min($folder.Depth, 10); $i++) {
                $depthIndicators += "<span class='depth-indicator active'></span>"
            }
            
            $html += "<tr>"
            $html += "<td class='path-display truncate' title='$(Get-HtmlSafeString $folder.FolderPath)'>$(Get-HtmlSafeString $folder.RelativePath)</td>"
            $html += "<td>$depthIndicators $($folder.Depth)</td>"
            $html += "<td class='truncate'>$ownerDisplay</td>"
            $html += "<td>$($folder.AceCount)</td>"
            $html += "<td>$($folder.UniqueIdentities)</td>"
            $html += "<td>$riskBadge</td>"
            $html += "<td>$orphanBadge</td>"
            $html += "<td>$complexBadge</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # SHARE PERMISSIONS SECTION
    if ($Script:Data.SharePermissions.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>Share Permissions</h2>
<span class="count">$($Script:Data.SharePermissions.Count) entries</span>
<span class="toggle">&#9660;</span>
</div>
<div class="section-content">
<table>
<tr><th>Share</th><th>Server</th><th>Identity</th><th>Rights</th><th>Type</th><th>Risk</th></tr>
"@
        foreach ($share in $Script:Data.SharePermissions) {
            $riskBadge = switch ($share.RiskLevel) {
                "Critical" { "<span class='badge badge-critical'>CRITICAL</span>" }
                "High"     { "<span class='badge badge-danger'>HIGH</span>" }
                "Medium"   { "<span class='badge badge-warning'>MEDIUM</span>" }
                default    { "<span class='badge badge-normal'>Normal</span>" }
            }
            
            $html += "<tr>"
            $html += "<td>$(Get-HtmlSafeString $share.ShareName)</td>"
            $html += "<td>$(Get-HtmlSafeString $share.Server)</td>"
            $html += "<td>$(Get-HtmlSafeString $share.Identity)</td>"
            $html += "<td>$($share.Rights)</td>"
            $html += "<td>$($share.AccessType)</td>"
            $html += "<td>$riskBadge</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # FOLDER SIZES SECTION (with bar chart)
    if ($Script:Data.FolderSizes.Count -gt 0) {
        # Get top 15 largest folders
        $topFolders = $Script:Data.FolderSizes | Sort-Object DirectSizeBytes -Descending | Select-Object -First 15
        $maxSize = ($topFolders | Measure-Object -Property DirectSizeBytes -Maximum).Maximum
        if ($null -eq $maxSize -or $maxSize -eq 0) { $maxSize = 1 }
        
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>Storage Distribution - Top Folders by Size</h2>
<span class="count">$($Script:Data.FolderSizes.Count) folders</span>
<span class="toggle">&#9660;</span>
</div>
<div class="section-content">
<div class="chart-container">
<div class="chart-title">Top 15 Largest Folders (Direct File Content)</div>
<div class="bar-chart">
"@
        $colorIndex = 0
        foreach ($folder in $topFolders) {
            $pct = [math]::Round(($folder.DirectSizeBytes / $maxSize) * 100, 1)
            $color = $Script:ChartColors[$colorIndex % $Script:ChartColors.Count]
            
            $html += @"
<div class="bar-item">
<div class="bar-label" title="$(Get-HtmlSafeString $folder.FolderPath)">$(Get-HtmlSafeString $folder.RelativePath)</div>
<div class="bar-container">
<div class="bar-fill" style="width:$pct%;background:$color">
<span class="bar-value">$($folder.FileCount) files</span>
</div>
</div>
<div class="bar-size">$($folder.DirectSize)</div>
</div>
"@
            $colorIndex++
        }
        $html += "</div></div></div></div>"
    }

    # ALL PERMISSIONS TABLE (collapsible by folder)
    if ($Script:Data.FolderPermissions.Count -gt 0) {
        # Group by folder
        $groupedPerms = $Script:Data.FolderPermissions | Group-Object FolderPath | Sort-Object { $_.Group[0].Depth }, Name
        
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>All Folder Permissions</h2>
<span class="count">$($Script:Data.FolderPermissions.Count) ACEs across $($groupedPerms.Count) folders</span>
<span class="toggle">&#9654;</span>
</div>
<div class="section-content collapsed" style="max-height:none;padding:15px;">
"@
        foreach ($group in ($groupedPerms | Select-Object -First 50)) {
            $folderPath = $group.Name
            $relativePath = $group.Group[0].RelativePath
            $depth = $group.Group[0].Depth
            $aceCount = $group.Count
            
            $hasRisk = ($group.Group | Where-Object { $_.RiskLevel -in @("Critical", "High", "Medium") }).Count -gt 0
            $hasOrphan = ($group.Group | Where-Object { $_.IsOrphanedSID }).Count -gt 0
            
            $badges = ""
            if ($hasRisk) { $badges += "<span class='badge badge-danger' style='margin-left:5px'>Risk</span>" }
            if ($hasOrphan) { $badges += "<span class='badge badge-warning' style='margin-left:5px'>Orphan</span>" }
            
            $html += @"
<div class="expandable-block">
<div class="expandable-header" onclick="toggleSection(this)">
<div>
<span class="path-display" style="font-weight:600;">$(Get-HtmlSafeString $relativePath)</span>
<span style="color:#666;font-size:11px;margin-left:10px;">$aceCount ACEs | Depth $depth</span>
$badges
</div>
<span class="toggle">&#9654;</span>
</div>
<div class="section-content collapsed" style="max-height:300px;">
<table>
<tr><th>Identity</th><th>Rights</th><th>Type</th><th>Inherited</th><th>Risk</th></tr>
"@
            foreach ($ace in ($group.Group | Sort-Object @{E={switch ($_.RiskLevel) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } default { 3 } }}}, Identity)) {
                $riskBadge = switch ($ace.RiskLevel) {
                    "Critical" { "<span class='badge badge-critical'>CRITICAL</span>" }
                    "High"     { "<span class='badge badge-danger'>HIGH</span>" }
                    "Medium"   { "<span class='badge badge-warning'>MEDIUM</span>" }
                    default    { "<span class='badge badge-normal'>Normal</span>" }
                }
                $inheritBadge = if ($ace.IsInherited) { "<span class='badge badge-info'>Yes</span>" } else { "<span class='badge badge-warning'>No</span>" }
                $identityDisplay = if ($ace.IsOrphanedSID) { "<code>$($ace.Identity)</code>" } else { Get-HtmlSafeString $ace.Identity }
                
                $html += "<tr><td>$identityDisplay</td><td class='truncate' title='$(Get-HtmlSafeString $ace.Rights)'>$(Get-HtmlSafeString $ace.Rights)</td><td>$($ace.AccessType)</td><td>$inheritBadge</td><td>$riskBadge</td></tr>"
            }
            $html += "</table></div></div>"
        }
        
        if ($groupedPerms.Count -gt 50) {
            $html += "<p style='text-align:center;color:#666;padding:15px;'>... and $($groupedPerms.Count - 50) more folders (see CSV for complete list)</p>"
        }
        
        $html += "</div></div>"
    }

    # ERRORS SECTION
    if ($Script:Data.Errors.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)" style="background:#fff3cd">
<h2>Errors Encountered</h2>
<span class="count" style="background:#856404">$($Script:Data.Errors.Count)</span>
<span class="toggle">&#9654;</span>
</div>
<div class="section-content collapsed">
<table>
<tr><th>Time</th><th>Operation</th><th>Target</th><th>Error</th></tr>
"@
        foreach ($err in $Script:Data.Errors) {
            $html += "<tr><td>$($err.Timestamp)</td><td>$($err.Operation)</td><td class='truncate path-display'>$(Get-HtmlSafeString $err.Target)</td><td class='truncate'>$(Get-HtmlSafeString $err.Error)</td></tr>"
        }
        $html += "</table></div></div>"
    }

    # Footer
    $html += @"
</div>
<div class="footer">
<div class="tagline">$($Script:Branding.Tagline)</div>
<p>Generated by $($Script:Branding.CompanyName) File Share Security Report v1.1</p>
<p>$($Script:ReportDate)</p>
</div>
<script>
function toggleSection(header) {
    var content = header.nextElementSibling;
    if (content) {
        if (content.classList.contains('collapsed')) {
            content.classList.remove('collapsed');
            header.querySelector('.toggle').innerHTML = '&#9660;';
        } else {
            content.classList.add('collapsed');
            header.querySelector('.toggle').innerHTML = '&#9654;';
        }
    }
}
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "HTML report generated: $htmlPath" -Level Success
    return $htmlPath
}
#endregion

#region Main Execution
function Invoke-FileShareSecurityReport {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor DarkYellow
    Write-Host "       File Share Security Report Tool v1.1                          " -ForegroundColor DarkYellow
    Write-Host "       $($Script:Branding.CompanyName) - $($Script:Branding.Tagline)                      " -ForegroundColor DarkYellow
    Write-Host "======================================================================" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  Analyzes NTFS permissions, inheritance, and security risks" -ForegroundColor Green
    Write-Host "  Detects orphaned SIDs, high-risk permissions, broken inheritance" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Scan depth: $MaxDepth levels" -ForegroundColor Cyan
    Write-Host "  Include inherited: $($IncludeInherited.IsPresent)" -ForegroundColor Cyan
    Write-Host "  Skip size calc: $($SkipSizeCalculation.IsPresent)" -ForegroundColor Cyan
    Write-Host ""
    
    # Validate output path
    if (-not (Test-Path $OutputPath)) {
        try { 
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Log "Created output directory: $OutputPath" -Level Success 
        }
        catch { 
            Write-Log "Cannot create output directory: $OutputPath" -Level Error
            return 
        }
    }
    
    # Collect scan info for all paths
    $Script:ScanInfo = @()
    foreach ($scanPath in $Path) {
        $info = Get-ScanSummary -ScanPath $scanPath
        $Script:ScanInfo += $info
        
        if (-not $info.Exists) {
            Write-Log "Path does not exist or is inaccessible: $scanPath" -Level Error
            continue
        }
        
        Write-Log "Validated path: $scanPath" -Level Success
    }
    
    # Process each valid path
    foreach ($scanPath in ($Script:ScanInfo | Where-Object { $_.Exists })) {
        $currentPath = $scanPath.Path
        $Script:CurrentBasePath = $currentPath
        
        Write-Host ""
        Write-Log "Scanning: $currentPath" -Level Info
        Write-Log "============================================" -Level Info
        
        # Get share permissions if applicable
        $sharePerms = Get-SharePermissions -SharePath $currentPath
        foreach ($sp in $sharePerms) {
            $Script:Data.SharePermissions.Add($sp)
        }
        
        # Start recursive folder scan
        $folderCount = 0
        $folders = Get-ChildItem -Path $currentPath -Directory -Recurse -Force -ErrorAction SilentlyContinue -Depth $MaxDepth
        $totalFolders = ($folders | Measure-Object).Count + 1  # +1 for root
        
        Write-Log "Found $totalFolders folders to scan (depth: $MaxDepth)" -Level Info
        
        # Process root folder
        $folderCount++
        Write-Progress -Activity "Scanning Permissions" -Status "Folder $folderCount of $totalFolders" -CurrentOperation $currentPath -PercentComplete 1
        Get-FolderACL -FolderPath $currentPath -BasePath $currentPath -Depth 0
        if (-not $SkipSizeCalculation) {
            Get-FolderSize -FolderPath $currentPath -BasePath $currentPath -Depth 0
        }
        
        # Process subfolders
        foreach ($folder in $folders) {
            if (Test-ShouldExcludePath $folder.FullName) { continue }
            
            $folderCount++
            $pctComplete = [math]::Round(($folderCount / $totalFolders) * 100, 0)
            Write-Progress -Activity "Scanning Permissions" -Status "Folder $folderCount of $totalFolders" -CurrentOperation $folder.FullName -PercentComplete $pctComplete
            
            $depth = Get-FolderDepth -FolderPath $folder.FullName -BasePath $currentPath
            Get-FolderACL -FolderPath $folder.FullName -BasePath $currentPath -Depth $depth
            
            if (-not $SkipSizeCalculation) {
                Get-FolderSize -FolderPath $folder.FullName -BasePath $currentPath -Depth $depth
            }
        }
        
        Write-Progress -Activity "Scanning Permissions" -Completed
    }
    
    # Export results
    $csvFiles = Export-ToCsv
    $htmlFile = Export-ToHtml
    
    $stopwatch.Stop()
    
    # Summary
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "                    Report Generation Complete                        " -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Log "Execution time: $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))" -Level Success
    Write-Log "Folders scanned: $($Script:Data.Owners.Count)" -Level Success
    Write-Log "Permissions analyzed: $($Script:Data.FolderPermissions.Count)" -Level Success
    Write-Log "Broken inheritance: $($Script:Data.BrokenInheritance.Count)" -Level $(if ($Script:Data.BrokenInheritance.Count -gt 0) { "Warning" } else { "Success" })
    Write-Log "High-risk permissions: $($Script:Data.HighRiskPermissions.Count)" -Level $(if ($Script:Data.HighRiskPermissions.Count -gt 0) { "Warning" } else { "Success" })
    Write-Log "Orphaned SIDs: $($Script:Data.OrphanedSIDs.Count)" -Level $(if ($Script:Data.OrphanedSIDs.Count -gt 0) { "Warning" } else { "Success" })
    Write-Log "Errors: $($Script:Data.Errors.Count)" -Level $(if ($Script:Data.Errors.Count -gt 0) { "Warning" } else { "Success" })
    Write-Host ""
    Write-Log "Output files:" -Level Info
    foreach ($csv in $csvFiles) { Write-Host "    CSV: $csv" -ForegroundColor White }
    Write-Host "    HTML: $htmlFile" -ForegroundColor DarkYellow
    Write-Host ""
    
    $openReport = Read-Host "Open HTML report in browser? (Y/N)"
    if ($openReport -eq 'Y') { Start-Process $htmlFile }
}

Invoke-FileShareSecurityReport
#endregion
