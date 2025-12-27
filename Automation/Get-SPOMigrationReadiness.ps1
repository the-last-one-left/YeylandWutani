<#
.SYNOPSIS
    SharePoint Online Migration Readiness Assessment Tool v1.0
    
.DESCRIPTION
    Comprehensive file server analysis to identify migration blockers and concerns
    before migrating to SharePoint Online. Generates detailed reports with issues
    categorized by severity and provides actionable remediation suggestions.
    
    Analysis includes:
    - Path length violations (400 character limit, 218 for sync)
    - Invalid character detection in file/folder names
    - Restricted file and folder names
    - Legacy Office format detection (.doc, .xls, .ppt)
    - Blocked/unsupported file types
    - Folder item count thresholds (5,000 view limit)
    - Large file detection (250GB max upload)
    - Permission complexity analysis
    - Library structure recommendations
    - OneNote notebook sizing (2GB limit)
    - System files that won't sync
    - Duplicate file detection
    
.PARAMETER Path
    The root path(s) to scan. Can be local paths or UNC paths.
    
.PARAMETER OutputPath
    Directory path for output files. Defaults to current directory.
    
.PARAMETER MaxDepth
    Maximum folder depth to scan. Default: 10. Range: 1-20.
    
.PARAMETER TargetSiteUrl
    Optional target SharePoint site URL to calculate final path lengths.
    Example: "https://contoso.sharepoint.com/sites/Finance"
    
.PARAMETER TargetLibraryName
    Optional target document library name. Default: "Shared Documents"
    
.PARAMETER IncludePermissions
    Include detailed NTFS permission analysis for migration planning.
    
.PARAMETER SkipSizeCalculation
    Skip folder size calculations for faster scans.
    
.EXAMPLE
    .\Get-SPOMigrationReadiness.ps1 -Path "D:\FileShare"
    Basic readiness assessment of a file share
    
.EXAMPLE
    .\Get-SPOMigrationReadiness.ps1 -Path "\\Server\Data" -TargetSiteUrl "https://contoso.sharepoint.com/sites/Projects"
    Scan with target URL to calculate final SharePoint paths
    
.EXAMPLE
    .\Get-SPOMigrationReadiness.ps1 -Path @("D:\Finance", "D:\HR") -IncludePermissions -OutputPath "C:\Reports"
    Multi-path scan with permission analysis

.NOTES
    Author: Yeyland Wutani LLC
    Version: 1.0
    Website: https://github.com/YeylandWutani
    
    SharePoint Online Limits Reference:
    - URL Path: 400 characters max
    - File name: 400 characters max (including extension)
    - OneDrive Sync: ~218 characters effective limit
    - File upload: 250 GB max
    - Library items: 30 million max (5,000 view threshold)
    - Folder items: Recommended <5,000 for performance
    - Unique permissions: 50,000 per library
    - OneNote notebooks: 2 GB max
    
    Requirements:
    - PowerShell 5.1 or later
    - Read access to source paths
    - For permission analysis: Admin rights recommended
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path(s) to scan (local or UNC)")]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false, HelpMessage = "Maximum folder depth to scan (1-20)")]
    [ValidateRange(1, 20)]
    [int]$MaxDepth = 10,
    
    [Parameter(Mandatory = $false, HelpMessage = "Target SharePoint site URL")]
    [string]$TargetSiteUrl = "",
    
    [Parameter(Mandatory = $false, HelpMessage = "Target document library name")]
    [string]$TargetLibraryName = "Shared Documents",
    
    [Parameter(Mandatory = $false, HelpMessage = "Include NTFS permission analysis")]
    [switch]$IncludePermissions,
    
    [Parameter(Mandatory = $false, HelpMessage = "Skip folder size calculations")]
    [switch]$SkipSizeCalculation,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePaths = @('$RECYCLE.BIN', 'System Volume Information', 'DfsrPrivate', '.snapshot')
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

# Chart colors
$Script:ChartColors = @(
    "#FF6600", "#CC5200", "#dc3545", "#ffc107", "#28a745", 
    "#6B7280", "#17a2b8", "#fd7e14", "#4B5563", "#20c997"
)

# Timestamps
$Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"

#region SharePoint Online Limits and Rules

# Invalid characters in SharePoint file/folder names
$Script:InvalidCharacters = @('"', '*', ':', '<', '>', '?', '/', '\', '|')
# Characters that cause issues but may work: #, %, &, ~, {, }
$Script:ProblematicCharacters = @('#', '%', '&', '~', '{', '}')

# Restricted file and folder names
$Script:RestrictedNames = @(
    '.lock', 'CON', 'PRN', 'AUX', 'NUL',
    'COM0', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    '_vti_', 'desktop.ini', 'thumbs.db', '.ds_store'
)

# Restricted name patterns (starts with)
$Script:RestrictedPrefixes = @('~$', '~')

# Legacy Office formats that don't support co-authoring/web editing
$Script:LegacyOfficeExtensions = @{
    '.doc'  = @{ ModernFormat = '.docx'; Type = 'Word Document' }
    '.dot'  = @{ ModernFormat = '.dotx'; Type = 'Word Template' }
    '.xls'  = @{ ModernFormat = '.xlsx'; Type = 'Excel Workbook' }
    '.xlt'  = @{ ModernFormat = '.xltx'; Type = 'Excel Template' }
    '.ppt'  = @{ ModernFormat = '.pptx'; Type = 'PowerPoint Presentation' }
    '.pot'  = @{ ModernFormat = '.potx'; Type = 'PowerPoint Template' }
    '.pps'  = @{ ModernFormat = '.ppsx'; Type = 'PowerPoint Show' }
    '.mdb'  = @{ ModernFormat = '.accdb'; Type = 'Access Database' }
}

# Blocked file types (typically blocked by SharePoint/admin)
$Script:BlockedExtensions = @(
    # Executables
    '.exe', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh',
    '.msi', '.msp', '.mst', '.scr', '.hta', '.cpl', '.msc',
    # Scripts and code
    '.reg', '.inf', '.pif', '.application', '.gadget', '.vb', '.vbe',
    # Other potentially dangerous
    '.ade', '.adp', '.chm', '.dll', '.cer', '.ins', '.isp', '.jar', '.lib',
    '.lnk', '.mde', '.scf', '.shb', '.sys', '.vxd', '.wsc', '.wsf'
)

# System files that won't sync
$Script:SystemFiles = @(
    'desktop.ini', 'thumbs.db', '.ds_store', 'icon\r', '.dropbox',
    '.dropbox.attr', '~$*', '.tmp', '*.tmp'
)

# SharePoint limits
$Script:Limits = @{
    MaxUrlLength        = 400    # Total URL path limit
    MaxFileNameLength   = 400    # File name limit
    SyncUrlLimit        = 218    # Effective OneDrive sync limit
    MaxFileSize         = 250GB  # Maximum file upload size
    MaxFileSizeBytes    = 268435456000  # 250 GB in bytes
    FolderThreshold     = 5000   # List view threshold
    FolderRecommended   = 2500   # Recommended per folder
    LibraryMaxItems     = 30000000  # 30 million
    OneNoteSizeLimit    = 2GB    # OneNote notebook limit
    OneNoteSizeBytes    = 2147483648  # 2 GB in bytes
    UniquePermissions   = 50000  # Max unique permissions per library
    SyncFileLimit       = 300000 # OneDrive sync file limit
}

#endregion

# Data collections
$Script:Data = @{
    ScanInfo             = $null
    PathLengthIssues     = [System.Collections.Generic.List[PSObject]]::new()
    InvalidCharIssues    = [System.Collections.Generic.List[PSObject]]::new()
    RestrictedNames      = [System.Collections.Generic.List[PSObject]]::new()
    LegacyOfficeFiles    = [System.Collections.Generic.List[PSObject]]::new()
    BlockedFiles         = [System.Collections.Generic.List[PSObject]]::new()
    LargeFiles           = [System.Collections.Generic.List[PSObject]]::new()
    FolderItemCounts     = [System.Collections.Generic.List[PSObject]]::new()
    OneNoteNotebooks     = [System.Collections.Generic.List[PSObject]]::new()
    SystemFiles          = [System.Collections.Generic.List[PSObject]]::new()
    PermissionAnalysis   = [System.Collections.Generic.List[PSObject]]::new()
    FolderSizes          = [System.Collections.Generic.List[PSObject]]::new()
    LibraryRecommendations = [System.Collections.Generic.List[PSObject]]::new()
    Errors               = [System.Collections.Generic.List[PSObject]]::new()
    Statistics           = @{}
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
        Timestamp = Get-Date -Format "HH:mm:ss"
        Operation = $Operation
        Target    = $Target
        Error     = $ErrorMessage
    })
}
#endregion

#region Helper Functions

function Format-FileSize {
    param([long]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1TB } { return "{0:N2} TB" -f ($_ / 1TB) }
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB) }
        default { return "$_ B" }
    }
}

function Get-RelativePath {
    param([string]$FullPath, [string]$BasePath)
    $normalizedFull = $FullPath.TrimEnd('\', '/')
    $normalizedBase = $BasePath.TrimEnd('\', '/')
    if ($normalizedFull.StartsWith($normalizedBase, [StringComparison]::OrdinalIgnoreCase)) {
        return $normalizedFull.Substring($normalizedBase.Length).TrimStart('\', '/')
    }
    return $normalizedFull
}

function Get-SharePointPath {
    param([string]$RelativePath, [string]$SiteUrl, [string]$LibraryName)
    
    if ([string]::IsNullOrEmpty($SiteUrl)) {
        # Estimate path: sites/SiteName/LibraryName/path
        return "sites/migration/$LibraryName/$RelativePath"
    }
    
    # Parse site URL to get path portion
    try {
        $uri = [System.Uri]$SiteUrl
        $sitePath = $uri.AbsolutePath.TrimStart('/')
        return "$sitePath/$LibraryName/$RelativePath"
    }
    catch {
        return "sites/unknown/$LibraryName/$RelativePath"
    }
}

function Test-IsExcluded {
    param([string]$ItemPath, [string[]]$ExcludePatterns)
    foreach ($pattern in $ExcludePatterns) {
        if ($ItemPath -like "*$pattern*") { return $true }
    }
    return $false
}

function Get-IssueSeverity {
    param([string]$IssueType, [PSObject]$IssueData)
    
    switch ($IssueType) {
        'PathLength' {
            if ($IssueData.SPOPathLength -gt 400) { return 'Critical' }
            if ($IssueData.SPOPathLength -gt 218) { return 'High' }
            return 'Medium'
        }
        'InvalidChar' { return 'Critical' }
        'RestrictedName' { return 'Critical' }
        'LegacyOffice' { return 'Medium' }
        'BlockedFile' { return 'Critical' }
        'LargeFile' {
            if ($IssueData.Size -gt $Script:Limits.MaxFileSizeBytes) { return 'Critical' }
            return 'Warning'
        }
        'FolderCount' {
            if ($IssueData.ItemCount -gt 10000) { return 'High' }
            if ($IssueData.ItemCount -gt 5000) { return 'Medium' }
            return 'Low'
        }
        default { return 'Medium' }
    }
}
#endregion

#region Analysis Functions

function Test-PathLength {
    param([string]$FullPath, [string]$RelativePath, [string]$ItemType)
    
    $spoPath = Get-SharePointPath -RelativePath $RelativePath -SiteUrl $TargetSiteUrl -LibraryName $TargetLibraryName
    $spoPathLength = $spoPath.Length
    $fileName = Split-Path -Path $FullPath -Leaf
    
    # Check various limits
    $issues = @()
    
    # URL path exceeds 400 characters
    if ($spoPathLength -gt $Script:Limits.MaxUrlLength) {
        $issues += "Exceeds 400 character URL limit"
    }
    # Path exceeds sync limit (218 chars effective)
    elseif ($spoPathLength -gt $Script:Limits.SyncUrlLimit) {
        $issues += "May cause OneDrive sync issues (>218 chars)"
    }
    
    # File name too long
    if ($fileName.Length -gt 256) {
        $issues += "File name exceeds 256 characters"
    }
    
    if ($issues.Count -gt 0) {
        $issueObj = [PSCustomObject]@{
            Path           = $FullPath
            RelativePath   = $RelativePath
            SPOPath        = $spoPath
            SPOPathLength  = $spoPathLength
            FileName       = $fileName
            FileNameLength = $fileName.Length
            ItemType       = $ItemType
            Issues         = $issues -join "; "
            Severity       = if ($spoPathLength -gt 400) { 'Critical' } elseif ($spoPathLength -gt 218) { 'High' } else { 'Medium' }
            CharsToRemove  = [Math]::Max(0, $spoPathLength - $Script:Limits.SyncUrlLimit)
        }
        $Script:Data.PathLengthIssues.Add($issueObj)
        return $false
    }
    return $true
}

function Test-InvalidCharacters {
    param([string]$FullPath, [string]$ItemName, [string]$ItemType)
    
    $foundInvalid = @()
    $foundProblematic = @()
    
    # Check for invalid characters
    foreach ($char in $Script:InvalidCharacters) {
        if ($ItemName.Contains($char)) {
            $foundInvalid += $char
        }
    }
    
    # Check for problematic characters
    foreach ($char in $Script:ProblematicCharacters) {
        if ($ItemName.Contains($char)) {
            $foundProblematic += $char
        }
    }
    
    # Check for leading/trailing spaces
    if ($ItemName -ne $ItemName.Trim()) {
        $foundInvalid += "[leading/trailing space]"
    }
    
    # Check for consecutive periods
    if ($ItemName -match '\.{2,}') {
        $foundInvalid += "[consecutive periods]"
    }
    
    # Check for ending with period
    if ($ItemName.EndsWith('.') -and $ItemType -eq 'Folder') {
        $foundInvalid += "[ends with period]"
    }
    
    if ($foundInvalid.Count -gt 0 -or $foundProblematic.Count -gt 0) {
        $Script:Data.InvalidCharIssues.Add([PSCustomObject]@{
            Path                 = $FullPath
            Name                 = $ItemName
            ItemType             = $ItemType
            InvalidCharacters    = if ($foundInvalid.Count -gt 0) { $foundInvalid -join ', ' } else { '' }
            ProblematicCharacters = if ($foundProblematic.Count -gt 0) { $foundProblematic -join ', ' } else { '' }
            Severity             = if ($foundInvalid.Count -gt 0) { 'Critical' } else { 'Medium' }
            SuggestedName        = ($ItemName -replace '[\"*:<>?/\\|]', '_') -replace '[\s]+', ' '
        })
        return $false
    }
    return $true
}

function Test-RestrictedName {
    param([string]$FullPath, [string]$ItemName, [string]$ItemType)
    
    $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($ItemName)
    $issues = @()
    
    # Check exact matches (case-insensitive)
    foreach ($restricted in $Script:RestrictedNames) {
        if ($ItemName -ieq $restricted -or $nameWithoutExt -ieq $restricted) {
            $issues += "Matches restricted name: $restricted"
        }
        # Check if name contains _vti_
        if ($ItemName -ilike "*_vti_*") {
            $issues += "Contains reserved string: _vti_"
        }
    }
    
    # Check prefixes
    foreach ($prefix in $Script:RestrictedPrefixes) {
        if ($ItemName.StartsWith($prefix)) {
            $issues += "Starts with restricted prefix: $prefix"
        }
    }
    
    if ($issues.Count -gt 0) {
        $Script:Data.RestrictedNames.Add([PSCustomObject]@{
            Path     = $FullPath
            Name     = $ItemName
            ItemType = $ItemType
            Issues   = $issues -join "; "
            Severity = 'Critical'
        })
        return $false
    }
    return $true
}

function Test-LegacyOfficeFormat {
    param([string]$FullPath, [System.IO.FileInfo]$FileInfo)
    
    $ext = $FileInfo.Extension.ToLower()
    
    if ($Script:LegacyOfficeExtensions.ContainsKey($ext)) {
        $formatInfo = $Script:LegacyOfficeExtensions[$ext]
        $Script:Data.LegacyOfficeFiles.Add([PSCustomObject]@{
            Path           = $FullPath
            Name           = $FileInfo.Name
            Extension      = $ext
            Type           = $formatInfo.Type
            ModernFormat   = $formatInfo.ModernFormat
            Size           = $FileInfo.Length
            SizeFormatted  = Format-FileSize -Bytes $FileInfo.Length
            LastModified   = $FileInfo.LastWriteTime
            Severity       = 'Medium'
            Impact         = 'No co-authoring, no web editing, AutoSave disabled'
        })
        return $false
    }
    return $true
}

function Test-BlockedFile {
    param([string]$FullPath, [System.IO.FileInfo]$FileInfo)
    
    $ext = $FileInfo.Extension.ToLower()
    
    if ($ext -in $Script:BlockedExtensions) {
        $Script:Data.BlockedFiles.Add([PSCustomObject]@{
            Path          = $FullPath
            Name          = $FileInfo.Name
            Extension     = $ext
            Size          = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            LastModified  = $FileInfo.LastWriteTime
            Severity      = 'Critical'
            Reason        = 'File type typically blocked by SharePoint'
        })
        return $false
    }
    return $true
}

function Test-FileSize {
    param([string]$FullPath, [System.IO.FileInfo]$FileInfo)
    
    # Check for files over 100MB (potential slow upload)
    # Check for files over 250GB (hard limit)
    
    if ($FileInfo.Length -gt $Script:Limits.MaxFileSizeBytes) {
        $Script:Data.LargeFiles.Add([PSCustomObject]@{
            Path          = $FullPath
            Name          = $FileInfo.Name
            Size          = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            LimitGB       = 250
            Severity      = 'Critical'
            Issue         = 'Exceeds 250 GB upload limit'
        })
        return $false
    }
    elseif ($FileInfo.Length -gt 10GB) {
        $Script:Data.LargeFiles.Add([PSCustomObject]@{
            Path          = $FullPath
            Name          = $FileInfo.Name
            Size          = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            LimitGB       = 250
            Severity      = 'Warning'
            Issue         = 'Large file - may take significant time to upload'
        })
    }
    return $true
}

function Test-OneNoteNotebook {
    param([string]$FullPath, [System.IO.DirectoryInfo]$FolderInfo)
    
    # OneNote folders typically end with .onenote or contain .one files
    # Check if this is a OneNote notebook folder
    $isOneNote = $false
    $oneFiles = @()
    
    try {
        $oneFiles = Get-ChildItem -Path $FullPath -Filter "*.one" -ErrorAction SilentlyContinue
        if ($oneFiles.Count -gt 0 -or $FolderInfo.Name -like "*.onenote") {
            $isOneNote = $true
        }
    }
    catch { }
    
    if ($isOneNote -and -not $SkipSizeCalculation) {
        try {
            $size = (Get-ChildItem -Path $FullPath -Recurse -File -ErrorAction SilentlyContinue | 
                     Measure-Object -Property Length -Sum).Sum
            
            if ($size -gt $Script:Limits.OneNoteSizeBytes) {
                $Script:Data.OneNoteNotebooks.Add([PSCustomObject]@{
                    Path          = $FullPath
                    Name          = $FolderInfo.Name
                    Size          = $size
                    SizeFormatted = Format-FileSize -Bytes $size
                    LimitGB       = 2
                    Severity      = 'Critical'
                    Issue         = 'Exceeds 2 GB OneNote notebook limit'
                })
                return $false
            }
            elseif ($size -gt 1GB) {
                $Script:Data.OneNoteNotebooks.Add([PSCustomObject]@{
                    Path          = $FullPath
                    Name          = $FolderInfo.Name
                    Size          = $size
                    SizeFormatted = Format-FileSize -Bytes $size
                    LimitGB       = 2
                    Severity      = 'Warning'
                    Issue         = 'Approaching 2 GB OneNote notebook limit'
                })
            }
        }
        catch { }
    }
    return $true
}

function Test-SystemFile {
    param([string]$FullPath, [string]$ItemName)
    
    $isSystemFile = $false
    $reason = ""
    
    # Check exact matches
    if ($ItemName.ToLower() -in @('desktop.ini', 'thumbs.db', '.ds_store', '.dropbox', '.dropbox.attr')) {
        $isSystemFile = $true
        $reason = "System file that will not sync"
    }
    # Check temp file patterns
    elseif ($ItemName -like '~$*' -or $ItemName -like '*.tmp') {
        $isSystemFile = $true
        $reason = "Temporary file that will not sync"
    }
    # Check PST files (sync issues)
    elseif ($ItemName -like '*.pst') {
        $isSystemFile = $true
        $reason = "PST file - may cause Outlook errors after migration"
    }
    
    if ($isSystemFile) {
        $Script:Data.SystemFiles.Add([PSCustomObject]@{
            Path     = $FullPath
            Name     = $ItemName
            Reason   = $reason
            Severity = 'Low'
        })
        return $false
    }
    return $true
}

function Get-FolderItemCount {
    param([string]$FolderPath, [string]$RelativePath)
    
    try {
        $items = Get-ChildItem -Path $FolderPath -ErrorAction Stop
        $fileCount = ($items | Where-Object { -not $_.PSIsContainer }).Count
        $folderCount = ($items | Where-Object { $_.PSIsContainer }).Count
        $totalCount = $items.Count
        
        if ($totalCount -gt $Script:Limits.FolderRecommended) {
            $severity = 'Low'
            $issue = "Exceeds recommended 2,500 items per folder"
            
            if ($totalCount -gt $Script:Limits.FolderThreshold) {
                $severity = 'High'
                $issue = "Exceeds 5,000 item list view threshold"
            }
            elseif ($totalCount -gt 10000) {
                $severity = 'Critical'
                $issue = "Significantly exceeds thresholds - will cause performance issues"
            }
            
            $Script:Data.FolderItemCounts.Add([PSCustomObject]@{
                Path         = $FolderPath
                RelativePath = $RelativePath
                FileCount    = $fileCount
                FolderCount  = $folderCount
                TotalCount   = $totalCount
                Threshold    = $Script:Limits.FolderThreshold
                Issue        = $issue
                Severity     = $severity
            })
        }
        
        return $totalCount
    }
    catch {
        return 0
    }
}

function Get-PermissionAnalysis {
    param([string]$FolderPath, [string]$RelativePath)
    
    if (-not $IncludePermissions) { return }
    
    try {
        $acl = Get-Acl -Path $FolderPath -ErrorAction Stop
        
        # Check for broken inheritance
        $inheritanceEnabled = -not $acl.AreAccessRulesProtected
        
        # Get unique principals
        $principals = $acl.Access | Select-Object -ExpandProperty IdentityReference -Unique
        
        # Analyze permission complexity
        $explicitRules = ($acl.Access | Where-Object { -not $_.IsInherited }).Count
        
        if (-not $inheritanceEnabled -or $explicitRules -gt 5) {
            $Script:Data.PermissionAnalysis.Add([PSCustomObject]@{
                Path               = $FolderPath
                RelativePath       = $RelativePath
                InheritanceEnabled = $inheritanceEnabled
                ExplicitRuleCount  = $explicitRules
                UniquePrincipals   = $principals.Count
                Principals         = ($principals | ForEach-Object { $_.Value }) -join "; "
                Owner              = $acl.Owner
                Recommendation     = if (-not $inheritanceEnabled) { 
                    "Consider using SharePoint groups instead of unique permissions" 
                } else { "Review permission structure" }
            })
        }
    }
    catch {
        Add-Error -Operation "PermissionAnalysis" -Target $FolderPath -ErrorMessage $_.Exception.Message
    }
}

function Get-LibraryRecommendations {
    param([string]$BasePath)
    
    Write-Log "Generating library structure recommendations..." -Level Info
    
    try {
        # Get top-level folders
        $topFolders = Get-ChildItem -Path $BasePath -Directory -ErrorAction Stop
        
        foreach ($folder in $topFolders) {
            if (Test-IsExcluded -ItemPath $folder.FullName -ExcludePatterns $ExcludePaths) { continue }
            
            # Get folder size and item count
            $size = 0
            $itemCount = 0
            
            if (-not $SkipSizeCalculation) {
                try {
                    $stats = Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue |
                             Measure-Object -Property Length -Sum
                    $size = $stats.Sum
                    $itemCount = $stats.Count
                }
                catch { }
            }
            
            # Determine recommendation
            $recommendation = "Single library"
            $reason = "Size and item count within normal limits"
            
            if ($itemCount -gt 100000) {
                $recommendation = "Multiple libraries"
                $reason = "High item count - consider splitting by year/category"
            }
            elseif ($size -gt 1TB) {
                $recommendation = "Consider Teams site"
                $reason = "Large data volume - may benefit from dedicated Team"
            }
            elseif ($itemCount -gt 50000) {
                $recommendation = "Use folders with metadata"
                $reason = "Moderate item count - use folders and indexed columns"
            }
            
            $Script:Data.LibraryRecommendations.Add([PSCustomObject]@{
                FolderName     = $folder.Name
                Path           = $folder.FullName
                Size           = $size
                SizeFormatted  = Format-FileSize -Bytes $size
                ItemCount      = $itemCount
                Recommendation = $recommendation
                Reason         = $reason
            })
        }
    }
    catch {
        Add-Error -Operation "LibraryRecommendations" -Target $BasePath -ErrorMessage $_.Exception.Message
    }
}
#endregion

#region Main Scanning Function

function Start-MigrationScan {
    param([string]$ScanPath)
    
    Write-Log "Scanning: $ScanPath" -Level Info
    
    $scanStats = @{
        TotalFiles       = 0
        TotalFolders     = 0
        TotalSize        = 0
        ScannedItems     = 0
        ErrorCount       = 0
    }
    
    # Get library recommendations first (top-level analysis)
    Get-LibraryRecommendations -BasePath $ScanPath
    
    # Recursive scan with depth tracking
    $basePath = $ScanPath.TrimEnd('\', '/')
    
    $scriptBlock = {
        param($item, $basePath, $depth)
        
        $relativePath = Get-RelativePath -FullPath $item.FullName -BasePath $basePath
        
        if ($item.PSIsContainer) {
            # Folder checks
            Test-PathLength -FullPath $item.FullName -RelativePath $relativePath -ItemType "Folder" | Out-Null
            Test-InvalidCharacters -FullPath $item.FullName -ItemName $item.Name -ItemType "Folder" | Out-Null
            Test-RestrictedName -FullPath $item.FullName -ItemName $item.Name -ItemType "Folder" | Out-Null
            Test-OneNoteNotebook -FullPath $item.FullName -FolderInfo $item | Out-Null
            Get-FolderItemCount -FolderPath $item.FullName -RelativePath $relativePath | Out-Null
            Get-PermissionAnalysis -FolderPath $item.FullName -RelativePath $relativePath
        }
        else {
            # File checks
            Test-PathLength -FullPath $item.FullName -RelativePath $relativePath -ItemType "File" | Out-Null
            Test-InvalidCharacters -FullPath $item.FullName -ItemName $item.Name -ItemType "File" | Out-Null
            Test-RestrictedName -FullPath $item.FullName -ItemName $item.Name -ItemType "File" | Out-Null
            Test-LegacyOfficeFormat -FullPath $item.FullName -FileInfo $item | Out-Null
            Test-BlockedFile -FullPath $item.FullName -FileInfo $item | Out-Null
            Test-FileSize -FullPath $item.FullName -FileInfo $item | Out-Null
            Test-SystemFile -FullPath $item.FullName -ItemName $item.Name | Out-Null
        }
    }
    
    # Use Get-ChildItem with -Depth parameter
    Write-Log "Enumerating files and folders (depth: $MaxDepth)..." -Level Info
    
    $items = @()
    try {
        $items = Get-ChildItem -Path $ScanPath -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
    }
    catch {
        Add-Error -Operation "Enumeration" -Target $ScanPath -ErrorMessage $_.Exception.Message
    }
    
    $totalItems = $items.Count
    Write-Log "Found $totalItems items to analyze" -Level Info
    
    $processedCount = 0
    $lastProgress = 0
    
    foreach ($item in $items) {
        $processedCount++
        
        # Progress update every 1%
        $currentProgress = [math]::Floor(($processedCount / [math]::Max($totalItems, 1)) * 100)
        if ($currentProgress -gt $lastProgress -and $currentProgress % 5 -eq 0) {
            Write-Progress -Activity "Analyzing files" -Status "$currentProgress% Complete" -PercentComplete $currentProgress
            $lastProgress = $currentProgress
        }
        
        # Skip excluded paths
        if (Test-IsExcluded -ItemPath $item.FullName -ExcludePatterns $ExcludePaths) { continue }
        
        try {
            $relativePath = Get-RelativePath -FullPath $item.FullName -BasePath $basePath
            
            if ($item.PSIsContainer) {
                $scanStats.TotalFolders++
                
                Test-PathLength -FullPath $item.FullName -RelativePath $relativePath -ItemType "Folder" | Out-Null
                Test-InvalidCharacters -FullPath $item.FullName -ItemName $item.Name -ItemType "Folder" | Out-Null
                Test-RestrictedName -FullPath $item.FullName -ItemName $item.Name -ItemType "Folder" | Out-Null
                Test-OneNoteNotebook -FullPath $item.FullName -FolderInfo $item | Out-Null
                Get-FolderItemCount -FolderPath $item.FullName -RelativePath $relativePath | Out-Null
                Get-PermissionAnalysis -FolderPath $item.FullName -RelativePath $relativePath
            }
            else {
                $scanStats.TotalFiles++
                $scanStats.TotalSize += $item.Length
                
                Test-PathLength -FullPath $item.FullName -RelativePath $relativePath -ItemType "File" | Out-Null
                Test-InvalidCharacters -FullPath $item.FullName -ItemName $item.Name -ItemType "File" | Out-Null
                Test-RestrictedName -FullPath $item.FullName -ItemName $item.Name -ItemType "File" | Out-Null
                Test-LegacyOfficeFormat -FullPath $item.FullName -FileInfo $item | Out-Null
                Test-BlockedFile -FullPath $item.FullName -FileInfo $item | Out-Null
                Test-FileSize -FullPath $item.FullName -FileInfo $item | Out-Null
                Test-SystemFile -FullPath $item.FullName -ItemName $item.Name | Out-Null
            }
            
            $scanStats.ScannedItems++
        }
        catch {
            $scanStats.ErrorCount++
            Add-Error -Operation "ItemAnalysis" -Target $item.FullName -ErrorMessage $_.Exception.Message
        }
    }
    
    Write-Progress -Activity "Analyzing files" -Completed
    return $scanStats
}

#endregion

#region Report Generation

function Get-HTMLReport {
    
    # Calculate summary statistics
    $criticalCount = 0
    $highCount = 0
    $mediumCount = 0
    $lowCount = 0
    
    # Count by severity
    $Script:Data.PathLengthIssues | ForEach-Object { 
        switch ($_.Severity) { 'Critical' { $criticalCount++ } 'High' { $highCount++ } 'Medium' { $mediumCount++ } }
    }
    $Script:Data.InvalidCharIssues | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $criticalCount++ } 'Medium' { $mediumCount++ } }
    }
    $Script:Data.RestrictedNames | ForEach-Object { $criticalCount++ }
    $Script:Data.BlockedFiles | ForEach-Object { $criticalCount++ }
    $Script:Data.LegacyOfficeFiles | ForEach-Object { $mediumCount++ }
    $Script:Data.LargeFiles | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $criticalCount++ } 'Warning' { $lowCount++ } }
    }
    $Script:Data.FolderItemCounts | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $criticalCount++ } 'High' { $highCount++ } 'Medium' { $mediumCount++ } 'Low' { $lowCount++ } }
    }
    $Script:Data.SystemFiles | ForEach-Object { $lowCount++ }
    
    $totalIssues = $criticalCount + $highCount + $mediumCount + $lowCount
    
    # Determine overall readiness
    $readinessScore = 100
    $readinessScore -= ($criticalCount * 10)
    $readinessScore -= ($highCount * 5)
    $readinessScore -= ($mediumCount * 2)
    $readinessScore -= ($lowCount * 0.5)
    $readinessScore = [Math]::Max(0, [Math]::Min(100, $readinessScore))
    
    $readinessStatus = switch ($readinessScore) {
        { $_ -ge 90 } { @{ Status = "Ready"; Color = "#28a745"; Message = "Minor issues to address before migration" } }
        { $_ -ge 70 } { @{ Status = "Mostly Ready"; Color = "#ffc107"; Message = "Some issues require attention" } }
        { $_ -ge 50 } { @{ Status = "Needs Work"; Color = "#fd7e14"; Message = "Significant remediation required" } }
        default { @{ Status = "Not Ready"; Color = "#dc3545"; Message = "Critical issues must be resolved" } }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SharePoint Online Migration Readiness Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary-orange: $($Script:Branding.PrimaryOrange);
            --grey: $($Script:Branding.Grey);
            --white: $($Script:Branding.White);
            --black: $($Script:Branding.Black);
            --light-orange: $($Script:Branding.LightOrange);
            --dark-orange: $($Script:Branding.DarkOrange);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
            color: var(--black);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, var(--primary-orange) 0%, var(--dark-orange) 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(255, 102, 0, 0.3);
        }
        
        header h1 { font-size: 2em; margin-bottom: 5px; }
        header .tagline { opacity: 0.9; font-size: 0.95em; }
        header .report-info { margin-top: 15px; font-size: 0.9em; opacity: 0.85; }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .summary-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.12);
        }
        
        .summary-card.critical { border-left: 4px solid #dc3545; }
        .summary-card.high { border-left: 4px solid #fd7e14; }
        .summary-card.medium { border-left: 4px solid #ffc107; }
        .summary-card.low { border-left: 4px solid #28a745; }
        .summary-card.info { border-left: 4px solid var(--primary-orange); }
        
        .summary-card h3 { font-size: 2em; margin-bottom: 5px; }
        .summary-card p { color: var(--grey); font-size: 0.9em; }
        
        .readiness-meter {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .meter-container {
            display: flex;
            align-items: center;
            gap: 30px;
        }
        
        .meter-gauge {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient(
                $($readinessStatus.Color) 0deg,
                $($readinessStatus.Color) ${readinessScore}%,
                #e9ecef ${readinessScore}%
            );
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        
        .meter-gauge::before {
            content: '';
            width: 120px;
            height: 120px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }
        
        .meter-score {
            position: relative;
            z-index: 1;
            font-size: 2em;
            font-weight: bold;
            color: var(--black);
        }
        
        .meter-info h2 { font-size: 1.8em; color: $($readinessStatus.Color); margin-bottom: 5px; }
        .meter-info p { color: var(--grey); }
        
        section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        section h2 {
            color: var(--primary-orange);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--light-orange);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 500;
        }
        
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; color: white; }
        .severity-warning { background: #17a2b8; color: white; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        th {
            background: var(--light-orange);
            color: var(--dark-orange);
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        
        tr:hover { background: #f8f9fa; }
        
        .path-cell {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .chart-box {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .chart-box h3 { margin-bottom: 15px; color: var(--grey); }
        
        .table-container {
            max-height: 500px;
            overflow-y: auto;
            border-radius: 8px;
            border: 1px solid #eee;
        }
        
        .recommendation-card {
            background: var(--light-orange);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid var(--primary-orange);
        }
        
        .recommendation-card h4 { color: var(--dark-orange); margin-bottom: 5px; }
        
        .no-issues {
            text-align: center;
            padding: 40px;
            color: #28a745;
        }
        
        .no-issues svg { width: 60px; height: 60px; margin-bottom: 15px; }
        
        footer {
            text-align: center;
            padding: 20px;
            color: var(--grey);
            font-size: 0.9em;
        }
        
        footer a { color: var(--primary-orange); text-decoration: none; }
        
        .collapsible {
            cursor: pointer;
            user-select: none;
        }
        
        .collapsible::after {
            content: ' ▼';
            font-size: 0.8em;
            opacity: 0.6;
        }
        
        .collapsible.collapsed::after { content: ' ►'; }
        
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 SharePoint Online Migration Readiness Report</h1>
            <p class="tagline">$($Script:Branding.CompanyName) - $($Script:Branding.Tagline)</p>
            <div class="report-info">
                Generated: $($Script:ReportDate) | Source: $($Script:Data.ScanInfo.SourcePaths -join ', ')
            </div>
        </header>
        
        <!-- Readiness Score -->
        <div class="readiness-meter">
            <div class="meter-container">
                <div class="meter-gauge">
                    <span class="meter-score">${readinessScore}%</span>
                </div>
                <div class="meter-info">
                    <h2>$($readinessStatus.Status)</h2>
                    <p>$($readinessStatus.Message)</p>
                    <p style="margin-top: 10px;">Total Issues: $totalIssues | Files Scanned: $($Script:Data.ScanInfo.TotalFiles | ForEach-Object { '{0:N0}' -f $_ }) | Total Size: $(Format-FileSize -Bytes $Script:Data.ScanInfo.TotalSize)</p>
                </div>
            </div>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>$criticalCount</h3>
                <p>Critical Issues</p>
            </div>
            <div class="summary-card high">
                <h3>$highCount</h3>
                <p>High Priority</p>
            </div>
            <div class="summary-card medium">
                <h3>$mediumCount</h3>
                <p>Medium Priority</p>
            </div>
            <div class="summary-card low">
                <h3>$lowCount</h3>
                <p>Low Priority</p>
            </div>
            <div class="summary-card info">
                <h3>$($Script:Data.LegacyOfficeFiles.Count)</h3>
                <p>Legacy Office Files</p>
            </div>
        </div>
        
        <!-- Issue Distribution Chart -->
        <div class="chart-container">
            <div class="chart-box">
                <h3>Issue Distribution by Category</h3>
                <canvas id="issueChart" height="200"></canvas>
            </div>
            <div class="chart-box">
                <h3>Severity Breakdown</h3>
                <canvas id="severityChart" height="200"></canvas>
            </div>
        </div>
"@

    # Path Length Issues Section
    if ($Script:Data.PathLengthIssues.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">📏 Path Length Issues ($($Script:Data.PathLengthIssues.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                SharePoint has a 400 character URL limit. OneDrive sync may fail around 218 characters. 
                Consider shortening folder names or restructuring paths.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Path</th>
                            <th>SPO Length</th>
                            <th>Chars to Remove</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($issue in ($Script:Data.PathLengthIssues | Sort-Object -Property SPOPathLength -Descending | Select-Object -First 100)) {
            $severityClass = "severity-$($issue.Severity.ToLower())"
            $html += @"
                        <tr>
                            <td><span class="severity-badge $severityClass">$($issue.Severity)</span></td>
                            <td class="path-cell" title="$($issue.Path)">$($issue.RelativePath)</td>
                            <td>$($issue.SPOPathLength)</td>
                            <td>$($issue.CharsToRemove)</td>
                            <td>$($issue.ItemType)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Invalid Characters Section
    if ($Script:Data.InvalidCharIssues.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">⚠️ Invalid Characters ($($Script:Data.InvalidCharIssues.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                These file/folder names contain characters not allowed in SharePoint: " * : < > ? / \ |
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Name</th>
                            <th>Invalid Chars</th>
                            <th>Suggested Name</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($issue in ($Script:Data.InvalidCharIssues | Select-Object -First 100)) {
            $severityClass = "severity-$($issue.Severity.ToLower())"
            $html += @"
                        <tr>
                            <td><span class="severity-badge $severityClass">$($issue.Severity)</span></td>
                            <td class="path-cell" title="$($issue.Path)">$([System.Web.HttpUtility]::HtmlEncode($issue.Name))</td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($issue.InvalidCharacters))</td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($issue.SuggestedName))</td>
                            <td>$($issue.ItemType)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Restricted Names Section
    if ($Script:Data.RestrictedNames.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">🚫 Restricted Names ($($Script:Data.RestrictedNames.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                These names are reserved by Windows or SharePoint: CON, PRN, AUX, NUL, COM0-9, LPT0-9, _vti_, etc.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Name</th>
                            <th>Issue</th>
                            <th>Path</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($issue in $Script:Data.RestrictedNames) {
            $html += @"
                        <tr>
                            <td><span class="severity-badge severity-critical">Critical</span></td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($issue.Name))</td>
                            <td>$($issue.Issues)</td>
                            <td class="path-cell" title="$($issue.Path)">$($issue.Path)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Legacy Office Files Section
    if ($Script:Data.LegacyOfficeFiles.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">📄 Legacy Office Files ($($Script:Data.LegacyOfficeFiles.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                These files use legacy formats (.doc, .xls, .ppt) that don't support co-authoring, web editing, or AutoSave in SharePoint.
                Consider converting to modern formats before migration.
            </p>
            <div class="recommendation-card">
                <h4>💡 Remediation Options</h4>
                <p>1. Use Convert-LegacyExcel.ps1 and Convert-LegacyWord.ps1 from this repository to batch convert files.</p>
                <p>2. Open files in Office and Save As modern format (.docx, .xlsx, .pptx).</p>
                <p>3. Post-migration, users can open and resave files, but co-authoring won't work until converted.</p>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Name</th>
                            <th>Current</th>
                            <th>Recommended</th>
                            <th>Size</th>
                            <th>Modified</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        # Group by extension for summary
        $grouped = $Script:Data.LegacyOfficeFiles | Group-Object Extension | Sort-Object Count -Descending
        
        foreach ($issue in ($Script:Data.LegacyOfficeFiles | Sort-Object -Property Size -Descending | Select-Object -First 100)) {
            $html += @"
                        <tr>
                            <td>$($issue.Type)</td>
                            <td class="path-cell" title="$($issue.Path)">$($issue.Name)</td>
                            <td>$($issue.Extension)</td>
                            <td>$($issue.ModernFormat)</td>
                            <td>$($issue.SizeFormatted)</td>
                            <td>$($issue.LastModified.ToString('yyyy-MM-dd'))</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Blocked Files Section
    if ($Script:Data.BlockedFiles.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">🔒 Blocked File Types ($($Script:Data.BlockedFiles.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                These file types are typically blocked by SharePoint Online for security reasons.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Name</th>
                            <th>Extension</th>
                            <th>Size</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($issue in ($Script:Data.BlockedFiles | Select-Object -First 100)) {
            $html += @"
                        <tr>
                            <td><span class="severity-badge severity-critical">Critical</span></td>
                            <td class="path-cell" title="$($issue.Path)">$($issue.Name)</td>
                            <td>$($issue.Extension)</td>
                            <td>$($issue.SizeFormatted)</td>
                            <td>$($issue.Reason)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Folder Item Counts Section
    if ($Script:Data.FolderItemCounts.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">📁 Folder Item Thresholds ($($Script:Data.FolderItemCounts.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                Folders exceeding 5,000 items trigger SharePoint's list view threshold. Consider restructuring into subfolders.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Folder</th>
                            <th>Files</th>
                            <th>Subfolders</th>
                            <th>Total</th>
                            <th>Issue</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($issue in ($Script:Data.FolderItemCounts | Sort-Object -Property TotalCount -Descending)) {
            $severityClass = "severity-$($issue.Severity.ToLower())"
            $html += @"
                        <tr>
                            <td><span class="severity-badge $severityClass">$($issue.Severity)</span></td>
                            <td class="path-cell" title="$($issue.Path)">$($issue.RelativePath)</td>
                            <td>$($issue.FileCount)</td>
                            <td>$($issue.FolderCount)</td>
                            <td><strong>$($issue.TotalCount)</strong></td>
                            <td>$($issue.Issue)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Large Files Section
    if ($Script:Data.LargeFiles.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">📦 Large Files ($($Script:Data.LargeFiles.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                Files over 10GB may take significant time to upload. Files over 250GB cannot be uploaded.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Issue</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($issue in ($Script:Data.LargeFiles | Sort-Object -Property Size -Descending)) {
            $severityClass = "severity-$($issue.Severity.ToLower())"
            $html += @"
                        <tr>
                            <td><span class="severity-badge $severityClass">$($issue.Severity)</span></td>
                            <td class="path-cell" title="$($issue.Path)">$($issue.Name)</td>
                            <td><strong>$($issue.SizeFormatted)</strong></td>
                            <td>$($issue.Issue)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Library Recommendations Section
    if ($Script:Data.LibraryRecommendations.Count -gt 0) {
        $html += @"
        
        <section>
            <h2>📚 Library Structure Recommendations</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                Suggested library structure based on folder sizes and item counts.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Folder</th>
                            <th>Size</th>
                            <th>Items</th>
                            <th>Recommendation</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($rec in ($Script:Data.LibraryRecommendations | Sort-Object -Property Size -Descending)) {
            $html += @"
                        <tr>
                            <td><strong>$($rec.FolderName)</strong></td>
                            <td>$($rec.SizeFormatted)</td>
                            <td>$($rec.ItemCount)</td>
                            <td>$($rec.Recommendation)</td>
                            <td>$($rec.Reason)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Permissions Analysis Section
    if ($Script:Data.PermissionAnalysis.Count -gt 0) {
        $html += @"
        
        <section>
            <h2 class="collapsible">🔐 Permission Analysis ($($Script:Data.PermissionAnalysis.Count))</h2>
            <p style="margin-bottom: 15px; color: var(--grey);">
                Folders with broken inheritance or complex permissions that may need special handling during migration.
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Folder</th>
                            <th>Inheritance</th>
                            <th>Explicit Rules</th>
                            <th>Principals</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($perm in ($Script:Data.PermissionAnalysis | Sort-Object -Property ExplicitRuleCount -Descending | Select-Object -First 50)) {
            $inheritStatus = if ($perm.InheritanceEnabled) { '<span style="color: #28a745;">✓ Enabled</span>' } else { '<span style="color: #dc3545;">✗ Disabled</span>' }
            $html += @"
                        <tr>
                            <td class="path-cell" title="$($perm.Path)">$($perm.RelativePath)</td>
                            <td>$inheritStatus</td>
                            <td>$($perm.ExplicitRuleCount)</td>
                            <td>$($perm.UniquePrincipals)</td>
                            <td>$($perm.Recommendation)</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    # Charts JavaScript
    $html += @"
        
        <footer>
            <p>Generated by <a href="https://github.com/YeylandWutani" target="_blank">$($Script:Branding.CompanyName)</a> - $($Script:Branding.Tagline)</p>
        </footer>
    </div>
    
    <script>
        // Issue Distribution Chart
        new Chart(document.getElementById('issueChart'), {
            type: 'bar',
            data: {
                labels: ['Path Length', 'Invalid Chars', 'Restricted Names', 'Legacy Office', 'Blocked Files', 'Large Files', 'Folder Counts'],
                datasets: [{
                    label: 'Issues Found',
                    data: [$($Script:Data.PathLengthIssues.Count), $($Script:Data.InvalidCharIssues.Count), $($Script:Data.RestrictedNames.Count), $($Script:Data.LegacyOfficeFiles.Count), $($Script:Data.BlockedFiles.Count), $($Script:Data.LargeFiles.Count), $($Script:Data.FolderItemCounts.Count)],
                    backgroundColor: ['#FF6600', '#CC5200', '#dc3545', '#ffc107', '#6B7280', '#17a2b8', '#28a745']
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true } }
            }
        });
        
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [$criticalCount, $highCount, $mediumCount, $lowCount],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(function(el) {
            el.addEventListener('click', function() {
                const content = this.parentElement.querySelector('.table-container, .recommendation-card');
                if (content) {
                    content.classList.toggle('hidden');
                    this.classList.toggle('collapsed');
                }
            });
        });
    </script>
</body>
</html>
"@

    return $html
}

#endregion

#region Main Execution

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
Write-Host "║  " -NoNewline -ForegroundColor DarkGray
Write-Host "SharePoint Online Migration Readiness Assessment" -NoNewline -ForegroundColor Cyan
Write-Host "              ║" -ForegroundColor DarkGray
Write-Host "║  " -NoNewline -ForegroundColor DarkGray
Write-Host "$($Script:Branding.CompanyName)" -NoNewline -ForegroundColor Yellow
Write-Host " - $($Script:Branding.Tagline)" -NoNewline -ForegroundColor Gray
Write-Host "              ║" -ForegroundColor DarkGray
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkGray
Write-Host ""

# Validate paths
$validPaths = @()
foreach ($p in $Path) {
    if (Test-Path -Path $p) {
        $validPaths += $p
        Write-Log "Valid path: $p" -Level Success
    }
    else {
        Write-Log "Path not found: $p" -Level Error
    }
}

if ($validPaths.Count -eq 0) {
    Write-Log "No valid paths to scan. Exiting." -Level Error
    exit 1
}

# Validate output path
if (-not (Test-Path -Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $OutputPath" -Level Info
    }
    catch {
        Write-Log "Failed to create output directory: $OutputPath" -Level Error
        exit 1
    }
}

# Initialize scan info
$Script:Data.ScanInfo = @{
    SourcePaths    = $validPaths
    TargetSiteUrl  = $TargetSiteUrl
    TargetLibrary  = $TargetLibraryName
    MaxDepth       = $MaxDepth
    ScanStart      = Get-Date
    TotalFiles     = 0
    TotalFolders   = 0
    TotalSize      = 0
}

# Run scan for each path
$overallStats = @{
    TotalFiles   = 0
    TotalFolders = 0
    TotalSize    = 0
}

foreach ($scanPath in $validPaths) {
    Write-Host ""
    Write-Log "Starting scan of: $scanPath" -Level Info
    Write-Log "Max depth: $MaxDepth | Include permissions: $IncludePermissions" -Level Debug
    
    $stats = Start-MigrationScan -ScanPath $scanPath
    
    $overallStats.TotalFiles += $stats.TotalFiles
    $overallStats.TotalFolders += $stats.TotalFolders
    $overallStats.TotalSize += $stats.TotalSize
    
    Write-Log "Scanned $($stats.TotalFiles) files and $($stats.TotalFolders) folders" -Level Success
}

$Script:Data.ScanInfo.TotalFiles = $overallStats.TotalFiles
$Script:Data.ScanInfo.TotalFolders = $overallStats.TotalFolders
$Script:Data.ScanInfo.TotalSize = $overallStats.TotalSize
$Script:Data.ScanInfo.ScanEnd = Get-Date
$Script:Data.ScanInfo.Duration = ($Script:Data.ScanInfo.ScanEnd - $Script:Data.ScanInfo.ScanStart).TotalMinutes

# Generate reports
Write-Host ""
Write-Log "Generating reports..." -Level Info

$baseFileName = "SPOMigrationReadiness_$($Script:Timestamp)"

# HTML Report
$htmlPath = Join-Path -Path $OutputPath -ChildPath "$baseFileName.html"
$htmlContent = Get-HTMLReport
$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Log "HTML report: $htmlPath" -Level Success

# Export CSVs for remediation
$csvExports = @{
    "PathLengthIssues"  = $Script:Data.PathLengthIssues
    "InvalidCharacters" = $Script:Data.InvalidCharIssues
    "RestrictedNames"   = $Script:Data.RestrictedNames
    "LegacyOfficeFiles" = $Script:Data.LegacyOfficeFiles
    "BlockedFiles"      = $Script:Data.BlockedFiles
    "FolderItemCounts"  = $Script:Data.FolderItemCounts
    "LargeFiles"        = $Script:Data.LargeFiles
}

foreach ($export in $csvExports.GetEnumerator()) {
    if ($export.Value.Count -gt 0) {
        $csvPath = Join-Path -Path $OutputPath -ChildPath "${baseFileName}_$($export.Key).csv"
        $export.Value | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV export: $($export.Key) ($($export.Value.Count) items)" -Level Debug
    }
}

# Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
Write-Host "║  " -NoNewline -ForegroundColor DarkGray
Write-Host "Scan Complete" -NoNewline -ForegroundColor Green
Write-Host "                                                ║" -ForegroundColor DarkGray
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkGray

$summaryData = @(
    @{ Label = "Files Scanned"; Value = "{0:N0}" -f $overallStats.TotalFiles }
    @{ Label = "Folders Scanned"; Value = "{0:N0}" -f $overallStats.TotalFolders }
    @{ Label = "Total Size"; Value = Format-FileSize -Bytes $overallStats.TotalSize }
    @{ Label = "Scan Duration"; Value = "{0:N1} minutes" -f $Script:Data.ScanInfo.Duration }
    @{ Label = "Path Length Issues"; Value = $Script:Data.PathLengthIssues.Count }
    @{ Label = "Invalid Characters"; Value = $Script:Data.InvalidCharIssues.Count }
    @{ Label = "Restricted Names"; Value = $Script:Data.RestrictedNames.Count }
    @{ Label = "Legacy Office Files"; Value = $Script:Data.LegacyOfficeFiles.Count }
    @{ Label = "Blocked Files"; Value = $Script:Data.BlockedFiles.Count }
    @{ Label = "Large Files"; Value = $Script:Data.LargeFiles.Count }
    @{ Label = "Folder Threshold Issues"; Value = $Script:Data.FolderItemCounts.Count }
)

foreach ($item in $summaryData) {
    Write-Host "  $($item.Label): " -NoNewline -ForegroundColor Gray
    Write-Host $item.Value -ForegroundColor White
}

Write-Host ""
Write-Host "  Report saved to: " -NoNewline -ForegroundColor Gray
Write-Host $htmlPath -ForegroundColor Cyan
Write-Host ""

#endregion
