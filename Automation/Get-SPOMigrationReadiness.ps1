<#
.SYNOPSIS
    SharePoint Online Migration Readiness Assessment Tool v1.0
    
.DESCRIPTION
    Comprehensive file server analysis to identify migration blockers and concerns
    before migrating to SharePoint Online.
    
.PARAMETER Path
    The root path(s) to scan. Can be local paths or UNC paths.
    
.PARAMETER OutputPath
    Directory path for output files. Defaults to current directory.
    
.PARAMETER MaxDepth
    Maximum folder depth to scan. Default: 10. Range: 1-20.
    
.PARAMETER TargetSiteUrl
    Optional target SharePoint site URL to calculate final path lengths.
    
.PARAMETER TargetLibraryName
    Optional target document library name. Default: "Shared Documents"
    
.PARAMETER IncludePermissions
    Include detailed NTFS permission analysis for migration planning.
    
.PARAMETER SkipSizeCalculation
    Skip folder size calculations for faster scans.

.EXAMPLE
    .\Get-SPOMigrationReadiness.ps1 -Path "D:\FileShare"
    
.EXAMPLE
    .\Get-SPOMigrationReadiness.ps1 -Path "\\Server\Data" -TargetSiteUrl "https://contoso.sharepoint.com/sites/Projects"

.NOTES
    Author: Yeyland Wutani LLC
    Version: 1.0
    Website: https://github.com/YeylandWutani
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$MaxDepth = 10,
    
    [Parameter(Mandatory = $false)]
    [string]$TargetSiteUrl = "",
    
    [Parameter(Mandatory = $false)]
    [string]$TargetLibraryName = "Shared Documents",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePermissions,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipSizeCalculation,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePaths = @('$RECYCLE.BIN', 'System Volume Information', 'DfsrPrivate', '.snapshot')
)

#region Configuration
$ErrorActionPreference = "Continue"

# Load System.Web for HtmlEncode
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Fallback HTML encode function if System.Web not available
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}
$ProgressPreference = "Continue"

# Branding
$script:PrimaryOrange = "#FF6600"
$script:Grey = "#6B7280"
$script:Tagline = "Building Better Systems"
$script:CompanyName = "Yeyland Wutani LLC"

# Timestamps
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"

# SharePoint limits
$script:InvalidChars = @('"', '*', ':', '<', '>', '?', '/', '\', '|')
$script:ProblematicChars = @('#', '%', '&', '~', '{', '}')

$script:RestrictedNames = @(
    '.lock', 'CON', 'PRN', 'AUX', 'NUL',
    'COM0', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    '_vti_', 'desktop.ini', 'thumbs.db', '.ds_store'
)

$script:LegacyOfficeExt = @{
    '.doc' = '.docx'; '.dot' = '.dotx'; '.xls' = '.xlsx'
    '.xlt' = '.xltx'; '.ppt' = '.pptx'; '.pot' = '.potx'
    '.pps' = '.ppsx'; '.mdb' = '.accdb'
}

$script:BlockedExt = @(
    '.exe', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh',
    '.msi', '.msp', '.mst', '.scr', '.hta', '.cpl', '.msc', '.reg', '.inf', '.pif',
    '.application', '.gadget', '.vb', '.vbe', '.ade', '.adp', '.chm', '.dll', '.cer',
    '.ins', '.isp', '.jar', '.lib', '.lnk', '.mde', '.scf', '.shb', '.sys', '.vxd', '.wsc'
)

$script:MaxUrlLength = 400
$script:SyncUrlLimit = 218
$script:MaxFileSizeBytes = 268435456000
$script:FolderThreshold = 5000
$script:FolderRecommended = 2500

# Data collections
$script:PathLengthIssues = [System.Collections.Generic.List[PSObject]]::new()
$script:InvalidCharIssues = [System.Collections.Generic.List[PSObject]]::new()
$script:RestrictedNameIssues = [System.Collections.Generic.List[PSObject]]::new()
$script:LegacyOfficeFiles = [System.Collections.Generic.List[PSObject]]::new()
$script:BlockedFiles = [System.Collections.Generic.List[PSObject]]::new()
$script:LargeFiles = [System.Collections.Generic.List[PSObject]]::new()
$script:FolderItemCounts = [System.Collections.Generic.List[PSObject]]::new()
$script:SystemFiles = [System.Collections.Generic.List[PSObject]]::new()
$script:PermissionIssues = [System.Collections.Generic.List[PSObject]]::new()
$script:LibraryRecs = [System.Collections.Generic.List[PSObject]]::new()
$script:Errors = [System.Collections.Generic.List[PSObject]]::new()

$script:TotalFiles = 0
$script:TotalFolders = 0
$script:TotalSize = 0
#endregion

#region Logging
function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
        "Debug" { "Gray" }
        default { "White" }
    }
    $symbol = switch ($Level) {
        "Info" { "[*]" }
        "Warning" { "[!]" }
        "Error" { "[X]" }
        "Success" { "[+]" }
        "Debug" { "[-]" }
        default { "[*]" }
    }
    
    Write-Host "$ts " -NoNewline -ForegroundColor DarkGray
    Write-Host "$symbol " -NoNewline -ForegroundColor $color
    Write-Host $Message -ForegroundColor $color
}
#endregion

#region Helper Functions
function Format-FileSize {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Get-RelativePath {
    param([string]$FullPath, [string]$BasePath)
    $nFull = $FullPath.TrimEnd('\', '/')
    $nBase = $BasePath.TrimEnd('\', '/')
    if ($nFull.StartsWith($nBase, [StringComparison]::OrdinalIgnoreCase)) {
        return $nFull.Substring($nBase.Length).TrimStart('\', '/')
    }
    return $nFull
}

function Get-SPOPath {
    param([string]$RelPath)
    if ([string]::IsNullOrEmpty($TargetSiteUrl)) {
        return "sites/migration/$TargetLibraryName/$RelPath"
    }
    try {
        $uri = [System.Uri]$TargetSiteUrl
        $sitePath = $uri.AbsolutePath.TrimStart('/')
        return "$sitePath/$TargetLibraryName/$RelPath"
    }
    catch {
        return "sites/unknown/$TargetLibraryName/$RelPath"
    }
}

function Test-Excluded {
    param([string]$ItemPath)
    foreach ($pattern in $ExcludePaths) {
        if ($ItemPath -like "*$pattern*") { return $true }
    }
    return $false
}

function Get-CleanName {
    param([string]$Name, [switch]$IncludeProblematic)
    # Replace truly invalid SharePoint characters
    $clean = $Name -replace '["*:<>?/\\|]', '_'
    # Optionally replace problematic characters too
    if ($IncludeProblematic) {
        $clean = $clean -replace '[#%&~{}]', '_'
    }
    $clean = $clean -replace '\s+', ' '
    return $clean.Trim()
}
#endregion

#region Analysis Functions
function Test-PathLength {
    param([string]$FullPath, [string]$RelPath, [string]$ItemType)
    
    $spoPath = Get-SPOPath -RelPath $RelPath
    $spoLen = $spoPath.Length
    $fileName = Split-Path -Path $FullPath -Leaf
    
    $issues = @()
    if ($spoLen -gt $script:MaxUrlLength) {
        $issues += "Exceeds 400 character URL limit"
    }
    elseif ($spoLen -gt $script:SyncUrlLimit) {
        $issues += "May cause OneDrive sync issues (>218 chars)"
    }
    
    if ($fileName.Length -gt 256) {
        $issues += "File name exceeds 256 characters"
    }
    
    if ($issues.Count -gt 0) {
        $sev = if ($spoLen -gt 400) { 'Critical' } elseif ($spoLen -gt 218) { 'High' } else { 'Medium' }
        $script:PathLengthIssues.Add([PSCustomObject]@{
            Path = $FullPath
            RelativePath = $RelPath
            SPOPath = $spoPath
            SPOPathLength = $spoLen
            ItemType = $ItemType
            Issues = $issues -join "; "
            Severity = $sev
            CharsToRemove = [Math]::Max(0, $spoLen - $script:SyncUrlLimit)
        })
    }
}

function Test-InvalidChars {
    param([string]$FullPath, [string]$ItemName, [string]$ItemType)
    
    $foundInvalid = @()
    $foundProblematic = @()
    
    # Check for truly invalid characters (will block upload)
    foreach ($char in $script:InvalidChars) {
        if ($ItemName.Contains($char)) { $foundInvalid += $char }
    }
    # Check for problematic characters (may cause URL issues)
    foreach ($char in $script:ProblematicChars) {
        if ($ItemName.Contains($char)) { $foundProblematic += $char }
    }
    # Check for spacing issues
    if ($ItemName -ne $ItemName.Trim()) { $foundInvalid += "[leading/trailing space]" }
    if ($ItemName -match '\.{2,}') { $foundInvalid += "[consecutive periods]" }
    if ($ItemName.EndsWith('.') -and $ItemType -eq 'Folder') { $foundInvalid += "[ends with period]" }
    
    if ($foundInvalid.Count -gt 0 -or $foundProblematic.Count -gt 0) {
        # Determine severity - Critical if truly invalid, Medium if only problematic
        $sev = if ($foundInvalid.Count -gt 0) { 'Critical' } else { 'Medium' }
        
        # Build display string showing what was found
        $allChars = @()
        if ($foundInvalid.Count -gt 0) { $allChars += $foundInvalid }
        if ($foundProblematic.Count -gt 0) { $allChars += $foundProblematic }
        $charsDisplay = $allChars -join ', '
        
        # Generate suggested name - include problematic chars in replacement if they were found
        $hasProblematic = $foundProblematic.Count -gt 0
        $suggestedName = Get-CleanName -Name $ItemName -IncludeProblematic:$hasProblematic
        
        $script:InvalidCharIssues.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $ItemName
            ItemType = $ItemType
            CharactersFound = $charsDisplay
            Severity = $sev
            SuggestedName = $suggestedName
        })
    }
}

function Test-RestrictedName {
    param([string]$FullPath, [string]$ItemName, [string]$ItemType)
    
    $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($ItemName)
    $issues = @()
    
    foreach ($restricted in $script:RestrictedNames) {
        if ($ItemName -ieq $restricted -or $nameNoExt -ieq $restricted) {
            $issues += "Matches restricted: $restricted"
        }
        if ($ItemName -ilike "*_vti_*") {
            $issues += "Contains _vti_"
        }
    }
    
    if ($ItemName.StartsWith('~$') -or $ItemName.StartsWith('~')) {
        $issues += "Starts with ~"
    }
    
    if ($issues.Count -gt 0) {
        $script:RestrictedNameIssues.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $ItemName
            ItemType = $ItemType
            Issues = ($issues -join "; ")
            Severity = 'Critical'
        })
    }
}

function Test-LegacyOffice {
    param([string]$FullPath, [System.IO.FileInfo]$FileInfo)
    
    $ext = $FileInfo.Extension.ToLower()
    if ($script:LegacyOfficeExt.ContainsKey($ext)) {
        $script:LegacyOfficeFiles.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $FileInfo.Name
            Extension = $ext
            ModernFormat = $script:LegacyOfficeExt[$ext]
            Size = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            LastModified = $FileInfo.LastWriteTime
            Severity = 'Medium'
        })
    }
}

function Test-BlockedFile {
    param([string]$FullPath, [System.IO.FileInfo]$FileInfo)
    
    $ext = $FileInfo.Extension.ToLower()
    if ($ext -in $script:BlockedExt) {
        $script:BlockedFiles.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $FileInfo.Name
            Extension = $ext
            Size = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            Severity = 'Critical'
            Reason = 'File type blocked by SharePoint'
        })
    }
}

function Test-FileSize {
    param([string]$FullPath, [System.IO.FileInfo]$FileInfo)
    
    if ($FileInfo.Length -gt $script:MaxFileSizeBytes) {
        $script:LargeFiles.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $FileInfo.Name
            Size = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            Severity = 'Critical'
            Issue = 'Exceeds 250 GB limit'
        })
    }
    elseif ($FileInfo.Length -gt 10GB) {
        $script:LargeFiles.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $FileInfo.Name
            Size = $FileInfo.Length
            SizeFormatted = Format-FileSize -Bytes $FileInfo.Length
            Severity = 'Warning'
            Issue = 'Large file - slow upload'
        })
    }
}

function Test-SystemFile {
    param([string]$FullPath, [string]$ItemName)
    
    $sysNames = @('desktop.ini', 'thumbs.db', '.ds_store', '.dropbox', '.dropbox.attr')
    $lower = $ItemName.ToLower()
    
    if ($lower -in $sysNames -or $ItemName -like '~$*' -or $ItemName -like '*.tmp' -or $ItemName -like '*.pst') {
        $reason = if ($ItemName -like '*.pst') { "PST file - sync issues" } else { "System/temp file" }
        $script:SystemFiles.Add([PSCustomObject]@{
            Path = $FullPath
            Name = $ItemName
            Reason = $reason
            Severity = 'Low'
        })
    }
}

function Get-FolderItemCount {
    param([string]$FolderPath, [string]$RelPath)
    
    try {
        $items = Get-ChildItem -Path $FolderPath -ErrorAction Stop
        $total = $items.Count
        
        if ($total -gt $script:FolderRecommended) {
            $sev = 'Low'
            $issue = "Exceeds recommended 2,500"
            if ($total -gt 10000) {
                $sev = 'Critical'
                $issue = "Exceeds 10,000 items"
            }
            elseif ($total -gt $script:FolderThreshold) {
                $sev = 'High'
                $issue = "Exceeds 5,000 threshold"
            }
            
            $files = ($items | Where-Object { -not $_.PSIsContainer }).Count
            $folders = ($items | Where-Object { $_.PSIsContainer }).Count
            
            $script:FolderItemCounts.Add([PSCustomObject]@{
                Path = $FolderPath
                RelativePath = $RelPath
                FileCount = $files
                FolderCount = $folders
                TotalCount = $total
                Issue = $issue
                Severity = $sev
            })
        }
    }
    catch { }
}

function Get-PermissionAnalysis {
    param([string]$FolderPath, [string]$RelPath)
    
    if (-not $IncludePermissions) { return }
    
    try {
        $acl = Get-Acl -Path $FolderPath -ErrorAction Stop
        $inheritEnabled = -not $acl.AreAccessRulesProtected
        $explicitRules = ($acl.Access | Where-Object { -not $_.IsInherited }).Count
        
        if (-not $inheritEnabled -or $explicitRules -gt 5) {
            $principals = $acl.Access | Select-Object -ExpandProperty IdentityReference -Unique
            $script:PermissionIssues.Add([PSCustomObject]@{
                Path = $FolderPath
                RelativePath = $RelPath
                InheritanceEnabled = $inheritEnabled
                ExplicitRuleCount = $explicitRules
                UniquePrincipals = $principals.Count
            })
        }
    }
    catch { }
}
#endregion

#region Main Scan
function Start-MigrationScan {
    param([string]$ScanPath)
    
    Write-Log "Scanning: $ScanPath" -Level Info
    
    $basePath = $ScanPath.TrimEnd('\', '/')
    
    Write-Log "Enumerating files and folders (depth: $MaxDepth)..." -Level Info
    
    $items = @()
    try {
        $items = Get-ChildItem -Path $ScanPath -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
    }
    catch {
        $script:Errors.Add([PSCustomObject]@{ Target = $ScanPath; Error = $_.Exception.Message })
    }
    
    $totalItems = $items.Count
    Write-Log "Found $totalItems items to analyze" -Level Info
    
    $processedCount = 0
    $lastProgress = 0
    
    foreach ($item in $items) {
        $processedCount++
        
        $currentProgress = [math]::Floor(($processedCount / [math]::Max($totalItems, 1)) * 100)
        if ($currentProgress -gt $lastProgress -and $currentProgress % 5 -eq 0) {
            Write-Progress -Activity "Analyzing files" -Status "$currentProgress% Complete" -PercentComplete $currentProgress
            $lastProgress = $currentProgress
        }
        
        if (Test-Excluded -ItemPath $item.FullName) { continue }
        
        try {
            $relPath = Get-RelativePath -FullPath $item.FullName -BasePath $basePath
            
            if ($item.PSIsContainer) {
                $script:TotalFolders++
                Test-PathLength -FullPath $item.FullName -RelPath $relPath -ItemType "Folder"
                Test-InvalidChars -FullPath $item.FullName -ItemName $item.Name -ItemType "Folder"
                Test-RestrictedName -FullPath $item.FullName -ItemName $item.Name -ItemType "Folder"
                Get-FolderItemCount -FolderPath $item.FullName -RelPath $relPath
                Get-PermissionAnalysis -FolderPath $item.FullName -RelPath $relPath
            }
            else {
                $script:TotalFiles++
                $script:TotalSize += $item.Length
                Test-PathLength -FullPath $item.FullName -RelPath $relPath -ItemType "File"
                Test-InvalidChars -FullPath $item.FullName -ItemName $item.Name -ItemType "File"
                Test-RestrictedName -FullPath $item.FullName -ItemName $item.Name -ItemType "File"
                Test-LegacyOffice -FullPath $item.FullName -FileInfo $item
                Test-BlockedFile -FullPath $item.FullName -FileInfo $item
                Test-FileSize -FullPath $item.FullName -FileInfo $item
                Test-SystemFile -FullPath $item.FullName -ItemName $item.Name
            }
        }
        catch {
            $script:Errors.Add([PSCustomObject]@{ Target = $item.FullName; Error = $_.Exception.Message })
        }
    }
    
    Write-Progress -Activity "Analyzing files" -Completed
}
#endregion

#region Report Generation
function Get-HTMLReport {
    # Count severities
    $critical = 0
    $high = 0
    $medium = 0
    $low = 0
    
    $script:PathLengthIssues | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $critical++ } 'High' { $high++ } 'Medium' { $medium++ } }
    }
    $script:InvalidCharIssues | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $critical++ } 'Medium' { $medium++ } }
    }
    $script:RestrictedNameIssues | ForEach-Object { $critical++ }
    $script:BlockedFiles | ForEach-Object { $critical++ }
    $script:LegacyOfficeFiles | ForEach-Object { $medium++ }
    $script:LargeFiles | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $critical++ } 'Warning' { $low++ } }
    }
    $script:FolderItemCounts | ForEach-Object {
        switch ($_.Severity) { 'Critical' { $critical++ } 'High' { $high++ } 'Medium' { $medium++ } 'Low' { $low++ } }
    }
    $script:SystemFiles | ForEach-Object { $low++ }
    
    $totalIssues = $critical + $high + $medium + $low
    
    # Readiness score
    $score = 100
    $score -= ($critical * 10)
    $score -= ($high * 5)
    $score -= ($medium * 2)
    $score -= ($low * 0.5)
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    
    $status = "Ready"
    $statusColor = "#28a745"
    $statusMsg = "Minor issues to address"
    
    if ($score -lt 90) { $status = "Mostly Ready"; $statusColor = "#ffc107"; $statusMsg = "Some issues require attention" }
    if ($score -lt 70) { $status = "Needs Work"; $statusColor = "#fd7e14"; $statusMsg = "Significant remediation required" }
    if ($score -lt 50) { $status = "Not Ready"; $statusColor = "#dc3545"; $statusMsg = "Critical issues must be resolved" }
    
    $totalSizeFormatted = Format-FileSize -Bytes $script:TotalSize
    
    # Build HTML
    $sb = [System.Text.StringBuilder]::new()
    
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="UTF-8">')
    [void]$sb.AppendLine('<title>SPO Migration Readiness Report</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('body { font-family: Segoe UI, sans-serif; background: #f5f7fa; margin: 20px; }')
    [void]$sb.AppendLine('.container { max-width: 1400px; margin: 0 auto; }')
    [void]$sb.AppendLine('header { background: linear-gradient(135deg, #FF6600, #CC5200); color: white; padding: 25px; border-radius: 10px; margin-bottom: 20px; }')
    [void]$sb.AppendLine('header h1 { margin: 0 0 5px 0; }')
    [void]$sb.AppendLine('.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 20px; }')
    [void]$sb.AppendLine('.summary-card { background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }')
    [void]$sb.AppendLine('.summary-card h3 { font-size: 2em; margin: 0 0 5px 0; }')
    [void]$sb.AppendLine('.summary-card p { color: #6B7280; margin: 0; }')
    [void]$sb.AppendLine('.critical { border-left: 4px solid #dc3545; }')
    [void]$sb.AppendLine('.high { border-left: 4px solid #fd7e14; }')
    [void]$sb.AppendLine('.medium { border-left: 4px solid #ffc107; }')
    [void]$sb.AppendLine('.low { border-left: 4px solid #28a745; }')
    [void]$sb.AppendLine('.info { border-left: 4px solid #FF6600; }')
    [void]$sb.AppendLine('.score-box { background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; display: flex; align-items: center; gap: 30px; }')
    [void]$sb.AppendLine('.score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2em; font-weight: bold; color: white; }')
    [void]$sb.AppendLine('section { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; }')
    [void]$sb.AppendLine('section h2 { color: #FF6600; border-bottom: 2px solid #FFF3E6; padding-bottom: 10px; }')
    [void]$sb.AppendLine('table { width: 100%; border-collapse: collapse; font-size: 0.9em; }')
    [void]$sb.AppendLine('th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }')
    [void]$sb.AppendLine('th { background: #FFF3E6; color: #CC5200; }')
    [void]$sb.AppendLine('tr:hover { background: #f8f9fa; }')
    [void]$sb.AppendLine('.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; color: white; }')
    [void]$sb.AppendLine('.badge-critical { background: #dc3545; }')
    [void]$sb.AppendLine('.badge-high { background: #fd7e14; }')
    [void]$sb.AppendLine('.badge-medium { background: #ffc107; color: #333; }')
    [void]$sb.AppendLine('.badge-low { background: #28a745; }')
    [void]$sb.AppendLine('.badge-warning { background: #17a2b8; }')
    [void]$sb.AppendLine('.path-cell { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: Consolas, monospace; font-size: 0.85em; }')
    [void]$sb.AppendLine('.table-container { max-height: 500px; overflow-y: auto; }')
    [void]$sb.AppendLine('footer { text-align: center; padding: 20px; color: #6B7280; }')
    [void]$sb.AppendLine('footer a { color: #FF6600; text-decoration: none; }')
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<div class="container">')
    
    # Header
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine('<h1>SharePoint Online Migration Readiness Report</h1>')
    [void]$sb.AppendLine("<p>$script:CompanyName - $script:Tagline</p>")
    [void]$sb.AppendLine("<p style=`"opacity:0.8;font-size:0.9em`">Generated: $script:ReportDate</p>")
    [void]$sb.AppendLine('</header>')
    
    # Score
    [void]$sb.AppendLine('<div class="score-box">')
    [void]$sb.AppendLine("<div class=`"score-circle`" style=`"background:$statusColor`">$([int]$score)%</div>")
    [void]$sb.AppendLine('<div>')
    [void]$sb.AppendLine("<h2 style=`"margin:0;color:$statusColor`">$status</h2>")
    [void]$sb.AppendLine("<p style=`"color:#6B7280`">$statusMsg</p>")
    [void]$sb.AppendLine("<p style=`"margin-top:10px`">Total Issues: $totalIssues | Files: $($script:TotalFiles.ToString('N0')) | Size: $totalSizeFormatted</p>")
    [void]$sb.AppendLine('</div></div>')
    
    # Summary cards
    [void]$sb.AppendLine('<div class="summary-grid">')
    [void]$sb.AppendLine("<div class=`"summary-card critical`"><h3>$critical</h3><p>Critical</p></div>")
    [void]$sb.AppendLine("<div class=`"summary-card high`"><h3>$high</h3><p>High</p></div>")
    [void]$sb.AppendLine("<div class=`"summary-card medium`"><h3>$medium</h3><p>Medium</p></div>")
    [void]$sb.AppendLine("<div class=`"summary-card low`"><h3>$low</h3><p>Low</p></div>")
    [void]$sb.AppendLine("<div class=`"summary-card info`"><h3>$($script:LegacyOfficeFiles.Count)</h3><p>Legacy Office</p></div>")
    [void]$sb.AppendLine('</div>')
    
    # Path Length Issues
    if ($script:PathLengthIssues.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Path Length Issues ($($script:PathLengthIssues.Count))</h2>")
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Severity</th><th>Path</th><th>SPO Length</th><th>Remove</th></tr>')
        foreach ($item in ($script:PathLengthIssues | Sort-Object SPOPathLength -Descending | Select-Object -First 100)) {
            $badgeClass = "badge-$($item.Severity.ToLower())"
            [void]$sb.AppendLine("<tr><td><span class=`"badge $badgeClass`">$($item.Severity)</span></td>")
            [void]$sb.AppendLine("<td class=`"path-cell`" title=`"$($item.Path)`">$($item.RelativePath)</td>")
            [void]$sb.AppendLine("<td>$($item.SPOPathLength)</td><td>$($item.CharsToRemove)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Invalid Characters
    if ($script:InvalidCharIssues.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Invalid Characters ($($script:InvalidCharIssues.Count))</h2>")
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Severity</th><th>Name</th><th>Invalid</th><th>Suggested</th></tr>')
        foreach ($item in ($script:InvalidCharIssues | Select-Object -First 100)) {
            $badgeClass = "badge-$($item.Severity.ToLower())"
            $safeName = ConvertTo-HtmlSafe $item.Name
            $safeChars = ConvertTo-HtmlSafe $item.InvalidChars
            $safeSuggested = ConvertTo-HtmlSafe $item.SuggestedName
            [void]$sb.AppendLine("<tr><td><span class=`"badge $badgeClass`">$($item.Severity)</span></td>")
            [void]$sb.AppendLine("<td>$safeName</td><td>$safeChars</td><td>$safeSuggested</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Restricted Names
    if ($script:RestrictedNameIssues.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Restricted Names ($($script:RestrictedNameIssues.Count))</h2>")
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Name</th><th>Issue</th><th>Path</th></tr>')
        foreach ($item in $script:RestrictedNameIssues) {
            $safeName = ConvertTo-HtmlSafe $item.Name
            [void]$sb.AppendLine("<tr><td>$safeName</td><td>$($item.Issues)</td>")
            [void]$sb.AppendLine("<td class=`"path-cell`">$($item.Path)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Legacy Office
    if ($script:LegacyOfficeFiles.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Legacy Office Files ($($script:LegacyOfficeFiles.Count))</h2>")
        [void]$sb.AppendLine('<p style="color:#6B7280">These files use older formats that do not support co-authoring or web editing.</p>')
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Name</th><th>Current</th><th>Modern</th><th>Size</th><th>Modified</th></tr>')
        foreach ($item in ($script:LegacyOfficeFiles | Sort-Object Size -Descending | Select-Object -First 100)) {
            [void]$sb.AppendLine("<tr><td class=`"path-cell`" title=`"$($item.Path)`">$($item.Name)</td>")
            [void]$sb.AppendLine("<td>$($item.Extension)</td><td>$($item.ModernFormat)</td>")
            [void]$sb.AppendLine("<td>$($item.SizeFormatted)</td><td>$($item.LastModified.ToString('yyyy-MM-dd'))</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Blocked Files
    if ($script:BlockedFiles.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Blocked Files ($($script:BlockedFiles.Count))</h2>")
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Name</th><th>Extension</th><th>Size</th><th>Reason</th></tr>')
        foreach ($item in ($script:BlockedFiles | Select-Object -First 100)) {
            [void]$sb.AppendLine("<tr><td class=`"path-cell`" title=`"$($item.Path)`">$($item.Name)</td>")
            [void]$sb.AppendLine("<td>$($item.Extension)</td><td>$($item.SizeFormatted)</td><td>$($item.Reason)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Folder Item Counts
    if ($script:FolderItemCounts.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Folder Item Counts ($($script:FolderItemCounts.Count))</h2>")
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Severity</th><th>Folder</th><th>Files</th><th>Folders</th><th>Total</th></tr>')
        foreach ($item in ($script:FolderItemCounts | Sort-Object TotalCount -Descending)) {
            $badgeClass = "badge-$($item.Severity.ToLower())"
            [void]$sb.AppendLine("<tr><td><span class=`"badge $badgeClass`">$($item.Severity)</span></td>")
            [void]$sb.AppendLine("<td class=`"path-cell`" title=`"$($item.Path)`">$($item.RelativePath)</td>")
            [void]$sb.AppendLine("<td>$($item.FileCount)</td><td>$($item.FolderCount)</td><td><strong>$($item.TotalCount)</strong></td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Large Files
    if ($script:LargeFiles.Count -gt 0) {
        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine("<h2>Large Files ($($script:LargeFiles.Count))</h2>")
        [void]$sb.AppendLine('<div class="table-container"><table>')
        [void]$sb.AppendLine('<tr><th>Severity</th><th>Name</th><th>Size</th><th>Issue</th></tr>')
        foreach ($item in ($script:LargeFiles | Sort-Object Size -Descending)) {
            $badgeClass = "badge-$($item.Severity.ToLower())"
            [void]$sb.AppendLine("<tr><td><span class=`"badge $badgeClass`">$($item.Severity)</span></td>")
            [void]$sb.AppendLine("<td class=`"path-cell`" title=`"$($item.Path)`">$($item.Name)</td>")
            [void]$sb.AppendLine("<td><strong>$($item.SizeFormatted)</strong></td><td>$($item.Issue)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></section>')
    }
    
    # Footer
    [void]$sb.AppendLine('<footer>')
    [void]$sb.AppendLine("<p>Generated by <a href=`"https://github.com/YeylandWutani`">$script:CompanyName</a> - $script:Tagline</p>")
    [void]$sb.AppendLine('</footer>')
    
    [void]$sb.AppendLine('</div></body></html>')
    
    return $sb.ToString()
}
#endregion

#region Main Execution
Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  SharePoint Online Migration Readiness Assessment" -ForegroundColor Cyan
Write-Host "  $script:CompanyName - $script:Tagline" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor DarkGray
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

# Scan each path
foreach ($scanPath in $validPaths) {
    Write-Host ""
    Write-Log "Starting scan of: $scanPath" -Level Info
    Write-Log "Max depth: $MaxDepth, Include permissions: $IncludePermissions" -Level Debug
    Start-MigrationScan -ScanPath $scanPath
    Write-Log "Scanned $script:TotalFiles files and $script:TotalFolders folders" -Level Success
}

# Generate reports
Write-Host ""
Write-Log "Generating reports..." -Level Info

$baseFileName = "SPOMigrationReadiness_$script:Timestamp"

# HTML Report
$htmlPath = Join-Path -Path $OutputPath -ChildPath "$baseFileName.html"
$htmlContent = Get-HTMLReport
$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Log "HTML report: $htmlPath" -Level Success

# CSV exports
$csvExports = @{
    "PathLengthIssues" = $script:PathLengthIssues
    "InvalidCharacters" = $script:InvalidCharIssues
    "RestrictedNames" = $script:RestrictedNameIssues
    "LegacyOfficeFiles" = $script:LegacyOfficeFiles
    "BlockedFiles" = $script:BlockedFiles
    "FolderItemCounts" = $script:FolderItemCounts
    "LargeFiles" = $script:LargeFiles
}

foreach ($key in $csvExports.Keys) {
    $data = $csvExports[$key]
    if ($data.Count -gt 0) {
        $csvPath = Join-Path -Path $OutputPath -ChildPath "${baseFileName}_${key}.csv"
        $data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV export: $key - $($data.Count) items" -Level Debug
    }
}

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  Scan Complete" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor DarkGray

Write-Host "  Files Scanned: " -NoNewline -ForegroundColor Gray
Write-Host $script:TotalFiles.ToString('N0') -ForegroundColor White
Write-Host "  Folders Scanned: " -NoNewline -ForegroundColor Gray
Write-Host $script:TotalFolders.ToString('N0') -ForegroundColor White
Write-Host "  Total Size: " -NoNewline -ForegroundColor Gray
Write-Host (Format-FileSize -Bytes $script:TotalSize) -ForegroundColor White
Write-Host "  Path Length Issues: " -NoNewline -ForegroundColor Gray
Write-Host $script:PathLengthIssues.Count -ForegroundColor White
Write-Host "  Invalid Characters: " -NoNewline -ForegroundColor Gray
Write-Host $script:InvalidCharIssues.Count -ForegroundColor White
Write-Host "  Restricted Names: " -NoNewline -ForegroundColor Gray
Write-Host $script:RestrictedNameIssues.Count -ForegroundColor White
Write-Host "  Legacy Office Files: " -NoNewline -ForegroundColor Gray
Write-Host $script:LegacyOfficeFiles.Count -ForegroundColor White
Write-Host "  Blocked Files: " -NoNewline -ForegroundColor Gray
Write-Host $script:BlockedFiles.Count -ForegroundColor White
Write-Host "  Large Files: " -NoNewline -ForegroundColor Gray
Write-Host $script:LargeFiles.Count -ForegroundColor White
Write-Host "  Folder Threshold Issues: " -NoNewline -ForegroundColor Gray
Write-Host $script:FolderItemCounts.Count -ForegroundColor White
Write-Host ""
Write-Host "  Report saved to: " -NoNewline -ForegroundColor Gray
Write-Host $htmlPath -ForegroundColor Cyan
Write-Host ""
#endregion
