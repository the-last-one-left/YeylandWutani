<#
.SYNOPSIS
    Advanced duplicate file detection and management tool with hash-based verification.

.DESCRIPTION
    Identifies duplicate files using cryptographic hash comparison (MD5 or SHA256) rather than 
    just file size. Provides multiple handling options including reporting, deletion, moving, 
    or creating hardlinks. Supports both interactive GUI mode and parameter-based automation.
    
    Features:
    - True duplicate detection via file hashing (MD5/SHA256)
    - Multiple action modes: Report, Delete, Move, Hardlink
    - Size-based filtering (min/max thresholds)
    - Path exclusion patterns
    - Multiple export formats (CSV, HTML, JSON)
    - Parallel processing on PowerShell 7+ (falls back to sequential on 5.1)
    - Interactive deletion prompts with preview
    - Comprehensive logging and statistics
    - WhatIf support for safe testing

.PARAMETER Path
    Directory path to scan for duplicates. If not specified, shows GUI folder picker.

.PARAMETER HashAlgorithm
    Hashing algorithm to use: MD5 (faster) or SHA256 (more secure). Default is SHA256.

.PARAMETER Action
    Action to perform on duplicates:
    - Report: Generate report only (default)
    - Delete: Remove duplicate files (keeps oldest or newest based on -KeepNewest)
    - Move: Move duplicates to specified folder
    - Hardlink: Replace duplicates with hardlinks to save space

.PARAMETER DestinationPath
    Target path for Move or Hardlink actions.

.PARAMETER MinFileSize
    Minimum file size in bytes to consider. Default is 1 byte (skip empty files).

.PARAMETER MaxFileSize
    Maximum file size in bytes to consider. Useful for excluding very large files.

.PARAMETER ExcludeExtensions
    File extensions to exclude from scanning (e.g., .tmp, .log).

.PARAMETER ExcludePaths
    Path patterns to exclude (supports wildcards).

.PARAMETER KeepNewest
    When deleting duplicates, keep the newest file instead of oldest.

.PARAMETER ExportFormat
    Report format: CSV, HTML, or JSON. Default is CSV.

.PARAMETER ExportPath
    Path for export report. If not specified, shows save dialog.

.PARAMETER Interactive
    Prompt before deleting each duplicate file.

.PARAMETER UseGUI
    Force GUI mode for folder/file selection even when parameters provided.

.PARAMETER ThrottleLimit
    Number of parallel threads for hash calculation (PS7+ only). Default is 8.

.PARAMETER LogPath
    Custom log file path. Defaults to script directory.

.PARAMETER Recurse
    Scan subdirectories recursively. Default is true.

.EXAMPLE
    .\Find-DuplicateFiles.ps1
    Interactive mode with GUI folder picker and save dialog.

.EXAMPLE
    .\Find-DuplicateFiles.ps1 -Path "D:\Photos" -ExportPath "C:\Reports\Duplicates.csv"
    Scan photos directory and export report to specified path.

.EXAMPLE
    .\Find-DuplicateFiles.ps1 -Path "D:\Data" -Action Delete -KeepNewest -Interactive
    Find duplicates and interactively delete older copies.

.EXAMPLE
    .\Find-DuplicateFiles.ps1 -Path "D:\Files" -Action Move -DestinationPath "D:\Duplicates"
    Move all duplicates to separate folder for review.

.EXAMPLE
    .\Find-DuplicateFiles.ps1 -Path "E:\Media" -MinFileSize 1MB -MaxFileSize 100MB -HashAlgorithm MD5
    Find duplicates between 1-100MB using faster MD5 hashing.

.EXAMPLE
    .\Find-DuplicateFiles.ps1 -Path "C:\Users" -ExcludeExtensions @('.tmp','.log') -ExcludePaths @('*\AppData\*','*\Temp\*')
    Scan with exclusions for temp files and specific paths.

.EXAMPLE
    .\Find-DuplicateFiles.ps1 -Path "D:\Archive" -Action Hardlink -DestinationPath "D:\Master" -WhatIf
    Preview hardlink operation without making changes.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: PowerShell 5.1 or later
    Version: 2.1
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='Report')]
param(
    [Parameter(Mandatory=$false)]
    [string]$Path,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('MD5','SHA256')]
    [string]$HashAlgorithm = 'SHA256',
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Report','Delete','Move','Hardlink')]
    [string]$Action = 'Report',
    
    [Parameter(Mandatory=$false, ParameterSetName='Move')]
    [Parameter(Mandatory=$false, ParameterSetName='Hardlink')]
    [string]$DestinationPath,
    
    [Parameter(Mandatory=$false)]
    [long]$MinFileSize = 1,
    
    [Parameter(Mandatory=$false)]
    [long]$MaxFileSize,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeExtensions,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludePaths,
    
    [Parameter(Mandatory=$false)]
    [switch]$KeepNewest,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('CSV','HTML','JSON')]
    [string]$ExportFormat = 'CSV',
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseGUI,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,32)]
    [int]$ThrottleLimit = 8,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse = $true
)

#Requires -Version 5.1

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "DuplicateFinder_$timestamp.log"

# Detect PowerShell version for parallel processing support
$script:CanUseParallel = $PSVersionTable.PSVersion.Major -ge 7

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $logEntry = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor Gray }
    }
}

function Get-FolderGUI {
    param([string]$Description = "Select folder to scan for duplicates")
    
    Add-Type -AssemblyName System.Windows.Forms
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = $Description
    $folderBrowser.RootFolder = 'MyComputer'
    
    if ($folderBrowser.ShowDialog() -eq 'OK') {
        return $folderBrowser.SelectedPath
    }
    return $null
}

function Get-SaveFileGUI {
    param([string]$Filter = "CSV Files (*.csv)|*.csv|HTML Files (*.html)|*.html|JSON Files (*.json)|*.json")
    
    Add-Type -AssemblyName System.Windows.Forms
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = $Filter
    $saveDialog.DefaultExt = $ExportFormat.ToLower()
    
    if ($saveDialog.ShowDialog() -eq 'OK') {
        return $saveDialog.FileName
    }
    return $null
}

function Get-FileHashSequential {
    <#
    .SYNOPSIS
        Sequential file hashing for PowerShell 5.1 compatibility.
    #>
    param(
        [System.IO.FileInfo[]]$Files,
        [string]$Algorithm
    )
    
    $results = [System.Collections.Generic.List[PSObject]]::new()
    $currentFile = 0
    $totalFiles = $Files.Count
    
    foreach ($file in $Files) {
        $currentFile++
        $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100)
        Write-Progress -Activity "Calculating file hashes" -Status "Processing: $($file.Name)" -PercentComplete $percentComplete -CurrentOperation "$currentFile of $totalFiles files"
        
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm $Algorithm -ErrorAction Stop
            $results.Add([PSCustomObject]@{
                FullName = $file.FullName
                Name = $file.Name
                Directory = $file.DirectoryName
                Size = $file.Length
                Hash = $hash.Hash
                Created = $file.CreationTime
                Modified = $file.LastWriteTime
                Extension = $file.Extension
            })
        } catch {
            Write-Warning "Failed to hash $($file.FullName): $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Calculating file hashes" -Completed
    return $results
}

function Get-FileHashParallel {
    <#
    .SYNOPSIS
        Parallel file hashing for PowerShell 7+. Falls back to sequential on PS 5.1.
    #>
    param(
        [System.IO.FileInfo[]]$Files,
        [string]$Algorithm
    )
    
    # Use sequential processing on PowerShell 5.1
    if (-not $script:CanUseParallel) {
        Write-Log "Using sequential processing (PowerShell $($PSVersionTable.PSVersion))"
        return Get-FileHashSequential -Files $Files -Algorithm $Algorithm
    }
    
    Write-Log "Using parallel processing with $ThrottleLimit threads (PowerShell $($PSVersionTable.PSVersion))"
    
    # PowerShell 7+ parallel processing
    $results = $Files | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $file = $_
        $algo = $using:Algorithm
        
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm $algo -ErrorAction Stop
            [PSCustomObject]@{
                FullName = $file.FullName
                Name = $file.Name
                Directory = $file.DirectoryName
                Size = $file.Length
                Hash = $hash.Hash
                Created = $file.CreationTime
                Modified = $file.LastWriteTime
                Extension = $file.Extension
            }
        } catch {
            Write-Warning "Failed to hash $($file.FullName): $($_.Exception.Message)"
            $null
        }
    }
    
    return $results | Where-Object { $_ -ne $null }
}

function Format-FileSize {
    param([long]$Bytes)
    
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    elseif ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    else { return "$Bytes bytes" }
}

function Export-DuplicateReport {
    param(
        [object[]]$Duplicates,
        [string]$Path,
        [string]$Format
    )
    
    switch ($Format) {
        'CSV' {
            $Duplicates | Export-Csv -Path $Path -NoTypeInformation
            Write-Log "CSV report exported to: $Path" -Level SUCCESS
        }
        'JSON' {
            $Duplicates | ConvertTo-Json -Depth 3 | Out-File -FilePath $Path -Encoding utf8
            Write-Log "JSON report exported to: $Path" -Level SUCCESS
        }
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Duplicate Files Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #FF6600; }
        .summary { background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .duplicate-group { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #FF6600; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .file-item { padding: 8px; margin: 5px 0; background: #f9f9f9; border-radius: 3px; }
        .hash { color: #666; font-family: monospace; font-size: 0.9em; }
        .size { color: #FF6600; font-weight: bold; }
        .path { color: #333; word-break: break-all; }
        .footer { margin-top: 20px; text-align: center; color: #999; }
    </style>
</head>
<body>
    <h1>Duplicate Files Report</h1>
    <div class="summary">
        <strong>Scan Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>Source Path:</strong> $Path<br>
        <strong>Hash Algorithm:</strong> $HashAlgorithm<br>
        <strong>Total Duplicate Sets:</strong> $($Duplicates.DuplicateSet | Select-Object -Unique | Measure-Object).Count<br>
        <strong>Total Duplicate Files:</strong> $($Duplicates.Count)<br>
        <strong>Potential Space Savings:</strong> $(Format-FileSize -Bytes ($Duplicates | Where-Object { $_.IsDuplicate } | Measure-Object -Property Size -Sum).Sum)
    </div>
"@
            
            $groupedDuplicates = $Duplicates | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
            
            foreach ($group in $groupedDuplicates) {
                $html += "<div class='duplicate-group'>"
                $html += "<div class='hash'>Hash: $($group.Name)</div>"
                $html += "<div class='size'>Size: $(Format-FileSize -Bytes $group.Group[0].Size) x $($group.Count) files</div>"
                
                foreach ($file in ($group.Group | Sort-Object -Property FullName)) {
                    $html += "<div class='file-item'>"
                    $html += "<div class='path'>$($file.FullName)</div>"
                    $html += "<small>Modified: $($file.Modified) | Created: $($file.Created)</small>"
                    $html += "</div>"
                }
                
                $html += "</div>"
            }
            
            $html += "<div class='footer'>Generated by Yeyland Wutani - Building Better Systems</div>"
            $html += "</body></html>"
            
            $html | Out-File -FilePath $Path -Encoding utf8
            Write-Log "HTML report exported to: $Path" -Level SUCCESS
        }
    }
}

function Remove-DuplicateFiles {
    param(
        [object[]]$Duplicates,
        [bool]$KeepNewest,
        [bool]$Interactive
    )
    
    $groupedDuplicates = $Duplicates | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
    $deletedCount = 0
    $savedSpace = 0
    
    foreach ($group in $groupedDuplicates) {
        $sortProperty = if ($KeepNewest) { 'Modified' } else { 'Created' }
        $files = $group.Group | Sort-Object -Property $sortProperty -Descending
        $keepFile = $files[0]
        $deleteFiles = @($files | Select-Object -Skip 1)
        
        Write-Host "`nDuplicate Set (Hash: $($group.Name)):" -ForegroundColor DarkYellow
        Write-Host "  KEEPING: $($keepFile.FullName)" -ForegroundColor Green
        
        foreach ($file in $deleteFiles) {
            Write-Host "  DELETE:  $($file.FullName)" -ForegroundColor Red
            
            if ($Interactive) {
                $response = Read-Host "Delete this file? (Y/N)"
                if ($response -ne 'Y') {
                    Write-Log "Skipped: $($file.FullName)" -Level WARNING
                    continue
                }
            }
            
            if ($PSCmdlet.ShouldProcess($file.FullName, "Delete duplicate file")) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Log "Deleted: $($file.FullName)" -Level SUCCESS
                    $deletedCount++
                    $savedSpace += $file.Size
                } catch {
                    Write-Log "Failed to delete $($file.FullName): $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }
    
    return @{
        DeletedCount = $deletedCount
        SavedSpace = $savedSpace
    }
}

function Move-DuplicateFiles {
    param(
        [object[]]$Duplicates,
        [string]$Destination
    )
    
    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
        Write-Log "Created destination folder: $Destination"
    }
    
    $groupedDuplicates = $Duplicates | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
    $movedCount = 0
    
    foreach ($group in $groupedDuplicates) {
        $files = $group.Group | Sort-Object -Property Created
        $duplicateFiles = @($files | Select-Object -Skip 1)
        
        foreach ($file in $duplicateFiles) {
            if ($PSCmdlet.ShouldProcess($file.FullName, "Move to $Destination")) {
                try {
                    $destFile = Join-Path $Destination $file.Name
                    
                    if (Test-Path $destFile) {
                        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                        $extension = $file.Extension
                        $destFile = Join-Path $Destination "$baseName`_$(Get-Random)$extension"
                    }
                    
                    Move-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction Stop
                    Write-Log "Moved: $($file.FullName) -> $destFile" -Level SUCCESS
                    $movedCount++
                } catch {
                    Write-Log "Failed to move $($file.FullName): $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }
    
    return $movedCount
}

function New-HardlinkForDuplicates {
    param(
        [object[]]$Duplicates,
        [string]$MasterPath
    )
    
    if (-not (Test-Path $MasterPath)) {
        New-Item -Path $MasterPath -ItemType Directory -Force | Out-Null
    }
    
    $groupedDuplicates = $Duplicates | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
    $linkedCount = 0
    $savedSpace = 0
    
    foreach ($group in $groupedDuplicates) {
        $files = $group.Group | Sort-Object -Property Created
        $masterFile = $files[0]
        $duplicateFiles = @($files | Select-Object -Skip 1)
        
        foreach ($file in $duplicateFiles) {
            if ($PSCmdlet.ShouldProcess($file.FullName, "Create hardlink to $($masterFile.FullName)")) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    
                    $result = cmd /c mklink /H "`"$($file.FullName)`"" "`"$($masterFile.FullName)`"" 2>&1
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "Hardlinked: $($file.FullName) -> $($masterFile.FullName)" -Level SUCCESS
                        $linkedCount++
                        $savedSpace += $file.Size
                    } else {
                        Write-Log "Failed to create hardlink for $($file.FullName): $result" -Level ERROR
                    }
                } catch {
                    Write-Log "Failed to hardlink $($file.FullName): $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }
    
    return @{
        LinkedCount = $linkedCount
        SavedSpace = $savedSpace
    }
}

# Main execution
try {
    Write-Host "`n+------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "|   " -ForegroundColor DarkGray -NoNewline
    Write-Host "Yeyland Wutani" -ForegroundColor DarkYellow -NoNewline
    Write-Host " - Duplicate File Finder              |" -ForegroundColor DarkGray
    Write-Host "|   Building Better Systems                              |" -ForegroundColor DarkGray
    Write-Host "+------------------------------------------------------------+`n" -ForegroundColor DarkGray
    
    Write-Log "=== Duplicate File Finder Started ==="
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Log "Parallel Processing: $(if ($script:CanUseParallel) { 'Available' } else { 'Not available (requires PS 7+)' })"
    
    # Get scan path
    if ([string]::IsNullOrWhiteSpace($Path) -or $UseGUI) {
        $Path = Get-FolderGUI
        if ([string]::IsNullOrWhiteSpace($Path)) {
            Write-Log "No folder selected. Exiting." -Level WARNING
            exit 0
        }
    }
    
    if (-not (Test-Path $Path)) {
        Write-Log "Path does not exist: $Path" -Level ERROR
        exit 1
    }
    
    Write-Log "Scanning path: $Path"
    Write-Log "Hash algorithm: $HashAlgorithm"
    Write-Log "Action mode: $Action"
    
    # Validate action-specific parameters
    if ($Action -in @('Move','Hardlink') -and [string]::IsNullOrWhiteSpace($DestinationPath)) {
        Write-Log "DestinationPath required for $Action action" -Level ERROR
        exit 1
    }
    
    # Collect files
    Write-Host "`n[Phase 1] Collecting files..." -ForegroundColor Cyan
    $fileParams = @{
        Path = $Path
        File = $true
        ErrorAction = 'SilentlyContinue'
    }
    if ($Recurse) { $fileParams.Add('Recurse', $true) }
    
    $allFiles = Get-ChildItem @fileParams | Where-Object {
        $file = $_
        
        # Size filters
        if ($file.Length -lt $MinFileSize) { return $false }
        if ($MaxFileSize -and $file.Length -gt $MaxFileSize) { return $false }
        
        # Extension exclusions
        if ($ExcludeExtensions -and $ExcludeExtensions -contains $file.Extension) { return $false }
        
        # Path exclusions
        if ($ExcludePaths) {
            foreach ($pattern in $ExcludePaths) {
                if ($file.FullName -like $pattern) { return $false }
            }
        }
        
        return $true
    }
    
    if ($allFiles.Count -eq 0) {
        Write-Log "No files found matching criteria" -Level WARNING
        exit 0
    }
    
    Write-Log "Found $($allFiles.Count) files to analyze"
    
    # Phase 1: Group by size for quick filtering
    Write-Host "[Phase 2] Grouping by file size..." -ForegroundColor Cyan
    $sizeGroups = $allFiles | Group-Object -Property Length | Where-Object { $_.Count -gt 1 }
    $candidates = @()
    foreach ($group in $sizeGroups) {
        $candidates += $group.Group
    }
    
    Write-Log "Identified $($candidates.Count) files with matching sizes (potential duplicates)"
    
    if ($candidates.Count -eq 0) {
        Write-Log "No potential duplicates found" -Level SUCCESS
        exit 0
    }
    
    # Phase 2: Calculate hashes
    Write-Host "[Phase 3] Calculating file hashes (this may take a while)..." -ForegroundColor Cyan
    if ($script:CanUseParallel) {
        Write-Host "  Using $HashAlgorithm with $ThrottleLimit parallel threads" -ForegroundColor Gray
    } else {
        Write-Host "  Using $HashAlgorithm (sequential mode - PS 5.1)" -ForegroundColor Gray
    }
    
    $hashedFiles = Get-FileHashParallel -Files $candidates -Algorithm $HashAlgorithm
    Write-Log "Successfully hashed $($hashedFiles.Count) files"
    
    # Phase 3: Identify true duplicates
    Write-Host "[Phase 4] Identifying duplicates..." -ForegroundColor Cyan
    $duplicateGroups = $hashedFiles | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
    
    if ($duplicateGroups.Count -eq 0) {
        Write-Log "No true duplicates found (files with matching sizes have different content)" -Level SUCCESS
        exit 0
    }
    
    $allDuplicates = foreach ($group in $duplicateGroups) {
        $files = $group.Group | Sort-Object -Property Created
        for ($i = 0; $i -lt $files.Count; $i++) {
            $files[$i] | Add-Member -NotePropertyName 'DuplicateSet' -NotePropertyValue $group.Name -Force
            $files[$i] | Add-Member -NotePropertyName 'IsDuplicate' -NotePropertyValue ($i -gt 0) -Force
            $files[$i]
        }
    }
    
    $duplicateFileCount = ($allDuplicates | Where-Object { $_.IsDuplicate }).Count
    $wastedSpace = ($allDuplicates | Where-Object { $_.IsDuplicate } | Measure-Object -Property Size -Sum).Sum
    
    # Statistics
    Write-Host "`n" -NoNewline
    Write-Host "=================== Duplicate Analysis ===================" -ForegroundColor DarkGray
    Write-Log "Found $($duplicateGroups.Count) sets of duplicates"
    Write-Log "Total duplicate files: $duplicateFileCount"
    Write-Log "Wasted space: $(Format-FileSize -Bytes $wastedSpace)" -Level WARNING
    Write-Host "===========================================================" -ForegroundColor DarkGray
    
    # Display sample duplicates
    Write-Host "`nSample duplicates:" -ForegroundColor Cyan
    $sampleGroups = $duplicateGroups | Select-Object -First 3
    foreach ($group in $sampleGroups) {
        Write-Host "`n  Hash: $($group.Name)" -ForegroundColor DarkYellow
        Write-Host "  Size: $(Format-FileSize -Bytes $group.Group[0].Size)" -ForegroundColor Gray
        foreach ($file in $group.Group) {
            Write-Host "    -> $($file.FullName)" -ForegroundColor Gray
        }
    }
    
    if ($duplicateGroups.Count -gt 3) {
        Write-Host "`n  ... and $($duplicateGroups.Count - 3) more duplicate sets" -ForegroundColor DarkGray
    }
    
    # Export report
    if ($Action -eq 'Report' -or $Action -ne 'Report') {
        Write-Host "`n[Phase 5] Exporting report..." -ForegroundColor Cyan
        
        if ([string]::IsNullOrWhiteSpace($ExportPath) -or $UseGUI) {
            $ExportPath = Get-SaveFileGUI
            if ([string]::IsNullOrWhiteSpace($ExportPath)) {
                Write-Log "No export path specified" -Level WARNING
            }
        }
        
        if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
            Export-DuplicateReport -Duplicates $allDuplicates -Path $ExportPath -Format $ExportFormat
        }
    }
    
    # Perform action
    if ($Action -ne 'Report') {
        Write-Host "`n[Phase 6] Performing action: $Action..." -ForegroundColor Cyan
        
        switch ($Action) {
            'Delete' {
                $result = Remove-DuplicateFiles -Duplicates $allDuplicates -KeepNewest $KeepNewest -Interactive $Interactive
                Write-Host "`n" -NoNewline
                Write-Host "=================== Deletion Summary =====================" -ForegroundColor DarkGray
                Write-Log "Files deleted: $($result.DeletedCount)" -Level SUCCESS
                Write-Log "Space recovered: $(Format-FileSize -Bytes $result.SavedSpace)" -Level SUCCESS
                Write-Host "===========================================================" -ForegroundColor DarkGray
            }
            'Move' {
                $movedCount = Move-DuplicateFiles -Duplicates $allDuplicates -Destination $DestinationPath
                Write-Log "Files moved: $movedCount" -Level SUCCESS
            }
            'Hardlink' {
                $result = New-HardlinkForDuplicates -Duplicates $allDuplicates -MasterPath $DestinationPath
                Write-Host "`n" -NoNewline
                Write-Host "=================== Hardlink Summary =====================" -ForegroundColor DarkGray
                Write-Log "Hardlinks created: $($result.LinkedCount)" -Level SUCCESS
                Write-Log "Space saved: $(Format-FileSize -Bytes $result.SavedSpace)" -Level SUCCESS
                Write-Host "===========================================================" -ForegroundColor DarkGray
            }
        }
    }
    
    Write-Log "=== Duplicate File Finder Completed ==="
    Write-Log "Full log: $logFile"
    Write-Host ""
    
} catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}
