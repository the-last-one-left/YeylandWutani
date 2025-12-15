<#
.SYNOPSIS
    Removes empty folders in depth-first order (handles nested empty folders in one pass).

.DESCRIPTION
    Scans a directory tree for empty folders and removes them in the correct order to handle
    cascading empty folder hierarchies. For example, if C:\1\2\3 are all empty, all three
    folders are removed in a single pass by processing deepest folders first.
    
    This is useful for:
    - Cleaning up after file migrations or moves
    - Removing empty folder structures from backups
    - Tidying up project directories
    - Post-ransomware cleanup folder structures
    - General filesystem housekeeping

.PARAMETER Path
    Root path to scan for empty folders. Can be a local drive or network share.

.PARAMETER ExcludePaths
    Path patterns to exclude from scanning (supports wildcards).
    Default excludes Windows, Program Files, and system folders.

.PARAMETER Action
    Action to perform:
    - Report: Show what would be deleted (default)
    - Delete: Actually remove empty folders

.PARAMETER Interactive
    Prompt for confirmation before deleting folders.

.PARAMETER LogPath
    Custom log file path. Defaults to script directory.

.PARAMETER ShowProgress
    Display progress bar during scan.

.EXAMPLE
    .\Remove-EmptyFolders.ps1 -Path "D:\Data"
    Scan D:\Data and show report of empty folders (no deletion).

.EXAMPLE
    .\Remove-EmptyFolders.ps1 -Path "D:\Data" -Action Delete
    Remove all empty folders from D:\Data in one pass.

.EXAMPLE
    .\Remove-EmptyFolders.ps1 -Path "C:\Projects" -Action Delete -Interactive
    Remove empty folders with confirmation prompts.

.EXAMPLE
    .\Remove-EmptyFolders.ps1 -Path "\\fileserver\data" -ExcludePaths @('*\Archive\*','*\Temp\*')
    Scan file server, excluding specific paths.

.EXAMPLE
    .\Remove-EmptyFolders.ps1 -Path "E:\Backup" -Action Delete -WhatIf
    Preview what would be deleted without making changes.

.NOTES
    Author: yourname
    Requires: PowerShell 5.1 or later
    Version: 1.1
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$Path,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePaths = @(
        '*\Windows\*',
        '*\Program Files\*',
        '*\Program Files (x86)\*',
        '*\ProgramData\*',
        '*\$Recycle.Bin\*',
        '*\System Volume Information\*',
        '*\Recovery\*',
        '*\WindowsApps\*'
    ),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Report', 'Delete')]
    [string]$Action = 'Report',
    
    [Parameter(Mandatory = $false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = $PSScriptRoot,
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowProgress
)

#region Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes timestamped log entries to file and console with color coding.
    #>
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $logEntry = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $script:logFile -Value $logEntry
    
    switch ($Level) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor Gray }
    }
}

function Test-ShouldExclude {
    <#
    .SYNOPSIS
        Checks if a folder path matches any exclusion pattern.
    #>
    param([string]$FolderPath)
    
    foreach ($pattern in $ExcludePaths) {
        if ($FolderPath -like $pattern) {
            return $true
        }
    }
    return $false
}

function Get-FolderDepth {
    <#
    .SYNOPSIS
        Returns the depth of a folder path based on path separator count.
    #>
    param([string]$FolderPath)
    
    return ($FolderPath.ToCharArray() | Where-Object { $_ -eq '\' -or $_ -eq '/' }).Count
}

#endregion Functions

#region Main Execution

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:logFile = Join-Path $LogPath "EmptyFolderCleanup_$timestamp.log"

try {
    Write-Host "`n========================================================" -ForegroundColor DarkGray
    Write-Host "  Empty Folder Cleanup Tool" -ForegroundColor Cyan
    Write-Host "========================================================`n" -ForegroundColor DarkGray
    
    Write-Log "=== Empty Folder Cleanup Started ==="
    Write-Log "Scan Path: $Path"
    Write-Log "Action: $Action"
    Write-Log "Log File: $script:logFile"
    
    # Phase 1: Scan for all folders
    Write-Host "[Phase 1] Scanning directory tree..." -ForegroundColor Cyan
    Write-Log "Collecting all directories..."
    
    $allFolders = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue
    $totalFolders = $allFolders.Count
    
    Write-Log "Found $totalFolders total folders to evaluate"
    
    # Phase 2: Identify empty folders
    Write-Host "[Phase 2] Identifying empty folders..." -ForegroundColor Cyan
    
    $emptyFolders = @()
    $currentFolder = 0
    
    foreach ($folder in $allFolders) {
        $currentFolder++
        
        if ($ShowProgress) {
            $percentComplete = [math]::Round(($currentFolder / $totalFolders) * 100)
            Write-Progress -Activity "Scanning Folders" -Status "Checking: $($folder.Name)" -PercentComplete $percentComplete
        }
        
        # Skip excluded paths
        if (Test-ShouldExclude -FolderPath $folder.FullName) {
            continue
        }
        
        # Check if truly empty (no files anywhere in subdirectories)
        try {
            $hasFiles = $folder.GetFiles("*", "AllDirectories").Count -gt 0
            
            if (-not $hasFiles) {
                $emptyFolders += $folder
            }
        }
        catch {
            Write-Log "Unable to check folder: $($folder.FullName) - $($_.Exception.Message)" -Level WARNING
        }
    }
    
    if ($ShowProgress) {
        Write-Progress -Activity "Scanning Folders" -Completed
    }
    
    Write-Log "Found $($emptyFolders.Count) empty folders"
    
    if ($emptyFolders.Count -eq 0) {
        Write-Host "`nNo empty folders found!" -ForegroundColor Green
        Write-Log "=== Empty Folder Cleanup Completed - Nothing to clean ==="
        exit 0
    }
    
    # Phase 3: Sort by depth (deepest first) - critical for cascading deletes
    Write-Host "[Phase 3] Sorting folders by depth (deepest first)..." -ForegroundColor Cyan
    
    $sortedFolders = $emptyFolders | Sort-Object -Property @{
        Expression = { Get-FolderDepth -FolderPath $_.FullName }
    } -Descending
    
    # Calculate depth statistics
    $depthStats = $sortedFolders | Group-Object -Property { Get-FolderDepth -FolderPath $_.FullName } | 
        Sort-Object -Property Name -Descending
    
    Write-Log "Depth distribution:"
    foreach ($depthGroup in $depthStats) {
        Write-Log "  Depth $($depthGroup.Name): $($depthGroup.Count) folders"
    }
    
    # Display summary
    Write-Host "`n------------------ Scan Results ------------------" -ForegroundColor DarkGray
    Write-Host "Empty Folders Found:  " -NoNewline -ForegroundColor Gray
    Write-Host "$($sortedFolders.Count)" -ForegroundColor $(if ($sortedFolders.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "Deepest Level:        " -NoNewline -ForegroundColor Gray
    Write-Host "$($depthStats[0].Name)" -ForegroundColor Cyan
    Write-Host "Shallowest Level:     " -NoNewline -ForegroundColor Gray
    Write-Host "$($depthStats[-1].Name)" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------" -ForegroundColor DarkGray
    
    # Show sample of deepest folders
    Write-Host "`nSample of empty folders (deepest first):" -ForegroundColor Cyan
    $sampleFolders = $sortedFolders | Select-Object -First 10
    foreach ($folder in $sampleFolders) {
        $depth = Get-FolderDepth -FolderPath $folder.FullName
        Write-Host "  [Depth $depth] " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($folder.FullName)" -ForegroundColor Gray
    }
    
    if ($sortedFolders.Count -gt 10) {
        Write-Host "  ... and $($sortedFolders.Count - 10) more folders" -ForegroundColor DarkGray
    }
    
    # Phase 4: Perform deletion if requested
    if ($Action -eq 'Delete') {
        Write-Host "`n[Phase 4] Removing empty folders..." -ForegroundColor Cyan
        
        if ($Interactive) {
            Write-Host "`nYou are about to delete $($sortedFolders.Count) empty folders." -ForegroundColor Yellow
            $response = Read-Host "Do you want to proceed? (Y/N)"
            
            if ($response -ne 'Y') {
                Write-Log "User cancelled deletion" -Level WARNING
                exit 0
            }
        }
        
        $deletedCount = 0
        $failedCount = 0
        $currentFolder = 0
        
        foreach ($folder in $sortedFolders) {
            $currentFolder++
            
            if ($ShowProgress) {
                $percentComplete = [math]::Round(($currentFolder / $sortedFolders.Count) * 100)
                Write-Progress -Activity "Deleting Empty Folders" -Status "Removing: $($folder.Name)" -PercentComplete $percentComplete
            }
            
            if ($PSCmdlet.ShouldProcess($folder.FullName, "Remove empty folder")) {
                try {
                    Remove-Item -Path $folder.FullName -Force -ErrorAction Stop
                    Write-Log "Deleted: $($folder.FullName)" -Level SUCCESS
                    $deletedCount++
                }
                catch {
                    Write-Log "Failed to delete $($folder.FullName): $($_.Exception.Message)" -Level ERROR
                    $failedCount++
                }
            }
        }
        
        if ($ShowProgress) {
            Write-Progress -Activity "Deleting Empty Folders" -Completed
        }
        
        # Summary
        Write-Host "`n------------------ Cleanup Summary ------------------" -ForegroundColor DarkGray
        Write-Log "Total empty folders found: $($sortedFolders.Count)"
        Write-Log "Successfully deleted: $deletedCount" -Level SUCCESS
        
        if ($failedCount -gt 0) {
            Write-Log "Failed deletions: $failedCount" -Level ERROR
        }
        
        Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
        
        # Verify cleanup
        if ($deletedCount -eq $sortedFolders.Count) {
            Write-Host "`n[OK] All empty folders removed successfully!" -ForegroundColor Green
        }
        elseif ($deletedCount -gt 0) {
            Write-Host "`n[WARN] Partial cleanup completed. Check log for errors." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`n[Report Mode] No folders were deleted. Use '-Action Delete' to remove them." -ForegroundColor Yellow
    }
    
    Write-Log "=== Empty Folder Cleanup Completed ==="
    Write-Host "Log file: $script:logFile" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}

#endregion Main Execution
