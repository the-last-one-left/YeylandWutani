<#
.SYNOPSIS
    Converts legacy Word documents (.doc) to modern format (.docx).

.DESCRIPTION
    Batch converts legacy Word 97-2003 (.doc) files to Office Open XML (.docx) format.
    Processes all .doc files in specified directory, creates converted subfolder for originals,
    and provides comprehensive logging of conversion operations. Handles COM automation safely
    with proper cleanup and error handling.

.PARAMETER Path
    Directory path containing .doc files to convert. Defaults to C:\Temp if not specified.

.PARAMETER Recurse
    Process subdirectories recursively. Default is non-recursive.

.PARAMETER KeepOriginal
    Retain original .doc files in place (skip moving to converted folder).

.PARAMETER ShowWord
    Display Word application during conversion. Useful for troubleshooting.

.PARAMETER LogPath
    Custom path for log file. Defaults to script directory.

.PARAMETER WhatIf
    Test mode - shows what would be converted without making changes.

.EXAMPLE
    .\Convert-LegacyWord.ps1
    Converts all .doc files in C:\Temp using defaults.

.EXAMPLE
    .\Convert-LegacyWord.ps1 -Path "D:\Documents" -Recurse -LogPath "C:\Logs"
    Recursively converts all .doc files in D:\Documents and logs to C:\Logs.

.EXAMPLE
    .\Convert-LegacyWord.ps1 -Path "\\server\share" -KeepOriginal -ShowWord
    Converts files on network share, keeps originals, shows Word during conversion.

.EXAMPLE
    .\Convert-LegacyWord.ps1 -WhatIf
    Preview what files would be converted without making changes.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: Word installed, appropriate file permissions
    Version: 2.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$Path = "C:\Temp",
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse,
    
    [Parameter(Mandatory=$false)]
    [switch]$KeepOriginal,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowWord,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = $PSScriptRoot
)

#Requires -Version 5.1

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "WordConversion_$timestamp.log"

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

function Test-WordInstalled {
    try {
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Convert-WordFile {
    param(
        [System.IO.FileInfo]$File,
        [Microsoft.Office.Interop.Word.Application]$WordApp
    )
    
    try {
        $outputPath = $File.FullName -replace '\.doc$', '.docx'
        
        # Check if output already exists
        if (Test-Path $outputPath) {
            Write-Log "Output file already exists: $outputPath" -Level WARNING
            return $false
        }
        
        Write-Log "Converting: $($File.Name)"
        
        # Open document
        $document = $WordApp.Documents.Open($File.FullName)
        
        # Save as .docx format
        $wdFixedFormat = [Microsoft.Office.Interop.Word.WdSaveFormat]::wdFormatXMLDocument
        $document.SaveAs([ref]$outputPath, [ref]$wdFixedFormat)
        $document.Close($false)
        
        Write-Log "Successfully converted to: $outputPath" -Level SUCCESS
        
        # Move original to converted folder if not keeping in place
        if (-not $KeepOriginal) {
            $convertedFolder = Join-Path $File.DirectoryName "converted"
            
            if (-not (Test-Path $convertedFolder)) {
                New-Item -Path $convertedFolder -ItemType Directory -Force | Out-Null
                Write-Log "Created converted folder: $convertedFolder"
            }
            
            $destination = Join-Path $convertedFolder $File.Name
            Move-Item -Path $File.FullName -Destination $destination -Force
            Write-Log "Moved original to: $destination"
        }
        
        return $true
        
    } catch {
        Write-Log "Failed to convert $($File.Name): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

# Main execution
try {
    Write-Host "`n+------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "|   " -ForegroundColor DarkGray -NoNewline
    Write-Host "Yeyland Wutani" -ForegroundColor DarkYellow -NoNewline
    Write-Host " - Legacy Word Converter              |" -ForegroundColor DarkGray
    Write-Host "|   Building Better Systems                              |" -ForegroundColor DarkGray
    Write-Host "+------------------------------------------------------------+`n" -ForegroundColor DarkGray
    
    Write-Log "Starting Word conversion process"
    Write-Log "Source Path: $Path"
    Write-Log "Recurse: $Recurse"
    Write-Log "Keep Original: $KeepOriginal"
    Write-Log "Log File: $logFile"
    
    # Verify Word is installed
    if (-not (Test-WordInstalled)) {
        Write-Log "Word is not installed or not accessible" -Level ERROR
        exit 1
    }
    
    # Find .doc files
    $searchParams = @{
        Path    = $Path
        Filter  = "*.doc"
        File    = $true
    }
    if ($Recurse) { $searchParams.Add('Recurse', $true) }
    
    $docFiles = Get-ChildItem @searchParams | Where-Object { $_.Extension -eq '.doc' }
    
    if ($docFiles.Count -eq 0) {
        Write-Log "No .doc files found in specified path" -Level WARNING
        exit 0
    }
    
    Write-Log "Found $($docFiles.Count) .doc file(s) to convert"
    
    # WhatIf mode
    if ($PSCmdlet.ShouldProcess("$($docFiles.Count) files", "Convert .doc to .docx")) {
        
        # Create Word COM object
        Write-Log "Initializing Word application"
        $word = New-Object -ComObject Word.Application
        $word.Visible = $ShowWord
        $word.DisplayAlerts = [Microsoft.Office.Interop.Word.WdAlertLevel]::wdAlertsNone
        $word.ScreenUpdating = $false
        
        # Process files
        $successCount = 0
        $failCount = 0
        $currentFile = 0
        
        foreach ($file in $docFiles) {
            $currentFile++
            $percentComplete = [math]::Round(($currentFile / $docFiles.Count) * 100)
            Write-Progress -Activity "Converting Word Documents" -Status "Processing $($file.Name)" -PercentComplete $percentComplete
            
            if (Convert-WordFile -File $file -WordApp $word) {
                $successCount++
            } else {
                $failCount++
            }
        }
        
        Write-Progress -Activity "Converting Word Documents" -Completed
        
        # Cleanup
        Write-Log "Cleaning up Word COM objects"
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
        # Summary
        Write-Host "`n" -NoNewline
        Write-Host "=================== Conversion Summary ===================" -ForegroundColor DarkGray
        Write-Log "Total files processed: $($docFiles.Count)"
        Write-Log "Successfully converted: $successCount" -Level SUCCESS
        if ($failCount -gt 0) {
            Write-Log "Failed conversions: $failCount" -Level ERROR
        }
        Write-Log "Log file: $logFile"
        Write-Host "==========================================================`n" -ForegroundColor DarkGray
        
    } else {
        Write-Host "`nWhatIf: Would convert the following files:" -ForegroundColor Cyan
        foreach ($file in $docFiles) {
            Write-Host "  -> $($file.FullName)" -ForegroundColor Gray
        }
    }
    
} catch {
    Write-Log "Critical error in main execution: $($_.Exception.Message)" -Level ERROR
    exit 1
} finally {
    # Final cleanup
    if ($word) {
        try {
            $word.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        } catch {
            # Suppress cleanup errors
        }
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
