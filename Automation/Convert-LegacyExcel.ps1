<#
.SYNOPSIS
    Converts legacy Excel files (.xls) to modern format (.xlsx).

.DESCRIPTION
    Batch converts legacy Excel 97-2003 (.xls) files to Office Open XML (.xlsx) format.
    Processes all .xls files in specified directory, creates converted subfolder for originals,
    and provides comprehensive logging of conversion operations. Handles COM automation safely
    with proper cleanup and error handling.

.PARAMETER Path
    Directory path containing .xls files to convert. Defaults to C:\Temp if not specified.

.PARAMETER Recurse
    Process subdirectories recursively. Default is non-recursive.

.PARAMETER KeepOriginal
    Retain original .xls files in place (skip moving to converted folder).

.PARAMETER ShowExcel
    Display Excel application during conversion. Useful for troubleshooting.

.PARAMETER LogPath
    Custom path for log file. Defaults to script directory.

.PARAMETER WhatIf
    Test mode - shows what would be converted without making changes.

.EXAMPLE
    .\Convert-LegacyExcel.ps1
    Converts all .xls files in C:\Temp using defaults.

.EXAMPLE
    .\Convert-LegacyExcel.ps1 -Path "D:\Documents" -Recurse -LogPath "C:\Logs"
    Recursively converts all .xls files in D:\Documents and logs to C:\Logs.

.EXAMPLE
    .\Convert-LegacyExcel.ps1 -Path "\\server\share" -KeepOriginal -ShowExcel
    Converts files on network share, keeps originals, shows Excel during conversion.

.EXAMPLE
    .\Convert-LegacyExcel.ps1 -WhatIf
    Preview what files would be converted without making changes.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: Excel installed, appropriate file permissions
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
    [switch]$ShowExcel,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = $PSScriptRoot
)

#Requires -Version 5.1

#region Banner
function Show-YWBanner {
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
        "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
    )
    $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
    $border  = "=" * 81
    Write-Host ""
    Write-Host $border -ForegroundColor Gray
    foreach ($line in $logo) { Write-Host $line -ForegroundColor DarkYellow }
    Write-Host ""
    Write-Host $tagline.PadLeft(62) -ForegroundColor Gray
    Write-Host $border -ForegroundColor Gray
    Write-Host ""
}
#endregion Banner

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "ExcelConversion_$timestamp.log"

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

function Test-ExcelInstalled {
    try {
        $excel = New-Object -ComObject Excel.Application -ErrorAction Stop
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Convert-ExcelFile {
    param(
        [System.IO.FileInfo]$File,
        [Microsoft.Office.Interop.Excel.Application]$ExcelApp
    )
    
    try {
        $outputPath = $File.FullName -replace '\.xls$', '.xlsx'
        
        # Check if output already exists
        if (Test-Path $outputPath) {
            Write-Log "Output file already exists: $outputPath" -Level WARNING
            return $false
        }
        
        Write-Log "Converting: $($File.Name)"
        
        # Open workbook
        $workbook = $ExcelApp.Workbooks.Open($File.FullName)
        
        # Save as .xlsx format
        $xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlOpenXMLWorkbook
        $workbook.SaveAs($outputPath, $xlFixedFormat)
        $workbook.Close($false)
        
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
    Show-YWBanner
    Write-Host "  Legacy Excel Converter" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "Starting Excel conversion process"
    Write-Log "Source Path: $Path"
    Write-Log "Recurse: $Recurse"
    Write-Log "Keep Original: $KeepOriginal"
    Write-Log "Log File: $logFile"
    
    # Verify Excel is installed
    if (-not (Test-ExcelInstalled)) {
        Write-Log "Excel is not installed or not accessible" -Level ERROR
        exit 1
    }
    
    # Find .xls files
    $searchParams = @{
        Path    = $Path
        Filter  = "*.xls"
        File    = $true
    }
    if ($Recurse) { $searchParams.Add('Recurse', $true) }
    
    $xlsFiles = Get-ChildItem @searchParams | Where-Object { $_.Extension -eq '.xls' }
    
    if ($xlsFiles.Count -eq 0) {
        Write-Log "No .xls files found in specified path" -Level WARNING
        exit 0
    }
    
    Write-Log "Found $($xlsFiles.Count) .xls file(s) to convert"
    
    # WhatIf mode
    if ($PSCmdlet.ShouldProcess("$($xlsFiles.Count) files", "Convert .xls to .xlsx")) {
        
        # Create Excel COM object
        Write-Log "Initializing Excel application"
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $ShowExcel
        $excel.DisplayAlerts = $false
        $excel.ScreenUpdating = $false
        
        # Process files
        $successCount = 0
        $failCount = 0
        $currentFile = 0
        
        foreach ($file in $xlsFiles) {
            $currentFile++
            $percentComplete = [math]::Round(($currentFile / $xlsFiles.Count) * 100)
            Write-Progress -Activity "Converting Excel Files" -Status "Processing $($file.Name)" -PercentComplete $percentComplete
            
            if (Convert-ExcelFile -File $file -ExcelApp $excel) {
                $successCount++
            } else {
                $failCount++
            }
        }
        
        Write-Progress -Activity "Converting Excel Files" -Completed
        
        # Cleanup
        Write-Log "Cleaning up Excel COM objects"
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
        # Summary
        Write-Host "`n" -NoNewline
        Write-Host "=================== Conversion Summary ===================" -ForegroundColor DarkGray
        Write-Log "Total files processed: $($xlsFiles.Count)"
        Write-Log "Successfully converted: $successCount" -Level SUCCESS
        if ($failCount -gt 0) {
            Write-Log "Failed conversions: $failCount" -Level ERROR
        }
        Write-Log "Log file: $logFile"
        Write-Host "==========================================================`n" -ForegroundColor DarkGray
        
    } else {
        Write-Host "`nWhatIf: Would convert the following files:" -ForegroundColor Cyan
        foreach ($file in $xlsFiles) {
            Write-Host "  -> $($file.FullName)" -ForegroundColor Gray
        }
    }
    
} catch {
    Write-Log "Critical error in main execution: $($_.Exception.Message)" -Level ERROR
    exit 1
} finally {
    # Final cleanup
    if ($excel) {
        try {
            $excel.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        } catch {
            # Suppress cleanup errors
        }
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
