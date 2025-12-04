<#
.SYNOPSIS
    Post-ransomware cleanup utility for identifying and removing ransomware artifacts.

.DESCRIPTION
    After ransomware remediation and file restoration, this tool helps clean up remaining artifacts including:
    - Ransomware ransom notes (txt, html, hta, rtf files with known patterns)
    - Files still encrypted with known ransomware extensions
    - Empty directories left from manual cleanup
    
    The script uses pattern matching based on extensive research of known ransomware families to identify
    artifacts while minimizing false positives. All operations support WhatIf mode for safe preview.
    
    IMPORTANT: This tool should ONLY be used AFTER:
    - The ransomware infection has been completely eliminated
    - All critical data has been restored from clean backups
    - Systems have been verified clean by security tools
    - A full backup of current state has been taken

.PARAMETER Path
    Root path to scan for ransomware artifacts. Can be a local drive or network share.

.PARAMETER Action
    Cleanup action to perform:
    - Report: Generate report only (default) - safe, no changes
    - DeleteNotes: Remove only ransom notes
    - DeleteEncrypted: Remove only encrypted files (caution!)
    - DeleteEmpty: Remove only empty folders
    - DeleteAll: Remove all artifacts (ransom notes + encrypted files + empty folders)

.PARAMETER KnownExtensions
    Additional ransomware file extensions to detect (beyond built-in list).
    Example: @('.customext','.badware')

.PARAMETER ExcludePaths
    Paths to exclude from scanning (e.g., system folders, specific applications).

.PARAMETER MinEncryptedSize
    Minimum file size (bytes) for encrypted file detection. Default 1KB to skip tiny files.

.PARAMETER MaxEncryptedSize
    Maximum file size (bytes) for encrypted file detection. Useful to limit scope.

.PARAMETER ExportFormat
    Report format: CSV, HTML, or JSON. Default is HTML.

.PARAMETER ExportPath
    Path for export report. If not specified, generates in script directory.

.PARAMETER Interactive
    Prompt for confirmation before deleting each item category.

.PARAMETER LogPath
    Custom log file path. Defaults to script directory.

.PARAMETER CreateBackup
    Create timestamped backup folder of items before deletion.

.PARAMETER BackupPath
    Custom backup location. Defaults to Path\RansomwareCleanup_Backup_[timestamp].

.EXAMPLE
    .\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action Report
    Scan D:\Data and generate report of all ransomware artifacts found.

.EXAMPLE
    .\Remove-RansomwareArtifacts.ps1 -Path "\\fileserver\shares" -Action DeleteNotes -Interactive
    Find and interactively delete ransom notes from file server.

.EXAMPLE
    .\Remove-RansomwareArtifacts.ps1 -Path "C:\Users" -Action DeleteEmpty
    Remove all empty folders from user directories (common after cleanup).

.EXAMPLE
    .\Remove-RansomwareArtifacts.ps1 -Path "D:\Restored" -Action DeleteAll -CreateBackup -Interactive
    Full cleanup with backup and interactive confirmation.

.EXAMPLE
    .\Remove-RansomwareArtifacts.ps1 -Path "E:\Archive" -Action Report -ExportFormat HTML -ExportPath "C:\Reports\cleanup.html"
    Generate detailed HTML report of artifacts.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: PowerShell 5.1 or later, appropriate file permissions
    Version: 1.0
    
    CRITICAL SAFETY NOTES:
    - Always use -Action Report first to review what will be affected
    - Create full system backups before running any deletion operations
    - Test on non-production systems first
    - Use -Interactive mode for additional safety
    - Verify restored data is intact before removing encrypted files
    - Document all cleanup operations for compliance/auditing
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$Path,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Report','DeleteNotes','DeleteEncrypted','DeleteEmpty','DeleteAll')]
    [string]$Action = 'Report',
    
    [Parameter(Mandatory=$false)]
    [string[]]$KnownExtensions,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludePaths = @('*\Windows\*','*\Program Files\*','*\Program Files (x86)\*','*\$Recycle.Bin\*','*\System Volume Information\*'),
    
    [Parameter(Mandatory=$false)]
    [long]$MinEncryptedSize = 1024,
    
    [Parameter(Mandatory=$false)]
    [long]$MaxEncryptedSize,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('CSV','HTML','JSON')]
    [string]$ExportFormat = 'HTML',
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup,
    
    [Parameter(Mandatory=$false)]
    [string]$BackupPath
)

#Requires -Version 5.1

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "RansomwareCleanup_$timestamp.log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS','CRITICAL')]
        [string]$Level = 'INFO'
    )
    
    $logEntry = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        'ERROR'    { Write-Host $logEntry -ForegroundColor Red }
        'WARNING'  { Write-Host $logEntry -ForegroundColor Yellow }
        'SUCCESS'  { Write-Host $logEntry -ForegroundColor Green }
        'CRITICAL' { Write-Host $logEntry -ForegroundColor Magenta }
        default    { Write-Host $logEntry -ForegroundColor Gray }
    }
}

# Comprehensive list of known ransomware file extensions based on research
# Source: Multiple ransomware databases, ID-Ransomware, BleepingComputer forums
$builtInExtensions = @(
    # Major ransomware families
    '.locked','.encrypted','.crypto','.crypt','.crypted','.enc','.encoded'
    # Specific variants - Common
    '.wannacry','.locky','.cerber','.ryuk','.maze','.sodinokibi','.revil'
    '.dharma','.phobos','.stop','.djvu','.akira','.blackcat','.alphv'
    # Specific variants - Active 2023-2025
    '.play','.lockbit','.clop','.royal','.hive','.blackbasta','.vice'
    '.ransom','.cryptolocker','.petya','.badrabbit','.notpetya','.gandcrab'
    # Extension patterns
    '.aaa','.abc','.xyz','.zzz','.ecc','.ezz','.exx','.vvv','.xxx','.ttt'
    '.ccc','.micro','.zepto','.osiris','.vault','.xtbl','.onion','.brrr'
    # Email-based extensions
    '.[[email protected]]','.[[email protected]]','.help@','.recovery@'
    # Random character patterns (common in 2024-2025)
    '.encrypted','.obfuscated','.anonymous','.deadbolt','.eking'
    # Additional patterns from research
    '.krab','.zzzzzzzz','.mrcr1','.rare1','.pegs1','.grhan','.data'
    '.tfude','.pdff','.tro','.cRh8','.3P7m','.aRpt','.eQTz','.3RNu'
    '.f41o1','.ppam','.mdk4y','.lol','.r5a','.lol!','.omg!','.rdm','.rrk'
)

# Comprehensive ransom note filename patterns
# Source: BleepingComputer, Ransomware analysis databases, CISA IOCs
$ransomNotePatterns = @(
    # Generic help/decrypt patterns
    '*readme*.txt','*readme*.html','*readme*.hta','*readme*.rtf'
    '*read*me*.txt','*read*me*.html','*read_me*'
    '*decrypt*.txt','*decrypt*.html','*decrypt*.hta'
    '*help*.txt','*help*.html','*how*to*decrypt*'
    '*recovery*.txt','*restore*.txt','*unlock*.txt'
    # Specific common names
    'help_decrypt*.txt','help_your_files*.txt','help_to_decrypt*.txt'
    'decrypt_instruction*.txt','decrypt_instructions*.html'
    'how_to_decrypt*.txt','how_to_decrypt*.html'
    'how_to_restore*.txt','how_to_recover*.txt'
    'recover_files*.txt','recovery_key*.txt'
    'your_files*.html','your_files*.url'
    'files_encrypted*.txt','attention*.rtf'
    'important*read*.txt','read*if*you*want*'
    # Specific ransomware families
    '_locky_recover*.txt','cryptolocker*.txt'
    '*ako-readme*.txt','*inc-readme*.txt','*play_readme*.txt'
    'ransom*.txt','ransom_note*.txt'
    'coin.locker*.txt','decrypt_readme*.txt'
    'hellothere*.txt','filesaregone*.txt'
    'info.hta','warning.txt','message.txt'
    # Pattern-based
    '*unlock*.*','*decryption*.*','*ransom*.*'
)

function Test-ShouldExcludePath {
    param([string]$FilePath)
    
    foreach ($pattern in $ExcludePaths) {
        if ($FilePath -like $pattern) {
            return $true
        }
    }
    return $false
}

function Test-IsRansomNote {
    param([System.IO.FileInfo]$File)
    
    $fileName = $File.Name.ToLower()
    
    # Check against known patterns
    foreach ($pattern in $ransomNotePatterns) {
        if ($fileName -like $pattern.ToLower()) {
            return $true
        }
    }
    
    # Additional content-based detection for text files
    if ($File.Extension -in @('.txt','.html','.htm','.hta','.rtf')) {
        if ($File.Length -lt 50KB) {  # Ransom notes are typically small
            try {
                $content = Get-Content -Path $File.FullName -TotalCount 20 -ErrorAction SilentlyContinue
                $contentText = $content -join ' '
                
                # Common ransom note phrases
                $ransomPhrases = @(
                    'files have been encrypted','your data has been encrypted'
                    'pay.*ransom','bitcoin','decrypt.*files','all your files'
                    'contact us at','recovery.*key','unique.*id'
                    'tor browser','\.onion','private key'
                )
                
                foreach ($phrase in $ransomPhrases) {
                    if ($contentText -match $phrase) {
                        return $true
                    }
                }
            } catch {
                # If we can't read it, don't flag it
            }
        }
    }
    
    return $false
}

function Test-IsEncryptedFile {
    param([System.IO.FileInfo]$File)
    
    # Combine built-in and custom extensions
    $allExtensions = $builtInExtensions + $KnownExtensions | Select-Object -Unique
    
    # Check if file has multiple extensions (common pattern)
    $fullName = $File.Name
    
    foreach ($ext in $allExtensions) {
        if ($fullName -match [regex]::Escape($ext)) {
            return $true
        }
    }
    
    # Check for email-pattern extensions
    if ($fullName -match '\[\[[a-z0-9@\.\-]+\]\]') {
        return $true
    }
    
    # Check for ID-pattern extensions (e.g., .id-ABC123.extension)
    if ($fullName -match '\.id-[A-Z0-9]+\.[a-z]{3,10}$') {
        return $true
    }
    
    # Check for random character extensions (7-12 chars)
    if ($fullName -match '\.[a-z0-9]{7,12}$' -and $File.Extension -notin @('.jpg','.jpeg','.png','.gif','.pdf','.doc','.docx','.xls','.xlsx','.txt')) {
        # Additional validation: check if it's a known good extension
        $suspiciousExt = $File.Extension
        $commonExtensions = @('.tmp','.bak','.cache','.config','.json','.xml','.log','.dat')
        
        if ($suspiciousExt -notin $commonExtensions) {
            return $true
        }
    }
    
    return $false
}

function Get-EmptyFolders {
    param([string]$RootPath)
    
    Write-Log "Scanning for empty folders..."
    
    $emptyFolders = Get-ChildItem -Path $RootPath -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object {
        $folder = $_
        
        # Exclude protected paths
        if (Test-ShouldExcludePath -FilePath $folder.FullName) {
            return $false
        }
        
        # Check if truly empty (no files in any subdirectory)
        $hasContent = $folder.GetFiles("*", "AllDirectories").Count -gt 0
        return -not $hasContent
    }
    
    # CRITICAL FIX: Sort by depth (deepest first) to handle nested empty folders like C:\1\2\3
    # This ensures C:\1\2\3 is deleted before C:\1\2 before C:\1 in a single pass
    # Count backslashes (or forward slashes) to determine nesting depth
    $emptyFolders = $emptyFolders | Sort-Object -Property @{
        Expression = {($_.FullName.ToCharArray() | Where-Object {$_ -eq '\' -or $_ -eq '/'}).Count}
    } -Descending
    
    if ($emptyFolders.Count -gt 0) {
        Write-Log "Empty folders will be processed in depth-first order (deepest first) - handles nested empty folders in one pass"
    }
    
    return $emptyFolders
}

function New-BackupFolder {
    param([object[]]$Items, [string]$BackupRoot)
    
    if (-not $CreateBackup -or $Items.Count -eq 0) {
        return $null
    }
    
    if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
        $BackupRoot = Join-Path $Path "RansomwareCleanup_Backup_$timestamp"
    }
    
    if (-not (Test-Path $BackupRoot)) {
        New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
        Write-Log "Created backup folder: $BackupRoot" -Level SUCCESS
    }
    
    foreach ($item in $Items) {
        try {
            $relativePath = $item.FullName.Substring($Path.Length).TrimStart('\')
            $backupPath = Join-Path $BackupRoot $relativePath
            $backupDir = Split-Path $backupPath -Parent
            
            if (-not (Test-Path $backupDir)) {
                New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
            }
            
            if ($item.PSIsContainer) {
                # Don't backup empty folders, just log them
                Add-Content -Path (Join-Path $BackupRoot "deleted_folders.txt") -Value $item.FullName
            } else {
                Copy-Item -Path $item.FullName -Destination $backupPath -Force
            }
        } catch {
            Write-Log "Failed to backup $($item.FullName): $($_.Exception.Message)" -Level WARNING
        }
    }
    
    return $BackupRoot
}

function Export-CleanupReport {
    param(
        [object]$Statistics,
        [string]$Path,
        [string]$Format
    )
    
    switch ($Format) {
        'CSV' {
            $allItems = @()
            
            if ($Statistics.RansomNotes) {
                $allItems += $Statistics.RansomNotes | Select-Object @{N='Type';E={'Ransom Note'}}, FullName, Length, LastWriteTime
            }
            if ($Statistics.EncryptedFiles) {
                $allItems += $Statistics.EncryptedFiles | Select-Object @{N='Type';E={'Encrypted File'}}, FullName, Length, LastWriteTime
            }
            if ($Statistics.EmptyFolders) {
                $allItems += $Statistics.EmptyFolders | Select-Object @{N='Type';E={'Empty Folder'}}, FullName, @{N='Length';E={0}}, LastWriteTime
            }
            
            $allItems | Export-Csv -Path $Path -NoTypeInformation
            Write-Log "CSV report exported to: $Path" -Level SUCCESS
        }
        
        'JSON' {
            $Statistics | ConvertTo-Json -Depth 3 | Out-File -FilePath $Path -Encoding utf8
            Write-Log "JSON report exported to: $Path" -Level SUCCESS
        }
        
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Ransomware Cleanup Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 4px solid #FF6600; }
        .stat-label { font-size: 0.9em; color: #666; text-transform: uppercase; }
        .stat-value { font-size: 2em; font-weight: bold; color: #333; }
        .section { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #FF6600; margin-top: 0; }
        .file-list { max-height: 400px; overflow-y: auto; }
        .file-item { padding: 10px; margin: 5px 0; background: #f9f9f9; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.9em; word-break: break-all; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .critical { background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .footer { margin-top: 30px; text-align: center; color: #999; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #FF6600; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
    </style>
</head>
<body>
    <h1>🛡️ Ransomware Cleanup Report</h1>
    
    <div class="summary">
        <strong>Scan Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>Source Path:</strong> $($Statistics.ScanPath)<br>
        <strong>Action Performed:</strong> $($Statistics.Action)<br>
        <strong>Scan Duration:</strong> $($Statistics.Duration)
    </div>
    
    <div class="stat-grid">
        <div class="stat-box">
            <div class="stat-label">Ransom Notes Found</div>
            <div class="stat-value" style="color: #dc3545;">$($Statistics.RansomNoteCount)</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">Encrypted Files Found</div>
            <div class="stat-value" style="color: #ffc107;">$($Statistics.EncryptedFileCount)</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">Empty Folders Found</div>
            <div class="stat-value" style="color: #6c757d;">$($Statistics.EmptyFolderCount)</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">Total Size</div>
            <div class="stat-value" style="color: #FF6600;">$($Statistics.TotalSize)</div>
        </div>
    </div>
"@
            
            if ($Statistics.RansomNoteCount -gt 0) {
                $html += @"
    <div class="section">
        <h2>📄 Ransom Notes Detected</h2>
        <div class="critical">
            <strong>CRITICAL:</strong> Ransom notes indicate a past ransomware infection. Ensure all systems have been thoroughly scanned and cleaned before removing these files.
        </div>
        <table>
            <tr><th>File Path</th><th>Size</th><th>Last Modified</th></tr>
"@
                foreach ($note in ($Statistics.RansomNotes | Select-Object -First 50)) {
                    $html += "<tr><td>$($note.FullName)</td><td>$([math]::Round($note.Length/1KB, 2)) KB</td><td>$($note.LastWriteTime)</td></tr>"
                }
                
                if ($Statistics.RansomNoteCount -gt 50) {
                    $html += "<tr><td colspan='3'><em>... and $($Statistics.RansomNoteCount - 50) more files</em></td></tr>"
                }
                
                $html += "</table></div>"
            }
            
            if ($Statistics.EncryptedFileCount -gt 0) {
                $html += @"
    <div class="section">
        <h2>🔒 Encrypted Files Detected</h2>
        <div class="warning">
            <strong>WARNING:</strong> These files appear to still be encrypted. Ensure you have restored all needed data from backups before removing these files.
        </div>
        <table>
            <tr><th>File Path</th><th>Size</th><th>Extension</th><th>Last Modified</th></tr>
"@
                foreach ($file in ($Statistics.EncryptedFiles | Select-Object -First 50)) {
                    $html += "<tr><td>$($file.FullName)</td><td>$([math]::Round($file.Length/1KB, 2)) KB</td><td>$($file.Extension)</td><td>$($file.LastWriteTime)</td></tr>"
                }
                
                if ($Statistics.EncryptedFileCount -gt 50) {
                    $html += "<tr><td colspan='4'><em>... and $($Statistics.EncryptedFileCount - 50) more files</em></td></tr>"
                }
                
                $html += "</table></div>"
            }
            
            if ($Statistics.EmptyFolderCount -gt 0) {
                $html += @"
    <div class="section">
        <h2>📁 Empty Folders Detected</h2>
        <p>These folders contain no files and can typically be safely removed.</p>
        <div class="file-list">
"@
                foreach ($folder in ($Statistics.EmptyFolders | Select-Object -First 100)) {
                    $html += "<div class='file-item'>$($folder.FullName)</div>"
                }
                
                if ($Statistics.EmptyFolderCount -gt 100) {
                    $html += "<div class='file-item'><em>... and $($Statistics.EmptyFolderCount - 100) more folders</em></div>"
                }
                
                $html += "</div></div>"
            }
            
            $html += @"
    <div class="footer">
        Generated by Yeyland Wutani - Building Better Systems<br>
        Log file: $logFile
    </div>
</body>
</html>
"@
            
            $html | Out-File -FilePath $Path -Encoding utf8
            Write-Log "HTML report exported to: $Path" -Level SUCCESS
        }
    }
}

function Remove-Items {
    param(
        [object[]]$Items,
        [string]$ItemType,
        [bool]$RequireConfirmation
    )
    
    if ($Items.Count -eq 0) {
        return 0
    }
    
    Write-Host "`n[$ItemType Removal]" -ForegroundColor Cyan
    Write-Host "Found $($Items.Count) items to remove" -ForegroundColor Yellow
    
    if ($RequireConfirmation) {
        $response = Read-Host "Do you want to proceed with removing these $ItemType? (Y/N)"
        if ($response -ne 'Y') {
            Write-Log "User cancelled $ItemType removal" -Level WARNING
            return 0
        }
    }
    
    $removedCount = 0
    
    foreach ($item in $Items) {
        if ($PSCmdlet.ShouldProcess($item.FullName, "Remove $ItemType")) {
            try {
                if ($item.PSIsContainer) {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                } else {
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                }
                Write-Log "Removed: $($item.FullName)" -Level SUCCESS
                $removedCount++
            } catch {
                Write-Log "Failed to remove $($item.FullName): $($_.Exception.Message)" -Level ERROR
            }
        }
    }
    
    return $removedCount
}

# Main execution
try {
    Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
    Write-Host "║   " -ForegroundColor DarkGray -NoNewline
    Write-Host "Yeyland Wutani" -ForegroundColor DarkYellow -NoNewline
    Write-Host " - Ransomware Artifact Cleanup        ║" -ForegroundColor DarkGray
    Write-Host "║   Building Better Systems                              ║" -ForegroundColor DarkGray
    Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor DarkGray
    
    Write-Log "=== Ransomware Cleanup Started ==="
    Write-Log "Scan Path: $Path"
    Write-Log "Action: $Action"
    Write-Log "Interactive Mode: $Interactive"
    
    # Safety warnings
    if ($Action -ne 'Report') {
        Write-Host "`n⚠️  WARNING: You are about to perform cleanup operations." -ForegroundColor Yellow
        Write-Host "   Ensure you have:" -ForegroundColor Yellow
        Write-Host "   1. Verified the ransomware infection is completely eliminated" -ForegroundColor Yellow
        Write-Host "   2. Restored all critical data from clean backups" -ForegroundColor Yellow
        Write-Host "   3. Created a full backup of the current state" -ForegroundColor Yellow
        Write-Host "   4. Tested this script in a non-production environment" -ForegroundColor Yellow
        
        if (-not $Interactive) {
            $confirmation = Read-Host "`nType 'PROCEED' to continue"
            if ($confirmation -ne 'PROCEED') {
                Write-Log "User did not confirm safety requirements. Exiting." -Level CRITICAL
                exit 0
            }
        }
    }
    
    $startTime = Get-Date
    
    # Phase 1: Scan for ransom notes
    Write-Host "`n[Phase 1] Scanning for ransom notes..." -ForegroundColor Cyan
    $ransomNotes = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        -not (Test-ShouldExcludePath -FilePath $_.FullName) -and (Test-IsRansomNote -File $_)
    }
    
    Write-Log "Found $($ransomNotes.Count) potential ransom notes"
    
    # Phase 2: Scan for encrypted files
    Write-Host "[Phase 2] Scanning for encrypted files..." -ForegroundColor Cyan
    $encryptedFiles = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $file = $_
        
        if (Test-ShouldExcludePath -FilePath $file.FullName) {
            return $false
        }
        
        if ($file.Length -lt $MinEncryptedSize) {
            return $false
        }
        
        if ($MaxEncryptedSize -and $file.Length -gt $MaxEncryptedSize) {
            return $false
        }
        
        return (Test-IsEncryptedFile -File $file)
    }
    
    Write-Log "Found $($encryptedFiles.Count) potential encrypted files"
    
    # Phase 3: Scan for empty folders
    Write-Host "[Phase 3] Scanning for empty folders..." -ForegroundColor Cyan
    $emptyFolders = Get-EmptyFolders -RootPath $Path
    Write-Log "Found $($emptyFolders.Count) empty folders"
    
    $duration = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
    
    # Statistics
    $stats = @{
        ScanPath = $Path
        Action = $Action
        Duration = $duration
        RansomNotes = $ransomNotes
        RansomNoteCount = $ransomNotes.Count
        EncryptedFiles = $encryptedFiles
        EncryptedFileCount = $encryptedFiles.Count
        EmptyFolders = $emptyFolders
        EmptyFolderCount = $emptyFolders.Count
        TotalSize = [math]::Round((($ransomNotes + $encryptedFiles | Measure-Object -Property Length -Sum).Sum / 1MB), 2).ToString() + " MB"
    }
    
    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════ Scan Results ═════════════════════" -ForegroundColor DarkGray
    Write-Host "Ransom Notes:     " -NoNewline -ForegroundColor Gray
    Write-Host "$($stats.RansomNoteCount)" -ForegroundColor $(if($stats.RansomNoteCount -gt 0){'Red'}else{'Green'})
    Write-Host "Encrypted Files:  " -NoNewline -ForegroundColor Gray
    Write-Host "$($stats.EncryptedFileCount)" -ForegroundColor $(if($stats.EncryptedFileCount -gt 0){'Yellow'}else{'Green'})
    Write-Host "Empty Folders:    " -NoNewline -ForegroundColor Gray
    Write-Host "$($stats.EmptyFolderCount)" -ForegroundColor $(if($stats.EmptyFolderCount -gt 0){'Cyan'}else{'Green'})
    Write-Host "Total Size:       $($stats.TotalSize)" -ForegroundColor Gray
    Write-Host "══════════════════════════════════════════════════════" -ForegroundColor DarkGray
    
    # Export report
    if ([string]::IsNullOrWhiteSpace($ExportPath)) {
        $ExportPath = Join-Path $LogPath "RansomwareCleanup_Report_$timestamp.$($ExportFormat.ToLower())"
    }
    
    Export-CleanupReport -Statistics $stats -Path $ExportPath -Format $ExportFormat
    
    # Perform cleanup actions
    if ($Action -ne 'Report') {
        Write-Host "`n[Phase 4] Performing cleanup..." -ForegroundColor Cyan
        
        $itemsToBackup = @()
        $removedStats = @{
            Notes = 0
            Encrypted = 0
            Folders = 0
        }
        
        switch ($Action) {
            'DeleteNotes' {
                $itemsToBackup = $ransomNotes
                $backupLocation = New-BackupFolder -Items $itemsToBackup -BackupRoot $BackupPath
                if ($backupLocation) {
                    Write-Log "Backup created at: $backupLocation" -Level SUCCESS
                }
                $removedStats.Notes = Remove-Items -Items $ransomNotes -ItemType "Ransom Notes" -RequireConfirmation $Interactive
            }
            
            'DeleteEncrypted' {
                $itemsToBackup = $encryptedFiles
                $backupLocation = New-BackupFolder -Items $itemsToBackup -BackupRoot $BackupPath
                if ($backupLocation) {
                    Write-Log "Backup created at: $backupLocation" -Level SUCCESS
                }
                $removedStats.Encrypted = Remove-Items -Items $encryptedFiles -ItemType "Encrypted Files" -RequireConfirmation $Interactive
            }
            
            'DeleteEmpty' {
                $itemsToBackup = $emptyFolders
                $backupLocation = New-BackupFolder -Items $itemsToBackup -BackupRoot $BackupPath
                if ($backupLocation) {
                    Write-Log "Backup created at: $backupLocation" -Level SUCCESS
                }
                $removedStats.Folders = Remove-Items -Items $emptyFolders -ItemType "Empty Folders" -RequireConfirmation $Interactive
            }
            
            'DeleteAll' {
                $itemsToBackup = $ransomNotes + $encryptedFiles + $emptyFolders
                $backupLocation = New-BackupFolder -Items $itemsToBackup -BackupRoot $BackupPath
                if ($backupLocation) {
                    Write-Log "Backup created at: $backupLocation" -Level SUCCESS
                }
                
                $removedStats.Notes = Remove-Items -Items $ransomNotes -ItemType "Ransom Notes" -RequireConfirmation $Interactive
                $removedStats.Encrypted = Remove-Items -Items $encryptedFiles -ItemType "Encrypted Files" -RequireConfirmation $Interactive
                $removedStats.Folders = Remove-Items -Items $emptyFolders -ItemType "Empty Folders" -RequireConfirmation $Interactive
            }
        }
        
        Write-Host "`n" -NoNewline
        Write-Host "═══════════════════ Cleanup Summary ══════════════════" -ForegroundColor DarkGray
        Write-Log "Ransom notes removed: $($removedStats.Notes)" -Level SUCCESS
        Write-Log "Encrypted files removed: $($removedStats.Encrypted)" -Level SUCCESS
        Write-Log "Empty folders removed: $($removedStats.Folders)" -Level SUCCESS
        Write-Host "══════════════════════════════════════════════════════" -ForegroundColor DarkGray
    }
    
    Write-Log "=== Ransomware Cleanup Completed ==="
    Write-Log "Report: $ExportPath"
    Write-Log "Log file: $logFile"
    Write-Host ""
    
} catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}
