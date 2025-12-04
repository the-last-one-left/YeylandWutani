# Automation

PowerShell scripts and frameworks for system provisioning, configuration management, deployment automation, and post-incident cleanup.

## Available Scripts

### Ransomware Cleanup (Post-Remediation)

#### Remove-RansomwareArtifacts.ps1
Post-ransomware cleanup utility for identifying and removing ransomware artifacts after successful remediation.

**⚠️ CRITICAL: Use only AFTER complete remediation and data restoration from clean backups**

**What It Does:**
- Identifies ransom notes using pattern matching (600+ known patterns)
- Detects encrypted files with known ransomware extensions (100+ variants)
- Finds empty folders left from manual cleanup
- Generates comprehensive reports before any changes
- Supports selective or complete cleanup operations

**Key Safety Features:**
- **Report-only mode** (default) - no changes made
- **Interactive confirmations** for additional safety
- **Backup creation** before any deletions
- **WhatIf support** for preview mode
- **Path exclusions** to protect system folders
- **Comprehensive logging** of all operations
- **Multiple confirmation layers** for destructive operations

**Ransomware Families Detected:**
Based on extensive research from CISA, BleepingComputer, ID-Ransomware, and r/sysadmin community knowledge:
- LockBit, REvil/Sodinokibi, Ryuk, Maze, Conti, BlackCat/ALPHV
- STOP/Djvu, Dharma, Phobos, Akira, Play, Royal, Vice
- WannaCry, Locky, Cerber, CryptoLocker, Petya, NotPetya
- And 80+ additional variants from 2016-2025

**Usage Workflow:**
```powershell
# STEP 1: Always start with a report (no changes)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action Report

# STEP 2: Review the generated HTML report thoroughly

# STEP 3: If safe to proceed, remove ransom notes only (least risk)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteNotes -Interactive -CreateBackup

# STEP 4: Remove empty folders (safe, common after cleanup)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteEmpty

# STEP 5: Only after verifying restored data - remove encrypted files
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteEncrypted -Interactive -CreateBackup

# ALTERNATIVE: Full cleanup in one operation (use with extreme caution)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteAll -Interactive -CreateBackup
```

**Real-World Scenarios:**

**Scenario 1: File Server Post-Restore**
```powershell
# After restoring from backup, clean up remnants
.\Remove-RansomwareArtifacts.ps1 `
    -Path "\\fileserver\shares" `
    -Action Report `
    -ExportFormat HTML `
    -ExportPath "C:\Reports\FileServer_Cleanup.html"

# Review report, then selectively clean
.\Remove-RansomwareArtifacts.ps1 `
    -Path "\\fileserver\shares" `
    -Action DeleteNotes `
    -CreateBackup `
    -BackupPath "\\backup\ransomware_artifacts"
```

**Scenario 2: User Workstation Cleanup**
```powershell
# Clean C:\Users after infection
.\Remove-RansomwareArtifacts.ps1 `
    -Path "C:\Users" `
    -Action DeleteAll `
    -Interactive `
    -ExcludePaths @('*\AppData\*','*\OneDrive\*') `
    -CreateBackup
```

**Scenario 3: Partial Restoration - Find Remaining Encrypted Files**
```powershell
# Identify what still needs restoration
.\Remove-RansomwareArtifacts.ps1 `
    -Path "D:\Documents" `
    -Action Report `
    -MinEncryptedSize 100KB `
    -ExportFormat JSON
```

**Scenario 4: Custom Ransomware Variant**
```powershell
# Add detected extensions not in built-in list
.\Remove-RansomwareArtifacts.ps1 `
    -Path "E:\Archive" `
    -KnownExtensions @('.customext','.newvariant') `
    -Action Report
```

**Report Features:**
- **HTML Report**: Visual display with color-coding, statistics dashboard, file lists
- **CSV Report**: Machine-readable for further analysis or documentation
- **JSON Report**: Structured data for automation or integration

**What Gets Detected:**

**Ransom Notes (Pattern Matching):**
- Generic: readme.txt, decrypt_instructions.html, how_to_recover.txt
- Family-specific: ako-readme.txt, inc-readme.txt, play_readme.txt
- Content-based: Files containing "bitcoin", "encrypted", "ransom", "decrypt"
- Extensions: .txt, .html, .hta, .rtf, .url

**Encrypted Files (Extension Analysis):**
- Known extensions: .locked, .encrypted, .crypto, .wannacry, .ryuk, etc.
- Email patterns: [[email protected]]
- ID patterns: .id-ABC123.extension
- Random character patterns: 7-12 character extensions

**Empty Folders:**
- True empty: No files in folder or any subdirectory
- Safe detection: Excludes system paths, validates recursively

---

### Empty Folder Cleanup

#### Remove-EmptyFolders.ps1
Simple, focused utility for removing empty folders in depth-first order (handles cascading empty folders in one pass).

**The Problem It Solves:**
When you have nested empty folders like `C:\1\2\3`, you want to remove all three folders without multiple passes. This script sorts folders by depth (deepest first) and removes them in the correct order.

**Key Features:**
- **Depth-first deletion** - Handles `C:\1\2\3` structures in one pass
- **Report mode** (default) - See what would be deleted first
- **Smart exclusions** - Automatically skips Windows, Program Files, system folders
- **Progress tracking** - Shows current folder being processed
- **Interactive mode** - Confirm before deletion
- **WhatIf support** - Preview without changes
- **Comprehensive logging** - Detailed operation tracking

**Perfect For:**
- Cleaning up after file migrations or bulk moves
- Post-ransomware cleanup (after restoring from backups)
- Removing empty backup folder structures
- General filesystem housekeeping
- Project directory tidying

**Usage Examples:**
```powershell
# Report mode - see what would be deleted (safe, no changes)
.\Remove-EmptyFolders.ps1 -Path "D:\Data"

# Delete all empty folders in one pass
.\Remove-EmptyFolders.ps1 -Path "D:\Data" -Action Delete

# Interactive deletion with confirmation
.\Remove-EmptyFolders.ps1 -Path "C:\Projects" -Action Delete -Interactive

# Preview with WhatIf
.\Remove-EmptyFolders.ps1 -Path "E:\Archive" -Action Delete -WhatIf

# With progress bar for large scans
.\Remove-EmptyFolders.ps1 -Path "\\fileserver\shares" -Action Delete -ShowProgress

# Exclude specific paths
.\Remove-EmptyFolders.ps1 -Path "D:\Data" -Action Delete -ExcludePaths @('*\KeepThis\*','*\Archive\*')
```

**How Depth-First Works:**
```
Before:
C:\Projects\
  └─ OldProject\
     └─ src\
        └─ backup\ (empty)

Scan finds 3 empty folders:
- C:\Projects\OldProject\src\backup (depth: 5)
- C:\Projects\OldProject\src (depth: 4)
- C:\Projects\OldProject (depth: 3)

Deletes in order:
1. Delete backup\ first
2. Then delete src\
3. Finally delete OldProject\

Result: All 3 folders removed in ONE pass!
```

**Output Example:**
```
═══════════════════ Scan Results ═════════════════════
Empty Folders Found:  47
Deepest Level:        8
Shallowest Level:     3
══════════════════════════════════════════════════════

Sample of empty folders (deepest first):
  [Depth 8] C:\Data\Archive\2023\Q1\Jan\Reports\Temp\Old
  [Depth 7] C:\Data\Archive\2023\Q1\Jan\Reports\Temp
  [Depth 6] C:\Data\Archive\2023\Q1\Jan\Reports
  ... and 44 more folders
```

**Safety Features:**
- Default excludes system folders (Windows, Program Files, etc.)
- Report mode is default (must explicitly choose Delete)
- Interactive confirmations available
- WhatIf support for preview
- Comprehensive logging of all operations
- Detailed error reporting for failed deletions

---

### Duplicate File Management

#### Find-DuplicateFiles.ps1
Advanced duplicate file detection using cryptographic hash comparison (MD5/SHA256) with multiple handling options.

**Key Features:**
- **True duplicate detection** via file hashing (not just size matching)
- **Multiple action modes**: Report, Delete, Move, Hardlink
- **Size filtering**: Min/max file size thresholds
- **Path exclusions**: Skip specific directories or patterns
- **Extension filtering**: Exclude file types from scanning
- **Parallel processing**: Multi-threaded hash calculation (configurable)
- **Export formats**: CSV, HTML (visual reports), JSON
- **Interactive deletion**: Preview and confirm before removing files
- **WhatIf support**: Test operations without making changes
- **GUI or CLI**: Supports both interactive and automated usage
- **Comprehensive logging**: Detailed operation tracking

**Action Modes:**
- **Report**: Generate duplicate report only (default)
- **Delete**: Remove duplicates (keeps oldest or newest based on preference)
- **Move**: Relocate duplicates to separate folder for review
- **Hardlink**: Replace duplicates with hardlinks to save space (NTFS only)

**Usage Examples:**
```powershell
# Interactive GUI mode (folder picker + save dialog)
.\Find-DuplicateFiles.ps1

# Basic scan with CSV report
.\Find-DuplicateFiles.ps1 -Path "D:\Photos" -ExportPath "C:\Reports\Duplicates.csv"

# Delete older duplicates interactively
.\Find-DuplicateFiles.ps1 -Path "D:\Data" -Action Delete -Interactive

# Delete duplicates but keep newest files
.\Find-DuplicateFiles.ps1 -Path "D:\Archive" -Action Delete -KeepNewest

# Move duplicates to review folder
.\Find-DuplicateFiles.ps1 -Path "D:\Files" -Action Move -DestinationPath "D:\Review"

# Create hardlinks to save space (preview mode)
.\Find-DuplicateFiles.ps1 -Path "D:\Media" -Action Hardlink -DestinationPath "D:\Master" -WhatIf

# Advanced filtering
.\Find-DuplicateFiles.ps1 -Path "E:\Data" `
    -MinFileSize 1MB `
    -MaxFileSize 100MB `
    -ExcludeExtensions @('.tmp','.log','.bak') `
    -ExcludePaths @('*\Temp\*','*\Cache\*')

# Fast scanning with MD5 (less secure but faster)
.\Find-DuplicateFiles.ps1 -Path "F:\LargeArchive" -HashAlgorithm MD5 -ThrottleLimit 16

# HTML report with visual grouping
.\Find-DuplicateFiles.ps1 -Path "C:\Users\Public" -ExportFormat HTML -ExportPath "C:\Reports\Duplicates.html"
```

**Performance Tips:**
- Use MD5 for faster scanning of large datasets (SHA256 is more secure but slower)
- Increase ThrottleLimit (up to 32) on systems with many CPU cores
- Apply MinFileSize filters to skip small files (e.g., `-MinFileSize 100KB`)
- Use path exclusions to skip system folders, temp directories, caches

**Space Recovery Examples:**
```powershell
# Find and report wasted space
.\Find-DuplicateFiles.ps1 -Path "D:\UserData" -ExportPath "C:\audit.csv"

# Safe deletion workflow
# 1. Generate report first
.\Find-DuplicateFiles.ps1 -Path "D:\Data" -ExportPath "C:\before_cleanup.csv"

# 2. Review report, then delete with confirmation
.\Find-DuplicateFiles.ps1 -Path "D:\Data" -Action Delete -Interactive

# 3. Generate after-report
.\Find-DuplicateFiles.ps1 -Path "D:\Data" -ExportPath "C:\after_cleanup.csv"
```

---

### Office Document Converters

#### Convert-LegacyExcel.ps1
Batch converts legacy Excel 97-2003 (.xls) files to modern Office Open XML (.xlsx) format.

**Features:**
- Recursive directory processing
- Automatic file organization (moves originals to "converted" subfolder)
- Progress tracking and comprehensive logging
- Safe COM object handling with proper cleanup
- WhatIf support for testing

**Usage:**
```powershell
# Convert all .xls files in C:\Temp
.\Convert-LegacyExcel.ps1

# Recursive conversion with custom log path
.\Convert-LegacyExcel.ps1 -Path "D:\Documents" -Recurse -LogPath "C:\Logs"

# Network share conversion, keep originals in place
.\Convert-LegacyExcel.ps1 -Path "\\server\share" -KeepOriginal

# Preview conversions without making changes
.\Convert-LegacyExcel.ps1 -WhatIf
```

#### Convert-LegacyWord.ps1
Batch converts legacy Word 97-2003 (.doc) files to modern Office Open XML (.docx) format.

**Features:**
- Recursive directory processing
- Automatic file organization (moves originals to "converted" subfolder)
- Progress tracking and comprehensive logging
- Safe COM object handling with proper cleanup
- WhatIf support for testing

**Usage:**
```powershell
# Convert all .doc files in C:\Temp
.\Convert-LegacyWord.ps1

# Recursive conversion with custom log path
.\Convert-LegacyWord.ps1 -Path "D:\Documents" -Recurse -LogPath "C:\Logs"

# Network share conversion, keep originals in place
.\Convert-LegacyWord.ps1 -Path "\\server\share" -KeepOriginal

# Preview conversions without making changes
.\Convert-LegacyWord.ps1 -WhatIf
```

---

## Future Contents

Additional automation tools for:
- **System Provisioning** - Automated server and workstation setup
- **Configuration Management** - Standardized system configurations and baselines
- **Software Deployment** - Application installation and update frameworks
- **Bulk Operations** - Mass user creation, group management, and permissions
- **Task Scheduling** - Automated job execution and orchestration

---

## Common Parameters

Most automation scripts accept standard parameters:
- `-Path` - Target directory for processing
- `-Recurse` - Process subdirectories recursively
- `-LogPath` - Custom log file location
- `-WhatIf` - Preview changes without execution
- `-Verbose` - Detailed operation logging
- `-Interactive` - Prompt for confirmations

---

## Requirements

- **PowerShell 5.1 or later**
- **Microsoft Office installed** (for document converters)
- **Administrative privileges** (for some operations)
- **NTFS file system** (for hardlink operations)
- **Appropriate file system permissions**

---

[← Back to Main Repository](../README.md)
