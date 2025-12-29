# Automation
PowerShell scripts for system provisioning, cleanup operations, migration preparation, software deployment, and file management automation.

---

## Available Scripts

### Software Deployment

| Script | Description |
|--------|-------------|
| `Deploy-RMMAgent.ps1` | Enterprise MSI deployment via PSEXEC. Queries AD for targets, validates reachability and PSEXEC compatibility (port 445, ADMIN$ share), then deploys MSI silently. Supports readiness-only mode, auto-detection of local MSI/PSExec files, and generates HTML reports. |

### Migration Preparation

| Script | Description |
|--------|-------------|
| `Get-SPOMigrationReadiness.ps1` | Comprehensive file server assessment for SharePoint Online migration. Detects path length issues, invalid characters, restricted names, legacy Office formats, blocked files, folder item thresholds, and provides library structure recommendations. |

### Ransomware Cleanup

| Script | Description |
|--------|-------------|
| `Remove-RansomwareArtifacts.ps1` | Post-remediation cleanup: identifies ransom notes, encrypted files, and empty folders. Supports 600+ note patterns and 100+ ransomware extensions. **Use only after complete remediation.** |

### File System Cleanup

| Script | Description |
|--------|-------------|
| `Remove-EmptyFolders.ps1` | Removes empty folders in depth-first order (handles nested empty structures in one pass) |
| `Find-DuplicateFiles.ps1` | Duplicate detection via MD5/SHA256 hashing with delete, move, or hardlink options |

### Office Document Conversion

| Script | Description |
|--------|-------------|
| `Convert-LegacyExcel.ps1` | Batch converts .xls files to .xlsx format |
| `Convert-LegacyWord.ps1` | Batch converts .doc files to .docx format |

---

## Usage Examples

### RMM Agent Deployment

```powershell
# Readiness check only - no MSI required, no changes made
.\Deploy-RMMAgent.ps1 -TestOnly

# Readiness check for specific OU
.\Deploy-RMMAgent.ps1 -TestOnly -SearchBase "OU=Workstations,DC=contoso,DC=com"

# Auto-detect MSI and PSExec in current directory
.\Deploy-RMMAgent.ps1

# Deploy with explicit MSI path
.\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi"

# Deploy to workstations only, exclude servers
.\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -ExcludeServers

# Deploy with custom MSI arguments
.\Deploy-RMMAgent.ps1 -MSIPath "C:\RMM.msi" -MSIArguments "/qn /norestart SERVERURL=https://rmm.example.com"

# Exclude specific machines by pattern
.\Deploy-RMMAgent.ps1 -MSIPath "C:\RMM.msi" -ExcludePattern "^DC-|^SQL-|^TEST-"

# Deploy to specific computers only
.\Deploy-RMMAgent.ps1 -MSIPath "C:\RMM.msi" -ComputerName "WKS01","WKS02","WKS03"

# Filter by OS
.\Deploy-RMMAgent.ps1 -TestOnly -Filter "OperatingSystem -like '*Windows 10*'"
```

### SharePoint Migration

```powershell
# SharePoint migration readiness assessment
.\Get-SPOMigrationReadiness.ps1 -Path "D:\FileShare" -OutputPath "C:\Reports"

# Include permission analysis for migration planning
.\Get-SPOMigrationReadiness.ps1 -Path "\\Server\Data" -IncludePermissions -TargetSiteUrl "https://contoso.sharepoint.com/sites/Projects"
```

### Ransomware Cleanup

```powershell
# Ransomware cleanup - report first (no changes)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action Report

# Remove ransom notes only
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteNotes -CreateBackup
```

### File Management

```powershell
# Find and remove empty folders
.\Remove-EmptyFolders.ps1 -Path "D:\Data" -Action Delete

# Find duplicate files with HTML report
.\Find-DuplicateFiles.ps1 -Path "D:\Photos" -ExportPath "C:\Reports\Duplicates.html"

# Convert legacy Office files before migration
.\Convert-LegacyExcel.ps1 -Path "D:\Documents" -Recurse
.\Convert-LegacyWord.ps1 -Path "D:\Documents" -Recurse
```

---

## RMM Deployment Phases

The `Deploy-RMMAgent.ps1` script executes in phases:

| Phase | Description |
|-------|-------------|
| **Prerequisites** | Locates PSExec.exe and validates MSI file |
| **Target Discovery** | Queries AD or uses manual computer list |
| **Reachability** | Filters to online systems via ICMP ping |
| **Compatibility** | Validates PSEXEC requirements on each target |
| **Deployment** | Copies MSI, executes via PSEXEC, cleans up |
| **Reporting** | Generates HTML report and CSV export |

### PSEXEC Compatibility Requirements

| Requirement | Check Method | Resolution |
|-------------|--------------|------------|
| Port 445 open | TCP connection test | Enable File and Printer Sharing |
| ADMIN$ accessible | UNC path test | Verify admin shares enabled |
| Admin rights | Implicit via share access | Use domain admin or local admin credentials |
| SMB enabled | Port 445 response | Start LanmanServer service |

---

## SharePoint Migration Readiness Checks

The `Get-SPOMigrationReadiness.ps1` script checks for:

| Issue Category | SharePoint Limit | Impact |
|----------------|------------------|--------|
| **Path Length** | 400 chars (URL), 218 chars (sync) | Files won't upload or sync |
| **Invalid Characters** | " * : < > ? / \ \| | Upload failures |
| **Restricted Names** | CON, PRN, AUX, NUL, COM0-9, LPT0-9 | Upload blocked |
| **Legacy Office** | .doc, .xls, .ppt | No co-authoring, no web editing |
| **Blocked Files** | .exe, .bat, .ps1, etc. | Upload blocked by policy |
| **File Size** | 250 GB max | Upload failure |
| **Folder Items** | 5,000 (view threshold) | Performance issues |

---

## Common Parameters

| Parameter | Description |
|-----------|-------------|
| `-Path` | Target directory |
| `-Action` | Operation mode (Report, Delete, Move, etc.) |
| `-WhatIf` | Preview changes without execution |
| `-TestOnly` | Run checks without deployment (Deploy-RMMAgent) |
| `-Interactive` | Prompt for confirmations |
| `-ExportPath` / `-OutputPath` | Output file location |

---

## Requirements

| Script | Requirements |
|--------|--------------|
| `Deploy-RMMAgent.ps1` | PowerShell 5.1+, AD module, PSExec.exe, Admin rights on targets |
| `Get-SPOMigrationReadiness.ps1` | PowerShell 5.1+, Read access to source paths |
| `Convert-Legacy*.ps1` | PowerShell 5.1+, Microsoft Office installed |
| `Find-DuplicateFiles.ps1` | PowerShell 5.1+, NTFS (for hardlinks) |
| All scripts | Windows environment |

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
