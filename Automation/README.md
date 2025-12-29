# Automation
PowerShell scripts for system provisioning, cleanup operations, migration preparation, software deployment, and file management automation.

---

## Available Scripts

### Software Deployment

| Script | Description |
|--------|-------------|
| `Deploy-RMMAgent.ps1` | Enterprise installer deployment via PSEXEC. Supports both MSI and EXE packages with automatic framework detection. Queries AD for targets, validates PSEXEC compatibility, deploys silently, validates installation, and generates HTML reports. |

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

## Installer Deployment (Deploy-RMMAgent.ps1)

Enterprise-grade installer deployment supporting both MSI and EXE packages with automatic silent switch detection.

### Supported Installer Types

| Type | Detection | Silent Switches | Reliability |
|------|-----------|-----------------|-------------|
| **MSI** | File extension | `/qn /norestart` | High |
| **NSIS** | NullsoftInst signature | `/S` (case-sensitive) | High |
| **Inno Setup** | Inno Setup signature | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-` | High |
| **InstallShield (MSI)** | InstallShield + MSI indicators | `/s /v"/qn /norestart"` | Medium |
| **InstallShield (Legacy)** | InstallShield only | Requires recorded `.iss` file | Low |
| **Wise InstallMaster** | Wise signature | `/s` | Medium |
| **WiX Burn** | WixBurn signature | `/quiet /norestart` | High |
| **InstallAware** | InstallAware signature | `/s` | Medium |
| **Advanced Installer** | Caphyon signature | `/i /qn` | Medium |

### Usage Examples

```powershell
# Analyze installer before deployment (shows framework and switches)
.\Deploy-RMMAgent.ps1 -InstallerPath "Setup.exe" -ShowInstallerInfo
.\Deploy-RMMAgent.ps1 -InstallerPath "Agent.msi" -ShowInstallerInfo

# Auto-detect installer in current directory
.\Deploy-RMMAgent.ps1 -ComputerName "WKS01"

# Deploy EXE with auto-detected silent switches
.\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Setup.exe" -ComputerName "WKS01","WKS02"

# Deploy EXE with custom switches (override auto-detection)
.\Deploy-RMMAgent.ps1 -InstallerPath "Setup.exe" -InstallerArguments "/S /D=C:\CustomPath"

# Deploy MSI with custom properties
.\Deploy-RMMAgent.ps1 -InstallerPath "Agent.msi" -InstallerProperties @{
    SERVERURL = "https://rmm.company.com"
    APIKEY = "abc123"
}

# Deploy MSI with transform file
.\Deploy-RMMAgent.ps1 -InstallerPath "Agent.msi" -TransformPath "Settings.mst"

# Readiness check only (no deployment)
.\Deploy-RMMAgent.ps1 -TestOnly

# Deploy to AD OU, exclude servers
.\Deploy-RMMAgent.ps1 -InstallerPath "Agent.msi" -SearchBase "OU=Workstations,DC=contoso,DC=com" -ExcludeServers

# Deploy with retry on failure
.\Deploy-RMMAgent.ps1 -InstallerPath "Setup.exe" -RetryCount 2 -CollectLogs
```

### Key Parameters

| Parameter | Aliases | Description |
|-----------|---------|-------------|
| `-InstallerPath` | `-MSIPath`, `-Path` | Path to MSI or EXE installer |
| `-InstallerArguments` | `-MSIArguments`, `-EXEArguments` | Override auto-detected silent switches |
| `-InstallerProperties` | `-MSIProperties` | Hashtable of properties to pass to installer |
| `-ShowInstallerInfo` | `-ShowMSIProperties` | Analyze installer and exit (no deployment) |
| `-TransformPath` | | MST transform file for MSI deployment |
| `-ComputerName` | | Specific target computer(s) |
| `-SearchBase` | | AD OU distinguished name to search |
| `-TestOnly` | | Run readiness checks only |
| `-RetryCount` | | Retry failed deployments (0-5) |
| `-CollectLogs` | | Pull install logs from failed systems |
| `-SkipValidation` | | Skip post-install registry verification |

### Deployment Phases

| Phase | Description |
|-------|-------------|
| **Installer Analysis** | Extract MSI properties or detect EXE framework |
| **Target Discovery** | Query AD or use manual computer list |
| **Reachability** | Filter to online systems via ICMP ping |
| **Compatibility** | Validate PSEXEC requirements (Port 445, ADMIN$) |
| **Deployment** | Copy installer, execute via PSEXEC, cleanup |
| **Validation** | Verify product in registry post-install |
| **Reporting** | Generate HTML report and CSV export |

### PSEXEC Compatibility Requirements

| Requirement | Check Method | Resolution |
|-------------|--------------|------------|
| Port 445 open | TCP connection test | Enable File and Printer Sharing |
| ADMIN$ accessible | UNC path test | Verify admin shares enabled |
| Admin rights | Implicit via share access | Use domain admin or local admin credentials |
| SMB enabled | Port 445 response | Start LanmanServer service |

---

## SharePoint Migration Readiness

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

```powershell
# SharePoint migration readiness assessment
.\Get-SPOMigrationReadiness.ps1 -Path "D:\FileShare" -OutputPath "C:\Reports"

# Include permission analysis for migration planning
.\Get-SPOMigrationReadiness.ps1 -Path "\\Server\Data" -IncludePermissions -TargetSiteUrl "https://contoso.sharepoint.com/sites/Projects"
```

---

## Ransomware Cleanup

```powershell
# Ransomware cleanup - report first (no changes)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action Report

# Remove ransom notes only
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteNotes -CreateBackup
```

---

## File Management

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

## Common Parameters

| Parameter | Description |
|-----------|-------------|
| `-Path` | Target directory |
| `-Action` | Operation mode (Report, Delete, Move, etc.) |
| `-WhatIf` | Preview changes without execution |
| `-TestOnly` | Run checks without deployment |
| `-Force` | Skip confirmation prompts |
| `-ExportPath` / `-OutputPath` | Output file location |

---

## Requirements

| Script | Requirements |
|--------|--------------|
| `Deploy-RMMAgent.ps1` | PowerShell 5.1+, AD module (for AD query), PSExec.exe, Admin rights on targets |
| `Get-SPOMigrationReadiness.ps1` | PowerShell 5.1+, Read access to source paths |
| `Convert-Legacy*.ps1` | PowerShell 5.1+, Microsoft Office installed |
| `Find-DuplicateFiles.ps1` | PowerShell 5.1+, NTFS (for hardlinks) |
| All scripts | Windows environment |

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
