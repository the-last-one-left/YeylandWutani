# Automation

General-purpose PowerShell scripts for workstation, server, and Microsoft 365 automation in MSP environments. All scripts require PowerShell 5.1 or later and include comment-based help — run `Get-Help .\ScriptName.ps1 -Full` for complete parameter documentation.

---

## Scripts

### Deployment & Configuration

| Script | Description |
|--------|-------------|
| `New-EmbeddedInstaller.ps1` | Encodes an EXE or MSI into Base64 and generates a self-contained deployment script for RMM tools that support scripts but not file drops. Auto-detects common installer frameworks (NSIS, Inno Setup, WiX Burn, InstallShield, etc.) and their silent switches. Supports GZip compression to reduce script size. |
| `Deploy-RMMAgent.ps1` | Deploys MSI and EXE packages to domain computers using PsExec. Useful for bootstrapping an RMM agent before remote management is available. |
| `Set-ServerBaseline.ps1` | Applies a standard baseline configuration to a new Windows Server — RMM agent install, NTP, driver updates, Server Manager tweaks, PowerShell 7, and terminal app. Designed for MSP onboarding. |
| `Install-SMTPRelay.ps1` | Installs the Yeyland Wutani SMTP Relay as a Windows service from a single self-contained script. |

### RDP File Signing

| Script | Description |
|--------|-------------|
| `New-RdpSigningCert.ps1` | **Run once on your admin machine.** Generates a self-signed code-signing certificate, or extracts values from an existing PFX, and outputs the Base64 strings and password to paste into `Sign-RdpFiles.ps1`. |
| `Sign-RdpFiles.ps1` | **Deploy via ASIO or RMM as SYSTEM/admin.** Self-contained workstation script — cert is embedded as Base64 in the file header. Installs the signing cert into machine trust stores, scans every user profile's Desktop and Documents (including OneDrive-redirected paths) for `.rdp` files, signs each one with `rdpsign.exe`, then removes the private key from the store. Skips `default.rdp`. Exits non-zero if any file fails. |

> **Context:** Microsoft's 2025 patch changed unsigned RDP files to prompt users about what to share on connect. These two scripts are the signing solution for managed workstations.

### Microsoft 365 & SharePoint

| Script | Description |
|--------|-------------|
| `Audit-365Archives.ps1` | Audits Online Archive mailboxes across a tenant. Temporarily licenses users to read archive data, collects results to CSV, and cleans up licensing changes afterward. |
| `Get-SPOMigrationReadiness.ps1` | Analyzes a file server path for SharePoint Online migration blockers — invalid characters, path length violations, file size limits, permissions, and more. Outputs a detailed readiness report. |

### File & Folder Management

| Script | Description |
|--------|-------------|
| `Convert-LegacyExcel.ps1` | Batch-converts `.xls` files to `.xlsx` using the local Excel COM object. Supports recursive scan, optional original file retention, and `-WhatIf`. |
| `Convert-LegacyWord.ps1` | Batch-converts `.doc` files to `.docx` using the local Word COM object. Supports recursive scan, optional original file retention, and `-WhatIf`. |
| `Find-DuplicateFiles.ps1` | Hash-based duplicate file detection. Supports SHA256/MD5, minimum/maximum file size filters, extension exclusions, and actions: report, move to a destination folder, or delete. |
| `Remove-EmptyFolders.ps1` | Removes empty folders depth-first so nested empties are handled in a single pass. Supports `-WhatIf`, interactive confirmation, and logging. |

### System & Security

| Script | Description |
|--------|-------------|
| `Reset-UserProfile.ps1` | Resets a Windows user profile by renaming the existing profile folder and clearing its registry entries. Supports local and remote computers. `-WhatIf` safe. |
| `Remove-RansomwareArtifacts.ps1` | Post-incident cleanup utility. Scans for known ransomware note filenames and encrypted file extensions, with options to report, quarantine, or delete. Supports interactive review mode and CSV/JSON export. |
| `Invoke-LetsEncryptRenewal.ps1` | Full Let's Encrypt certificate lifecycle automation via the ACME protocol. Supports HTTP-01 and DNS-01 challenges and can deploy renewed certs to IIS, RD Gateway, or WatchGuard Firebox. |

### Utilities

| Script | Description |
|--------|-------------|
| `Get-SalesTaxRate.ps1` | Queries the Avalara public tax rate API for U.S. sales tax rates by address or coordinates. Returns structured output or raw JSON. |
| `Invoke-HatzChat.ps1` | Interactive terminal chat client for the Hatz AI API. Maintains conversation history, supports model selection, and can be configured via environment variable for the API key. |

---

## New-EmbeddedInstaller.ps1

Encodes any EXE or MSI into a self-contained PowerShell deployment script. The generated script decodes the binary at runtime, writes it to a temp path, runs the silent install, cleans up, and returns an exit code your RMM can act on — no file server or share required.

**Auto-detected installer frameworks:**

| Framework | Silent Switch |
|-----------|--------------|
| NSIS (Nullsoft) | `/S` |
| Inno Setup | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-` |
| WiX Burn | `/quiet /norestart` |
| InstallShield | `/s /v"/qn /norestart"` |
| MSI (any) | `/qn /norestart` |

```powershell
# Embed an MSI with auto-detected arguments
.\New-EmbeddedInstaller.ps1 -InstallerPath ".\Agent.msi"

# Auto-detect framework and silent switches for an EXE
.\New-EmbeddedInstaller.ps1 -InstallerPath ".\WG-MVPN-SSL_12_11_5.exe"

# Inspect framework detection without generating a script
.\New-EmbeddedInstaller.ps1 -InstallerPath ".\Setup.exe" -ShowInstallerInfo

# Override silent switches and set output path
.\New-EmbeddedInstaller.ps1 -InstallerPath ".\Setup.exe" -Arguments "/S /NORESTART" -OutputPath ".\Deploy-App.ps1"

# Compress to reduce script size (useful for large installers near RMM limits)
.\New-EmbeddedInstaller.ps1 -InstallerPath ".\BigApp.msi" -Compress -Description "BigApp v2.1"

# Add pre/post install steps
.\New-EmbeddedInstaller.ps1 -InstallerPath ".\Agent.msi" `
    -PreScript  'Stop-Service "OldAgent" -ErrorAction SilentlyContinue' `
    -PostScript 'Start-Service "NewAgent"'
```

**RMM script size limits (for planning):**

| RMM Platform | Typical Limit |
|-------------|--------------|
| Datto RMM | ~1 MB |
| Syncro | ~1 MB |
| NinjaRMM | ~5 MB |
| ConnectWise Automate | ~16 MB |

---

## Set-ServerBaseline.ps1

Applies a standard MSP baseline to a freshly provisioned Windows Server in one run: installs the ConnectWise Control agent, sets NTP, updates hardware drivers (Dell DSU / HP SPP), disables Server Manager auto-start, installs PowerShell 7 and Windows Terminal, and configures power management.

```powershell
# Full baseline — prompts interactively for agent token
.\Set-ServerBaseline.ps1

# Full baseline with token embedded (unattended deployment)
.\Set-ServerBaseline.ps1 -AgentToken "your-token-here"

# Baseline with custom NTP, skip RMM install (already managed)
.\Set-ServerBaseline.ps1 -SkipRMMInstall -NTPServer "time.windows.com"

# Skip driver updates on non-Dell/HP hardware
.\Set-ServerBaseline.ps1 -AgentToken "your-token-here" -SkipDriverUpdates

# Run with no interactive prompts (scripted/RMM deployment)
.\Set-ServerBaseline.ps1 -AgentToken "your-token-here" -Force
```

---

## RDP File Signing (New-RdpSigningCert.ps1 + Sign-RdpFiles.ps1)

Two-script workflow to sign `.rdp` files on managed workstations after Microsoft's 2025 patch introduced per-session share prompts for unsigned files.

**Step 1 — run once on your admin machine:**

```powershell
# Generate a new self-signed code-signing cert
.\New-RdpSigningCert.ps1

# Use a 3-year cert with a specific password
.\New-RdpSigningCert.ps1 -ValidYears 3 -PfxPassword "SuperSecret99!"

# Extract Base64 strings from an existing PFX (no new cert created)
.\New-RdpSigningCert.ps1 -ExistingPfxPath "C:\Certs\my-signing.pfx" -PfxPassword "hunter2"
```

The script outputs three values (`$PFX_BASE64`, `$CER_BASE64`, `$PFX_PASSWORD`) to paste into the configuration block at the top of `Sign-RdpFiles.ps1`.

**Step 2 — deploy via RMM or ASIO as SYSTEM:**

```powershell
# After populating the config block, deploy Sign-RdpFiles.ps1
# The script runs silently and exits 0 on success, 1 on any signing failure
.\Sign-RdpFiles.ps1
```

The script installs the cert into machine trust stores, scans all user profiles (including OneDrive-redirected Desktop/Documents), signs every `.rdp` file with `rdpsign.exe`, then removes the private key. Safe to re-run — previously signed files are re-signed with the same cert.

---

## Remove-RansomwareArtifacts.ps1

Post-incident cleanup after ransomware remediation and file restoration. Scans for ransom note files and known encrypted file extensions from 100+ ransomware families, then reports, quarantines, or deletes them.

> **Always run `-Action Report` first** — review before deleting anything.

```powershell
# Safe scan — report only, no changes
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action Report

# Preview what would be deleted (WhatIf)
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action DeleteAll -WhatIf

# Remove only ransom note files, prompt before each
.\Remove-RansomwareArtifacts.ps1 -Path "\\fileserver\shares" -Action DeleteNotes -Interactive

# Remove empty folders left after manual file restoration
.\Remove-RansomwareArtifacts.ps1 -Path "C:\Users" -Action DeleteEmpty

# Full cleanup with backup copies and interactive confirmation
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Restored" -Action DeleteAll -CreateBackup -Interactive

# Export detailed HTML report
.\Remove-RansomwareArtifacts.ps1 -Path "E:\Archive" -Action Report -ExportFormat HTML -ExportPath "C:\Reports\cleanup.html"

# Add custom encrypted extensions beyond the built-in list
.\Remove-RansomwareArtifacts.ps1 -Path "D:\Data" -Action Report -KnownExtensions @('.customenc','.locked2')
```

**Actions:**

| Action | Effect |
|--------|--------|
| `Report` | Scan and report only — no changes (default) |
| `DeleteNotes` | Remove ransom note files only |
| `DeleteEncrypted` | Remove encrypted files only |
| `DeleteEmpty` | Remove empty folders only |
| `DeleteAll` | Remove notes + encrypted files + empty folders |

---

## Invoke-LetsEncryptRenewal.ps1

Full Let's Encrypt certificate lifecycle via the ACME protocol (Posh-ACME). Interactive guided menu for first-time setup; subsequent renewals run fully unattended as SYSTEM via a scheduled task.

**Deployment targets:** IIS, RD Gateway (TSGateway), PFX export, WatchGuard Firebox (SSH + FTP pipeline).  
**Challenge types:** HTTP-01 (no wildcard, port 80 required) or DNS-01 (wildcard support, 30+ DNS provider plugins).

```powershell
# Interactive first-time setup (guided menu)
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "mail.contoso.com" -ContactEmail "admin@contoso.com"

# Wildcard cert via Cloudflare DNS-01
.\Invoke-LetsEncryptRenewal.ps1 `
    -DomainName "*.contoso.com" `
    -ContactEmail "admin@contoso.com" `
    -ChallengeType Dns `
    -DnsPlugin Cloudflare `
    -DnsPluginArgs @{ CFToken = (Read-Host -AsSecureString "CF Token") }

# Multi-domain SAN cert via Route53
.\Invoke-LetsEncryptRenewal.ps1 `
    -DomainName "contoso.com" `
    -AdditionalDomains @("www.contoso.com", "mail.contoso.com") `
    -ContactEmail "admin@contoso.com" `
    -ChallengeType Dns `
    -DnsPlugin Route53 `
    -DnsPluginArgs @{ R53AccessKey = "xxx"; R53SecretKey = (Read-Host -AsSecureString) }

# Manual DNS-01 (pauses for you to create TXT records)
.\Invoke-LetsEncryptRenewal.ps1 `
    -DomainName "rdg.contoso.com" `
    -ContactEmail "admin@contoso.com" `
    -ChallengeType DnsManual

# Test issuance against Let's Encrypt staging (no rate limits)
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "test.contoso.com" -ContactEmail "admin@contoso.com" -Staging
```

---

## Audit-365Archives.ps1

Audits Online Archive mailboxes in a Microsoft 365 tenant — useful when archive mailboxes did not migrate and need assessment before decommissioning a source tenant. Dynamically identifies an eligible license SKU, temporarily assigns it to each user, collects primary and archive mailbox statistics, then removes the license.

```powershell
# Audit all mailboxes in the tenant
.\Audit-365Archives.ps1 -OutputPath "C:\Reports\ArchiveAudit"

# Audit a specific list of users from CSV (requires UserPrincipalName column)
.\Audit-365Archives.ps1 -InputCsv "C:\Users.csv" -OutputPath "C:\Reports\ArchiveAudit"

# Extend provisioning wait for slow tenants
.\Audit-365Archives.ps1 -InputCsv "C:\Users.csv" -WaitTimeSeconds 300
```

---

## Get-SPOMigrationReadiness.ps1

Scans a file server path and identifies everything that will break a SharePoint Online migration before you start: path length violations, invalid characters, oversized files, and NTFS permission complexity.

```powershell
# Scan a local file share
.\Get-SPOMigrationReadiness.ps1 -Path "D:\FileShare"

# Scan a UNC path with a known SPO target (calculates final path lengths)
.\Get-SPOMigrationReadiness.ps1 -Path "\\Server\Data" -TargetSiteUrl "https://contoso.sharepoint.com/sites/Projects"

# Scan multiple roots with full permission analysis
.\Get-SPOMigrationReadiness.ps1 -Path "D:\Finance","D:\HR" -IncludePermissions -OutputPath "C:\Reports"

# Fast scan (skip folder size calculation)
.\Get-SPOMigrationReadiness.ps1 -Path "\\fileserver\data" -SkipSizeCalculation
```

---

## Find-DuplicateFiles.ps1

Hash-based duplicate detection — compares actual file contents (SHA256 or MD5), not just names or sizes.

```powershell
# Report duplicates in a folder (no changes)
.\Find-DuplicateFiles.ps1 -Path "D:\Photos" -ExportPath "C:\Reports\Duplicates.html" -ExportFormat HTML

# Delete duplicates, keeping the oldest copy
.\Find-DuplicateFiles.ps1 -Path "D:\Archive" -Action Delete

# Delete duplicates, keeping the newest copy, with interactive confirmation
.\Find-DuplicateFiles.ps1 -Path "D:\Archive" -Action Delete -KeepNewest -Interactive

# Move duplicates to a staging folder instead of deleting
.\Find-DuplicateFiles.ps1 -Path "D:\Shares" -Action Move -DestinationPath "D:\Duplicates-Review"

# Limit scope to files between 1 MB and 500 MB, exclude temp files
.\Find-DuplicateFiles.ps1 -Path "D:\Data" -MinFileSize 1MB -MaxFileSize 500MB -ExcludeExtensions ".tmp",".log"
```

---

## Convert-LegacyExcel.ps1 / Convert-LegacyWord.ps1

Batch-converts `.xls` → `.xlsx` and `.doc` → `.docx` using the locally installed Office COM object.

```powershell
# Convert all .xls files in a folder (keeps originals by default)
.\Convert-LegacyExcel.ps1 -Path "D:\Finance"

# Recursive conversion, delete originals after successful convert
.\Convert-LegacyExcel.ps1 -Path "D:\Finance" -Recurse -DeleteOriginals

# Preview what would be converted without making changes
.\Convert-LegacyExcel.ps1 -Path "D:\Finance" -WhatIf

# Same options apply to Word files
.\Convert-LegacyWord.ps1 -Path "D:\Contracts" -Recurse -DeleteOriginals
```

---

## Remove-EmptyFolders.ps1

Removes empty folder hierarchies in a single depth-first pass — if `\A\B\C` are all empty, all three are removed without needing to re-run.

```powershell
# Report empty folders without deleting (safe preview)
.\Remove-EmptyFolders.ps1 -Path "D:\Data"

# Delete all empty folders
.\Remove-EmptyFolders.ps1 -Path "D:\Data" -Action Delete

# Delete with interactive confirmation per folder
.\Remove-EmptyFolders.ps1 -Path "C:\Projects" -Action Delete -Interactive

# Preview deletions with WhatIf
.\Remove-EmptyFolders.ps1 -Path "D:\Data" -Action Delete -WhatIf

# Exclude specific paths from scanning
.\Remove-EmptyFolders.ps1 -Path "\\fileserver\data" -ExcludePaths @('*\Archive\*','*\Temp\*') -Action Delete
```
