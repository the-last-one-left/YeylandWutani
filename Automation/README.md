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
