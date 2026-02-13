# Automation
PowerShell scripts for system provisioning, cleanup operations, migration preparation, software deployment, profile management, email infrastructure, and file management automation.

---

## Available Scripts

### Server Provisioning

| Script | Description |
|--------|-------------|
| `Set-ServerBaseline.ps1` | Comprehensive server baseline automation for MSP deployments. Configures ConnectWise Control agent, hardware drivers (Dell DSU/HP SPP), Windows Terminal, PowerShell 7, NTP, power management, Windows Update, Remote Desktop, security logging, and event logs. Supports IT247.net hosted Control and embedded agent deployment. |

### Email Infrastructure

| Script | Description |
|--------|-------------|
| `Install-SMTPRelay.ps1` | Single-file SMTP relay installer for forwarding email from devices to Microsoft 365 via Graph API. Supports legacy devices (printers, scanners, LOB apps) that can't use modern auth. Optionally creates Entra ID app registration, configures SMTP authentication, IP-based access control, and client secret expiry reminders. Runs as Windows service via NSSM. |

### Software Deployment

| Script | Description |
|--------|-------------|
| `Deploy-RMMAgent.ps1` | Enterprise installer deployment via PSEXEC. Supports both MSI and EXE packages with automatic framework detection. Queries AD for targets, validates PSEXEC compatibility, deploys silently, validates installation, and generates HTML reports. |

### Profile Management

| Script | Description |
|--------|-------------|
| `Reset-UserProfile.ps1` | Recreates corrupted Windows user profiles without data loss. Renames the existing profile folder and clears registry entries, triggering a fresh profile on next login. Supports local and remote computers. |

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

## SMTP Relay Installation (Install-SMTPRelay.ps1)

Single-file installer that deploys an SMTP relay service for forwarding email from legacy devices to Microsoft 365 via Graph API. Ideal for printers, scanners, multifunction devices, and line-of-business applications that can't use modern authentication.

### Architecture

```
Device (Scanner/Printer/App)
    ↓ SMTP (plaintext, port 25)
Windows Server Running Relay
    ↓ HTTPS/OAuth2 (Graph API)
Microsoft 365
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Single-File Deployment** | All components embedded (relay script, uninstaller, service manager) |
| **Entra ID Integration** | Optionally creates app registration with Mail.Send permission |
| **SMTP Authentication** | Optional username/password auth for additional security |
| **IP Access Control** | Restrict relay access by IP address or CIDR range |
| **Secret Expiry Alerts** | Email reminder 1 month before client secret expires |
| **Windows Service** | Runs as service via NSSM with auto-restart on failure |
| **No TLS Required** | Accepts plaintext SMTP from devices (relay-to-M365 uses HTTPS) |
| **Upgrade Support** | Preserves configuration when upgrading to newer versions |

### Installation Modes

| Mode | Use Case | Configuration |
|------|----------|---------------|
| **Fresh Install** | New deployment | Creates service, app registration (optional), configuration |
| **Upgrade** | Update existing installation | Preserves config, updates scripts, restarts service |
| **Uninstall** | Complete removal | Removes service, firewall rules, optionally preserves logs/config |

### Usage Examples

```powershell
# Standard installation (creates Entra app automatically)
.\Install-SMTPRelay.ps1

# Custom service name and install path
.\Install-SMTPRelay.ps1 -ServiceName "Company SMTP Relay" -InstallPath "D:\Services\SMTPRelay"

# Custom SMTP port (non-standard)
.\Install-SMTPRelay.ps1 -SmtpPort 2525

# Skip app registration (use existing Entra app)
.\Install-SMTPRelay.ps1 -SkipAppRegistration

# Upgrade existing installation
# Installer detects existing install and offers upgrade option automatically
.\Install-SMTPRelay.ps1
```

### Installation Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ServiceName` | Windows service display name | `SMTP Relay` |
| `-AppName` | Entra ID application name | Same as ServiceName |
| `-InstallPath` | Installation directory | `C:\SMTPRelay` |
| `-SmtpPort` | SMTP listen port | `25` |
| `-SkipAppRegistration` | Use existing Entra app (manual config) | False |

### Entra ID App Registration

The installer can automatically create an Entra ID app registration with the required permissions:

| Permission | Type | Purpose |
|------------|------|---------|
| `Mail.Send` | Application | Send email as any user in the organization |

**Automatic Creation Requirements:**
- Global Administrator or Application Administrator account
- Microsoft.Graph PowerShell module (auto-installed if missing)

**Manual Configuration:**
1. Azure Portal > Entra ID > App registrations > New registration
2. Add API permission: Microsoft Graph > Application > Mail.Send
3. Grant admin consent
4. Create client secret (save the value)
5. Use `-SkipAppRegistration` and provide tenant ID, client ID, and secret when prompted

### Configuration Options

The installer prompts for the following settings during installation:

| Setting | Description | Security Impact |
|---------|-------------|-----------------|
| **Send-As Address** | Email address for outbound messages (user, shared mailbox, or distribution list) | None |
| **Force Send-As** | Override device From address with configured address | Recommended |
| **SMTP Authentication** | Require username/password from devices | Optional additional security layer |
| **IP Access Control** | Whitelist of allowed IP addresses or CIDR ranges | Primary security mechanism |
| **Secret Expiry Reminder** | Email alert 1 month before client secret expires | Prevents service disruption |

### Device Configuration

Configure devices to use the relay with these settings:

| Setting | Value | Notes |
|---------|-------|-------|
| **SMTP Server** | Server hostname or IP address | Use FQDN for DNS resolution |
| **SMTP Port** | 25 (or custom port) | Must match relay configuration |
| **Authentication** | Username/password if enabled | Optional, disabled by default |
| **Encryption** | None / Disabled | TLS/STARTTLS not supported |
| **From Address** | Any valid email address | Overridden if Force Send-As enabled |

**Important:** The relay accepts plaintext SMTP from devices. Relay-to-M365 communication uses HTTPS (Graph API) and is always encrypted. Deploy the relay on a trusted internal network only.

### Security Recommendations

| Recommendation | Implementation |
|----------------|----------------|
| **Restrict Access** | Configure IP ACL to allow only known device IPs |
| **Enable SMTP Auth** | Add username/password requirement for extra security |
| **Limit Send-As Scope** | Use Application Access Policy to restrict app to specific mailbox |
| **Monitor Logs** | Review relay logs regularly for unauthorized attempts |
| **Internal Network** | Never expose relay directly to the Internet |
| **Firewall Rules** | Restrict port 25 to internal network only |

### Application Access Policy (Recommended)

By default, the app can send email as any mailbox in the tenant. Restrict it to the relay mailbox only:

```powershell
# Connect to Exchange Online PowerShell
Connect-ExchangeOnline

# Restrict app to relay mailbox only
New-ApplicationAccessPolicy `
    -AppId "YOUR-CLIENT-ID" `
    -PolicyScopeGroupId "relay@contoso.com" `
    -AccessRight RestrictAccess `
    -Description "Restrict SMTP Relay to relay mailbox only"

# Test the policy
Test-ApplicationAccessPolicy `
    -Identity "relay@contoso.com" `
    -AppId "YOUR-CLIENT-ID"
```

### Post-Installation Management

| Task | Command |
|------|---------|
| **Check Service Status** | `Get-Service "SMTP Relay"` |
| **Restart Service** | `Restart-Service "SMTP Relay"` |
| **View Today's Log** | `Get-Content "C:\SMTPRelay\Logs\SMTPRelay_YYYYMMDD.log" -Tail 50` |
| **Edit Configuration** | `notepad "C:\SMTPRelay\config.json"` |
| **Test Relay** | `Send-MailMessage -SmtpServer localhost -Port 25 -From "test@test.com" -To "you@contoso.com" -Subject "Test" -Body "Test message"` |
| **Uninstall** | `C:\SMTPRelay\Uninstall-SMTPRelay.ps1` |

### Configuration File (config.json)

After installation, edit `C:\SMTPRelay\config.json` to modify settings:

| Setting | Description | Default |
|---------|-------------|---------|
| `TenantId` | Entra ID tenant ID | From installation |
| `ClientId` | Entra app client ID | From installation |
| `ClientSecret` | Client secret value | From installation |
| `SendAsAddress` | Relay sender address | From installation |
| `ForceSendAs` | Override device From address | `true` |
| `SmtpPort` | SMTP listen port | `25` |
| `SmtpAuthEnabled` | Require SMTP authentication | `false` |
| `SmtpAuthUsername` | SMTP auth username | Empty |
| `SmtpAuthPassword` | SMTP auth password | Empty |
| `AllowedClients` | IP whitelist (array) | Private ranges |
| `LogLevel` | Logging verbosity | `INFO` |
| `LogRetentionDays` | Days to keep logs | `30` |
| `ClientSecretExpiry` | Secret expiration date | From installation |
| `ReminderEmail` | Alert destination | From installation |

**Note:** Restart the service after modifying the configuration file.

### Troubleshooting

| Issue | Solution |
|-------|----------|
| **Service won't start** | Check logs in `C:\SMTPRelay\Logs`, verify Entra credentials in config.json |
| **Port 25 in use** | Stop conflicting service (IIS SMTP) or use different port with `-SmtpPort` |
| **Device can't connect** | Verify IP in AllowedClients list, check firewall rules |
| **Messages not delivered** | Check Graph API token in logs, verify Mail.Send permission granted |
| **SMTP auth failures** | Enable DEBUG logging: set `LogLevel` to `DEBUG` in config.json and restart service |
| **Secret expired** | Create new secret in Azure Portal, update config.json, restart service |

### Upgrade Process

When running the installer on a system with an existing installation:

1. Installer detects existing service and configuration
2. Offers three options: **Upgrade**, **Uninstall**, or **Fresh Install**
3. **Upgrade mode:**
   - Stops service
   - Preserves existing config.json
   - Updates relay script and uninstaller
   - Restarts service with new scripts
   - Retains all logs and settings

### Client Secret Expiry Reminder

The relay can send an email reminder when the client secret is approaching expiration:

| Setting | Behavior |
|---------|----------|
| **Trigger** | Checked at service startup |
| **Timing** | One-time alert sent when <30 days until expiry |
| **Recipients** | Email address configured during installation |
| **Delivery** | Sent via Graph API using relay credentials |
| **Persistence** | Flag saved to config.json to prevent duplicate alerts |

### Embedded Components

The installer is completely self-contained with these embedded components:

| Component | Purpose | Source |
|-----------|---------|--------|
| **Relay Script** | Core SMTP-to-Graph relay logic | Embedded PowerShell |
| **Uninstaller** | Service removal script | Embedded PowerShell |
| **NSSM** | Service manager (Non-Sucking Service Manager) | Downloaded from nssm.cc |

### Supported Scenarios

| Scenario | Configuration |
|----------|---------------|
| **Printer/Scanner Email** | Default settings, no SMTP auth required |
| **LOB Application** | Enable SMTP auth for credential-based security |
| **Monitoring Alerts** | IP ACL + Force Send-As for consistent sender |
| **Multi-Site Relay** | Install on each site with local IP ranges in ACL |
| **High Security** | SMTP auth + strict IP ACL + Application Access Policy |

---

## Server Baseline Configuration (Set-ServerBaseline.ps1)

Automated server provisioning and hardening for MSP environments with modular component deployment.

### Deployment Components

| Component | Configuration | Purpose |
|-----------|---------------|----------|
| **ConnectWise Control** | MSI deployment with custom installer ID or IT247.net URL | Remote management and monitoring |
| **Hardware Drivers** | Dell DSU (OpenManage) or HP SPP (Support Pack) | Automated driver and firmware updates |
| **Windows Terminal** | Latest stable release via GitHub | Modern command-line interface |
| **PowerShell 7** | Latest stable release via GitHub | Cross-platform PowerShell core |
| **NTP Configuration** | Time source, sync interval, reliability | Accurate time synchronization |
| **Server Manager** | Disable auto-start on login | Reduce post-login delays |
| **Power Management** | High performance, disable USB suspend, monitor timeout | Optimize server responsiveness |
| **Windows Update** | Auto-download, notify for install | Controlled update management |
| **Remote Desktop** | NLA requirement, session limits, timeouts | Secure RDP configuration |
| **Security Logging** | Process creation, PowerShell logging, script block logging | Enhanced audit trail |
| **Event Logs** | Application (32MB), Security (128MB), System (32MB) | Adequate log retention |

### ConnectWise Control Deployment Methods

| Method | Use Case | Configuration |
|--------|----------|---------------|
| **Standard Installer** | Self-hosted Control server | `-ControlServer "control.company.com" -AgentToken "{GUID}"` |
| **IT247.net Hosted** | IT247.net managed Control | `-ControlServer "prod.setup.itsupport247.net" -AgentToken "{Full URL}"` |
| **Embedded Agent** | Air-gapped or offline deployment | `-UseEmbeddedAgent` (requires Base64-encoded MSI in script) |

### Usage Examples

```powershell
# Full baseline with standard ConnectWise Control
.\Set-ServerBaseline.ps1 -ControlServer "control.company.com" -AgentToken "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

# Full baseline with IT247.net hosted Control
.\Set-ServerBaseline.ps1 -ControlServer "prod.setup.itsupport247.net" -AgentToken "https://prod.setup.itsupport247.net/windows/BareboneAgent/32/Client_Name_MSI/setup"

# Baseline with embedded agent (offline deployment)
.\Set-ServerBaseline.ps1 -UseEmbeddedAgent

# Baseline without RMM agent
.\Set-ServerBaseline.ps1 -SkipRMMInstall -NTPServer "time.windows.com"

# Skip driver updates (already managed)
.\Set-ServerBaseline.ps1 -ControlServer "control.company.com" -AgentToken "{GUID}" -SkipDriverUpdates

# Disable IE Enhanced Security (domain controllers, application servers)
.\Set-ServerBaseline.ps1 -ControlServer "control.company.com" -AgentToken "{GUID}" -DisableIESecurity

# Non-interactive deployment (automation/MDT/SCCM)
.\Set-ServerBaseline.ps1 -ControlServer "control.company.com" -AgentToken "{GUID}" -Force

# Minimal baseline (skip optional components)
.\Set-ServerBaseline.ps1 -SkipRMMInstall -SkipDriverUpdates -SkipTerminalInstall -SkipPowerShell7
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|----------|
| `-ControlServer` | ConnectWise Control server URL (no https:// or trailing slash) | None |
| `-AgentToken` | Custom Installer ID (GUID) for standard Control, or full URL for IT247.net | None |
| `-NTPServer` | Custom NTP time source | `us.pool.ntp.org` |
| `-SkipRMMInstall` | Skip ConnectWise Control agent deployment | False |
| `-UseEmbeddedAgent` | Use Base64-encoded embedded agent (no network download) | False |
| `-SkipDriverUpdates` | Skip hardware driver updates | False |
| `-SkipServerManager` | Skip disabling Server Manager auto-start | False |
| `-SkipTerminalInstall` | Skip Windows Terminal installation | False |
| `-SkipPowerShell7` | Skip PowerShell 7 installation | False |
| `-DisableIESecurity` | Disable IE Enhanced Security Configuration | False |
| `-Force` | Non-interactive mode, skip all prompts | False |

### Hardware Driver Management

| Manufacturer | Tool | Functionality |
|--------------|------|---------------|
| **Dell** | Dell System Update (DSU) | Automated firmware/driver updates via OpenManage repository |
| **HP** | Service Pack for ProLiant (SPP) | Automated firmware/driver updates via HP repository |
| **Other** | Skipped | Manual driver management required |

### Obtaining ConnectWise Control Tokens

**Standard Self-Hosted Control:**
1. Navigate to Admin > Extensions > Custom Installers
2. Create or select installer configuration
3. Copy the GUID from the installer ID

**IT247.net Hosted Control:**
1. Log into IT247.net client portal
2. Navigate to installer downloads section
3. Copy the full MSI installer URL
4. Use complete URL as `-AgentToken` parameter

### Embedded Agent Configuration

For air-gapped deployments, embed the ConnectWise Control MSI as Base64:

```powershell
# Generate Base64-encoded agent
$bytes = [System.IO.File]::ReadAllBytes("C:\Path\To\Agent.msi")
$base64 = [Convert]::ToBase64String($bytes)
$base64 | Set-Content "agent_base64.txt"

# Add to script's $EmbeddedAgent variable
# Then deploy with -UseEmbeddedAgent switch
```

### Automation Integration

| Platform | Implementation |
|----------|----------------|
| **MDT/WDS** | Add to task sequence post-OS install |
| **SCCM/ConfigMgr** | Deploy as package with `-Force` switch |
| **Azure Automation** | Run via Hybrid Worker on-premises |
| **Group Policy** | Deploy via startup script (requires `-Force`) |
| **Scheduled Task** | First-boot configuration with `-Force` |

### Security Configuration Details

| Setting | Value | Purpose |
|---------|-------|----------|
| **Process Creation Logging** | Enabled | Audit all process starts |
| **PowerShell Module Logging** | Enabled | Log PowerShell module loads |
| **PowerShell Script Block Logging** | Enabled | Log all PowerShell script execution |
| **NLA for RDP** | Required | Prevent unauthenticated RDP enumeration |
| **RDP Session Timeout** | Configured | Auto-disconnect idle sessions |

---

## User Profile Reset (Reset-UserProfile.ps1)

Automates the process of recreating corrupted Windows user profiles while preserving all user data.

### Common Scenarios

| Issue | Symptoms |
|-------|----------|
| **Temporary Profile** | User logs in to TEMP profile, "We can't sign into your account" message |
| **Profile Corruption** | Missing desktop icons, taskbar reset, application settings lost |
| **Failed Windows Update** | Profile damaged after interrupted update or upgrade |
| **NTUSER.DAT Errors** | Registry hive corruption preventing normal login |
| **Slow Login** | Profile takes excessive time to load due to corruption |

### How It Works

| Step | Action | Result |
|------|--------|--------|
| 1 | Verify user logged off | Checks `Win32_UserProfile.Loaded` property |
| 2 | Gather profile info | Collects SID, path, size, last use time |
| 3 | Rename profile folder | `Username` → `Username.old.YYYYMMDD-HHMMSS` |
| 4 | Remove registry entry | Clears `HKLM:\...\ProfileList\{SID}` |
| 5 | User logs in | Windows generates fresh profile automatically |

### Usage Examples

```powershell
# Reset profile on local computer
.\Reset-UserProfile.ps1 -Username "jsmith"

# Reset profile on remote computer
.\Reset-UserProfile.ps1 -Username "jsmith" -ComputerName "WORKSTATION01"

# Preview changes without executing (WhatIf mode)
.\Reset-UserProfile.ps1 -Username "jsmith" -WhatIf

# Skip confirmation prompt (for scripted use)
.\Reset-UserProfile.ps1 -Username "jsmith" -Force

# Custom backup suffix
.\Reset-UserProfile.ps1 -Username "jsmith" -BackupSuffix "backup.corrupted"
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Username` | Target username (must match C:\Users folder name) | Required |
| `-ComputerName` | Target computer (local or remote) | Local computer |
| `-UsersPath` | Base path for user profiles | `C:\Users` |
| `-BackupSuffix` | Custom suffix for renamed folder | `old.YYYYMMDD-HHMMSS` |
| `-Force` | Bypass confirmation prompt | False |
| `-WhatIf` | Preview mode, no changes made | False |

### Profile Information Display

The script displays detailed profile information before proceeding:

```
  Profile Information
  -------------------
  Username        : jsmith
  Computer        : WORKSTATION01
  Profile Path    : C:\Users\jsmith
  Folder Exists   : Yes
  SID             : S-1-5-21-1234567890-1234567890-1234567890-1001
  Profile Loaded  : No
  Last Used       : 12/28/2025 2:30:15 PM
  Registry Entry  : Exists
  Folder Size     : 4.23 GB
```

### Post-Reset Data Migration

After the user logs in and generates a fresh profile, migrate data from the `.old` folder:

| Folder | Contains | Migration Priority |
|--------|----------|-------------------|
| `Desktop` | Desktop files and shortcuts | High |
| `Documents` | User documents | High |
| `Downloads` | Downloaded files | Medium |
| `Pictures` | Photos and images | Medium |
| `Videos` | Video files | Medium |
| `Favorites` | Browser bookmarks (IE/Edge Legacy) | Low |
| `AppData\Local` | Application caches, local settings | As needed |
| `AppData\Roaming` | Application settings, profiles | As needed |

### Safety Features

| Feature | Description |
|---------|-------------|
| **No Data Loss** | Old profile folder renamed, never deleted |
| **Load Check** | Refuses to run if user is logged in |
| **Confirmation** | Requires typing "RESET" to proceed (unless `-Force`) |
| **WhatIf Support** | Preview all actions before execution |
| **Remote Support** | Works via registry remoting and UNC paths |

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
| `Install-SMTPRelay.ps1` | PowerShell 5.1+, Administrator rights, Internet access (NSSM download), Microsoft.Graph module (for auto app creation) |
| `Deploy-RMMAgent.ps1` | PowerShell 5.1+, AD module (for AD query), PSExec.exe, Admin rights on targets |
| `Reset-UserProfile.ps1` | PowerShell 5.1+, Local Administrator rights, User must be logged off |
| `Get-SPOMigrationReadiness.ps1` | PowerShell 5.1+, Read access to source paths |
| `Convert-Legacy*.ps1` | PowerShell 5.1+, Microsoft Office installed |
| `Find-DuplicateFiles.ps1` | PowerShell 5.1+, NTFS (for hardlinks) |
| All scripts | Windows environment |

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
