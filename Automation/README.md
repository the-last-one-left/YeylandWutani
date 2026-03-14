# Automation
PowerShell scripts for system provisioning, cleanup operations, migration preparation, software deployment, profile management, certificate lifecycle management, email infrastructure, and file management automation.

---

## Available Scripts

### Certificate Management

| Script | Description |
|--------|-------------|
| `Invoke-LetsEncryptRenewal.ps1` | Full Let's Encrypt certificate lifecycle management for MSP environments. Interactive guided setup or fully unattended via scheduled task. Supports IIS binding updates, RD Gateway, PFX export, and WatchGuard Firebox deployment via SSH. Handles HTTP-01 and DNS-01 (30+ provider plugins) challenges, wildcard and multi-domain SANs, DPAPI-encrypted credential storage, expired cert cleanup, and optional email reporting via Microsoft 365 Graph API or SMTP. |

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

### Microsoft 365 Administration

| Script | Description |
|--------|-------------|
| `Audit-365Archives.ps1` | Audits Online Archive mailboxes in a source tenant post-migration. Dynamically identifies an available license with Exchange Online archiving, temporarily assigns it, retrieves primary and archive mailbox statistics, then removes the license. Exports incremental CSV and YW-branded HTML report. |

### Utilities

| Script | Description |
|--------|-------------|
| `Get-SalesTaxRate.ps1` | Queries Avalara's public tax rate endpoint for U.S. sales tax rates. Supports address-based and coordinate-based lookup. Returns combined rate with full jurisdiction breakdown (State, County, City, Special). No API key required. Pipeline-friendly for batch processing. |

### AI Chat Client

| Script | Description |
|--------|-------------|
| `Invoke-HatzChat.ps1` | Interactive terminal chat client for Hatz AI API. Multi-model support (Claude, GPT-4, Gemini), file editing via search/replace blocks, folder context injection, tool integration, DPAPI-encrypted credential storage, conversation history, and visual feedback (spinner, token bar). |

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

## Let's Encrypt Certificate Renewal (Invoke-LetsEncryptRenewal.ps1)

Automated Let's Encrypt certificate lifecycle management designed for MSP environments. Run interactively once to configure and install a scheduled task; subsequent renewals happen fully unattended as SYSTEM.

### Deployment Modes

| Mode | Target | How It Works |
|------|--------|--------------|
| **IIS** | Local IIS | Imports cert to `Cert:\LocalMachine\WebHosting` (or `\My`), updates all matching HTTPS bindings |
| **RD Gateway** | Local TSGateway service | Imports to `Cert:\LocalMachine\My`, binds via RDS PowerShell drive or WMI, restarts TSGateway |
| **PFX Export** | Any server (Apache, nginx, load balancer) | Exports PFX + plain-text password file to a specified folder |
| **WatchGuard Firebox** | Firebox Web UI SSL cert | SSH to Firebox, transfers PFX via ephemeral FTP server, imports and activates as `web-server-cert` |

### Challenge Types

| Type | Use Case | Wildcard Support |
|------|----------|-----------------|
| **HTTP-01** | Port 80 accessible from internet, IIS present | No |
| **DNS-01 (plugin)** | Automated TXT record via provider API (30+ plugins) | Yes |
| **DNS-01 (manual)** | No API access; script pauses for manual TXT creation | Yes |

> DNS-01 plugin examples: Azure, Cloudflare, GoDaddy, Route53, Namecheap, Hetzner, Porkbun, DuckDNS, and 25+ more. Run `Get-PAPlugin` after install to list all.

### Key Features

| Feature | Description |
|---------|-------------|
| **Interactive Setup** | Guided menu on first run — no parameters required |
| **Unattended Renewal** | Scheduled task runs daily as SYSTEM; only renews within threshold window |
| **Renewal Threshold** | Configurable (default 30 days). Cert checked daily; email only sent on action |
| **Shared Cert Cache** | Posh-ACME data stored in `ProgramData` — same cache for interactive user and SYSTEM |
| **DPAPI Credentials** | All secrets (DNS plugin, Firebox SSH, email) encrypted with LocalMachine DPAPI, ACL-restricted |
| **Wildcard Certs** | Supported via DNS-01 (e.g. `*.contoso.com`) |
| **Multi-Domain SANs** | Multiple domains on a single certificate via `-AdditionalDomains` |
| **Staging Support** | `-Staging` flag for testing without consuming rate limits |
| **Expired Cert Cleanup** | Auto-removes expired Let's Encrypt certs from both cert stores on every run |
| **Email Reporting** | Success/failure/update notifications via Graph API (OAuth2) or SMTP (STARTTLS) |
| **Update Task** | Menu option to refresh credentials or reconfigure without reissuing the cert |

### Interactive Menu

On first run without parameters, a guided menu walks through all configuration:

```
  Let's Encrypt Certificate Manager v1.4.0
  ─────────────────────────────────────────
  What would you like to do?

  [1] Request/renew a certificate (one-time)
  [2] Request/renew + install scheduled auto-renewal task
  [3] Remove existing scheduled renewal task
  [4] Update existing scheduled task (refresh credentials / reconfigure)
  [5] Exit
```

Followed by deployment target, challenge type, and optional email reporting configuration.

### Usage Examples

```powershell
# First-time interactive setup (recommended) — menu guides through everything
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com"

# Staging test run (not browser-trusted, avoids rate limits)
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" -Staging

# Non-interactive: IIS, HTTP-01, install scheduled task at 3 AM
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" `
    -DeployMode IIS -InstallScheduledTask

# Wildcard via Cloudflare DNS-01, PFX export
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "*.contoso.com" -ContactEmail "admin@contoso.com" `
    -ChallengeType Dns -DnsPlugin Cloudflare `
    -DnsPluginArgs @{ CFToken = (Read-Host "CF Token" -AsSecureString) } `
    -DeployMode PFX -PfxOutputPath "C:\Certs"

# WatchGuard Firebox web-server-cert, DNS-01, scheduled task
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "fw.contoso.com" -ContactEmail "admin@contoso.com" `
    -ChallengeType Dns -DnsPlugin Cloudflare `
    -DnsPluginArgs @{ CFToken = (Read-Host "CF Token" -AsSecureString) } `
    -DeployMode WatchGuard -FireboxHost 10.0.0.1 -InstallScheduledTask

# RD Gateway (run on the RD Gateway server)
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "gateway.contoso.com" -ContactEmail "admin@contoso.com" `
    -DeployMode RDGateway -InstallScheduledTask

# Force immediate renewal (ignore threshold)
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" `
    -DeployMode IIS -ForceRenewal

# Remove scheduled task
.\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" `
    -RemoveScheduledTask
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-DomainName` | Primary domain (certificate CN) | Required |
| `-ContactEmail` | Let's Encrypt account contact email | Required |
| `-AdditionalDomains` | Additional SANs on the certificate | None |
| `-ChallengeType` | `Http`, `Dns`, or `DnsManual` | `Http` |
| `-DnsPlugin` | Posh-ACME DNS plugin name | None |
| `-DnsPluginArgs` | Hashtable of plugin credentials | None |
| `-DnsSleep` | DNS propagation wait in seconds | `120` |
| `-RenewalDays` | Days before expiry to trigger renewal | `30` |
| `-DeployMode` | `IIS`, `RDGateway`, `PFX`, or `WatchGuard` | Prompted |
| `-PfxOutputPath` | Folder for PFX export (sets PFX mode) | None |
| `-FireboxHost` | Firebox hostname or IP (WatchGuard mode) | Prompted |
| `-FireboxSshPort` | Firebox SSH port | `4118` |
| `-FireboxLocalIP` | This machine's IP for Firebox FTP callback | Auto-detected |
| `-FireboxFtpPort` | Local FTP port for cert transfer | `2121` |
| `-InstallScheduledTask` | Install daily scheduled renewal task | False |
| `-TaskTime` | Scheduled task run time | `03:00` |
| `-RemoveScheduledTask` | Remove the scheduled task | False |
| `-SendReport` | Enable email status reporting | False |
| `-Staging` | Use Let's Encrypt staging environment | False |
| `-ForceRenewal` | Renew even if cert is still valid | False |
| `-CertStorePath` | Windows cert store path | `Cert:\LocalMachine\WebHosting` |

### WatchGuard Firebox Deployment

Deploys the certificate to the Firebox Web UI SSL (`web-server-cert`) using a fully automated SSH + FTP pipeline:

```
Script (PowerShell)
    ↓ SSH (port 4118) — Posh-SSH module
WatchGuard Firebox CLI
    ↓ FTP callback (port 2121) — ephemeral in-process FTP server
Script receives PFX transfer request → sends fullchain.pfx
    ↓ Firebox imports and activates cert
web-server-cert updated → Firebox Web UI now uses new cert
```

**Credential Security:** SSH credentials are encrypted with DPAPI (LocalMachine scope) and stored in `firebox_creds.json`. The scheduled task reads these without prompting — no plaintext secrets in task arguments.

> **Note:** IKEv2 Mobile VPN certificate assignment via CLI is not available on Fireware v12.10+. That requires manual update in the Firebox Web UI.

### RD Gateway Deployment

Binds the certificate to the TSGateway service via the RDS PowerShell drive (with WMI fallback). TSGateway is restarted to apply the cert — active gateway sessions will be dropped briefly.

**Requirements:**
- Script must run **on the RD Gateway server** (not remotely)
- Remote Desktop Gateway role service must be installed
- The menu always shows this option; an error is thrown at deploy time if TSGateway is not present

### Email Reporting

Sends HTML-formatted reports on renewal outcomes. Skipped runs (cert not yet due) do not generate emails — only Success, Failed, and Updated events trigger a notification.

| Method | Configuration | Requirements |
|--------|--------------|--------------|
| **Microsoft 365 Graph API** | Tenant ID, Client ID, Client Secret | `Mail.Send` Application permission + admin consent |
| **SMTP** | Server, port, credentials | STARTTLS supported on port 587 |

The client secret (Graph) and SMTP password are DPAPI-encrypted at rest. Configure during interactive setup — settings persist for all future task runs.

### Credential Storage

All secrets are encrypted with Windows DPAPI (LocalMachine scope) and stored in `C:\ProgramData\YeylandWutani\LetsEncrypt\`:

| File | Contents |
|------|----------|
| `plugin_creds.json` | DNS plugin API credentials |
| `firebox_creds.json` | Firebox SSH username + password |
| `email_config.json` | Graph/SMTP settings + encrypted secret/password |

Files are ACL-restricted to Administrators and SYSTEM. The scheduled task (running as SYSTEM) can decrypt all secrets without any user interaction.

### Scheduled Task Behavior

| Run Condition | Action | Email? |
|---------------|--------|--------|
| Cert has >30 days remaining | Log skip, exit | No |
| Cert within 30-day window | Renew + deploy | Yes (Success) |
| Renewal fails | Log error | Yes (Failed) |
| Update task selected (menu option 4) | Reinstall task, no cert order | Yes (Updated) |

Posh-ACME data (accounts, orders, cached certs) is stored in `C:\ProgramData\YeylandWutani\PoshAcme` — a shared path accessible to both the interactive user and the SYSTEM account, preventing unnecessary re-issuance.

### Expired Certificate Cleanup

On every run, the script sweeps `Cert:\LocalMachine\WebHosting` and `Cert:\LocalMachine\My` for expired Let's Encrypt certificates (identified by issuer) and removes them automatically. Any cert currently assigned to an IIS SSL binding is always protected regardless of expiry date.

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

## Hatz AI Chat Client (Invoke-HatzChat.ps1)

Interactive terminal-based chat client for the Hatz AI API with file editing capabilities, conversation management, and tool integration.

### Architecture

```
PowerShell Terminal
    ↓ HTTPS (X-API-Key auth)
Hatz AI API (ai.hatz.ai/v1)
    ↓ Model selection
Claude, GPT-4, Gemini, etc.
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Model Support** | Access all Hatz AI models (Claude Opus/Sonnet, GPT-4o, Gemini, etc.) |
| **Conversation History** | Maintains context across turns with configurable history limit |
| **File Editing** | `/edit` command with search/replace blocks for precise code changes |
| **Folder Context** | `/folder` injects entire directories as conversation context |
| **Tool Integration** | Enable web search, code execution, and other Hatz tools |
| **System Prompts** | Persistent system prompts stored locally |
| **DPAPI Encryption** | API keys encrypted at rest using Windows DPAPI |
| **Live Spinner** | Animated spinner with elapsed time during API calls |
| **Token Tracking** | Per-response and session token usage with context bar |
| **Multiline Input** | `/multi` command for composing multi-line prompts |

### Installation

No installation required. Run directly from PowerShell 5.1+:

```powershell
# First run - prompts for API key (saved securely via DPAPI)
.\Invoke-HatzChat.ps1

# With specific model
.\Invoke-HatzChat.ps1 -DefaultModel "anthropic.claude-sonnet-4-5"

# Pass API key directly (not persisted)
.\Invoke-HatzChat.ps1 -ApiKey "your-key-here"
```

### Commands Reference

| Command | Description |
|---------|-------------|
| `/help` | Show all available commands |
| `/quit` | Exit the chat session |
| `/clear` | Clear conversation history (keeps system prompt) |
| `/model` | Switch to a different model |
| `/system` | View or update the system prompt |
| `/history` | Display conversation history |
| `/context` | Show current context size and token usage |
| `/file <path>` | Inject a file's contents into the conversation |
| `/folder [path]` | Inject files from a folder (selective or all) |
| `/edit <path>` | Edit a file using AI-generated search/replace blocks |
| `/run <path>` | Execute a script and capture output |
| `/workspace [path]` | Set working directory for relative paths |
| `/tools` | List and enable/disable available tools |
| `/autotools` | Toggle automatic tool selection |
| `/multi` | Enter multiline input mode (end with `.` on its own line) |

### File Editing (`/edit`)

The `/edit` command uses a search/replace block approach (inspired by Aider) for precise code modifications:

```
<<<<<<< SEARCH
exact original lines to find
=======
replacement lines
>>>>>>> REPLACE
```

**Benefits over full-file replacement:**

| Approach | Tokens | Accuracy | Speed |
|----------|--------|----------|-------|
| Full file return | ~2000+ | Phantom edits possible | Slow, timeouts |
| **Search/Replace** | ~100-300 | Only specified lines change | Fast |

**Three-tier matching:**
1. Exact substring match
2. Normalized line endings (CRLF → LF)
3. Whitespace-fuzzy (handles indentation variations)

**Safety features:**
- `.bak` file created before overwriting
- Preview diff before applying
- Partial application option if some blocks fail

### Folder Injection (`/folder`)

Inject directory contents as conversation context:

```powershell
/folder              # Lists files in workspace, prompts for selection
/folder all          # Injects all text files (with progress bar)
/folder C:\Projects  # Inject from specific path
```

Binary files are automatically excluded. Progress bar shows injection status for large directories.

### Tool Integration

Enable Hatz AI tools for enhanced capabilities:

```powershell
/tools                    # List available tools
/tools google_search      # Enable specific tool
/autotools               # Toggle automatic tool selection
```

Available tools include:
- `google_search` - Web search
- `tavily_search` - Research search
- `firecrawl` - Web page content extraction
- `code_interpreter` - Python code execution

### UX Features

| Feature | Description |
|---------|-------------|
| **Animated Spinner** | Shows `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` during API calls with elapsed time |
| **Token Budget Bar** | Visual `[████████░░░░░░]` showing context window usage |
| **Retry Countdown** | Live `[~] Retrying in 5s... 4s...` on transient errors |
| **Command Hints** | `/edti` → `Did you mean: /edit` |
| **Syntax Highlighting** | Basic code highlighting in responses (PS7+/Windows Terminal) |

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ApiBaseUrl` | Override API endpoint | `https://ai.hatz.ai/v1` |
| `-EnvVarName` | Environment variable for API key | `HATZ_AI_API_KEY` |
| `-ApiKey` | Pass API key directly (not persisted) | None |
| `-DefaultModel` | Model to use without prompting | `anthropic.claude-opus-4-6` |
| `-MaxHistory` | Max non-system messages kept (0 = unlimited) | `40` |

### Credential Storage

API keys are encrypted using Windows DPAPI and stored in:

```
%APPDATA%\HatzChat\api_key.clixml
```

DPAPI encrypts per-user/per-machine — the file cannot be decrypted on another machine or by another Windows user account.

**Migration:** If a plaintext API key exists in the legacy environment variable, it's automatically migrated to the encrypted file and the env var is cleared.

### Context Limits

Built-in context window sizes for token budget tracking:

| Model | Context Window |
|-------|----------------|
| `anthropic.claude-opus-4-6` | 200,000 |
| `anthropic.claude-sonnet-4-5` | 200,000 |
| `openai.gpt-4o` | 128,000 |
| `openai.gpt-4-turbo` | 128,000 |
| `google.gemini-2.0-flash` | 1,000,000 |

### Requirements

- PowerShell 5.1+ (native `Invoke-RestMethod`)
- Internet access to Hatz AI API
- Hatz AI API key (generate at Hatz Admin Dashboard > Settings)

### Troubleshooting

| Issue | Solution |
|-------|----------|
| **Invalid API key** | Delete credential file and re-run: `Remove-Item "$env:APPDATA\HatzChat\api_key.clixml"` |
| **Timeout on large requests** | Use `/edit` instead of pasting full files; timeouts are retried automatically |
| **UTF-8 encoding issues** | Script sets console encoding to UTF-8; ensure Windows Terminal or PS7 for best results |
| **Spinner not animating** | Legacy console detected; falls back to ASCII spinner `\|/-` |

---

## Audit-365Archives.ps1

Post-migration tool for auditing Online Archive mailboxes in Microsoft 365 tenants. Designed for decommissioning scenarios where archive mailboxes did not migrate and need assessment before shutting down the source tenant.

### How It Works

1. Dynamically identifies any available license SKU containing Exchange Online (Plan 2) archiving
2. Temporarily assigns the license to each user
3. Waits for archive mailbox provisioning (configurable delay)
4. Retrieves primary and archive mailbox statistics (size, item count, dates, last logon)
5. Removes the temporary license
6. Writes incremental CSV results and generates a YW-branded HTML report

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-InputCsv` | All tenant members | Path to CSV with `UserPrincipalName` column. Omit to process all accounts (including disabled — intentional for decommissioning). |
| `-OutputPath` | Current directory | Base path for output files (script appends `.csv` and `.html`) |
| `-WaitTimeSeconds` | 180 | Seconds to wait for archive provisioning after license assignment |
| `-MaxRetries` | 3 | Retry attempts when checking for archive mailbox (60-second intervals) |

### Usage Examples

```powershell
# Audit all mailboxes in tenant
.\Audit-365Archives.ps1 -OutputPath "C:\Reports\ArchiveAudit"

# Process specific users from CSV with extended provisioning wait
.\Audit-365Archives.ps1 -InputCsv "C:\Users.csv" -WaitTimeSeconds 240

# Default run (all users, results in current directory)
.\Audit-365Archives.ps1
```

### Requirements

- Microsoft.Graph.Users module
- ExchangeOnlineManagement module
- Exchange Administrator or Global Administrator role
- Available licenses that include Exchange Online Plan 2 (Archiving)

---

## Get-SalesTaxRate.ps1

U.S. sales tax rate lookup using Avalara's public calculator endpoint. No API key or account required. Supports address-based and coordinate-based lookups with a full jurisdiction breakdown. Pipeline-friendly for batch processing.

### Lookup Modes

| Mode | Parameters | Example |
|------|-----------|---------|
| **Address** | `-LineAddress1`, `-City`, `-Region` | `.\Get-SalesTaxRate.ps1 -LineAddress1 "350 5th Ave" -City "New York" -Region "NY"` |
| **Coordinates** | `-Latitude`, `-Longitude` | `.\Get-SalesTaxRate.ps1 -Latitude 47.6062 -Longitude -122.3321` |

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-LineAddress1` | Street address |
| `-City` | City name |
| `-Region` | Two-letter state code (e.g., `WA`, `NY`) |
| `-Latitude` | Decimal latitude (coordinate mode) |
| `-Longitude` | Decimal longitude (coordinate mode) |
| `-Amount` | Optional dollar amount to calculate tax on |
| `-Raw` | Return raw API response object for scripting |

### Usage Examples

```powershell
# Basic address lookup
.\Get-SalesTaxRate.ps1 -LineAddress1 "1 Microsoft Way" -City "Redmond" -Region "WA"

# Calculate tax on a purchase amount
.\Get-SalesTaxRate.ps1 -LineAddress1 "350 5th Ave" -City "New York" -Region "NY" -Amount 1500.00

# Coordinate-based lookup
.\Get-SalesTaxRate.ps1 -Latitude 47.6062 -Longitude -122.3321

# Batch lookup from CSV
Import-Csv .\addresses.csv | ForEach-Object {
    .\Get-SalesTaxRate.ps1 -LineAddress1 $_.Street -City $_.City -Region $_.State
} | Export-Csv .\tax_rates.csv -NoTypeInformation
```

### Notes

- Uses Avalara's public unauthenticated endpoint (same as the free web calculator)
- For high-volume or production use, consider Avalara's official AvaTax API with credentials
- Returns rates as percentages (e.g., `10.2` = 10.2%)

---

## Requirements

| Script | Requirements |
|--------|--------------|
| `Invoke-LetsEncryptRenewal.ps1` | PowerShell 5.1+, Administrator rights, Internet access to Let's Encrypt ACME endpoints. Posh-ACME auto-installed. Posh-SSH auto-installed for WatchGuard mode. IIS optional (HTTP-01 / IIS binding). TSGateway service required on-box for RD Gateway mode. |
| `Invoke-HatzChat.ps1` | PowerShell 5.1+, Internet access to Hatz AI API (`ai.hatz.ai`), Hatz AI API key. No additional modules required. |
| `Install-SMTPRelay.ps1` | PowerShell 5.1+, Administrator rights, Internet access (NSSM download), Microsoft.Graph module (for auto app creation) |
| `Deploy-RMMAgent.ps1` | PowerShell 5.1+, AD module (for AD query), PSExec.exe, Admin rights on targets |
| `Reset-UserProfile.ps1` | PowerShell 5.1+, Local Administrator rights, User must be logged off |
| `Get-SPOMigrationReadiness.ps1` | PowerShell 5.1+, Read access to source paths |
| `Convert-Legacy*.ps1` | PowerShell 5.1+, Microsoft Office installed |
| `Find-DuplicateFiles.ps1` | PowerShell 5.1+, NTFS (for hardlinks) |
| `Audit-365Archives.ps1` | PowerShell 5.1+, Microsoft.Graph.Users module, ExchangeOnlineManagement module, Exchange Administrator or Global Administrator role |
| `Get-SalesTaxRate.ps1` | PowerShell 5.1+, Internet access (no API key required) |
| All scripts | Windows Server 2016+ or Windows 10/11, PowerShell 5.1+ |

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
