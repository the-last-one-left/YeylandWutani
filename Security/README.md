# Security

Security assessment, threat detection, compliance tools, certificate management, and access recovery for Microsoft 365, Windows file systems, SQL Server, and enterprise infrastructure.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Find-PersistenceThreats.ps1` | Comprehensive Windows persistence mechanism analyzer with threat scoring - scans 22 categories beyond Autoruns |
| `Find-RMMArtifacts.ps1` | Detect remnants of RMM tools and remote access software when onboarding new clients |
| `Get-CopilotReadinessReport.ps1` | Microsoft 365 Copilot readiness assessment: licensing, data governance, oversharing risks, sensitive content detection |
| `Find-WildcardCertificateUsage.ps1` | Discover everywhere a wildcard (or any) SSL certificate is used across Windows servers |
| `Get-M365SecurityAnalysis.ps1` | Microsoft 365 security analysis: compromised account detection, sign-in analysis, MFA audit, inbox rules |
| `Get-SPOSecurityReport.ps1` | SharePoint Online security assessment: permissions, external sharing, anonymous links |
| `Get-FileShareSecurityReport.ps1` | Windows file share security audit: NTFS permissions, broken inheritance, orphaned SIDs |
| `New-SQLTempAdmin.ps1` | SQL Server access recovery: create temporary sysadmin account when locked out of an instance |

---

## Find-PersistenceThreats.ps1 (v1.1.1)

**Purpose:** Comprehensive Windows persistence mechanism analyzer designed for incident response, security assessments, and routine hygiene checks. Scans 22 persistence categories with intelligent threat scoring—detecting techniques that Autoruns and similar tools often miss.

**Why This Matters:** Attackers establish persistence through dozens of Windows mechanisms beyond the obvious startup folders and Run keys. WMI event subscriptions, COM hijacking, IFEO debuggers, and accessibility feature attacks are commonly missed by traditional tools. This scanner finds them all and prioritizes findings by actual threat level.

**Persistence Categories Scanned (22 Total):**

| Category | Detection Focus |
|----------|-----------------|
| Registry Run Keys | 12+ locations including WOW64, Policies, Active Setup, RunServices |
| Startup Folders | User and Common startup with .lnk resolution |
| Scheduled Tasks | Encoded PowerShell detection with automatic Base64 decoding |
| WMI Event Subscriptions | CommandLine and ActiveScript consumers (stealthy persistence) |
| Services | Unusual paths, script executors, auto-start stopped services |
| IFEO Debugger | Image File Execution Options hijacks |
| IFEO GlobalFlag | Silent Process Exit monitors (hidden from Autoruns) |
| Winlogon | Shell, Userinit, Taskman modifications |
| BITS Jobs | Background transfers with NotifyCmdLine persistence |
| AppInit/AppCert DLLs | DLL injection mechanisms |
| Accessibility Hijacks | sethc, utilman, osk, magnify, narrator attacks |
| COM Object Hijacking | HKCU CLSID overrides (InprocServer32/LocalServer32) |
| PowerShell Profiles | All 6 profile locations |
| Browser Extensions | Chrome, Edge, Firefox with manifest parsing |
| Security Providers | SSPs and Authentication Packages |
| Print Monitors | Custom print monitor DLLs |
| Netsh Helpers | Non-System32 helper DLLs |
| Time Providers | Custom W32Time provider DLLs |
| Boot Execute | BootExecute and SetupExecute entries |
| Office Add-ins | Word, Excel, PowerPoint, Outlook across versions, VSTO |

**Threat Scoring System:**

| Score | Level | Meaning |
|-------|-------|---------|
| 70+ | Critical | Requires immediate investigation |
| 50-69 | High | Strong indicators of malicious persistence |
| 30-49 | Medium | Suspicious, warrants review |
| 10-29 | Low | Minor anomalies |
| 0-9 | Info | Informational, likely benign |

**Scoring Factors:**

| Indicator | Points | Description |
|-----------|--------|-------------|
| WMI Persistence | +40 | Often missed by traditional tools |
| Accessibility Hijack | +45 | Sticky keys attack pattern |
| IFEO Debugger | +35 | Process hijacking technique |
| Encoded Command | +35 | Base64/obfuscated PowerShell |
| File Not Found | +30 | Referenced executable missing |
| BITS Job | +30 | Background transfer persistence |
| COM Hijack | +30 | HKCU overriding HKLM |
| Temp Directory | +25 | Executable in temp location |
| Unsigned Binary | +20 | No valid digital signature |
| AppData Location | +10 | User-writable location |
| Recently Created | +10 | Created within 7 days |

**Usage:**
```powershell
# Basic scan - all categories, threat scoring
.\Find-PersistenceThreats.ps1

# High-threat items only with HTML report
.\Find-PersistenceThreats.ps1 -ThreatThreshold 50 -ExportHTML

# Full export (HTML + CSV + JSON)
.\Find-PersistenceThreats.ps1 -ExportHTML -ExportCSV -ExportJSON

# Create baseline for future comparison
.\Find-PersistenceThreats.ps1 -BaselineMode

# Compare against saved baseline
.\Find-PersistenceThreats.ps1 -CompareBaseline ".\baseline_SERVER01_20241229.json"

# Include Microsoft-signed entries (normally filtered)
.\Find-PersistenceThreats.ps1 -IncludeMicrosoft

# Scan remote computer
.\Find-PersistenceThreats.ps1 -ComputerName "SERVER01"

# Preview without making changes
.\Find-PersistenceThreats.ps1 -WhatIf
```

**Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ComputerName` | Target computer(s) to scan | Local machine |
| `-ThreatThreshold` | Minimum score to display (0-100) | 0 (show all) |
| `-ExportHTML` | Generate branded HTML report | $false |
| `-ExportCSV` | Generate CSV export | $false |
| `-ExportJSON` | Generate JSON export | $false |
| `-BaselineMode` | Save results as baseline | $false |
| `-CompareBaseline` | Path to baseline file for comparison | None |
| `-IncludeMicrosoft` | Include Microsoft-signed entries | $false |
| `-WhatIf` | Preview mode | N/A |

**Intelligent Whitelisting:**

The scanner automatically filters known-good software to reduce noise:
- Microsoft products (Teams, Edge, OneDrive, Office, PowerToys)
- Google Chrome and updater components
- Python launcher and shell extensions
- Enterprise software (Zoom, Webex, Cisco, Slack, Adobe)
- Security tools (Cylance, CrowdStrike, SentinelOne, Palo Alto)
- Default Windows WMI filters and Netsh helpers

**Output Example:**
```
================================================================================
  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___
  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|
   \ V /| _| \ V /| |__ / _ \ |  ` | |) |  \ \/\/ /| |_| | | |/ _ \|  ` || |
    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|

                 B U I L D I N G   B E T T E R   S Y S T E M S
================================================================================

[*] Persistence Threat Analyzer v1.1.1
[*] Scanning 22 persistence categories with threat scoring

================================================================================
[*] Scanning: WORKSTATION01
[>] [1/19] Checking Registry Run Keys...
[>] [2/19] Checking Startup Folders...
...
[>] [19/19] Checking Office Add-ins...
[*] Filtered 12 known Microsoft entries

[+] SCAN COMPLETE FOR WORKSTATION01
  Total entries:  180
  Critical:       0
  High:           0
  Medium:         1
  Low:            0
  Info:           179

[!] HIGH-THREAT ENTRIES:
  [MEDIUM] Registry Run Key: {89B4C1CD-B018-4511-B0A1-5476DBF70820}
    Value: C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install

[+] HTML report: C:\Reports\PersistenceThreats_WORKSTATION01_20241230_122949.html

================================================================================
[+] Scan complete.
```

**HTML Report Features:**
- Dark theme with Yeyland Wutani branding
- Summary cards showing Critical/High/Medium/Low/Info counts
- Entries grouped by category, sorted by threat score
- Expandable threat indicators for each finding
- Responsive design for easy viewing

**Advantages Over Autoruns:**

| Feature | Autoruns | Find-PersistenceThreats |
|---------|----------|-------------------------|
| WMI Event Subscriptions | Requires WMI tab | Explicitly checked |
| IFEO GlobalFlag/Silent Exit | Not detected | Full detection |
| Encoded PowerShell | Shows raw | Decodes Base64 |
| Threat Scoring | None | Intelligent prioritization |
| Browser Extensions | Not included | Chrome, Edge, Firefox |
| PowerShell Profiles | Not included | All 6 locations |
| BITS Jobs | Not included | NotifyCmdLine detection |
| Office Add-ins | Not included | All versions + VSTO |
| Baseline Comparison | Manual | Built-in |
| Client Reports | Screenshot | Branded HTML |

**Requirements:**
- PowerShell 5.1+
- Administrator privileges (recommended for full access)
- No external modules required

---

## New-SQLTempAdmin.ps1 (v1.0)

**Purpose:** Emergency access recovery tool for SQL Server instances. Creates a temporary sysadmin login when all administrative access has been lost due to forgotten SA passwords, deleted logins, or domain migration issues.

**Why This Matters:** Getting locked out of SQL Server happens more often than DBAs want to admit—domain migrations, departed employees, forgotten credentials. Reinstalling SQL Server and reattaching databases is time-consuming and risky. This tool leverages SQL Server's single-user mode backdoor to restore access in minutes.

**Common Lockout Scenarios:**
- SA password forgotten and no Windows logins have sysadmin rights
- All sysadmin logins accidentally deleted or disabled
- Server moved to new domain without trusted relationship
- Previous MSP departed without documenting credentials

**How It Works:**

| Step | Action |
|------|--------|
| 1 | Validates prerequisites (admin rights, SQLCMD, service exists) |
| 2 | Stops SQL Server service (disconnects all users) |
| 3 | Starts SQL Server in single-user mode (`-m` flag) |
| 4 | Creates new SQL login via SQLCMD with Windows Authentication |
| 5 | Adds login to sysadmin role |
| 6 | Restarts SQL Server in normal multi-user mode |
| 7 | Verifies new login can connect |

**Usage:**
```powershell
# Default instance - creates 'TempSA' with password 'password'
.\New-SQLTempAdmin.ps1

# Named instance with custom credentials
.\New-SQLTempAdmin.ps1 -InstanceName "SQLEXPRESS" -LoginName "RecoveryAdmin" -Password "Str0ngP@ss!"

# SQL Server 2019 named instance
.\New-SQLTempAdmin.ps1 -InstanceName "SQL2019" -LoginName "EmergencyAccess" -Password "C0mpl3x!Pass"

# Skip confirmation prompts (scripted use)
.\New-SQLTempAdmin.ps1 -Force

# Preview what would happen without making changes
.\New-SQLTempAdmin.ps1 -WhatIf

# Longer timeout for large instances
.\New-SQLTempAdmin.ps1 -ServiceTimeout 120
```

**Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-InstanceName` | SQL Server instance name (MSSQLSERVER for default, or named instance) | MSSQLSERVER |
| `-LoginName` | Name for the new SQL Server login | TempSA |
| `-Password` | Password for the new login | password |
| `-ServiceTimeout` | Seconds to wait for service operations (30-300) | 60 |
| `-Force` | Skip confirmation prompts | $false |
| `-WhatIf` | Preview actions without executing | N/A |

**Instance Name Examples:**

| Installation Type | Instance Name Parameter |
|-------------------|------------------------|
| Default instance | `-InstanceName "MSSQLSERVER"` (or omit) |
| SQL Express | `-InstanceName "SQLEXPRESS"` |
| Named instance | `-InstanceName "SQL2019"` |

**Safety Features:**
- Requires explicit Administrator privileges
- Confirmation prompt before service interruption (unless `-Force`)
- WhatIf support for previewing actions
- Automatic service recovery if creation fails mid-process
- Temporary SQL file cleanup after execution

**Output:**
```
=================================================================================
  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ 
  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|
   \ V /| _| \ V /| |__ / _ \ | .` | |) |  \ \/\/ /| |_| | | |/ _ \| .` || | 
    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|

                        B U I L D I N G   B E T T E R   S Y S T E M S
=================================================================================

SQL Server Temporary Admin Account Recovery
=============================================

[*] Configuration:
   Instance:     MSSQLSERVER
   Service:      MSSQLSERVER
   Server:       localhost
   New Login:    TempSA
   Password:     ********

[>] Checking prerequisites...
[+] Running with Administrator privileges.
[+] SQLCMD utility found.
[+] SQL Server service 'MSSQLSERVER' found. Status: Running

[>] Stopping SQL Server service 'MSSQLSERVER'...
[+] Service stopped successfully.
[>] Starting SQL Server in single-user mode...
[+] SQL Server started in single-user mode.
[>] Creating SQL login 'TempSA'...
[+] Login 'TempSA' created and added to sysadmin role.
[>] Stopping SQL Server service 'MSSQLSERVER'...
[+] Service stopped successfully.
[>] Starting SQL Server in normal mode...
[+] SQL Server started successfully.
[>] Verifying login...
[+] Login verification successful.

============================================================
[+] Recovery complete!

   Connection Details:
   Server:    localhost
   Login:     TempSA
   Password:  password

   Connect via SSMS with SQL Server Authentication

[!] Remember to change the password and remove this account when done.
============================================================
```

**Requirements:**
- Windows local Administrator privileges
- SQLCMD utility (included with SQL Server installations)
- SQL Server service must exist on the local machine
- Must be run directly on the SQL Server host

**Post-Recovery Best Practices:**
1. Connect with the new account via SSMS
2. Re-enable or reset the SA account password
3. Create proper sysadmin logins for authorized users
4. Delete the temporary recovery account
5. Document new credentials in password manager

---

## Find-RMMArtifacts.ps1 (v1.0)

**Purpose:** Essential tool when taking over a new client. Detects remnants of Remote Monitoring and Management (RMM) tools and remote access software that weren't properly removed by the previous MSP.

**Why This Matters:** Leftover RMM artifacts create security vulnerabilities, service conflicts, unnecessary network traffic, and potential unauthorized remote access. This tool scans for artifacts from 30+ RMM and remote access products.

**Detected RMM Platforms:**

| Product | Vendor | Detection Methods |
|---------|--------|-------------------|
| NinjaRMM (NinjaOne) | NinjaOne | Services, Processes, Files, Registry |
| Datto RMM | Datto (Kaseya) | Services, Processes, Files, Registry |
| ConnectWise Automate (LabTech) | ConnectWise | Services, Processes, Files, Registry |
| ConnectWise RMM (Continuum) | ConnectWise | Services, Processes, Files, Registry |
| Atera | Atera Networks | Services, Processes, Files, Registry |
| Kaseya VSA | Kaseya | Services, Processes, Files, Registry |
| Syncro | Syncro MSP | Services, Processes, Files, Registry |
| N-able N-central | N-able | Services, Processes, Files, Registry |
| N-able N-sight | N-able | Services, Processes, Files, Registry |
| Action1 | Action1 Corp | Services, Processes, Files, Registry |
| ManageEngine Desktop Central | Zoho | Services, Processes, Files, Registry |
| Pulseway | Pulseway | Services, Processes, Files, Registry |
| Level | Level.io | Services, Processes, Files, Registry |
| Microsoft Intune | Microsoft | Services, Processes, Files, Registry |

**Detected Remote Access Tools:**

| Product | Vendor |
|---------|--------|
| ConnectWise Control (ScreenConnect) | ConnectWise |
| TeamViewer | TeamViewer GmbH |
| AnyDesk | AnyDesk Software |
| LogMeIn | GoTo |
| GoToAssist / GoTo Resolve | GoTo |
| Splashtop | Splashtop Inc. |
| BeyondTrust (Bomgar) | BeyondTrust |
| Chrome Remote Desktop | Google |
| VNC variants (Tight/Ultra/Real) | Various |
| Zoho Assist | Zoho Corp |
| RustDesk | RustDesk |
| SimpleHelp | SimpleHelp |
| DWService | DWService |
| RemotePC | iDrive |
| Supremo | Nanosystems |

**Detection Methods:**
- **Windows Services**: Running and stopped services from all detected products
- **Running Processes**: Active processes indicating live RMM connections
- **File System**: Installation directories in Program Files, ProgramData, AppData
- **Registry Keys**: HKLM/HKCU entries including uninstall keys
- **Installed Software**: Registry-based software enumeration
- **Scheduled Tasks**: Persistence mechanisms via task scheduler

**Usage:**
```powershell
# Basic local scan (all RMM and remote access tools)
.\Find-RMMArtifacts.ps1

# Scan multiple computers
.\Find-RMMArtifacts.ps1 -ComputerName "PC01","PC02","PC03"

# Exclude your current RMM from results
.\Find-RMMArtifacts.ps1 -ExcludeProducts "NinjaRMMAgent"

# RMM tools only (skip remote access detection)
.\Find-RMMArtifacts.ps1 -IncludeRemoteAccess:$false

# Export CSV alongside HTML report
.\Find-RMMArtifacts.ps1 -ExportCSV -OutputPath "C:\Reports"

# Pipeline from Active Directory
Get-ADComputer -Filter "Name -like 'WS-*'" | 
    Select-Object -ExpandProperty Name | 
    .\Find-RMMArtifacts.ps1 -OutputPath "C:\ClientOnboarding"
```

**Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ComputerName` | Target computer(s) to scan | Local computer |
| `-OutputPath` | Report output directory | Current directory |
| `-ExportCSV` | Generate CSV exports with HTML | HTML only |
| `-IncludeRemoteAccess` | Include remote access tools in scan | $true |
| `-ExcludeProducts` | Array of product names to exclude | None |
| `-DeepScan` | Enable thorough file system scanning | $false |

**Report Features:**
- **Risk Level Assessment**: Clean / Low / Medium / High / Critical based on artifact count
- **Product Cards**: Expandable details for each detected product
- **Artifact Breakdown**: Services, processes, files, registry, tasks per product
- **Service Status**: Running vs. stopped state for each detected service
- **Console Summary**: Quick overview with color-coded findings

**Requirements:**
- PowerShell 5.1+
- Admin rights (for service/registry access)
- WinRM enabled (for remote computer scanning)
- No external dependencies

---

## Get-CopilotReadinessReport.ps1 (v1.2)

**Purpose:** Comprehensive pre-deployment assessment for Microsoft 365 Copilot. Identifies licensing gaps, data governance issues, and oversharing risks that could expose sensitive content through Copilot.

**Why This Matters:** Copilot surfaces content based on user permissions. Sites with "Everyone" access, organization-wide sharing links, or sensitive files become accessible to ALL Copilot users—even if they weren't explicitly shared.

**Assessment Areas:**

| Area | What's Analyzed |
|------|-----------------|
| **Licensing** | Eligible base licenses (E3/E5/Business Premium), Copilot assignments, available licenses |
| **Data Governance** | Sensitivity labels configuration, labeled M365 Groups percentage |
| **Security Posture** | Conditional Access policies, guest user count, MFA indicators |
| **User Readiness** | Active users (30-day), OneDrive provisioning status, Teams/Outlook/OneDrive usage |
| **Sharing Links** | Anonymous links, organization-wide links with file counts and locations |
| **SharePoint Sites** | "Everyone" access detection, permission complexity, oversharing risk scoring |
| **Sensitive Content** | Files containing PII keywords (SSN, credit card, password, confidential) |
| **Teams** | Team count, guest member detection |

**Usage:**
```powershell
# Standard assessment (prompts for authentication)
.\Get-CopilotReadinessReport.ps1

# Reuse existing Graph session
.\Get-CopilotReadinessReport.ps1 -SkipNewConnection

# Custom client name for report branding
.\Get-CopilotReadinessReport.ps1 -ClientName "Contoso Corporation"

# Export CSV data alongside HTML report
.\Get-CopilotReadinessReport.ps1 -ExportCSV -OutputPath "C:\Reports"

# Adjust activity threshold
.\Get-CopilotReadinessReport.ps1 -DaysInactive 60 -TopCandidates 100
```

**Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputPath` | Report output directory | Current directory |
| `-ClientName` | Override organization name in report | Auto-detected from tenant |
| `-SkipNewConnection` | Reuse existing Graph session | Forces new auth |
| `-ExportCSV` | Generate CSV exports with HTML | HTML only |
| `-TopCandidates` | Number of top Copilot candidates to identify | 50 |
| `-DaysInactive` | Inactivity threshold for flagging users | 30 |

**Required Graph Permissions:**
- User.Read.All, Directory.Read.All, Reports.Read.All
- Policy.Read.All, Sites.Read.All, Group.Read.All
- Organization.Read.All

**Required Modules:**
- Microsoft.Graph.Authentication
- Microsoft.Graph.Users
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.Reports
- Microsoft.Graph.Groups

---

## Find-WildcardCertificateUsage.ps1 (v1.0)

**Purpose:** Essential tool for certificate renewals and compliance auditing. Discovers all locations where a specific certificate (especially wildcards) is deployed across your infrastructure.

**Discovery Methods:**
- **Certificate Store Enumeration**: Scans LocalMachine\My store on remote servers via PowerShell Remoting
- **IIS Bindings**: Identifies which websites are using the certificate
- **RDP Configuration**: Checks Remote Desktop certificate assignments via WMI
- **HTTP.SYS Bindings**: Examines SSL bindings registered with HTTP.SYS
- **SSL Port Probing**: Directly connects to common SSL ports to identify certificates in use

**Usage:**
```powershell
# Find by thumbprint (recommended for wildcards)
.\Find-WildcardCertificateUsage.ps1 -Thumbprint "A1B2C3D4E5F6789012345678901234567890ABCD"

# Find by subject pattern
.\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*.contoso.com"

# Find by friendly name
.\Find-WildcardCertificateUsage.ps1 -FriendlyName "Contoso Wildcard 2024"

# Search specific servers (from list)
.\Find-WildcardCertificateUsage.ps1 -Thumbprint "A1B2..." -ComputerName (Get-Content servers.txt)

# Port-only scan (when remoting unavailable)
.\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*wildcard*" -SkipRemoting -ScanPorts 443,8443,3389
```

**Requirements:** PowerShell 5.1+, PowerShell Remoting, AD module

---

## Get-M365SecurityAnalysis.ps1 (v10.2)

**Capabilities:**
- Sign-in log analysis with geolocation and high-risk ISP detection
- Attack pattern detection: password spray, brute force, confirmed breach
- MFA status audit with privileged account focus
- Inbox rule analysis for data exfiltration patterns
- Admin audit log monitoring with risk scoring
- App registration analysis for OAuth abuse

**Usage:**
```powershell
# Launch GUI application
.\Get-M365SecurityAnalysis.ps1

# Workflow:
# 1. Connect to Microsoft 365
# 2. Set date range (default: 14 days)
# 3. Run data collection operations
# 4. Generate HTML security report
```

**Required Modules:** Microsoft.Graph.*, ExchangeOnlineManagement

---

## Get-SPOSecurityReport.ps1 (v3.1)

**Capabilities:**
- Site permission enumeration (Admins, Owners, Members, Visitors)
- External sharing configuration audit
- Anonymous link discovery
- Storage distribution analysis
- Document library inventory

**Usage:**
```powershell
# Basic security report
.\Get-SPOSecurityReport.ps1 -TenantName "contoso"

# Full deep-dive with library analysis
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive -OutputPath "C:\Reports"

# Include OneDrive sites
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -IncludeOneDrive
```

**Required Modules:** Microsoft.Graph.*, Microsoft.Online.SharePoint.PowerShell

---

## Get-FileShareSecurityReport.ps1 (v1.1)

**Capabilities:**
- NTFS permission analysis with risk classification
- Share permission enumeration (SMB level)
- Broken inheritance detection with complexity scoring
- Orphaned SID identification (deleted accounts in ACLs)
- High-risk permission flagging (Everyone, Authenticated Users, Domain Users)

**Usage:**
```powershell
# Basic local share scan
.\Get-FileShareSecurityReport.ps1 -Path "D:\Shares"

# Remote share with deep scan
.\Get-FileShareSecurityReport.ps1 -Path "\\FileServer\Data" -MaxDepth 8 -OutputPath "C:\Reports"

# Multiple paths, fast scan
.\Get-FileShareSecurityReport.ps1 -Path @("D:\Finance", "D:\HR") -SkipSizeCalculation
```

**Risk Levels:**
- **Critical**: Everyone/Auth Users with FullControl or Modify
- **High**: Broad groups (BUILTIN\Users) with write access
- **Medium**: Interactive/Network users with elevated permissions

---

## Security Notice

These tools are for authorized security testing and recovery only. Users must obtain proper authorization before running on production systems. SQL Server recovery tools should only be used on systems you are authorized to administer.

---

## Requirements

- PowerShell 5.1+
- Microsoft Graph PowerShell modules (for M365/SPO/Copilot tools)
- Exchange Online Management module (for M365 tool)
- SharePoint Online Management Shell (for SPO tool)
- Active Directory PowerShell module (for certificate discovery)
- SQLCMD utility (for SQL Server recovery)
- Admin rights for file system, certificate, and SQL Server operations
- Appropriate admin roles for cloud tools (Security Reader, SharePoint Admin, etc.)

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
