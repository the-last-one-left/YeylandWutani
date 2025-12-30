# Security

Security assessment, threat detection, compliance tools, and certificate management for Microsoft 365, Windows file systems, and enterprise infrastructure.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Find-RMMArtifacts.ps1` | Detect remnants of RMM tools and remote access software when onboarding new clients |
| `Get-CopilotReadinessReport.ps1` | Microsoft 365 Copilot readiness assessment: licensing, data governance, oversharing risks, sensitive content detection |
| `Find-WildcardCertificateUsage.ps1` | Discover everywhere a wildcard (or any) SSL certificate is used across Windows servers |
| `Get-M365SecurityAnalysis.ps1` | Microsoft 365 security analysis: compromised account detection, sign-in analysis, MFA audit, inbox rules |
| `Get-SPOSecurityReport.ps1` | SharePoint Online security assessment: permissions, external sharing, anonymous links |
| `Get-FileShareSecurityReport.ps1` | Windows file share security audit: NTFS permissions, broken inheritance, orphaned SIDs |

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

These tools are for authorized security testing only. Users must obtain proper authorization before running on production systems.

---

## Requirements

- PowerShell 5.1+
- Microsoft Graph PowerShell modules (for M365/SPO/Copilot tools)
- Exchange Online Management module (for M365 tool)
- SharePoint Online Management Shell (for SPO tool)
- Active Directory PowerShell module (for certificate discovery)
- Admin rights for file system and certificate scanning
- Appropriate admin roles for cloud tools (Security Reader, SharePoint Admin, etc.)

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
