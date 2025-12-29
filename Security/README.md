# Security

Security assessment, threat detection, compliance tools, and certificate management for Microsoft 365, Windows file systems, and enterprise infrastructure.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-CopilotReadinessReport.ps1` | Microsoft 365 Copilot readiness assessment: licensing, data governance, oversharing risks, sensitive content detection, sharing link analysis |
| `Find-WildcardCertificateUsage.ps1` | Discover everywhere a wildcard (or any) SSL certificate is used across Windows servers |
| `Get-M365SecurityAnalysis.ps1` | Microsoft 365 security analysis: compromised account detection, sign-in analysis, MFA audit, inbox rules, admin logs |
| `Get-SPOSecurityReport.ps1` | SharePoint Online security assessment: permissions, external sharing, anonymous links, storage analysis |
| `Get-FileShareSecurityReport.ps1` | Windows file share security audit: NTFS permissions, broken inheritance, orphaned SIDs, high-risk ACLs |

---

## Get-CopilotReadinessReport.ps1 (v1.0)

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

**Report Highlights:**

- **Readiness Score**: 0-100% weighted across licensing, governance, security, and user readiness
- **Critical Alerts**: Red warning boxes for "Everyone" access sites, anonymous sharing links
- **Sensitive Content Detection**: Scans document libraries for PII keyword matches
- **Sharing Link Analysis**: Identifies anonymous and org-wide links with file counts
- **Risk-Scored Sites**: HIGH/MEDIUM/LOW classification with direct links to review permissions
- **OneDrive Provisioning**: Clear explanation of what it means and who needs it

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

**Output Files:**
- `CopilotReadiness_{ClientName}_{Timestamp}.html` - Full visual report
- `CopilotReadiness_Licenses.csv` - License summary (with -ExportCSV)
- `CopilotReadiness_EligibleUsers.csv` - Eligible users list (with -ExportCSV)
- `CopilotReadiness_SensitivityLabels.csv` - Labels configured (with -ExportCSV)

---

## Find-WildcardCertificateUsage.ps1 (v1.0)

**Purpose:** Essential tool for certificate renewals and compliance auditing. Discovers all locations where a specific certificate (especially wildcards) is deployed across your infrastructure.

**Discovery Methods:**
- **Certificate Store Enumeration**: Scans LocalMachine\My store on remote servers via PowerShell Remoting
- **IIS Bindings**: Identifies which websites are using the certificate
- **RDP Configuration**: Checks Remote Desktop certificate assignments via WMI
- **HTTP.SYS Bindings**: Examines SSL bindings registered with HTTP.SYS
- **SSL Port Probing**: Directly connects to common SSL ports to identify certificates in use

**Search Options:**
- Thumbprint (most reliable - same wildcard cert has identical thumbprints everywhere)
- Subject pattern (e.g., `*.contoso.com`)
- Friendly name

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

# Limit to specific OU in AD
.\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*.domain.com" -OUSearchBase "OU=Servers,DC=domain,DC=com"

# Port-only scan (when remoting unavailable)
.\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*wildcard*" -SkipRemoting -ScanPorts 443,8443,3389

# Custom ports and timeout
.\Find-WildcardCertificateUsage.ps1 -Thumbprint "A1B2..." -ScanPorts 443,8443,636,5986 -TimeoutSeconds 10

# Include workstations (not just servers)
.\Find-WildcardCertificateUsage.ps1 -Thumbprint "A1B2..." -IncludeClients
```

**Output:**
- HTML report with Yeyland Wutani branding
- CSV exports for certificate instances, IIS bindings, RDP services, port scan results
- Expiration warnings (yellow <30 days, red if expired)

**Requirements:**
- PowerShell 5.1+
- PowerShell Remoting enabled on target servers (for full discovery)
- Active Directory PowerShell module (for automatic server discovery)
- Admin rights for certificate store access

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

# Filter specific sites
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -SiteUrlFilter "*project*"
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
- Folder size distribution visualization
- Supports local paths and UNC paths

**Usage:**
```powershell
# Basic local share scan
.\Get-FileShareSecurityReport.ps1 -Path "D:\Shares"

# Remote share with deep scan
.\Get-FileShareSecurityReport.ps1 -Path "\\FileServer\Data" -MaxDepth 8 -OutputPath "C:\Reports"

# Multiple paths, fast scan (skip size calculation)
.\Get-FileShareSecurityReport.ps1 -Path @("D:\Finance", "D:\HR") -SkipSizeCalculation

# Include inherited permissions in report
.\Get-FileShareSecurityReport.ps1 -Path "\\DC01\SYSVOL" -IncludeInherited
```

**Risk Levels:**
- **Critical**: Everyone/Auth Users with FullControl or Modify
- **High**: Broad groups (BUILTIN\Users) with write access
- **Medium**: Interactive/Network users with elevated permissions

**Requirements:** PowerShell 5.1+, Admin rights for full ACL access

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
