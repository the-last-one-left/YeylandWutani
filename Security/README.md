# Security

Security assessment, threat detection, and compliance tools for Microsoft 365 and Windows file systems.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-M365SecurityAnalysis.ps1` | Microsoft 365 security analysis: compromised account detection, sign-in analysis, MFA audit, inbox rules, admin logs |
| `Get-SPOSecurityReport.ps1` | SharePoint Online security assessment: permissions, external sharing, anonymous links, storage analysis |
| `Get-FileShareSecurityReport.ps1` | Windows file share security audit: NTFS permissions, broken inheritance, orphaned SIDs, high-risk ACLs |

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
- Microsoft Graph PowerShell modules (for M365/SPO tools)
- Exchange Online Management module (for M365 tool)
- SharePoint Online Management Shell (for SPO tool)
- Admin rights for file system scanning
- Appropriate admin roles for cloud tools (Security Reader, SharePoint Admin, etc.)

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
