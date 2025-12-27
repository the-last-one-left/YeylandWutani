# Security

Security assessment, threat detection, and compliance tools for Microsoft 365 environments.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-M365SecurityAnalysis.ps1` | Microsoft 365 security analysis: compromised account detection, sign-in analysis, MFA audit, inbox rules, admin logs |
| `Get-SPOSecurityReport.ps1` | SharePoint Online security assessment: permissions, external sharing, anonymous links, storage analysis |

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

## Security Notice

These tools are for authorized security testing only. Users must obtain proper authorization before running on production systems.

---

## Requirements

- PowerShell 5.1+
- Microsoft Graph PowerShell modules
- Exchange Online Management module
- SharePoint Online Management Shell
- Appropriate admin roles (Security Reader, SharePoint Admin, etc.)

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
