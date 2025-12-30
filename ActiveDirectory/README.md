# Active Directory

PowerShell tools for Active Directory security auditing, health monitoring, troubleshooting, recovery, and hybrid identity management.

---

## Available Scripts

### Security Auditing

| Script | Description |
|--------|-------------|
| `Get-ADSecurityAudit.ps1` | Comprehensive AD security audit with HTML reporting: user/computer analysis, password health, service account detection, privileged group membership, health scoring, and visual dashboards |

### Health Monitoring

| Script | Description |
|--------|-------------|
| `Get-ADHealthCheck.ps1` | Comprehensive DC health monitoring: replication, FSMO roles, services, DNS, SYSVOL/NETLOGON shares, time sync |
| `Get-ADReplicationStatus.ps1` | Detailed replication partner analysis with error code translation |
| `Get-AADConnectSyncStatus.ps1` | Azure AD Connect sync health for hybrid environments |
| `Get-DNSZoneHealth.ps1` | AD-integrated DNS zone health discovery with aging/scavenging analysis, stale record detection, and interactive remediation |

### User & Group Management

| Script | Description |
|--------|-------------|
| `Get-ADUserTroubleshooter.ps1` | Deep-dive user diagnostics: account status, password, last logon, group memberships, Azure AD sync |
| `Get-ADGroupMembershipReport.ps1` | Group analysis with nested member resolution and empty group detection |
| `Get-StaleADObjects.ps1` | Identifies inactive computer/user accounts for security and cleanup |

### DFSR Recovery

| Script | Description |
|--------|-------------|
| `Repair-SingleDCDFSRDatabase.ps1` | Emergency DFSR database recovery for single DC environments |
| `Repair-MultiDCDFSRReplication.ps1` | DFSR SYSVOL recovery for multi-DC environments (authoritative/non-authoritative) |

### Permissions

| Script | Description |
|--------|-------------|
| `Set-RedirectedFolderPermissions.ps1` | Repairs NTFS permissions on redirected folders per Microsoft best practices |

---

## Get-ADSecurityAudit.ps1

Comprehensive Active Directory security audit tool that generates professional HTML reports suitable for client presentation and quarterly reviews.

### Audit Categories

- **User Account Analysis** - Active, disabled, inactive, never logged on, locked accounts
- **Recently Created Accounts** - Detect potential unauthorized account creation
- **Password Security** - Expired, expiring soon, never expires, stale passwords
- **Service Account Detection** - Pattern matching and non-expiring password flags
- **Computer Account Analysis** - Active, stale, disabled, OS distribution, legacy OS detection
- **Privileged Group Membership** - Domain Admins, Enterprise Admins, Schema Admins, etc.
- **VPN Group Membership** - WatchGuard SSL-VPN, IKEv2, and similar groups

### Report Features

- **AD Health Score** (0-100) based on security metrics
- **Interactive Table of Contents** with clickable navigation
- **Visual Charts** - User status, password health, OS distribution, privileged groups
- **CSV Exports** for each audit category
- **Dark-themed HTML** with Yeyland Wutani branding

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputPath` | Current directory | Directory for report output |
| `-InactiveDays` | 90 | Days without logon to flag as inactive |
| `-PasswordAgeDays` | 90 | Days to consider a password stale |
| `-PasswordExpiringDays` | 14 | Days to check for soon-to-expire passwords |
| `-RecentlyCreatedDays` | 30 | Days to check for recently created accounts |
| `-SearchBase` | Entire domain | OU distinguished name to limit scope |
| `-IncludeDisabled` | $false | Include disabled accounts in inactive reports |
| `-SkipComputerAudit` | $false | Skip computer account auditing |
| `-SkipGroupAudit` | $false | Skip privileged group membership auditing |
| `-ExportCSV` | $true | Export individual CSV files per category |
| `-Quiet` | $false | Suppress console output except errors |

### Usage Examples

```powershell
# Full audit with defaults
.\Get-ADSecurityAudit.ps1

# Custom thresholds with specific output location
.\Get-ADSecurityAudit.ps1 -OutputPath "C:\Audits" -InactiveDays 60 -PasswordAgeDays 120

# Quick user-only audit (skip computers and groups)
.\Get-ADSecurityAudit.ps1 -SkipComputerAudit -SkipGroupAudit

# Audit specific OU only
.\Get-ADSecurityAudit.ps1 -SearchBase "OU=Corporate,DC=contoso,DC=com"

# Check for accounts created in last 7 days
.\Get-ADSecurityAudit.ps1 -RecentlyCreatedDays 7

# Quarterly review with extended thresholds
.\Get-ADSecurityAudit.ps1 -OutputPath "\\server\reports" -InactiveDays 180 -PasswordAgeDays 180
```

### Output Files

The script generates the following files (prefixed with `AD_Audit_{domain}_{timestamp}`):

**HTML Report**
- `_Report.html` - Comprehensive visual report with charts and tables

**CSV Exports**
- `_ActiveUsers.csv` / `_DisabledUsers.csv` / `_InactiveUsers.csv`
- `_NeverLoggedOn.csv` / `_LockedUsers.csv`
- `_RecentlyCreated.csv` / `_ServiceAccounts.csv`
- `_ExpiredPasswords.csv` / `_UpcomingExpirations.csv`
- `_PasswordNeverExpires.csv` / `_StalePasswords.csv`
- `_ActiveComputers.csv` / `_DisabledComputers.csv` / `_StaleComputers.csv`
- `_WindowsServers.csv` / `_LegacyOS.csv`
- `_PrivilegedGroupMembers.csv` / `_VPNUsers.csv`
- `_UserTimeline.csv`

---

## Other Usage Examples

```powershell
# Daily health check
.\Get-ADHealthCheck.ps1 -ExportPath "C:\Reports\ADHealth.csv"

# User troubleshooting
.\Get-ADUserTroubleshooter.ps1 -Identity "jdoe" -CheckAzureADSync

# Find stale objects (90+ days inactive)
.\Get-StaleADObjects.ps1 -InactiveDays 90 -ExportPath "C:\Reports"

# Check Azure AD Connect sync
.\Get-AADConnectSyncStatus.ps1

# DNS Zone Health Discovery
.\Get-DNSZoneHealth.ps1

# DNS Zone Health with remediation mode
.\Get-DNSZoneHealth.ps1 -StaleThresholdDays 30 -Remediate -IncludeReverseZones

# Export DNS health report
.\Get-DNSZoneHealth.ps1 -ExportPath "C:\Reports\DNSHealth.html"

# DFSR recovery (single DC)
.\Repair-SingleDCDFSRDatabase.ps1

# Fix redirected folder permissions
.\Set-RedirectedFolderPermissions.ps1 -RootPath "\\server\users" -GrantAdminAccess
```

---

## Requirements

- PowerShell 5.1+
- Active Directory PowerShell module (RSAT)
- DNS Server module (RSAT) - for `Get-DNSZoneHealth.ps1`
- Domain Admin credentials (or delegated permissions)
- For hybrid: Azure AD PowerShell modules

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
