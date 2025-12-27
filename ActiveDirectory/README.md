# Active Directory

PowerShell tools for Active Directory health monitoring, troubleshooting, recovery, and hybrid identity management.

---

## Available Scripts

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

## Usage Examples

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
