# Active Directory

PowerShell tools for Active Directory health monitoring, troubleshooting, recovery, auditing, and hybrid identity management.

## Available Scripts

### Health Monitoring & Diagnostics

#### Get-ADHealthCheck.ps1
Comprehensive Active Directory infrastructure health monitoring for domain controllers.

**What It Monitors:**
- Domain controller availability and response times
- FSMO role holder verification and distribution
- AD replication status across all domain controllers
- DNS service health and resolution
- Critical AD services (NTDS, DNS, DFSR, KDC, W32Time, Netlogon)
- SYSVOL and NETLOGON share accessibility
- Time synchronization across DCs
- Recent AD replication failures with error code translation

**Perfect For:**
- Daily health checks and monitoring
- Troubleshooting replication issues
- Pre-maintenance validation
- Post-migration verification
- Identifying failing domain controllers
- Generating compliance reports

**Usage Examples:**
```powershell
# Quick health check of all DCs
.\Get-ADHealthCheck.ps1

# Check specific DC and export results
.\Get-ADHealthCheck.ps1 -DomainController "DC01" -ExportPath "C:\Reports\DC01_Health.csv"

# Full domain health assessment
.\Get-ADHealthCheck.ps1 -ExportPath "C:\Reports\ADHealth_$(Get-Date -Format 'yyyyMMdd').csv"
```

**Output Includes:**
- Domain controller inventory with OS versions
- FSMO role distribution across DCs
- Service status for all critical AD components
- Share accessibility verification
- Replication partner health matrix
- Time sync status across domain
- Color-coded health indicators (Green/Yellow/Red)

**Common Issues Detected:**
- Domain controllers not responding to ping
- DNS resolution failures
- DFSR service not running
- SYSVOL/NETLOGON shares not accessible
- Replication failures (with error codes)
- Time drift between domain controllers
- Critical services stopped or disabled

---

#### Get-ADReplicationStatus.ps1
Focused AD replication monitoring with detailed partner analysis and error translation.

**What It Checks:**
- Replication partner status for all domain controllers
- Last successful replication timestamps
- Replication failures with translated error codes
- Consecutive failure counts per partner
- Pending replication operations
- Replication latency metrics
- Site link health

**Error Code Translation:**
Automatically translates common AD replication errors:
- **8606**: Insufficient attributes given to create object
- **8240**: No such object on server
- **5**: Access is denied
- **1722**: RPC server unavailable
- **1256**: Remote system not available
- **1908**: Could not find domain controller
- **8452**: Naming violation
- **8524**: DSA is unavailable

**Usage Examples:**
```powershell
# Check all DC replication status
.\Get-ADReplicationStatus.ps1

# Check specific DC
.\Get-ADReplicationStatus.ps1 -DomainController "DC02"

# Show only DCs with issues
.\Get-ADReplicationStatus.ps1 -ShowPendingOnly

# Export full replication report
.\Get-ADReplicationStatus.ps1 -ExportPath "C:\Reports\Replication.csv"
```

**Troubleshooting Commands Provided:**
```powershell
# Force replication between specific DCs
repadmin /replicate <DestDC> <SourceDC> <NamingContext>

# Force replication from all partners
repadmin /syncall /AdeP

# View detailed replication status
repadmin /showrepl <DC>

# Check replication queue
repadmin /queue
```

---

### User & Group Management

#### Get-ADUserTroubleshooter.ps1
Deep-dive user account diagnostics for resolving authentication and access issues.

**Comprehensive Analysis:**
- Account status (enabled/disabled, locked, expired)
- Password status, expiration, and policy compliance
- Last logon information across ALL domain controllers
- Direct and nested group memberships
- Account attributes and security flags
- Kerberos settings and delegation
- Azure AD Connect sync status (hybrid environments)
- Account restrictions (logon hours, workstation restrictions)

**Common Problems Identified:**
- Account locked out (with unlock commands)
- Password expired or must change at next logon
- Account disabled or expired
- User not replicated to all domain controllers
- Recent bad password attempts
- Conflicting group memberships
- Missing from Azure AD (hybrid environments)

**Usage Examples:**
```powershell
# Basic user troubleshooting
.\Get-ADUserTroubleshooter.ps1 -Identity "jdoe"

# Using email address
.\Get-ADUserTroubleshooter.ps1 -Identity "john.doe@contoso.com"

# Full analysis with nested groups
.\Get-ADUserTroubleshooter.ps1 -Identity "jdoe" -IncludeGroupDetails

# Check Azure AD sync status
.\Get-ADUserTroubleshooter.ps1 -Identity "jdoe" -CheckAzureADSync
```

**Quick Fix Commands Provided:**
```powershell
# Unlock account
Unlock-ADAccount -Identity 'username'

# Enable account
Enable-ADAccount -Identity 'username'

# Reset password
Set-ADAccountPassword -Identity 'username' -Reset

# Clear bad password count
Set-ADUser -Identity 'username' -Clear badPwdCount

# Force password change at next logon
Set-ADUser -Identity 'username' -ChangePasswordAtLogon $true
```

**Real-World Scenarios:**

**Scenario 1: User Can't Log In**
```powershell
# Run diagnostics
.\Get-ADUserTroubleshooter.ps1 -Identity "jsmith"

# Script identifies: Account locked out
# Provides: Unlock-ADAccount command
# Verifies: Last logon times and replication status
```

**Scenario 2: Hybrid Sync Issues**
```powershell
# Check user sync status
.\Get-ADUserTroubleshooter.ps1 -Identity "jdoe" -CheckAzureADSync

# Identifies: User not synced to Azure AD
# Shows: User OU location and sync scope
# Helps: Determine if OU is in sync scope
```

---

#### Get-ADGroupMembershipReport.ps1
Comprehensive group analysis and membership reporting with nested group resolution.

**Features:**
- Direct and nested group member enumeration
- User, computer, and group object identification
- Member details (enabled status, last logon, department, title)
- Empty groups detection
- Large groups identification (100+ members)
- Nested group depth analysis
- Multiple export formats (CSV, detailed reports)

**Usage Examples:**
```powershell
# Report on specific group with nested members
.\Get-ADGroupMembershipReport.ps1 -GroupName "Domain Admins" -IncludeNested

# Find all empty groups
.\Get-ADGroupMembershipReport.ps1 -ShowEmptyGroups -ExportPath "C:\Reports"

# Show groups with 50+ members
.\Get-ADGroupMembershipReport.ps1 -MinimumMembers 50

# Full group audit with export
.\Get-ADGroupMembershipReport.ps1 -GroupName "*Admins*" -IncludeNested -ExportPath "C:\Reports"
```

**Output Reports:**
- Group membership matrix with nesting levels
- Empty groups list (candidates for cleanup)
- Large groups report (potential performance impact)
- Member type breakdown (users vs computers vs groups)
- Department distribution for group members

**Perfect For:**
- Access control audits
- Security group reviews
- Privileged access documentation
- Cleanup of unused groups
- Compliance reporting
- Understanding nested group impacts

---

### Compliance & Auditing

#### Get-StaleADObjects.ps1
Identifies inactive and stale computer/user accounts for security and cleanup.

**Detection Criteria:**
- Computer accounts inactive for X days (default: 90)
- User accounts inactive for X days (default: 90)
- Accounts that have never logged on
- Disabled accounts in active OUs
- Accounts with expired passwords
- Pre-Windows 2000 Compatible Access group members (security check)

**Advanced Features:**
- Configurable inactivity thresholds
- OU exclusion capability
- Option to include/exclude disabled accounts
- Operating system breakdown for stale computers
- Department analysis for stale users
- Multiple export formats

**Usage Examples:**
```powershell
# Find objects inactive 90+ days
.\Get-StaleADObjects.ps1

# Custom threshold and export
.\Get-StaleADObjects.ps1 -InactiveDays 180 -ExportPath "C:\Reports"

# Include never-logged-on accounts
.\Get-StaleADObjects.ps1 -IncludeNeverLoggedOn

# Exclude disabled accounts from results
.\Get-StaleADObjects.ps1 -ExcludeDisabled

# Exclude specific OUs
.\Get-StaleADObjects.ps1 -ExcludeOUs @("OU=Servers,DC=domain,DC=com","OU=Service Accounts,DC=domain,DC=com")
```

**Reports Generated:**
- Stale computers list with OS breakdown
- Stale users list with department breakdown
- Never-logged-on accounts
- Security group membership issues
- Recommended cleanup actions

**Cleanup Workflow:**
```powershell
# 1. Generate initial report
.\Get-StaleADObjects.ps1 -InactiveDays 90 -ExportPath "C:\Reports"

# 2. Review with business units

# 3. Disable accounts first (safe step)
# Disable-ADAccount -Identity 'username'

# 4. Wait 30 days grace period

# 5. Remove accounts after confirmation
# Remove-ADObject -Identity 'DN' -Confirm:$false
```

**Security Benefits:**
- Reduces attack surface
- Identifies zombie accounts
- Improves licensing compliance
- Reduces AD bloat
- Enhances security posture

---

### Hybrid Identity Management

#### Get-AADConnectSyncStatus.ps1
Monitors Azure AD Connect synchronization health for hybrid identity environments.

**⚠️ CRITICAL: 75% of clients use hybrid identity - this is essential for MSP operations**

**What It Monitors:**
- ADSync service status
- Sync scheduler configuration and next run time
- Last sync cycle time and results
- Connector status and errors
- Pending exports/imports
- Sync rules configuration
- Database health

**Common Issues Detected:**
- ADSync service not running
- Sync scheduler disabled or stuck
- Last sync failed or stale
- Connector errors preventing sync
- Pending export operations
- Database corruption
- Maintenance mode enabled

**Usage Examples:**
```powershell
# Check sync status on local server
.\Get-AADConnectSyncStatus.ps1

# Check remote AAD Connect server
.\Get-AADConnectSyncStatus.ps1 -AADConnectServer "AADCONNECT01"

# Include sync rules configuration
.\Get-AADConnectSyncStatus.ps1 -ShowSyncRules

# Export detailed report
.\Get-AADConnectSyncStatus.ps1 -ExportPath "C:\Reports\AADConnectStatus.json"
```

**Troubleshooting Commands Provided:**
```powershell
# Start sync cycle manually
Start-ADSyncSyncCycle -PolicyType Delta

# View sync errors
Get-ADSyncCSObject | Where-Object { $_.ErrorObject }

# Restart sync service
Restart-Service ADSync

# View connector statistics
Get-ADSyncConnector | Get-ADSyncConnectorStatistics
```

**Real-World Scenario:**
```powershell
# User reports can't log in to Office 365
.\Get-AADConnectSyncStatus.ps1

# Script identifies:
# - Last sync: 12 hours ago (should be every 30 min)
# - Sync scheduler: Disabled
# - Connector errors: 15

# Resolution:
Start-ADSyncSyncCycle -PolicyType Delta

# Verify sync completes
.\Get-AADConnectSyncStatus.ps1
```

---

### DFSR Recovery & Repair

#### Repair-SingleDCDFSRDatabase.ps1
Emergency DFSR database recovery for single domain controller environments.

**⚠️ CRITICAL: Use ONLY in single DC environments. For multi-DC use Repair-MultiDCDFSRReplication.ps1**

**What It Does:**
- Auto-detects Volume GUID from event logs (Event ID 2212/2213)
- Backs up SYSVOL and DFSR database
- Rebuilds corrupted DFSR database
- Configures DC as authoritative for SYSVOL
- Forces SYSVOL re-initialization
- Restores proper permissions

**When To Use:**
- Event ID 2104: DFSR database corruption
- Event ID 2212/2213: Unexpected shutdown, dirty database
- SYSVOL/NETLOGON shares missing on single DC
- Group Policy not applying due to SYSVOL issues

**Safety Features:**
- Automatic DC count verification
- Complete SYSVOL backup before changes
- DFSR database backup
- Auto-detection of Volume GUID
- Step-by-step execution with logging
- Post-recovery verification

**Usage Examples:**
```powershell
# Auto-detect GUID and repair (recommended)
.\Repair-SingleDCDFSRDatabase.ps1

# Specify GUID manually
.\Repair-SingleDCDFSRDatabase.ps1 -VolumeGUID '021FA783-34D8-415C-9C7C-B9473701A259'

# Custom volume letter
.\Repair-SingleDCDFSRDatabase.ps1 -VolumeLetter 'D'
```

**Step-by-Step Process:**
1. Verifies single DC environment (safety check)
2. Detects Volume GUID from events or WMI
3. Backs up SYSVOL content
4. Backs up DFSR database
5. Stops DFSR service
6. Removes corrupted database
7. Restores SYSTEM permissions
8. Configures authoritative SYSVOL
9. Starts DFSR service and monitors initialization
10. Verifies SYSVOL/NETLOGON shares

**Post-Recovery:**
```powershell
# Verify shares
net share

# Check Event Viewer for Event ID 4602
Get-WinEvent -LogName 'DFS Replication' -MaxEvents 20

# Test Group Policy
gpupdate /force
gpresult /r

# Schedule disk check
chkdsk C: /F /R
```

---

#### Repair-MultiDCDFSRReplication.ps1
DFSR SYSVOL recovery for environments with multiple domain controllers.

**⚠️ RUN THIS SCRIPT ON THE PROBLEM DOMAIN CONTROLLER ONLY**

**Two Recovery Modes:**

**Non-Authoritative (Default - Most Common):**
- Problem DC syncs SYSVOL from healthy DCs
- Use when one DC has issues, others are healthy
- Safest option for most scenarios
- Preserves SYSVOL from healthy DCs

**Authoritative:**
- Forces all DCs to sync from THIS DC
- Use when need to force specific SYSVOL content
- Makes THIS DC the source of truth
- Use with extreme caution

**Comprehensive Health Checks:**
- Verifies multi-DC environment (refuses to run on single DC)
- Checks AD replication health
- Identifies healthy source DCs
- Validates SYSVOL/NETLOGON share accessibility
- Tests DC connectivity across sites

**Usage Examples:**
```powershell
# Non-authoritative restore (sync from healthy DCs)
.\Repair-MultiDCDFSRReplication.ps1

# Specify source DC to sync from
.\Repair-MultiDCDFSRReplication.ps1 -RestoreType NonAuthoritative -AuthoritativeSourceDC "DC01"

# Authoritative restore (make THIS DC source of truth)
.\Repair-MultiDCDFSRReplication.ps1 -RestoreType Authoritative

# Skip backup (low disk space)
.\Repair-MultiDCDFSRReplication.ps1 -SkipBackup

# Force without confirmations (automation)
.\Repair-MultiDCDFSRReplication.ps1 -Force
```

**Event IDs To Monitor:**
- **Event 4602**: Authoritative initialization completed
- **Event 4614**: Non-authoritative initialization started
- **Event 4604**: Non-authoritative initialization completed
- **Event 2212**: Unexpected shutdown (trigger for recovery)
- **Event 2213**: Dirty database shutdown

**Common Scenarios:**

**Scenario 1: DC03 SYSVOL Not Replicating**
```powershell
# Run on DC03 (the problem DC)
.\Repair-MultiDCDFSRReplication.ps1

# Script automatically:
# - Identifies DC01 and DC02 as healthy
# - Syncs SYSVOL from healthy DCs
# - Monitors for Event 4614/4604
```

**Scenario 2: Force All DCs to Match PDC**
```powershell
# Run on PDC Emulator
.\Repair-MultiDCDFSRReplication.ps1 -RestoreType Authoritative

# Then on each OTHER DC:
# 1. Start DFSR service
# 2. Re-enable SYSVOL subscription
# 3. Run: dfsrdiag pollad
# 4. Monitor for Event 4614/4604
```

**Scenario 3: Event 4012 - Too Long Offline**
```powershell
# DC offline 107 days (MaxOfflineTimeInDays = 60)
# SYSVOL marked as stale

# Run on affected DC
.\Repair-MultiDCDFSRReplication.ps1 -RestoreType NonAuthoritative

# Syncs fresh SYSVOL from healthy DCs
```

---

### Permissions Management

#### Set-RedirectedFolderPermissions.ps1
Repairs and configures NTFS permissions on redirected folder shares per Microsoft best practices.

**Microsoft Recommended Permissions:**

**Root Folder:**
- CREATOR OWNER: Full Control (subfolders and files only)
- SYSTEM: Full Control (this folder, subfolders, files)
- Authenticated Users: List/Read, Create folders (this folder only)
- Domain Admins: Full Control (optional)

**User Folders:**
- User (Owner): Full Control (this folder, subfolders, files)
- SYSTEM: Full Control (this folder, subfolders, files)
- Admin Groups: Full Control (optional, configurable)

**Advanced Features:**
- **Auto-detection** of redirected folder paths from GPO settings
- **Intelligent user lookup** with multiple fallback methods
- **Multiple admin groups** (Help Desk, IT Support, etc.)
- **Permission backup** before making changes
- **Parallel processing** (10 threads default, configurable)
- **Test mode** - validate without making changes
- **Folder exclusion** capability
- **Comprehensive logging** with error/warning counts

**Common Problems It Fixes:**
- Broken inheritance from bad takeown operations
- Missing CREATOR OWNER permissions
- Users can't access their own folders
- Admins can't access any folders
- Mixed permission states from manual changes
- Everyone/Authenticated Users full control (security issue)

**Usage Examples:**
```powershell
# Auto-detect and apply default permissions
.\Set-RedirectedFolderPermissions.ps1

# Specific path with admin access
.\Set-RedirectedFolderPermissions.ps1 -RootPath "\\server\users" -GrantAdminAccess

# Multiple admin groups
.\Set-RedirectedFolderPermissions.ps1 `
    -RootPath "\\fileserver\redirected" `
    -AdminGroup "Domain Admins" `
    -AdditionalAdminGroups @("Help Desk","IT Support") `
    -GrantAdminAccess

# Test mode (no changes)
.\Set-RedirectedFolderPermissions.ps1 -TestMode -ExportPath "C:\Reports"

# Performance tuning
.\Set-RedirectedFolderPermissions.ps1 `
    -RootPath "\\server\users" `
    -ProcessInParallel $true `
    -ThrottleLimit 20

# With folder exclusions
.\Set-RedirectedFolderPermissions.ps1 `
    -RootPath "\\server\users" `
    -ExcludeFolders @("admin","templates","_archive")
```

**Intelligent User Lookup:**
The script tries multiple methods to resolve folder names to AD users:
1. Exact SamAccountName match
2. DisplayName match
3. Wildcard SamAccountName for "domain\username" folders
4. Partial matching for variations

**Real-World Scenarios:**

**Scenario 1: Inherited Permissions Nightmare**
```powershell
# After someone ran takeown /r on root folder
.\Set-RedirectedFolderPermissions.ps1 -RootPath "\\fileserver\users" -BackupPermissions

# Script:
# - Backs up existing permissions
# - Resets root folder to Microsoft standards
# - Fixes each user folder with proper ownership
# - Removes admin access (unless -GrantAdminAccess specified)
```

**Scenario 2: Help Desk Access Required**
```powershell
# Need support team to access user folders
.\Set-RedirectedFolderPermissions.ps1 `
    -RootPath "\\server\redirected" `
    -AdminGroup "Domain Admins" `
    -AdditionalAdminGroups @("Tier 1 Support","Tier 2 Support") `
    -GrantAdminAccess

# All specified groups get full control
```

**Scenario 3: Large Environment Optimization**
```powershell
# 500+ user folders, optimize performance
.\Set-RedirectedFolderPermissions.ps1 `
    -RootPath "\\fileserver\users" `
    -ProcessInParallel $true `
    -ThrottleLimit 20 `
    -BackupPermissions $true `
    -ExportPath "C:\Reports"

# Parallel processing reduces total time significantly
```

**Test Mode Workflow:**
```powershell
# 1. Run test mode first
.\Set-RedirectedFolderPermissions.ps1 -TestMode -ExportPath "C:\Reports"

# 2. Review report showing:
#    - Folders that will be processed
#    - Users that will be resolved
#    - Permissions that will be applied

# 3. Run for real
.\Set-RedirectedFolderPermissions.ps1 -BackupPermissions
```

**Safety Features:**
- Permission backup before changes
- Test mode for validation
- Confirmation required before proceeding
- Comprehensive logging
- Error tracking and reporting
- WhatIf support (via ShouldProcess)

---

## Common Workflows

### Daily Health Monitoring
```powershell
# Morning health check routine
.\Get-ADHealthCheck.ps1 -ExportPath "C:\Reports\Daily"
.\Get-ADReplicationStatus.ps1 -ExportPath "C:\Reports\Daily"
.\Get-AADConnectSyncStatus.ps1 -ExportPath "C:\Reports\Daily"
```

### User Authentication Issues
```powershell
# Full user diagnostics
.\Get-ADUserTroubleshooter.ps1 -Identity "username" -IncludeGroupDetails -CheckAzureADSync
```

### Monthly Cleanup & Auditing
```powershell
# Identify stale objects
.\Get-StaleADObjects.ps1 -InactiveDays 90 -ExportPath "C:\Reports\Monthly"

# Audit privileged groups
.\Get-ADGroupMembershipReport.ps1 -GroupName "*Admin*" -IncludeNested -ExportPath "C:\Reports\Monthly"
```

### DFSR Emergency Response
```powershell
# Single DC
.\Repair-SingleDCDFSRDatabase.ps1

# Multi-DC
.\Repair-MultiDCDFSRReplication.ps1 -RestoreType NonAuthoritative
```

### Redirected Folder Permissions Reset
```powershell
# After permissions disaster
.\Set-RedirectedFolderPermissions.ps1 -TestMode
.\Set-RedirectedFolderPermissions.ps1 -BackupPermissions
```

---

## Environment Considerations

**MSP Multi-Client Environment:**
- Scripts work across different client domains
- No hardcoded values - all dynamic
- Supports both on-premises and hybrid (75% of clients)
- Compatible with common MSP infrastructure:
  - WatchGuard firewalls
  - Aruba switches and access points
  - Microsoft 365 email
  - Hybrid identity via Azure AD Connect

**Typical Client Configurations:**
- Single domain controller (use single DC scripts)
- 2-5 domain controllers (use multi-DC scripts)
- Hybrid identity with AAD Connect (monitor sync status)
- Redirected folders on file servers (permission management)

---

## Requirements

### Software
- **PowerShell 5.1 or later**
- **Active Directory PowerShell module (RSAT)**
- **Domain administrative credentials** (or appropriate delegated permissions)
- **Network connectivity to domain controllers**
- **For hybrid scenarios**: Azure AD PowerShell modules

### Permissions
- **Health checks**: Domain Admin or Read-Only Domain Admin
- **User troubleshooting**: Help Desk with user read permissions
- **DFSR repair**: Domain Admin, run on affected DC
- **Permission management**: Domain Admin or delegated file permissions

### Compatibility
- **Windows Server**: 2016, 2019, 2022, 2025
- **Domain Functional Level**: 2012 R2 or higher recommended
- **Azure AD Connect**: All versions supported

---

## Best Practices

### Before Running Scripts
1. **Test in non-production first** - Always validate in dev/staging
2. **Backup** - Ensure AD and file server backups are current
3. **Change control** - Document what you're doing and why
4. **Off-hours** - Run impactful scripts during maintenance windows

### Security Considerations
- **Least privilege** - Use service accounts with minimum required permissions
- **Audit logs** - Enable PowerShell transcription and module logging
- **Review output** - Always review reports before taking action
- **Multi-factor** - Require MFA for Domain Admin operations

### Operational Guidelines
- **Monitor AD replication** - Check daily, especially after changes
- **Regular cleanup** - Monthly stale object audits
- **Hybrid sync health** - Check sync status at least weekly
- **Document changes** - Log all administrative actions

### Emergency Response
1. **Assess impact** - Use health check scripts first
2. **Identify root cause** - Review event logs and replication status
3. **Test fix** - Use test mode or WhatIf when available
4. **Execute repair** - Run appropriate recovery script
5. **Verify** - Confirm resolution with health checks
6. **Document** - Record issue, resolution, and preventive measures

---

## Troubleshooting Guide

### AD Replication Issues
```powershell
# 1. Check overall health
.\Get-ADHealthCheck.ps1

# 2. Detailed replication analysis
.\Get-ADReplicationStatus.ps1

# 3. If DFSR/SYSVOL issues found
.\Repair-MultiDCDFSRReplication.ps1 -RestoreType NonAuthoritative
```

### User Can't Authenticate
```powershell
# 1. Full user diagnostics
.\Get-ADUserTroubleshooter.ps1 -Identity "username"

# 2. If hybrid environment
.\Get-ADUserTroubleshooter.ps1 -Identity "username" -CheckAzureADSync

# 3. Check sync status
.\Get-AADConnectSyncStatus.ps1
```

### Redirected Folders Not Working
```powershell
# 1. Verify folder exists and user can access
Test-Path "\\server\users\username"

# 2. Fix permissions
.\Set-RedirectedFolderPermissions.ps1 -RootPath "\\server\users"

# 3. Check SYSVOL replication (GPO issues)
.\Get-ADReplicationStatus.ps1
```

---

## Support & Contributions

**Yeyland Wutani - Building Better Systems**

These scripts are maintained for MSP escalation team operations with focus on:
- Real-world MSP client scenarios
- Hybrid identity environments
- Rapid troubleshooting and recovery
- Compliance and auditing needs

For issues or enhancements, document findings with:
- Client environment details
- Error messages or unexpected behavior
- Expected vs actual results
- Relevant event log entries

---

[← Back to Main Repository](../README.md)
