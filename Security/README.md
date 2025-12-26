# Security

Security assessment, hardening validation, and incident response tools for enterprise environments.

## Contents

This directory contains tools for:
- **Security Auditing** - Microsoft 365 and SharePoint security posture analysis
- **Threat Detection** - Compromised account identification and risk scoring
- **Compliance Validation** - MFA adoption, conditional access, and privilege reviews
- **Incident Response** - Forensic data collection and attack pattern detection

## Security Notice

**IMPORTANT:** These tools are intended for authorized security testing and administration only. Users must:
- Obtain explicit authorization before running on production systems
- Comply with all applicable laws, regulations, and organizational policies
- Understand tool functionality before execution
- Use responsibly and ethically

Unauthorized access to computer systems is illegal. Yeyland Wutani LLC assumes no liability for misuse.

## Usage Guidelines

- Run with least privilege necessary (some tools require administrative rights)
- Review output carefully for sensitive information before sharing
- Store logs and results securely
- Follow incident response procedures when anomalies are detected
- Document all security testing activities

---

## Available Tools

### Get-M365SecurityAnalysis.ps1 - Microsoft 365 Security Analysis Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-FF6600.svg)](https://docs.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Microsoft%20365-6B7280.svg)](https://www.microsoft.com/microsoft-365)
[![Version](https://img.shields.io/badge/Version-10.2-FF6600.svg)]()

**Version:** 10.2 | **Author:** Yeyland Wutani LLC

#### Overview
Comprehensive security analysis tool for Microsoft 365 tenants that detects compromised accounts, identifies security threats, and analyzes suspicious activity patterns using Microsoft Graph PowerShell APIs. This production-grade tool provides forensic-level insights into tenant security posture through an intuitive dark/light mode GUI interface.

#### Core Capabilities

**Authentication & Access Analysis**
- **Sign-in Logs**: Geolocation analysis with IPv4/IPv6 support, unusual location detection, high-risk ISP identification (VPN/hosting/datacenter providers)
- **Failed Login Patterns**: Password spray, brute force, and confirmed breach detection with IP correlation
- **MFA Status Audit**: Comprehensive multi-factor authentication assessment with privileged account focus
- **Conditional Access**: Policy configuration review and risk assessment

**Threat Detection**
- **Inbox Rules**: Forwarding, deletion, and suspicious pattern detection targeting data exfiltration
- **Mailbox Delegations**: External delegate and high-privilege access identification
- **Password Changes**: Suspicious password reset pattern analysis for credential harvesting detection
- **Message Traces**: Exchange Online message trace with spam pattern analysis and configurable thresholds

**Administrative Oversight**
- **Admin Audit Logs**: High-risk operation monitoring with automated risk scoring
- **App Registrations**: High-privilege permission and configuration analysis for OAuth abuse
- **Risk Scoring**: User risk assessment (Critical/High/Medium/Low) with weighted threat indicators

#### Attack Patterns Detected

| Attack Type | Detection Method |
|------------|-----------------|
| Password Spray | Same IP, multiple user attempts |
| Brute Force | Multiple failures, single user |
| Confirmed Breach | Failed attempts followed by success from same IP |
| Data Exfiltration | Suspicious forwarding rules, external delegates |
| Privilege Escalation | High-risk app permissions, admin role changes |
| Anomalous Access | Unexpected countries, impossible travel |
| OAuth Abuse | Suspicious app registrations and permissions |

#### Key Features

- **Modern GUI**: Dark/light theme interface with real-time progress tracking
- **Risk-Based Scoring**: Automated user risk calculation with customizable weights
- **HTML Reporting**: Comprehensive reports with collapsible sections and color-coded risk indicators
- **Geolocation Intelligence**: Cached IP geolocation with high-risk ISP identification
- **Smart Fallbacks**: Automatic Exchange Online fallback for non-premium Azure AD tenants
- **Batch Processing**: Handles large tenants with configurable batch sizes and rate limiting

#### Required Modules
- Microsoft.Graph.Authentication (v2.0.0+)
- Microsoft.Graph.Users (v2.0.0+)
- Microsoft.Graph.Identity.SignIns (v2.0.0+)
- Microsoft.Graph.Reports (v2.0.0+)
- ExchangeOnlineManagement (v3.0.0+)

*Modules are auto-installed if missing*

#### Required Permissions

**Microsoft Graph API (Delegated):**
- User.Read.All
- AuditLog.Read.All
- Directory.Read.All
- Mail.Read / Mail.ReadWrite
- MailboxSettings.Read / MailboxSettings.ReadWrite
- SecurityEvents.Read.All
- IdentityRiskEvent.Read.All
- IdentityRiskyUser.Read.All
- Application.Read.All
- RoleManagement.Read.All
- Policy.Read.All
- UserAuthenticationMethod.Read.All

**Exchange Online:**
- Exchange Administrator or Security Reader role

#### Usage

```powershell
# Launch the GUI application
.\Get-M365SecurityAnalysis.ps1

# Workflow:
# 1. Click "Connect to Microsoft 365" and authenticate
# 2. Set date range (default: 14 days)
# 3. Run data collection operations as needed
# 4. Generate HTML security report
# 5. Review Critical/High-risk users and attack patterns
```

#### Output Files

| File | Description |
|------|-------------|
| `SecurityReport.html` | Comprehensive HTML report with dark mode support |
| `UserLocationData.csv` | Sign-in logs with geolocation |
| `AdminAuditLogs_HighRisk.csv` | High-risk administrative actions |
| `InboxRules.csv` | Mailbox forwarding and deletion rules |
| `FailedLoginAnalysis.csv` | Attack pattern detection results |
| `MFAStatus.csv` | Multi-factor authentication status |
| `ETRSpamAnalysis.csv` | Spam pattern analysis |

#### Risk Scoring Matrix

| Factor | Points | Description |
|--------|--------|-------------|
| No MFA | 40 | Account without multi-factor authentication |
| Confirmed Breach | 50 | 5+ failed logins then success from same IP |
| High-Risk ISP | 25 | VPN/Hosting/Datacenter provider |
| Suspicious Rules | 15 | Email forwarding or deletion rules |
| Password Spray | 30 | Same IP, multiple user attempts |
| Admin Without MFA | +10 | Additional risk for privileged accounts |

#### Yeyland Wutani Use Cases
- **Incident Response**: Rapid threat identification during active compromises
- **Security Assessments**: Baseline tenant security posture evaluation
- **Compliance Auditing**: MFA adoption, conditional access, and privileged access reviews
- **Proactive Monitoring**: Scheduled runs for early threat detection
- **Client Reporting**: Professional HTML reports for executive briefings

#### Technical Notes
- Supports Azure AD Free (limited features) and Azure AD Premium (full capabilities)
- Automatic module installation for Microsoft.Graph and ExchangeOnlineManagement
- Configurable date ranges (1-365 days, Exchange limited to 10 days)
- Working directory default: `C:\Temp\<TenantName>\<Timestamp>\`
- Detailed execution logging for troubleshooting and compliance

---

### Get-SPOSecurityReport.ps1 - SharePoint Online Security Assessment

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-FF6600.svg)](https://docs.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Microsoft%20365-6B7280.svg)](https://www.microsoft.com/microsoft-365)
[![Version](https://img.shields.io/badge/Version-3.1-FF6600.svg)]()

**Version:** 3.1 | **Author:** Yeyland Wutani LLC

#### Overview
Comprehensive SharePoint Online security and usage reporting tool designed for MSP security audits. Generates detailed reports on site permissions, external sharing configurations, anonymous access links, and storage distribution using Microsoft Graph SDK and SPO Management Shell with delegated authentication (no app registration required).

#### Core Capabilities

**Site Security Analysis**
- **All Site Types**: Scans Team Sites, Communication Sites, Classic Sites, Hub Sites, and Teams Channels
- **Permission Enumeration**: Site Admins, Owners, Members, and Visitors for every site
- **External User Detection**: Identifies and flags guest accounts across the tenant
- **OneDrive Exclusion**: Focuses on collaborative SharePoint sites by default (optional OneDrive inclusion)

**External Sharing Assessment**
- **Tenant-Level Settings**: Sharing capability, anonymous link expiration, domain restrictions
- **Per-Site Configuration**: Individual site sharing settings with capability descriptions
- **Sharing Link Discovery**: Anonymous links, organization links, and specific people links
- **Deep Library Analysis**: Recursive scanning of document libraries for sharing exposure

**Storage & Structure Analysis**
- **Storage Metrics**: Site storage usage with quota percentages
- **Folder Size Distribution**: Hierarchical breakdown of storage by folder
- **Library Inventory**: Document library enumeration with size and type information
- **Unique Permissions**: Items with broken inheritance flagged for review

#### Key Features
- **No App Registration**: Uses delegated authentication with interactive sign-in
- **Branded HTML Reports**: Professional reports with collapsible sections and visual charts
- **CSV Export**: Raw data exports for all collected metrics
- **Configurable Depth**: Adjustable folder scan depth (1-10 levels)
- **Progress Tracking**: Real-time progress with estimated completion

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-TenantName` | String | **Required.** SharePoint tenant name (e.g., 'contoso' for contoso.sharepoint.com) |
| `-OutputPath` | String | Directory for output files (default: current directory) |
| `-IncludeLibraryDeepDive` | Switch | Enable detailed library analysis with sharing links and folder sizes |
| `-IncludeOneDrive` | Switch | Include OneDrive for Business sites (excluded by default) |
| `-SiteUrlFilter` | String | Filter sites by URL pattern (supports wildcards) |
| `-MaxSites` | Int | Limit number of sites to process (useful for testing) |
| `-MaxScanDepth` | Int | Folder depth for recursive scanning (1-10, default: 3) |
| `-SkipTenantSettings` | Switch | Skip tenant-level settings (if limited permissions) |

#### Usage Examples

```powershell
# Basic security report for all SharePoint sites
.\Get-SPOSecurityReport.ps1 -TenantName "contoso"

# Full deep-dive with library analysis
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive -OutputPath "C:\Reports"

# Include OneDrive sites in the scan
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -IncludeOneDrive

# Filter to specific sites only
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -SiteUrlFilter "*project*"

# Test run with limited sites
.\Get-SPOSecurityReport.ps1 -TenantName "contoso" -MaxSites 10 -IncludeLibraryDeepDive
```

#### Required Modules
- Microsoft.Graph.Authentication (v2.0.0+)
- Microsoft.Graph.Sites (v2.0.0+)
- Microsoft.Graph.Users (v2.0.0+)
- Microsoft.Graph.Groups (v2.0.0+)
- Microsoft.Online.SharePoint.PowerShell (v16.0.0+)

#### Required Permissions
**Microsoft Graph (Delegated):**
- Sites.Read.All
- User.Read.All
- Group.Read.All
- GroupMember.Read.All

**SharePoint Online:**
- SharePoint Administrator or Global Administrator

#### Output Files
| File | Description |
|------|-------------|
| `SPO_SecurityReport_<timestamp>.html` | Branded HTML report with visual charts |
| `SPO_Sites_<timestamp>.csv` | Site inventory with storage and sharing settings |
| `SPO_SiteMembers_<timestamp>.csv` | User permissions by site |
| `SPO_ExternalSharingSettings_<timestamp>.csv` | Sharing capability by site |
| `SPO_Libraries_<timestamp>.csv` | Document library inventory |
| `SPO_SharingLinks_<timestamp>.csv` | Discovered sharing links (deep dive) |
| `SPO_UniquePermissions_<timestamp>.csv` | Items with unique permissions (deep dive) |
| `SPO_FolderSizes_<timestamp>.csv` | Folder size distribution (deep dive) |
| `SPO_Errors_<timestamp>.csv` | Errors encountered during scan |

#### Yeyland Wutani Use Cases
- **Security Assessments**: Baseline external sharing posture for new clients
- **Compliance Audits**: Document access controls for regulatory requirements
- **Risk Identification**: Find anonymous links and overshared content
- **Storage Analysis**: Identify large sites/libraries for quota planning
- **Permission Reviews**: Regular audits of site access and guest users
- **Incident Response**: Investigate potential data exposure incidents

---

## Tool Comparison

| Feature | Get-M365SecurityAnalysis | Get-SPOSecurityReport |
|---------|-------------------------|----------------------|
| **Focus** | Account compromise & threats | SharePoint permissions & sharing |
| **Interface** | GUI (Dark/Light mode) | Command-line |
| **Authentication** | Graph + Exchange Online | Graph + SPO Management |
| **Primary Output** | Risk-scored user analysis | Site permission inventory |
| **Typical Use** | Incident response, security audits | Compliance, permission reviews |

## Requirements

- PowerShell 5.1 or later (7+ recommended for cross-platform tools)
- Administrative privileges for system-level operations
- Appropriate security clearances and authorizations
- Understanding of security concepts and potential impacts

---

[← Back to Main Repository](../README.md)
